// Before any include. Windows defines min and max as function-like macros, and
// OpenSSL's own headers pull in <windows.h> on that platform — so defining this
// down beside <winsock2.h> happens after the damage is already done, which is
// exactly how the first attempt at this failed.
#if defined(_WIN32) && !defined(NOMINMAX)
#define NOMINMAX
#endif

#include "oracle_scanner/byte_stream.hpp"
#include "oracle_scanner/connect_error.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <thread>
#include <utility>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#endif

namespace oracle_scanner {

#if defined(_WIN32)
// Windows has no SIGPIPE; a closed peer surfaces as an error return.
class ScopedSigPipeBlock {};
#else
// Blocks SIGPIPE for this thread across a write, and consumes the one our own
// write may have raised.
//
// Writing to a peer that has closed returns EPIPE and raises SIGPIPE, whose
// default action terminates the process. Without this, an Oracle server closing
// mid-write takes down the whole DuckDB process instead of failing one
// statement. macOS suppresses the signal for sockets and Linux does not, which
// is why it only ever appeared there.
//
// Only a signal this scope could have raised is consumed. If SIGPIPE was
// already blocked on entry, a pending one may predate us and belongs to
// whoever blocked it, so it is left alone.
class ScopedSigPipeBlock {
public:
    ScopedSigPipeBlock() {
        sigset_t block;
        sigemptyset(&block);
        sigaddset(&block, SIGPIPE);
        if (pthread_sigmask(SIG_BLOCK, &block, &previous) != 0) {
            return;
        }
        active = true;
        was_blocked = sigismember(&previous, SIGPIPE) == 1;
    }

    ~ScopedSigPipeBlock() {
        if (!active) {
            return;
        }
        if (!was_blocked) {
            sigset_t pending;
            sigemptyset(&pending);
            if (sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1) {
                sigset_t just_sigpipe;
                sigemptyset(&just_sigpipe);
                sigaddset(&just_sigpipe, SIGPIPE);
                int delivered = 0;
                // It is pending and blocked, so this takes it without waiting.
                sigwait(&just_sigpipe, &delivered);
            }
        }
        pthread_sigmask(SIG_SETMASK, &previous, nullptr);
    }

    ScopedSigPipeBlock(const ScopedSigPipeBlock &) = delete;
    ScopedSigPipeBlock &operator=(const ScopedSigPipeBlock &) = delete;

private:
    sigset_t previous {};
    bool active = false;
    bool was_blocked = false;
};
#endif


struct OpenSslByteStream::Impl {
    BIO *bio = nullptr;
    SSL_CTX *context = nullptr;
    uint32_t read_timeout_seconds = 0;
    int socket_fd = -1;
    bool use_tls = false;
    bool closed = false;
    // Set by the connect loop while it talks to a listener; see
    // ByteStream::SetDeadline.
    std::optional<std::chrono::steady_clock::time_point> deadline;

    ~Impl() {
        if (bio) {
            BIO_free_all(bio);
        }
        if (context) {
            SSL_CTX_free(context);
        }
    }
};

static void RequireOpenSsl(int result, const char *operation) {
    if (result == 1) {
        return;
    }
    ERR_clear_error();
    throw ProtocolError(ProtocolErrorKind::INVALID_STATE, std::string("OpenSSL failed while ") + operation);
}

static std::string DrainOpenSslErrors() {
    std::string result;
    for (auto error = ERR_get_error(); error != 0; error = ERR_get_error()) {
        char text[256];
        ERR_error_string_n(error, text, sizeof(text));
        if (!result.empty()) {
            result += "; ";
        }
        result += text;
    }
    return result.empty() ? "no OpenSSL error detail" : result;
}

static int PemPasswordCallback(char *destination, int destination_size, int, void *user_data) {
    const auto *password = static_cast<const std::string *>(user_data);
    if (!password || destination_size <= 0 || password->size() >= static_cast<size_t>(destination_size)) {
        return 0;
    }
    std::copy(password->begin(), password->end(), destination);
    return static_cast<int>(password->size());
}

static void FreePemInfo(STACK_OF(X509_INFO) *info) {
    sk_X509_INFO_pop_free(info, X509_INFO_free);
}

using PemInfoPtr = std::unique_ptr<STACK_OF(X509_INFO), decltype(&FreePemInfo)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using PrivateKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using CertificatePtr = std::unique_ptr<X509, decltype(&X509_free)>;

static PemInfoPtr ReadPemInfo(const std::string &pem, const std::string &password, const char *operation) {
    auto bio = BioPtr(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!bio) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, std::string("OpenSSL could not allocate PEM BIO while ") + operation);
    }
    // OpenSSL's password callback takes the user datum as `void *`, so the
    // const has to come off to pass it. PemPasswordCallback only reads it, and
    // copying the password to a non-const buffer would put a second copy of a
    // secret in memory for no gain.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    auto *info = PEM_X509_INFO_read_bio(bio.get(), nullptr, PemPasswordCallback, const_cast<std::string *>(&password));
    if (!info) {
        ERR_clear_error();
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, std::string("OpenSSL failed while ") + operation);
    }
    return PemInfoPtr(info, FreePemInfo);
}

static void LoadVerifyCertificatesFromPem(SSL_CTX *context, const std::string &pem, const std::string &password,
                                          const char *operation) {
    auto info = ReadPemInfo(pem, password, operation);
    size_t certificates = 0;
    auto *store = SSL_CTX_get_cert_store(context);
    for (int index = 0; index < sk_X509_INFO_num(info.get()); index++) {
        const auto *entry = sk_X509_INFO_value(info.get(), index);
        if (!entry->x509) {
            continue;
        }
        certificates++;
        if (X509_STORE_add_cert(store, entry->x509) != 1) {
            const auto error = ERR_peek_last_error();
            if (ERR_GET_LIB(error) == ERR_LIB_X509 && ERR_GET_REASON(error) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                ERR_clear_error();
                continue;
            }
            ERR_clear_error();
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, std::string("OpenSSL failed while ") + operation);
        }
    }
    if (certificates == 0) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, std::string("OpenSSL found no CA certificates while ") + operation);
    }
}

static void LoadClientIdentityFromPem(SSL_CTX *context, const std::string &pem, const std::string &password) {
    auto info = ReadPemInfo(pem, password, "reading in-memory wallet PEM");
    auto key_bio = BioPtr(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!key_bio) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL could not allocate wallet key BIO");
    }
    // Same reason as above: the callback datum is a `void *` in OpenSSL's API.
    auto private_key = PrivateKeyPtr(PEM_read_bio_PrivateKey(key_bio.get(), nullptr, PemPasswordCallback,
                                                             // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
                                                             const_cast<std::string *>(&password)),
                                      EVP_PKEY_free);
    X509 *certificate = nullptr;
    if (private_key) {
        for (int index = 0; index < sk_X509_INFO_num(info.get()); index++) {
            const auto *entry = sk_X509_INFO_value(info.get(), index);
            if (entry->x509 && X509_check_private_key(entry->x509, private_key.get()) == 1) {
                certificate = entry->x509;
                break;
            }
            ERR_clear_error();
        }
    }
    if (!private_key) {
        ERR_clear_error();
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                            "OpenSSL could not decrypt the client private key in wallet PEM");
    }
    if (!certificate) {
        ERR_clear_error();
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                            "OpenSSL could not find a certificate matching the wallet private key");
    }
    RequireOpenSsl(SSL_CTX_use_certificate(context, certificate), "loading client certificate");
    RequireOpenSsl(SSL_CTX_use_PrivateKey(context, private_key.get()), "loading client private key");
    for (int index = 0; index < sk_X509_INFO_num(info.get()); index++) {
        const auto *entry = sk_X509_INFO_value(info.get(), index);
        if (!entry->x509 || entry->x509 == certificate) {
            continue;
        }
        auto chain_certificate = CertificatePtr(X509_dup(entry->x509), X509_free);
        if (!chain_certificate || SSL_CTX_add_extra_chain_cert(context, chain_certificate.get()) != 1) {
            ERR_clear_error();
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL failed while loading client certificate chain");
        }
        // SSL_CTX owns successfully added chain certificates, so the unique_ptr
        // has to stop owning this one. The released pointer is deliberately
        // dropped: ownership moved, it was not leaked.
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        chain_certificate.release();
    }
    RequireOpenSsl(SSL_CTX_check_private_key(context), "checking client private key");
}

static std::string HostAndPort(const std::string &host, uint16_t port) {
    if (host.empty() || host.size() > 255 || port == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TCP endpoint is invalid");
    }
    // ConnectionConfig admits DNS names, IPv4 literals, and simple IPv6
    // literals. BIO requires brackets around an IPv6 address with a port.
    std::ostringstream result;
    if (host.find(':') != std::string::npos && host.front() != '[') {
        result << '[' << host << ']';
    } else {
        result << host;
    }
    result << ':' << port;
    return result.str();
}

static bool IsIpAddress(const std::string &value) {
#if defined(_WIN32)
    IN_ADDR ipv4 {};
    IN6_ADDR ipv6 {};
    return InetPtonA(AF_INET, value.c_str(), &ipv4) == 1 || InetPtonA(AF_INET6, value.c_str(), &ipv6) == 1;
#else
    in_addr ipv4 {};
    in6_addr ipv6 {};
    return inet_pton(AF_INET, value.c_str(), &ipv4) == 1 || inet_pton(AF_INET6, value.c_str(), &ipv6) == 1;
#endif
}

// The wait for one blocking step: the transport's own timeout, cut down to
// whatever is left before `deadline` when there is one. An expired deadline is
// no time at all.
static timeval StepTimeout(uint32_t timeout_seconds,
                           const std::optional<std::chrono::steady_clock::time_point> &deadline) {
    auto wait = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::seconds(timeout_seconds));
    if (deadline) {
        const auto left =
            std::chrono::duration_cast<std::chrono::microseconds>(*deadline - std::chrono::steady_clock::now());
        wait = (std::max)(std::chrono::microseconds(0), (std::min)(wait, left));
    }
    const auto count = wait.count();
    return {static_cast<decltype(timeval::tv_sec)>(count / 1000000),
            static_cast<decltype(timeval::tv_usec)>(count % 1000000)};
}

static bool WaitForBio(BIO *bio, uint32_t timeout_seconds,
                       const std::optional<std::chrono::steady_clock::time_point> &deadline) {
    int socket_fd = -1;
    if (BIO_get_fd(bio, &socket_fd) < 0 || socket_fd < 0) {
        return false;
    }
    const auto want_read = BIO_should_read(bio);
    const auto want_write = BIO_should_write(bio);
    if (!want_read && !want_write) {
        return false;
    }
    fd_set readable;
    fd_set writable;
    FD_ZERO(&readable);
    FD_ZERO(&writable);
    if (want_read) {
        FD_SET(socket_fd, &readable);
    }
    if (want_write) {
        FD_SET(socket_fd, &writable);
    }
    timeval timeout = StepTimeout(timeout_seconds, deadline);
    return select(socket_fd + 1, want_read ? &readable : nullptr, want_write ? &writable : nullptr, nullptr,
                  &timeout) > 0;
}

// Waits for the BIO's socket to become readable (or writable) until the
// deadline. Before the socket exists — the connect BIO creates it on its first
// step — there is nothing to wait on, so it naps briefly and lets the caller
// step the BIO again.
static bool WaitUntil(BIO *bio, bool for_read, std::chrono::steady_clock::time_point deadline) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
        return false;
    }
    int socket_fd = -1;
    if (BIO_get_fd(bio, &socket_fd) < 0 || socket_fd < 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        return true;
    }
    const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now).count();
    fd_set ready;
    FD_ZERO(&ready);
    FD_SET(socket_fd, &ready);
    timeval timeout {static_cast<decltype(timeval::tv_sec)>(remaining / 1000000),
                     static_cast<decltype(timeval::tv_usec)>(remaining % 1000000)};
    return select(socket_fd + 1, for_read ? &ready : nullptr, for_read ? nullptr : &ready, nullptr, &timeout) > 0;
}

std::vector<std::string> OpenSslResolveHost(const std::string &host, uint16_t port) {
#ifdef __EMSCRIPTEN__
    (void)host;
    (void)port;
    throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                        "the default Oracle resolver needs a socket library, which a WebAssembly build does not have");
#else
    BIO_ADDRINFO *resolved = nullptr;
    const auto service = std::to_string(port);
    if (BIO_lookup_ex(host.c_str(), service.c_str(), BIO_LOOKUP_CLIENT, AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP,
                      &resolved) != 1) {
        ERR_clear_error();
        throw OracleConnectError(ProtocolErrorKind::TRUNCATED, ConnectFailure::UNREACHABLE,
                                 "Oracle host name '" + host + "' did not resolve");
    }
    std::vector<std::string> result;
    for (const BIO_ADDRINFO *entry = resolved; entry; entry = BIO_ADDRINFO_next(entry)) {
        char *text = BIO_ADDR_hostname_string(BIO_ADDRINFO_address(entry), 1);
        if (text) {
            result.emplace_back(text);
            OPENSSL_free(text);
        }
    }
    BIO_ADDRINFO_free(resolved);
    return result;
#endif
}

OpenSslByteStream::OpenSslByteStream(std::unique_ptr<Impl> implementation_p)
    : implementation(std::move(implementation_p)) {
}

OpenSslByteStream::~OpenSslByteStream() {
    Close();
}

std::unique_ptr<OpenSslByteStream> OpenSslByteStream::Connect(const std::string &host, uint16_t port,
                                                               uint32_t connect_timeout_seconds,
                                                               uint32_t read_timeout_seconds, bool use_tls,
                                                               const TlsConfiguration &tls) {
#ifdef __EMSCRIPTEN__
    // A WebAssembly build has no raw TCP socket, so this transport cannot
    // connect at all. Saying that plainly, before anything is allocated, is the
    // difference between a deterministic answer and whatever the runtime
    // reports when the socket call fails. It is the *default* transport that
    // is unavailable, not the protocol: everything above ByteStream is
    // transport-agnostic, so such a build would install its own through
    // OpenOracleTransport. Note that doing so needs an answer for blocking
    // reads as well, since every TTC exchange is a synchronous request and
    // response.
    (void)host;
    (void)port;
    (void)connect_timeout_seconds;
    (void)read_timeout_seconds;
    (void)use_tls;
    (void)tls;
    throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                        "the default Oracle transport needs a TCP socket, which a WebAssembly build does not have");
#else

    if (connect_timeout_seconds == 0 || connect_timeout_seconds > 3600 || read_timeout_seconds == 0 ||
        read_timeout_seconds > 86400) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TCP timeout is outside the supported range");
    }
    auto result = std::make_unique<Impl>();
    result->read_timeout_seconds = read_timeout_seconds;
    result->use_tls = use_tls;
    const auto endpoint = HostAndPort(host, port);
    // One deadline for this attempt: the TCP connect and the TLS handshake
    // share connect_timeout_seconds between them, as they always did.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(connect_timeout_seconds);

    // TCP first, on its own BIO, driven by hand rather than by
    // BIO_do_connect_retry. That helper resets and retries a refused connect
    // until the timeout, so a listener that is down — the most common thing a
    // failover has to get past — cost the whole timeout instead of failing at
    // once and letting the next address be tried.
    result->bio = BIO_new_connect(endpoint.c_str());
    if (!result->bio) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL could not allocate a TCP BIO");
    }
    BIO_set_nbio(result->bio, 1);
    // The handshake writes, so a peer that resets mid-negotiation would raise
    // SIGPIPE here just as an ordinary write would.
    const ScopedSigPipeBlock no_sigpipe;
    while (true) {
        if (BIO_do_connect(result->bio) > 0) {
            break;
        }
        if (!BIO_should_retry(result->bio)) {
            const auto error_detail = DrainOpenSslErrors();
            throw OracleConnectError(ProtocolErrorKind::TRUNCATED, ConnectFailure::UNREACHABLE,
                                     "Oracle TCP connection to " + endpoint + " failed: " + error_detail);
        }
        if (!WaitUntil(result->bio, BIO_should_read(result->bio) != 0, deadline)) {
            ERR_clear_error();
            throw OracleConnectError(ProtocolErrorKind::TRUNCATED, ConnectFailure::UNREACHABLE,
                                     "Oracle TCP connection to " + endpoint + " timed out");
        }
    }

    if (use_tls) {
        result->context = SSL_CTX_new(TLS_client_method());
        if (!result->context) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL could not allocate a TLS context");
        }
        RequireOpenSsl(SSL_CTX_set_min_proto_version(result->context, TLS1_2_VERSION), "setting TLS minimum version");
        SSL_CTX_set_verify(result->context, SSL_VERIFY_PEER, nullptr);
        if (!tls.ca_pem_contents.empty()) {
            // An explicit trust bundle is an allow-list. Do not silently add
            // system roots, which would make an "untrusted CA" setting
            // ineffective and could broaden the caller's trust boundary.
            LoadVerifyCertificatesFromPem(result->context, tls.ca_pem_contents, "", "loading configured CA certificate");
        } else if (!tls.client_pem_contents.empty()) {
            LoadVerifyCertificatesFromPem(result->context, tls.client_pem_contents, tls.client_pem_password,
                                          "loading wallet CA certificate");
        } else if (SSL_CTX_set_default_verify_paths(result->context) != 1) {
            ERR_clear_error();
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL could not load system CA certificates");
        }
        if (!tls.client_pem_contents.empty()) {
            LoadClientIdentityFromPem(result->context, tls.client_pem_contents, tls.client_pem_password);
        }
        BIO *ssl_bio = BIO_new_ssl(result->context, 1);
        if (!ssl_bio) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL could not allocate a TLS BIO");
        }
        // From here the chain owns the TCP BIO, and freeing its head frees
        // both.
        result->bio = BIO_push(ssl_bio, result->bio);
        SSL *ssl = nullptr;
        RequireOpenSsl(BIO_get_ssl(result->bio, &ssl), "retrieving TLS session");
        if (!ssl) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL returned no TLS session");
        }
        // The connect loop dials a resolved address and passes the configured
        // host name in `tls`, so the name checked is never the IP it happened
        // to reach. A caller that passes neither gets the host it dialed.
        const auto &sni_name = tls.sni_name.empty() ? host : tls.sni_name;
        const auto &server_name = tls.server_name.empty() ? host : tls.server_name;
        if (!IsIpAddress(sni_name)) {
            RequireOpenSsl(SSL_set_tlsext_host_name(ssl, sni_name.c_str()), "setting TLS server name");
        }
        if (IsIpAddress(server_name)) {
            RequireOpenSsl(X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), server_name.c_str()),
                           "setting TLS IP verification");
        } else {
            RequireOpenSsl(SSL_set1_host(ssl, server_name.c_str()), "setting TLS hostname verification");
        }
        while (true) {
            if (BIO_do_handshake(result->bio) > 0) {
                break;
            }
            if (!BIO_should_retry(result->bio)) {
                const auto verify_result = SSL_get_verify_result(ssl);
                const auto error_detail = DrainOpenSslErrors();
                if (verify_result != X509_V_OK) {
                    // A certificate that does not verify is a fact about trust
                    // and configuration, and it is reported as such so the
                    // connect loop stops instead of trying the next address.
                    throw OracleConnectError(ProtocolErrorKind::INVALID_STATE, ConnectFailure::TLS_VERIFICATION,
                                             std::string("Oracle TLS certificate verification failed: ") +
                                                 X509_verify_cert_error_string(verify_result));
                }
                throw OracleConnectError(ProtocolErrorKind::TRUNCATED, ConnectFailure::TLS_HANDSHAKE,
                                         "Oracle TLS handshake with " + endpoint + " failed: " + error_detail);
            }
            if (!WaitUntil(result->bio, BIO_should_read(result->bio) != 0, deadline)) {
                ERR_clear_error();
                throw OracleConnectError(ProtocolErrorKind::TRUNCATED, ConnectFailure::TLS_HANDSHAKE,
                                         "Oracle TLS handshake with " + endpoint + " timed out");
            }
        }
        if (SSL_get_verify_result(ssl) != X509_V_OK) {
            throw OracleConnectError(ProtocolErrorKind::INVALID_STATE, ConnectFailure::TLS_VERIFICATION,
                                     "Oracle TLS certificate verification failed");
        }
        if (!tls.expected_server_dn.empty()) {
            CertificatePtr peer(SSL_get1_peer_certificate(ssl), X509_free);
            if (!peer) {
                throw OracleConnectError(ProtocolErrorKind::INVALID_STATE, ConnectFailure::TLS_VERIFICATION,
                                         "Oracle TLS peer sent no certificate");
            }
            const BioPtr rendered(BIO_new(BIO_s_mem()), BIO_free);
            if (!rendered ||
                X509_NAME_print_ex(rendered.get(), X509_get_subject_name(peer.get()), 0, XN_FLAG_RFC2253) < 0) {
                throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                                    "Oracle TLS peer certificate subject could not be read");
            }
            char *subject_data = nullptr;
            const auto subject_size = BIO_get_mem_data(rendered.get(), &subject_data);
            const std::string subject(subject_data, subject_data + std::max<decltype(subject_size)>(subject_size, 0));
            if (!OracleServerDnMatches(tls.expected_server_dn, subject)) {
                // The DN is never reported back: it is the thing being checked,
                // and echoing it turns a failed check into an oracle for it.
                throw OracleConnectError(ProtocolErrorKind::INVALID_STATE, ConnectFailure::TLS_VERIFICATION,
                                         "Oracle TLS server certificate subject does not match the expected DN");
            }
        }
    }
    if (BIO_get_fd(result->bio, &result->socket_fd) < 0 || result->socket_fd < 0) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL could not retrieve Oracle TCP socket");
    }
    return std::unique_ptr<OpenSslByteStream>(new OpenSslByteStream(std::move(result)));
#endif
}

namespace {

std::string Trim(const std::string &value) {
    size_t begin = 0;
    size_t end = value.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(value[begin]))) {
        begin++;
    }
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        end--;
    }
    return value.substr(begin, end - begin);
}

// Splits a DN into its `attribute=value` components. Oracle writes them
// comma-separated; a value that itself contains a comma is escaped with a
// backslash, which is the only escape this needs to honour.
std::vector<std::pair<std::string, std::string>> SplitDistinguishedName(const std::string &value) {
    std::vector<std::pair<std::string, std::string>> components;
    std::string current;
    const auto flush = [&]() {
        const auto separator = current.find('=');
        if (separator == std::string::npos) {
            components.emplace_back(std::string(), Trim(current));
            return;
        }
        auto attribute = Trim(current.substr(0, separator));
        std::transform(attribute.begin(), attribute.end(), attribute.begin(),
                       [](unsigned char character) { return static_cast<char>(std::toupper(character)); });
        components.emplace_back(std::move(attribute), Trim(current.substr(separator + 1)));
    };
    for (size_t index = 0; index < value.size(); index++) {
        if (value[index] == '\\' && index + 1 < value.size()) {
            current.push_back(value[++index]);
            continue;
        }
        if (value[index] == ',') {
            flush();
            current.clear();
            continue;
        }
        current.push_back(value[index]);
    }
    flush();
    return components;
}

} // namespace

bool OracleServerDnMatches(const std::string &expected, const std::string &actual) {
    if (expected.empty()) {
        return false;
    }
    auto expected_components = SplitDistinguishedName(expected);
    auto actual_components = SplitDistinguishedName(actual);
    if (expected_components.size() != actual_components.size()) {
        return false;
    }
    // Order is not part of the identity: OpenSSL prints the DN outermost-first
    // and Oracle's tnsnames.ora writes it the other way round, so comparing the
    // rendered strings would reject a certificate that matches.
    std::sort(expected_components.begin(), expected_components.end());
    std::sort(actual_components.begin(), actual_components.end());
    return expected_components == actual_components;
}

size_t OpenSslByteStream::Read(uint8_t *destination, size_t maximum_size) {
    if (!implementation || implementation->closed || !destination || maximum_size == 0) {
        return 0;
    }
    const auto requested = static_cast<int>((std::min)(maximum_size, static_cast<size_t>((std::numeric_limits<int>::max)())));
    while (true) {
        const auto count = BIO_read(implementation->bio, destination, requested);
        if (count > 0) {
            return static_cast<size_t>(count);
        }
        if (count == 0 && BIO_eof(implementation->bio)) {
            return 0;
        }
        if (!BIO_should_retry(implementation->bio) ||
            !WaitForBio(implementation->bio, implementation->read_timeout_seconds, implementation->deadline)) {
            ERR_clear_error();
            throw ProtocolError(ProtocolErrorKind::TRUNCATED, "Oracle TCP read failed or timed out");
        }
    }
}

size_t OpenSslByteStream::Write(const uint8_t *source, size_t size) {
    if (!implementation || implementation->closed || !source || size == 0) {
        return 0;
    }
    const ScopedSigPipeBlock no_sigpipe;
    const auto requested = static_cast<int>((std::min)(size, static_cast<size_t>((std::numeric_limits<int>::max)())));
    while (true) {
        const auto count = BIO_write(implementation->bio, source, requested);
        if (count > 0) {
            return static_cast<size_t>(count);
        }
        if (!BIO_should_retry(implementation->bio) ||
            !WaitForBio(implementation->bio, implementation->read_timeout_seconds, implementation->deadline)) {
            ERR_clear_error();
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle TCP write failed or timed out");
        }
    }
}

void OpenSslByteStream::SendUrgent(uint8_t value) {
    if (!implementation || implementation->closed) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle TCP stream is closed");
    }
    if (implementation->use_tls) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle CHECK_OOB is not supported over TCPS");
    }
#if defined(_WIN32)
    const auto sent = send(implementation->socket_fd, reinterpret_cast<const char *>(&value), 1, MSG_OOB);
    if (sent != 1) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle TCP urgent-byte send failed");
    }
#else
    const ScopedSigPipeBlock no_sigpipe;
    while (true) {
        const auto sent = send(implementation->socket_fd, &value, 1, MSG_OOB);
        if (sent == 1) {
            return;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            fd_set writable;
            FD_ZERO(&writable);
            FD_SET(implementation->socket_fd, &writable);
            timeval timeout = StepTimeout(implementation->read_timeout_seconds, implementation->deadline);
            if (select(implementation->socket_fd + 1, nullptr, &writable, nullptr, &timeout) > 0) {
                continue;
            }
        }
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle TCP urgent-byte send failed");
    }
#endif
}

void OpenSslByteStream::SetDeadline(std::optional<std::chrono::steady_clock::time_point> deadline) {
    if (implementation) {
        implementation->deadline = deadline;
    }
}

void OpenSslByteStream::Close() {
    if (implementation) {
        implementation->closed = true;
        // Freeing the BIO can drive a TLS shutdown, which is a write like any
        // other and so can meet a peer that has already gone.
        const ScopedSigPipeBlock no_sigpipe;
        implementation.reset();
    }
}

} // namespace oracle_scanner

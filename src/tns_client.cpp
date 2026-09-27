#include "oracle_scanner/tns_client.hpp"
#include "oracle_scanner/auth_crypto.hpp"
#include "oracle_scanner/client_identity.hpp"
#include "oracle_scanner/connect_error.hpp"
#include "oracle_scanner/connect_plan.hpp"
#include "oracle_scanner/descriptor_parser.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/transport_factory.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace oracle_scanner {

namespace {

void RunCheckOobProbe(ByteStream &stream, uint16_t negotiated_sdu) {
    stream.SendUrgent(0x21);
    TnsPacketStream packets(stream, true, negotiated_sdu);
    // Current Thin clients use the reset-form marker to finish the OOB
    // check. The listener's CONTROL response is only meaningful after this
    // exact marker shape.
    packets.Send({TnsPacketType::MARKER, 0, {0x01, 0x00, 0x02}});
    const auto reply = packets.Receive();
    // The two-byte CONTROL body is listener-version dependent (19c emits a
    // different value than newer Free builds); it is an acknowledgement, not
    // a negotiated value. Its exact width and framing are the contract.
    if (reply.type != TnsPacketType::CONTROL || reply.flags != 0x20 || reply.payload.size() != 2) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "Oracle CHECK_OOB probe returned invalid CONTROL reply (type " +
                                std::to_string(static_cast<uint8_t>(reply.type)) + ", flags " +
                                std::to_string(reply.flags) + ", payload bytes " + std::to_string(reply.payload.size()) + ")");
    }
}


std::string DescribeAddress(const ConnectAddress &address) {
    const auto host = address.host.find(':') != std::string::npos ? "[" + address.host + "]" : address.host;
    return host + ":" + std::to_string(address.port) + (address.protocol == TransportProtocol::TCPS ? "/tcps" : "");
}

std::string AddressKey(const ConnectAddress &address) {
    std::string host = address.host;
    std::transform(host.begin(), host.end(), host.begin(),
                   [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    return host + ":" + std::to_string(address.port);
}

constexpr size_t MAX_LISTED_ATTEMPTS = 16;
constexpr size_t MAX_ATTEMPT_TEXT = 240;

// What each attempt did, for the error a failed connect finally reports. It
// names addresses and outcomes; it never holds a credential, and connect data
// is not recorded at all.
class ConnectAttemptLog {
public:
    void Add(const ConnectAddress &target, const std::string &dialed, const std::string &outcome) {
        total++;
        if (entries.size() == MAX_LISTED_ATTEMPTS) {
            return;
        }
        auto entry = DescribeAddress(target);
        if (!dialed.empty() && dialed != target.host) {
            entry += " [" + dialed + "]";
        }
        entry += ": " + outcome;
        if (entry.size() > MAX_ATTEMPT_TEXT) {
            entry = entry.substr(0, MAX_ATTEMPT_TEXT) + "...";
        }
        entries.push_back(std::move(entry));
    }
    void AddFailure(const ConnectAddress &target, const std::string &dialed, const OracleConnectError &error) {
        Add(target, dialed, std::string(ConnectFailureName(error.Failure())) + " (" + error.what() + ")");
    }
    size_t Total() const {
        return total;
    }
    std::string Render() const {
        std::string result;
        for (size_t index = 0; index < entries.size(); index++) {
            result += (index == 0 ? "" : "; ") + std::to_string(index + 1) + ") " + entries[index];
        }
        if (total > entries.size()) {
            result += "; and " + std::to_string(total - entries.size()) + " more";
        }
        return result;
    }

private:
    std::vector<std::string> entries;
    size_t total = 0;
};

void CloseQuietly(std::unique_ptr<ByteStream> &stream) noexcept {
    if (!stream) {
        return;
    }
    try {
        stream->Close();
    } catch (...) {
    }
    stream.reset();
}

// What bounds one physical connect: its clock, its deadline, and who may
// cancel it. Shared rather than owned by the connect loop, because the limits
// have to outlive it — they keep holding through TTC negotiation and
// authentication, which run after the loop has returned an accepted stream.
struct ConnectLimits {
    OracleConnectEnvironment environment;
    std::chrono::steady_clock::time_point deadline;
    uint32_t budget_seconds = 0;
    std::function<bool()> cancelled;

    void CheckCancelled() const {
        if (OracleConnectCancelled() || (cancelled && cancelled())) {
            throw OracleConnectError(ProtocolErrorKind::INVALID_STATE, ConnectFailure::CANCELLED,
                                     "Oracle connect was cancelled");
        }
    }
    void CheckBudget(const std::string &when) const {
        if (environment.now() >= deadline) {
            throw OracleConnectError(ProtocolErrorKind::TRUNCATED, ConnectFailure::BUDGET_EXHAUSTED,
                                     "Oracle connect budget of " + std::to_string(budget_seconds) + " s ran out " +
                                         when);
        }
    }
};

// The stream a connection is established through. From the first CONNECT to
// the end of authentication it checks the overall deadline and cancellation
// around every read and write, and it has passed the deadline on to the
// transport so a blocking wait is cut short too. Without it the budget was
// consulted only between attempts, and then only up to ACCEPT: a listener that
// answered slowly, a byte at a time, or a server that accepted and then said
// nothing during negotiation or O5LOGON, all ran on past it.
//
// Disarm, once the session is authenticated, turns it into a plain pass-through
// and lifts the transport deadline: an established session is bounded by its
// read timeout, not by how long connecting was allowed to take.
class EstablishmentStream final : public ByteStream {
public:
    EstablishmentStream(std::unique_ptr<ByteStream> inner_p, std::shared_ptr<const ConnectLimits> limits_p)
        : inner(std::move(inner_p)), limits(std::move(limits_p)) {
        inner->SetDeadline(limits->deadline);
    }
    size_t Read(uint8_t *destination, size_t maximum_size) override {
        return Guard([&] { return inner->Read(destination, maximum_size); });
    }
    size_t Write(const uint8_t *source, size_t size) override {
        return Guard([&] { return inner->Write(source, size); });
    }
    void SendUrgent(uint8_t value) override {
        Guard([&] {
            inner->SendUrgent(value);
            return size_t(0);
        });
    }
    void SetDeadline(std::optional<std::chrono::steady_clock::time_point> deadline) override {
        inner->SetDeadline(deadline);
    }
    void Close() override {
        inner->Close();
    }
    void Disarm() {
        if (armed) {
            armed = false;
            inner->SetDeadline(std::nullopt);
        }
    }

private:
    void Check() const {
        limits->CheckCancelled();
        limits->CheckBudget("before the connection was ready");
    }

    template <class FUNCTION>
    size_t Guard(FUNCTION function) {
        if (!armed) {
            return function();
        }
        Check();
        size_t result = 0;
        try {
            result = function();
        } catch (const OracleConnectError &) {
            throw;
        } catch (const ProtocolError &) {
            // A wait the transport cut short at the deadline reports as a
            // failed read; say what it really was.
            Check();
            throw;
        }
        Check();
        return result;
    }

    std::unique_ptr<ByteStream> inner;
    std::shared_ptr<const ConnectLimits> limits;
    bool armed = true;
};

// The single, bounded loop that turns a configuration into one accepted
// transport. It is iterative on purpose — redirects included — so every bound
// (passes, addresses, resolved IPs, redirect hops, transport opens, time) is a
// counter or a deadline checked in one place rather than a recursion depth.
//
// Only this phase is ever retried: reaching a listener and getting ACCEPT. TTC
// negotiation and authentication run after it returns and are never repeated,
// and nothing here survives into an established session, so a session lost
// later fails its operation instead of being silently re-established.
class ConnectRun {
public:
    struct Accepted {
        std::unique_ptr<ByteStream> stream;
        // Owned by `stream`; disarmed by the connection once authenticated.
        EstablishmentStream *establishment = nullptr;
        TnsConnectResult result;
        std::string descriptor;
        ConnectAddress original;
    };

    ConnectRun(const ConnectionConfig &config_p, const TlsConfiguration &tls_p)
        : config(config_p), tls(tls_p), environment(CurrentOracleConnectEnvironment()) {
        deadline = environment.now() + std::chrono::seconds(EffectiveConnectBudgetSeconds(config));
        auto shared = std::make_shared<ConnectLimits>();
        shared->environment = environment;
        shared->deadline = deadline;
        shared->budget_seconds = EffectiveConnectBudgetSeconds(config);
        shared->cancelled = config.connect_cancelled;
        limits = std::move(shared);
    }

    Accepted Run() {
        const auto order = PlanConnectOrder(config, environment.random);
        std::optional<OracleConnectError> last;
        try {
            for (uint32_t pass = 0; pass <= config.routing.retry_count; pass++) {
                if (pass > 0) {
                    Delay();
                }
                for (const auto &original : order) {
                    try {
                        return DialOriginal(original);
                    } catch (const OracleConnectError &error) {
                        if (!ConnectFailureAllowsFailover(error.Failure())) {
                            throw;
                        }
                        last = error;
                    }
                }
            }
        } catch (const OracleConnectError &error) {
            throw Final(error);
        } catch (const ProtocolError &error) {
            throw Final(OracleConnectError(error.Kind(), ConnectFailure::PROTOCOL, error.what()));
        }
        if (!last) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle connect planned no attempt");
        }
        throw Final(*last);
    }

private:
    // One level of a redirect chain: the addresses one listener named (or, at
    // the root, the one configured address), how far through them the chain
    // has got, and what to send them. A level stays on the stack while any of
    // its addresses is untried, so when a deeper branch fails the chain
    // resumes here instead of losing the alternatives.
    struct Level {
        std::vector<ConnectAddress> targets;
        size_t next_target = 0;
        std::vector<std::string> addresses;
        size_t next_address = 0;
        std::string reconnect_data;
        uint8_t packet_flags = 0;
        size_t depth = 0;
    };

    // One configured address: each address its name resolves to, in turn,
    // each followed through whatever redirects its listener answers with.
    Accepted DialOriginal(const ConnectAddress &original) {
        std::vector<std::string> resolved;
        try {
            resolved = Resolve(original);
        } catch (const OracleConnectError &error) {
            attempts.AddFailure(original, std::string(), error);
            throw;
        }
        std::optional<OracleConnectError> last;
        for (const auto &address : resolved) {
            try {
                return FollowChain(original, address);
            } catch (const OracleConnectError &error) {
                if (!ConnectFailureAllowsFailover(error.Failure())) {
                    throw;
                }
                last = error;
            }
        }
        if (!last) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle host resolved to no address");
        }
        throw *last;
    }

    // One chain, from one resolved address of a configured one, through every
    // redirect its listeners answer with. The levels form a stack: a redirect
    // pushes the addresses the listener named, and a level whose addresses
    // are all spent is popped, which resumes the level above at its next
    // address. Only when the root is spent has the chain failed, and then the
    // caller moves on to the next resolved or configured address.
    Accepted FollowChain(const ConnectAddress &original, const std::string &first_address) {
        // Every hop is checked against the name the user configured for this
        // attempt, never against a host a listener named. See
        // ConnectionConfig::tls_server_name.
        auto attempt_tls = tls;
        if (attempt_tls.server_name.empty()) {
            attempt_tls.server_name = original.host;
        }
        if (attempt_tls.sni_name.empty()) {
            attempt_tls.sni_name = original.host;
        }
        std::vector<Level> stack(1);
        stack[0].targets = {original};
        stack[0].next_target = 1;
        stack[0].addresses = {first_address};
        std::optional<OracleConnectError> last;
        size_t last_depth = 0;
        const auto remember = [&](const OracleConnectError &error, size_t depth) {
            if (!ConnectFailureAllowsFailover(error.Failure())) {
                throw error;
            }
            last = error;
            last_depth = depth;
        };
        while (!stack.empty()) {
            auto &level = stack.back();
            if (level.next_address == level.addresses.size()) {
                if (level.next_target == level.targets.size()) {
                    stack.pop_back();
                    continue;
                }
                const auto target = level.targets[level.next_target++];
                level.addresses.clear();
                level.next_address = 0;
                try {
                    level.addresses = Resolve(target);
                } catch (const OracleConnectError &error) {
                    attempts.AddFailure(target, std::string(), error);
                    remember(error, level.depth);
                }
                continue;
            }
            // Copied out: pushing a level below invalidates `level`.
            const auto target = level.targets[level.next_target - 1];
            const auto address = level.addresses[level.next_address++];
            const auto depth = level.depth;
            const auto packet_flags = level.packet_flags;
            const auto descriptor =
                level.reconnect_data.empty() ? BuildConnectDescriptor(config, target) : level.reconnect_data;

            BeforeAttempt();
            std::unique_ptr<ByteStream> stream;
            try {
                stream = OpenOracleTransport(address, target.port, AttemptTimeoutSeconds(), config.read_timeout_seconds,
                                             target.protocol == TransportProtocol::TCPS, attempt_tls);
            } catch (const OracleConnectError &error) {
                attempts.AddFailure(target, address, error);
                remember(error, depth);
                continue;
            } catch (const ProtocolError &error) {
                // An installed transport may report a failed open as a plain
                // truncation; that is still an unreachable address.
                if (error.Kind() != ProtocolErrorKind::TRUNCATED) {
                    attempts.Add(target, address, std::string("transport error (") + error.what() + ")");
                    throw;
                }
                const OracleConnectError unreachable(ProtocolErrorKind::TRUNCATED, ConnectFailure::UNREACHABLE,
                                                     error.what());
                attempts.AddFailure(target, address, unreachable);
                remember(unreachable, depth);
                continue;
            }
            auto *establishment = new EstablishmentStream(std::move(stream), limits);
            stream.reset(establishment);
            TnsConnectResult result;
            try {
                TnsPacketStream handshake(*stream, false);
                TnsConnectOptions options;
                options.supports_oob = target.protocol != TransportProtocol::TCPS;
                options.packet_flags = packet_flags;
                result = RunTnsConnect(handshake, descriptor, options);
            } catch (const OracleConnectError &error) {
                CloseQuietly(stream);
                attempts.AddFailure(target, address, error);
                remember(error, depth);
                continue;
            } catch (const ProtocolError &error) {
                // Lost I/O was already turned into TRANSPORT_LOST by
                // RunTnsConnect; anything else is the listener's answer not
                // making sense, and another listener is not asked.
                CloseQuietly(stream);
                attempts.Add(target, address, std::string("protocol error (") + error.what() + ")");
                throw;
            }
            if (result.disposition == TnsConnectDisposition::ACCEPTED) {
                return Accept(std::move(stream), *establishment, result, descriptor, original, target, address);
            }
            CloseQuietly(stream);
            std::vector<ConnectAddress> next;
            try {
                next = FollowRedirect(target, result.redirect, depth, stack);
            } catch (const OracleConnectError &error) {
                attempts.AddFailure(target, address, error);
                remember(error, depth);
                continue;
            } catch (const ProtocolError &error) {
                attempts.Add(target, address, std::string("unusable redirect (") + error.what() + ")");
                throw;
            }
            // What was parsed, never what was received: the listener's text
            // can carry its whole CONNECT_DATA, which is not diagnostics.
            std::string named;
            for (const auto &hop : next) {
                named += (named.empty() ? "" : ", ") + DescribeAddress(hop);
            }
            attempts.Add(target, address, "redirected to " + named);
            Level below;
            below.targets = std::move(next);
            below.reconnect_data = result.redirect.reconnect_data;
            below.packet_flags = TNS_PACKET_FLAG_REDIRECT;
            below.depth = depth + 1;
            stack.push_back(std::move(below));
        }
        if (!last) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle redirect chain had no address");
        }
        if (last_depth == 0) {
            throw *last;
        }
        throw OracleConnectError(last->Kind(), ConnectFailure::REDIRECT_FAILED,
                                 std::string("every address the Oracle listener redirected to failed: ") + last->what(),
                                 last->OracleErrorCode());
    }

    // ACCEPT is not yet a connection: the CHECK_OOB probe still talks to the
    // listener, and the budget and cancellation are checked once more before
    // the stream is handed over. It is handed over still armed — TTC
    // negotiation and O5LOGON run within the same budget, and the connection
    // disarms it only once authenticated.
    Accepted Accept(std::unique_ptr<ByteStream> stream, EstablishmentStream &establishment,
                    const TnsConnectResult &result,
                    const std::string &descriptor, const ConnectAddress &original, const ConnectAddress &target,
                    const std::string &address) {
        try {
            if (result.check_oob) {
                RunCheckOobProbe(*stream, result.negotiated_sdu);
            }
            CheckCancelled();
            CheckBudget("before the accepted connection was handed over");
        } catch (const OracleConnectError &error) {
            CloseQuietly(stream);
            attempts.AddFailure(target, address, error);
            throw;
        } catch (...) {
            CloseQuietly(stream);
            throw;
        }
        return {std::move(stream), &establishment, result, descriptor, original};
    }

    // Validates one REDIRECT and returns the next level's addresses. Throws
    // for a redirect that must not be followed. A cycle is judged against the
    // path the chain actually took to get here — the current address of every
    // level on the stack — not against every address any listener offered,
    // which would call a sibling branch a loop.
    std::vector<ConnectAddress> FollowRedirect(const ConnectAddress &from, const TnsRedirect &redirect, size_t depth,
                                               const std::vector<Level> &stack) {
        if (depth + 1 > MAX_CONNECT_REDIRECTS) {
            throw OracleConnectError(ProtocolErrorKind::INVALID_STATE, ConnectFailure::REDIRECT_FAILED,
                                     "Oracle listener exceeded the redirect limit of " +
                                         std::to_string(MAX_CONNECT_REDIRECTS));
        }
        const auto redirected = ParseRedirectAddresses(redirect.address);
        if (!redirect.reconnect_data.empty()) {
            ValidateRedirectReconnectData(redirect.reconnect_data);
        }
        std::set<std::string> path;
        for (const auto &level : stack) {
            path.insert(AddressKey(level.targets[level.next_target - 1]));
        }
        std::vector<ConnectAddress> next;
        for (const auto &candidate : redirected) {
            auto address = candidate.address;
            if (!candidate.protocol_given) {
                address.protocol = from.protocol;
            } else if (address.protocol != from.protocol) {
                // Never TCPS to TCP, and not the other way either: the
                // protocol is the user's choice, and a listener naming another
                // one is refused rather than obeyed. python-oracledb keeps the
                // original protocol across a redirect as well.
                throw OracleConnectError(
                    ProtocolErrorKind::INVALID_STATE, ConnectFailure::PROTOCOL,
                    from.protocol == TransportProtocol::TCPS
                        ? "Oracle listener redirected a TCPS connection to TCP; refusing to downgrade"
                        : "Oracle listener redirected a TCP connection to TCPS; the protocol cannot change on a "
                          "redirect");
            }
            if (path.count(AddressKey(address)) != 0) {
                continue;
            }
            next.push_back(std::move(address));
        }
        if (next.empty()) {
            throw OracleConnectError(ProtocolErrorKind::INVALID_STATE, ConnectFailure::REDIRECT_FAILED,
                                     "Oracle listener redirect loops back to an address already on its path");
        }
        return next;
    }

    // Name resolution within the budget. The platform resolver has no timeout
    // of its own, so the lookup runs on the bounded resolver pool and this
    // waits for it in slices, checking the budget and cancellation; a lookup
    // given up on is dropped if it has not started, and otherwise finishes on
    // its worker, harmlessly.
    std::vector<std::string> Resolve(const ConnectAddress &target) {
        CheckCancelled();
        CheckBudget("before resolving " + target.host);
        if (IsIpLiteral(target.host)) {
            return {target.host};
        }
        const auto when = "while resolving " + target.host;
        auto result = ResolveOracleHostOnPool(
            target.host, target.port,
            [&] {
                CheckCancelled();
                CheckBudget(when);
            },
            [&] { return std::chrono::duration_cast<std::chrono::milliseconds>(deadline - environment.now()); });
        CheckBudget(when);
        return result;
    }

    void CheckCancelled() const {
        limits->CheckCancelled();
    }

    void CheckBudget(const std::string &when) const {
        limits->CheckBudget(when);
    }

    void BeforeAttempt() {
        CheckCancelled();
        CheckBudget("before the next attempt");
        if (++transport_opens > MAX_CONNECT_TRANSPORT_OPENS) {
            throw OracleConnectError(ProtocolErrorKind::TRUNCATED, ConnectFailure::BUDGET_EXHAUSTED,
                                     "Oracle connect reached its limit of " +
                                         std::to_string(MAX_CONNECT_TRANSPORT_OPENS) + " transport attempts");
        }
    }

    // The per-attempt transport timeout, cut down to what is left of the
    // overall budget. A transport takes whole seconds, so this rounds up, and
    // the TCP connect or TLS handshake is the one wait that may run past the
    // budget — by less than a second. Everything after it runs under
    // SetDeadline and DeadlineStream.
    uint32_t AttemptTimeoutSeconds() const {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - environment.now()).count();
        const auto remaining_seconds =
            static_cast<uint64_t>((std::max)(remaining, decltype(remaining)(1)) + 999) / 1000;
        return static_cast<uint32_t>(
            (std::min)(static_cast<uint64_t>(config.connect_timeout_seconds), remaining_seconds));
    }

    // RETRY_DELAY, spent in slices so that cancellation is noticed, and never
    // past the budget: a delay that would end after it ends the connect now.
    void Delay() {
        const auto delay = std::chrono::milliseconds(uint64_t(config.routing.retry_delay_seconds) * 1000U);
        CheckCancelled();
        if (environment.now() + delay >= deadline) {
            throw OracleConnectError(ProtocolErrorKind::TRUNCATED, ConnectFailure::BUDGET_EXHAUSTED,
                                     "Oracle connect budget of " +
                                         std::to_string(EffectiveConnectBudgetSeconds(config)) +
                                         " s leaves no room for RETRY_DELAY");
        }
        const auto end = environment.now() + delay;
        while (environment.now() < end) {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(end - environment.now());
            environment.sleep((std::min)(left, std::chrono::milliseconds(100)));
            CheckCancelled();
        }
    }

    // The error a failed connect reports. A connect that made one attempt
    // reports that attempt's error unchanged; one that made several says how
    // many and lists them, keeping the last failure's kind and ORA- code.
    OracleConnectError Final(const OracleConnectError &error) const {
        if (attempts.Total() <= 1) {
            return error;
        }
        return OracleConnectError(error.Kind(), error.Failure(),
                                  "Oracle could not connect after " + std::to_string(attempts.Total()) +
                                      " attempts: " + error.what() + ". Attempts: " + attempts.Render(),
                                  error.OracleErrorCode());
    }

    const ConnectionConfig &config;
    const TlsConfiguration &tls;
    OracleConnectEnvironment environment;
    std::chrono::steady_clock::time_point deadline;
    std::shared_ptr<const ConnectLimits> limits;
    ConnectAttemptLog attempts;
    size_t transport_opens = 0;
};

} // namespace

TnsClientConnection::TnsClientConnection(std::unique_ptr<ByteStream> stream_p, uint16_t negotiated_sdu_p,
                                         std::string connect_descriptor_p, std::string auth_connect_string_p,
                                         OracleClientIdentity client_identity_p, bool cancellation_supported,
                                         bool end_of_response_negotiated_p)
    : stream(std::move(stream_p)), packets(std::make_unique<TnsPacketStream>(*stream, true, negotiated_sdu_p)),
      ttc(std::make_unique<TtcChannel>(*packets, negotiated_sdu_p, 16U << 20U, cancellation_supported)),
      negotiated_sdu(negotiated_sdu_p), end_of_response_negotiated(end_of_response_negotiated_p),
      connect_descriptor(std::move(connect_descriptor_p)), auth_connect_string(std::move(auth_connect_string_p)),
      client_identity(std::move(client_identity_p)) {
}

TnsClientConnection::~TnsClientConnection() {
    Close();
}

std::unique_ptr<TnsClientConnection> TnsClientConnection::Connect(const ConnectionConfig &config,
                                                                   const TlsConfiguration &tls) {
    ValidateConnectionConfig(config);
    // Per physical connection, and never written back: the caller's config —
    // a pool's, say — stays exactly what it was, so the next connection plans
    // from the original addresses rather than from wherever this one went.
    auto effective_config = config;
    if (effective_config.connection_id.empty()) {
        effective_config.connection_id = Base64Encode(SecureRandomBytes(16));
    }
    if (effective_config.client_program.empty()) {
        effective_config.client_program = CurrentExecutablePath();
    }
    ConnectRun run(effective_config, tls);
    auto accepted = run.Run();
    const auto uses_tls = accepted.original.protocol == TransportProtocol::TCPS;
    auto *establishment = accepted.establishment;
    // AUTH_CONNECT_STRING names the logical target the user configured — the
    // original address and the original CONNECT_DATA — even when a listener
    // redirected the transport elsewhere. python-oracledb sends its original
    // connect string there too; the listener-facing CONNECT carried the
    // redirect's own data.
    auto connection = std::unique_ptr<TnsClientConnection>(new TnsClientConnection(
        std::move(accepted.stream), accepted.result.negotiated_sdu, accepted.descriptor,
        BuildAuthConnectString(effective_config, accepted.original),
        CurrentOracleClientIdentity(effective_config.client_program), !uses_tls, accepted.result.end_of_response));
    // The connect budget and cancellation keep holding through TTC negotiation
    // and O5LOGON, and are lifted when authentication completes.
    connection->end_establishment = [establishment] { establishment->Disarm(); };
    return connection;
}

void TnsClientConnection::EndEstablishment() {
    if (end_establishment) {
        end_establishment();
        end_establishment = nullptr;
    }
}

TnsPacketStream &TnsClientConnection::Packets() {
    if (!packets) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle TNS connection is closed");
    }
    return *packets;
}

TtcChannel &TnsClientConnection::Ttc() {
    if (!ttc) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle TTC connection is closed");
    }
    return *ttc;
}

uint16_t TnsClientConnection::NegotiatedSdu() const {
    return negotiated_sdu;
}

uint8_t TnsClientConnection::TtcFieldVersion() const {
    return ttc_field_version;
}

uint8_t TnsClientConnection::TtcServerFieldVersion() const {
    return ttc_server_field_version;
}

bool TnsClientConnection::EndOfResponseNegotiated() const {
    return end_of_response_negotiated;
}

OracleConnectionState TnsClientConnection::State() const {
    return state;
}

TtcProtocolInfo TnsClientConnection::Negotiate(const TtcNegotiationOptions &options) {
    if (state != OracleConnectionState::TRANSPORT_CONNECTED) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "TTC negotiation is not valid in the current connection state");
    }
    auto result = RunTtcNegotiation(Ttc(), options);
    ttc_field_version = result.field_version;
    ttc_server_field_version = result.server_field_version;
    state = OracleConnectionState::TTC_NEGOTIATED;
    return result;
}

O5LogonResponse TnsClientConnection::AuthenticateO5Logon(const std::string &username, const std::string &password,
                                                          uint32_t auth_mode,
                                                          const std::vector<TtcParameter> &phase_one_parameters) {
    if (state != OracleConnectionState::TTC_NEGOTIATED) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "O5LOGON requires completed TTC negotiation");
    }
    O5LogonRequest request;
    request.username = username;
    request.password = password;
    request.auth_mode = auth_mode;
    request.phase_one_parameters = phase_one_parameters;
    if (request.phase_one_parameters.empty()) {
        request.phase_one_parameters = {{"AUTH_TERMINAL", client_identity.terminal, 0},
                                        {"AUTH_PROGRAM_NM", client_identity.program, 0},
                                        {"AUTH_MACHINE", client_identity.machine, 0},
                                        {"AUTH_PID", client_identity.process_id, 0},
                                        {"AUTH_SID", client_identity.os_user, 0}};
    }
    request.phase_two_parameters = {{"SESSION_CLIENT_CHARSET", "873", 0},
                                    {"SESSION_CLIENT_DRIVER_NAME", "python-oracledb thn : 4.0.1", 0},
                                    // Oracle's authentication parser retains the NUL terminator as part of this value.
                                    {"SESSION_CLIENT_VERSION", "67112960", 0},
                                    {"AUTH_ALTER_SESSION",
                                     std::string("ALTER SESSION SET TIME_ZONE='+04:00'\0",
                                                 sizeof("ALTER SESSION SET TIME_ZONE='+04:00'\0") - 1),
                                     1},
                                    {"AUTH_CONNECT_STRING", auth_connect_string, 0}};
    request.client_session_key = SecureRandomBytes(32);
    request.password_salt = SecureRandomBytes(16);
    request.speedy_key_salt = SecureRandomBytes(16);
    auto result = RunO5Logon(Ttc(), request);
    state = OracleConnectionState::AUTHENTICATED;
    EndEstablishment();
    return result;
}

void TnsClientConnection::Close() {
    // The callback points into the stream about to be freed; drop it first, so
    // EndEstablishment after Close is a no-op rather than a use after free.
    end_establishment = nullptr;
    ttc.reset();
    packets.reset();
    if (stream) {
        stream->Close();
        stream.reset();
    }
    state = OracleConnectionState::CLOSED;
}

} // namespace oracle_scanner

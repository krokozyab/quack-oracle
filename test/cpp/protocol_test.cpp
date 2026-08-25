// Before any include. Windows defines min and max as function-like macros,
// and the headers this pulls in reach <windows.h> — so `(std::min)(...)` is
// rewritten by the preprocessor and the file stops compiling, with the brace
// counting going wrong several lines later as a consequence.
#if defined(_WIN32) && !defined(NOMINMAX)
#define NOMINMAX
#endif

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if !defined(_WIN32)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <functional>
#include <thread>

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/byte_stream.hpp"
#include "oracle_scanner/auth_crypto.hpp"
#include "oracle_scanner/call_registry.hpp"
#include "oracle_scanner/call_builder.hpp"
#include "oracle_scanner/bind_validation.hpp"
#include "oracle_scanner/sql_binds.hpp"
#include "oracle_scanner/sql_statement.hpp"
#include "oracle_scanner/validating_session.hpp"
#include "oracle_scanner/statement_registry.hpp"
#include "oracle_scanner/connect_descriptor.hpp"
#include "oracle_scanner/client_identity.hpp"
#include "oracle_scanner/data_assembler.hpp"
#include "oracle_scanner/descriptor_parser.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/tns_packet.hpp"
#include "oracle_scanner/tns_connect.hpp"
#include "oracle_scanner/tns_handshake.hpp"
#include "oracle_scanner/tns_client.hpp"
#include "oracle_scanner/transport_factory.hpp"
#include "oracle_scanner/ttc_channel.hpp"
#include "oracle_scanner/ttc_error.hpp"
#include "oracle_scanner/ttc_parameter.hpp"
#include "oracle_scanner/ttc_auth.hpp"
#include "oracle_scanner/ttc_fetch.hpp"
#include "oracle_scanner/ttc_piggyback.hpp"
#include "oracle_scanner/ttc_transaction.hpp"
#include "oracle_scanner/native_session.hpp"
#include "oracle_scanner/ttc_fetch_response.hpp"
#include "oracle_scanner/ttc_lob.hpp"
#include "oracle_scanner/ttc_describe.hpp"
#include "oracle_scanner/ttc_execute_response.hpp"
#include "oracle_scanner/ttc_cursor.hpp"
#include "oracle_scanner/ttc_call_response.hpp"
#include "oracle_scanner/ttc_io_vector.hpp"
#include "oracle_scanner/ttc_out_binds.hpp"
#include "oracle_scanner/ttc_execute.hpp"
#include "oracle_scanner/ttc_statement_channel.hpp"
#include "oracle_scanner/ttc_row_data.hpp"
#include "oracle_scanner/ttc_negotiation.hpp"
#include "oracle_scanner/ttc_o5logon.hpp"
#include "oracle_scanner/transaction.hpp"
#include "oracle_scanner/session_factory.hpp"
#include "oracle_scanner/session_pool.hpp"
#include "oracle_scanner/value_codec.hpp"
#include "oracle_scanner/sso_wallet.hpp"
#include "oracle_scanner/wallet_archive.hpp"

#include "miniz.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <csignal>
#if !defined(_WIN32)
#include <pthread.h>
#endif
#include <cstdlib>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <deque>
#include <vector>

// A release build defines NDEBUG, and assert() then removes not just the check
// but everything inside it — including the call being checked. A suite written
// with assert therefore stops testing the moment it is built for release, which
// is exactly the build nothing here ever ran. CHECK always evaluates its
// expression and always reports, so the two builds test the same thing.
[[noreturn]] static void CheckFailed(const char *expression, const char *file, int line) {
    std::cerr << file << ":" << line << ": check failed: " << expression << std::endl;
    std::abort();
}

#define CHECK(expression)                                                                                              \
    do {                                                                                                               \
        if (!(expression)) {                                                                                           \
            CheckFailed(#expression, __FILE__, __LINE__);                                                              \
        }                                                                                                              \
    } while (0)

using namespace oracle_scanner;
using namespace duckdb_miniz;

template <class FUNCTION>
static void ExpectError(ProtocolErrorKind kind, FUNCTION function) {
    try {
        function();
        CHECK(false && "expected ProtocolError");
    } catch (const ProtocolError &error) {
        CHECK(error.Kind() == kind);
    }
}

template <class FUNCTION>
static void ExpectProtocolError(FUNCTION function) {
    try {
        function();
        CHECK(false && "expected ProtocolError");
    } catch (const ProtocolError &) {
    }
}

static void TestUniversalIntegers() {
    ByteWriter writer;
    writer.WriteUB4(0).WriteUB4(255).WriteUB4(256).WriteUB4(0x12345678).WriteUB8(UINT64_C(0x123456789abcdef0));
    ByteReader reader(writer.Data());
    CHECK(reader.ReadUB4() == 0);
    CHECK(reader.ReadUB4() == 255);
    CHECK(reader.ReadUB4() == 256);
    CHECK(reader.ReadUB4() == 0x12345678);
    CHECK(reader.ReadUB8() == UINT64_C(0x123456789abcdef0));
    CHECK(reader.Remaining() == 0);

    ExpectError(ProtocolErrorKind::MALFORMED, [] { ByteReader(std::vector<uint8_t> {0x81, 0}).ReadUB4(); });
    ExpectError(ProtocolErrorKind::TRUNCATED, [] { ByteReader(std::vector<uint8_t> {4, 1, 2}).ReadUB4(); });
}

// Every call here does the work; none of it may sit inside an assert, which a
// release build removes along with the call. This whole helper used to write
// its archive from inside asserts, so with NDEBUG it produced an empty file and
// the wallet tests failed on a build nothing ever ran them in.
static std::string WriteWalletArchiveForTest(const std::string &path,
                                             const std::vector<std::pair<std::string, std::string>> &entries) {
    mz_zip_archive archive {};
    mz_zip_zero_struct(&archive);
    const auto initialized = mz_zip_writer_init_heap(&archive, 0, 0);
    CHECK(initialized);
    (void)initialized;
    for (const auto &entry : entries) {
        const auto added =
            mz_zip_writer_add_mem(&archive, entry.first.c_str(), entry.second.data(), entry.second.size(), 0);
        CHECK(added);
        (void)added;
    }
    void *archive_data = nullptr;
    size_t archive_size = 0;
    const auto finalized = mz_zip_writer_finalize_heap_archive(&archive, &archive_data, &archive_size);
    CHECK(finalized);
    (void)finalized;
    const auto ended = mz_zip_writer_end(&archive);
    CHECK(ended);
    (void)ended;
    std::ofstream output(path, std::ios::binary);
    CHECK(output);
    output.write(static_cast<const char *>(archive_data), static_cast<std::streamsize>(archive_size));
    output.close();
    mz_free(archive_data);
    return path;
}

// The temporary directory, honouring TMPDIR where a runner sets one. Hardcoding
// a path is not portable: `/private/tmp` is where macOS actually keeps /tmp, and
// it does not exist on Linux at all, so a wallet written there could not be
// reopened and the suite aborted on the first archive test.
static std::string TemporaryDirectory() {
    if (const auto *configured = std::getenv("TMPDIR")) {
        std::string directory(configured);
        while (directory.size() > 1 && directory.back() == '/') {
            directory.pop_back();
        }
        if (!directory.empty()) {
            return directory;
        }
    }
    return "/tmp";
}

static void TestWalletArchive() {
    const auto base = TemporaryDirectory() + "/oracle_scanner_wallet_archive_" +
                      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const auto pem_path = base + ".pem";
    const auto zip_path = base + ".zip";
    const auto missing_path = base + "_missing.zip";
    const auto duplicate_path = base + "_duplicate.zip";
    const auto duplicate_tnsnames_path = base + "_duplicate_tnsnames.zip";
    const auto corrupt_path = base + "_corrupt.zip";
    const auto nested_path = base + "_nested.zip";
    const auto oversized_path = base + "_oversized.zip";
    const auto oversized_pem_path = base + "_oversized.pem";
    const auto nul_pem_path = base + "_nul.pem";
    const auto many_entries_path = base + "_many_entries.zip";
    const std::string pem = "-----BEGIN CERTIFICATE-----\nunit-test\n-----END CERTIFICATE-----\n";
    const std::string tnsnames =
        "unit_low = (description= (address=(protocol=tcps)(port=1522)(host=db.example.com))"
        "(connect_data=(service_name=unit_low.example.com)))\n";
    const auto duplicate_aliases = tnsnames +
                                   "UNIT_LOW = (DESCRIPTION=(ADDRESS=(PROTOCOL=tcps)(PORT=1522)(HOST=other.example.com))"
                                   "(CONNECT_DATA=(SERVICE_NAME=other.example.com)))\n";
    {
        std::ofstream plain(pem_path, std::ios::binary);
        plain << pem;
    }
    CHECK(ReadWalletPemArchive(pem_path).empty());
    CHECK(ReadWalletPemFile(pem_path) == pem);
    CHECK(ReadPemFile(pem_path) == pem);
    WriteWalletArchiveForTest(zip_path, {{"tnsnames.ora", tnsnames}, {"ewallet.pem", pem}});
    CHECK(ReadWalletPemArchive(zip_path) == pem);
    CHECK(ReadWalletPemFile(zip_path) == pem);
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)ReadPemFile(zip_path); });
    CHECK(ReadWalletTnsNamesArchive(zip_path) == tnsnames);
    const auto descriptor = FindTnsAliasDescriptor(ReadWalletTnsNamesArchive(zip_path), "UNIT_LOW");
    const auto parsed = ParseConnectDescriptor(descriptor);
    CHECK(parsed.endpoints.size() == 1 && parsed.endpoints[0].protocol == TransportProtocol::TCPS &&
           parsed.endpoints[0].host == "db.example.com" && parsed.endpoints[0].port == 1522 &&
           parsed.service_name == "unit_low.example.com");
    WriteWalletArchiveForTest(missing_path, {{"tnsnames.ora", tnsnames}});
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)ReadWalletPemArchive(missing_path); });
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)FindTnsAliasDescriptor(tnsnames, "missing"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)FindTnsAliasDescriptor(duplicate_aliases, "unit_low"); });
    WriteWalletArchiveForTest(duplicate_path, {{"ewallet.pem", pem}, {"ewallet.pem", pem}});
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)ReadWalletPemArchive(duplicate_path); });
    WriteWalletArchiveForTest(nested_path, {{"wallet/ewallet.pem", pem}});
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)ReadWalletPemArchive(nested_path); });
    std::vector<std::pair<std::string, std::string>> many_entries {{"ewallet.pem", pem}};
    for (size_t index = 0; index < 32; index++) {
        many_entries.emplace_back("extra_" + std::to_string(index), "x");
    }
    WriteWalletArchiveForTest(many_entries_path, many_entries);
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { (void)ReadWalletPemArchive(many_entries_path); });
    WriteWalletArchiveForTest(oversized_path, {{"ewallet.pem", std::string((1U << 20U) + 1, 'A')}});
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)ReadWalletPemArchive(oversized_path); });
    {
        std::ofstream oversized_pem(oversized_pem_path, std::ios::binary);
        oversized_pem << std::string((1U << 20U) + 1, 'A');
    }
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { (void)ReadWalletPemFile(oversized_pem_path); });
    {
        std::ofstream nul_pem(nul_pem_path, std::ios::binary);
        nul_pem << pem << '\0' << "unexpected";
    }
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)ReadWalletPemFile(nul_pem_path); });
    WriteWalletArchiveForTest(duplicate_tnsnames_path, {{"ewallet.pem", pem}, {"tnsnames.ora", tnsnames},
                                                         {"tnsnames.ora", tnsnames}});
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)ReadWalletTnsNamesArchive(duplicate_tnsnames_path); });
    {
        std::ofstream corrupt(corrupt_path, std::ios::binary);
        corrupt << "PK\x03\x04not a ZIP archive";
    }
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)ReadWalletPemArchive(corrupt_path); });
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)ReadWalletTnsNamesArchive(corrupt_path); });
    std::remove(pem_path.c_str());
    std::remove(zip_path.c_str());
    std::remove(missing_path.c_str());
    std::remove(duplicate_path.c_str());
    std::remove(nested_path.c_str());
    std::remove(many_entries_path.c_str());
    std::remove(oversized_path.c_str());
    std::remove(oversized_pem_path.c_str());
    std::remove(nul_pem_path.c_str());
    std::remove(duplicate_tnsnames_path.c_str());
    std::remove(corrupt_path.c_str());
}

static void TestLengthPrefixedValues() {
    std::vector<uint8_t> long_value(70000);
    for (size_t index = 0; index < long_value.size(); index++) {
        long_value[index] = static_cast<uint8_t>(index);
    }
    ByteWriter writer;
    writer.WriteLengthPrefixed(std::nullopt).WriteLengthPrefixed(std::vector<uint8_t> {'o', 'k'})
        .WriteLengthPrefixed(long_value);
    ByteReader reader(writer.Data());
    CHECK(!reader.ReadLengthPrefixed(1).has_value());
    CHECK(reader.ReadLengthPrefixed(2).value() == std::vector<uint8_t>({'o', 'k'}));
    CHECK(reader.ReadLengthPrefixed(long_value.size()).value() == long_value);

    ByteWriter bounded;
    bounded.WriteLengthPrefixed(long_value);
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED,
                [&] { ByteReader(bounded.Data()).ReadLengthPrefixed(long_value.size() - 1); });
}

// Oracle does not distinguish an empty character value from NULL. The codec
// pins that as one policy: every zero-length wire form decodes to std::nullopt
// and an empty value encodes to the NULL indicator, so no present-but-empty
// value ever reaches a type codec or the DuckDB adapter.
static void TestEmptyValuesAreNull() {
    ByteWriter writer;
    writer.WriteLengthPrefixed(std::nullopt).WriteLengthPrefixed(std::vector<uint8_t> {});
    CHECK(writer.Data() == std::vector<uint8_t>({TNS_NULL_LENGTH_INDICATOR, TNS_NULL_LENGTH_INDICATOR}));

    ByteReader written(writer.Data());
    CHECK(!written.ReadLengthPrefixed(16).has_value());
    CHECK(!written.ReadLengthPrefixed(16).has_value());

    // Both zero-length short forms a server can send decode to NULL.
    const std::vector<uint8_t> short_forms {0, TNS_NULL_LENGTH_INDICATOR};
    ByteReader shorts(short_forms);
    CHECK(!shorts.ReadLengthPrefixed(16).has_value());
    CHECK(!shorts.ReadLengthPrefixed(16).has_value());

    // A chunked value whose first chunk terminates the sequence carries no
    // bytes, so it is the same NULL rather than a distinct empty value.
    ByteWriter chunked;
    chunked.WriteByte(TNS_LONG_LENGTH_INDICATOR).WriteUB4(0);
    CHECK(!ByteReader(chunked.Data()).ReadLengthPrefixed(16).has_value());

    // A chunked value that does carry bytes stays present and exact.
    ByteWriter carried;
    carried.WriteByte(TNS_LONG_LENGTH_INDICATOR).WriteUB4(2).WriteRaw(std::vector<uint8_t> {'o', 'k'}).WriteUB4(0);
    CHECK(ByteReader(carried.Data()).ReadLengthPrefixed(16).value() == std::vector<uint8_t>({'o', 'k'}));

    // A row of empty column values is a row of SQL NULLs, which is what the
    // adapter's value conversion depends on: no type codec is asked to decode
    // zero bytes.
    ByteWriter row;
    row.WriteByte(TTC_MESSAGE_ROW_DATA);
    row.WriteLengthPrefixed(std::vector<uint8_t> {}).WriteLengthPrefixed(std::nullopt);
    row.WriteByte(TNS_LONG_LENGTH_INDICATOR).WriteUB4(0);
    const auto values = DecodeTtcRowData(row.Data(), 3);
    CHECK(values.size() == 3);
    CHECK(!values[0].has_value());
    CHECK(!values[1].has_value());
    CHECK(!values[2].has_value());
}

static void TestTtcDescribeInfoVersionGates() {
    ByteWriter writer;
    writer.WriteByte(16); // DESCRIBE_INFO
    writer.WriteLengthPrefixed(std::nullopt);
    writer.WriteUB4(0); // maximum row size
    writer.WriteUB4(1); // column count
    writer.WriteByte(0); // descriptor flags
    writer.WriteByte(2).WriteByte(0).WriteByte(0).WriteByte(0); // NUMBER metadata prefix
    writer.WriteUB4(22).WriteUB4(0).WriteUB8(0).WriteUB4(0);
    writer.WriteUB2(0).WriteUB2(0).WriteByte(0).WriteUB4(0).WriteUB4(0); // oaccolid
    // TTIPRO version 6 still carries oaccolid and nullable in a modern OALL8
    // DESCRIBE_INFO response; only the server-version number is legacy.
    writer.WriteByte(0).WriteByte(0).WriteUB4(0).WriteUB4(0).WriteUB4(0);
    writer.WriteUB2(0).WriteUB4(0);
    writer.WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0);

    const auto describe = DecodeTtcDescribeInfoPrefix(writer.Data(), 6);
    CHECK(describe.columns.size() == 1);
    CHECK(describe.columns[0].oracle_type == 2);
    CHECK(!describe.columns[0].nullable && describe.columns[0].name.empty());
    CHECK(describe.bytes_consumed == writer.Data().size());
}

static void TestTtcReturnParameterPrefix() {
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_PARAMETER).WriteUB2(2).WriteUB4(7).WriteUB4(8);
    writer.WriteUB2(3).WriteRaw(reinterpret_cast<const uint8_t *>("xyz"), 3);
    writer.WriteUB2(1).WriteUB2(1).WriteLengthPrefixed(std::vector<uint8_t> {'k'});
    writer.WriteUB2(1).WriteLengthPrefixed(std::vector<uint8_t> {'v'}).WriteUB2(0);
    writer.WriteUB2(2).WriteRaw(reinterpret_cast<const uint8_t *>("ok"), 2);
    const auto decoded = DecodeTtcReturnParameterPrefix(writer.Data());
    CHECK(decoded.bytes_consumed == writer.Data().size());
}

// An end-of-call that stops mid-field is truncated, and saying so is the whole
// point: a decoder that instead accepted the prefix and reported the response
// finished is what let a fetch spanning more than one packet look complete.
// There used to be an ORA-01403 fallback here that did exactly that.
static void TestTtcFetchTruncatedEndOfCallIsTruncated() {
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_ERROR).WriteUB4(0).WriteUB2(0).WriteUB4(0);
    writer.WriteUB2(1403).WriteUB2(0).WriteUB2(0).WriteUB4(42);
    writer.WriteByte(0);
    ExpectError(ProtocolErrorKind::TRUNCATED,
                [&] { (void)DecodeTtcFetchResponse(writer.Data(), {OracleColumn {"N", 2, 0, 0, 0, true}}, 12); });
}

static void TestPacketFraming() {
    std::vector<uint8_t> payload {1, 2, 3, 4};
    auto encoded = EncodeTnsPacket(TnsPacketType::CONNECT, 7, payload, true);
    auto decoded = DecodeTnsPacket(encoded, true);
    CHECK(decoded.type == TnsPacketType::CONNECT);
    CHECK(decoded.flags == 7);
    CHECK(decoded.payload == payload);

    auto truncated = encoded;
    truncated.pop_back();
    ExpectError(ProtocolErrorKind::TRUNCATED, [&] { DecodeTnsPacket(truncated, true); });

    std::vector<uint8_t> ttc(30, 42);
    auto packets = EncodeTnsDataPackets(ttc, true, 20);
    CHECK(packets.size() == 3);
    for (size_t index = 0; index < packets.size(); index++) {
        auto packet = DecodeTnsPacket(packets[index], true, 20);
        CHECK(packet.payload.size() <= 12);
        auto flags = static_cast<uint16_t>((packet.payload[0] << 8U) | packet.payload[1]);
        CHECK(flags == (index + 1 == packets.size() ? TNS_DATA_FLAG_END_OF_RESPONSE : 0));
    }

    TnsDataAssembler assembler(64);
    for (size_t index = 0; index < packets.size(); index++) {
        auto completed = assembler.Push(DecodeTnsPacket(packets[index], true, 20));
        CHECK(completed.has_value() == (index + 1 == packets.size()));
        if (completed) {
            CHECK(*completed == ttc);
        }
    }
}

class FragmentedStream : public ByteStream {
public:
    explicit FragmentedStream(std::vector<uint8_t> input_p = {}, size_t fragment_p = 3)
        : input(std::move(input_p)), fragment(fragment_p) {
    }
    size_t Read(uint8_t *destination, size_t maximum_size) override {
        if (read_offset == input.size()) {
            return 0;
        }
        auto count = (std::min)({fragment, maximum_size, input.size() - read_offset});
        std::copy(input.begin() + read_offset, input.begin() + read_offset + count, destination);
        read_offset += count;
        return count;
    }
    size_t Write(const uint8_t *source, size_t size) override {
        auto count = (std::min)(fragment, size);
        output.insert(output.end(), source, source + count);
        return count;
    }
    void Close() override {
        closed = true;
    }

    std::vector<uint8_t> input;
    std::vector<uint8_t> output;
    size_t read_offset = 0;
    size_t fragment;
    bool closed = false;
};

static void TestPacketStream() {
    auto wire = EncodeTnsPacket(TnsPacketType::ACCEPT, 3, {7, 8, 9, 10}, true);
    FragmentedStream stream(wire, 2);
    TnsPacketStream packets(stream, true, 1024);
    auto received = packets.Receive();
    CHECK(received.type == TnsPacketType::ACCEPT && received.flags == 3);
    CHECK(received.payload == std::vector<uint8_t>({7, 8, 9, 10}));
    packets.Send({TnsPacketType::DATA, 0, {0, 0, 42}});
    CHECK(DecodeTnsPacket(stream.output, true).payload == std::vector<uint8_t>({0, 0, 42}));
    stream.output.clear();
    packets.Send(std::vector<TnsPacket> {{TnsPacketType::DATA, 0, {0, 0, 1}}, {TnsPacketType::DATA, 0, {0, 0, 2}}});
    CHECK(stream.output.size() == 22);

    wire.pop_back();
    FragmentedStream truncated(wire);
    TnsPacketStream truncated_packets(truncated, true);
    ExpectError(ProtocolErrorKind::TRUNCATED, [&] { truncated_packets.Receive(); });

    std::vector<uint8_t> oversized_header(8);
    oversized_header[2] = 0x10;
    FragmentedStream oversized(oversized_header);
    TnsPacketStream bounded(oversized, true, 1024);
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { bounded.Receive(); });
}

static uint16_t ReadUInt16(const std::vector<uint8_t> &value, size_t offset) {
    return static_cast<uint16_t>((static_cast<uint16_t>(value[offset]) << 8U) | value[offset + 1]);
}

static void TestConnectPackets() {
    const std::string descriptor = "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCLPDB1)))";
    auto packets = BuildTnsConnectPackets(descriptor);
    CHECK(packets.size() == 1 && packets[0].type == TnsPacketType::CONNECT);
    const auto &payload = packets[0].payload;
    CHECK(payload.size() == 66 + descriptor.size());
    CHECK(ReadUInt16(payload, 0) == 319 && ReadUInt16(payload, 2) == 300);
    CHECK(ReadUInt16(payload, 6) == 8192 && ReadUInt16(payload, 8) == 8192 &&
           ReadUInt16(payload, 16) == descriptor.size());
    CHECK(ReadUInt16(payload, 18) == 74);
    CHECK(payload[24] == 0x84 && payload[25] == 0x84 && payload[52] == 0x20 && payload[56] == 0x20 &&
           payload[65] == 0x01);
    CHECK(std::string(payload.begin() + 66, payload.end()) == descriptor);

    std::string long_descriptor(231, 'x');
    packets = BuildTnsConnectPackets(long_descriptor);
    CHECK(packets.size() == 2 && packets[0].payload.size() == 66);
    CHECK(packets[1].type == TnsPacketType::DATA && packets[1].payload.size() == 2 + long_descriptor.size());
    CHECK(packets[1].payload[0] == 0 && packets[1].payload[1] == 0);
    CHECK(std::string(packets[1].payload.begin() + 2, packets[1].payload.end()) == long_descriptor);
    ExpectError(ProtocolErrorKind::MALFORMED, [] { BuildTnsConnectPackets("x", {300, 318, 8192, 65535}); });
}

static void TestConnectHandshake() {
    std::vector<uint8_t> accept_payload(37);
    accept_payload[26] = 0x20;
    accept_payload[27] = 0x00;
    accept_payload[36] = 1;
    auto accepted_wire = EncodeTnsPacket(TnsPacketType::RESEND, 0, {}, false);
    const auto accept_wire = EncodeTnsPacket(TnsPacketType::ACCEPT, 0, accept_payload, false);
    accepted_wire.insert(accepted_wire.end(), accept_wire.begin(), accept_wire.end());
    FragmentedStream accepted(std::move(accepted_wire), 2);
    TnsPacketStream accepted_packets(accepted, false);
    auto result = RunTnsConnect(accepted_packets, "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=X)))");
    CHECK(result.disposition == TnsConnectDisposition::ACCEPTED && result.negotiated_sdu == 8192 && result.check_oob);
    const auto first_packet_length = ReadUInt16(accepted.output, 0);
    CHECK(DecodeTnsPacket(std::vector<uint8_t>(accepted.output.begin(), accepted.output.begin() + first_packet_length), false).type ==
           TnsPacketType::CONNECT);
    CHECK(accepted.output.size() > first_packet_length);
    CHECK(DecodeTnsPacket(std::vector<uint8_t>(accepted.output.begin() + first_packet_length,
                                                accepted.output.begin() + 2 * first_packet_length), false)
               .type == TnsPacketType::CONNECT);

    FragmentedStream redirected(EncodeTnsPacket(TnsPacketType::REDIRECT, 0,
                                                {'x', 'x', '(', 'D', 'E', 'S', 'C', 'R', 'I', 'P', 'T', 'I', 'O',
                                                 'N', '=', '(', 'A', ')', ')'}, false));
    TnsPacketStream redirected_packets(redirected, false);
    result = RunTnsConnect(redirected_packets, "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=X)))");
    CHECK(result.disposition == TnsConnectDisposition::REDIRECTED);
    CHECK(result.redirect_descriptor == "(DESCRIPTION=(A))");

    FragmentedStream refused(EncodeTnsPacket(TnsPacketType::REFUSE, 0, {}, false));
    TnsPacketStream refused_packets(refused, false);
    ExpectError(ProtocolErrorKind::INVALID_STATE,
                [&] { RunTnsConnect(refused_packets, "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=X)))"); });
}

static void TestTtcChannel() {
    const std::vector<uint8_t> message {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    auto encoded = EncodeTnsDataPackets(message, true, 20);
    std::vector<uint8_t> inbound;
    for (const auto &packet : encoded) {
        inbound.insert(inbound.end(), packet.begin(), packet.end());
    }
    FragmentedStream stream(inbound, 3);
    TnsPacketStream packets(stream, true, 20);
    TtcChannel channel(packets, 20, 64);
    CHECK(channel.Receive() == message);
    channel.Send(message);
    std::vector<uint8_t> outbound;
    for (const auto &packet : EncodeTnsDataPackets(message, true, 20, 0)) {
        outbound.insert(outbound.end(), packet.begin(), packet.end());
    }
    CHECK(stream.output == outbound);
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { channel.Send({}); });
}

static void TestTtcChannelShortPacketBoundary() {
    const std::vector<uint8_t> message {1, 6, 0, 'o', 'k', 0};
    std::vector<uint8_t> inbound;
    for (const auto &packet : EncodeTnsDataPackets(message, true, 64, 0)) {
        inbound.insert(inbound.end(), packet.begin(), packet.end());
    }
    FragmentedStream stream(inbound, 2);
    TnsPacketStream packets(stream, true, 64);
    TtcChannel channel(packets, 64, 128);
    CHECK(channel.Receive() == message);
}

// Nothing in the framing says where a data response ends: a legacy session gets
// no END_OF_RESPONSE, and fragments are not padded to the SDU. The statement
// channel therefore joins fragments until the decoder reports a terminator, and
// reads another only when the decode ran out of bytes.
static void TestStatementChannelJoinsFragmentedResponse() {
    const OracleColumn column {"N", 2, 0, 0, 0, true};
    ByteWriter response;
    constexpr uint8_t row_header = 6;
    response.WriteByte(row_header).WriteByte(0).WriteUB2(0).WriteUB4(0).WriteUB4(1);
    response.WriteUB2(0).WriteUB4(0).WriteUB4(0);
    response.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(EncodeOracleNumber("7"));
    // Split exactly here: the first fragment is a valid but unterminated
    // prefix, so the decoder returns without a terminator rather than
    // throwing, which is the other way the loop learns it needs more bytes.
    const size_t split = response.Data().size();
    response.WriteByte(TTC_MESSAGE_ERROR).WriteUB4(0).WriteUB2(0).WriteUB4(0);
    response.WriteUB2(0).WriteUB2(0).WriteUB2(0).WriteUB4(42).WriteUB4(0);
    response.WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0);
    response.WriteUB4(0).WriteUB2(0).WriteByte(0).WriteUB4(0).WriteUB2(0);
    response.WriteUB4(0).WriteByte(0).WriteByte(0).WriteUB2(0).WriteUB4(0).WriteByte(0);
    response.WriteUB2(0).WriteUB4(0).WriteUB2(0).WriteUB4(1403).WriteUB8(1);
    response.WriteLengthPrefixed(std::vector<uint8_t> {'n', 'o', ' ', 'd', 'a', 't', 'a'});

    const auto &bytes = response.Data();
    std::vector<uint8_t> inbound;
    for (const auto &packet : EncodeTnsDataPackets({bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(split)},
                                                   true, 512, 0)) {
        inbound.insert(inbound.end(), packet.begin(), packet.end());
    }
    for (const auto &packet :
         EncodeTnsDataPackets({bytes.begin() + static_cast<std::ptrdiff_t>(split), bytes.end()}, true, 512, 0)) {
        inbound.insert(inbound.end(), packet.begin(), packet.end());
    }

    FragmentedStream stream(inbound, 7);
    TnsPacketStream packets(stream, true, 512);
    TtcChannel channel(packets, 512, 1U << 20U);
    OracleStatementRegistry statements;
    TtcStatementChannel statement_channel(channel, statements);
    const auto handle = statements.Open(OracleSqlKind::QUERY);
    statements.BindRemoteCursor(handle, 42);
    statements.MarkExecuted(handle, true);
    statements.BeginFetch(handle);

    const auto decoded = statement_channel.ReceiveDecodedFetchResponse(handle, {column});
    CHECK(decoded.completed && decoded.exhausted);
    CHECK(decoded.rows.size() == 1 && decoded.rows[0][0].has_value());
    CHECK(DecodeOracleNumber(*decoded.rows[0][0]) == "7");
}

static void TestTtcCancellation() {
    std::vector<uint8_t> inbound = EncodeTnsPacket(TnsPacketType::MARKER, 0, {0x01, 0x00, 0x02}, true);
    const auto terminal = EncodeTnsDataPackets({29}, true, 64);
    inbound.insert(inbound.end(), terminal.front().begin(), terminal.front().end());
    FragmentedStream stream(inbound, 2);
    TnsPacketStream packets(stream, true, 64);
    TtcChannel channel(packets, 64, 128);
    channel.Cancel();
    ExpectError(ProtocolErrorKind::INVALID_STATE, [&] { channel.Cancel(); });
    CHECK(channel.Receive() == std::vector<uint8_t>({29}));

    FragmentedStream outbound(stream.output, 3);
    TnsPacketStream outbound_packets(outbound, true, 64);
    const auto interrupt = outbound_packets.Receive();
    const auto reset = outbound_packets.Receive();
    CHECK(interrupt.type == TnsPacketType::MARKER && interrupt.payload == std::vector<uint8_t>({0x01, 0x00, 0x03}));
    CHECK(reset.type == TnsPacketType::MARKER && reset.payload == std::vector<uint8_t>({0x01, 0x00, 0x02}));

    FragmentedStream tcps_stream;
    TnsPacketStream tcps_packets(tcps_stream, true, 64);
    TtcChannel tcps_channel(tcps_packets, 64, 128, false);
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [&] { tcps_channel.Cancel(); });
}

static void TestTtcErrorDiagnostics() {
    const std::vector<uint8_t> response = {TTC_MESSAGE_ERROR, 0, 1, 'O', 'R', 'A', '-', '0', '1', '0', '1', '7',
                                           ':', ' ', 'i', 'n', 'v', 'a', 'l', 'i', 'd', ' ', 'l', 'o', 'g', 'o', 'n'};
    CHECK(IsTtcErrorMessage(response));
    const auto error = ParseTtcServerError(response);
    CHECK(error.ora_code == 1017 && error.message == "ORA-01017: invalid logon");
    ExpectError(ProtocolErrorKind::INVALID_STATE, [&] { ThrowTtcServerError(response); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { ParseTtcServerError({TTC_MESSAGE_PARAMETER}); });

    // The end-of-call up to the extended error number and row count. The two
    // bytes after the OS error are the statement and call numbers; what follows
    // them is a universal UB2, one byte when zero, not two fixed bytes.
    const auto end_of_call = [](uint32_t error_number, uint64_t row_count, bool with_trailer) {
        ByteWriter writer;
        writer.WriteByte(TTC_MESSAGE_ERROR).WriteUB4(0).WriteUB2(0).WriteUB4(0);
        writer.WriteUB2(0).WriteUB2(0).WriteUB2(0).WriteUB4(88).WriteUB4(0);
        writer.WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0);
        writer.WriteUB4(0).WriteUB2(0).WriteByte(0).WriteUB4(0).WriteUB2(0);
        writer.WriteUB4(0);                                  // OS error
        writer.WriteByte(0).WriteByte(0).WriteUB2(0);        // statement, call, padding
        writer.WriteUB4(0).WriteByte(0);                     // success iterations, empty oerrdd
        writer.WriteUB2(0).WriteUB4(0).WriteUB2(0);          // batch codes, offsets, messages
        writer.WriteUB4(error_number).WriteUB8(row_count);
        if (with_trailer) {
            writer.WriteUB4(3).WriteUB4(0); // SQL type and server checksum
        }
        return writer.Data();
    };

    const auto decoded = DecodeTtcErrorPrefix(end_of_call(0, 7, false));
    CHECK(decoded.error_number == 0 && decoded.cursor_id == 88 && decoded.row_count == 7);
    CHECK(decoded.bytes_consumed == end_of_call(0, 7, false).size());

    // Above the gate the server appends a SQL type and a checksum before the
    // message text. Oracle 19c reports field version 12 and sends neither;
    // Free 23ai and OCI Autonomous report 27 and send both.
    const auto with_trailer = DecodeTtcErrorPrefix(end_of_call(0, 7, true), 27);
    CHECK(with_trailer.error_number == 0 && with_trailer.row_count == 7);
    CHECK(with_trailer.bytes_consumed == end_of_call(0, 7, true).size());

    // Reading a trailer that is not there, or missing one that is, both leave
    // the decode disagreeing with the message rather than silently succeeding.
    ExpectError(ProtocolErrorKind::TRUNCATED, [&] { (void)DecodeTtcErrorPrefix(end_of_call(0, 7, false), 27); });
    CHECK(DecodeTtcErrorPrefix(end_of_call(0, 7, true), 12).bytes_consumed < end_of_call(0, 7, true).size());
}

static void TestTtcParameters() {
    const std::vector<TtcParameter> parameters = {
        {"AUTH_VFR_DATA", "00112233445566778899AABBCCDDEEFF", 0x0c},
        {"AUTH_SESSKEY", "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF", 0},
        {"AUTH_PBKDF2_CSK_SALT", "00112233445566778899AABBCCDDEEFF", 0},
        {"AUTH_PBKDF2_VGEN_COUNT", "4096", 0},
        {"AUTH_PBKDF2_SDER_COUNT", "3", 0}};
    auto decoded = DecodeTtcParameters(EncodeTtcParameters(parameters));
    CHECK(decoded.size() == parameters.size() && decoded[0].flags == 0x0c);
    auto challenge = O5LogonChallengeFromParameters(decoded);
    CHECK(challenge.verifier_iterations == 4096 && challenge.combo_key_iterations == 3);
    decoded.push_back(decoded.front());
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { O5LogonChallengeFromParameters(decoded); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { DecodeTtcParameters({7, 0}); });
}

static void TestTtcAuthEncoding() {
    const std::vector<TtcParameter> parameters = {{"AUTH_PROGRAM_NM", "DuckDB", 0}, {"AUTH_MACHINE", "host", 0}};
    auto message = EncodeTtcAuthFunction(TTC_FUNCTION_AUTH_PHASE_ONE, 7, "scott", 1, parameters);
    ByteReader reader(message);
    CHECK(reader.ReadByte() == TTC_MESSAGE_FUNCTION && reader.ReadByte() == TTC_FUNCTION_AUTH_PHASE_ONE);
    CHECK(reader.ReadByte() == 7 && reader.ReadByte() == 1 && reader.ReadUB4() == 5 && reader.ReadUB4() == 1);
    CHECK(reader.ReadByte() == 1);
    CHECK(reader.ReadUB4() == parameters.size());
    CHECK(reader.ReadByte() == 1 && reader.ReadByte() == 1);
    CHECK(reader.ReadLengthPrefixed(5).value() == std::vector<uint8_t>({'s', 'c', 'o', 't', 't'}));
    CHECK(reader.ReadUB4() == parameters[0].key.size());
    CHECK(reader.ReadLengthPrefixed(parameters[0].key.size()).value() ==
           std::vector<uint8_t>({'A', 'U', 'T', 'H', '_', 'P', 'R', 'O', 'G', 'R', 'A', 'M', '_', 'N', 'M'}));

    O5LogonResponse response {"AA", "CC", "BB", std::vector<uint8_t>(32, 1)};
    auto phase_two = BuildO5LogonPhaseTwoParameters(response);
    CHECK(phase_two.size() == 3 && phase_two[1].key == "AUTH_PBKDF2_SPEEDY_KEY" &&
           phase_two[2].key == "AUTH_PASSWORD");
    ExpectError(ProtocolErrorKind::MALFORMED,
                [] { EncodeTtcAuthFunction(0, 0, "x", 0, {}); });
}

static void TestTtcFetchCodec() {
    const TtcFetchRequest request {9, 42, 512};
    const auto encoded = EncodeTtcFetchRequest(request);
    ByteReader reader(encoded);
    CHECK(reader.ReadByte() == TTC_MESSAGE_FUNCTION && reader.ReadByte() == TTC_FUNCTION_FETCH);
    CHECK(reader.ReadByte() == 9 && reader.ReadUB4() == 42 && reader.ReadUB4() == 512 && reader.Remaining() == 0);
    const auto decoded = DecodeTtcFetchRequest(encoded);
    CHECK(decoded.sequence == request.sequence && decoded.cursor_id == request.cursor_id &&
           decoded.requested_rows == request.requested_rows);
    ExpectError(ProtocolErrorKind::MALFORMED, [] { EncodeTtcFetchRequest({0, 0, 1}); });
    ExpectError(ProtocolErrorKind::MALFORMED, [&] {
        auto malformed = encoded;
        malformed.push_back(0);
        DecodeTtcFetchRequest(malformed);
    });
}

static void TestTtcFetchResponse() {
    const std::vector<OracleColumn> columns = {{"A", 1, 16, 0, 0, true}, {"B", 2, 22, 0, 0, true}};
    ByteWriter response;
    response.WriteByte(6).WriteByte(0).WriteUB2(0).WriteUB4(0).WriteUB4(0).WriteUB2(0);
    // No bit vector: every column of this row is on the wire. This fixture
    // used to carry a one-byte all-zero vector, which was read as a marker that
    // changed nothing; a live 19c capture showed an all-zero vector means the
    // opposite — the row repeats the previous one and carries no values — so
    // the shape that belongs with a full ROW_DATA is no vector at all. See
    // TestRepeatedRowsCarryNoValues for the captured form.
    response.WriteUB4(0).WriteUB4(0);
    response.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(std::vector<uint8_t> {'x'}).WriteLengthPrefixed(std::nullopt);
    response.WriteByte(9).WriteUB4(0).WriteUB2(0);
    const auto decoded = DecodeTtcFetchResponse(response.Data(), columns);
    CHECK(decoded.completed && !decoded.exhausted && decoded.bytes_consumed == response.Data().size());
    CHECK(decoded.rows.size() == 1 && decoded.rows[0][0].value() == std::vector<uint8_t>({'x'}) &&
           !decoded.rows[0][1].has_value());

    // The capture-backed 0x15 continuation keeps values omitted by its bitmap
    // and reads only the columns that changed from the preceding row.
    ByteWriter continued;
    continued.WriteByte(TTC_MESSAGE_ROW_DATA)
        .WriteLengthPrefixed(std::vector<uint8_t> {'x'})
        .WriteLengthPrefixed(std::vector<uint8_t> {'1'});
    continued.WriteByte(21).WriteUInt16LE(1).WriteByte(0x02);
    continued.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(std::vector<uint8_t> {'2'});
    continued.WriteByte(9).WriteUB4(0).WriteUB2(0);
    const auto continued_decoded = DecodeTtcFetchResponse(continued.Data(), columns);
    CHECK(continued_decoded.used_row_continuation && continued_decoded.rows.size() == 2 &&
           continued_decoded.rows[1][0].value() == std::vector<uint8_t>({'x'}) &&
           continued_decoded.rows[1][1].value() == std::vector<uint8_t>({'2'}));

    // A new OFETCH response can begin with a ROW_HEADER bitmap rather than a
    // 0x15 marker. The bitmap selects values that changed from the final
    // prefetch row in the preceding execute response.
    const std::vector<OracleColumn> three_columns = { {"A", 1, 16, 0, 0, true}, {"B", 1, 16, 0, 0, true},
                                                      {"C", 1, 16, 0, 0, true} };
    const TtcRowData preceding = {std::vector<uint8_t> {'a'}, std::vector<uint8_t> {'b'}, std::vector<uint8_t> {'c'}};
    ByteWriter row_header_selected;
    row_header_selected.WriteByte(6).WriteByte(0).WriteUB2(0).WriteUB4(0).WriteUB4(0).WriteUB2(0);
    row_header_selected.WriteUB4(1).WriteLengthPrefixed(std::vector<uint8_t> {0x01}).WriteUB4(0);
    row_header_selected.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(std::vector<uint8_t> {'z'});
    row_header_selected.WriteByte(9).WriteUB4(0).WriteUB2(0);
    const auto header_selected = DecodeTtcFetchResponse(row_header_selected.Data(), three_columns, 6, preceding);
    CHECK(header_selected.used_row_header_selection && header_selected.rows.size() == 1 && header_selected.last_row &&
           header_selected.rows[0][0].value() == std::vector<uint8_t>({'z'}) &&
           header_selected.rows[0][1].value() == std::vector<uint8_t>({'b'}) &&
           header_selected.rows[0][2].value() == std::vector<uint8_t>({'c'}));
    ExpectError(ProtocolErrorKind::MALFORMED,
                [&] { DecodeTtcFetchResponse(row_header_selected.Data(), three_columns, 6); });

    // Bitmap selection is little-endian by column index and must also retain
    // columns beyond the first byte of a wide described row.
    const std::vector<OracleColumn> wide_columns = { {"C1", 1, 16, 0, 0, true}, {"C2", 1, 16, 0, 0, true},
                                                     {"C3", 1, 16, 0, 0, true}, {"C4", 1, 16, 0, 0, true},
                                                     {"C5", 1, 16, 0, 0, true}, {"C6", 1, 16, 0, 0, true},
                                                     {"C7", 1, 16, 0, 0, true}, {"C8", 1, 16, 0, 0, true},
                                                     {"C9", 1, 16, 0, 0, true} };
    TtcRowData wide_preceding(9, std::vector<uint8_t> {'x'});
    ByteWriter wide_header_selected;
    wide_header_selected.WriteByte(6).WriteByte(0).WriteUB2(0).WriteUB4(0).WriteUB4(0).WriteUB2(0);
    wide_header_selected.WriteUB4(2).WriteLengthPrefixed(std::vector<uint8_t> {0x01, 0x01}).WriteUB4(0);
    wide_header_selected.WriteByte(TTC_MESSAGE_ROW_DATA)
        .WriteLengthPrefixed(std::vector<uint8_t> {'1'})
        .WriteLengthPrefixed(std::vector<uint8_t> {'9'});
    wide_header_selected.WriteByte(9).WriteUB4(0).WriteUB2(0);
    const auto wide_selected = DecodeTtcFetchResponse(wide_header_selected.Data(), wide_columns, 6, wide_preceding);
    CHECK(wide_selected.used_row_header_selection && wide_selected.rows.size() == 1 &&
           wide_selected.rows[0][0].value() == std::vector<uint8_t> {'1'} &&
           wide_selected.rows[0][8].value() == std::vector<uint8_t> {'9'} &&
           wide_selected.rows[0][7].value() == std::vector<uint8_t> {'x'});

    // Free 23ai emits the wide 0x15 count as TTC UB2 rather than the classic
    // two-byte little-endian counter. Its bitmap remains fixed-width.
    ByteWriter wide_universal_continuation;
    wide_universal_continuation.WriteByte(21).WriteUB2(1).WriteByte(0x01).WriteByte(0x00);
    wide_universal_continuation.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(std::vector<uint8_t> {'z'});
    wide_universal_continuation.WriteByte(9).WriteUB4(0).WriteUB2(0);
    const auto wide_continued = DecodeTtcFetchResponse(wide_universal_continuation.Data(), wide_columns, 6, wide_preceding);
    CHECK(wide_continued.used_row_continuation && wide_continued.rows.size() == 1 &&
           wide_continued.rows[0][0].value() == std::vector<uint8_t> {'z'} &&
           wide_continued.rows[0][8].value() == std::vector<uint8_t> {'x'});
}

static void TestTtcIoVector() {
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_IO_VECTOR).WriteByte(0).WriteUB2(2).WriteUB4(0).WriteUB4(1).WriteUB2(0);
    writer.WriteUB2(0).WriteUB2(0).WriteByte(TTC_BIND_DIRECTION_OUT).WriteByte(TTC_BIND_DIRECTION_IN);
    const auto vector = DecodeTtcIoVector(writer.Data());
    CHECK(vector.iteration_count == 1 && vector.directions == std::vector<uint8_t>({TTC_BIND_DIRECTION_OUT, TTC_BIND_DIRECTION_IN}));
    CHECK(vector.bytes_consumed == writer.Data().size());
    auto prefixed = writer.Data();
    prefixed.push_back(TTC_MESSAGE_ROW_DATA);
    CHECK(DecodeTtcIoVectorPrefix(prefixed).bytes_consumed == writer.Data().size());
    const std::vector<OracleBind> binds = {{"c", ORACLE_WIRE_TYPE_CURSOR, BindDirection::BIND_OUT, std::nullopt},
                                           {"id", 2, BindDirection::BIND_IN, std::vector<uint8_t> {0xc1, 0x02}}};
    CHECK(GetTtcOutputBindIndexes(vector, binds) == std::vector<size_t>({0}));
    auto cursor_in_out = vector;
    cursor_in_out.directions = {TTC_BIND_DIRECTION_IN_OUT, TTC_BIND_DIRECTION_IN};
    // Oracle 19c reports an OUT SYS_REFCURSOR as IN OUT in its IO_VECTOR.
    CHECK(GetTtcOutputBindIndexes(cursor_in_out, binds) == std::vector<size_t>({0}));
    auto invalid = writer.Data();
    invalid.back() = 0xff;
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { DecodeTtcIoVector(invalid); });
}

static void TestTtcRefCursorDescriptor() {
    ByteWriter writer;
    writer.WriteUB4(32).WriteUB4(1).WriteByte(0);
    writer.WriteByte(2).WriteByte(0).WriteByte(10).WriteByte(0).WriteUB4(22).WriteUB4(0).WriteUB8(0);
    writer.WriteUB4(0).WriteUB2(0).WriteUB2(0).WriteByte(0).WriteUB4(0).WriteUB4(0).WriteByte(1).WriteByte(0);
    writer.WriteUB4(1).WriteLengthPrefixed(std::vector<uint8_t> {'N'});
    writer.WriteUB4(0).WriteUB4(0).WriteUB2(0).WriteUB4(0);
    writer.WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB2(42);
    const auto descriptor = DecodeTtcRefCursorDescriptor(writer.Data());
    CHECK(descriptor.cursor_id == 42 && descriptor.columns.size() == 1 && descriptor.columns[0].name == "N" &&
           descriptor.columns[0].oracle_type == 2 && descriptor.bytes_consumed == writer.Data().size());
    auto invalid = writer.Data();
    invalid.back() = 0;
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { DecodeTtcRefCursorDescriptor(invalid); });
}

static void TestTtcImplicitResultSet() {
    ByteWriter descriptor;
    descriptor.WriteUB4(32).WriteUB4(1).WriteByte(0);
    descriptor.WriteByte(2).WriteByte(0).WriteByte(10).WriteByte(0).WriteUB4(22).WriteUB4(0).WriteUB8(0);
    descriptor.WriteUB4(0).WriteUB2(0).WriteUB2(0).WriteByte(0).WriteUB4(0).WriteUB4(0).WriteByte(1).WriteByte(0);
    descriptor.WriteUB4(1).WriteLengthPrefixed(std::vector<uint8_t> {'N'});
    descriptor.WriteUB4(0).WriteUB4(0).WriteUB2(0).WriteUB4(0);
    descriptor.WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB2(9);
    auto second_descriptor = descriptor.Data();
    second_descriptor.back() = 10;

    ByteWriter message;
    message.WriteByte(TTC_MESSAGE_IMPLICIT_RESULT_SET).WriteUB4(2).WriteByte(0).WriteRaw(descriptor.Data());
    message.WriteByte(2).WriteByte(0xaa).WriteByte(0xbb).WriteRaw(second_descriptor);
    const auto decoded = DecodeTtcImplicitResultSet(message.Data());
    CHECK(decoded.bytes_consumed == message.Data().size() && decoded.cursors.size() == 2);
    CHECK(decoded.cursors[0].cursor_id == 9 && decoded.cursors[1].cursor_id == 10);
    auto trailing = message.Data();
    trailing.push_back(0);
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { DecodeTtcImplicitResultSet(trailing); });
}

static void TestTtcOutBindsRow() {
    ByteWriter descriptor;
    descriptor.WriteUB4(32).WriteUB4(1).WriteByte(0);
    descriptor.WriteByte(2).WriteByte(0).WriteByte(10).WriteByte(0).WriteUB4(22).WriteUB4(0).WriteUB8(0);
    descriptor.WriteUB4(0).WriteUB2(0).WriteUB2(0).WriteByte(0).WriteUB4(0).WriteUB4(0).WriteByte(1).WriteByte(0);
    descriptor.WriteUB4(1).WriteLengthPrefixed(std::vector<uint8_t> {'N'});
    descriptor.WriteUB4(0).WriteUB4(0).WriteUB2(0).WriteUB4(0);
    descriptor.WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB2(9);
    ByteWriter row;
    row.WriteByte(TTC_MESSAGE_ROW_DATA).WriteByte(1).WriteRaw(descriptor.Data()).WriteByte(0);
    const std::vector<OracleBind> binds = {{"c", ORACLE_WIRE_TYPE_CURSOR, BindDirection::BIND_OUT, std::nullopt}};
    const auto decoded = DecodeTtcOutBindsRow(row.Data(), binds, {0});
    CHECK(decoded.cursor_values.size() == 1 && decoded.cursor_values[0] && decoded.cursor_values[0]->cursor_id == 9 &&
           decoded.bytes_consumed == row.Data().size());

    ByteWriter response;
    response.WriteByte(TTC_MESSAGE_IO_VECTOR).WriteByte(0).WriteUB2(1).WriteUB4(0).WriteUB4(1).WriteUB2(0);
    response.WriteUB2(0).WriteUB2(0).WriteByte(TTC_BIND_DIRECTION_OUT);
    response.WriteRaw(row.Data()).WriteByte(0x09); // later TTC status belongs to the response dispatcher
    const auto plsql = DecodeTtcPlsqlOutBindsResponse(response.Data(), binds);
    CHECK(plsql.io_vector.directions == std::vector<uint8_t>({TTC_BIND_DIRECTION_OUT}));
    CHECK(plsql.output_indexes == std::vector<size_t>({0}) && plsql.values.cursor_values[0]);
    CHECK(plsql.bytes_consumed + 1 == response.Data().size());
}

static void TestTtcCallResponse() {
    const std::vector<OracleBind> binds = {{"value", 1, BindDirection::BIND_OUT, std::nullopt, 32}};
    ByteWriter response;
    response.WriteByte(TTC_MESSAGE_IO_VECTOR).WriteByte(0).WriteUB2(1).WriteUB4(0).WriteUB4(1).WriteUB2(0);
    response.WriteUB2(0).WriteUB2(0).WriteByte(TTC_BIND_DIRECTION_OUT);
    response.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(std::vector<uint8_t> {'x'}).WriteByte(0);
    response.WriteByte(TTC_MESSAGE_ERROR).WriteUB4(0).WriteUB2(0).WriteUB4(0);
    response.WriteUB2(0).WriteUB2(0).WriteUB2(0).WriteUB4(77).WriteUB4(0).WriteByte(0).WriteByte(0);
    response.WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0);
    response.WriteUB4(0).WriteUB2(0).WriteByte(0).WriteUB4(0).WriteUB2(0);
    response.WriteUB4(0).WriteByte(0).WriteByte(0).WriteUB2(0).WriteUB4(0).WriteUB4(0);
    response.WriteUB2(0).WriteUB4(0).WriteUB2(0).WriteUB4(0).WriteUB8(1);
    response.WriteByte(9).WriteUB4(0).WriteUB2(0);
    const auto decoded = DecodeTtcCallResponse(response.Data(), binds);
    CHECK(decoded.completed && decoded.bytes_consumed == response.Data().size() && decoded.out_binds && decoded.completion);
    CHECK(decoded.out_binds->scalar_values[0] == std::optional<std::vector<uint8_t>>(std::vector<uint8_t> {static_cast<uint8_t>('x')}));
    CHECK(decoded.completion->cursor_id == 77 && decoded.completion->row_count == 1);
}

static void TestTtcExecuteNoBindsCodec() {
    TtcExecuteNoBindsRequest request;
    request.sequence = 3;
    request.options = 7;
    request.sql = "select 1 from dual";
    request.prefetch_buffer_bytes = 4096;
    request.prefetch_rows = 25;
    request.maximum_long_bytes = 8192;
    request.is_query = true;
    const auto encoded = EncodeTtcExecuteNoBindsRequest(request);
    ByteReader reader(encoded);
    CHECK(reader.ReadByte() == TTC_MESSAGE_FUNCTION && reader.ReadByte() == TTC_FUNCTION_EXECUTE && reader.ReadByte() == 3);
    CHECK(reader.ReadUB4() == 0x8067 && reader.ReadUB4() == 0 && reader.ReadByte() == 1);
    CHECK(reader.ReadUB4() == request.sql.size() && reader.ReadByte() == 1 && reader.ReadUB4() == 13);
    const std::vector<uint8_t> sql_bytes(request.sql.begin(), request.sql.end());
    CHECK(std::search(encoded.begin(), encoded.end(), sql_bytes.begin(), sql_bytes.end()) != encoded.end());
    request.sql.clear();
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { EncodeTtcExecuteNoBindsRequest(request); });
}

static void TestTtcRowDataCodec() {
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_ROW_DATA)
        .WriteLengthPrefixed(std::vector<uint8_t> {'4', '2'})
        .WriteLengthPrefixed(std::nullopt)
        .WriteLengthPrefixed(std::vector<uint8_t> {'x'});
    const auto row = DecodeTtcRowData(writer.Data(), 3);
    CHECK(row.size() == 3 && row[0].value() == std::vector<uint8_t>({'4', '2'}) && !row[1].has_value() &&
           row[2].value() == std::vector<uint8_t>({'x'}));
    ExpectError(ProtocolErrorKind::MALFORMED, [] { DecodeTtcRowData({TTC_MESSAGE_ROW_DATA}, 0); });
    auto malformed = writer.Data();
    malformed.push_back(0);
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { DecodeTtcRowData(malformed, 3); });
    CHECK(DecodeTtcRowDataPrefix(malformed, 3).bytes_consumed == writer.Data().size());
}

static void TestTtcNegotiation() {
    TtcNegotiationOptions options;
    options.driver_name = "oracle_scanner_test";
    auto request = BuildTtcProtocolRequest(options);
    CHECK(request[0] == TTC_MESSAGE_PROTOCOL && request[1] == 6 && request[2] == 0);
    CHECK(std::string(request.begin() + 3, request.end() - 1) == options.driver_name);

    ByteWriter server;
    server.WriteByte(TTC_MESSAGE_PROTOCOL).WriteByte(6).WriteByte(0).WriteNullTerminated("Oracle Database");
    server.WriteUInt16LE(ORACLE_CHARSET_AL32UTF8).WriteByte(0).WriteUInt16LE(0).WriteUInt16BE(0);
    server.WriteByte(0).WriteByte(0);
    const auto protocol_response = server.Take();
    const std::vector<uint8_t> data_type_response {TTC_MESSAGE_DATA_TYPES, 0, 0};
    std::vector<uint8_t> inbound;
    for (const auto &packet : EncodeTnsDataPackets(protocol_response, true, 64)) {
        inbound.insert(inbound.end(), packet.begin(), packet.end());
    }
    for (const auto &packet : EncodeTnsDataPackets(data_type_response, true, 64)) {
        inbound.insert(inbound.end(), packet.begin(), packet.end());
    }
    FragmentedStream stream(inbound, 5);
    TnsPacketStream packets(stream, true, 64);
    TtcChannel channel(packets, 64);
    auto info = RunTtcNegotiation(channel, options);
    CHECK(info.server_version == 6 && info.server_banner == "Oracle Database");
    CHECK(info.charset_id == ORACLE_CHARSET_AL32UTF8);
    ExpectError(ProtocolErrorKind::UNSUPPORTED,
                [] { ParseTtcProtocolResponse({0xde, 0xad, 0xbe, 0xef}); });
}

static void TestTtcExecuteNoBindsShape() {
    TtcExecuteNoBindsRequest query;
    query.sql = "select 1 from dual";
    query.is_query = true;
    const auto encoded = EncodeTtcExecuteNoBindsRequest(query);
    ByteReader reader(encoded);
    CHECK(reader.ReadByte() == TTC_MESSAGE_FUNCTION && reader.ReadByte() == TTC_FUNCTION_EXECUTE && reader.ReadByte() == 1);
    CHECK(reader.ReadUB4() == 0x8061 && reader.ReadUB4() == 0);
    CHECK(reader.ReadByte() == 1 && reader.ReadUB4() == query.sql.size());
    CHECK(reader.ReadByte() == 1 && reader.ReadUB4() == 13);

    TtcExecuteNoBindsRequest dml;
    dml.sql = "insert into t values (1)";
    const auto dml_encoded = EncodeTtcExecuteNoBindsRequest(dml);
    ByteReader dml_reader(dml_encoded);
    dml_reader.Skip(3);
    CHECK(dml_reader.ReadUB4() == 0x8021);

    TtcExecuteNoBindsRequest plsql;
    plsql.sql = "BEGIN NULL; END;";
    plsql.is_plsql = true;
    const auto plsql_encoded = EncodeTtcExecuteNoBindsRequest(plsql);
    ByteReader plsql_reader(plsql_encoded);
    plsql_reader.Skip(3);
    CHECK(plsql_reader.ReadUB4() == 0x21);
}

static void TestTtcExecuteRefCursorBindShape() {
    TtcExecuteBindsRequest request;
    request.sql = "BEGIN :out_cur := demo.open_rows(:id); END;";
    request.is_plsql = true;
    request.binds = {{"out_cur", ORACLE_WIRE_TYPE_CURSOR, BindDirection::BIND_OUT, std::nullopt},
                     {"id", 2, BindDirection::BIND_IN, std::vector<uint8_t> {0xc1, 0x02}}};
    const auto encoded = EncodeTtcExecuteBindsRequest(request);
    ByteReader reader(encoded);
    CHECK(reader.ReadByte() == TTC_MESSAGE_FUNCTION && reader.ReadByte() == TTC_FUNCTION_EXECUTE && reader.ReadByte() == 1);
    CHECK(reader.ReadUB4() == 0x429); // PARSE | EXECUTE | BIND | PLSQL_BIND
    const std::vector<uint8_t> cursor_placeholder {TTC_MESSAGE_ROW_DATA, 0, 2, 0xc1, 0x02};
    CHECK(std::search(encoded.begin(), encoded.end(), cursor_placeholder.begin(), cursor_placeholder.end()) != encoded.end());

    request.binds.front().direction = BindDirection::BIND_IN;
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { EncodeTtcExecuteBindsRequest(request); });
    request.binds.front().direction = BindDirection::BIND_OUT;
    request.binds[1].direction = BindDirection::BIND_OUT;
    request.binds[1].value.reset();
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { EncodeTtcExecuteBindsRequest(request); });
}

// Array DML: one parse, one set of bind metadata, one ROW_DATA per row. The
// execution count lives in al8i4[1], and the metadata has to be sized to the
// widest value across every iteration because Oracle sizes its own buffer from
// it and never sees the later rows' lengths any other way.
static void TestTtcExecuteArrayDml() {
    TtcExecuteBindsRequest request;
    request.sql = "insert into t (a, b) values (:1, :2)";
    request.binds = {{"1", 2, BindDirection::BIND_IN, std::vector<uint8_t> {0xc1, 0x02}},
                     {"2", 1, BindDirection::BIND_IN, std::vector<uint8_t> {'x'}}};
    request.additional_iterations = {
        {{"1", 2, BindDirection::BIND_IN, std::vector<uint8_t> {0xc1, 0x03}},
         {"2", 1, BindDirection::BIND_IN, std::vector<uint8_t> {'l', 'o', 'n', 'g', 'e', 'r'}}}};
    const auto encoded = EncodeTtcExecuteBindsRequest(request);

    // The SQL text is the last thing before al8i4, so the execution count is
    // the second UB4 after it.
    const std::vector<uint8_t> sql_bytes(request.sql.begin(), request.sql.end());
    const auto sql_at = std::search(encoded.begin(), encoded.end(), sql_bytes.begin(), sql_bytes.end());
    CHECK(sql_at != encoded.end());
    // The reader holds a reference, so the tail has to outlive it.
    const std::vector<uint8_t> after_sql(sql_at + static_cast<std::ptrdiff_t>(sql_bytes.size()), encoded.end());
    ByteReader al8i4(after_sql);
    CHECK(al8i4.ReadUB4() == 1); // al8i4[0]: parse on a fresh cursor
    CHECK(al8i4.ReadUB4() == 2); // al8i4[1]: two executions

    // One ROW_DATA per iteration, in order, each carrying its own row.
    const std::vector<uint8_t> first_row {TTC_MESSAGE_ROW_DATA, 2, 0xc1, 0x02, 1, 'x'};
    const std::vector<uint8_t> second_row {TTC_MESSAGE_ROW_DATA, 2,   0xc1, 0x03, 6,
                                           'l',                  'o', 'n',  'g',  'e', 'r'};
    const auto first_at = std::search(encoded.begin(), encoded.end(), first_row.begin(), first_row.end());
    const auto second_at = std::search(encoded.begin(), encoded.end(), second_row.begin(), second_row.end());
    CHECK(first_at != encoded.end() && second_at != encoded.end() && first_at < second_at);

    // The second row's six-byte value is what the character bind's buffer must
    // be sized to; declaring the first row's single byte would truncate it.
    const std::vector<uint8_t> narrow_buffer {1, 1, 1, 0, 0, 1, 1};
    CHECK(std::search(encoded.begin(), encoded.end(), narrow_buffer.begin(), narrow_buffer.end()) == encoded.end());
    const std::vector<uint8_t> wide_buffer {1, 1, 0, 0, 1, 6};
    CHECK(std::search(encoded.begin(), encoded.end(), wide_buffer.begin(), wide_buffer.end()) != encoded.end());

    // Every iteration is described by the one metadata block, so a row that
    // disagrees with it would be read as the type the first row declared.
    auto mismatched = request;
    mismatched.additional_iterations[0][1].oracle_type = 2;
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { EncodeTtcExecuteBindsRequest(mismatched); });
    auto short_row = request;
    short_row.additional_iterations[0].pop_back();
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { EncodeTtcExecuteBindsRequest(short_row); });

    // A PL/SQL array bind is a different wire feature and a query has no
    // iterations; neither is guessed at here.
    auto plsql = request;
    plsql.is_plsql = true;
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [&] { EncodeTtcExecuteBindsRequest(plsql); });
    auto query = request;
    query.is_query = true;
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [&] { EncodeTtcExecuteBindsRequest(query); });

    // Every iteration writes into the same OUT buffer, and nothing here has
    // evidence for how Oracle returns the set.
    auto out_bind = request;
    out_bind.binds[1].direction = BindDirection::BIND_OUT;
    out_bind.binds[1].maximum_bytes = 16;
    out_bind.additional_iterations[0][1].direction = BindDirection::BIND_OUT;
    out_bind.additional_iterations[0][1].maximum_bytes = 16;
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [&] { EncodeTtcExecuteBindsRequest(out_bind); });
}

// The end-of-call of a real DML carries oerrdd, the logical rowid of the row it
// touched: a UB4 length and then, only when that length is non-zero, the buffer
// itself. Every fetch end-of-call leaves it empty, where reading the buffer
// unconditionally as one length-prefixed field is indistinguishable — so this
// is the capture that separates the two readings. 19c, `INSERT INTO t (id,
// label) VALUES (:1, :2)` run once.
// A failed array DML says which iteration it was on. Without it the caller is
// told that a batch of a thousand rows violated a constraint and nothing about
// which row did it, since Oracle's own text names only the constraint.
static void TestTtcErrorNamesTheFailingIteration() {
    ByteWriter writer;
    writer.WriteByte(4);          // TTIOER
    writer.WriteUB4(2);           // call status
    writer.WriteUB2(0);           // end-to-end sequence
    writer.WriteUB4(4);           // current row: the fifth iteration, zero-based
    writer.WriteUB2(1);           // legacy short error number
    writer.WriteUB2(0).WriteUB2(0);
    writer.WriteUB4(2);           // cursor id
    writer.WriteUB4(0);           // sql offset
    writer.WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0);
    writer.WriteUB4(0).WriteUB2(0).WriteByte(0).WriteUB4(0).WriteUB2(0); // rowid
    writer.WriteUB4(0);           // OS error
    writer.WriteByte(0).WriteByte(0);
    writer.WriteUB2(0);           // padding
    writer.WriteUB4(4);           // successful iterations
    writer.WriteUB4(0);           // oerrdd length
    writer.WriteByte(0).WriteByte(0).WriteByte(0); // batch arrays, all empty
    writer.WriteUB4(1);           // ORA-00001
    writer.WriteUB8(4);           // rows affected before the failure
    const std::string text = "ORA-00001: unique constraint violated\n";
    writer.WriteLengthPrefixed(std::vector<uint8_t>(text.begin(), text.end()));

    const auto decoded = DecodeTtcErrorPrefix(writer.Data(), 12);
    CHECK(decoded.error_number == 1);
    CHECK(decoded.current_row == 4);
    // Oracle ends its message with a newline. Carrying it into an exception
    // hides whatever a caller appends and wraps the message in any display
    // that stops at the first line — which is exactly what it did.
    CHECK(decoded.message == "ORA-00001: unique constraint violated");
}

static void TestTtcErrorCarriesADmlRowId() {
    const std::vector<uint8_t> completion {
        0x04, 0x01, 0x02, 0x02, 0xd3, 0xbc, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x24, 0x68, 0x01, 0x01, 0x00, 0x02, 0x86, 0xe9,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x0d, 0x0d, 0x01, 0x00, 0x01, 0x24, 0x68,
        0x00, 0x01, 0x00, 0x00, 0x86, 0xe9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01};
    const auto decoded = DecodeTtcErrorPrefix(completion, 12);
    CHECK(decoded.error_number == 0);
    CHECK(decoded.row_count == 1);
    CHECK(decoded.bytes_consumed == completion.size());

    // The same statement run three times in one array DML, which is the only
    // thing that differs: three successful iterations and three rows.
    const std::vector<uint8_t> batched {
        0x04, 0x01, 0x02, 0x02, 0xd3, 0xa0, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x0c,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x24, 0x68, 0x01, 0x01, 0x00, 0x02, 0x86,
        0xe9, 0x01, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0x01, 0x0d, 0x0d, 0x01, 0x00, 0x01,
        0x24, 0x68, 0x00, 0x01, 0x00, 0x00, 0x86, 0xe9, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x03};
    const auto batched_decoded = DecodeTtcErrorPrefix(batched, 12);
    CHECK(batched_decoded.error_number == 0);
    CHECK(batched_decoded.row_count == 3);
    CHECK(batched_decoded.bytes_consumed == batched.size());
}

// The local TLS server and the closed-peer write test are built on POSIX
// sockets and signals. Porting them to Winsock would be a second
// implementation of the thing under test, so they are simply not built on
// Windows — everything else in this suite is portable and still runs there.
#if !defined(_WIN32)
// A local TLS server, so certificate verification can be tested against cases
// no live endpoint offers: an expired certificate, and the wallet-free path
// where the client presents nothing and trusts an explicit CA. Everything is
// loopback and in-memory; nothing here talks to Oracle.
namespace local_tls {

struct Identity {
    std::string certificate_pem;
    std::string key_pem;
};

static std::string PemOf(const std::function<int(BIO *)> &writer) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    CHECK(bio && writer(bio.get()) == 1);
    char *data = nullptr;
    const auto size = BIO_get_mem_data(bio.get(), &data);
    CHECK(size > 0);
    return std::string(data, data + size);
}

// A self-signed certificate that is also its own trust root, so a test can hand
// it to the client as the CA and get a chain of one.
static Identity MakeIdentity(const std::string &common_name, long not_before_seconds, long not_after_seconds) {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> key_context(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    CHECK(key_context && EVP_PKEY_keygen_init(key_context.get()) == 1);
    CHECK(EVP_PKEY_CTX_set_rsa_keygen_bits(key_context.get(), 2048) == 1);
    EVP_PKEY *raw_key = nullptr;
    CHECK(EVP_PKEY_keygen(key_context.get(), &raw_key) == 1);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw_key, EVP_PKEY_free);

    std::unique_ptr<X509, decltype(&X509_free)> certificate(X509_new(), X509_free);
    CHECK(certificate);
    CHECK(X509_set_version(certificate.get(), 2) == 1);
    CHECK(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) == 1);
    CHECK(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), not_before_seconds) != nullptr);
    CHECK(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), not_after_seconds) != nullptr);
    CHECK(X509_set_pubkey(certificate.get(), key.get()) == 1);
    auto *name = X509_get_subject_name(certificate.get());
    CHECK(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                      reinterpret_cast<const unsigned char *>(common_name.c_str()), -1, -1, 0) == 1);
    CHECK(X509_set_issuer_name(certificate.get(), name) == 1);
    X509V3_CTX extension_context;
    X509V3_set_ctx_nodb(&extension_context);
    X509V3_set_ctx(&extension_context, certificate.get(), certificate.get(), nullptr, nullptr, 0);
    const auto add_extension = [&](int nid, const std::string &value) {
        std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> extension(
            X509V3_EXT_conf_nid(nullptr, &extension_context, nid, value.c_str()), X509_EXTENSION_free);
        CHECK(extension && X509_add_ext(certificate.get(), extension.get(), -1) == 1);
    };
    add_extension(NID_basic_constraints, "critical,CA:TRUE");
    add_extension(NID_subject_alt_name, "DNS:" + common_name);
    CHECK(X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0);

    Identity identity;
    identity.certificate_pem = PemOf([&](BIO *bio) { return PEM_write_bio_X509(bio, certificate.get()); });
    identity.key_pem = PemOf(
        [&](BIO *bio) { return PEM_write_bio_PrivateKey(bio, key.get(), nullptr, nullptr, 0, nullptr, nullptr); });
    return identity;
}

// Accepts exactly one connection, completes the handshake, and closes. The
// client under test only needs the handshake's verdict.
class Server {
public:
    explicit Server(const Identity &identity) {
        context = SSL_CTX_new(TLS_server_method());
        CHECK(context);
        std::unique_ptr<BIO, decltype(&BIO_free)> certificate_bio(
            BIO_new_mem_buf(identity.certificate_pem.data(), static_cast<int>(identity.certificate_pem.size())),
            BIO_free);
        std::unique_ptr<X509, decltype(&X509_free)> certificate(
            PEM_read_bio_X509(certificate_bio.get(), nullptr, nullptr, nullptr), X509_free);
        std::unique_ptr<BIO, decltype(&BIO_free)> key_bio(
            BIO_new_mem_buf(identity.key_pem.data(), static_cast<int>(identity.key_pem.size())), BIO_free);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
            PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
        CHECK(certificate && key);
        CHECK(SSL_CTX_use_certificate(context, certificate.get()) == 1);
        CHECK(SSL_CTX_use_PrivateKey(context, key.get()) == 1);

        listener = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(listener >= 0);
        int reuse = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        CHECK(bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
        CHECK(listen(listener, 1) == 0);
        socklen_t address_size = sizeof(address);
        CHECK(getsockname(listener, reinterpret_cast<sockaddr *>(&address), &address_size) == 0);
        port = ntohs(address.sin_port);
        worker = std::thread([this] { Serve(); });
    }

    ~Server() {
        if (worker.joinable()) {
            worker.join();
        }
        if (listener >= 0) {
            close(listener);
        }
        if (context) {
            SSL_CTX_free(context);
        }
    }

    uint16_t Port() const {
        return port;
    }

private:
    void Serve() {
        // This thread's own writes can meet a client that has already rejected
        // the certificate and gone. Blocking the signal here, rather than for
        // the whole process, keeps the main thread's disposition at the default
        // — which is what makes the client-side protection in openssl_stream
        // something this suite actually exercises rather than hides.
        sigset_t block;
        sigemptyset(&block);
        sigaddset(&block, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &block, nullptr);

        const auto accepted = accept(listener, nullptr, nullptr);
        if (accepted < 0) {
            return;
        }
        auto *ssl = SSL_new(context);
        if (ssl) {
            SSL_set_fd(ssl, accepted);
            // A rejected certificate makes this fail, which is the expected
            // outcome for three of the four cases and not an error here.
            (void)SSL_accept(ssl);
            SSL_free(ssl);
        }
        close(accepted);
    }

    SSL_CTX *context = nullptr;
    int listener = -1;
    uint16_t port = 0;
    std::thread worker;
};

} // namespace local_tls

// The wallet-free TLS path and the certificate cases no live endpoint provides.
static void TestLocalTlsCertificateVerification() {
    const std::string server_name = "oracle-scanner.test";
    const auto valid = local_tls::MakeIdentity(server_name, -3600, 3600);
    const auto expired = local_tls::MakeIdentity(server_name, -7200, -3600);
    const auto other = local_tls::MakeIdentity(server_name, -3600, 3600);

    // Wallet-free: the client presents no certificate of its own and trusts an
    // explicit CA. This is the path no live endpoint here exercises.
    {
        local_tls::Server server(valid);
        TlsConfiguration tls;
        tls.server_name = server_name;
        tls.ca_pem_contents = valid.certificate_pem;
        auto stream = OpenSslByteStream::Connect("127.0.0.1", server.Port(), 5, 5, true, tls);
        CHECK(stream);
        stream->Close();
    }

    // An expired certificate is refused even though it is the very certificate
    // the client was told to trust.
    {
        local_tls::Server server(expired);
        TlsConfiguration tls;
        tls.server_name = server_name;
        tls.ca_pem_contents = expired.certificate_pem;
        ExpectProtocolError([&] { (void)OpenSslByteStream::Connect("127.0.0.1", server.Port(), 5, 5, true, tls); });
    }

    // A name the certificate does not carry.
    {
        local_tls::Server server(valid);
        TlsConfiguration tls;
        tls.server_name = "oracle-scanner.invalid";
        tls.ca_pem_contents = valid.certificate_pem;
        ExpectProtocolError([&] { (void)OpenSslByteStream::Connect("127.0.0.1", server.Port(), 5, 5, true, tls); });
    }

    // A CA that did not sign what the server presented, even though both carry
    // the same subject.
    {
        local_tls::Server server(valid);
        TlsConfiguration tls;
        tls.server_name = server_name;
        tls.ca_pem_contents = other.certificate_pem;
        ExpectProtocolError([&] { (void)OpenSslByteStream::Connect("127.0.0.1", server.Port(), 5, 5, true, tls); });
    }

    // And the DN check on top of a certificate that already verifies.
    {
        local_tls::Server server(valid);
        TlsConfiguration tls;
        tls.server_name = server_name;
        tls.ca_pem_contents = valid.certificate_pem;
        tls.expected_server_dn = "CN=" + server_name;
        auto stream = OpenSslByteStream::Connect("127.0.0.1", server.Port(), 5, 5, true, tls);
        CHECK(stream);
        stream->Close();
    }
    {
        local_tls::Server server(valid);
        TlsConfiguration tls;
        tls.server_name = server_name;
        tls.ca_pem_contents = valid.certificate_pem;
        tls.expected_server_dn = "CN=oracle-scanner.invalid";
        ExpectProtocolError([&] { (void)OpenSslByteStream::Connect("127.0.0.1", server.Port(), 5, 5, true, tls); });
    }
}
#endif // !_WIN32

// A descriptor may name the server certificate's DN, and Oracle writes it
// double-quoted because it contains commas, spaces and '='. Until the parser
// accepted a quoted value, such a descriptor did not merely lose the DN — it
// failed to parse at all, so the whole alias was unusable.
static void TestDescriptorSecuritySection() {
    const std::string with_dn =
        "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=db.example.com)(PORT=1522))"
        "(CONNECT_DATA=(SERVICE_NAME=svc))"
        "(SECURITY=(SSL_SERVER_DN_MATCH=yes)"
        "(SSL_SERVER_CERT_DN=\"CN=db.example.com, O=Example Corp, L=Redwood City, ST=California, C=US\")))";
    const auto parsed = ParseConnectDescriptor(with_dn);
    CHECK(parsed.endpoints.size() == 1 && parsed.service_name == "svc");
    CHECK(parsed.server_cert_dn == "CN=db.example.com, O=Example Corp, L=Redwood City, ST=California, C=US");
    CHECK(parsed.server_dn_match);

    // A descriptor that names no DN is the current Autonomous Database shape;
    // hostname verification still applies and nothing is relaxed.
    const std::string without_dn =
        "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=db.example.com)(PORT=1522))"
        "(CONNECT_DATA=(SERVICE_NAME=svc))(SECURITY=(SSL_SERVER_DN_MATCH=yes)))";
    const auto plain = ParseConnectDescriptor(without_dn);
    CHECK(plain.server_cert_dn.empty() && plain.server_dn_match);

    // ssl_server_dn_match=no is recorded, and that is all it does: this client
    // has no insecure mode to fall back to.
    const std::string dn_match_off =
        "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=db.example.com)(PORT=1522))"
        "(CONNECT_DATA=(SERVICE_NAME=svc))(SECURITY=(SSL_SERVER_DN_MATCH=no)))";
    CHECK(!ParseConnectDescriptor(dn_match_off).server_dn_match);

    // The quoted form is the only place those characters are allowed; an
    // unquoted value carrying them is still a malformed descriptor.
    ExpectError(ProtocolErrorKind::MALFORMED, [] {
        ParseConnectDescriptor("(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=db.example.com)(PORT=1522))"
                               "(CONNECT_DATA=(SERVICE_NAME=svc))(SECURITY=(SSL_SERVER_CERT_DN=CN=db, O=Example)))");
    });
    ExpectError(ProtocolErrorKind::MALFORMED, [] {
        ParseConnectDescriptor("(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=db.example.com)(PORT=1522))"
                               "(CONNECT_DATA=(SERVICE_NAME=svc))(SECURITY=(SSL_SERVER_CERT_DN=\"CN=db)))");
    });
}

// The DN check compares identities, not renderings. OpenSSL prints a subject
// outermost-first and Oracle's tnsnames.ora writes it the other way round, so
// comparing the two strings would reject a certificate that matches.
static void TestServerDnComparison() {
    const std::string openssl_form = "CN=host.example.com,O=Example Corp,L=Redwood City,ST=California,C=US";
    const std::string oracle_form = "C=US, ST=California, L=Redwood City, O=Example Corp, CN=host.example.com";
    CHECK(OracleServerDnMatches(openssl_form, openssl_form));
    CHECK(OracleServerDnMatches(oracle_form, openssl_form));
    // Attribute names are case-insensitive; values are not.
    CHECK(OracleServerDnMatches("cn=host.example.com,o=Example Corp,l=Redwood City,st=California,c=US", openssl_form));
    CHECK(!OracleServerDnMatches("CN=HOST.EXAMPLE.COM,O=Example Corp,L=Redwood City,ST=California,C=US", openssl_form));
    // A DN that is a subset of the certificate's is a different identity, not a
    // weaker form of the same one.
    CHECK(!OracleServerDnMatches("CN=host.example.com,O=Example Corp", openssl_form));
    CHECK(!OracleServerDnMatches("CN=other.example.com,O=Example Corp,L=Redwood City,ST=California,C=US",
                                  openssl_form));
    // A comma inside a value is escaped, and splitting on it blindly would turn
    // one component into two.
    CHECK(OracleServerDnMatches("O=Example\\, Inc,CN=host", "CN=host,O=Example\\, Inc"));
    CHECK(!OracleServerDnMatches("", openssl_form));
}

static void TestO5LogonFlow() {
    const std::string password_text = "password";
    std::vector<uint8_t> password(password_text.begin(), password_text.end());
    std::vector<uint8_t> verifier(16, 1);
    std::vector<uint8_t> server_key(32, 2);
    std::vector<uint8_t> combo_salt(16, 3);
    std::vector<uint8_t> client_key(32, 4);
    std::vector<uint8_t> password_salt(16, 5);
    std::vector<uint8_t> speedy_key_salt(16, 6);
    std::vector<uint8_t> verifier_salt = verifier;
    const std::string speedy_key = "AUTH_PBKDF2_SPEEDY_KEY";
    verifier_salt.insert(verifier_salt.end(), speedy_key.begin(), speedy_key.end());
    auto password_key = Pbkdf2Sha512(password, verifier_salt, 4096, 64);
    auto password_hash = Sha512({password_key, verifier});
    password_hash.resize(32);

    O5LogonChallenge challenge {UpperHex(verifier), UpperHex(AesCbcEncryptRaw(password_hash, server_key)),
                                 UpperHex(combo_salt), 4096, 3, 0x4815};
    auto expected = BuildO5LogonResponse(password_text, challenge, client_key, password_salt, speedy_key_salt);
    // Independent fixture generated by python-oracledb Thin crypto.pyx using
    // the deterministic values above. Keep this separate from the local
    // decrypt/re-encrypt checks: it catches argument order and padding drift.
    CHECK(expected.client_session_key_hex == "943AC8F19CBDD7B87FE42E647CA185C525BBEA12F29754E044880948317ACF4C");
    CHECK(expected.speedy_key_hex ==
           "AF5BAE5C9A0695915753A469A1EC49825CAFD9423545249D7097DBFBF9A0903D60767610ED701A5A0172D314C408C4FD"
           "AF4A1AC6BCFE6DF669B5D842CB1CAA513D3626553C708442140278484D6A910D");
    CHECK(expected.encrypted_password_hex == "7801985D953F1D0B60D3B97C91019FD7DFA434F5836344CCAD0EA929FCC8FEB9");
    std::vector<uint8_t> proof(16, 0);
    proof.insert(proof.end(), {'S', 'E', 'R', 'V', 'E', 'R', '_', 'T', 'O', '_', 'C', 'L', 'I', 'E', 'N', 'T'});
    const std::vector<TtcParameter> challenge_parameters = {
        {"AUTH_VFR_DATA", challenge.verifier_data_hex, 0},
        {"AUTH_SESSKEY", challenge.server_session_key_hex, 0},
        {"AUTH_PBKDF2_CSK_SALT", challenge.combo_key_salt_hex, 0},
        {"AUTH_PBKDF2_VGEN_COUNT", "4096", 0},
        {"AUTH_PBKDF2_SDER_COUNT", "3", 0}};
    const std::vector<TtcParameter> proof_parameters = {
        {"AUTH_SVR_RESPONSE", UpperHex(AesCbcEncrypt(expected.combo_key, proof)), 0}};
    std::vector<uint8_t> inbound;
    for (const auto &packet : EncodeTnsDataPackets(EncodeTtcParameters(challenge_parameters), true, 128)) {
        inbound.insert(inbound.end(), packet.begin(), packet.end());
    }
    for (const auto &packet : EncodeTnsDataPackets(EncodeTtcParameters(proof_parameters), true, 128)) {
        inbound.insert(inbound.end(), packet.begin(), packet.end());
    }
    FragmentedStream stream(inbound, 7);
    TnsPacketStream packets(stream, true, 128);
    TtcChannel channel(packets, 128);
    O5LogonRequest request;
    request.username = "scott";
    request.password = password_text;
    request.phase_one_parameters = {{"AUTH_PROGRAM_NM", "DuckDB", 0}};
    request.client_session_key = client_key;
    request.password_salt = password_salt;
    request.speedy_key_salt = speedy_key_salt;
    auto response = RunO5Logon(channel, request);
    CHECK(response.client_session_key_hex == expected.client_session_key_hex);
    CHECK(!stream.output.empty());
}

static void TestConnectDescriptor() {
    ConnectionConfig config;
    config.host = "db.example.com";
    config.service_name = "ORCLPDB1";
    auto descriptor = BuildConnectDescriptor(config);
    CHECK(descriptor.find("(PROTOCOL=tcp)") != std::string::npos);
    CHECK(descriptor.find("(HOST=db.example.com)") != std::string::npos);
    CHECK(descriptor.find("(SERVICE_NAME=ORCLPDB1)") != std::string::npos);
    CHECK(BuildAuthConnectString(config).find("(CID=") == std::string::npos);
    CHECK(BuildAuthConnectString(config).find("(SERVICE_NAME=ORCLPDB1)") != std::string::npos);
    config.connection_id = "A1B2C3";
    CHECK(BuildConnectDescriptor(config).find("(CONNECTION_ID=A1B2C3)") != std::string::npos);
    CHECK(BuildAuthConnectString(config).find("(CONNECTION_ID=A1B2C3)") != std::string::npos);
    const auto identity = CurrentOracleClientIdentity();
    CHECK(!identity.program.empty() && identity.program.front() == '/' && identity.terminal == "unknown" && !identity.machine.empty() &&
           !identity.process_id.empty() && !identity.os_user.empty());

    config.host = "bad)(HOST=attacker";
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { BuildConnectDescriptor(config); });

    config.host = "db.example.com";
    config.tls_server_name = "wallet.example.com";
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { BuildConnectDescriptor(config); });
    config.protocol = TransportProtocol::TCPS;
    CHECK(BuildConnectDescriptor(config).find("(PROTOCOL=tcps)") != std::string::npos);
    config.tls_sni_name = "sni.example.com";
    CHECK(BuildConnectDescriptor(config).find("(PROTOCOL=tcps)") != std::string::npos);
    config.tls_sni_name = "bad)(HOST=attacker";
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { BuildConnectDescriptor(config); });
    config.tls_sni_name.clear();
    config.tls_server_name = "bad)(HOST=attacker";
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { BuildConnectDescriptor(config); });
    config.tls_server_name.clear();
    config.host = "2001:db8::1";
    CHECK(BuildConnectDescriptor(config).find("(HOST=2001:db8::1)") != std::string::npos);
    config.host = "2001:db8::1)(HOST=attacker";
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { BuildConnectDescriptor(config); });
    config.host = "a:b";
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { BuildConnectDescriptor(config); });
    config.host = "db.example.com";
    config.tls_sni_name = std::string(256, 'a');
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { BuildConnectDescriptor(config); });
}

static void TestDescriptorParser() {
    auto parsed = ParseConnectDescriptor(
        "(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCPS)(HOST=db-one.example)(PORT=1522))"
        "(ADDRESS=(PROTOCOL=TCP)(HOST=db-two.example)(PORT=1521)))(CONNECT_DATA=(SERVICE_NAME=ORCLPDB1)))");
    CHECK(parsed.service_name == "ORCLPDB1" && parsed.endpoints.size() == 2);
    CHECK(parsed.endpoints[0].protocol == TransportProtocol::TCPS && parsed.endpoints[0].port == 1522);
    CHECK(parsed.endpoints[1].protocol == TransportProtocol::TCP && parsed.endpoints[1].host == "db-two.example");
    const auto spaced = ParseConnectDescriptor(
        " ( DESCRIPTION = ( ADDRESS = ( PROTOCOL = tcps ) ( HOST = db.example ) ( PORT = 1522 ) ) "
        "( CONNECT_DATA = ( SERVICE_NAME = unit_low.example ) ) ) ");
    CHECK(spaced.endpoints.size() == 1 && spaced.endpoints[0].protocol == TransportProtocol::TCPS &&
           spaced.endpoints[0].host == "db.example" && spaced.service_name == "unit_low.example");
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [] {
        ParseConnectDescriptor("(DESCRIPTION=(ADDRESS=(PROTOCOL=IPC)(HOST=x)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=x)))");
    });
    ExpectError(ProtocolErrorKind::MALFORMED, [] {
        ParseConnectDescriptor("(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=x)(PORT=no))(CONNECT_DATA=(SERVICE_NAME=x)))");
    });
    ExpectError(ProtocolErrorKind::MALFORMED, [] {
        ParseConnectDescriptor(
            "(NOT_DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=x)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=x)))");
    });
    ExpectError(ProtocolErrorKind::MALFORMED, [] {
        ParseConnectDescriptor("(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=x)(PORT=1))(SERVICE_NAME=x))");
    });
}

static void TestValueCodecs() {
    OracleDateTime value;
    value.year = 2026;
    value.month = 8;
    value.day = 18;
    value.hour = 12;
    value.minute = 34;
    value.second = 56;
    value.nanosecond = 123456789;
    value.offset_minutes = 240;
    value.has_offset = true;

    auto date = DecodeOracleDate(EncodeOracleDate(value));
    CHECK(date.year == value.year && date.month == value.month && date.day == value.day);
    auto timestamp = DecodeOracleTimestamp(EncodeOracleTimestamp(value, true));
    CHECK(timestamp.nanosecond == value.nanosecond);
    CHECK(timestamp.offset_minutes == value.offset_minutes);

    for (auto input : {0.0, -0.0, 1.25, -18.5, std::numeric_limits<double>::infinity()}) {
        auto decoded = DecodeOracleBinaryDouble(EncodeOracleBinaryDouble(input));
        CHECK(decoded == input);
    }

    value.month = 2;
    value.day = 30;
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { EncodeOracleDate(value); });

    const std::vector<std::pair<std::string, std::string>> numbers = {
        {"0", "0"},       {"1", "1"},         {"-1", "-1"},       {"12.34", "12.34"},
        {"0.01", "0.01"}, {".1", "0.1"},      {"-0.001", "-0.001"},
        {"1e6", "1000000"}, {"1234567890123456789012345678901234567890", "1234567890123456789012345678901234567890"}};
    for (const auto &number : numbers) {
        CHECK(DecodeOracleNumber(EncodeOracleNumber(number.first)) == number.second);
    }
    CHECK(EncodeOracleNumber("1") == std::vector<uint8_t>({193, 2}));
    CHECK(EncodeOracleNumber("-1") == std::vector<uint8_t>({62, 100, 102}));
    CHECK(EncodeOracleNumber("1234") == std::vector<uint8_t>({194, 13, 35}));
    CHECK(DecodeOracleNumber({192, 2}) == "0.01");
    ExpectError(ProtocolErrorKind::MALFORMED, [] { EncodeOracleNumber("1.2.3"); });
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [] { EncodeOracleNumber("1e1000"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { DecodeOracleNumber({193, 1}); });
}

class TestCursor : public OracleCursor {
public:
    explicit TestCursor(size_t &closed_p) : closed(closed_p) {
    }
    const std::vector<OracleColumn> &Columns() const override {
        return columns;
    }
    OracleBatch Fetch(size_t) override {
        return {};
    }
    void Cancel() override {
    }
    void Close() override {
        closed++;
    }

private:
    size_t &closed;
    std::vector<OracleColumn> columns;
};

static void TestCallRegistry() {
    size_t closed = 0;
    CallRegistry registry(2);
    std::vector<std::unique_ptr<OracleCursor>> cursors;
    cursors.push_back(std::make_unique<TestCursor>(closed));
    cursors.push_back(std::make_unique<TestCursor>(closed));
    auto handles = registry.Register(std::move(cursors));
    CHECK(handles.size() == 2 && handles[0].call_id == handles[1].call_id);
    CHECK(FormatCursorHandle(handles[0]) == "oracle:1:1");
    const auto parsed = ParseCursorHandle("oracle:1:1");
    CHECK(parsed.call_id == handles[0].call_id && parsed.cursor_id == handles[0].cursor_id);
    ExpectError(ProtocolErrorKind::MALFORMED, [] { ParseCursorHandle("oracle:01:1"); });
    CHECK(registry.OpenCursorCount() == 2);

    auto consumed = registry.Take(handles[0]);
    CHECK(registry.OpenCursorCount() == 1);
    ExpectError(ProtocolErrorKind::INVALID_STATE, [&] { registry.Take(handles[0]); });
    consumed->Close();
    CHECK(registry.Close(handles[0].call_id));
    CHECK(closed == 2 && registry.OpenCursorCount() == 0);
    CHECK(!registry.Close(handles[0].call_id));

    std::vector<std::unique_ptr<OracleCursor>> too_many;
    for (size_t index = 0; index < 3; index++) {
        too_many.push_back(std::make_unique<TestCursor>(closed));
    }
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { registry.Register(std::move(too_many)); });

    OracleCallResult result;
    result.explicit_cursors.push_back(std::make_unique<TestCursor>(closed));
    result.implicit_cursors.push_back(std::make_unique<TestCursor>(closed));
    CallRegistry call_result_registry(2);
    const auto result_handles = call_result_registry.Register(std::move(result));
    CHECK(result_handles.size() == 2 && result_handles[0].cursor_id == 1 && result_handles[1].cursor_id == 2);
    call_result_registry.CloseAll();
}

static void TestProcedureCallBuilder() {
    const std::vector<OracleBind> arguments = {{"p_id", 0, BindDirection::BIND_IN, std::nullopt},
                                               {"p_result", 0, BindDirection::BIND_OUT, std::nullopt}};
    CHECK(ParseOracleCallableName("app.billing.process_invoice") == "app.billing.process_invoice");
    CHECK(ParseOracleCallableName("\"App\".\"Do Work\"") == "\"App\".\"Do Work\"");
    CHECK(BuildOracleProcedureCallBlock("app.billing.process_invoice", arguments) ==
           "BEGIN app.billing.process_invoice(p_id => :p_id, p_result => :p_result); END;");
    CHECK(BuildOracleProcedureCallBlock("app.ping", {}) == "BEGIN app.ping; END;");
    OracleBind return_bind {"return_value", 0, BindDirection::BIND_OUT, std::nullopt};
    CHECK(BuildOracleFunctionCallBlock("app.billing.invoice_total", return_bind, arguments) ==
           "BEGIN :return_value := app.billing.invoice_total(p_id => :p_id, p_result => :p_result); END;");
    OracleCallRequest function_request {OracleCallableKind::FUNCTION, "app.answer", return_bind, {}};
    CHECK(BuildOracleCallBlock(function_request) == "BEGIN :return_value := app.answer; END;");
    function_request.return_bind.reset();
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { BuildOracleCallBlock(function_request); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { ParseOracleCallableName("app.proc; DELETE FROM x"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { ParseOracleCallableName("\"unterminated"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [&] {
        BuildOracleProcedureCallBlock("app.proc", {{"p", 0, BindDirection::BIND_IN, std::nullopt},
                                                     {"P", 0, BindDirection::BIND_IN, std::nullopt}});
    });
    return_bind.direction = BindDirection::BIND_IN;
    ExpectError(ProtocolErrorKind::MALFORMED,
                [&] { BuildOracleFunctionCallBlock("app.answer", return_bind, {}); });
}

static void TestBindValidation() {
    const std::vector<OracleBind> binds = {{"id", 2, BindDirection::BIND_IN, std::vector<uint8_t> {1}},
                                           {"label", 1, BindDirection::BIND_IN, std::nullopt}};
    CHECK(CanonicalOracleBindName("p$name#1") == "P$NAME#1" && CanonicalOracleBindName("1") == "1");
    ValidateOracleBinds(binds, OracleBindUse::QUERY);
    ValidateOracleBindBatch({binds, {{"ID", 2, BindDirection::BIND_IN, std::vector<uint8_t> {2}},
                                     {"LABEL", 1, BindDirection::BIND_IN, std::vector<uint8_t> {'x'}}}});
    ExpectError(ProtocolErrorKind::MALFORMED, [] { CanonicalOracleBindName("1bad"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [&] {
        ValidateOracleBinds({{"id", 2, BindDirection::BIND_IN, std::nullopt}, {"ID", 2, BindDirection::BIND_IN, std::nullopt}},
                            OracleBindUse::DML);
    });
    ExpectError(ProtocolErrorKind::MALFORMED, [&] {
        ValidateOracleBinds({{"out_value", 2, BindDirection::BIND_OUT, std::nullopt}}, OracleBindUse::QUERY);
    });
}

static void TestSqlBindExtraction() {
    const std::string sql = "select :first, ':ignored', q'[ :also_ignored ]', :1 -- :comment\n"
                            "from dual /* :block */ where id = :FIRST";
    const auto placeholders = ExtractOracleBindPlaceholders(sql);
    CHECK(placeholders == std::vector<std::string>({"FIRST", "1"}));
    ValidateOracleStatementBinds(sql, {{"first", 1, BindDirection::BIND_IN, std::nullopt},
                                       {"1", 2, BindDirection::BIND_IN, std::nullopt}},
                                OracleBindUse::QUERY);
    const auto ordered = OrderOracleStatementBinds("select :second, :first from dual",
                                                   {{"first", 1, BindDirection::BIND_IN, std::nullopt},
                                                    {"second", 2, BindDirection::BIND_IN, std::nullopt}},
                                                   OracleBindUse::QUERY);
    CHECK(ordered.size() == 2 && ordered[0].name == "second" && ordered[1].name == "first");
    ExpectError(ProtocolErrorKind::MALFORMED, [&] {
        ValidateOracleStatementBinds(sql, {{"first", 1, BindDirection::BIND_IN, std::nullopt}}, OracleBindUse::QUERY);
    });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { ExtractOracleBindPlaceholders("select 'unterminated"); });
}

static void TestSqlStatementValidation() {
    const std::vector<OracleBind> binds = {{"id", 2, BindDirection::BIND_IN, std::nullopt}};
    CHECK(ClassifyOracleSql(" /* leading */ SELECT ':not_a_bind' FROM dual WHERE id = :id") == OracleSqlKind::QUERY);
    CHECK(ClassifyOracleSql("update invoices set state = 'paid' where id = :id") == OracleSqlKind::DML);
    CHECK(ClassifyOracleSql("begin app.ping; end") == OracleSqlKind::PLSQL);
    ValidateOracleQuery("select * from invoices where id = :id", binds);
    ValidateOracleDml("delete from invoices where id = :id", binds);
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { ValidateOracleQuery("delete from invoices where id = :id", binds); });
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { ValidateOracleDml("merge into invoices x using dual on (1=1)", {}); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { ValidateOracleQuery("select 1; delete from x", {}); });
}

class TestSession : public OracleSession {
public:
    std::unique_ptr<OracleCursor> Query(const std::string &, const std::vector<OracleBind> &) override {
        queries++;
        return nullptr;
    }
    uint64_t Execute(const std::string &, const std::vector<OracleBind> &) override {
        executes++;
        return 0;
    }
    uint64_t ExecuteWithRowCount(const std::string &, const std::vector<OracleBind> &) override {
        counted_executes++;
        return counted_execute_rows;
    }
    uint64_t ExecuteBatch(const std::string &, const std::vector<std::vector<OracleBind>> &) override {
        batches++;
        return 0;
    }
    std::vector<OracleBind> ExecuteReturning(const std::string &, const std::vector<OracleBind> &binds) override {
        return binds;
    }
    OracleCallResult Call(const OracleCallRequest &) override {
        calls++;
        return {};
    }
    void Commit() override {
        commits++;
        if (fail_commit) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "injected commit failure");
        }
    }
    void Rollback() override {
        rollbacks++;
    }
    void Cancel() override {
    }
    void Close() override {
        closes++;
    }

    size_t commits = 0;
    size_t rollbacks = 0;
    size_t closes = 0;
    size_t queries = 0;
    size_t executes = 0;
    size_t counted_executes = 0;
    size_t batches = 0;
    size_t calls = 0;
    uint64_t counted_execute_rows = 0;
    bool fail_commit = false;
};

class BlockingCommitSession final : public TestSession {
public:
    void Commit() override {
        std::unique_lock<std::mutex> guard(mutex);
        entered = true;
        entered_condition.notify_all();
        release_condition.wait(guard, [&] { return release; });
        commits++;
    }

    void WaitUntilCommitEntered() {
        std::unique_lock<std::mutex> guard(mutex);
        entered_condition.wait(guard, [&] { return entered; });
    }

    void ReleaseCommit() {
        std::lock_guard<std::mutex> guard(mutex);
        release = true;
        release_condition.notify_all();
    }

private:
    std::mutex mutex;
    std::condition_variable entered_condition;
    std::condition_variable release_condition;
    bool entered = false;
    bool release = false;
};

static void TestValidatedSession() {
    auto raw = std::make_unique<TestSession>();
    auto *inner = raw.get();
    ValidatedOracleSession session(std::move(raw));
    const std::vector<OracleBind> binds = {{"id", 2, BindDirection::BIND_IN, std::nullopt}};
    session.Query("select * from invoices where id = :id", binds);
    session.Execute("delete from invoices where id = :id", binds);
    session.ExecuteBatch("update invoices set id = :id", {binds});
    OracleCallRequest call {OracleCallableKind::PROCEDURE, "app.ping", std::nullopt, {}};
    session.Call(call);
    CHECK(inner->queries == 1 && inner->executes == 1 && inner->batches == 1 && inner->calls == 1);
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { session.Execute("select * from invoices where id = :id", binds); });
    CHECK(inner->executes == 1);
    session.Close();
    ExpectError(ProtocolErrorKind::INVALID_STATE, [&] { session.Commit(); });
}

static void TestStatementRegistry() {
    OracleStatementRegistry registry(2);
    const auto query = registry.Open(OracleSqlKind::QUERY);
    const auto dml = registry.Open(OracleSqlKind::DML);
    CHECK(query.statement_id != 0 && query.statement_id != dml.statement_id && registry.OpenCount() == 2);
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { registry.Open(OracleSqlKind::PLSQL); });
    registry.MarkExecuted(query, true);
    registry.BindRemoteCursor(query, 42);
    CHECK(registry.RemoteCursorId(query) == 42);
    registry.BeginFetch(query);
    registry.MarkExhausted(query);
    CHECK(registry.State(query) == OracleStatementState::EXHAUSTED);
    registry.MarkExecuted(dml, false);
    ExpectError(ProtocolErrorKind::INVALID_STATE, [&] { registry.BeginFetch(dml); });
    CHECK(registry.Close(query));
    CHECK(registry.State(query) == OracleStatementState::CLOSED);
    registry.Poison(dml);
    CHECK(registry.State(dml) == OracleStatementState::POISONED);
    registry.CloseAll();
    CHECK(registry.OpenCount() == 0);
}

static void TestTtcStatementChannel() {
    std::vector<uint8_t> inbound;
    for (const auto &packet : EncodeTnsDataPackets({6, 1}, true, 64)) {
        inbound.insert(inbound.end(), packet.begin(), packet.end());
    }
    for (const auto &packet : EncodeTnsDataPackets({TTC_MESSAGE_ERROR, 'O', 'R', 'A', '-', '0', '1', '0', '1', '7'}, true, 64)) {
        inbound.insert(inbound.end(), packet.begin(), packet.end());
    }
    FragmentedStream stream(inbound, 3);
    TnsPacketStream packets(stream, true, 64);
    TtcChannel channel(packets, 64);
    OracleStatementRegistry registry;
    const auto handle = registry.Open(OracleSqlKind::QUERY);
    registry.MarkExecuted(handle, true);
    registry.BindRemoteCursor(handle, 42);
    TtcStatementChannel statements(channel, registry);
    statements.Fetch(handle, 2, 10);
    CHECK(registry.State(handle) == OracleStatementState::FETCHING);
    CHECK(statements.ReceiveFetchResponse(handle) == std::vector<uint8_t>({6, 1}));
    // A direct ERROR can be terminal ORA-01403. Raw fetch I/O therefore
    // leaves classification to DecodeTtcFetchResponse, which has columns and
    // can distinguish it from a real server failure.
    CHECK(statements.ReceiveFetchResponse(handle) ==
           std::vector<uint8_t>({TTC_MESSAGE_ERROR, 'O', 'R', 'A', '-', '0', '1', '0', '1', '7'}));
    CHECK(registry.State(handle) == OracleStatementState::FETCHING);
    FragmentedStream sent_stream(stream.output, 3);
    TnsPacketStream sent_packets(sent_stream, true, 64);
    std::vector<uint8_t> sent;
    while (sent_stream.read_offset < sent_stream.input.size()) {
        const auto packet = sent_packets.Receive();
        CHECK(packet.type == TnsPacketType::DATA && packet.payload.size() >= 2);
        sent.insert(sent.end(), packet.payload.begin() + 2, packet.payload.end());
    }
    CHECK(DecodeTtcFetchRequest(sent).cursor_id == 42);
}

static void TestTtcCursorClosePiggyback() {
    const auto encoded = EncodeTtcCloseCursorsPiggyback(9, {42, 300});
    CHECK(encoded == std::vector<uint8_t>({TTC_MESSAGE_PIGGYBACK, TTC_PIGGYBACK_CLOSE_CURSORS, 9, 1, 1, 2, 1, 42,
                                            2, 1, 44}));
    ExpectError(ProtocolErrorKind::MALFORMED, [] { EncodeTtcCloseCursorsPiggyback(1, {}); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { EncodeTtcCloseCursorsPiggyback(1, {0}); });

    FragmentedStream stream({}, 3);
    TnsPacketStream packets(stream, true, 64);
    TtcChannel channel(packets, 64);
    OracleStatementRegistry registry;
    const auto closed = registry.Open(OracleSqlKind::QUERY);
    registry.MarkExecuted(closed, true);
    registry.BindRemoteCursor(closed, 42);
    TtcStatementChannel statements(channel, registry);
    CHECK(statements.Close(closed));
    CHECK(registry.State(closed) == OracleStatementState::CLOSED);
    CHECK(channel.PendingCloseCursorCount() == 1);
    CHECK(!statements.Close(closed));

    const auto next = registry.Open(OracleSqlKind::QUERY);
    TtcExecuteNoBindsRequest request;
    request.sql = "select 1 from dual";
    request.is_query = true;
    statements.ExecuteNoBinds(next, request);
    CHECK(channel.PendingCloseCursorCount() == 0);

    FragmentedStream sent_stream(stream.output, 3);
    TnsPacketStream sent_packets(sent_stream, true, 64);
    std::vector<uint8_t> sent;
    while (sent_stream.read_offset < sent_stream.input.size()) {
        const auto packet = sent_packets.Receive();
        CHECK(packet.type == TnsPacketType::DATA && packet.payload.size() >= 2);
        sent.insert(sent.end(), packet.payload.begin() + 2, packet.payload.end());
    }
    CHECK(sent.size() > 8);
    CHECK(std::vector<uint8_t>(sent.begin(), sent.begin() + 8) ==
           std::vector<uint8_t>({TTC_MESSAGE_PIGGYBACK, TTC_PIGGYBACK_CLOSE_CURSORS, 1, 1, 1, 1, 1, 42}));
    CHECK(sent.at(8) == TTC_MESSAGE_FUNCTION && sent.at(9) == TTC_FUNCTION_EXECUTE);
}

static void TestTtcTransactionCodec() {
    CHECK(EncodeTtcCommitRequest(7) == std::vector<uint8_t>({TTC_MESSAGE_FUNCTION, TTC_FUNCTION_COMMIT, 7}));
    CHECK(EncodeTtcRollbackRequest(8) == std::vector<uint8_t>({TTC_MESSAGE_FUNCTION, TTC_FUNCTION_ROLLBACK, 8}));
    ByteWriter status;
    status.WriteByte(TTC_MESSAGE_STATUS).WriteUB4(1).WriteUB2(77);
    const auto decoded = DecodeTtcTransactionStatus(status.Data());
    CHECK(decoded.call_status == 1 && decoded.end_to_end_sequence == 77);
    ExpectError(ProtocolErrorKind::MALFORMED, [] { DecodeTtcTransactionStatus({TTC_MESSAGE_ERROR}); });

    std::vector<uint8_t> inbound;
    for (const auto &packet : EncodeTnsDataPackets(status.Data(), true, 64)) {
        inbound.insert(inbound.end(), packet.begin(), packet.end());
    }
    FragmentedStream stream(inbound, 3);
    TnsPacketStream packets(stream, true, 64);
    TtcChannel channel(packets, 64);
    CHECK(channel.Commit(9).end_to_end_sequence == 77);
    FragmentedStream sent_stream(stream.output, 3);
    TnsPacketStream sent_packets(sent_stream, true, 64);
    const auto sent = sent_packets.Receive();
    CHECK(std::vector<uint8_t>(sent.payload.begin() + 2, sent.payload.end()) == EncodeTtcCommitRequest(9));
}

static void TestTtcExecuteStatementChannel() {
    std::vector<uint8_t> inbound;
    for (const auto &packet : EncodeTnsDataPackets({16, 1}, true, 64)) {
        inbound.insert(inbound.end(), packet.begin(), packet.end());
    }
    FragmentedStream stream(inbound, 4);
    TnsPacketStream packets(stream, true, 64);
    TtcChannel channel(packets, 64);
    OracleStatementRegistry registry;
    const auto handle = registry.Open(OracleSqlKind::QUERY);
    TtcStatementChannel statements(channel, registry);
    TtcExecuteNoBindsRequest request;
    request.sql = "select 1 from dual";
    request.is_query = true;
    statements.ExecuteNoBinds(handle, request);
    CHECK(statements.ReceiveExecuteResponse(handle) == std::vector<uint8_t>({16, 1}));
    statements.CompleteExecute(handle, true, 77);
    CHECK(registry.State(handle) == OracleStatementState::EXECUTED && registry.RemoteCursorId(handle) == 77);
    FragmentedStream sent_stream(stream.output, 3);
    TnsPacketStream sent_packets(sent_stream, true, 64);
    std::vector<uint8_t> sent;
    while (sent_stream.read_offset < sent_stream.input.size()) {
        const auto packet = sent_packets.Receive();
        CHECK(packet.type == TnsPacketType::DATA && packet.payload.size() >= 2);
        sent.insert(sent.end(), packet.payload.begin() + 2, packet.payload.end());
    }
    CHECK(sent.at(1) == TTC_FUNCTION_EXECUTE);

    ByteWriter out_bind_response;
    out_bind_response.WriteByte(TTC_MESSAGE_IO_VECTOR).WriteByte(0).WriteUB2(1).WriteUB4(0).WriteUB4(1).WriteUB2(0);
    out_bind_response.WriteUB2(0).WriteUB2(0).WriteByte(TTC_BIND_DIRECTION_OUT);
    out_bind_response.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(std::vector<uint8_t> {'x'}).WriteByte(0);
    std::vector<uint8_t> bound_inbound;
    for (const auto &packet : EncodeTnsDataPackets(out_bind_response.Data(), true, 64)) {
        bound_inbound.insert(bound_inbound.end(), packet.begin(), packet.end());
    }
    FragmentedStream bound_stream(bound_inbound, 3);
    TnsPacketStream bound_packets(bound_stream, true, 64);
    TtcChannel bound_channel(bound_packets, 64);
    OracleStatementRegistry bound_registry;
    const auto bound_handle = bound_registry.Open(OracleSqlKind::PLSQL);
    TtcStatementChannel bound_statements(bound_channel, bound_registry);
    TtcExecuteBindsRequest bound_request;
    bound_request.sql = "BEGIN demo.set_value(:value); END;";
    bound_request.is_plsql = true;
    bound_request.binds = {{"value", 1, BindDirection::BIND_OUT, std::nullopt, 32}};
    bound_statements.ExecuteBinds(bound_handle, bound_request);
    const auto output = bound_statements.ReceivePlsqlOutBindsResponse(bound_handle, bound_request.binds);
    CHECK(output.values.scalar_values[0] == std::optional<std::vector<uint8_t>>(std::vector<uint8_t> {static_cast<uint8_t>('x')}));
    bound_statements.CompleteExecute(bound_handle, false, 0);
    CHECK(bound_registry.State(bound_handle) == OracleStatementState::EXHAUSTED && !bound_stream.output.empty());

    ByteWriter dml_response;
    dml_response.WriteByte(TTC_MESSAGE_ERROR).WriteUB4(0).WriteUB2(0).WriteUB4(0);
    dml_response.WriteUB2(0).WriteUB2(0).WriteUB2(0).WriteUB4(0).WriteUB4(0).WriteByte(0).WriteByte(0);
    dml_response.WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0);
    dml_response.WriteUB4(0).WriteUB2(0).WriteByte(0).WriteUB4(0).WriteUB2(0);
    dml_response.WriteUB4(0).WriteByte(0).WriteByte(0).WriteUB2(0).WriteUB4(0).WriteByte(0);
    dml_response.WriteUB2(0).WriteUB4(0).WriteUB2(0).WriteUB4(0).WriteUB8(1);
    std::vector<uint8_t> dml_inbound;
    for (const auto &packet : EncodeTnsDataPackets(dml_response.Data(), true, 64)) {
        dml_inbound.insert(dml_inbound.end(), packet.begin(), packet.end());
    }
    FragmentedStream dml_stream(dml_inbound, 3);
    TnsPacketStream dml_packets(dml_stream, true, 64);
    TtcChannel dml_channel(dml_packets, 64);
    OracleStatementRegistry dml_registry;
    const auto dml_handle = dml_registry.Open(OracleSqlKind::DML);
    TtcStatementChannel dml_statements(dml_channel, dml_registry);
    TtcExecuteNoBindsRequest dml_request;
    dml_request.sql = "insert into t values (1)";
    dml_statements.ExecuteNoBinds(dml_handle, dml_request);
    const auto dml_completion = dml_statements.ReceiveDmlResponse(dml_handle, 12);
    CHECK(dml_completion.error_number == 0 && dml_completion.row_count == 1);
    dml_statements.CompleteExecute(dml_handle, false, 0);
    CHECK(dml_registry.State(dml_handle) == OracleStatementState::EXHAUSTED);
}

static const char *RequiredEnvironment(const char *name) {
    const auto value = std::getenv(name);
    if (!value || value[0] == '\0') {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "required live-test environment variable is missing");
    }
    return value;
}

static void TestLiveTnsNegotiation() {
    if (!std::getenv("ORACLE_SCANNER_LIVE")) {
        return;
    }
    ConnectionConfig config;
    // An Autonomous endpoint is normally reached through its wallet's
    // tnsnames.ora rather than a hand-written host/port/service, so the lane
    // accepts an alias and resolves it the same way the adapter does.
    const auto live_alias = std::getenv("ORACLE_SCANNER_LIVE_TNS_ALIAS");
    if (live_alias && live_alias[0] != '\0') {
        const auto descriptor =
            FindTnsAliasDescriptor(ReadWalletTnsNamesArchive(RequiredEnvironment("ORACLE_SCANNER_LIVE_WALLET_FILE")),
                                   live_alias);
        const auto parsed = ParseConnectDescriptor(descriptor);
        if (parsed.endpoints.size() != 1) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                "ORACLE_SCANNER_LIVE_TNS_ALIAS must resolve to exactly one ADDRESS");
        }
        config.host = parsed.endpoints[0].host;
        config.port = parsed.endpoints[0].port;
        config.service_name = parsed.service_name;
        config.protocol = parsed.endpoints[0].protocol;
        config.tls_server_cert_dn = parsed.server_cert_dn;
    } else {
        config.host = RequiredEnvironment("ORA19C_HOST");
        config.service_name = RequiredEnvironment("ORA19C_SERVICE");
    }
    if (const auto user = std::getenv("ORA19C_USER")) {
        config.user = user;
    }
    const auto port_text = live_alias && live_alias[0] != '\0' ? nullptr : RequiredEnvironment("ORA19C_PORT");
    const auto port = port_text ? std::strtoul(port_text, nullptr, 10) : config.port;
    if (port == 0 || port > 65535) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "ORA19C_PORT is invalid");
    }
    config.port = static_cast<uint16_t>(port);
    config.connect_timeout_seconds = 10;
    config.read_timeout_seconds = 10;
    if (const auto protocol = std::getenv("ORACLE_SCANNER_LIVE_PROTOCOL")) {
        if (std::string(protocol) != "tcps") {
            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                "ORACLE_SCANNER_LIVE_PROTOCOL must be tcps when it is set");
        }
        config.protocol = TransportProtocol::TCPS;
        // Optional, as it is in a secret: an empty server name verifies against
        // the host being connected to, which is what an alias-resolved
        // Autonomous endpoint wants.
        if (const auto tls_server_name = std::getenv("ORACLE_SCANNER_LIVE_TLS_SERVER_NAME")) {
            config.tls_server_name = tls_server_name;
        }
        if (const auto tls_sni_name = std::getenv("ORACLE_SCANNER_LIVE_TLS_SNI_NAME")) {
            config.tls_sni_name = tls_sni_name;
        }
        config.wallet_pem_file = RequiredEnvironment("ORACLE_SCANNER_LIVE_WALLET_FILE");
        // Optional since the wallet's cwallet.sso opens without one. Leaving it
        // unset is what exercises the auto-login path against a real database;
        // setting it selects the encrypted ewallet.pem instead.
        if (const auto wallet_password = std::getenv("ORACLE_SCANNER_LIVE_WALLET_PASSWORD")) {
            config.wallet_password = wallet_password;
        }
    }
    if (const auto client_program = std::getenv("ORACLE_SCANNER_LIVE_CLIENT_PROGRAM")) {
        config.client_program = client_program;
    }
    TlsConfiguration tls;
    if (config.protocol == TransportProtocol::TCPS) {
        tls.server_name = config.tls_server_name;
        tls.sni_name = config.tls_sni_name.empty() ? config.host : config.tls_sni_name;
        if (!config.wallet_pem_file.empty()) {
            tls.client_pem_contents =
                ReadWalletIdentityPem(config.wallet_pem_file, !config.wallet_password.empty());
        }
        tls.client_pem_password = config.wallet_password;
    }
    const auto stage = std::getenv("ORACLE_SCANNER_LIVE_STAGE");
    if (stage && std::string(stage) == "tcps_negative") {
        if (config.protocol != TransportProtocol::TCPS) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                "tcps_negative live stage requires ORACLE_SCANNER_LIVE_PROTOCOL=tcps");
        }
        auto wrong_server_name = tls;
        wrong_server_name.server_name = "oracle-scanner.invalid";
        ExpectProtocolError([&] { (void)TnsClientConnection::Connect(config, wrong_server_name); });

        auto wrong_wallet_password = tls;
        wrong_wallet_password.client_pem_password += "-wrong";
        ExpectProtocolError([&] { (void)TnsClientConnection::Connect(config, wrong_wallet_password); });

        auto untrusted_ca = tls;
        untrusted_ca.ca_pem_contents = ReadPemFile(RequiredEnvironment("ORACLE_SCANNER_LIVE_UNTRUSTED_CA_FILE"));
        ExpectProtocolError([&] { (void)TnsClientConnection::Connect(config, untrusted_ca); });

        // A DN that is not this server's is refused even though the
        // certificate itself verifies and its hostname matches, which is the
        // whole point of the check being separate from those two.
        auto wrong_server_dn = tls;
        wrong_server_dn.expected_server_dn = "CN=oracle-scanner.invalid, O=Nobody, C=US";
        ExpectProtocolError([&] { (void)TnsClientConnection::Connect(config, wrong_server_dn); });

        // And a DN this client accepts as well-formed but which names one
        // component too few is still a different identity.
        auto short_server_dn = tls;
        short_server_dn.expected_server_dn = "CN=" + (tls.server_name.empty() ? config.host : tls.server_name);
        ExpectProtocolError([&] { (void)TnsClientConnection::Connect(config, short_server_dn); });
        return;
    }
    auto connection = TnsClientConnection::Connect(config, tls);
    if (stage && std::string(stage) == "connect") {
        connection->Close();
        return;
    }
    const auto protocol = connection->Negotiate();
    CHECK(protocol.charset_id == ORACLE_CHARSET_AL32UTF8);
    if (stage && std::string(stage) == "auth") {
        connection->AuthenticateO5Logon(RequiredEnvironment("ORA19C_USER"), RequiredEnvironment("ORA19C_PASSWORD"));
        CHECK(connection->State() == OracleConnectionState::AUTHENTICATED);
    }
    if (stage && (std::string(stage) == "execute" || std::string(stage) == "fetch")) {
        connection->AuthenticateO5Logon(RequiredEnvironment("ORA19C_USER"), RequiredEnvironment("ORA19C_PASSWORD"));
        OracleStatementRegistry statements;
        const auto handle = statements.Open(OracleSqlKind::QUERY);
        TtcStatementChannel channel(connection->Ttc(), statements);
        TtcExecuteNoBindsRequest request;
        const bool test_fetch = std::string(stage) == "fetch";
        request.sql = test_fetch ? "select level from dual connect by level <= 3" : "select 1 from dual";
        request.is_query = true;
        channel.ExecuteNoBinds(handle, request);
        const auto response = channel.ReceiveExecuteResponse(handle);
        const auto decoded = DecodeTtcExecuteResponse(response, connection->TtcFieldVersion(), connection->TtcServerFieldVersion());
        CHECK(decoded.columns.size() == 1 && !decoded.rows.empty() && decoded.completion &&
               decoded.completion->cursor_id != 0);
        channel.CompleteExecute(handle, true, decoded.completion->cursor_id);
        if (test_fetch) {
            CHECK(!decoded.exhausted);
            channel.Fetch(handle, 2, 2);
            // The server may open the fetch response with a selected-columns
            // bit vector that reuses values from the last row already received,
            // so the last prefetched row has to be carried in exactly as
            // NativeOracleCursor carries it. All three supported servers do
            // this for this query.
            const std::optional<TtcRowData> preceding_row = decoded.rows.back();
            const auto fetched = channel.ReceiveDecodedFetchResponse(handle, decoded.columns, connection->TtcServerFieldVersion(), preceding_row);
            CHECK(!fetched.rows.empty() && fetched.exhausted && fetched.completion);
            channel.MarkFetchExhausted(handle);
        }
    }
    if (stage && std::string(stage) == "close_cursor") {
        connection->AuthenticateO5Logon(RequiredEnvironment("ORA19C_USER"), RequiredEnvironment("ORA19C_PASSWORD"));
        OracleStatementRegistry statements;
        TtcStatementChannel channel(connection->Ttc(), statements);
        const auto first = statements.Open(OracleSqlKind::QUERY);
        TtcExecuteNoBindsRequest first_request;
        first_request.sql = "select level from dual connect by level <= 3";
        first_request.is_query = true;
        channel.ExecuteNoBinds(first, first_request);
        const auto first_response = DecodeTtcExecuteResponse(channel.ReceiveExecuteResponse(first), connection->TtcFieldVersion(), connection->TtcServerFieldVersion());
        CHECK(first_response.completion && first_response.completion->cursor_id != 0);
        channel.CompleteExecute(first, true, first_response.completion->cursor_id);
        CHECK(channel.Close(first));

        // The next execute carries CLOSE_CURSORS before OALL8. A successful
        // reply proves the server accepted the queued release rather than
        // interpreting it as a malformed standalone call.
        const auto next = statements.Open(OracleSqlKind::QUERY);
        TtcExecuteNoBindsRequest next_request;
        next_request.sequence = 3;
        next_request.sql = "select 1 from dual";
        next_request.is_query = true;
        channel.ExecuteNoBinds(next, next_request);
        const auto next_response = DecodeTtcExecuteResponse(channel.ReceiveExecuteResponse(next), connection->TtcFieldVersion(), connection->TtcServerFieldVersion());
        CHECK(next_response.completion && next_response.completion->cursor_id != 0);
        channel.CompleteExecute(next, true, next_response.completion->cursor_id);
    }
    if (stage && std::string(stage) == "dml") {
        connection->AuthenticateO5Logon(RequiredEnvironment("ORA19C_USER"), RequiredEnvironment("ORA19C_PASSWORD"));
        const std::string table = RequiredEnvironment("ORACLE_SCANNER_LIVE_DML_TABLE");
        OracleStatementRegistry statements;
        TtcStatementChannel channel(connection->Ttc(), statements);
        const auto handle = statements.Open(OracleSqlKind::DML);
        TtcExecuteNoBindsRequest request;
        request.sequence = 3;
        request.sql = "INSERT INTO " + table + " (id) VALUES (1)";
        channel.ExecuteNoBinds(handle, request);
        const auto completion = channel.ReceiveDmlResponse(handle, connection->TtcServerFieldVersion());
        CHECK(completion.error_number == 0);
        channel.CompleteExecute(handle, false, 0);
        CHECK(statements.State(handle) == OracleStatementState::EXHAUSTED);

        // The transaction-scoped read proves the DML took effect on this
        // native session even where the server emits zero in this OALL8
        // completion's extended row-count slot.
        const auto verification = statements.Open(OracleSqlKind::QUERY);
        TtcExecuteNoBindsRequest verification_request;
        verification_request.sequence = 4;
        verification_request.sql = "SELECT COUNT(*) FROM " + table;
        verification_request.is_query = true;
        channel.ExecuteNoBinds(verification, verification_request);
        const auto verification_response = DecodeTtcExecuteResponse(channel.ReceiveExecuteResponse(verification), connection->TtcFieldVersion(), connection->TtcServerFieldVersion());
        CHECK(verification_response.rows.size() == 1 && verification_response.rows[0].size() == 1 &&
               verification_response.rows[0][0] && DecodeOracleNumber(*verification_response.rows[0][0]) == "1");
        CHECK(verification_response.completion && verification_response.completion->cursor_id != 0);
        channel.CompleteExecute(verification, true, verification_response.completion->cursor_id);
    }
    if (stage && std::string(stage) == "transaction_control") {
        connection->AuthenticateO5Logon(RequiredEnvironment("ORA19C_USER"), RequiredEnvironment("ORA19C_PASSWORD"));
        const auto committed = connection->Ttc().Commit(3);
        const auto rolled_back = connection->Ttc().Rollback(4);
        CHECK(committed.call_status != 0 && rolled_back.call_status != 0);
    }
    if (stage && std::string(stage) == "native_session") {
        auto native = NativeOracleSession::Connect(config, RequiredEnvironment("ORA19C_PASSWORD"));
        auto cursor = native->Query("select level from dual connect by level <= 3", {});
        const auto first = cursor->Fetch(1);
        CHECK(first.rows.size() == 1 && !first.exhausted);
        const auto second = cursor->Fetch(2);
        CHECK(second.rows.size() == 2 && !second.exhausted);
        const auto terminal = cursor->Fetch(1);
        CHECK(terminal.rows.empty() && terminal.exhausted);
        cursor->Close();
        native->Commit();
        native->Rollback();
        native->Close();
    }
    // Can one session carry two cursors at once? Everything about reading a
    // transaction's own uncommitted writes depends on the answer, and reasoning
    // about the TTC channel is not evidence. Two cursors, fetches interleaved,
    // and each has to return its own complete result.
    if (stage && std::string(stage) == "native_interleaved_cursors") {
        auto native = NativeOracleSession::Connect(config, RequiredEnvironment("ORA19C_PASSWORD"));
        auto left = native->Query("SELECT level AS n FROM dual CONNECT BY level <= 6", {});
        auto right = native->Query("SELECT 100 + level AS n FROM dual CONNECT BY level <= 6", {});
        std::vector<std::string> left_rows;
        std::vector<std::string> right_rows;
        bool left_done = false;
        bool right_done = false;
        while (!left_done || !right_done) {
            if (!left_done) {
                const auto batch = left->Fetch(2);
                for (const auto &row : batch.rows) {
                    CHECK(row.size() == 1 && row[0]);
                    left_rows.push_back(DecodeOracleNumber(*row[0]));
                }
                left_done = batch.exhausted;
            }
            if (!right_done) {
                const auto batch = right->Fetch(2);
                for (const auto &row : batch.rows) {
                    CHECK(row.size() == 1 && row[0]);
                    right_rows.push_back(DecodeOracleNumber(*row[0]));
                }
                right_done = batch.exhausted;
            }
        }
        CHECK(left_rows.size() == 6 && right_rows.size() == 6);
        for (size_t index = 0; index < 6; index++) {
            CHECK(left_rows[index] == std::to_string(index + 1));
            CHECK(right_rows[index] == std::to_string(101 + index));
        }
        left->Close();
        right->Close();
        native->Rollback();
        native->Close();
    }
    if (stage && std::string(stage) == "native_zero_row") {
        auto native = NativeOracleSession::Connect(config, RequiredEnvironment("ORA19C_PASSWORD"));
        auto cursor = native->Query("SELECT 42 AS answer FROM dual WHERE 1 = 0", {});
        const auto batch = cursor->Fetch(1);
        CHECK(batch.rows.empty() && batch.exhausted);
        cursor->Close();
        native->Close();
    }
    if (stage && std::string(stage) == "native_wide_row") {
        auto native = NativeOracleSession::Connect(config, RequiredEnvironment("ORA19C_PASSWORD"));
        auto cursor = native->Query(
            "SELECT level AS id, 'a' AS c2, 'b' AS c3, 'c' AS c4, 'd' AS c5, "
            "'e' AS c6, 'f' AS c7, 'g' AS c8, 'h' AS c9 FROM dual CONNECT BY level <= 3", {});
        std::vector<TtcRowData> rows;
        for (;;) {
            const auto batch = cursor->Fetch(1);
            rows.insert(rows.end(), batch.rows.begin(), batch.rows.end());
            if (batch.exhausted) {
                break;
            }
        }
        CHECK(rows.size() == 3);
        for (size_t row = 0; row < rows.size(); row++) {
            CHECK(rows[row].size() == 9 && rows[row][0] && DecodeOracleNumber(*rows[row][0]) == std::to_string(row + 1));
            for (size_t column = 1; column < rows[row].size(); column++) {
                CHECK(rows[row][column] && rows[row][column]->size() == 1);
            }
        }
        cursor->Close();
        native->Close();
    }
    if (stage && std::string(stage) == "native_wide_row_continuation") {
        connection->AuthenticateO5Logon(RequiredEnvironment("ORA19C_USER"), RequiredEnvironment("ORA19C_PASSWORD"));
        OracleStatementRegistry statements;
        const auto handle = statements.Open(OracleSqlKind::QUERY);
        TtcStatementChannel channel(connection->Ttc(), statements);
        TtcExecuteNoBindsRequest request;
        request.sql = "SELECT level AS id, 'a' AS c2, 'b' AS c3, 'c' AS c4, 'd' AS c5, "
                      "'e' AS c6, 'f' AS c7, 'g' AS c8, 'h' AS c9 FROM dual CONNECT BY level <= 50";
        request.is_query = true;
        channel.ExecuteNoBinds(handle, request);
        const auto initial = DecodeTtcExecuteResponse(channel.ReceiveExecuteResponse(handle), connection->TtcFieldVersion(), connection->TtcServerFieldVersion());
        CHECK(initial.rows.size() == 2 && initial.completion && initial.completion->cursor_id != 0);
        channel.CompleteExecute(handle, true, initial.completion->cursor_id);
        channel.Fetch(handle, 2, 48);
        const auto fetched = channel.ReceiveDecodedFetchResponse(handle, initial.columns, connection->TtcServerFieldVersion(), initial.rows.back());
        CHECK(fetched.used_row_continuation);
        CHECK(fetched.rows.size() == 48);
        CHECK(!fetched.exhausted);
        CHECK(fetched.rows.back().size() == 9 && fetched.rows.back()[0] &&
               DecodeOracleNumber(*fetched.rows.back()[0]) == "50");
        channel.Fetch(handle, 3, 1);
        const auto terminal = channel.ReceiveDecodedFetchResponse(handle, initial.columns, connection->TtcServerFieldVersion(), fetched.last_row);
        CHECK(terminal.rows.empty() && terminal.exhausted);
        channel.MarkFetchExhausted(handle);
    }
    if (stage && std::string(stage) == "native_cancel") {
        auto native = NativeOracleSession::Connect(config, RequiredEnvironment("ORA19C_PASSWORD"));
        std::exception_ptr cancellation_error;
        std::thread query([&] {
            try {
                // This is intentionally a server-side, CPU-bound statement:
                // it makes the cancellation exchange independent of fetch
                // timing and proves that the connection survives ORA-01013.
                (void)native->Query(
                    "SELECT COUNT(*) FROM all_objects a CROSS JOIN all_objects b CROSS JOIN all_objects c", {});
            } catch (...) {
                cancellation_error = std::current_exception();
            }
        });
        std::this_thread::sleep_for(std::chrono::seconds(1));
        native->Cancel();
        query.join();
        CHECK(cancellation_error);
        try {
            std::rethrow_exception(cancellation_error);
        } catch (const ProtocolError &error) {
            CHECK(error.Kind() == ProtocolErrorKind::INVALID_STATE);
            CHECK(std::string(error.what()).find("ORA-01013") != std::string::npos);
        }

        auto reusable = native->Query("SELECT 42 FROM dual", {});
        const auto batch = reusable->Fetch(1);
        CHECK(batch.rows.size() == 1 && batch.rows[0].size() == 1 && batch.rows[0][0] &&
               DecodeOracleNumber(*batch.rows[0][0]) == "42");
        reusable->Close();
        native->Close();
    }
    if (stage && std::string(stage) == "native_session_binds") {
        auto native = NativeOracleSession::Connect(config, RequiredEnvironment("ORA19C_PASSWORD"));
        const std::vector<OracleBind> binds = {
            {"n", 2, BindDirection::BIND_IN, EncodeOracleNumber("42")},
            {"label", 1, BindDirection::BIND_IN, std::vector<uint8_t> {'o', 'r', 'a'}},
        };
        auto cursor = native->Query("SELECT :n AS n, :label AS label FROM dual", binds);
        const auto batch = cursor->Fetch(2);
        CHECK(batch.rows.size() == 1 && batch.rows[0].size() == 2 && batch.rows[0][0] && batch.rows[0][1] &&
               DecodeOracleNumber(*batch.rows[0][0]) == "42" &&
               std::string(batch.rows[0][1]->begin(), batch.rows[0][1]->end()) == "ora");
        cursor->Close();
        native->Close();
    }
    if (stage && std::string(stage) == "native_session_numeric_bind") {
        auto native = NativeOracleSession::Connect(config, RequiredEnvironment("ORA19C_PASSWORD"));
        const std::vector<OracleBind> binds = {{"n", 2, BindDirection::BIND_IN, EncodeOracleNumber("42")}};
        auto cursor = native->Query("SELECT :n AS n FROM dual", binds);
        const auto batch = cursor->Fetch(2);
        CHECK(batch.rows.size() == 1 && batch.rows[0].size() == 1 && batch.rows[0][0] &&
               DecodeOracleNumber(*batch.rows[0][0]) == "42");
        cursor->Close();
        native->Close();
    }
    if (stage && std::string(stage) == "native_call_cursor") {
        auto native = NativeOracleSession::Connect(config, RequiredEnvironment("ORA19C_PASSWORD"));
        OracleCallRequest request;
        request.kind = OracleCallableKind::PROCEDURE;
        request.qualified_name = RequiredEnvironment("ORACLE_SCANNER_LIVE_CALL_NAME");
        request.arguments = {
            {"c", ORACLE_WIRE_TYPE_CURSOR, BindDirection::BIND_OUT, std::nullopt, 4},
            {"n", 2, BindDirection::BIND_OUT, std::nullopt, 22},
        };
        auto result = native->Call(request);
        CHECK(result.outputs.size() == 1 && result.outputs[0].value && DecodeOracleNumber(*result.outputs[0].value) == "42");
        CHECK(result.explicit_cursors.size() == 1);
        const auto batch = result.explicit_cursors[0]->Fetch(2);
        CHECK(batch.rows.size() == 1 && batch.rows[0].size() == 1 && batch.rows[0][0] &&
               DecodeOracleNumber(*batch.rows[0][0]) == "7");
        result.explicit_cursors[0]->Close();
        native->Close();
    }
    if (stage && std::string(stage) == "native_call_function") {
        auto native = NativeOracleSession::Connect(config, RequiredEnvironment("ORA19C_PASSWORD"));
        OracleCallRequest request;
        request.kind = OracleCallableKind::FUNCTION;
        request.qualified_name = RequiredEnvironment("ORACLE_SCANNER_LIVE_CALL_NAME");
        request.return_bind = {"r", 2, BindDirection::BIND_OUT, std::nullopt, 22};
        auto result = native->Call(request);
        CHECK(result.outputs.size() == 1 && result.outputs[0].name == "r" && result.outputs[0].value &&
               DecodeOracleNumber(*result.outputs[0].value) == "42");
        CHECK(result.explicit_cursors.empty() && result.implicit_cursors.empty());
        native->Close();
    }
    if (stage && std::string(stage) == "native_session_dml") {
        const std::string table = RequiredEnvironment("ORACLE_SCANNER_LIVE_DML_TABLE");
        auto native = NativeOracleSession::Connect(config, RequiredEnvironment("ORA19C_PASSWORD"));

        // The current OALL8 profile does not return a reliable affected-row
        // count, so validate the public session API through the transaction
        // view instead. This also verifies that Query and Execute share one
        // authenticated native session.
        (void)native->Execute("INSERT INTO " + table + " (id) VALUES (:id)",
                              {{"id", 2, BindDirection::BIND_IN, EncodeOracleNumber("1")}});
        auto inserted = native->Query("SELECT COUNT(*) FROM " + table, {});
        const auto visible = inserted->Fetch(2);
        CHECK(visible.rows.size() == 1 && visible.rows[0].size() == 1 && visible.rows[0][0] &&
               DecodeOracleNumber(*visible.rows[0][0]) == "1");
        inserted->Close();

        native->Rollback();
        auto rolled_back = native->Query("SELECT COUNT(*) FROM " + table, {});
        const auto absent = rolled_back->Fetch(2);
        CHECK(absent.rows.size() == 1 && absent.rows[0].size() == 1 && absent.rows[0][0] &&
               DecodeOracleNumber(*absent.rows[0][0]) == "0");
        rolled_back->Close();
        native->Close();
    }
    if (stage && std::string(stage) == "native_session_close_first") {
        auto native = NativeOracleSession::Connect(config, RequiredEnvironment("ORA19C_PASSWORD"));
        auto cursor = native->Query("SELECT 1 FROM dual", {});
        native->Close();
        // The cursor owns no transport. It must become unusable without
        // dereferencing the former session channel, and explicit close must
        // remain harmless for clients that use this destruction order.
        bool rejected = false;
        try {
            (void)cursor->Fetch(1);
        } catch (const ProtocolError &error) {
            rejected = error.Kind() == ProtocolErrorKind::INVALID_STATE;
        }
        CHECK(rejected);
        cursor->Close();
    }
    if (stage && (std::string(stage) == "plsql_cursor" || std::string(stage) == "plsql_cursor_fetch")) {
        connection->AuthenticateO5Logon(RequiredEnvironment("ORA19C_USER"), RequiredEnvironment("ORA19C_PASSWORD"));
        OracleStatementRegistry statements;
        const auto handle = statements.Open(OracleSqlKind::PLSQL);
        TtcStatementChannel channel(connection->Ttc(), statements);
        const std::vector<OracleBind> binds = {{"c", ORACLE_WIRE_TYPE_CURSOR, BindDirection::BIND_OUT, std::nullopt, 4}};
        TtcExecuteBindsRequest request;
        request.sequence = 3;
        request.sql = "BEGIN OPEN :c FOR SELECT 1 AS value FROM dual; END;";
        request.binds = binds;
        request.is_plsql = true;
        channel.ExecuteBinds(handle, request);
        const auto decoded = channel.ReceiveCallResponse(handle, binds, connection->TtcFieldVersion(), connection->TtcServerFieldVersion());
        CHECK(decoded.out_binds && decoded.out_binds->cursor_values.size() == 1 &&
               decoded.out_binds->cursor_values[0] && decoded.out_binds->cursor_values[0]->cursor_id != 0);
        if (std::string(stage) == "plsql_cursor_fetch") {
            const auto &cursor = *decoded.out_binds->cursor_values[0];
            const auto cursor_handle = statements.Open(OracleSqlKind::QUERY);
            channel.CompleteExecute(cursor_handle, true, cursor.cursor_id);
            channel.Fetch(cursor_handle, 4, 2);
            const auto fetched = channel.ReceiveDecodedFetchResponse(cursor_handle, cursor.columns, connection->TtcServerFieldVersion());
            CHECK(!fetched.rows.empty() && fetched.exhausted && fetched.completion);
            channel.MarkFetchExhausted(cursor_handle);
        }
    }
    if (stage && std::string(stage) == "plsql_scalar") {
        connection->AuthenticateO5Logon(RequiredEnvironment("ORA19C_USER"), RequiredEnvironment("ORA19C_PASSWORD"));
        OracleStatementRegistry statements;
        const auto handle = statements.Open(OracleSqlKind::PLSQL);
        TtcStatementChannel channel(connection->Ttc(), statements);
        const std::vector<OracleBind> binds = {{"n", 2, BindDirection::BIND_OUT, std::nullopt, 22}};
        TtcExecuteBindsRequest request;
        request.sequence = 3;
        request.sql = "BEGIN :n := 42; END;";
        request.binds = binds;
        request.is_plsql = true;
        channel.ExecuteBinds(handle, request);
        const auto decoded = channel.ReceiveCallResponse(handle, binds, connection->TtcFieldVersion(), connection->TtcServerFieldVersion());
        CHECK(decoded.out_binds && decoded.out_binds->scalar_values.size() == 1 &&
               decoded.out_binds->scalar_values[0].has_value());
    }
    if (stage && (std::string(stage) == "plsql_implicit" || std::string(stage) == "plsql_implicit_fetch")) {
        connection->AuthenticateO5Logon(RequiredEnvironment("ORA19C_USER"), RequiredEnvironment("ORA19C_PASSWORD"));
        OracleStatementRegistry statements;
        const auto handle = statements.Open(OracleSqlKind::PLSQL);
        TtcStatementChannel channel(connection->Ttc(), statements);
        TtcExecuteNoBindsRequest request;
        request.sequence = 3;
        request.is_plsql = true;
        request.sql = "DECLARE c SYS_REFCURSOR; BEGIN OPEN c FOR SELECT 1 AS value FROM dual; DBMS_SQL.RETURN_RESULT(c); END;";
        channel.ExecuteNoBinds(handle, request);
        const auto decoded = channel.ReceiveCallResponse(handle, {}, connection->TtcFieldVersion(), connection->TtcServerFieldVersion());
        CHECK(decoded.implicit_cursors.size() == 1 && decoded.implicit_cursors[0].cursor_id != 0);
        if (std::string(stage) == "plsql_implicit_fetch") {
            const auto &cursor = decoded.implicit_cursors[0];
            const auto cursor_handle = statements.Open(OracleSqlKind::QUERY);
            channel.CompleteExecute(cursor_handle, true, cursor.cursor_id);
            channel.Fetch(cursor_handle, 4, 2);
            const auto fetched = channel.ReceiveDecodedFetchResponse(cursor_handle, cursor.columns, connection->TtcServerFieldVersion());
            CHECK(!fetched.rows.empty() && fetched.exhausted && fetched.completion);
            channel.MarkFetchExhausted(cursor_handle);
        }
    }
    connection->Close();
}

static void TestTransactions() {
    auto first = std::make_shared<TestSession>();
    auto second = std::make_shared<TestSession>();
    OracleTransaction transaction;
    CHECK(&transaction.RegisterWrite("one", first) == first.get());
    CHECK(&transaction.RegisterWrite("one", first) == first.get());
    CHECK(transaction.WriteCatalog() == "one");
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [&] { transaction.RegisterWrite("two", second); });
    ExpectError(ProtocolErrorKind::INVALID_STATE, [&] { transaction.RegisterWrite("one", second); });
    transaction.Commit();
    CHECK(first->commits == 1 && transaction.State() == TransactionState::COMMITTED);
    ExpectError(ProtocolErrorKind::INVALID_STATE, [&] { transaction.Rollback(); });

    auto failing = std::make_shared<TestSession>();
    failing->fail_commit = true;
    OracleTransaction poisoned;
    poisoned.RegisterWrite("one", failing);
    ExpectError(ProtocolErrorKind::INVALID_STATE, [&] { poisoned.Commit(); });
    CHECK(poisoned.State() == TransactionState::POISONED && failing->closes == 1);

    auto abandoned = std::make_shared<TestSession>();
    {
        OracleTransaction scoped;
        scoped.RegisterWrite("one", abandoned);
    }
    CHECK(abandoned->rollbacks == 1);

    auto blocking = std::make_shared<BlockingCommitSession>();
    OracleTransaction concurrent;
    concurrent.RegisterWrite("one", blocking);
    std::thread committer([&] { concurrent.Commit(); });
    blocking->WaitUntilCommitEntered();
    ExpectError(ProtocolErrorKind::INVALID_STATE, [&] { concurrent.Rollback(); });
    blocking->ReleaseCommit();
    committer.join();
    CHECK(blocking->commits == 1 && concurrent.State() == TransactionState::COMMITTED);
}

// The DuckDB adapter opens every session through OpenOracleSession, so this
// seam is what lets adapter and orchestration paths run against a fake session
// with no database and no network. Production installs no factory.
// A column described with zero byte width can only be SQL NULL, and Oracle
// omits it from ROW_DATA completely — no value, no NULL length byte. Both
// message shapes below are the live 19c captures, and Free 23ai and OCI
// Autonomous send the same thing. Reading one value per described column
// misassigns the values that are present and then desynchronizes the response.
static void TestZeroWidthColumnsCarryNoRowBytes() {
    OracleColumn omitted;
    omitted.name = "E";
    omitted.oracle_type = 96;
    omitted.byte_width = 0;
    omitted.omitted_from_row_data = true;
    OracleColumn carried;
    carried.name = "F";
    carried.oracle_type = 96;
    carried.byte_width = 1;

    // `SELECT '' AS e, 'x' AS f FROM dual`: ROW_HEADER, then one value for two
    // columns, then end of request.
    const std::vector<uint8_t> mixed {0x06, 0x22, 0x01, 0x02, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00,
                                      0x07, 0x01, 0x78, 0x1d};
    const auto decoded = DecodeTtcFetchResponse(mixed, {omitted, carried}, 6);
    CHECK(decoded.rows.size() == 1 && decoded.rows[0].size() == 2);
    CHECK(!decoded.rows[0][0].has_value());
    CHECK(decoded.rows[0][1].value() == std::vector<uint8_t>({'x'}));

    // Column order does not matter: the value belongs to the column that
    // carries bytes, wherever it sits.
    const auto reversed = DecodeTtcFetchResponse(mixed, {carried, omitted}, 6);
    CHECK(reversed.rows[0][0].value() == std::vector<uint8_t>({'x'}));
    CHECK(!reversed.rows[0][1].has_value());

    // `SELECT '' AS e FROM dual`: ROW_DATA is its message byte and nothing
    // else, which is why the old decoder read the following message as a
    // value length.
    const std::vector<uint8_t> lone {0x06, 0x22, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x07, 0x1d};
    const auto lone_decoded = DecodeTtcFetchResponse(lone, {omitted}, 6);
    CHECK(lone_decoded.rows.size() == 1 && lone_decoded.rows[0].size() == 1);
    CHECK(!lone_decoded.rows[0][0].has_value());
}

// A row header whose bit vector selects no column says the row that follows is
// identical to the previous one and carries no values at all. Captured from a
// live 19c scan of a column with thousands of repeating values: the header, a
// bare ROW_DATA, then BIT_VECTOR/ROW_DATA pairs for the rest, then ORA-01403.
// Reading a full row there instead consumed the following message's bytes as a
// value length, and the scan died a few rows later on whatever byte it landed
// on — "unknown TTC message 0 in fetch response" and friends.
// A LOB column's row data carries a locator, and the locator's length is stated
// twice: a universal int, then the ordinary length prefix. Reading the int and
// then that many raw bytes consumes exactly as many bytes, so the wrong reading
// stays in frame through every column of the row and only shows itself when the
// locator is sent back — one byte out of place — and 19c answers ORA-22275.
//
// Live 19c, `SELECT doc FROM oracle_scanner_lob WHERE id = 4 AND ROWNUM = 1`,
// where DOC is a CLOB holding ten Cyrillic characters.
static void TestLobRowDataCarriesALocator() {
    OracleColumn doc;
    doc.name = "DOC";
    doc.oracle_type = ORACLE_WIRE_TYPE_CLOB;
    doc.byte_width = 4000;

    const std::vector<uint8_t> lob_row_one_clob {
    0x06, 0x22, 0x01, 0x01, 0x00, 0x02, 0x08, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x72, 0x72, 0x00, 0x70, 0x00,
    0x02, 0x02, 0x0c, 0x82, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x7e, 0x3f, 0x00,
    0x01, 0x24, 0x91, 0x00, 0x01, 0x24, 0x90, 0x00, 0x02, 0x00, 0x02, 0x03, 0x69, 0x6d, 0xb1, 0xff, 0xff, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x3d, 0x55, 0xbe, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00,
    0x01, 0x00, 0x22, 0x00, 0x00, 0x00, 0x01, 0x00, 0xf6, 0xfe, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x24, 0x90, 0x00, 0x40, 0x86,
    0xe9, 0x00, 0x03, 0x04, 0x01, 0x01, 0x02, 0x32, 0x1d, 0x01, 0x01, 0x02, 0x05, 0x7b, 0x00, 0x00, 0x01, 0x02,
    0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x05, 0x7b, 0x01, 0x01, 0x19, 0x4f, 0x52, 0x41, 0x2d, 0x30, 0x31, 0x34, 0x30, 0x33,
    0x3a, 0x20, 0x6e, 0x6f, 0x20, 0x64, 0x61, 0x74, 0x61, 0x20, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x0a};

    const auto decoded = DecodeTtcFetchResponse(lob_row_one_clob, {doc}, 6);
    CHECK(decoded.rows.size() == 1);
    CHECK(decoded.rows[0].size() == 1);
    CHECK(decoded.rows[0][0].has_value());
    // 114 bytes on this server, and self-describing: the first two say 0x0070.
    CHECK(decoded.rows[0][0]->size() == 114);
    CHECK((*decoded.rows[0][0])[0] == 0x00 && (*decoded.rows[0][0])[1] == 0x70);
    CHECK(decoded.exhausted);

    // Reading the same bytes as an ordinary value keeps the frame but shifts
    // the locator, which is the defect this capture exists to pin.
    const auto as_plain =
        DecodeTtcRowDataPrefix(std::vector<uint8_t>(lob_row_one_clob.begin() + 11, lob_row_one_clob.end()), 1);
    CHECK(as_plain.values.size() == 1);
    CHECK(as_plain.values[0].has_value());
    CHECK(*as_plain.values[0] != *decoded.rows[0][0]);
}

// Four rows, and from the second one on the server sends a BIT_VECTOR before
// each ROW_DATA. Those rows go through the continuation decoder rather than the
// full one, so it needs the same notion of a locator; without it the first
// continued row desynchronizes the rest of the message. Live 19c,
// `SELECT doc FROM oracle_scanner_lob WHERE id IN (1, 2)` over a table that
// held four matching rows.
static void TestLobLocatorsSurviveARowContinuation() {
    OracleColumn doc;
    doc.name = "DOC";
    doc.oracle_type = ORACLE_WIRE_TYPE_CLOB;
    doc.byte_width = 4000;

    const std::vector<uint8_t> lob_rows_with_bit_vector {
    0x06, 0x22, 0x01, 0x01, 0x00, 0x02, 0x08, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x72, 0x72, 0x00, 0x70, 0x00,
    0x02, 0x02, 0x0c, 0x82, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x7d, 0xa9, 0x00,
    0x01, 0x24, 0x91, 0x00, 0x01, 0x24, 0x90, 0x00, 0x02, 0x00, 0x02, 0x03, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x3d, 0x55, 0xbe, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00,
    0x01, 0x00, 0x22, 0x00, 0x00, 0x00, 0x01, 0x00, 0xf6, 0xfe, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x24, 0x90, 0x00, 0x40, 0x86,
    0xe9, 0x00, 0x00, 0x07, 0x01, 0x72, 0x72, 0x00, 0x70, 0x00, 0x02, 0x02, 0x0c, 0x82, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x7d, 0xdb, 0x00, 0x01, 0x24, 0x91, 0x00, 0x01, 0x24, 0x90, 0x00,
    0x02, 0x00, 0x02, 0x03, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x55, 0xbe, 0x13, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x00, 0x22, 0x00, 0x00, 0x00, 0x01, 0x00,
    0xf6, 0xfe, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x24, 0x90, 0x00, 0x40, 0x86, 0xe9, 0x00, 0x01, 0x15, 0x01, 0x01, 0x01, 0x07,
    0x01, 0x72, 0x72, 0x00, 0x70, 0x00, 0x02, 0x02, 0x0c, 0x82, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x0c, 0x8a, 0xf1, 0x00, 0x01, 0x24, 0x91, 0x00, 0x01, 0x24, 0x90, 0x00, 0x02, 0x00, 0x02, 0x03,
    0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x55, 0xbe, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x00, 0x22, 0x00, 0x00, 0x00, 0x01, 0x00, 0xf6, 0xfe, 0x0f, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x24, 0x90, 0x00, 0x40, 0x86, 0xe9, 0x00, 0x07, 0x15, 0x01, 0x01, 0x01, 0x07, 0x01, 0x72, 0x72, 0x00,
    0x70, 0x00, 0x02, 0x02, 0x0c, 0x82, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x8b,
    0x23, 0x00, 0x01, 0x24, 0x91, 0x00, 0x01, 0x24, 0x90, 0x00, 0x02, 0x00, 0x02, 0x03, 0x69, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x55, 0xbe, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe,
    0xef, 0x00, 0x01, 0x00, 0x22, 0x00, 0x00, 0x00, 0x01, 0x00, 0xf6, 0xfe, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x24, 0x90, 0x00,
    0x40, 0x86, 0xe9, 0x00, 0x08, 0x04, 0x01, 0x01, 0x02, 0x32, 0x29, 0x01, 0x04, 0x02, 0x05, 0x7b, 0x00, 0x00,
    0x01, 0x02, 0x00, 0x03, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x05, 0x7b, 0x01, 0x04, 0x19, 0x4f, 0x52, 0x41, 0x2d, 0x30, 0x31, 0x34,
    0x30, 0x33, 0x3a, 0x20, 0x6e, 0x6f, 0x20, 0x64, 0x61, 0x74, 0x61, 0x20, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x0a};

    const auto decoded = DecodeTtcFetchResponse(lob_rows_with_bit_vector, {doc}, 6);
    CHECK(decoded.rows.size() == 4);
    CHECK(decoded.used_row_continuation);
    for (const auto &row : decoded.rows) {
        CHECK(row.size() == 1);
        CHECK(row[0].has_value() && row[0]->size() == 114);
    }
    // Every row holds a different locator: they are per value, not a template.
    CHECK(*decoded.rows[0][0] != *decoded.rows[1][0]);
    CHECK(decoded.exhausted);
}

// GET_LENGTH answers with the return parameter, the echoed locator and the
// length — and nothing else. The locator comes back updated rather than
// verbatim, so it cannot be checked against the one sent. Live 19c, a CLOB of
// ten characters.
static void TestLobGetLengthResponse() {
    const std::vector<uint8_t> lob_get_length_response {
    0x08, 0x00, 0x70, 0x00, 0x02, 0x02, 0x0c, 0x82, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x0c, 0x7e, 0x3f, 0x00, 0x01, 0x24, 0x91, 0x00, 0x01, 0x24, 0x90, 0x00, 0x02, 0x00, 0x02, 0x03, 0x69, 0x6d,
    0xb1, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x55, 0xbe, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde,
    0xad, 0xbe, 0xef, 0x00, 0x01, 0x00, 0x22, 0x00, 0x00, 0x00, 0x01, 0x00, 0xf6, 0xfe, 0x09, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x24,
    0x90, 0x00, 0x40, 0x86, 0xe9, 0x00, 0x03, 0x01, 0x0a, 0x04, 0x01, 0x01, 0x02, 0x32, 0x1e, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    const auto decoded = DecodeTtcLobResponse(lob_get_length_response, 114);
    CHECK(decoded.amount == 10);
    CHECK(decoded.data.empty());
    // The end-of-call is left for the caller, exactly as the fetch path does.
    CHECK(decoded.bytes_consumed < lob_get_length_response.size());
    CHECK(IsTtcErrorMessage(
        std::vector<uint8_t>(lob_get_length_response.begin() + static_cast<std::ptrdiff_t>(decoded.bytes_consumed),
                             lob_get_length_response.end())));
}

// A CLOB read comes back as AL16UTF16 whatever the content is: these ten
// Cyrillic characters arrive as twenty bytes, the same width the ASCII sample
// does. Live 19c.
static void TestLobReadResponseIsUtf16ForAClob() {
    const std::vector<uint8_t> lob_read_clob_response {
    0x0e, 0xfe, 0x01, 0x14, 0x04, 0x3f, 0x04, 0x40, 0x04, 0x38, 0x04, 0x32, 0x04, 0x35, 0x04, 0x42, 0x00, 0x20,
    0x04, 0x3c, 0x04, 0x38, 0x04, 0x40, 0x00, 0x08, 0x00, 0x70, 0x00, 0x02, 0x02, 0x0c, 0x82, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x7e, 0x3f, 0x00, 0x01, 0x24, 0x91, 0x00, 0x01, 0x24, 0x90,
    0x00, 0x02, 0x00, 0x02, 0x03, 0x69, 0x6d, 0xb1, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x55, 0xbe, 0x13,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x00, 0x22, 0x00, 0x00, 0x00, 0x01,
    0x00, 0xf6, 0xfe, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x24, 0x90, 0x00, 0x40, 0x86, 0xe9, 0x00, 0x03, 0x01, 0x0a, 0x04, 0x01,
    0x01, 0x02, 0x32, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    const auto decoded = DecodeTtcLobResponse(lob_read_clob_response, 114);
    CHECK(decoded.amount == 10);
    CHECK(decoded.data.size() == 20);
    const auto text = DecodeUtf16BeToUtf8(decoded.data);
    CHECK(std::string(text.begin(), text.end()) == "\xd0\xbf\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82 \xd0\xbc\xd0\xb8\xd1\x80");
}

// A BLOB read carries its bytes as they are stored, with no character set in
// the way. Live 19c, a BLOB holding the single byte 0xff.
static void TestLobReadResponseIsRawForABlob() {
    const std::vector<uint8_t> lob_read_blob_response {
    0x0e, 0xfe, 0x01, 0x01, 0xff, 0x00, 0x08, 0x00, 0x70, 0x00, 0x02, 0x01, 0x0c, 0x02, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x7e, 0x40, 0x00, 0x01, 0x24, 0x93, 0x00, 0x01, 0x24, 0x90, 0x00,
    0x03, 0x00, 0x03, 0x00, 0x00, 0x6a, 0xb1, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x55, 0xbe, 0x13, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x00, 0x22, 0x00, 0x00, 0x00, 0x01, 0x00,
    0xf6, 0xfe, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x24, 0x90, 0x00, 0x40, 0x86, 0xe9, 0x00, 0x03, 0x01, 0x01, 0x04, 0x01, 0x01,
    0x02, 0x32, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    const auto decoded = DecodeTtcLobResponse(lob_read_blob_response, 114);
    CHECK(decoded.amount == 1);
    CHECK(decoded.data == std::vector<uint8_t>({0xff}));
}

// A LOB large enough to outgrow one packet arrives as several, and the return
// parameter that says how much was served is only in the last. An incomplete
// response therefore has to read as truncated rather than as a malformed one:
// the caller reads another message on TRUNCATED and gives up on anything else.
static void TestPartialLobResponseReadsAsTruncated() {
    // The same capture as the CLOB read above, cut short at every length.
    const std::vector<uint8_t> whole {
    0x0e, 0xfe, 0x01, 0x14, 0x04, 0x3f, 0x04, 0x40, 0x04, 0x38, 0x04, 0x32, 0x04, 0x35, 0x04, 0x42, 0x00, 0x20,
    0x04, 0x3c, 0x04, 0x38, 0x04, 0x40, 0x00, 0x08, 0x00, 0x70, 0x00, 0x02, 0x02, 0x0c, 0x82, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x7e, 0x3f, 0x00, 0x01, 0x24, 0x91, 0x00, 0x01, 0x24, 0x90,
    0x00, 0x02, 0x00, 0x02, 0x03, 0x69, 0x6d, 0xb1, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x55, 0xbe, 0x13,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x00, 0x22, 0x00, 0x00, 0x00, 0x01,
    0x00, 0xf6, 0xfe, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x24, 0x90, 0x00, 0x40, 0x86, 0xe9, 0x00, 0x03, 0x01, 0x0a, 0x04, 0x01,
    0x01, 0x02, 0x32, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    for (size_t length = 1; length + 1 < whole.size(); length++) {
        const std::vector<uint8_t> partial(whole.begin(), whole.begin() + static_cast<std::ptrdiff_t>(length));
        try {
            DecodeTtcLobResponse(partial, 114);
        } catch (const ProtocolError &error) {
            CHECK(error.Kind() == ProtocolErrorKind::TRUNCATED);
        }
    }
}

// The request layout is positional: every pointer and length is written whether
// or not it carries anything, and the locator sits after the array-LOB fields.
// The amount pointer is set even for GET_LENGTH, which is what makes the server
// answer with a length at all — without it the response ends at the locator and
// the end-of-call is read as the amount.
static void TestLobRequestLayout() {
    TtcLobRequest request;
    request.sequence = 7;
    request.locator = std::vector<uint8_t>(114, 0xab);
    request.operation = LOB_OP_GET_LENGTH;
    const auto encoded = EncodeTtcLobRequest(request);
    CHECK(encoded[0] == 3 && encoded[1] == TTC_FUNCTION_LOB_OP && encoded[2] == 7);
    // The locator is the last thing before the amount, and both are present.
    // A zero amount is still written, as one universal-integer byte, because it
    // is the pointer before it that decides whether the server answers with a
    // length at all.
    CHECK(encoded.size() > 114 + 3);
    CHECK(encoded.back() == 0x00);
    CHECK(std::vector<uint8_t>(encoded.end() - 115, encoded.end() - 1) == request.locator);

    bool refused = false;
    try {
        TtcLobRequest empty;
        empty.locator = {};
        EncodeTtcLobRequest(empty);
    } catch (const ProtocolError &error) {
        refused = error.Kind() == ProtocolErrorKind::MALFORMED;
    }
    CHECK(refused);

    refused = false;
    try {
        TtcLobRequest zero_offset;
        zero_offset.locator = std::vector<uint8_t>(40, 0x01);
        zero_offset.offset = 0;
        EncodeTtcLobRequest(zero_offset);
    } catch (const ProtocolError &error) {
        refused = error.Kind() == ProtocolErrorKind::MALFORMED;
    }
    CHECK(refused);

    refused = false;
    try {
        TtcLobRequest huge;
        huge.locator = std::vector<uint8_t>(40, 0x01);
        huge.amount = (64ULL << 20U);
        EncodeTtcLobRequest(huge);
    } catch (const ProtocolError &error) {
        refused = error.Kind() == ProtocolErrorKind::LIMIT_EXCEEDED;
    }
    CHECK(refused);
}

// Every other character value on this wire is UTF-8, so a CLOB is converted on
// the way in. An odd byte count or a lone surrogate is a misread rather than
// text, and inventing a replacement character would put bytes in a column that
// the database does not hold.
static void TestUtf16BeConversion() {
    const auto ascii = DecodeUtf16BeToUtf8({0x00, 0x68, 0x00, 0x69});
    CHECK(std::string(ascii.begin(), ascii.end()) == "hi");

    const auto cyrillic = DecodeUtf16BeToUtf8({0x04, 0x3f});
    CHECK(cyrillic == std::vector<uint8_t>({0xd0, 0xbf}));

    // U+1F600, a surrogate pair, and the one case where four bytes in become
    // four bytes out.
    const auto astral = DecodeUtf16BeToUtf8({0xd8, 0x3d, 0xde, 0x00});
    CHECK(astral == std::vector<uint8_t>({0xf0, 0x9f, 0x98, 0x80}));

    CHECK(DecodeUtf16BeToUtf8({}).empty());

    for (const std::vector<uint8_t> &bad : {std::vector<uint8_t>({0x00}),
                                            std::vector<uint8_t>({0xd8, 0x3d}),
                                            std::vector<uint8_t>({0xd8, 0x3d, 0x00, 0x41}),
                                            std::vector<uint8_t>({0xde, 0x00, 0x00, 0x41})}) {
        bool refused = false;
        try {
            DecodeUtf16BeToUtf8(bad);
        } catch (const ProtocolError &error) {
            refused = error.Kind() == ProtocolErrorKind::MALFORMED;
        }
        CHECK(refused);
    }
}

// The transport seam: a real TNS handshake, driven end to end against scripted
// bytes with no socket and no OpenSSL. Before OpenOracleTransport existed the
// connect path named OpenSslByteStream directly, so REDIRECT — a branch that
// only a listener in front of a different instance produces — had no offline
// coverage at all. Here it is one entry in a script.
class ScriptedTransport : public ByteStream {
public:
    // Writes land in a buffer the caller owns, because a redirected connect
    // destroys the first transport before the test can look at it.
    ScriptedTransport(std::vector<uint8_t> input_p, std::vector<uint8_t> *sink_p = nullptr)
        : input(std::move(input_p)), sink(sink_p) {
    }
    size_t Read(uint8_t *destination, size_t maximum_size) override {
        const auto count = (std::min)(maximum_size, input.size() - read_offset);
        std::copy(input.begin() + static_cast<std::ptrdiff_t>(read_offset),
                  input.begin() + static_cast<std::ptrdiff_t>(read_offset + count), destination);
        read_offset += count;
        return count;
    }
    size_t Write(const uint8_t *source, size_t size) override {
        if (sink) {
            sink->insert(sink->end(), source, source + size);
        }
        return size;
    }
    void Close() override {
        closed = true;
    }

    std::vector<uint8_t> input;
    std::vector<uint8_t> *sink = nullptr;
    size_t read_offset = 0;
    bool closed = false;
};

static std::vector<uint8_t> AcceptPacketBytes(bool check_oob) {
    // The fields the ACCEPT parser reads: version at 0, SDU at 26, and the
    // optional flags2 at 33 whose bit 0 is CHECK_OOB.
    std::vector<uint8_t> payload(37, 0);
    payload[0] = 0x01;
    payload[1] = 0x3e; // version 318, what 19c answers
    payload[26] = 0x20;
    payload[27] = 0x00; // SDU 8192
    payload[33] = 0x00;
    payload[34] = 0x00;
    payload[35] = 0x00;
    payload[36] = check_oob ? 0x01 : 0x00;
    return EncodeTnsPacket(TnsPacketType::ACCEPT, 0, payload, false);
}

#if !defined(_WIN32)
// Writing to a peer that has closed returns EPIPE and raises SIGPIPE, whose
// default action terminates the process. That is not a test concern: an Oracle
// server closing mid-write would take down the whole DuckDB process instead of
// failing one statement, and it does so only on Linux, because macOS suppresses
// the signal for sockets. openssl_stream blocks it around every write and
// consumes the one it raised, so this has to surface as an ordinary
// ProtocolError — and this process has to still be here to report it.
static void TestWriteToClosedPeerDoesNotKillTheProcess() {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    CHECK(bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
    CHECK(listen(listener, 1) == 0);
    socklen_t address_size = sizeof(address);
    CHECK(getsockname(listener, reinterpret_cast<sockaddr *>(&address), &address_size) == 0);
    const auto port = ntohs(address.sin_port);

    // Accepts once and drops the connection immediately, which is what an
    // Oracle listener does to a connection it will not serve.
    std::thread closer([listener] {
        const auto accepted = accept(listener, nullptr, nullptr);
        if (accepted >= 0) {
            close(accepted);
        }
    });

    auto stream = OpenSslByteStream::Connect("127.0.0.1", port, 5, 5, false);
    CHECK(stream != nullptr);
    closer.join();
    close(listener);

    // The first write usually lands in the kernel buffer; the peer's RST is
    // seen by the next one. Both are attempted, and either an error or a clean
    // return is acceptable — what is not acceptable is dying.
    const std::vector<uint8_t> payload(64, 0x5a);
    bool reported = false;
    for (int attempt = 0; attempt < 8 && !reported; attempt++) {
        try {
            stream->Write(payload.data(), payload.size());
        } catch (const ProtocolError &error) {
            reported = error.Kind() == ProtocolErrorKind::INVALID_STATE ||
                       error.Kind() == ProtocolErrorKind::TRUNCATED;
        }
    }
    // There is deliberately no CHECK on `reported`: whether the peer's RST has
    // arrived by any given attempt is timing, and asserting on it would make
    // this flaky. Reaching this line is the assertion — an unprotected write
    // would have killed the process several lines ago, with no output.
    (void)reported;
    stream->Close();
}
#endif // !_WIN32

static void TestConnectRunsThroughTheTransportSeam() {
    const std::string redirect_descriptor =
        "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.0.9)(PORT=1522))(CONNECT_DATA=(SERVICE_NAME=moved)))";
    std::vector<uint8_t> redirect_payload(redirect_descriptor.begin(), redirect_descriptor.end());

    std::vector<std::pair<std::string, uint16_t>> endpoints;
    // A deque, so a reference handed to a transport stays valid when the next
    // connect appends.
    std::deque<std::vector<uint8_t>> written;
    size_t connect_count = 0;
    ScopedOracleTransportFactory installed(
        [&](const std::string &host, uint16_t port, uint32_t, uint32_t, bool use_tls,
            const TlsConfiguration &) -> std::unique_ptr<ByteStream> {
            CHECK(!use_tls);
            endpoints.emplace_back(host, port);
            written.emplace_back();
            return std::make_unique<ScriptedTransport>(
                connect_count++ == 0 ? EncodeTnsPacket(TnsPacketType::REDIRECT, 0, redirect_payload, false)
                                     : AcceptPacketBytes(false),
                &written.back());
        });

    ConnectionConfig config;
    config.host = "first.example";
    config.port = 1521;
    config.service_name = "svc";

    auto connection = TnsClientConnection::Connect(config);
    CHECK(connection != nullptr);
    CHECK(connection->State() == OracleConnectionState::TRANSPORT_CONNECTED);
    CHECK(connection->NegotiatedSdu() == 8192);

    // The redirect was followed to the address the listener named, and only
    // there: two connects, the second at the redirected endpoint.
    CHECK(connect_count == 2);
    CHECK(endpoints.size() == 2);
    CHECK(endpoints[0].first == "first.example" && endpoints[0].second == 1521);
    CHECK(endpoints[1].first == "10.0.0.9" && endpoints[1].second == 1522);

    // Each attempt wrote a CONNECT packet, and the second carried the
    // descriptor the listener handed back rather than the original one.
    CHECK(written.size() == 2);
    for (const auto &bytes : written) {
        // The buffer holds everything the connect wrote, so the first packet is
        // sliced off by its own declared length rather than decoded whole.
        CHECK(bytes.size() > 2);
        const size_t declared = (static_cast<size_t>(bytes[0]) << 8U) | bytes[1];
        CHECK(declared >= 2 && declared <= bytes.size());
        CHECK(DecodeTnsPacket(std::vector<uint8_t>(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(declared)),
                              false)
                  .type == TnsPacketType::CONNECT);
    }
    const auto &second = written[1];
    CHECK(std::search(second.begin(), second.end(), redirect_descriptor.begin(), redirect_descriptor.end()) !=
          second.end());
}

// The CHECK_OOB probe needs a TCP urgent byte, which a transport is entitled
// not to have — TLS has none, and neither would a tunnelled one. The refusal
// has to come from the transport by kind rather than by type, which is why
// SendUrgent is on the interface with this default.
static void TestTransportWithoutOutOfBandRefusesTheOobProbe() {
    ScopedOracleTransportFactory installed(
        [&](const std::string &, uint16_t, uint32_t, uint32_t, bool, const TlsConfiguration &)
            -> std::unique_ptr<ByteStream> { return std::make_unique<ScriptedTransport>(AcceptPacketBytes(true)); });

    ConnectionConfig config;
    config.host = "first.example";
    config.port = 1521;
    config.service_name = "svc";

    bool refused = false;
    try {
        TnsClientConnection::Connect(config);
    } catch (const ProtocolError &error) {
        refused = error.Kind() == ProtocolErrorKind::UNSUPPORTED;
    }
    CHECK(refused);

    // And the seam restores itself: with no factory installed the default is
    // the real transport again, which is what production always uses.
    ScriptedTransport plain({});
    bool defaulted = false;
    try {
        plain.SendUrgent(0x21);
    } catch (const ProtocolError &error) {
        defaulted = error.Kind() == ProtocolErrorKind::UNSUPPORTED;
    }
    CHECK(defaulted);
}

static void TestRepeatedRowsCarryNoValues() {
    OracleColumn label;
    label.name = "LABEL";
    label.oracle_type = 1;
    label.byte_width = 20;

    // ROW_HEADER with a one-byte 0x00 bit vector, one bare ROW_DATA, then a
    // BIT_VECTOR selecting nothing with its own bare ROW_DATA, then the
    // end-of-fetch TTIOER carrying ORA-01403.
    const std::vector<uint8_t> repeated {0x06, 0x02, 0x00, 0x00, 0x02, 0x07, 0xfe, 0x00, 0x01, 0x01, 0x01,
                                         0x00, 0x00, 0x07, 0x15, 0x00, 0x00, 0x07, 0x04, 0x01, 0x01, 0x02,
                                         0x6f, 0xd8, 0x01, 0x05, 0x02, 0x05, 0x7b, 0x00, 0x00, 0x01, 0x02,
                                         0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                                         0x05, 0x7b, 0x01, 0x05, 0x19, 'O',  'R',  'A',  '-',  '0',  '1',
                                         '4',  '0',  '3',  ':',  ' ',  'n',  'o',  ' ',  'd',  'a',  't',
                                         'a',  ' ',  'f',  'o',  'u',  'n',  'd',  '\n'};
    TtcRowData preceding;
    preceding.push_back(std::vector<uint8_t>({'b', 'u', 'l', 'k'}));
    const auto decoded = DecodeTtcFetchResponse(repeated, {label}, 6, preceding);
    CHECK(decoded.rows.size() == 2);
    for (const auto &row : decoded.rows) {
        CHECK(row.size() == 1);
        CHECK(row[0].has_value() && *row[0] == std::vector<uint8_t>({'b', 'u', 'l', 'k'}));
    }
    // ORA-01403 is the end of the fetch, not an error to raise.
    CHECK(decoded.exhausted);

    // Without a preceding row there is nothing to repeat, and saying so is
    // better than inventing a value.
    bool refused = false;
    try {
        DecodeTtcFetchResponse(repeated, {label}, 6);
    } catch (const ProtocolError &error) {
        refused = error.Kind() == ProtocolErrorKind::MALFORMED;
    }
    CHECK(refused);
}

// TTIOER ends the response, and its tail is capability-dependent. This is the
// live Free 23ai end-of-call for `SELECT '' AS only_col FROM dual`: after the
// extended error number and row count it carries three more bytes that Oracle
// 19c does not send. Treating those as a new message reads `00` as a message
// type; the decoder must consume them as part of the TTIOER instead.
static void TestTtcErrorTailEndsTheResponse() {
    OracleColumn column;
    column.name = "ONLY_COL";
    column.oracle_type = 96;
    column.byte_width = 0;
    column.omitted_from_row_data = true;

    std::vector<uint8_t> message {0x06, 0x22, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x07};
    const std::vector<uint8_t> end_of_call {0x04, 0x01, 0x01, 0x01, 0xd5, 0x00, 0x00, 0x00, 0x00, 0x01,
                                            0x02, 0x01, 0x14, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01,
                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00};
    message.insert(message.end(), end_of_call.begin(), end_of_call.end());

    // Free 23ai reports field version 27, so its end-of-call carries the SQL
    // type and checksum trailer and the whole message is consumed exactly.
    const auto decoded = DecodeTtcFetchResponse(message, {column}, 27);
    CHECK(decoded.rows.size() == 1 && !decoded.rows[0][0].has_value());
    CHECK(decoded.completion && decoded.completion->error_number == 0);
    CHECK(decoded.bytes_consumed == message.size());
    CHECK(decoded.completed);

    // Decoding the same message as if the server were below the gate leaves the
    // trailer unread, and the decoder says so rather than accepting a prefix.
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)DecodeTtcFetchResponse(message, {column}, 12); });
}

// The TTC field version both sides speak is the lower of what this client
// advertises and what the server reports at TNS_CCAP_FIELD_VERSION, and every
// response decoder is given that rather than a literal. Live values: Oracle 19c
// reports 12, Free 23ai and OCI Autonomous report 27, so all three negotiate to
// this client's 12.
static void TestNegotiatedTtcFieldVersion() {
    const auto negotiated = [](uint8_t server_field_version) {
        ByteWriter capabilities;
        for (size_t index = 0; index < 16; index++) {
            capabilities.WriteByte(index == TTC_CAPABILITY_FIELD_VERSION_INDEX ? server_field_version : 0);
        }
        ByteWriter message;
        message.WriteByte(TTC_MESSAGE_PROTOCOL).WriteByte(6).WriteByte(0);
        message.WriteNullTerminated("Oracle");
        message.WriteUInt16LE(ORACLE_CHARSET_AL32UTF8).WriteByte(0);
        message.WriteUInt16LE(0); // no protocol element table
        message.WriteUInt16BE(0); // no format descriptor
        message.WriteLengthPrefixed(capabilities.Data());
        message.WriteLengthPrefixed(std::vector<uint8_t> {0});
        return ParseTtcProtocolResponse(message.Data()).field_version;
    };
    // A server above this client's version negotiates down to the client's.
    CHECK(negotiated(27) == ORACLE_CLIENT_TTC_FIELD_VERSION);
    CHECK(negotiated(12) == 12);
    // A server below it wins, because both sides must speak one shape.
    CHECK(negotiated(6) == 6);
}

// A transport-level end of response is a negotiated capability, not something a
// client may assume: it needs ACCEPT protocol version 319 or later together with
// the flags2 bit. Oracle 19c answers 318 with neither, which is why its data
// responses carry no END_OF_RESPONSE at all.
static void TestEndOfResponseNegotiation() {
    const auto accepted = [](uint16_t version, uint32_t flags2) {
        std::vector<uint8_t> payload(37, 0);
        payload[0] = static_cast<uint8_t>(version >> 8U);
        payload[1] = static_cast<uint8_t>(version & 0xffU);
        payload[26] = 0x20; // SDU 8192, the live negotiated value
        payload[33] = static_cast<uint8_t>(flags2 >> 24U);
        payload[34] = static_cast<uint8_t>((flags2 >> 16U) & 0xffU);
        payload[35] = static_cast<uint8_t>((flags2 >> 8U) & 0xffU);
        payload[36] = static_cast<uint8_t>(flags2 & 0xffU);
        FragmentedStream stream(EncodeTnsPacket(TnsPacketType::ACCEPT, 0, payload, false));
        TnsPacketStream packets(stream, false);
        return RunTnsConnect(packets, "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=X)))");
    };
    // Oracle 19c: version 318, flags2 CHECK_OOB only.
    const auto legacy = accepted(318, 0x00000001);
    CHECK(legacy.accept_version == 318 && !legacy.end_of_response && legacy.check_oob);
    // Free 23ai and OCI Autonomous: version 319 with the end-of-response bit.
    const auto modern = accepted(319, 0x1a000000);
    CHECK(modern.accept_version == 319 && modern.end_of_response);
    // The version gate and the bit are both required.
    CHECK(!accepted(318, 0x1a000000).end_of_response);
    CHECK(!accepted(319, 0x00000001).end_of_response);
}

static void TestSessionFactory() {
    ConnectionConfig config;
    config.host = "db.example.com";
    config.port = 1521;
    config.service_name = "service";
    config.user = "app_user";

    {
        ConnectionConfig seen;
        std::string seen_password;
        size_t opened = 0;
        ScopedOracleSessionFactory installed([&](const ConnectionConfig &requested, const std::string &password) {
            seen = requested;
            seen_password = password;
            opened++;
            return std::make_unique<TestSession>();
        });

        auto session = OpenOracleSession(config, "secret");
        CHECK(session != nullptr);
        CHECK(opened == 1);
        // The seam forwards the request unchanged, including the password it
        // never stores anywhere else.
        CHECK(seen.host == config.host && seen.port == config.port && seen.service_name == config.service_name &&
               seen.user == config.user);
        CHECK(seen_password == "secret");

        // The session the factory produced is the one the caller gets.
        session->Execute("delete from invoices where id = :id", {{"id", 2, BindDirection::BIND_IN, std::nullopt}});
        CHECK(static_cast<TestSession *>(session.get())->executes == 1);

        // A nested installer wins while it is alive and restores the outer one.
        {
            size_t nested_opened = 0;
            ScopedOracleSessionFactory nested([&](const ConnectionConfig &, const std::string &) {
                nested_opened++;
                return std::make_unique<TestSession>();
            });
            (void)OpenOracleSession(config, "secret");
            CHECK(nested_opened == 1 && opened == 1);
        }
        (void)OpenOracleSession(config, "secret");
        CHECK(opened == 2);
    }

    // A factory that produces nothing is a caller error, not a null session
    // handed to the adapter.
    ScopedOracleSessionFactory empty([](const ConnectionConfig &, const std::string &) {
        return std::unique_ptr<OracleSession> {};
    });
    ExpectError(ProtocolErrorKind::INVALID_STATE, [&] { (void)OpenOracleSession(config, "secret"); });
}

static void TestSessionPool() {
    size_t created = 0;
    std::shared_ptr<TestSession> first;
    OracleSessionPool pool(1, [&] {
        created++;
        first = std::make_shared<TestSession>();
        return std::static_pointer_cast<OracleSession>(first);
    });
    {
        auto lease = pool.Acquire();
        CHECK(lease && &lease.Get() == first.get());
        ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { pool.Acquire(); });
    }
    CHECK(created == 1 && pool.IdleCount() == 1 && pool.LiveCount() == 1);
    {
        auto lease = pool.Acquire();
        lease.Poison();
    }
    CHECK(first->closes == 1 && pool.IdleCount() == 0 && pool.LiveCount() == 0);
}

static void TestAuthCrypto() {
    auto first_random = SecureRandomBytes(32);
    auto second_random = SecureRandomBytes(32);
    CHECK(first_random.size() == 32 && second_random.size() == 32 && first_random != second_random);
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [] { SecureRandomBytes(0); });
    CHECK(Base64Encode(std::vector<uint8_t> {'M', 'a', 'n'}) == "TWFu");

    std::vector<uint8_t> password {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    std::vector<uint8_t> salt {'s', 'a', 'l', 't'};
    auto derived = Pbkdf2Sha512(password, salt, 1, 64);
    CHECK(UpperHex(derived) ==
           "867F70CF1ADE02CFF3752599A3A53DC4AF34C7A669815AE5D513554E1C8CF252"
           "C02D470A285A0501BAD999BFE943C08F050235D7D68B1DA55E63F73B60A57FCE");
    CHECK(DecodeHex(UpperHex(derived), 64) == derived);

    std::vector<uint8_t> key(32, 7);
    std::vector<uint8_t> plaintext {'S', 'E', 'R', 'V', 'E', 'R', '_', 'T', 'O', '_', 'C', 'L', 'I', 'E', 'N', 'T'};
    auto ciphertext = AesCbcEncrypt(key, plaintext);
    CHECK(ciphertext.size() == 32);
    CHECK(AesCbcDecrypt(key, ciphertext) == plaintext);

    std::vector<uint8_t> verifier(16);
    std::vector<uint8_t> server_key(32);
    std::vector<uint8_t> client_key(32);
    std::vector<uint8_t> combo_salt(16);
    std::vector<uint8_t> password_salt(16);
    for (size_t index = 0; index < 32; index++) {
        server_key[index] = static_cast<uint8_t>(index + 1);
        client_key[index] = static_cast<uint8_t>(index + 33);
        if (index < 16) {
            verifier[index] = static_cast<uint8_t>(index + 65);
            combo_salt[index] = static_cast<uint8_t>(index + 81);
            password_salt[index] = static_cast<uint8_t>(index + 97);
        }
    }
    std::vector<uint8_t> verifier_salt = verifier;
    const std::string speedy_key = "AUTH_PBKDF2_SPEEDY_KEY";
    verifier_salt.insert(verifier_salt.end(), speedy_key.begin(), speedy_key.end());
    auto password_key = Pbkdf2Sha512(password, verifier_salt, 4096, 64);
    auto password_hash = Sha512({password_key, verifier});
    password_hash.resize(32);

    O5LogonChallenge challenge;
    challenge.verifier_data_hex = UpperHex(verifier);
    challenge.server_session_key_hex = UpperHex(AesCbcEncryptRaw(password_hash, server_key));
    challenge.combo_key_salt_hex = UpperHex(combo_salt);
    challenge.verifier_iterations = 4096;
    challenge.combo_key_iterations = 3;
    std::vector<uint8_t> speedy_key_salt(16, 6);
    auto response = BuildO5LogonResponse("password", challenge, client_key, password_salt, speedy_key_salt);
    CHECK(AesCbcDecryptRaw(password_hash, DecodeHex(response.client_session_key_hex, 32)) == client_key);
    auto password_block = AesCbcDecrypt(response.combo_key, DecodeHex(response.encrypted_password_hex, 128));
    CHECK(std::equal(password_salt.begin(), password_salt.end(), password_block.begin()));
    CHECK(std::string(password_block.begin() + 16, password_block.end()) == "password");

    std::vector<uint8_t> proof(16, 0);
    proof.insert(proof.end(), {'S', 'E', 'R', 'V', 'E', 'R', '_', 'T', 'O', '_', 'C', 'L', 'I', 'E', 'N', 'T'});
    CHECK(VerifyO5LogonServerResponse(response, UpperHex(AesCbcEncrypt(response.combo_key, proof))));
    proof.back() = 'X';
    CHECK(!VerifyO5LogonServerResponse(response, UpperHex(AesCbcEncrypt(response.combo_key, proof))));

    challenge.verifier_iterations = 0;
    ExpectError(ProtocolErrorKind::MALFORMED,
                [&] { BuildO5LogonResponse("password", challenge, client_key, password_salt, speedy_key_salt); });
    challenge.verifier_iterations = 4096;
    challenge.verifier_type = 0xb152;
    ExpectError(ProtocolErrorKind::MALFORMED,
                [&] { BuildO5LogonResponse("password", challenge, client_key, password_salt, speedy_key_salt); });
}

// Builds a wallet in the shape Oracle's auto-login store has, from a throwaway
// identity generated here. Nothing in this suite may carry real wallet bytes:
// a cwallet.sso is credential material, so the only honest fixture is one the
// test makes itself.
static std::string BuildAutoLoginWallet(const local_tls::Identity &identity, const std::string &store_password,
                                        unsigned char flavour = '6') {
    std::unique_ptr<BIO, decltype(&BIO_free)> certificate_bio(
        BIO_new_mem_buf(identity.certificate_pem.data(), static_cast<int>(identity.certificate_pem.size())), BIO_free);
    std::unique_ptr<X509, decltype(&X509_free)> certificate(
        PEM_read_bio_X509(certificate_bio.get(), nullptr, nullptr, nullptr), X509_free);
    std::unique_ptr<BIO, decltype(&BIO_free)> key_bio(
        BIO_new_mem_buf(identity.key_pem.data(), static_cast<int>(identity.key_pem.size())), BIO_free);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    CHECK(certificate && key);

    std::unique_ptr<PKCS12, decltype(&PKCS12_free)> store(
        PKCS12_create(store_password.c_str(), "oracle_scanner test", key.get(), certificate.get(), nullptr, 0, 0, 0, 0,
                      0),
        PKCS12_free);
    CHECK(store);
    unsigned char *encoded = nullptr;
    const auto encoded_size = i2d_PKCS12(store.get(), &encoded);
    CHECK(encoded_size > 0 && encoded != nullptr);
    const std::string pkcs12(reinterpret_cast<const char *>(encoded), static_cast<size_t>(encoded_size));
    OPENSSL_free(encoded);

    // The header wraps the store password with AES-128-CBC under a key kept in
    // the file itself and the fixed IV the format uses.
    const std::string wrapping_key(16, '\x11');
    const std::array<unsigned char, 16> iv = {0xC0, 0x34, 0xD8, 0x31, 0x1C, 0x02, 0xCE, 0xF8,
                                              0x51, 0xF0, 0x14, 0x4B, 0x81, 0xED, 0x4B, 0xF2};
    std::string padded = store_password;
    const auto padding = static_cast<size_t>(16 - (padded.size() % 16));
    padded.append(padding, static_cast<char>(padding));
    std::string wrapped(padded.size(), '\0');
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> cipher(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    CHECK(cipher);
    CHECK(EVP_EncryptInit_ex(cipher.get(), EVP_aes_128_cbc(), nullptr,
                             reinterpret_cast<const unsigned char *>(wrapping_key.data()), iv.data()) == 1);
    EVP_CIPHER_CTX_set_padding(cipher.get(), 0);
    int produced = 0;
    CHECK(EVP_EncryptUpdate(cipher.get(), reinterpret_cast<unsigned char *>(wrapped.data()), &produced,
                            reinterpret_cast<const unsigned char *>(padded.data()),
                            static_cast<int>(padded.size())) == 1);
    int final_produced = 0;
    CHECK(EVP_EncryptFinal_ex(cipher.get(), reinterpret_cast<unsigned char *>(wrapped.data()) + produced,
                              &final_produced) == 1);
    wrapped.resize(static_cast<size_t>(produced) + static_cast<size_t>(final_produced));

    const auto header_size = static_cast<uint32_t>(1 + wrapping_key.size() + wrapped.size());
    std::string wallet;
    wallet.push_back(static_cast<char>(0xA1));
    wallet.push_back(static_cast<char>(0xF8));
    wallet.push_back(static_cast<char>(0x4E));
    wallet.push_back(static_cast<char>(flavour));
    const auto append_big_endian = [&wallet](uint32_t value) {
        wallet.push_back(static_cast<char>((value >> 24U) & 0xFFU));
        wallet.push_back(static_cast<char>((value >> 16U) & 0xFFU));
        wallet.push_back(static_cast<char>((value >> 8U) & 0xFFU));
        wallet.push_back(static_cast<char>(value & 0xFFU));
    };
    append_big_endian(6);
    append_big_endian(header_size);
    wallet.push_back(static_cast<char>(0x06));
    wallet.append(wrapping_key);
    wallet.append(wrapped);
    wallet.append(pkcs12);
    return wallet;
}

static void TestSsoWallet() {
    const auto identity = local_tls::MakeIdentity("sso.example.com", -3600, 3600);
    const auto wallet = BuildAutoLoginWallet(identity, "store-password");

    CHECK(HasSsoWalletMagic(wallet));
    CHECK(!HasSsoWalletMagic("not a wallet"));

    // The whole point: the identity comes back without anyone supplying the
    // store password, because the header carried it.
    const auto pem = SsoWalletToPem(wallet);
    CHECK(pem.find("-----BEGIN PRIVATE KEY-----") != std::string::npos);
    CHECK(pem.find("-----BEGIN CERTIFICATE-----") != std::string::npos);

    // And the recovered identity is the one that went in, not merely something
    // that parses: the certificate must match the private key.
    std::unique_ptr<BIO, decltype(&BIO_free)> pem_bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())),
                                                      BIO_free);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> recovered_key(
        PEM_read_bio_PrivateKey(pem_bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    std::unique_ptr<X509, decltype(&X509_free)> recovered_certificate(
        PEM_read_bio_X509(pem_bio.get(), nullptr, nullptr, nullptr), X509_free);
    CHECK(recovered_key && recovered_certificate);
    CHECK(X509_check_private_key(recovered_certificate.get(), recovered_key.get()) == 1);

    // A wallet locked to the machine that made it is refused by name rather
    // than failing later inside OpenSSL with nothing to act on.
    const auto local_wallet = BuildAutoLoginWallet(identity, "store-password", '8');
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [&] { (void)SsoWalletToPem(local_wallet); });

    auto foreign_magic = wallet;
    foreign_magic[1] = static_cast<char>(0x00);
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)SsoWalletToPem(foreign_magic); });

    auto unknown_version = wallet;
    unknown_version[3] = '9';
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [&] { (void)SsoWalletToPem(unknown_version); });

    auto unknown_header_version = wallet;
    unknown_header_version[7] = static_cast<char>(0x07);
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [&] { (void)SsoWalletToPem(unknown_header_version); });

    auto unknown_password_kind = wallet;
    unknown_password_kind[12] = static_cast<char>(0x42);
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [&] { (void)SsoWalletToPem(unknown_password_kind); });

    ExpectError(ProtocolErrorKind::TRUNCATED, [&] { (void)SsoWalletToPem(wallet.substr(0, 10)); });
    ExpectError(ProtocolErrorKind::TRUNCATED, [&] { (void)SsoWalletToPem(wallet.substr(0, 13)); });
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [] { (void)SsoWalletToPem(std::string()); });

    // Header claims more wrapped password than the file holds.
    auto oversized_header = wallet;
    oversized_header[10] = static_cast<char>(0x40);
    ExpectError(ProtocolErrorKind::TRUNCATED, [&] { (void)SsoWalletToPem(oversized_header); });

    // A payload that is no longer a PKCS#12 store, with the header intact.
    auto broken_payload = wallet;
    broken_payload[wallet.size() - 1] = static_cast<char>(~broken_payload[wallet.size() - 1]);
    broken_payload[45] = static_cast<char>(0x00);
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)SsoWalletToPem(broken_payload); });

    // And the archive path: a wallet ZIP holding only cwallet.sso resolves
    // without a password, exactly as it does for SQL*Plus and JDBC.
    const auto base = TemporaryDirectory() + "/oracle_scanner_sso_" + std::to_string(::getpid());
    const auto sso_only_path = base + "_sso.zip";
    WriteWalletArchiveForTest(sso_only_path, {{"cwallet.sso", wallet}, {"tnsnames.ora", "unit_low = (description=)"}});
    CHECK(ReadWalletIdentityPem(sso_only_path, false) == pem);
    CHECK(ReadWalletIdentityPem(sso_only_path, true) == pem);
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)ReadWalletPemArchive(sso_only_path); });

    // With both members present the password decides which one is used.
    const auto both_path = base + "_both.zip";
    const auto plain_pem = identity.certificate_pem + identity.key_pem;
    WriteWalletArchiveForTest(both_path, {{"cwallet.sso", wallet}, {"ewallet.pem", plain_pem}});
    CHECK(ReadWalletIdentityPem(both_path, false) == pem);
    CHECK(ReadWalletIdentityPem(both_path, true) == plain_pem);

    // A wallet path pointing straight at cwallet.sso works too.
    const auto sso_file_path = base + ".sso";
    {
        std::ofstream output(sso_file_path, std::ios::binary);
        CHECK(output);
        output.write(wallet.data(), static_cast<std::streamsize>(wallet.size()));
    }
    CHECK(ReadWalletIdentityPem(sso_file_path, false) == pem);

    std::remove(sso_only_path.c_str());
    std::remove(both_path.c_str());
    std::remove(sso_file_path.c_str());
}

int main() {

    TestUniversalIntegers();
    TestWalletArchive();
    TestLengthPrefixedValues();
    TestEmptyValuesAreNull();
    TestTtcDescribeInfoVersionGates();
    TestTtcReturnParameterPrefix();
    TestTtcFetchTruncatedEndOfCallIsTruncated();
    TestPacketFraming();
    TestPacketStream();
    TestConnectPackets();
    TestConnectHandshake();
    TestTtcChannel();
    TestTtcChannelShortPacketBoundary();
    TestStatementChannelJoinsFragmentedResponse();
    TestTtcCancellation();
    TestTtcErrorDiagnostics();
    TestTtcParameters();
    TestTtcAuthEncoding();
    TestTtcFetchCodec();
    TestTtcFetchResponse();
    TestTtcIoVector();
    TestTtcRefCursorDescriptor();
    TestTtcImplicitResultSet();
    TestTtcOutBindsRow();
    TestTtcCallResponse();
    TestTtcExecuteNoBindsCodec();
    TestTtcExecuteNoBindsShape();
    TestTtcExecuteRefCursorBindShape();
#if !defined(_WIN32)
    TestLocalTlsCertificateVerification();
#endif
    TestDescriptorSecuritySection();
    TestServerDnComparison();
    TestTtcExecuteArrayDml();
    TestTtcErrorNamesTheFailingIteration();
    TestTtcErrorCarriesADmlRowId();
    TestTtcRowDataCodec();
    TestTtcNegotiation();
    TestO5LogonFlow();
    TestConnectDescriptor();
    TestDescriptorParser();
    TestValueCodecs();
    TestAuthCrypto();
    TestCallRegistry();
    TestProcedureCallBuilder();
    TestBindValidation();
    TestSqlBindExtraction();
    TestSqlStatementValidation();
    TestTransactions();
    TestValidatedSession();
    TestStatementRegistry();
    TestTtcStatementChannel();
    TestTtcCursorClosePiggyback();
    TestTtcTransactionCodec();
    TestTtcExecuteStatementChannel();
    TestLiveTnsNegotiation();
    TestZeroWidthColumnsCarryNoRowBytes();
    TestLobRowDataCarriesALocator();
    TestLobLocatorsSurviveARowContinuation();
    TestLobGetLengthResponse();
    TestLobReadResponseIsUtf16ForAClob();
    TestLobReadResponseIsRawForABlob();
    TestPartialLobResponseReadsAsTruncated();
    TestLobRequestLayout();
    TestUtf16BeConversion();
#if !defined(_WIN32)
    TestWriteToClosedPeerDoesNotKillTheProcess();
#endif
    TestConnectRunsThroughTheTransportSeam();
    TestTransportWithoutOutOfBandRefusesTheOobProbe();
    TestRepeatedRowsCarryNoValues();
    TestTtcErrorTailEndsTheResponse();
    TestNegotiatedTtcFieldVersion();
    TestEndOfResponseNegotiation();
    TestSessionFactory();
    TestSessionPool();
    TestSsoWallet();
    std::cout << "oracle_scanner protocol tests passed\n";
    return 0;
}

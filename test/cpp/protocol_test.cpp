// Before any include. Windows defines min and max as function-like macros,
// and the headers this pulls in reach <windows.h> — so `(std::min)(...)` is
// rewritten by the preprocessor and the file stops compiling, with the brace
// counting going wrong several lines later as a consequence.
#if defined(_WIN32) && !defined(NOMINMAX)
#define NOMINMAX
#endif

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if !defined(_WIN32)
#include <arpa/inet.h>
#include <csignal>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
#include "oracle_scanner/connect_error.hpp"
#include "oracle_scanner/connect_plan.hpp"
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
#include "oracle_scanner/oracle_vector.hpp"
#include "oracle_scanner/oson.hpp"
#include "oracle_scanner/ttc_define.hpp"
#include "oracle_scanner/ttc_fetch_response.hpp"
#include "oracle_scanner/ttc_lob.hpp"
#include "oracle_scanner/temp_lob.hpp"
#include "oracle_scanner/lob_prefetch_cursor.hpp"
#include "oracle_scanner/lob_prefetch_reader.hpp"
#include "oracle_scanner/io_deadline_binding.hpp"
#include "oracle_scanner/transaction_session_pool.hpp"
#include "oracle_scanner/ttc_describe.hpp"
#include "oracle_scanner/ttc_execute_response.hpp"
#include "oracle_scanner/ttc_cursor.hpp"
#include "oracle_scanner/ttc_call_response.hpp"
#include "oracle_scanner/ttc_io_vector.hpp"
#include "oracle_scanner/ttc_out_binds.hpp"
#include "oracle_scanner/ttc_execute.hpp"
#include "oracle_scanner/ttc_data_types_template.hpp"
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
#include <array>
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
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <utility>
#include <chrono>
#include <deque>
#include <map>
#include <memory>
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

// For the connect loop: the ConnectFailure is what decides whether another
// address is tried, so that is what these tests pin.
template <class FUNCTION>
static void ExpectConnectFailure(ConnectFailure failure, FUNCTION function) {
    try {
        function();
        CHECK(false && "expected OracleConnectError");
    } catch (const OracleConnectError &error) {
        CHECK(error.Failure() == failure);
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
    // What crossed the connection is counted; a round trip needs a response read after a request, which
    // this stream, read before it is written, does not have.
    const auto traffic = packets.GetStatistics();
    CHECK(traffic.bytes_received == wire.size() && traffic.bytes_sent == 11 + 22 && traffic.round_trips == 0);

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

    // REDIRECT data is a UB2 length and then that many bytes. The redirect is
    // only split here, not parsed: "(DESCRIPTION=(A))" is enough.
    FragmentedStream redirected(EncodeTnsPacket(TnsPacketType::REDIRECT, 0,
                                                {0x00, 0x11, '(', 'D', 'E', 'S', 'C', 'R', 'I', 'P', 'T', 'I', 'O',
                                                 'N', '=', '(', 'A', ')', ')'}, false));
    TnsPacketStream redirected_packets(redirected, false);
    result = RunTnsConnect(redirected_packets, "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=X)))");
    CHECK(result.disposition == TnsConnectDisposition::REDIRECTED);
    CHECK(result.redirect.address == "(DESCRIPTION=(A))" && result.redirect.reconnect_data.empty());

    // The parser this replaced skipped forward to the first '(' and so read
    // these two junk bytes as a harmless prefix. Read as what they are — a
    // length of 0x7878 — they declare far more than the listener sends, and the
    // connect waits for the rest rather than searching past them.
    FragmentedStream prefixed(EncodeTnsPacket(TnsPacketType::REDIRECT, 0,
                                              {'x', 'x', '(', 'D', 'E', 'S', 'C', 'R', 'I', 'P', 'T', 'I', 'O',
                                               'N', '=', '(', 'A', ')', ')'}, false));
    TnsPacketStream prefixed_packets(prefixed, false);
    ExpectError(ProtocolErrorKind::TRUNCATED,
                [&] { RunTnsConnect(prefixed_packets, "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=X)))"); });

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

static void TestStatementChannelJoinsFragmentedExecuteResponse() {
    ByteWriter describe;
    describe.WriteByte(16).WriteLengthPrefixed(std::nullopt).WriteUB4(0).WriteUB4(1).WriteByte(0);
    describe.WriteByte(2).WriteByte(0).WriteByte(0).WriteByte(0);
    describe.WriteUB4(22).WriteUB4(0).WriteUB8(0).WriteUB4(0);
    describe.WriteUB2(0).WriteUB2(0).WriteByte(0).WriteUB4(0).WriteUB4(0);
    describe.WriteByte(0).WriteByte(0).WriteUB4(0).WriteUB4(0).WriteUB4(0);
    describe.WriteUB2(0).WriteUB4(0);
    describe.WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0);

    ByteWriter response;
    response.WriteRaw(describe.Data());
    response.WriteByte(6).WriteByte(0).WriteUB2(0).WriteUB4(0).WriteUB4(1);
    response.WriteUB2(0).WriteUB4(0).WriteUB4(0);
    response.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(EncodeOracleNumber("7"));
    response.WriteByte(TTC_MESSAGE_ERROR).WriteUB4(0).WriteUB2(0).WriteUB4(0);
    response.WriteUB2(0).WriteUB2(0).WriteUB2(0).WriteUB4(42).WriteUB4(0);
    response.WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0);
    response.WriteUB4(0).WriteUB2(0).WriteByte(0).WriteUB4(0).WriteUB2(0);
    response.WriteUB4(0).WriteByte(0).WriteByte(0).WriteUB2(0).WriteUB4(0).WriteByte(0);
    response.WriteUB2(0).WriteUB4(0).WriteUB2(0).WriteUB4(0).WriteUB8(1);

    const auto split = describe.Data().size();
    const auto first = std::vector<uint8_t>(response.Data().begin(),
                                            response.Data().begin() + static_cast<std::ptrdiff_t>(split));
    const auto second = std::vector<uint8_t>(response.Data().begin() + static_cast<std::ptrdiff_t>(split),
                                             response.Data().end());
    std::vector<uint8_t> inbound;
    for (const auto &packet : EncodeTnsDataPackets(first, true, 512, 0)) {
        inbound.insert(inbound.end(), packet.begin(), packet.end());
    }
    for (const auto &packet : EncodeTnsDataPackets(second, true, 512, 0)) {
        inbound.insert(inbound.end(), packet.begin(), packet.end());
    }

    FragmentedStream stream(inbound, 7);
    TnsPacketStream packets(stream, true, 512);
    TtcChannel channel(packets, 512, 1U << 20U);
    OracleStatementRegistry statements;
    const auto handle = statements.Open(OracleSqlKind::QUERY);
    TtcStatementChannel statement_channel(channel, statements);
    TtcExecuteNoBindsRequest request;
    request.sql = "select 7 from dual";
    request.is_query = true;
    statement_channel.ExecuteNoBinds(handle, request);

    const auto decoded = statement_channel.ReceiveDecodedExecuteResponse(handle);
    CHECK(decoded.columns.size() == 1 && decoded.rows.size() == 1 && decoded.completion &&
          decoded.completion->cursor_id == 42 && DecodeOracleNumber(*decoded.rows[0][0]) == "7");
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
    try {
        ThrowTtcServerError(response);
    } catch (const ProtocolError &failure) {
        CHECK(failure.OracleCode() == 1017);
    }
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
        {"AUTH_VFR_DATA", "00112233445566778899AABBCCDDEEFF", O5LOGON_VERIFIER_12C},
        {"AUTH_SESSKEY", "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF", 0},
        {"AUTH_PBKDF2_CSK_SALT", "00112233445566778899AABBCCDDEEFF", 0},
        {"AUTH_PBKDF2_VGEN_COUNT", "4096", 0},
        {"AUTH_PBKDF2_SDER_COUNT", "3", 0}};
    auto decoded = DecodeTtcParameters(EncodeTtcParameters(parameters));
    CHECK(decoded.size() == parameters.size() && decoded[0].flags == O5LOGON_VERIFIER_12C);
    auto challenge = O5LogonChallengeFromParameters(decoded);
    CHECK(challenge.verifier_iterations == 4096 && challenge.combo_key_iterations == 3);
    decoded.push_back(decoded.front());
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { O5LogonChallengeFromParameters(decoded); });

    // The verifier type is read before any 12C field is required, so an
    // account on another verifier is reported as that, by type, rather than as
    // a malformed or incomplete challenge. An 11G challenge need not carry the
    // PBKDF2 fields at all.
    const auto message_for = [](const std::vector<TtcParameter> &challenge) {
        try {
            (void)O5LogonChallengeFromParameters(challenge);
        } catch (const ProtocolError &error) {
            CHECK(error.Kind() == ProtocolErrorKind::UNSUPPORTED);
            return std::string(error.what());
        }
        CHECK(false && "expected the verifier to be refused");
        return std::string();
    };
    const auto verifier_only = [](uint32_t type) {
        return std::vector<TtcParameter> {{"AUTH_VFR_DATA", "00112233445566778899AABBCCDDEEFF", type},
                                          {"AUTH_SESSKEY", std::string(96, 'A'), 0}};
    };
    auto message = message_for(verifier_only(O5LOGON_VERIFIER_11G_1));
    CHECK(message.find("11G password verifier (type 0xB152)") != std::string::npos);
    CHECK(message.find("12C verifier (type 0x4815)") != std::string::npos);
    CHECK(message_for(verifier_only(O5LOGON_VERIFIER_11G_2)).find("11G password verifier (type 0x1B25)") !=
          std::string::npos);
    const auto ten_g = message_for(verifier_only(O5LOGON_VERIFIER_10G));
    CHECK(ten_g.find("10G password verifier (type 0x0939)") != std::string::npos);
    CHECK(ten_g.find("SEC_CASE_SENSITIVE_LOGON") != std::string::npos);
    CHECK(message_for(verifier_only(0x1234)).find("unknown password verifier (type 0x1234)") != std::string::npos);
    // A flag of zero is not taken to mean 12C any more.
    CHECK(message_for(verifier_only(0)).find("type 0x0000") != std::string::npos);
    // Nothing from the challenge's values reaches the message.
    CHECK(message.find("00112233") == std::string::npos && message.find("AAAA") == std::string::npos);

    // A 12C challenge missing a field names the field, not its value.
    auto incomplete = parameters;
    incomplete.erase(incomplete.begin() + 2);
    try {
        (void)O5LogonChallengeFromParameters(incomplete);
        CHECK(false && "expected a missing field");
    } catch (const ProtocolError &error) {
        CHECK(error.Kind() == ProtocolErrorKind::MALFORMED);
        CHECK(std::string(error.what()).find("AUTH_PBKDF2_CSK_SALT") != std::string::npos);
    }
    ExpectError(ProtocolErrorKind::MALFORMED,
                [&] { (void)O5LogonChallengeFromParameters({{"AUTH_SESSKEY", "00", 0}}); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { DecodeTtcParameters({7, 0}); });

    // A parameter's declared size is an upper bound, not its length. A database
    // that is not AL32UTF8 announces a name sized for the character set this
    // client asked for — "AUTH_SESSKEY" as 36 bytes, three per character — and
    // then sends its twelve ASCII ones. Requiring the two to agree is what made
    // every such database fail before it could authenticate.
    ByteWriter oversized;
    oversized.WriteByte(TTC_MESSAGE_PARAMETER).WriteUB4(1);
    oversized.WriteUB4(36).WriteLengthPrefixed(std::vector<uint8_t>(12, 'A'));
    oversized.WriteUB4(96).WriteLengthPrefixed(std::vector<uint8_t>(32, 'B'));
    oversized.WriteUB4(0);
    const auto understated = DecodeTtcParameters(oversized.Take());
    CHECK(understated.size() == 1);
    CHECK(understated[0].key == std::string(12, 'A') && understated[0].value == std::string(32, 'B'));

    // Longer than declared is the other direction, and there the declaration
    // does bound the value: the reader refuses it rather than trusting it.
    ByteWriter overrun;
    overrun.WriteByte(TTC_MESSAGE_PARAMETER).WriteUB4(1);
    overrun.WriteUB4(4).WriteLengthPrefixed(std::vector<uint8_t>(4, 'A'));
    overrun.WriteUB4(2).WriteLengthPrefixed(std::vector<uint8_t>(6, 'B'));
    overrun.WriteUB4(0);
    const auto overrun_message = overrun.Take();
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { (void)DecodeTtcParameters(overrun_message); });
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

// A BIGINT column is read with TryDecodeOracleInteger and falls back to the
// decimal text only when that says no. Wherever it answers, the answer must be
// what parsing the text gives; wherever the text is not a whole int64, or the
// wire form is malformed, it must not answer at all.
static void TestOracleIntegerMatchesDecimalText() {
    const auto compare = [](const std::vector<uint8_t> &wire) {
        const auto direct = TryDecodeOracleInteger(wire);
        std::optional<int64_t> parsed;
        try {
            const auto text = DecodeOracleNumber(wire);
            if (text.find('.') == std::string::npos) {
                parsed = std::stoll(text);
            }
        } catch (const std::exception &) {
        }
        CHECK(direct == parsed);
    };
    for (const auto *text : {"0", "1", "-1", "99", "100", "-100", "101", "9999999999", "10000000000",
                             "123456789012345678", "9223372036854775807", "-9223372036854775808",
                             "9223372036854775808", "-9223372036854775809", "1e18", "1e19", "-1e18", "1e30",
                             "-1e30", "1.5", "-1.5", "0.5", "-0.5", "100.01", "12345678901234567890123",
                             "9223372036854775800", "-9223372036854775700", "1e-30"}) {
        compare(EncodeOracleNumber(text));
    }
    std::mt19937_64 random(20261021);
    for (size_t index = 0; index < 200000; index++) {
        const auto bits = random();
        const auto shift = static_cast<unsigned>(random() % 64U);
        auto value = static_cast<int64_t>(bits >> shift);
        if ((random() & 1U) != 0) {
            value = -value;
        }
        compare(EncodeOracleNumber(std::to_string(value)));
        if (index % 4 == 0) {
            compare(EncodeOracleNumber(std::to_string(value) + "." + std::to_string(random() % 1000U + 1U)));
        }
    }
    // Malformed forms: the string path reports them, so this must not answer.
    for (const auto &wire : std::vector<std::vector<uint8_t>> {
             {}, {0xC1}, {0xC1, 0x00}, {0xC1, 0x65}, {0xC1, 0x02, 0x01}, {0x3E, 0x66}, std::vector<uint8_t>(22, 0xC1)}) {
        CHECK(!TryDecodeOracleInteger(wire));
        compare(wire);
    }
}

// The fragment loop hands the decoder a growing response and expects it to
// resume after the last row it finished. Whatever the split points, the result
// must be exactly what one pass over the joined response produces.
static void TestFetchResponseDecoderResumes() {
    const std::vector<OracleColumn> columns = {{"A", 1, 16, 0, 0, true}, {"B", 1, 16, 0, 0, true},
                                               {"C", 1, 16, 0, 0, true}};
    const TtcRowData preceding = {std::vector<uint8_t> {'p'}, std::vector<uint8_t> {'q'}, std::nullopt};
    ByteWriter response;
    // A row header selecting column A, its ROW_DATA, then full rows,
    // continuations in both captured count forms.
    response.WriteByte(6).WriteByte(0).WriteUB2(0).WriteUB4(0).WriteUB4(0).WriteUB2(0);
    response.WriteUB4(1).WriteLengthPrefixed(std::vector<uint8_t> {0x01}).WriteUB4(0);
    response.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(std::vector<uint8_t> {'a', '0'});
    for (uint8_t row = 1; row <= 6; row++) {
        response.WriteByte(TTC_MESSAGE_ROW_DATA)
            .WriteLengthPrefixed(std::vector<uint8_t> {'a', static_cast<uint8_t>('0' + row)})
            .WriteLengthPrefixed(std::vector<uint8_t>(row, 'b'))
            .WriteLengthPrefixed(std::nullopt);
        response.WriteByte(21).WriteUInt16LE(1).WriteByte(0x04);
        response.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(std::vector<uint8_t> {'c', row});
        response.WriteByte(21).WriteUB2(2).WriteByte(0x03);
        response.WriteByte(TTC_MESSAGE_ROW_DATA)
            .WriteLengthPrefixed(std::vector<uint8_t> {'x'})
            .WriteLengthPrefixed(std::nullopt);
    }
    // An all-zero bit vector: the next row repeats the previous one.
    response.WriteByte(6).WriteByte(0).WriteUB2(0).WriteUB4(0).WriteUB4(0).WriteUB2(0);
    response.WriteUB4(1).WriteLengthPrefixed(std::vector<uint8_t> {0x00}).WriteUB4(0);
    response.WriteByte(TTC_MESSAGE_ROW_DATA);
    // A row header still waiting for its ROW_DATA while a continuation row
    // decodes: the rows in between are not kept until the header is answered.
    response.WriteByte(6).WriteByte(0).WriteUB2(0).WriteUB4(0).WriteUB4(0).WriteUB2(0);
    response.WriteUB4(1).WriteLengthPrefixed(std::vector<uint8_t> {0x02}).WriteUB4(0);
    response.WriteByte(21).WriteUInt16LE(1).WriteByte(0x01);
    response.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(std::vector<uint8_t> {'h'});
    response.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(std::vector<uint8_t> {'s'});
    response.WriteByte(9).WriteUB4(0).WriteUB2(0);
    const auto &bytes = response.Data();

    const auto expected = DecodeTtcFetchResponse(bytes, columns, 6, preceding);
    CHECK(expected.completed && expected.bytes_consumed == bytes.size() && expected.rows.size() == 22 &&
           expected.used_row_header_selection && expected.used_row_continuation);
    CHECK(expected.rows[0][0].value() == std::vector<uint8_t>({'a', '0'}) &&
           expected.rows[0][1].value() == std::vector<uint8_t>({'q'}) && !expected.rows[0][2]);
    CHECK(expected.rows[19] == expected.rows[18] && expected.rows[18][0].value() == std::vector<uint8_t>({'x'}));
    CHECK(expected.rows[20][0].value() == std::vector<uint8_t>({'h'}) && !expected.rows[20][1] &&
           expected.rows[21][1].value() == std::vector<uint8_t>({'s'}) &&
           expected.rows[21][2].value() == std::vector<uint8_t>({'c', 6}));

    for (size_t step = 1; step <= 17; step++) {
        TtcFetchResponseDecoder decoder(columns, 6, preceding);
        bool complete = false;
        for (size_t size = (std::min)(step, bytes.size());; size = (std::min)(size + step, bytes.size())) {
            const std::vector<uint8_t> received(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(size));
            try {
                complete = decoder.Decode(received);
            } catch (const ProtocolError &error) {
                CHECK(error.Kind() == ProtocolErrorKind::TRUNCATED);
            }
            if (complete || size == bytes.size()) {
                break;
            }
        }
        CHECK(complete);
        const auto resumed = decoder.Take();
        CHECK(resumed.rows == expected.rows && resumed.last_row == expected.last_row &&
               resumed.bytes_consumed == expected.bytes_consumed && resumed.completed &&
               resumed.exhausted == expected.exhausted &&
               resumed.used_row_header_selection == expected.used_row_header_selection &&
               resumed.used_row_continuation == expected.used_row_continuation);
    }

    // A response cannot become shorter than what was already decoded from it.
    TtcFetchResponseDecoder shrinking(columns, 6, preceding);
    const std::vector<uint8_t> most(bytes.begin(), bytes.end() - 1);
    try {
        (void)shrinking.Decode(most);
    } catch (const ProtocolError &error) {
        CHECK(error.Kind() == ProtocolErrorKind::TRUNCATED);
    }
    ExpectError(ProtocolErrorKind::INVALID_STATE, [&] { (void)shrinking.Decode({bytes.front()}); });

    // Bytes that are wrong after a kept row are still wrong, not truncated.
    ByteWriter unknown;
    unknown.WriteByte(TTC_MESSAGE_ROW_DATA)
        .WriteLengthPrefixed(std::vector<uint8_t> {'k'})
        .WriteLengthPrefixed(std::nullopt)
        .WriteLengthPrefixed(std::nullopt);
    unknown.WriteByte(0xEE);
    ExpectError(ProtocolErrorKind::MALFORMED, [&] {
        TtcFetchResponseDecoder decoder(columns, 6, preceding);
        (void)decoder.Decode(unknown.Data());
    });
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
    // 873 is AL32UTF8; the negotiation accepts whatever the server reports,
    // which is checked below with a database character set that is not UTF-8.
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

    // The character set the server reports is its own, not a negotiated one:
    // this client asks for AL32UTF8 in TTIDTY and Oracle converts on its side.
    // Requiring 873 here refused every database in another character set before
    // it could authenticate, which is how a TR8MSWIN1254 database surfaced as
    // "Oracle server selected an unsupported character set".
    ByteWriter turkish_server;
    turkish_server.WriteByte(TTC_MESSAGE_PROTOCOL).WriteByte(6).WriteByte(0).WriteNullTerminated("Oracle Database");
    turkish_server.WriteUInt16LE(873 + 1).WriteByte(0).WriteUInt16LE(0).WriteUInt16BE(0);
    turkish_server.WriteByte(0).WriteByte(0);
    std::vector<uint8_t> turkish_inbound;
    for (const auto &packet : EncodeTnsDataPackets(turkish_server.Take(), true, 64)) {
        turkish_inbound.insert(turkish_inbound.end(), packet.begin(), packet.end());
    }
    for (const auto &packet : EncodeTnsDataPackets(data_type_response, true, 64)) {
        turkish_inbound.insert(turkish_inbound.end(), packet.begin(), packet.end());
    }
    FragmentedStream turkish_stream(turkish_inbound, 5);
    TnsPacketStream turkish_packets(turkish_stream, true, 64);
    TtcChannel turkish_channel(turkish_packets, 64);
    const auto turkish_info = RunTtcNegotiation(turkish_channel, options);
    CHECK(turkish_info.charset_id == 874);
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
// A throwaway certificate and key, used both by the local TLS server below and
// by the wallet tests. It is pure OpenSSL with no sockets in it, so it lives
// outside the !_WIN32 guard: the server needs loopback and does not build on
// Windows, while the wallet tests do build there and need an identity.
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

} // namespace local_tls

#if !defined(_WIN32)
// Test servers write to clients that may already have given up — a client
// that rejects a certificate, or one that stopped on its connect budget — and
// that write must not raise SIGPIPE. Blocking the signal in the server thread
// alone proved not to be enough on macOS, where CTest runs saw it delivered
// anyway; SO_NOSIGPIPE on the accepted socket (macOS) and MSG_NOSIGNAL on each
// send (Linux) stop it at the socket. Only the test's own server sockets get
// this: the client's protection is what TestWriteToClosedPeerDoesNotKillTheProcess
// checks, and none of this touches it.
static void SuppressSigPipeOnSocket(int socket_fd) {
#if defined(SO_NOSIGPIPE)
    int one = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#else
    (void)socket_fd;
#endif
}

#if defined(MSG_NOSIGNAL)
static constexpr int TEST_SEND_FLAGS = MSG_NOSIGNAL;
#else
static constexpr int TEST_SEND_FLAGS = 0;
#endif

// A local TLS server, so certificate verification can be tested against cases
// no live endpoint offers: an expired certificate, and the wallet-free path
// where the client presents nothing and trusts an explicit CA. Everything is
// loopback and in-memory; nothing here talks to Oracle.
namespace local_tls {


// Accepts exactly one connection, completes the handshake, and closes. The
// client under test only needs the handshake's verdict.
class Server {
public:
    explicit Server(const Identity &identity, bool reset_read_p = false, bool delayed_read_p = false)
        : reset_read(reset_read_p), delayed_read(delayed_read_p) {
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

    void ResetReadAndWait() {
        release_read.store(true);
        if (worker.joinable()) { worker.join(); }
    }
    void ReleaseRead() { release_read.store(true); }

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
        SuppressSigPipeOnSocket(accepted);
        auto *ssl = SSL_new(context);
        if (ssl) {
            SSL_set_fd(ssl, accepted);
            // A rejected certificate makes this fail, which is the expected
            // outcome for three of the four cases and not an error here.
            const auto accepted_tls = SSL_accept(ssl);
            if (accepted_tls == 1 && (reset_read || delayed_read)) {
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
                while (!release_read.load() && std::chrono::steady_clock::now() < deadline) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
                if (delayed_read) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    const uint8_t byte = 0x5a;
                    (void)SSL_write(ssl, &byte, 1);
                } else {
                    linger reset {1,0}; setsockopt(accepted, SOL_SOCKET, SO_LINGER, &reset, sizeof(reset));
                }
            }
            SSL_free(ssl);
        }
        close(accepted);
    }

    SSL_CTX *context = nullptr;
    int listener = -1;
    uint16_t port = 0;
    std::thread worker;
    bool reset_read = false;
    bool delayed_read = false;
    std::atomic<bool> release_read {false};
};

} // namespace local_tls

static void TestTlsReadFailureDoesNotKillTheProcess() {
    const std::string name = "oracle-scanner.test";
    auto identity = local_tls::MakeIdentity(name, -3600, 3600);
    local_tls::Server server(identity, true);
    TlsConfiguration tls; tls.server_name = name; tls.ca_pem_contents = identity.certificate_pem;
    auto stream = OpenSslByteStream::Connect("127.0.0.1", server.Port(), 5, 5, true, tls);
    server.ResetReadAndWait();
    bool failed = false;
    uint8_t byte;
    try { failed = stream->Read(&byte, 1) == 0; }
    catch (const ProtocolError &error) { failed = error.Kind() == ProtocolErrorKind::TRUNCATED; }
    CHECK(failed);
    stream->Close();
}

static void TestTlsReadIgnoresUnrelatedErrorQueue() {
    const std::string name = "oracle-scanner.test";
    auto identity = local_tls::MakeIdentity(name, -3600, 3600);
    local_tls::Server server(identity, false, true);
    TlsConfiguration tls; tls.server_name = name; tls.ca_pem_contents = identity.certificate_pem;
    auto stream = OpenSslByteStream::Connect("127.0.0.1", server.Port(), 5, 5, true, tls);
    // Represents an unrelated failed BIO on the same caller thread. A healthy
    // nonblocking TLS read must still wait for the delayed byte, not fail with
    // this stale EPIPE when SSL_get_error determines WANT_READ.
    ERR_raise(ERR_LIB_SYS, EPIPE);
    server.ReleaseRead();
    uint8_t byte = 0;
    CHECK(stream->Read(&byte, 1) == 1 && byte == 0x5a);
    stream->Close();
}

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
        ExpectConnectFailure(ConnectFailure::TLS_VERIFICATION, [&] { (void)OpenSslByteStream::Connect("127.0.0.1", server.Port(), 5, 5, true, tls); });
    }

    // A name the certificate does not carry.
    {
        local_tls::Server server(valid);
        TlsConfiguration tls;
        tls.server_name = "oracle-scanner.invalid";
        tls.ca_pem_contents = valid.certificate_pem;
        ExpectConnectFailure(ConnectFailure::TLS_VERIFICATION, [&] { (void)OpenSslByteStream::Connect("127.0.0.1", server.Port(), 5, 5, true, tls); });
    }

    // A CA that did not sign what the server presented, even though both carry
    // the same subject.
    {
        local_tls::Server server(valid);
        TlsConfiguration tls;
        tls.server_name = server_name;
        tls.ca_pem_contents = other.certificate_pem;
        ExpectConnectFailure(ConnectFailure::TLS_VERIFICATION, [&] { (void)OpenSslByteStream::Connect("127.0.0.1", server.Port(), 5, 5, true, tls); });
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
        ExpectConnectFailure(ConnectFailure::TLS_VERIFICATION, [&] { (void)OpenSslByteStream::Connect("127.0.0.1", server.Port(), 5, 5, true, tls); });
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
        {"AUTH_VFR_DATA", challenge.verifier_data_hex, O5LOGON_VERIFIER_12C},
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
    // A DESCRIPTION-level key this client does not know is refused by name
    // rather than skipped, since skipping it could drop a setting the user
    // expects to work. A missing CONNECT_DATA is still malformed.
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [] {
        ParseConnectDescriptor("(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=x)(PORT=1))(SERVICE_NAME=x))");
    });
    ExpectError(ProtocolErrorKind::MALFORMED,
                [] { ParseConnectDescriptor("(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=x)(PORT=1)))"); });
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

    // The decoded fields are UTC; the wall clock adds the offset back, across
    // a day, a month, a year and a leap day, in both directions.
    const auto wall = [](OracleDateTime utc) {
        const auto local = OracleZonedWallClock(utc);
        return std::to_string(local.year) + "-" + std::to_string(local.month) + "-" + std::to_string(local.day) + " " +
               std::to_string(local.hour) + ":" + std::to_string(local.minute) + ":" + std::to_string(local.second);
    };
    CHECK(wall(timestamp) == "2026-8-18 16:34:56");
    CHECK(wall({2026, 12, 31, 23, 30, 0, 0, 90, true}) == "2027-1-1 1:0:0");
    CHECK(wall({2024, 3, 1, 2, 15, 0, 0, -180, true}) == "2024-2-29 23:15:0");
    CHECK(wall({2025, 1, 1, 0, 0, 0, 0, -1, true}) == "2024-12-31 23:59:0");
    CHECK(wall({2026, 4, 30, 21, 45, 9, 0, 135, true}) == "2026-5-1 0:0:9");
    // Without an offset there is nothing to add, and nothing is.
    CHECK(wall({2026, 4, 30, 21, 45, 9, 0, 0, false}) == "2026-4-30 21:45:9");

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
    OracleCallRequest function_request {OracleCallableKind::FUNCTION, "app.answer", return_bind, {}, {}, {}};
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

// A composite is a sequence of validated DML statements in one anonymous
// block. What has to hold: the statements in order, each followed by its own
// exact row-count check; no transaction control anywhere in the block; one
// bind per name however many statements use it, sent in the block's
// first-occurrence order; and nothing that is not one plain DML statement.
static void TestDmlCompositeBlock() {
    const std::vector<OracleBind> arguments = {{"b", 1, BindDirection::BIND_IN, std::vector<uint8_t> {'x'}},
                                               {"a", 1, BindDirection::BIND_IN, std::vector<uint8_t> {'y'}}};
    OracleCallRequest request;
    request.kind = OracleCallableKind::DML_COMPOSITE;
    request.arguments = arguments;
    request.dml_operations = {{"INSERT INTO T (V) VALUES (:a)", 1}, {"UPDATE T SET V = :b WHERE V = :a -- tail", 0}};
    const auto block = BuildOracleCallBlock(request);
    CHECK(block == "BEGIN\n"
                   "INSERT INTO T (V) VALUES (:a)\n;\n"
                   "IF SQL%ROWCOUNT <> 1 THEN RAISE_APPLICATION_ERROR(-20906, "
                   "'DML composite operation 1 affected row count mismatch'); END IF;\n"
                   "UPDATE T SET V = :b WHERE V = :a -- tail\n;\n"
                   "IF SQL%ROWCOUNT <> 0 THEN RAISE_APPLICATION_ERROR(-20906, "
                   "'DML composite operation 2 affected row count mismatch'); END IF;\n"
                   "END;");
    // :a first, though the caller listed b first: PL/SQL binds by first use.
    const auto ordered = OrderOracleStatementBinds(block, arguments, OracleBindUse::CALL);
    CHECK(ordered.size() == 2 && ordered[0].name == "a" && ordered[1].name == "b");
    // Positional binds name themselves 1, 2, ... and work the same way.
    OracleCallRequest positional = request;
    positional.arguments = {{"1", 2, BindDirection::BIND_IN, std::vector<uint8_t> {0xc1, 0x02}}};
    positional.dml_operations = {{"DELETE FROM T WHERE ID = :1", 1}, {"UPDATE U SET N = N + 1 WHERE ID = :1", 1}};
    CHECK(BuildOracleCallBlock(positional).find("WHERE ID = :1\n;\n") != std::string::npos);

    const auto refused = [&](ProtocolErrorKind kind, const std::function<void(OracleCallRequest &)> &change) {
        auto bad = request;
        change(bad);
        ExpectError(kind, [&] { BuildOracleCallBlock(bad); });
    };
    // Not one plain DML statement: transaction control, DDL, PL/SQL, a query,
    // a second statement after a terminator, MERGE.
    for (const auto *sql : {"COMMIT", "ROLLBACK", "SAVEPOINT s", "CREATE TABLE T2 (ID NUMBER)", "BEGIN NULL; END;",
                            "SELECT * FROM T", "UPDATE T SET V = :a; COMMIT", "UPDATE T SET V = :a;",
                            "MERGE INTO T USING DUAL ON (1 = 1) WHEN MATCHED THEN UPDATE SET V = :a",
                            "UPDATE T SET V = :a /* unterminated", "UPDATE T SET V = 'unterminated"}) {
        refused(ProtocolErrorKind::MALFORMED, [&](OracleCallRequest &bad) { bad.dml_operations[0].sql = sql; });
    }
    // A placeholder nothing binds, and a bind nothing uses.
    refused(ProtocolErrorKind::MALFORMED,
            [](OracleCallRequest &bad) { bad.dml_operations[0].sql = "UPDATE T SET V = :missing"; });
    refused(ProtocolErrorKind::MALFORMED, [](OracleCallRequest &bad) {
        bad.arguments.push_back({"unused", 1, BindDirection::BIND_IN, std::vector<uint8_t> {'z'}});
    });
    // Input binds only, each name once.
    refused(ProtocolErrorKind::MALFORMED,
            [](OracleCallRequest &bad) { bad.arguments[0].direction = BindDirection::BIND_OUT; });
    refused(ProtocolErrorKind::MALFORMED, [](OracleCallRequest &bad) { bad.arguments[1].name = "B"; });
    // A composite names no callable and returns nothing; a callable carries no DML.
    refused(ProtocolErrorKind::MALFORMED, [](OracleCallRequest &bad) { bad.qualified_name = "APP.PROC"; });
    refused(ProtocolErrorKind::MALFORMED, [](OracleCallRequest &bad) {
        bad.return_bind = OracleBind {"r", 2, BindDirection::BIND_OUT, std::nullopt};
    });
    refused(ProtocolErrorKind::MALFORMED, [](OracleCallRequest &bad) { bad.dml_operations.clear(); });
    refused(ProtocolErrorKind::MALFORMED, [](OracleCallRequest &bad) {
        bad.kind = OracleCallableKind::PROCEDURE;
        bad.qualified_name = "APP.PROC";
        bad.arguments.clear();
    });
    // The bounds, each just past its limit.
    refused(ProtocolErrorKind::LIMIT_EXCEEDED, [](OracleCallRequest &bad) {
        bad.dml_operations.resize(ORACLE_DML_COMPOSITE_MAX_OPERATIONS + 1, bad.dml_operations[0]);
    });
    refused(ProtocolErrorKind::LIMIT_EXCEEDED, [](OracleCallRequest &bad) {
        bad.dml_operations[0].expected_rows = ORACLE_DML_COMPOSITE_MAX_EXPECTED_ROWS + 1;
    });
    refused(ProtocolErrorKind::LIMIT_EXCEEDED, [](OracleCallRequest &bad) {
        bad.dml_operations[0].sql = "UPDATE T SET V = :a WHERE '" +
                                    std::string(ORACLE_DML_COMPOSITE_MAX_SQL_BYTES, 'x') + "' IS NOT NULL";
    });
    refused(ProtocolErrorKind::LIMIT_EXCEEDED, [](OracleCallRequest &bad) {
        bad.arguments[0].value = std::vector<uint8_t>(ORACLE_DML_COMPOSITE_MAX_PAYLOAD_BYTES, 'x');
    });
    refused(ProtocolErrorKind::LIMIT_EXCEEDED, [](OracleCallRequest &bad) {
        bad.arguments.clear();
        std::string sql = "INSERT INTO T VALUES (";
        for (size_t index = 0; index <= ORACLE_DML_COMPOSITE_MAX_BINDS; index++) {
            const auto name = "p" + std::to_string(index);
            bad.arguments.push_back({name, 1, BindDirection::BIND_IN, std::vector<uint8_t> {'v'}});
            sql += (index == 0 ? ":" : ", :") + name;
        }
        bad.dml_operations = {{sql + ")", 1}};
    });
    // Exactly at the limits is accepted.
    auto at_limit = request;
    at_limit.dml_operations.resize(ORACLE_DML_COMPOSITE_MAX_OPERATIONS, request.dml_operations[0]);
    at_limit.dml_operations.back().expected_rows = ORACLE_DML_COMPOSITE_MAX_EXPECTED_ROWS;
    at_limit.dml_operations.back().sql = "UPDATE T SET V = :b WHERE V = :a";
    (void)BuildOracleCallBlock(at_limit);
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
    ValidateOracleAdmin("CREATE TABLE admin_probe (label VARCHAR2(100) DEFAULT 'x;y')");
    ValidateOracleAdmin("GRANT CREATE SESSION TO admin_probe");
    ExpectError(ProtocolErrorKind::MALFORMED, [] { ValidateOracleAdmin("COMMIT"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { ValidateOracleAdmin("CREATE TABLE x(id NUMBER); DROP TABLE y"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { ValidateOracleAdmin("CREATE TABLE x AS SELECT :1 FROM dual"); });
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
    OracleCallRequest call {OracleCallableKind::PROCEDURE, "app.ping", std::nullopt, {}, {}, {}};
    session.Call(call);
    CHECK(inner->queries == 1 && inner->executes == 1 && inner->batches == 1 && inner->calls == 1);
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { session.Execute("select * from invoices where id = :id", binds); });
    CHECK(inner->executes == 1);
    // A composite reaches the session only as a block it would build itself.
    OracleCallRequest composite;
    composite.kind = OracleCallableKind::DML_COMPOSITE;
    composite.arguments = binds;
    composite.dml_operations = {{"delete from invoices where id = :id", 1}};
    session.Call(composite);
    composite.dml_operations.push_back({"commit", 0});
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { session.Call(composite); });
    CHECK(inner->calls == 2);
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
    const auto dml_split = dml_response.Data().size() - 1;
    const auto dml_first = std::vector<uint8_t>(dml_response.Data().begin(),
                                                dml_response.Data().begin() + static_cast<std::ptrdiff_t>(dml_split));
    const auto dml_last = std::vector<uint8_t>(dml_response.Data().begin() + static_cast<std::ptrdiff_t>(dml_split),
                                               dml_response.Data().end());
    for (const auto &packet : EncodeTnsDataPackets(dml_first, true, 512, 0)) {
        dml_inbound.insert(dml_inbound.end(), packet.begin(), packet.end());
    }
    for (const auto &packet : EncodeTnsDataPackets(dml_last, true, 512, 0)) {
        dml_inbound.insert(dml_inbound.end(), packet.begin(), packet.end());
    }
    FragmentedStream dml_stream(dml_inbound, 3);
    TnsPacketStream dml_packets(dml_stream, true, 512);
    TtcChannel dml_channel(dml_packets, 512);
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

    std::vector<uint8_t> call_inbound;
    for (const auto &packet : EncodeTnsDataPackets(dml_first, true, 512, 0)) {
        call_inbound.insert(call_inbound.end(), packet.begin(), packet.end());
    }
    for (const auto &packet : EncodeTnsDataPackets(dml_last, true, 512, 0)) {
        call_inbound.insert(call_inbound.end(), packet.begin(), packet.end());
    }
    FragmentedStream call_stream(call_inbound, 3);
    TnsPacketStream call_packets(call_stream, true, 512);
    TtcChannel call_channel(call_packets, 512);
    OracleStatementRegistry call_registry;
    const auto call_handle = call_registry.Open(OracleSqlKind::PLSQL);
    TtcStatementChannel call_statements(call_channel, call_registry);
    TtcExecuteNoBindsRequest call_request;
    call_request.sql = "BEGIN NULL; END;";
    call_request.is_plsql = true;
    call_statements.ExecuteNoBinds(call_handle, call_request);
    const auto call_response = call_statements.ReceiveCallResponse(call_handle, {}, 12, 12);
    CHECK(call_response.completed && call_response.completion && call_response.completion->error_number == 0);
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

        // Only meaningful for a wallet whose key is actually encrypted. A
        // wallet ZIP that carries cwallet.sso is opened auto-login and needs no
        // password at all, so a "wrong" one changes nothing — asserting a
        // failure there aborted this stage before the checks below ever ran.
        if (!config.wallet_password.empty()) {
            auto wrong_wallet_password = tls;
            wrong_wallet_password.client_pem_password += "-wrong";
            ExpectProtocolError([&] { (void)TnsClientConnection::Connect(config, wrong_wallet_password); });
        }

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
    // The server reports its own character set, which is not required to be
    // AL32UTF8: this lane runs against TR8MSWIN1254 databases too.
    CHECK(protocol.charset_id != 0);
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
        const auto decoded = channel.ReceiveDecodedExecuteResponse(handle, connection->TtcFieldVersion(),
                                        connection->TtcServerFieldVersion());
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
        const auto first_response = channel.ReceiveDecodedExecuteResponse(first, connection->TtcFieldVersion(),
                                           connection->TtcServerFieldVersion());
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
        const auto next_response = channel.ReceiveDecodedExecuteResponse(next, connection->TtcFieldVersion(),
                                           connection->TtcServerFieldVersion());
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
        const auto verification_response = channel.ReceiveDecodedExecuteResponse(verification, connection->TtcFieldVersion(),
                                             connection->TtcServerFieldVersion());
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
        const auto initial = channel.ReceiveDecodedExecuteResponse(handle, connection->TtcFieldVersion(),
                                       connection->TtcServerFieldVersion());
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

    // Keep another unblocked thread alive: on macOS a socket SIGPIPE may reach
    // it even while the writing thread blocks the signal. Continue after the
    // first ECONNRESET so a subsequent write reaches EPIPE too.
    std::atomic<bool> done {false};
    std::thread observer([&] {
        while (!done.load()) { std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    });
    const std::vector<uint8_t> payload(64, 0x5a);
    bool reported = false;
    for (int attempt = 0; attempt < 8; attempt++) {
        try {
            stream->Write(payload.data(), payload.size());
        } catch (const ProtocolError &error) {
            reported = error.Kind() == ProtocolErrorKind::INVALID_STATE ||
                       error.Kind() == ProtocolErrorKind::TRUNCATED;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    done = true;
    observer.join();
    CHECK(reported);
    (void)reported;
    stream->Close();
}

static void IgnoreSignal(int) {
}

// A read waits for the server, and two ordinary things must not end that wait
// early. A signal that interrupts it (a profiler, a terminal resize, a language
// runtime) is not a timeout: the wait used to report one, and the statement and
// its session were lost. And a process holding many files hands out descriptors
// past FD_SETSIZE, where select() cannot wait at all and FD_SET writes past the
// end of its set. Here the socket's descriptor is pushed past 1100 and the
// reading thread is signalled, without SA_RESTART, while the reply is late.
static void TestReadWaitsThroughSignalsAndHighDescriptors() {
    rlimit limit {};
    CHECK(getrlimit(RLIMIT_NOFILE, &limit) == 0);
    const rlim_t wanted = 1200;
    if (limit.rlim_cur < wanted && (limit.rlim_max == RLIM_INFINITY || limit.rlim_max >= wanted)) {
        limit.rlim_cur = wanted;
        CHECK(setrlimit(RLIMIT_NOFILE, &limit) == 0);
    }
    std::vector<int> filler;
    const int null_file = open("/dev/null", O_RDONLY);
    CHECK(null_file >= 0);
    while (true) {
        const int duplicate = dup(null_file);
        if (duplicate < 0 || duplicate >= 1100) {
            if (duplicate >= 0) {
                close(duplicate);
            }
            break;
        }
        filler.push_back(duplicate);
    }

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
    CHECK(listen(listener, 1) == 0);
    socklen_t address_size = sizeof(address);
    CHECK(getsockname(listener, reinterpret_cast<sockaddr *>(&address), &address_size) == 0);
    const auto port = ntohs(address.sin_port);

    // Answers one byte, late.
    std::atomic<bool> finished {false};
    std::thread server([listener, &finished] {
        const auto accepted = accept(listener, nullptr, nullptr);
        if (accepted < 0) {
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        const uint8_t reply = 0x2a;
        (void)send(accepted, &reply, 1, 0);
        while (!finished.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        close(accepted);
    });

    auto stream = OpenSslByteStream::Connect("127.0.0.1", port, 5, 5, false);
    CHECK(stream != nullptr);
    const bool high_descriptor = !filler.empty() && filler.back() >= 1099;
    if (!high_descriptor) {
        std::fprintf(stderr, "note: descriptor limit too low to place the socket past FD_SETSIZE; signals only\n");
    }

    struct sigaction action {};
    struct sigaction previous {};
    action.sa_handler = IgnoreSignal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    CHECK(sigaction(SIGUSR1, &action, &previous) == 0);
    const auto reader = pthread_self();
    std::thread signaller([reader] {
        for (int round = 0; round < 6; round++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            pthread_kill(reader, SIGUSR1);
        }
    });

    uint8_t received = 0;
    size_t count = 0;
    std::string failure;
    try {
        count = stream->Read(&received, 1);
    } catch (const ProtocolError &error) {
        failure = error.what();
    }
    signaller.join();
    CHECK(failure.empty());
    CHECK(count == 1 && received == 0x2a);

    finished = true;
    stream->Close();
    server.join();
    close(listener);
    sigaction(SIGUSR1, &previous, nullptr);
    for (const auto descriptor : filler) {
        close(descriptor);
    }
    close(null_file);
}
#endif // !_WIN32

static void TestConnectRunsThroughTheTransportSeam() {
    const std::string redirect_descriptor =
        "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.0.9)(PORT=1522))(CONNECT_DATA=(SERVICE_NAME=moved)))";
    // A UB2 length, then the data.
    std::vector<uint8_t> redirect_payload {static_cast<uint8_t>(redirect_descriptor.size() >> 8U),
                                           static_cast<uint8_t>(redirect_descriptor.size())};
    redirect_payload.insert(redirect_payload.end(), redirect_descriptor.begin(), redirect_descriptor.end());

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

    // Each attempt wrote a CONNECT packet. The redirect carried no reconnect
    // data, so the second CONNECT is rebuilt for the new address with the
    // original service — the listener's SERVICE_NAME=moved sits in the address
    // part, which names where to go, not what to ask for.
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
    const std::string second_text(second.begin(), second.end());
    CHECK(second_text.find("(HOST=10.0.0.9)(PORT=1522)") != std::string::npos);
    CHECK(second_text.find("(SERVICE_NAME=svc)") != std::string::npos);
    // The re-CONNECT carries the redirect flag; the first CONNECT does not.
    CHECK(written[0][5] == 0x00 && second[5] == TNS_PACKET_FLAG_REDIRECT);
    // And O5LOGON will still name what the user configured.
    CHECK(connection->AuthConnectString().find("(HOST=first.example)") != std::string::npos);
    CHECK(connection->AuthConnectString().find("(CID=") == std::string::npos);
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

// ---------------------------------------------------------------------------
// Multi-address connects, SCAN names, listener redirects and failover.
//
// Every packet below is SYNTHETIC: built here from the field layouts that
// python-oracledb Thin (commit 4a6d3b39, connect.pyx and connection.pyx) and
// go-ora (commit 360b4b7a, network/redirect_packet.go, refuse_packet.go and
// session.go) read and write. None is a capture, which is the limit of what
// these tests prove.
// ---------------------------------------------------------------------------

// REDIRECT: a UB2 length, then the data inline — or, when `inline_data` is
// false, nothing inline and the data in one DATA packet after two zero data
// flag bytes, which is the form go-ora reads when the REDIRECT is empty.
static std::vector<uint8_t> RedirectPacketBytes(const std::string &data, uint8_t flags = 0, bool inline_data = true) {
    std::vector<uint8_t> payload {static_cast<uint8_t>(data.size() >> 8U), static_cast<uint8_t>(data.size())};
    if (inline_data) {
        payload.insert(payload.end(), data.begin(), data.end());
        return EncodeTnsPacket(TnsPacketType::REDIRECT, flags, payload, false);
    }
    auto wire = EncodeTnsPacket(TnsPacketType::REDIRECT, flags, payload, false);
    std::vector<uint8_t> continuation {0x00, 0x00};
    continuation.insert(continuation.end(), data.begin(), data.end());
    const auto data_packet = EncodeTnsPacket(TnsPacketType::DATA, 0, continuation, false);
    wire.insert(wire.end(), data_packet.begin(), data_packet.end());
    return wire;
}

// REFUSE: user reason, system reason, a UB2 message length, the message. The
// message is the listener's descriptor-shaped text with (ERR=...).
static std::vector<uint8_t> RefusePacketBytes(uint32_t oracle_error) {
    const std::string message = "(DESCRIPTION=(TMP=)(VSNNUM=0)(ERR=" + std::to_string(oracle_error) +
                                ")(ERROR_STACK=(ERROR=(CODE=" + std::to_string(oracle_error) + ")(EMFI=4))))";
    std::vector<uint8_t> payload {0x22, 0x00, static_cast<uint8_t>(message.size() >> 8U),
                                  static_cast<uint8_t>(message.size())};
    payload.insert(payload.end(), message.begin(), message.end());
    return EncodeTnsPacket(TnsPacketType::REFUSE, 0, payload, false);
}

static std::vector<uint8_t> Bytes(const std::string &text) {
    return {text.begin(), text.end()};
}

static void TestRedirectDataSplitting() {
    // Address only.
    auto redirect = ParseTnsRedirectData(Bytes("(ADDRESS=(PROTOCOL=TCP)(HOST=node1)(PORT=1521))"), 0);
    CHECK(redirect.address == "(ADDRESS=(PROTOCOL=TCP)(HOST=node1)(PORT=1521))" && redirect.reconnect_data.empty());

    // Address, NUL, reconnect data — with and without the 0x02 flag, since
    // python-oracledb splits on the NUL regardless.
    auto with_reconnect = Bytes("(ADDRESS=(PROTOCOL=TCP)(HOST=node1)(PORT=1521))");
    with_reconnect.push_back(0);
    const std::string reconnect = "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=svc)(INSTANCE_NAME=inst1)))";
    with_reconnect.insert(with_reconnect.end(), reconnect.begin(), reconnect.end());
    for (const uint8_t flags : {uint8_t(0), TNS_REDIRECT_FLAG_HAS_RECONNECT_DATA}) {
        redirect = ParseTnsRedirectData(with_reconnect, flags);
        CHECK(redirect.address == "(ADDRESS=(PROTOCOL=TCP)(HOST=node1)(PORT=1521))");
        CHECK(redirect.reconnect_data == reconnect);
    }

    // Trailing NUL padding, and CR/LF inside the text, are tolerated.
    auto padded = with_reconnect;
    padded.push_back(0);
    padded.push_back(0);
    CHECK(ParseTnsRedirectData(padded, 0).reconnect_data == reconnect);
    CHECK(ParseTnsRedirectData(Bytes("\r\n(ADDRESS=(HOST=node1)\r\n(PORT=1521))\r\n"), 0).address ==
          "(ADDRESS=(HOST=node1)  (PORT=1521))");

    // A NUL with nothing after it is an address with no reconnect data.
    auto bare = Bytes("(ADDRESS=(HOST=node1)(PORT=1521))");
    bare.push_back(0);
    CHECK(ParseTnsRedirectData(bare, 0).reconnect_data.empty());

    // Flagged as carrying reconnect data, but no separator.
    ExpectError(ProtocolErrorKind::MALFORMED, [] {
        (void)ParseTnsRedirectData(Bytes("(ADDRESS=(HOST=node1)(PORT=1521))"), TNS_REDIRECT_FLAG_HAS_RECONNECT_DATA);
    });
    // No searching for a descriptor start: a prefix is refused.
    ExpectError(ProtocolErrorKind::MALFORMED,
                [] { (void)ParseTnsRedirectData(Bytes("junk(ADDRESS=(HOST=node1)(PORT=1521))"), 0); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)ParseTnsRedirectData(Bytes("(ADDRESS=(HOST=\x01))"), 0); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)ParseTnsRedirectData({}, 0); });
    auto bad_reconnect = Bytes("(ADDRESS=(HOST=node1)(PORT=1521))");
    bad_reconnect.push_back(0);
    bad_reconnect.push_back('x');
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)ParseTnsRedirectData(bad_reconnect, 0); });
}

static void TestRedirectPacketFraming() {
    const std::string descriptor = "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=X)))";
    const std::string address = "(ADDRESS=(PROTOCOL=TCP)(HOST=node1)(PORT=1521))";
    const auto run = [&](std::vector<uint8_t> wire) {
        FragmentedStream stream(std::move(wire), 5);
        TnsPacketStream packets(stream, false);
        return RunTnsConnect(packets, descriptor);
    };

    // Inline, and entirely in the DATA continuation.
    CHECK(run(RedirectPacketBytes(address)).redirect.address == address);
    CHECK(run(RedirectPacketBytes(address, 0, false)).redirect.address == address);

    // Split between the two: part inline, the rest in DATA.
    {
        std::vector<uint8_t> payload {0x00, static_cast<uint8_t>(address.size())};
        payload.insert(payload.end(), address.begin(), address.begin() + 10);
        auto wire = EncodeTnsPacket(TnsPacketType::REDIRECT, 0, payload, false);
        std::vector<uint8_t> rest {0x00, 0x00};
        rest.insert(rest.end(), address.begin() + 10, address.end());
        const auto data = EncodeTnsPacket(TnsPacketType::DATA, 0, rest, false);
        wire.insert(wire.end(), data.begin(), data.end());
        CHECK(run(wire).redirect.address == address);
    }
    // A zero length, and a payload with no length at all.
    ExpectError(ProtocolErrorKind::MALFORMED,
                [&] { run(EncodeTnsPacket(TnsPacketType::REDIRECT, 0, {0x00, 0x00}, false)); });
    ExpectError(ProtocolErrorKind::TRUNCATED, [&] { run(EncodeTnsPacket(TnsPacketType::REDIRECT, 0, {0x00}, false)); });
    // Inline data longer than declared.
    {
        std::vector<uint8_t> payload {0x00, 0x05};
        payload.insert(payload.end(), address.begin(), address.end());
        ExpectError(ProtocolErrorKind::MALFORMED, [&] { run(EncodeTnsPacket(TnsPacketType::REDIRECT, 0, payload, false)); });
    }
    // A continuation that is not DATA.
    {
        auto wire = EncodeTnsPacket(TnsPacketType::REDIRECT, 0, {0x00, 0x10}, false);
        const auto marker = EncodeTnsPacket(TnsPacketType::MARKER, 0, {0x01, 0x00, 0x02}, false);
        wire.insert(wire.end(), marker.begin(), marker.end());
        ExpectError(ProtocolErrorKind::MALFORMED, [&] { run(wire); });
    }
    // A continuation that overruns the declared length.
    {
        auto wire = EncodeTnsPacket(TnsPacketType::REDIRECT, 0, {0x00, 0x04}, false);
        std::vector<uint8_t> overlong {0x00, 0x00};
        overlong.insert(overlong.end(), address.begin(), address.end());
        const auto data = EncodeTnsPacket(TnsPacketType::DATA, 0, overlong, false);
        wire.insert(wire.end(), data.begin(), data.end());
        ExpectError(ProtocolErrorKind::MALFORMED, [&] { run(wire); });
    }
    // An empty continuation, which would otherwise let a listener stall the
    // client one empty packet at a time.
    {
        auto wire = EncodeTnsPacket(TnsPacketType::REDIRECT, 0, {0x00, 0x04}, false);
        const auto data = EncodeTnsPacket(TnsPacketType::DATA, 0, {0x00, 0x00}, false);
        wire.insert(wire.end(), data.begin(), data.end());
        ExpectError(ProtocolErrorKind::MALFORMED, [&] { run(wire); });
    }
    // More continuation packets than the bound allows, one byte each.
    {
        auto wire = EncodeTnsPacket(TnsPacketType::REDIRECT, 0, {0x00, 0x40}, false);
        for (size_t index = 0; index <= TNS_MAX_REDIRECT_CONTINUATIONS; index++) {
            const auto data = EncodeTnsPacket(TnsPacketType::DATA, 0, {0x00, 0x00, '('}, false);
            wire.insert(wire.end(), data.begin(), data.end());
        }
        ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { run(wire); });
    }
    // The listener hangs up before the data is complete.
    ExpectConnectFailure(ConnectFailure::TRANSPORT_LOST,
                         [&] { run(EncodeTnsPacket(TnsPacketType::REDIRECT, 0, {0x00, 0x10}, false)); });
}

static void TestRefusalCarriesTheOracleCode() {
    const auto refuse_wire = RefusePacketBytes(12514);
    auto refusal = ParseTnsRefusal(std::vector<uint8_t>(refuse_wire.begin() + 8, refuse_wire.end()));
    CHECK(refusal.oracle_error == 12514 && refusal.user_reason == 0x22 && refusal.system_reason == 0);
    // Case and spacing, the way go-ora's pattern allows them.
    const std::string loose = "(description=(err = 12528 )(vsnnum=0))";
    std::vector<uint8_t> payload {0, 0, 0, static_cast<uint8_t>(loose.size())};
    payload.insert(payload.end(), loose.begin(), loose.end());
    CHECK(ParseTnsRefusal(payload).oracle_error == 12528);
    // Short, empty, and lying about its length: diagnostics only, never a throw.
    CHECK(ParseTnsRefusal({}).oracle_error == 0);
    CHECK(ParseTnsRefusal({1, 2, 0xff, 0xff, '(', 'E'}).oracle_error == 0);
    CHECK(ParseTnsRefusal({1, 2, 0xff, 0xff, '(', 'E'}).message == "(E");

    FragmentedStream stream(RefusePacketBytes(12514), 7);
    TnsPacketStream packets(stream, false);
    try {
        RunTnsConnect(packets, "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=X)))");
        CHECK(false && "expected a refusal");
    } catch (const OracleConnectError &error) {
        CHECK(error.Kind() == ProtocolErrorKind::INVALID_STATE);
        CHECK(error.Failure() == ConnectFailure::LISTENER_REFUSED && error.OracleErrorCode() == 12514);
        CHECK(std::string(error.what()).find("ORA-12514") != std::string::npos);
    }
}

static void TestReconnectCarriesTheRedirectFlag() {
    TnsConnectOptions options;
    options.packet_flags = TNS_PACKET_FLAG_REDIRECT;
    auto packets = BuildTnsConnectPackets("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=X)))", options);
    CHECK(packets.size() == 1 && packets[0].flags == TNS_PACKET_FLAG_REDIRECT);
    CHECK(EncodeTnsPacket(packets[0].type, packets[0].flags, packets[0].payload, false)[5] == 0x04);
    // Long connect data: only the CONNECT carries the flag, as in both
    // references; its DATA continuation does not.
    packets = BuildTnsConnectPackets(std::string(300, 'x'), options);
    CHECK(packets.size() == 2 && packets[0].flags == TNS_PACKET_FLAG_REDIRECT && packets[1].flags == 0);
    CHECK(BuildTnsConnectPackets("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=X)))")[0].flags == 0);
}

static void TestDescriptorRoutingParameters() {
    // A SCAN descriptor the way Oracle's high-availability guidance writes one.
    auto scan = ParseConnectDescriptor(
        "(DESCRIPTION=(CONNECT_TIMEOUT=90)(RETRY_COUNT=20)(RETRY_DELAY=3)(TRANSPORT_CONNECT_TIMEOUT=3)"
        "(ADDRESS_LIST=(LOAD_BALANCE=on)(ADDRESS=(PROTOCOL=TCP)(HOST=scan.example)(PORT=1521)))"
        "(ADDRESS_LIST=(LOAD_BALANCE=on)(ADDRESS=(PROTOCOL=TCP)(HOST=standby-scan.example)(PORT=1521)))"
        "(CONNECT_DATA=(SERVICE_NAME=sales.example)))");
    CHECK(scan.address_lists.size() == 2 && scan.address_lists[0].load_balance && scan.address_lists[0].failover);
    CHECK(*scan.connect_timeout_seconds == 90 && *scan.retry_count == 20 && *scan.retry_delay_seconds == 3 &&
          *scan.transport_connect_timeout_seconds == 3);
    CHECK(scan.endpoints.size() == 2 && scan.endpoints[1].host == "standby-scan.example");

    // Direct addresses form one implicit list governed by the DESCRIPTION.
    auto direct = ParseConnectDescriptor(
        "(DESCRIPTION=(FAILOVER=off)(LOAD_BALANCE=yes)(ADDRESS=(HOST=a.example))(ADDRESS=(PROTOCOL=tcp)(HOST=b.example)"
        "(PORT=1522))(CONNECT_DATA=(SERVICE_NAME=svc)(INSTANCE_NAME=svc1)(SERVER=dedicated)))");
    CHECK(direct.address_lists.size() == 1 && direct.address_lists[0].addresses.size() == 2);
    CHECK(!direct.address_lists[0].failover && direct.address_lists[0].load_balance);
    CHECK(!direct.retry_count && !direct.connect_timeout_seconds);
    // PROTOCOL and PORT default to TCP and 1521.
    CHECK(direct.address_lists[0].addresses[0].protocol == TransportProtocol::TCP &&
          direct.address_lists[0].addresses[0].port == 1521);
    CHECK(direct.instance_name == "svc1" && direct.server_type == "DEDICATED");

    // Harmless keys are accepted: an Autonomous Database wallet entry.
    auto autonomous = ParseConnectDescriptor(
        "(description= (retry_count=20)(retry_delay=3)(address=(protocol=tcps)(port=1522)(host=adb.example))"
        "(connect_data=(service_name=x_low.adb.example))(security=(ssl_server_dn_match=yes)))");
    CHECK(*autonomous.retry_count == 20 && autonomous.endpoints[0].protocol == TransportProtocol::TCPS);
    CHECK(ParseConnectDescriptor("(DESCRIPTION=(EXPIRE_TIME=10)(SDU=8192)(ENABLE=broken)(SOURCE_ROUTE=off)"
                                 "(ADDRESS=(HOST=a)(PORT=1)(SEND_BUF_SIZE=65536))(CONNECT_DATA=(SERVICE_NAME=s)))")
              .endpoints.size() == 1);

    // What would silently change meaning is refused by name.
    const std::vector<std::string> unsupported {
        "(DESCRIPTION_LIST=(DESCRIPTION=(ADDRESS=(HOST=a)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=s)))"
        "(DESCRIPTION=(ADDRESS=(HOST=b)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=other))))",
        "(DESCRIPTION_LIST=(DESCRIPTION=(ADDRESS=(HOST=a)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=s)))"
        "(DESCRIPTION=(ADDRESS=(HOST=b)(PORT=1))(CONNECT_DATA=(SID=s))))",
        "(DESCRIPTION_LIST=(MYSTERY=1)(DESCRIPTION=(ADDRESS=(HOST=a)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=s))))",
        "(DESCRIPTION=(SOURCE_ROUTE=on)(ADDRESS=(HOST=a)(PORT=1))(ADDRESS=(HOST=b)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=s)))",
        "(DESCRIPTION=(ADDRESS=(HOST=a)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=s)(FAILOVER_MODE=(TYPE=select)(METHOD=basic))))",
        "(DESCRIPTION=(ADDRESS=(HOST=a)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=s)(SERVER=pooled)))",
        "(DESCRIPTION=(ADDRESS=(HOST=a)(PORT=1)(HTTPS_PROXY=proxy))(CONNECT_DATA=(SERVICE_NAME=s)))",
        "(DESCRIPTION=(ADDRESS=(HOST=a)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=s)(UR=A)))",
        "(DESCRIPTION=(MYSTERY=1)(ADDRESS=(HOST=a)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=s)))",
        "(DESCRIPTION=(TRANSPORT_CONNECT_TIMEOUT=250ms)(ADDRESS=(HOST=a)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=s)))",
        "(DESCRIPTION=(ADDRESS_LIST=(SOURCE_ROUTE=yes)(ADDRESS=(HOST=a)(PORT=1)))(CONNECT_DATA=(SERVICE_NAME=s)))",
    };
    for (const auto &descriptor : unsupported) {
        ExpectError(ProtocolErrorKind::UNSUPPORTED, [&] { (void)ParseConnectDescriptor(descriptor); });
    }
    // A SID names the database the older way; a descriptor has one of the two.
    const auto by_sid = ParseConnectDescriptor("(DESCRIPTION=(ADDRESS=(HOST=a)(PORT=1))(CONNECT_DATA=(SID=orcl)))");
    CHECK(by_sid.sid == "orcl" && by_sid.service_name.empty());
    ExpectError(ProtocolErrorKind::MALFORMED, [] {
        (void)ParseConnectDescriptor("(DESCRIPTION=(ADDRESS=(HOST=a)(PORT=1))(CONNECT_DATA=(SID=a)(SERVICE_NAME=b)))");
    });
    // A list of descriptions that name one database is read as their addresses in order.
    const auto listed = ParseConnectDescriptor(
        "(DESCRIPTION_LIST=(FAILOVER=on)(LOAD_BALANCE=off)"
        "(DESCRIPTION=(CONNECT_TIMEOUT=7)(ADDRESS_LIST=(ADDRESS=(HOST=a)(PORT=1))(ADDRESS=(HOST=b)(PORT=2)))"
        "(CONNECT_DATA=(SERVICE_NAME=s)))"
        "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=c)(PORT=3))(CONNECT_DATA=(SERVICE_NAME=s))))");
    CHECK(listed.service_name == "s" && listed.endpoints.size() == 3 && listed.address_lists.size() == 2 &&
          listed.endpoints[2].host == "c" && listed.endpoints[2].port == 3 && *listed.connect_timeout_seconds == 7);
    CHECK(listed.failover && !listed.load_balance);
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)ParseConnectDescriptor("(DESCRIPTION_LIST=)"); });
    const std::vector<std::string> malformed {
        "(DESCRIPTION=(FAILOVER=on)(FAILOVER=off)(ADDRESS=(HOST=a)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=s)))",
        "(DESCRIPTION=(FAILOVER=maybe)(ADDRESS=(HOST=a)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=s)))",
        "(DESCRIPTION=(RETRY_COUNT=x)(ADDRESS=(HOST=a)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=s)))",
        "(DESCRIPTION=(CONNECT_TIMEOUT=0)(ADDRESS=(HOST=a)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=s)))",
        "(DESCRIPTION=(ADDRESS_LIST=(FAILOVER=on))(CONNECT_DATA=(SERVICE_NAME=s)))",
        "(DESCRIPTION=(ADDRESS=(PORT=1))(CONNECT_DATA=(SERVICE_NAME=s)))",
    };
    for (const auto &descriptor : malformed) {
        ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)ParseConnectDescriptor(descriptor); });
    }
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [] {
        (void)ParseConnectDescriptor("(DESCRIPTION=(RETRY_COUNT=101)(ADDRESS=(HOST=a)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=s)))");
    });
    std::string many = "(DESCRIPTION=";
    for (size_t index = 0; index <= MAX_CONNECT_ADDRESSES; index++) {
        many += "(ADDRESS=(HOST=h" + std::to_string(index) + ")(PORT=1521))";
    }
    many += "(CONNECT_DATA=(SERVICE_NAME=s)))";
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)ParseConnectDescriptor(many); });
}

static void TestRedirectAddressParsing() {
    auto parsed = ParseRedirectAddresses("(ADDRESS=(PROTOCOL=TCP)(HOST=node1-vip)(PORT=1521))");
    CHECK(parsed.size() == 1 && parsed[0].address.host == "node1-vip" && parsed[0].protocol_given);
    parsed = ParseRedirectAddresses("(ADDRESS_LIST=(ADDRESS=(HOST=node1)(PORT=1521))(ADDRESS=(PROTOCOL=tcp)(HOST=node2)(PORT=1522)))");
    CHECK(parsed.size() == 2 && !parsed[0].protocol_given && parsed[1].address.port == 1522);
    // A full DESCRIPTION, with keys that are the listener's own business.
    parsed = ParseRedirectAddresses(
        "(DESCRIPTION=(SOMETHING=x)(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.0.21)(PORT=1521))"
        "(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.0.22)(PORT=1521)))(CONNECT_DATA=(SERVICE_NAME=moved)))");
    CHECK(parsed.size() == 2 && parsed[1].address.host == "10.0.0.22");
    ExpectError(ProtocolErrorKind::UNSUPPORTED,
                [] { (void)ParseRedirectAddresses("(ADDRESS=(PROTOCOL=IPC)(HOST=x)(PORT=1))"); });
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [] {
        (void)ParseRedirectAddresses("(DESCRIPTION_LIST=(DESCRIPTION=(ADDRESS=(HOST=x)(PORT=1))))");
    });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)ParseRedirectAddresses("(CONNECT_DATA=(SERVICE_NAME=x))"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)ParseRedirectAddresses("(ADDRESS=(HOST=x))"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)ParseRedirectAddresses("(DESCRIPTION=(CONNECT_DATA=(S=x)))"); });
    ExpectError(ProtocolErrorKind::MALFORMED,
                [] { (void)ParseRedirectAddresses("(ADDRESS=(HOST=bad)(HOST=x)(PORT=1)(PORT=2))"); });

    ValidateRedirectReconnectData("(DESCRIPTION=(ADDRESS=(HOST=x)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=s)(CID=(PROGRAM=p))))");
    ExpectError(ProtocolErrorKind::MALFORMED, [] { ValidateRedirectReconnectData("(ADDRESS=(HOST=x)(PORT=1))"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { ValidateRedirectReconnectData("(DESCRIPTION=(ADDRESS=(HOST=x)))"); });
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED,
                [] { ValidateRedirectReconnectData(std::string(MAX_RECONNECT_DATA_BYTES + 1, '(')); });
}

static ConnectionConfig RoutedConfig(const std::vector<std::vector<std::string>> &lists, bool failover = true,
                                     bool load_balance = false) {
    ConnectionConfig config;
    config.service_name = "svc";
    for (const auto &hosts : lists) {
        ConnectAddressList list;
        list.failover = failover;
        list.load_balance = load_balance;
        for (const auto &host : hosts) {
            list.addresses.push_back({host, 1521, TransportProtocol::TCP});
        }
        config.routing.address_lists.push_back(list);
    }
    config.routing.failover = failover;
    config.routing.load_balance = load_balance;
    return config;
}

static std::vector<std::string> Hosts(const std::vector<ConnectAddress> &addresses) {
    std::vector<std::string> result;
    for (const auto &address : addresses) {
        result.push_back(address.host);
    }
    return result;
}

// A random source that plays back a fixed sequence, so a shuffle is a known
// permutation.
static std::function<uint64_t()> Sequence(std::vector<uint64_t> values) {
    auto shared = std::make_shared<std::vector<uint64_t>>(std::move(values));
    auto position = std::make_shared<size_t>(0);
    return [shared, position]() { return (*shared)[(*position)++ % shared->size()]; };
}

static void TestConnectOrderPolicy() {
    const auto never = []() -> uint64_t {
        CHECK(false && "LOAD_BALANCE is off: no randomness may be drawn");
        return 0;
    };
    using Order = std::vector<std::string>;
    CHECK(Hosts(PlanConnectOrder(RoutedConfig({{"a", "b", "c"}}), never)) == Order({"a", "b", "c"}));
    CHECK(Hosts(PlanConnectOrder(RoutedConfig({{"a", "b", "c"}}, false, false), never)) == Order({"a"}));
    // failover + load balance: all three, in the permutation the draws pick.
    // Fisher-Yates from the end: swap(c, index 0) -> c b a; swap(b, index 1) -> c b a.
    CHECK(Hosts(PlanConnectOrder(RoutedConfig({{"a", "b", "c"}}, true, true), Sequence({0, 1}))) ==
          Order({"c", "b", "a"}));
    CHECK(Hosts(PlanConnectOrder(RoutedConfig({{"a", "b", "c"}}, true, true), Sequence({2, 0}))) ==
          Order({"b", "a", "c"}));
    // no failover + load balance: exactly one, chosen by the draw.
    CHECK(Hosts(PlanConnectOrder(RoutedConfig({{"a", "b", "c"}}, false, true), Sequence({1}))) == Order({"b"}));
    // Two lists: the DESCRIPTION's policy picks lists, each list's picks within.
    auto two = RoutedConfig({{"a1", "a2"}, {"b1", "b2"}});
    CHECK(Hosts(PlanConnectOrder(two, never)) == Order({"a1", "a2", "b1", "b2"}));
    two.routing.load_balance = true;
    CHECK(Hosts(PlanConnectOrder(two, Sequence({0}))) == Order({"b1", "b2", "a1", "a2"}));
    two.routing.load_balance = false;
    two.routing.failover = false;
    CHECK(Hosts(PlanConnectOrder(two, never)) == Order({"a1", "a2"}));
    // The single HOST/PORT form is one address, whatever the policy.
    ConnectionConfig single;
    single.host = "db.example";
    single.service_name = "svc";
    CHECK(Hosts(PlanConnectOrder(single, never)) == Order({"db.example"}));
}

static void TestRoutedConfigValidationAndDescriptors() {
    auto config = RoutedConfig({{"node1", "node2"}});
    config.instance_name = "svc1";
    config.server_type = "dedicated";
    const auto descriptor = BuildConnectDescriptor(config, config.routing.address_lists[0].addresses[1]);
    CHECK(descriptor.find("(HOST=node2)") != std::string::npos);
    CHECK(descriptor.find("(SERVICE_NAME=svc)(INSTANCE_NAME=svc1)(SERVER=DEDICATED)") != std::string::npos);
    CHECK(BuildAuthConnectString(config).find("(HOST=node1)") != std::string::npos);
    // A host beside a descriptor's addresses is ambiguous.
    auto both = config;
    both.host = "other";
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { ValidateConnectionConfig(both); });
    // protocol has to agree with the addresses.
    auto disagreeing = config;
    disagreeing.routing.address_lists[0].addresses[1].protocol = TransportProtocol::TCPS;
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { ValidateConnectionConfig(disagreeing); });
    disagreeing.protocol = TransportProtocol::TCPS;
    ValidateConnectionConfig(disagreeing);
    auto empty_list = config;
    empty_list.routing.address_lists.push_back({});
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { ValidateConnectionConfig(empty_list); });
    auto bad_host = config;
    bad_host.routing.address_lists[0].addresses[0].host = "x)(HOST=y";
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { ValidateConnectionConfig(bad_host); });
    auto pooled = config;
    pooled.server_type = "POOLED";
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [&] { ValidateConnectionConfig(pooled); });
    auto retries = config;
    retries.routing.retry_count = MAX_CONNECT_RETRY_COUNT + 1;
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { ValidateConnectionConfig(retries); });
    // The pool key follows the addresses and their order, never a password.
    auto reordered = RoutedConfig({{"node2", "node1"}});
    CHECK(ConnectionTargetKey(RoutedConfig({{"node1", "node2"}})) != ConnectionTargetKey(reordered));
    // The default budget never undercuts the per-attempt timeout.
    ConnectionConfig slow;
    slow.host = "db";
    slow.service_name = "svc";
    slow.connect_timeout_seconds = 120;
    CHECK(EffectiveConnectBudgetSeconds(slow) == 120);
    slow.connect_timeout_seconds = 10;
    CHECK(EffectiveConnectBudgetSeconds(slow) == DEFAULT_CONNECT_BUDGET_SECONDS);
}

// A scripted network. Each dialed "address:port" — an IP for a resolved name —
// answers each new connection with the next behaviour in its script; the last
// one repeats. An address with no script is unreachable, the way a closed port
// is. Every transport handed out is counted while alive, so a test can see
// that a failed attempt released its transport.
class FakeNetwork {
public:
    enum class Kind { ANSWER, UNREACHABLE, BLACK_HOLE, BAD_CERTIFICATE };
    struct Behaviour {
        Kind kind = Kind::ANSWER;
        std::vector<uint8_t> bytes;
    };
    struct Open {
        std::string address;
        uint16_t port = 0;
        uint32_t timeout = 0;
        bool tls = false;
        std::string server_name;
        std::string sni_name;
    };

    class Transport : public ScriptedTransport {
    public:
        Transport(std::vector<uint8_t> input, std::vector<uint8_t> *sink, int &live_p, bool urgent_p)
            : ScriptedTransport(std::move(input), sink), live(live_p), urgent(urgent_p) {
            live++;
        }
        ~Transport() override {
            live--;
        }
        // A plain TCP transport has an out-of-band channel; when the network
        // says so, the CHECK_OOB probe's urgent byte is simply accepted.
        void SendUrgent(uint8_t value) override {
            if (!urgent) {
                ScriptedTransport::SendUrgent(value);
            }
        }

    private:
        int &live;
        bool urgent;
    };

    void Script(const std::string &address, uint16_t port, std::vector<Behaviour> behaviours) {
        scripts[address + ":" + std::to_string(port)] = std::deque<Behaviour>(behaviours.begin(), behaviours.end());
    }
    void Answer(const std::string &address, uint16_t port, std::vector<uint8_t> bytes) {
        Script(address, port, {{Kind::ANSWER, std::move(bytes)}});
    }

    OracleTransportFactory Factory(std::chrono::steady_clock::time_point *clock = nullptr) {
        return [this, clock](const std::string &host, uint16_t port, uint32_t timeout, uint32_t, bool use_tls,
                             const TlsConfiguration &tls) -> std::unique_ptr<ByteStream> {
            opens.push_back({host, port, timeout, use_tls, tls.server_name, tls.sni_name});
            const auto found = scripts.find(host + ":" + std::to_string(port));
            if (found == scripts.end() || found->second.empty()) {
                throw OracleConnectError(ProtocolErrorKind::TRUNCATED, ConnectFailure::UNREACHABLE,
                                         "scripted: connection refused");
            }
            auto behaviour = found->second.front();
            if (found->second.size() > 1) {
                found->second.pop_front();
            }
            switch (behaviour.kind) {
            case Kind::UNREACHABLE:
                throw OracleConnectError(ProtocolErrorKind::TRUNCATED, ConnectFailure::UNREACHABLE,
                                         "scripted: connection refused");
            case Kind::BLACK_HOLE:
                // Nothing answers, so the whole per-attempt timeout is spent.
                if (clock) {
                    *clock += std::chrono::seconds(timeout);
                }
                throw OracleConnectError(ProtocolErrorKind::TRUNCATED, ConnectFailure::UNREACHABLE,
                                         "scripted: connection timed out");
            case Kind::BAD_CERTIFICATE:
                throw OracleConnectError(ProtocolErrorKind::INVALID_STATE, ConnectFailure::TLS_VERIFICATION,
                                         "scripted: certificate verification failed");
            case Kind::ANSWER:
                break;
            }
            written.emplace_back();
            return std::make_unique<Transport>(std::move(behaviour.bytes), &written.back(), live, supports_urgent);
        };
    }

    std::vector<std::string> Opened() const {
        std::vector<std::string> result;
        for (const auto &open : opens) {
            result.push_back(open.address);
        }
        return result;
    }

    std::map<std::string, std::deque<Behaviour>> scripts;
    std::vector<Open> opens;
    // One entry per transport actually handed out, holding what the client
    // wrote to it.
    std::deque<std::vector<uint8_t>> written;
    int live = 0;
    bool supports_urgent = false;
};

// A clock that moves only when the connect sleeps or a scripted black hole
// spends a timeout, plus a record of the sleeping.
struct FakeClock {
    std::chrono::steady_clock::time_point now {};
    std::chrono::milliseconds slept {0};
    std::function<void()> on_sleep;
    std::function<uint64_t()> random;

    OracleConnectEnvironment Environment() {
        OracleConnectEnvironment environment;
        environment.now = [this] { return now; };
        environment.sleep = [this](std::chrono::milliseconds duration) {
            now += duration;
            slept += duration;
            if (on_sleep) {
                on_sleep();
            }
        };
        environment.random = [this]() -> uint64_t { return random ? random() : 0; };
        return environment;
    }
};

// The first packet a client wrote: its header flags and its connect data,
// inline or from the DATA continuation.
struct WrittenConnect {
    uint8_t flags = 0;
    std::string data;
};

static WrittenConnect FirstConnect(const std::vector<uint8_t> &bytes) {
    CHECK(bytes.size() >= 8);
    const size_t length = (static_cast<size_t>(bytes[0]) << 8U) | bytes[1];
    CHECK(length <= bytes.size() && bytes[4] == static_cast<uint8_t>(TnsPacketType::CONNECT));
    WrittenConnect result;
    result.flags = bytes[5];
    if (length > 74) {
        result.data.assign(bytes.begin() + 74, bytes.begin() + static_cast<std::ptrdiff_t>(length));
    } else {
        CHECK(bytes.size() >= length + 10);
        const size_t next = (static_cast<size_t>(bytes[length]) << 8U) | bytes[length + 1];
        result.data.assign(bytes.begin() + static_cast<std::ptrdiff_t>(length + 10),
                           bytes.begin() + static_cast<std::ptrdiff_t>(length + next));
    }
    return result;
}

static std::string RedirectData(const std::string &address, const std::string &reconnect = std::string()) {
    auto data = address;
    if (!reconnect.empty()) {
        data.push_back('\0');
        data += reconnect;
    }
    return data;
}

static void TestConnectFailsOverToTheNextAddress() {
    FakeNetwork network;
    network.Answer("node2", 1521, AcceptPacketBytes(false));
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    ScopedOracleTransportFactory installed(network.Factory());
    {
        const auto connection = TnsClientConnection::Connect(RoutedConfig({{"node1", "node2"}}));
        CHECK(network.Opened() == std::vector<std::string>({"node1", "node2"}));
        // The failed attempt left nothing open; the accepted one is held.
        CHECK(network.live == 1);
        CHECK(connection->AuthConnectString().find("(HOST=node2)") != std::string::npos);
    }
    CHECK(network.live == 0);

    // FAILOVER=OFF with LOAD_BALANCE=OFF: the first address only, and its
    // failure is reported exactly as a single-address connect reports it.
    network.opens.clear();
    try {
        TnsClientConnection::Connect(RoutedConfig({{"node1", "node2"}}, false, false));
        CHECK(false && "expected the first address to fail");
    } catch (const OracleConnectError &error) {
        CHECK(error.Failure() == ConnectFailure::UNREACHABLE && error.Kind() == ProtocolErrorKind::TRUNCATED);
        CHECK(std::string(error.what()) == "scripted: connection refused");
    }
    CHECK(network.Opened() == std::vector<std::string>({"node1"}));
}

static void TestRefusalFailsOverAndKeepsTheCode() {
    FakeNetwork network;
    network.Answer("node1", 1521, RefusePacketBytes(12514));
    network.Answer("node2", 1521, AcceptPacketBytes(false));
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    ScopedOracleTransportFactory installed(network.Factory());
    (void)TnsClientConnection::Connect(RoutedConfig({{"node1", "node2"}}));
    CHECK(network.Opened() == std::vector<std::string>({"node1", "node2"}));
    CHECK(network.live == 0);

    network.opens.clear();
    network.Answer("node2", 1521, RefusePacketBytes(12528));
    try {
        TnsClientConnection::Connect(RoutedConfig({{"node1", "node2"}}));
        CHECK(false && "expected every listener to refuse");
    } catch (const OracleConnectError &error) {
        const std::string message = error.what();
        CHECK(error.Failure() == ConnectFailure::LISTENER_REFUSED && error.Kind() == ProtocolErrorKind::INVALID_STATE);
        // The last refusal's code; both refusals in the attempt list.
        CHECK(error.OracleErrorCode() == 12528);
        CHECK(message.find("after 2 attempts") != std::string::npos);
        CHECK(message.find("node1:1521: listener refused") != std::string::npos);
        CHECK(message.find("ORA-12514") != std::string::npos && message.find("ORA-12528") != std::string::npos);
    }
    CHECK(network.live == 0);
}

static void TestEveryAddressUnreachableIsListed() {
    FakeNetwork network;
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    ScopedOracleTransportFactory installed(network.Factory());
    auto config = RoutedConfig({{"node1", "node2", "node3"}});
    config.user = "scott";
    try {
        TnsClientConnection::Connect(config);
        CHECK(false && "expected every address to fail");
    } catch (const OracleConnectError &error) {
        const std::string message = error.what();
        CHECK(error.Failure() == ConnectFailure::UNREACHABLE && error.Kind() == ProtocolErrorKind::TRUNCATED);
        CHECK(message.find("after 3 attempts") != std::string::npos);
        for (const auto *host : {"node1:1521", "node2:1521", "node3:1521"}) {
            CHECK(message.find(host) != std::string::npos);
        }
        // Addresses and outcomes only: no user, no connect data.
        CHECK(message.find("scott") == std::string::npos);
        CHECK(message.find("CONNECT_DATA") == std::string::npos && message.find("SERVICE_NAME") == std::string::npos);
    }
    CHECK(network.Opened().size() == 3 && network.live == 0);
}

static void TestScanNameWithSeveralAddresses() {
    FakeNetwork network;
    network.Script("10.0.0.1", 1522, {{FakeNetwork::Kind::UNREACHABLE, {}}});
    network.Answer("10.0.0.2", 1522, AcceptPacketBytes(false));
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    ScopedOracleTransportFactory installed(network.Factory());
    ScopedOracleHostResolver resolver([](const std::string &host, uint16_t) {
        CHECK(host == "scan.example");
        return std::vector<std::string> {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.2"};
    });
    ConnectionConfig config;
    config.host = "scan.example";
    config.port = 1522;
    config.service_name = "svc";
    config.protocol = TransportProtocol::TCPS;
    (void)TnsClientConnection::Connect(config);
    CHECK(network.Opened() == std::vector<std::string>({"10.0.0.1", "10.0.0.2"}));
    // Dialed by IP, verified and introduced by the configured name.
    for (const auto &open : network.opens) {
        CHECK(open.tls && open.server_name == "scan.example" && open.sni_name == "scan.example");
    }
    // An explicit TLS_SERVER_NAME is checked on every attempt; SNI still
    // names the configured host, as it always did.
    network.opens.clear();
    config.tls_server_name = "cert.example";
    TlsConfiguration tls;
    tls.server_name = config.tls_server_name;
    (void)TnsClientConnection::Connect(config, tls);
    CHECK(network.opens.back().server_name == "cert.example" && network.opens.back().sni_name == "scan.example");
    // Duplicates the resolver returned are dialed once.
    ScopedOracleHostResolver duplicates([](const std::string &, uint16_t) {
        return std::vector<std::string> {"10.0.0.1", "10.0.0.1", "10.0.0.3"};
    });
    network.opens.clear();
    ExpectConnectFailure(ConnectFailure::UNREACHABLE, [&] { (void)TnsClientConnection::Connect(config, tls); });
    CHECK(network.Opened() == std::vector<std::string>({"10.0.0.1", "10.0.0.3"}));
}

static void TestScanListenerRedirectsToANode() {
    const std::string node_address = "(ADDRESS=(PROTOCOL=TCP)(HOST=node1-vip)(PORT=1521))";
    const std::string reconnect = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=node1-vip)(PORT=1521))"
                                  "(CONNECT_DATA=(SERVICE_NAME=svc)(INSTANCE_NAME=svc1)(CID=(PROGRAM=x))))";
    for (const bool inline_data : {true, false}) {
        FakeNetwork network;
        network.Answer("10.0.0.1", 1521,
                       RedirectPacketBytes(RedirectData(node_address, reconnect), TNS_REDIRECT_FLAG_HAS_RECONNECT_DATA,
                                           inline_data));
        network.Answer("10.0.1.1", 1521, AcceptPacketBytes(false));
        FakeClock clock;
        ScopedOracleConnectEnvironment environment(clock.Environment());
        ScopedOracleTransportFactory installed(network.Factory());
        ScopedOracleHostResolver resolver([](const std::string &host, uint16_t) {
            return host == "scan.example" ? std::vector<std::string> {"10.0.0.1"}
                                          : std::vector<std::string> {"10.0.1.1"};
        });
        ConnectionConfig config;
        config.host = "scan.example";
        config.service_name = "svc";
        const auto connection = TnsClientConnection::Connect(config);
        CHECK(network.Opened() == std::vector<std::string>({"10.0.0.1", "10.0.1.1"}));
        CHECK(network.live == 1);
        const auto first = FirstConnect(network.written[0]);
        const auto second = FirstConnect(network.written[1]);
        CHECK(first.flags == 0 && first.data.find("(HOST=scan.example)") != std::string::npos);
        // The re-CONNECT carries the redirect flag and the listener's reconnect
        // data, verbatim.
        CHECK(second.flags == TNS_PACKET_FLAG_REDIRECT && second.data == reconnect);
        CHECK(connection->ConnectDescriptor() == reconnect);
        // O5LOGON names what was configured, without the listener-only CID.
        const auto &auth = connection->AuthConnectString();
        CHECK(auth.find("(HOST=scan.example)") != std::string::npos && auth.find("(SERVICE_NAME=svc)") != std::string::npos);
        CHECK(auth.find("(CID=") == std::string::npos);

        // The configuration is untouched: the next physical connection starts
        // at the SCAN address again, not at the node the last one reached.
        network.opens.clear();
        (void)TnsClientConnection::Connect(config);
        CHECK(network.Opened() == std::vector<std::string>({"10.0.0.1", "10.0.1.1"}));
    }
}

static void TestRedirectWithoutReconnectDataIsRebuilt() {
    FakeNetwork network;
    network.Answer("scan", 1521,
                   RedirectPacketBytes("(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=node2)(PORT=1525))"
                                       "(CONNECT_DATA=(SERVICE_NAME=elsewhere)))"));
    network.Answer("node2", 1525, AcceptPacketBytes(false));
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    ScopedOracleTransportFactory installed(network.Factory());
    auto config = RoutedConfig({{"scan"}});
    config.instance_name = "svc2";
    const auto connection = TnsClientConnection::Connect(config);
    const auto second = FirstConnect(network.written[1]);
    // The new address, the original service and instance: the address part of
    // a redirect says where to go, not what to ask for.
    CHECK(second.flags == TNS_PACKET_FLAG_REDIRECT);
    CHECK(second.data.find("(HOST=node2)(PORT=1525)") != std::string::npos);
    CHECK(second.data.find("(SERVICE_NAME=svc)(INSTANCE_NAME=svc2)") != std::string::npos);
    CHECK(second.data.find("elsewhere") == std::string::npos);
}

static void TestUnreachableRedirectTargetFallsBack() {
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    // The first SCAN address sends the client to a node that is down; the
    // second SCAN address is still tried before anything else.
    {
        FakeNetwork network;
        network.Answer("10.0.0.1", 1521, RedirectPacketBytes("(ADDRESS=(PROTOCOL=TCP)(HOST=node1)(PORT=1521))"));
        network.Answer("10.0.0.2", 1521, AcceptPacketBytes(false));
        ScopedOracleTransportFactory installed(network.Factory());
        ScopedOracleHostResolver resolver([](const std::string &host, uint16_t) {
            return host == "scan" ? std::vector<std::string> {"10.0.0.1", "10.0.0.2"}
                                  : std::vector<std::string> {host};
        });
        const auto connection = TnsClientConnection::Connect(RoutedConfig({{"scan", "backup"}}));
        CHECK(network.Opened() == std::vector<std::string>({"10.0.0.1", "node1", "10.0.0.2"}));
        CHECK(network.live == 1);
    }
    // And when the SCAN has nothing left, the rest of the configured list.
    {
        FakeNetwork network;
        network.Answer("scan", 1521, RedirectPacketBytes("(ADDRESS_LIST=(ADDRESS=(HOST=node1)(PORT=1521))"
                                                         "(ADDRESS=(HOST=node2)(PORT=1521)))"));
        network.Answer("backup", 1521, AcceptPacketBytes(false));
        ScopedOracleTransportFactory installed(network.Factory());
        (void)TnsClientConnection::Connect(RoutedConfig({{"scan", "backup"}}));
        // Both redirect targets were tried, in the listener's order.
        CHECK(network.Opened() == std::vector<std::string>({"scan", "node1", "node2", "backup"}));
    }
    // With nowhere left, the failure says the redirect is what failed.
    {
        FakeNetwork network;
        network.Answer("scan", 1521, RedirectPacketBytes("(ADDRESS=(HOST=node1)(PORT=1521))"));
        ScopedOracleTransportFactory installed(network.Factory());
        ExpectConnectFailure(ConnectFailure::REDIRECT_FAILED,
                             [] { (void)TnsClientConnection::Connect(RoutedConfig({{"scan"}})); });
    }
}

static void TestRedirectCyclesAndLimits() {
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    {
        FakeNetwork network;
        network.Answer("a", 1521, RedirectPacketBytes("(ADDRESS=(HOST=b)(PORT=1521))"));
        network.Answer("b", 1521, RedirectPacketBytes("(ADDRESS=(HOST=A)(PORT=1521))"));
        network.Answer("c", 1521, AcceptPacketBytes(false));
        ScopedOracleTransportFactory installed(network.Factory());
        try {
            TnsClientConnection::Connect(RoutedConfig({{"a"}}));
            CHECK(false && "expected a redirect cycle");
        } catch (const OracleConnectError &error) {
            CHECK(error.Failure() == ConnectFailure::REDIRECT_FAILED);
            CHECK(std::string(error.what()).find("loops back") != std::string::npos);
        }
        // A cycle is this listener's problem, not the configuration's: the next
        // configured address still gets its turn.
        network.opens.clear();
        (void)TnsClientConnection::Connect(RoutedConfig({{"a", "c"}}));
        CHECK(network.Opened() == std::vector<std::string>({"a", "b", "c"}));

        // Within one hop: the first node the listener named sends the client
        // back where it started, and the second node it named still answers.
        network.opens.clear();
        network.Answer("scan", 1521,
                       RedirectPacketBytes("(ADDRESS_LIST=(ADDRESS=(HOST=n1)(PORT=1521))(ADDRESS=(HOST=n2)(PORT=1521)))"));
        network.Answer("n1", 1521, RedirectPacketBytes("(ADDRESS=(HOST=scan)(PORT=1521))"));
        network.Answer("n2", 1521, AcceptPacketBytes(false));
        const auto connection = TnsClientConnection::Connect(RoutedConfig({{"scan"}}));
        CHECK(network.Opened() == std::vector<std::string>({"scan", "n1", "n2"}) && network.live == 1);
    }
    {
        FakeNetwork network;
        const std::vector<std::string> chain {"h0", "h1", "h2", "h3", "h4"};
        for (size_t index = 0; index + 1 < chain.size(); index++) {
            network.Answer(chain[index], 1521,
                           RedirectPacketBytes("(ADDRESS=(HOST=" + chain[index + 1] + ")(PORT=1521))"));
        }
        network.Answer("h4", 1521, AcceptPacketBytes(false));
        ScopedOracleTransportFactory installed(network.Factory());
        try {
            TnsClientConnection::Connect(RoutedConfig({{"h0"}}));
            CHECK(false && "expected the redirect limit");
        } catch (const OracleConnectError &error) {
            CHECK(error.Failure() == ConnectFailure::REDIRECT_FAILED);
            CHECK(std::string(error.what()).find("redirect limit") != std::string::npos);
        }
        CHECK(network.Opened() == std::vector<std::string>({"h0", "h1", "h2", "h3"}));
        CHECK(network.live == 0);
    }
}

static void TestRedirectCannotChangeTheProtocol() {
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    FakeNetwork network;
    network.Answer("secure", 1522, RedirectPacketBytes("(ADDRESS=(PROTOCOL=TCP)(HOST=node1)(PORT=1521))"));
    network.Answer("node1", 1521, AcceptPacketBytes(false));
    network.Answer("other", 1522, AcceptPacketBytes(false));
    ScopedOracleTransportFactory installed(network.Factory());
    auto config = RoutedConfig({{"secure", "other"}});
    for (auto &address : config.routing.address_lists[0].addresses) {
        address.protocol = TransportProtocol::TCPS;
        address.port = 1522;
    }
    config.protocol = TransportProtocol::TCPS;
    try {
        TnsClientConnection::Connect(config);
        CHECK(false && "expected the downgrade to be refused");
    } catch (const OracleConnectError &error) {
        CHECK(error.Failure() == ConnectFailure::PROTOCOL);
        CHECK(std::string(error.what()).find("refusing to downgrade") != std::string::npos);
    }
    // Refused outright: not the redirect target, and not the next address.
    CHECK(network.Opened() == std::vector<std::string>({"secure"}));

    // A redirect that names no protocol keeps TCPS, and TLS settings with it.
    network.opens.clear();
    network.Answer("secure", 1522, RedirectPacketBytes("(ADDRESS=(HOST=node2)(PORT=1522))"));
    network.Answer("node2", 1522, AcceptPacketBytes(false));
    (void)TnsClientConnection::Connect(config);
    CHECK(network.Opened() == std::vector<std::string>({"secure", "node2"}));
    CHECK(network.opens[1].tls && network.opens[1].server_name == "secure" && network.opens[1].sni_name == "secure");

    // Nor may a TCP connection be sent to TCPS.
    network.opens.clear();
    network.Answer("plain", 1521, RedirectPacketBytes("(ADDRESS=(PROTOCOL=TCPS)(HOST=node3)(PORT=2484))"));
    ExpectConnectFailure(ConnectFailure::PROTOCOL, [] { (void)TnsClientConnection::Connect(RoutedConfig({{"plain"}})); });
}

static void TestMalformedListenerAnswersAreNotFailedOver() {
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    FakeNetwork network;
    network.Answer("a", 1521, RedirectPacketBytes("junk"));
    network.Answer("b", 1521, AcceptPacketBytes(false));
    ScopedOracleTransportFactory installed(network.Factory());
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)TnsClientConnection::Connect(RoutedConfig({{"a", "b"}})); });
    CHECK(network.Opened() == std::vector<std::string>({"a"}) && network.live == 0);

    // A certificate that does not verify ends the connect too.
    network.opens.clear();
    network.Script("a", 1521, {{FakeNetwork::Kind::BAD_CERTIFICATE, {}}});
    ExpectConnectFailure(ConnectFailure::TLS_VERIFICATION,
                         [] { (void)TnsClientConnection::Connect(RoutedConfig({{"a", "b"}})); });
    CHECK(network.Opened() == std::vector<std::string>({"a"}));

    // Anything after ACCEPT is not a connect failure at all: here the CHECK_OOB
    // probe, which a scripted transport cannot answer. The second address is
    // never tried.
    network.opens.clear();
    network.Answer("a", 1521, AcceptPacketBytes(true));
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [] { (void)TnsClientConnection::Connect(RoutedConfig({{"a", "b"}})); });
    CHECK(network.Opened() == std::vector<std::string>({"a"}));
}

static void TestUnresolvableNameFailsOver() {
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    FakeNetwork network;
    network.Answer("b", 1521, AcceptPacketBytes(false));
    ScopedOracleTransportFactory installed(network.Factory());
    ScopedOracleHostResolver resolver([](const std::string &host, uint16_t) -> std::vector<std::string> {
        if (host == "gone.example") {
            throw OracleConnectError(ProtocolErrorKind::TRUNCATED, ConnectFailure::UNREACHABLE, "scripted: no such host");
        }
        return {host};
    });
    (void)TnsClientConnection::Connect(RoutedConfig({{"gone.example", "b"}}));
    CHECK(network.Opened() == std::vector<std::string>({"b"}));
    // A resolver that returns nothing is the same failure.
    ScopedOracleHostResolver empty([](const std::string &, uint16_t) { return std::vector<std::string>(); });
    ExpectConnectFailure(ConnectFailure::UNREACHABLE, [] { (void)ResolveOracleHost("x.example", 1521); });
    // An IP literal never reaches a resolver.
    CHECK(ResolveOracleHost("2001:db8::1", 1521) == std::vector<std::string>({"2001:db8::1"}));
}

static void TestRetriesDelaysAndTheBudget() {
    FakeNetwork network;
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    ScopedOracleTransportFactory installed(network.Factory(&clock.now));

    // RETRY_COUNT=2, RETRY_DELAY=5: three passes, two delays.
    auto config = RoutedConfig({{"dead"}});
    config.routing.retry_count = 2;
    config.routing.retry_delay_seconds = 5;
    try {
        TnsClientConnection::Connect(config);
        CHECK(false && "expected every pass to fail");
    } catch (const OracleConnectError &error) {
        CHECK(error.Failure() == ConnectFailure::UNREACHABLE);
        CHECK(std::string(error.what()).find("after 3 attempts") != std::string::npos);
    }
    CHECK(network.Opened().size() == 3 && clock.slept == std::chrono::seconds(10));

    // A 12-second budget: attempts at 0, 5 and 10 s, each allowed only what is
    // left of the budget, and no delay that would end past it.
    network.opens.clear();
    config.routing.retry_count = 10;
    config.routing.connect_budget_seconds = 12;
    config.connect_timeout_seconds = 10;
    try {
        TnsClientConnection::Connect(config);
        CHECK(false && "expected the budget to run out");
    } catch (const OracleConnectError &error) {
        CHECK(error.Failure() == ConnectFailure::BUDGET_EXHAUSTED && error.Kind() == ProtocolErrorKind::TRUNCATED);
        CHECK(std::string(error.what()).find("leaves no room for RETRY_DELAY") != std::string::npos);
    }
    CHECK(network.opens.size() == 3 && network.opens[0].timeout == 10 && network.opens[1].timeout == 7 &&
          network.opens[2].timeout == 2);

    // Addresses that swallow the connect spend their whole timeout, and the
    // budget stops the list partway through.
    network.opens.clear();
    auto holes = RoutedConfig({{"h1", "h2", "h3"}});
    for (const auto *host : {"h1", "h2", "h3"}) {
        network.Script(host, 1521, {{FakeNetwork::Kind::BLACK_HOLE, {}}});
    }
    holes.routing.connect_budget_seconds = 15;
    holes.connect_timeout_seconds = 10;
    ExpectConnectFailure(ConnectFailure::BUDGET_EXHAUSTED, [&] { (void)TnsClientConnection::Connect(holes); });
    CHECK(network.Opened() == std::vector<std::string>({"h1", "h2"}));
    CHECK(network.opens[0].timeout == 10 && network.opens[1].timeout == 5);
}

static void TestCancellationStopsTheConnect() {
    FakeNetwork network;
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    ScopedOracleTransportFactory installed(network.Factory());
    auto config = RoutedConfig({{"dead"}});
    config.routing.retry_count = 5;
    config.routing.retry_delay_seconds = 5;

    bool cancelled = true;
    {
        ScopedOracleConnectCancellation cancellation([&] { return cancelled; });
        ExpectConnectFailure(ConnectFailure::CANCELLED, [&] { (void)TnsClientConnection::Connect(config); });
        CHECK(network.opens.empty());

        // Cancelled during the first retry delay: noticed within one slice.
        cancelled = false;
        clock.on_sleep = [&] { cancelled = true; };
        ExpectConnectFailure(ConnectFailure::CANCELLED, [&] { (void)TnsClientConnection::Connect(config); });
        CHECK(network.opens.size() == 1 && clock.slept == std::chrono::milliseconds(100));
    }
    // The check was this thread's, and it is gone with its scope.
    CHECK(!OracleConnectCancelled());

    // The configuration can carry its own check, which is how the DuckDB
    // adapter hands over a query's interrupt flag.
    network.opens.clear();
    auto interrupted = config;
    interrupted.connect_cancelled = [] { return true; };
    ExpectConnectFailure(ConnectFailure::CANCELLED, [&] { (void)TnsClientConnection::Connect(interrupted); });
    CHECK(network.opens.empty());
}

static void TestLoadBalanceShufflesEachConnection() {
    FakeNetwork network;
    for (const auto *host : {"a", "b", "c"}) {
        network.Answer(host, 1521, AcceptPacketBytes(false));
    }
    FakeClock clock;
    clock.random = Sequence({0, 1, 2, 0});
    ScopedOracleConnectEnvironment environment(clock.Environment());
    ScopedOracleTransportFactory installed(network.Factory());
    const auto config = RoutedConfig({{"a", "b", "c"}}, true, true);
    const auto key = ConnectionTargetKey(config);
    // Draws 0,1 give c,b,a; draws 2,0 give b,a,c. Each connection shuffles
    // afresh and the first address in its order answers.
    (void)TnsClientConnection::Connect(config);
    (void)TnsClientConnection::Connect(config);
    CHECK(network.Opened() == std::vector<std::string>({"c", "b"}));
    CHECK(ConnectionTargetKey(config) == key);
    // LOAD_BALANCE=OFF keeps the written order every time.
    network.opens.clear();
    const auto ordered = RoutedConfig({{"a", "b", "c"}});
    (void)TnsClientConnection::Connect(ordered);
    (void)TnsClientConnection::Connect(ordered);
    CHECK(network.Opened() == std::vector<std::string>({"a", "a"}));
}

// What a SCAN listener really sends back: its reconnect data echoes the
// client's own CONNECT data, so it carries this client's CONNECTION_ID — base64,
// ending in "==" and possibly holding '+' and '/' — and its CID, whose PROGRAM
// is an executable path that may contain spaces. The first release parsed that
// echo with the strict grammar meant for user-written descriptors and refused
// the '=' ("Oracle descriptor atom contains an invalid character"), which broke
// every redirected connect. Hand-written reconnect data in
// the tests above never carried either field.
static std::string EchoedConnectData(const std::string &host) {
    ConnectionConfig echoed;
    echoed.host = host;
    echoed.service_name = "svc";
    echoed.connection_id = "q0N+/Zy1AbCdEfGhIjKlMn==";
    echoed.client_program = "/Applications/My Tools/duckdb";
    return BuildConnectDescriptor(echoed);
}

static void TestListenerEchoOfTheClientsConnectData() {
    const auto reconnect = EchoedConnectData("scan.example");
    CHECK(reconnect.find("(CONNECTION_ID=q0N+/Zy1AbCdEfGhIjKlMn==)") != std::string::npos);
    CHECK(reconnect.find("/Applications/My Tools/duckdb") != std::string::npos);
    // The strict grammar still refuses it — which is right for a descriptor a
    // user typed — and the listener grammar accepts it.
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)ParseConnectDescriptor(reconnect); });
    ValidateRedirectReconnectData(reconnect);
    ValidateRedirectReconnectData("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=svc)(SERVER=dedicated)"
                                  "(CID=(PROGRAM=C:\\Program Files\\DuckDB\\duckdb.exe)(HOST=WORKSTATION)"
                                  "(USER=John Smith))(CONNECTION_ID=a+b/c==)))");
    // A redirect address given as a whole DESCRIPTION echoing the same data.
    const auto addresses =
        ParseRedirectAddresses("(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=node1-vip)(PORT=1521))"
                               "(CONNECT_DATA=(SERVICE_NAME=svc)(CONNECTION_ID=a+b/c==)))");
    CHECK(addresses.size() == 1 && addresses[0].address.host == "node1-vip");
    // Leniency covers values, not the fields that are used: a host is still
    // checked on its own, and structure is still structure.
    ExpectError(ProtocolErrorKind::MALFORMED,
                [] { (void)ParseRedirectAddresses("(ADDRESS=(PROTOCOL=TCP)(HOST=node=1)(PORT=1521))"); });
    ExpectError(ProtocolErrorKind::MALFORMED,
                [] { (void)ParseRedirectAddresses("(ADDRESS=(PROTOCOL=TCP)(HOST=node1)(PORT=15 21))"); });
    ExpectError(ProtocolErrorKind::MALFORMED,
                [] { ValidateRedirectReconnectData("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=a(b)))"); });
    ExpectError(ProtocolErrorKind::MALFORMED,
                [] { ValidateRedirectReconnectData("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=)))"); });

    // End to end: SCAN redirects with the echo as reconnect data, the node
    // accepts, and the echo is what the re-CONNECT carries, byte for byte.
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    FakeNetwork network;
    network.Answer("scan.example", 1521,
                   RedirectPacketBytes(RedirectData("(ADDRESS=(PROTOCOL=TCP)(HOST=node1-vip)(PORT=1521))", reconnect),
                                       TNS_REDIRECT_FLAG_HAS_RECONNECT_DATA));
    network.Answer("node1-vip", 1521, AcceptPacketBytes(false));
    ScopedOracleTransportFactory installed(network.Factory());
    ConnectionConfig config;
    config.host = "scan.example";
    config.service_name = "svc";
    const auto connection = TnsClientConnection::Connect(config);
    CHECK(network.Opened() == std::vector<std::string>({"scan.example", "node1-vip"}));
    const auto second = FirstConnect(network.written[1]);
    CHECK(second.flags == TNS_PACKET_FLAG_REDIRECT && second.data == reconnect);

    // And a redirect that cannot be followed says so, rather than surfacing a
    // bare parser message that reads as if the user's secret were at fault.
    network.opens.clear();
    network.Answer("scan.example", 1521, RedirectPacketBytes("(ADDRESS=(PROTOCOL=TCP)(HOST=node1)(PORT=x))"));
    try {
        (void)TnsClientConnection::Connect(config);
        CHECK(false && "expected the redirect to be refused");
    } catch (const ProtocolError &error) {
        CHECK(std::string(error.what()).find("Oracle listener sent a redirect this client could not follow") !=
              std::string::npos);
    }
}

// A node listener reached through a SCAN redirect asks for the CHECK_OOB probe and
// answers it with a CONTROL packet whose header flags are 0x24, not the 0x20
// 19c and Free send: the re-CONNECT's 0x04 redirect bit comes back with it.
// Seen live; 0.3.0 refused it as an invalid CONTROL reply. The
// type and the two-byte body are what the probe checks.
static void TestOobProbeAfterRedirectAcceptsTheRedirectFlag() {
    const auto accept_then_control = [](uint8_t flags, std::vector<uint8_t> body) {
        auto wire = AcceptPacketBytes(true);
        const auto control = EncodeTnsPacket(TnsPacketType::CONTROL, flags, body, true);
        wire.insert(wire.end(), control.begin(), control.end());
        return wire;
    };
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    FakeNetwork network;
    network.supports_urgent = true;
    network.Answer("scan", 1521, RedirectPacketBytes("(ADDRESS=(PROTOCOL=TCP)(HOST=node1)(PORT=1521))"));
    network.Answer("node1", 1521, accept_then_control(0x24, {0x00, 0x09}));
    ScopedOracleTransportFactory installed(network.Factory());
    auto connection = TnsClientConnection::Connect(RoutedConfig({{"scan"}}));
    CHECK(connection->State() == OracleConnectionState::TRANSPORT_CONNECTED);
    // The probe's reset marker went out after the re-CONNECT.
    const auto &node_bytes = network.written.back();
    const std::vector<uint8_t> reset_marker {0x01, 0x00, 0x02};
    CHECK(std::search(node_bytes.begin(), node_bytes.end(), reset_marker.begin(), reset_marker.end()) != node_bytes.end());

    // The plain 0x20 answer still works, and what the probe does check still
    // holds: a CONTROL body of the wrong width, or a reply that is not CONTROL.
    network.Answer("scan", 1521, accept_then_control(0x20, {0x00, 0x09}));
    (void)TnsClientConnection::Connect(RoutedConfig({{"scan"}}));
    network.Answer("scan", 1521, accept_then_control(0x24, {0x00, 0x09, 0x00}));
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)TnsClientConnection::Connect(RoutedConfig({{"scan"}})); });
    auto not_control = AcceptPacketBytes(true);
    const auto marker = EncodeTnsPacket(TnsPacketType::MARKER, 0x24, {0x01, 0x00, 0x02}, true);
    not_control.insert(not_control.end(), marker.begin(), marker.end());
    network.Answer("scan", 1521, not_control);
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)TnsClientConnection::Connect(RoutedConfig({{"scan"}})); });
}

// Review regressions. A redirect chain keeps every level's untried addresses:
// when one node's own redirect leads nowhere, the next node the SCAN listener
// named is still tried.
static void TestRedirectChainKeepsEachLevelsAlternatives() {
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    {
        FakeNetwork network;
        network.Answer("scan", 1521,
                       RedirectPacketBytes("(ADDRESS_LIST=(ADDRESS=(HOST=n1)(PORT=1521))(ADDRESS=(HOST=n2)(PORT=1521)))"));
        network.Answer("n1", 1521, RedirectPacketBytes("(ADDRESS=(HOST=dead)(PORT=1521))"));
        network.Answer("n2", 1521, AcceptPacketBytes(false));
        ScopedOracleTransportFactory installed(network.Factory());
        const auto connection = TnsClientConnection::Connect(RoutedConfig({{"scan"}}));
        CHECK(network.Opened() == std::vector<std::string>({"scan", "n1", "dead", "n2"}));
        CHECK(network.live == 1);
        // The accepted CONNECT went to n2 as the SCAN listener's redirect
        // directed, flagged as a re-CONNECT.
        CHECK(FirstConnect(network.written.back()).flags == TNS_PACKET_FLAG_REDIRECT);
    }
    // Two levels deep: the branch under n1 is exhausted at both of its own
    // levels before the chain returns to n2.
    {
        FakeNetwork network;
        network.Answer("scan", 1521,
                       RedirectPacketBytes("(ADDRESS_LIST=(ADDRESS=(HOST=n1)(PORT=1521))(ADDRESS=(HOST=n2)(PORT=1521)))"));
        network.Answer("n1", 1521,
                       RedirectPacketBytes("(ADDRESS_LIST=(ADDRESS=(HOST=m1)(PORT=1521))(ADDRESS=(HOST=m2)(PORT=1521)))"));
        network.Answer("m1", 1521, RefusePacketBytes(12516));
        network.Answer("n2", 1521, AcceptPacketBytes(false));
        ScopedOracleTransportFactory installed(network.Factory());
        (void)TnsClientConnection::Connect(RoutedConfig({{"scan"}}));
        CHECK(network.Opened() == std::vector<std::string>({"scan", "n1", "m1", "m2", "n2"}));
    }
    // A sibling is not a cycle: n1 redirecting to n2, which the SCAN listener
    // also offered but the chain has not visited, is followed. Only an
    // address on the chain's own path counts as looping back.
    {
        FakeNetwork network;
        network.Answer("scan", 1521,
                       RedirectPacketBytes("(ADDRESS_LIST=(ADDRESS=(HOST=n1)(PORT=1521))(ADDRESS=(HOST=n2)(PORT=1521)))"));
        network.Answer("n1", 1521, RedirectPacketBytes("(ADDRESS=(HOST=n2)(PORT=1521))"));
        network.Answer("n2", 1521, AcceptPacketBytes(false));
        ScopedOracleTransportFactory installed(network.Factory());
        (void)TnsClientConnection::Connect(RoutedConfig({{"scan"}}));
        CHECK(network.Opened() == std::vector<std::string>({"scan", "n1", "n2"}));
    }
}

// A transport whose every read costs time on the fake clock.
class SlowTransport : public ScriptedTransport {
public:
    SlowTransport(std::vector<uint8_t> input, FakeClock &clock_p, std::chrono::milliseconds per_read_p,
                  size_t chunk_p)
        : ScriptedTransport(std::move(input)), clock(clock_p), per_read(per_read_p), chunk(chunk_p) {
    }
    size_t Read(uint8_t *destination, size_t maximum_size) override {
        clock.now += per_read;
        if (on_read) {
            on_read();
        }
        return ScriptedTransport::Read(destination, (std::min)(maximum_size, chunk));
    }
    std::function<void()> on_read;

private:
    FakeClock &clock;
    std::chrono::milliseconds per_read;
    size_t chunk;
};

// The overall budget holds through the listener exchange, not only between
// attempts: an ACCEPT that arrives after it is spent does not make a
// connection, however it trickled in.
static void TestBudgetHoldsThroughTheListenerExchange() {
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    auto config = RoutedConfig({{"scan"}});
    config.routing.connect_budget_seconds = 1;
    size_t opens = 0;

    // One slow read: the whole ACCEPT, two seconds late.
    {
        ScopedOracleTransportFactory installed([&](const std::string &, uint16_t, uint32_t, uint32_t, bool,
                                                   const TlsConfiguration &) -> std::unique_ptr<ByteStream> {
            opens++;
            return std::make_unique<SlowTransport>(AcceptPacketBytes(false), clock, std::chrono::seconds(2), 4096);
        });
        ExpectConnectFailure(ConnectFailure::BUDGET_EXHAUSTED, [&] { (void)TnsClientConnection::Connect(config); });
        CHECK(opens == 1);
    }
    // A dribble: a byte at a time, each well inside any read timeout, adding
    // up to far more than the budget.
    clock.now = {};
    config.routing.connect_budget_seconds = 2;
    {
        ScopedOracleTransportFactory installed([&](const std::string &, uint16_t, uint32_t, uint32_t, bool,
                                                   const TlsConfiguration &) -> std::unique_ptr<ByteStream> {
            return std::make_unique<SlowTransport>(AcceptPacketBytes(false), clock, std::chrono::milliseconds(300), 1);
        });
        try {
            (void)TnsClientConnection::Connect(config);
            CHECK(false && "expected the budget to run out mid-exchange");
        } catch (const OracleConnectError &error) {
            CHECK(error.Failure() == ConnectFailure::BUDGET_EXHAUSTED);
            CHECK(std::string(error.what()).find("before the connection was ready") != std::string::npos);
        }
        CHECK(clock.now <= std::chrono::steady_clock::time_point {} + std::chrono::milliseconds(2300));
    }
    // A resolver that eats the budget.
    clock.now = {};
    {
        FakeNetwork network;
        network.Answer("scan", 1521, AcceptPacketBytes(false));
        ScopedOracleTransportFactory installed(network.Factory());
        ScopedOracleHostResolver resolver([&](const std::string &host, uint16_t) {
            clock.now += std::chrono::seconds(5);
            return std::vector<std::string> {host};
        });
        ExpectConnectFailure(ConnectFailure::BUDGET_EXHAUSTED, [&] { (void)TnsClientConnection::Connect(config); });
        CHECK(network.opens.empty());
    }
    // Cancellation reaches into the exchange as well.
    clock.now = {};
    config.routing.connect_budget_seconds = 60;
    {
        bool cancelled = false;
        ScopedOracleConnectCancellation cancellation([&] { return cancelled; });
        ScopedOracleTransportFactory installed([&](const std::string &, uint16_t, uint32_t, uint32_t, bool,
                                                   const TlsConfiguration &) -> std::unique_ptr<ByteStream> {
            auto transport =
                std::make_unique<SlowTransport>(AcceptPacketBytes(false), clock, std::chrono::milliseconds(1), 4);
            transport->on_read = [&] { cancelled = true; };
            return transport;
        });
        ExpectConnectFailure(ConnectFailure::CANCELLED, [&] { (void)TnsClientConnection::Connect(config); });
    }
}

// The same with the real clock: a name that takes three seconds to resolve,
// against a one-second budget, ends the connect in about one.
static void TestSlowNameResolutionIsCutOffByTheBudget() {
    ScopedOracleTransportFactory installed([](const std::string &, uint16_t, uint32_t, uint32_t, bool,
                                              const TlsConfiguration &) -> std::unique_ptr<ByteStream> {
        CHECK(false && "a transport must not be opened after the budget ran out");
        return nullptr;
    });
    ScopedOracleHostResolver resolver([](const std::string &host, uint16_t) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return std::vector<std::string> {host};
    });
    auto config = RoutedConfig({{"slow.example"}});
    config.routing.connect_budget_seconds = 1;
    const auto started = std::chrono::steady_clock::now();
    ExpectConnectFailure(ConnectFailure::BUDGET_EXHAUSTED, [&] { (void)TnsClientConnection::Connect(config); });
    const auto elapsed = std::chrono::steady_clock::now() - started;
    CHECK(elapsed >= std::chrono::milliseconds(900) && elapsed < std::chrono::milliseconds(2500));
}

// A resolver that hangs must not turn into a thread per connect. Lookups run
// on a bounded pool; connects that give up leave at most MAX_RESOLVER_WORKERS
// lookups running between them, and a lookup whose caller gave up before a
// worker took it is never run at all.
static void TestResolverWorkersAreBounded() {
    struct State {
        std::mutex lock;
        std::condition_variable changed;
        bool release = false;
        int active = 0;
        int most_active = 0;
        int started = 0;
    };
    auto state = std::make_shared<State>();
    ScopedOracleHostResolver resolver([state](const std::string &, uint16_t) {
        std::unique_lock<std::mutex> guard(state->lock);
        state->started++;
        state->active++;
        state->most_active = (std::max)(state->most_active, state->active);
        state->changed.wait(guard, [&] { return state->release; });
        state->active--;
        state->changed.notify_all();
        return std::vector<std::string> {"127.0.0.1"};
    });
    auto config = RoutedConfig({{"hanging.example"}});

    // Twelve connects in a row, each cancelled while its lookup hangs.
    for (int index = 0; index < 12; index++) {
        auto checks = std::make_shared<int>(0);
        config.connect_cancelled = [checks] { return ++*checks > 2; };
        ExpectConnectFailure(ConnectFailure::CANCELLED, [&] { (void)TnsClientConnection::Connect(config); });
    }
    CHECK(OracleResolverWorkerCount() <= MAX_RESOLVER_WORKERS);

    // Then more at once than there are workers and queue places together, each
    // with a one-second budget: every one ends on its budget, none hangs, and
    // still no more workers exist.
    config.connect_cancelled = nullptr;
    config.routing.connect_budget_seconds = 1;
    std::vector<std::thread> callers;
    std::mutex outcomes_lock;
    std::vector<ConnectFailure> outcomes;
    const auto started_at = std::chrono::steady_clock::now();
    for (size_t index = 0; index < MAX_RESOLVER_WORKERS + MAX_RESOLVER_QUEUE + 4; index++) {
        callers.emplace_back([&] {
            try {
                (void)TnsClientConnection::Connect(config);
            } catch (const OracleConnectError &error) {
                std::lock_guard<std::mutex> guard(outcomes_lock);
                outcomes.push_back(error.Failure());
            }
        });
    }
    for (auto &caller : callers) {
        caller.join();
    }
    CHECK(std::chrono::steady_clock::now() - started_at < std::chrono::milliseconds(3000));
    CHECK(outcomes.size() == callers.size());
    for (const auto failure : outcomes) {
        CHECK(failure == ConnectFailure::BUDGET_EXHAUSTED);
    }
    CHECK(OracleResolverWorkerCount() <= MAX_RESOLVER_WORKERS);

    std::unique_lock<std::mutex> guard(state->lock);
    CHECK(state->most_active <= static_cast<int>(MAX_RESOLVER_WORKERS));
    // Only lookups a worker had already taken ever ran; the rest were
    // withdrawn by the callers that gave up on them.
    CHECK(state->started <= static_cast<int>(MAX_RESOLVER_WORKERS));
    state->release = true;
    state->changed.notify_all();
    CHECK(state->changed.wait_for(guard, std::chrono::seconds(5), [&] { return state->active == 0; }));
}

// A transport that answers CONNECT with ACCEPT at once and then, when asked
// for more, spends time on the fake clock and hangs up: a server that accepted
// and then went quiet during TTC negotiation.
class QuietAfterAccept : public ScriptedTransport {
public:
    QuietAfterAccept(FakeClock &clock_p, std::function<void()> on_quiet_p = nullptr)
        : ScriptedTransport(AcceptPacketBytes(false)), clock(clock_p), on_quiet(std::move(on_quiet_p)) {
    }
    size_t Read(uint8_t *destination, size_t maximum_size) override {
        if (read_offset == input.size()) {
            clock.now += std::chrono::seconds(5);
            if (on_quiet) {
                on_quiet();
            }
            return 0;
        }
        return ScriptedTransport::Read(destination, maximum_size);
    }

private:
    FakeClock &clock;
    std::function<void()> on_quiet;
};

// The budget covers the whole establishment, not just the listener exchange:
// TTC negotiation and O5LOGON run under the same deadline and cancellation,
// until authentication completes.
static void TestBudgetHoldsUntilAuthentication() {
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    auto config = RoutedConfig({{"db"}});
    config.routing.connect_budget_seconds = 1;
    {
        ScopedOracleTransportFactory installed([&](const std::string &, uint16_t, uint32_t, uint32_t, bool,
                                                   const TlsConfiguration &) -> std::unique_ptr<ByteStream> {
            return std::make_unique<QuietAfterAccept>(clock);
        });
        auto connection = TnsClientConnection::Connect(config);
        ExpectConnectFailure(ConnectFailure::BUDGET_EXHAUSTED, [&] { (void)connection->Negotiate(); });
    }
    // Cancellation reaches negotiation too.
    clock.now = {};
    config.routing.connect_budget_seconds = 60;
    {
        bool cancelled = false;
        config.connect_cancelled = [&] { return cancelled; };
        ScopedOracleTransportFactory installed([&](const std::string &, uint16_t, uint32_t, uint32_t, bool,
                                                   const TlsConfiguration &) -> std::unique_ptr<ByteStream> {
            return std::make_unique<QuietAfterAccept>(clock, [&] { cancelled = true; });
        });
        auto connection = TnsClientConnection::Connect(config);
        ExpectConnectFailure(ConnectFailure::CANCELLED, [&] { (void)connection->Negotiate(); });
        config.connect_cancelled = nullptr;
    }
    // Once establishment is over the budget no longer applies: the same quiet
    // server is now an ordinary truncated read, whatever the clock says.
    clock.now = {};
    config.routing.connect_budget_seconds = 1;
    {
        ScopedOracleTransportFactory installed([&](const std::string &, uint16_t, uint32_t, uint32_t, bool,
                                                   const TlsConfiguration &) -> std::unique_ptr<ByteStream> {
            return std::make_unique<QuietAfterAccept>(clock);
        });
        auto connection = TnsClientConnection::Connect(config);
        connection->EndEstablishment();
        // Twice is harmless.
        connection->EndEstablishment();
        try {
            (void)connection->Negotiate();
            CHECK(false && "expected the quiet server to fail negotiation");
        } catch (const OracleConnectError &) {
            CHECK(false && "the connect budget must not apply after establishment");
        } catch (const ProtocolError &error) {
            CHECK(error.Kind() == ProtocolErrorKind::TRUNCATED);
        }
    }
    // EndEstablishment after Close touches nothing: Close frees the stream the
    // disarm callback pointed into, and has to drop the callback with it. Under
    // ASan, which the debug build uses, the old order was a heap use after free.
    {
        FakeNetwork network;
        network.Answer("db", 1521, AcceptPacketBytes(false));
        ScopedOracleTransportFactory installed(network.Factory());
        auto connection = TnsClientConnection::Connect(config);
        connection->Close();
        connection->EndEstablishment();
        connection->Close();
        CHECK(connection->State() == OracleConnectionState::CLOSED && network.live == 0);
    }
}

// The error lists what was parsed from a redirect — host, port, protocol —
// and never what the listener sent: a DESCRIPTION can carry its whole
// CONNECT_DATA, and reconnect data is connect data by definition.
static void TestRedirectTextStaysOutOfErrors() {
    FakeClock clock;
    ScopedOracleConnectEnvironment environment(clock.Environment());
    FakeNetwork network;
    network.Answer("scan", 1521,
                   RedirectPacketBytes(RedirectData("(DESCRIPTION=(ADDRESS=(HOST=dead)(PORT=1521))"
                                                    "(CONNECT_DATA=(TOKEN=PRIVATE_MARKER)))",
                                                    "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=svc)"
                                                    "(TOKEN=RECONNECT_MARKER)))")));
    ScopedOracleTransportFactory installed(network.Factory());
    try {
        (void)TnsClientConnection::Connect(RoutedConfig({{"scan"}}));
        CHECK(false && "expected the redirect target to be unreachable");
    } catch (const OracleConnectError &error) {
        const std::string message = error.what();
        CHECK(message.find("PRIVATE_MARKER") == std::string::npos);
        CHECK(message.find("RECONNECT_MARKER") == std::string::npos);
        CHECK(message.find("CONNECT_DATA") == std::string::npos);
        CHECK(message.find("redirected to dead:1521") != std::string::npos);
    }
    // Nor does a redirect that is refused while being followed leak it.
    network.Answer("scan", 1521,
                   RedirectPacketBytes("(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=node)(PORT=2484))"
                                       "(CONNECT_DATA=(TOKEN=PRIVATE_MARKER)))"));
    try {
        (void)TnsClientConnection::Connect(RoutedConfig({{"scan"}}));
        CHECK(false && "expected the protocol change to be refused");
    } catch (const OracleConnectError &error) {
        CHECK(std::string(error.what()).find("PRIVATE_MARKER") == std::string::npos);
    }
}

#if !defined(_WIN32)
// A small loopback listener: it accepts connections one after another, reads
// one TNS packet from each, keeps it, and answers with the next scripted reply.
// It is what the default transport — a real socket through OpenSSL — needs to
// be exercised end to end offline. It is a mock of the listener's first
// exchange and nothing more, not a database.
class MockListener {
public:
    // `hold` is how long each accepted connection is kept open after the
    // reply; a long hold with an empty reply is a listener that accepts the
    // TCP connection and then says nothing.
    explicit MockListener(std::vector<std::vector<uint8_t>> replies_p,
                          std::chrono::milliseconds hold_p = std::chrono::milliseconds(50))
        : replies(std::move(replies_p)), hold(hold_p) {
        listener = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(listener >= 0);
        int reuse = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        CHECK(bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
        CHECK(listen(listener, 4) == 0);
        socklen_t size = sizeof(address);
        CHECK(getsockname(listener, reinterpret_cast<sockaddr *>(&address), &size) == 0);
        port = ntohs(address.sin_port);
        worker = std::thread([this] { Serve(); });
    }
    ~MockListener() {
        if (worker.joinable()) {
            worker.join();
        }
        close(listener);
    }
    uint16_t Port() const {
        return port;
    }
    // The first packet each accepted connection sent.
    std::vector<std::vector<uint8_t>> received;

private:
    static bool ReadFully(int socket_fd, uint8_t *destination, size_t size) {
        while (size > 0) {
            const auto count = recv(socket_fd, destination, size, 0);
            if (count <= 0) {
                return false;
            }
            destination += count;
            size -= static_cast<size_t>(count);
        }
        return true;
    }
    void Serve() {
        sigset_t block;
        sigemptyset(&block);
        sigaddset(&block, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &block, nullptr);
        for (const auto &reply : replies) {
            const auto accepted = accept(listener, nullptr, nullptr);
            if (accepted < 0) {
                return;
            }
            SuppressSigPipeOnSocket(accepted);
            std::vector<uint8_t> packet(8);
            if (ReadFully(accepted, packet.data(), 8)) {
                const size_t length = (static_cast<size_t>(packet[0]) << 8U) | packet[1];
                packet.resize((std::max)(length, size_t(8)));
                if (ReadFully(accepted, packet.data() + 8, packet.size() - 8)) {
                    received.push_back(packet);
                    if (!reply.empty()) {
                        (void)send(accepted, reply.data(), reply.size(), TEST_SEND_FLAGS);
                    }
                }
            }
            // Keep the accepted connection open briefly so the client reads
            // the reply before it sees the close.
            std::this_thread::sleep_for(hold);
            close(accepted);
        }
    }

    std::vector<std::vector<uint8_t>> replies;
    std::chrono::milliseconds hold;
    int listener = -1;
    uint16_t port = 0;
    std::thread worker;
};

// The default transport against real sockets: a closed port, a listener that
// redirects, and one that accepts. The closed port has to fail at once — the
// old BIO_do_connect_retry path retried a refused connect for the whole
// timeout — and the redirect has to reach the second listener with the
// redirect flag on the wire.
static void TestLoopbackListenersFailoverAndRedirect() {
    // A port that was bound and closed without listening: connect is refused.
    int closed_socket = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(closed_socket >= 0);
    sockaddr_in closed_address {};
    closed_address.sin_family = AF_INET;
    closed_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(closed_socket, reinterpret_cast<sockaddr *>(&closed_address), sizeof(closed_address)) == 0);
    socklen_t closed_size = sizeof(closed_address);
    CHECK(getsockname(closed_socket, reinterpret_cast<sockaddr *>(&closed_address), &closed_size) == 0);
    const auto closed_port = ntohs(closed_address.sin_port);
    close(closed_socket);

    MockListener node({AcceptPacketBytes(false)});
    const auto node_address = "(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=" + std::to_string(node.Port()) + "))";
    MockListener scan({RedirectPacketBytes(node_address)});

    ConnectionConfig config;
    config.service_name = "svc";
    config.connect_timeout_seconds = 10;
    ConnectAddressList list;
    list.addresses.push_back({"127.0.0.1", closed_port, TransportProtocol::TCP});
    list.addresses.push_back({"127.0.0.1", scan.Port(), TransportProtocol::TCP});
    config.routing.address_lists.push_back(list);

    const auto started = std::chrono::steady_clock::now();
    auto connection = TnsClientConnection::Connect(config);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    CHECK(connection && connection->State() == OracleConnectionState::TRANSPORT_CONNECTED);
    // Well inside the ten-second per-attempt timeout.
    CHECK(elapsed < std::chrono::seconds(5));
    connection.reset();
    CHECK(scan.received.size() == 1 && node.received.size() == 1);
    CHECK(scan.received[0][5] == 0x00 && node.received[0][5] == TNS_PACKET_FLAG_REDIRECT);

    // A closed port alone reports UNREACHABLE promptly.
    ConnectionConfig closed_only;
    closed_only.host = "127.0.0.1";
    closed_only.port = closed_port;
    closed_only.service_name = "svc";
    const auto closed_started = std::chrono::steady_clock::now();
    ExpectConnectFailure(ConnectFailure::UNREACHABLE, [&] { (void)TnsClientConnection::Connect(closed_only); });
    CHECK(std::chrono::steady_clock::now() - closed_started < std::chrono::seconds(5));
}

// A listener that accepts the TCP connection and then never answers. With a
// 30-second read timeout and a 1-second budget the connect ends in about one
// second: the deadline reaches the socket wait itself.
static void TestSilentListenerIsBoundedByTheBudget() {
    MockListener silent({std::vector<uint8_t>()}, std::chrono::milliseconds(3000));
    ConnectionConfig config;
    config.host = "127.0.0.1";
    config.port = silent.Port();
    config.service_name = "svc";
    config.read_timeout_seconds = 30;
    config.routing.connect_budget_seconds = 1;
    const auto started = std::chrono::steady_clock::now();
    ExpectConnectFailure(ConnectFailure::BUDGET_EXHAUSTED, [&] { (void)TnsClientConnection::Connect(config); });
    const auto elapsed = std::chrono::steady_clock::now() - started;
    CHECK(elapsed >= std::chrono::milliseconds(900) && elapsed < std::chrono::milliseconds(2500));
}

// The same against a real socket and the whole native session: the server
// accepts and then says nothing. With a 30-second read timeout and a 1-second
// budget, NativeOracleSession::Connect ends in about a second, on the budget.
static void TestSilentServerAfterAcceptIsBoundedByTheBudget() {
    MockListener listener({AcceptPacketBytes(false)}, std::chrono::milliseconds(3000));
    ConnectionConfig config;
    config.host = "127.0.0.1";
    config.port = listener.Port();
    config.service_name = "synthetic";
    config.user = "placeholder";
    config.read_timeout_seconds = 30;
    config.routing.connect_budget_seconds = 1;
    const auto started = std::chrono::steady_clock::now();
    ExpectConnectFailure(ConnectFailure::BUDGET_EXHAUSTED,
                         [&] { (void)NativeOracleSession::Connect(config, "placeholder"); });
    const auto elapsed = std::chrono::steady_clock::now() - started;
    CHECK(elapsed >= std::chrono::milliseconds(900) && elapsed < std::chrono::milliseconds(2500));
}

#endif // !_WIN32

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
    challenge.verifier_type = O5LOGON_VERIFIER_12C;
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
    // Unsupported, not malformed: the response is never built for another
    // verifier, and the type is checked before anything else.
    for (const uint32_t type : {O5LOGON_VERIFIER_11G_1, O5LOGON_VERIFIER_11G_2, O5LOGON_VERIFIER_10G, uint32_t(0)}) {
        challenge.verifier_type = type;
        ExpectError(ProtocolErrorKind::UNSUPPORTED,
                    [&] { BuildO5LogonResponse("password", challenge, client_key, password_salt, speedy_key_salt); });
    }
    // A 12C challenge of the wrong shape says which lengths it had.
    challenge.verifier_type = O5LOGON_VERIFIER_12C;
    challenge.server_session_key_hex += "00112233445566778899AABBCCDDEEFF";
    try {
        (void)BuildO5LogonResponse("password", challenge, client_key, password_salt, speedy_key_salt);
        CHECK(false && "expected the session key length to be refused");
    } catch (const ProtocolError &error) {
        CHECK(error.Kind() == ProtocolErrorKind::MALFORMED);
        CHECK(std::string(error.what()).find("session key 48 bytes") != std::string::npos);
    }
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
    const auto base = TemporaryDirectory() + "/oracle_scanner_sso_" +
                      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
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

    // A wallet folder, as python-oracledb's wallet_location names one.
    const auto folder = base + "_folder";
    CHECK(std::filesystem::create_directory(folder));
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)ReadWalletIdentityPem(folder, false); });
    {
        std::ofstream output(folder + "/cwallet.sso", std::ios::binary);
        CHECK(output);
        output.write(wallet.data(), static_cast<std::streamsize>(wallet.size()));
    }
    CHECK(ReadWalletIdentityPem(folder, false) == pem);
    CHECK(ReadWalletIdentityPem(folder, true) == pem);
    {
        std::ofstream output(folder + "/ewallet.pem", std::ios::binary);
        output << plain_pem;
    }
    CHECK(ReadWalletIdentityPem(folder, false) == pem);
    CHECK(ReadWalletIdentityPem(folder, true) == plain_pem);
    std::remove((folder + "/cwallet.sso").c_str());
    std::remove((folder + "/ewallet.pem").c_str());
    std::filesystem::remove(folder);

    std::remove(sso_only_path.c_str());
    std::remove(both_path.c_str());
    std::remove(sso_file_path.c_str());
}

// Easy Connect strings and tnsnames.ora from a folder: the two ways a
// python-oracledb DSN reaches a connection without a wallet ZIP.
static void TestEasyConnectAndTnsNamesFolder() {
    const auto describe = [](const std::string &text) { return ParseConnectDescriptor(EasyConnectToDescriptor(text)); };

    auto one = describe("db.example.com/sales.example.com");
    CHECK(one.endpoints.size() == 1 && one.endpoints[0].host == "db.example.com" && one.endpoints[0].port == 1521 &&
          one.endpoints[0].protocol == TransportProtocol::TCP && one.service_name == "sales.example.com");
    one = describe("//db.example.com:1530/sales");
    CHECK(one.endpoints[0].port == 1530 && one.service_name == "sales");
    one = describe("tcps://db.example.com:2484/sales");
    CHECK(one.endpoints[0].protocol == TransportProtocol::TCPS && one.endpoints[0].port == 2484);
    one = describe("TCP://db/sales:shared/inst1");
    CHECK(one.server_type == "shared" || one.server_type == "SHARED");
    CHECK(one.instance_name == "inst1");
    one = describe("[::1]:1522/sales");
    CHECK(one.endpoints[0].host == "::1" && one.endpoints[0].port == 1522);

    const auto many = describe("a.example:1521,b.example:1522,c.example/svc?failover=off&load_balance=on&"
                               "retry_count=3&retry_delay=2&transport_connect_timeout=5&connect_timeout=40");
    CHECK(many.endpoints.size() == 3 && many.endpoints[1].host == "b.example" && many.endpoints[1].port == 1522 &&
          many.endpoints[2].port == 1521);
    CHECK(!many.failover && many.load_balance);
    CHECK(many.retry_count && *many.retry_count == 3 && many.retry_delay_seconds && *many.retry_delay_seconds == 2);
    CHECK(many.transport_connect_timeout_seconds && *many.transport_connect_timeout_seconds == 5);
    CHECK(many.connect_timeout_seconds && *many.connect_timeout_seconds == 40);

    const auto dn = describe("tcps://db.example/svc?ssl_server_cert_dn=\"CN=db.example,O=Corp\"&ssl_server_dn_match=on");
    CHECK(dn.server_cert_dn == "CN=db.example,O=Corp");

    CHECK(IsEasyConnectString("host/service") && IsEasyConnectString("host:1521") &&
          IsEasyConnectString("tcps://host/service"));
    CHECK(!IsEasyConnectString("(DESCRIPTION=)") && !IsEasyConnectString("mydb_high") && !IsEasyConnectString(""));

    // Refused by name, never dropped.
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)EasyConnectToDescriptor("db.example:1521"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)EasyConnectToDescriptor("db.example/"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)EasyConnectToDescriptor("db.example/svc name"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)EasyConnectToDescriptor("db(x)/svc"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)EasyConnectToDescriptor("db:port/svc"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)EasyConnectToDescriptor("db/svc?retry_count"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)EasyConnectToDescriptor("db/svc?ssl_server_cert_dn=a)(b"); });
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [] { (void)EasyConnectToDescriptor("http://db/svc"); });
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [] { (void)EasyConnectToDescriptor("db/svc?https_proxy=p"); });
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [] { (void)EasyConnectToDescriptor("db/svc?wallet_location=/x"); });
    ExpectError(ProtocolErrorKind::UNSUPPORTED,
                [&] { (void)describe("db/svc:pooled"); });
    ExpectError(ProtocolErrorKind::UNSUPPORTED,
                [&] { (void)ParseConnectDescriptor(EasyConnectToDescriptor("db/svc?connect_timeout=250ms")); });
    std::string too_many;
    for (size_t index = 0; index < 17; index++) {
        too_many += (index ? ",h" : "h") + std::to_string(index);
    }
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { (void)EasyConnectToDescriptor(too_many + "/svc"); });

    // tnsnames.ora from a folder, from the file itself, and from a ZIP.
    const auto base = TemporaryDirectory() + "/oracle_scanner_tnsnames_" +
                      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const std::string tnsnames =
        "# comment\nfolder_db = (DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=f.example)(PORT=1521))"
        "(CONNECT_DATA=(SERVICE_NAME=folder.example)))\n";
    CHECK(std::filesystem::create_directory(base));
    ExpectError(ProtocolErrorKind::INVALID_STATE, [&] { (void)ReadTnsNamesSource(base); });
    {
        std::ofstream output(base + "/tnsnames.ora", std::ios::binary);
        output << tnsnames;
    }
    CHECK(ReadTnsNamesSource(base) == tnsnames);
    CHECK(ReadTnsNamesSource(base + "/tnsnames.ora") == tnsnames);
    const auto parsed = ParseConnectDescriptor(FindTnsAliasDescriptor(ReadTnsNamesSource(base), "FOLDER_DB"));
    CHECK(parsed.endpoints.size() == 1 && parsed.endpoints[0].host == "f.example" && parsed.service_name == "folder.example");
    {
        std::ofstream output(base + "/nul.ora", std::ios::binary);
        output << tnsnames << '\0';
    }
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)ReadTnsNamesSource(base + "/nul.ora"); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)ReadTnsNamesSource(std::string()); });
    const auto zip_path = base + "/wallet.zip";
    WriteWalletArchiveForTest(zip_path, {{"tnsnames.ora", tnsnames}});
    CHECK(ReadTnsNamesSource(zip_path) == tnsnames);
    std::remove((base + "/tnsnames.ora").c_str());
    std::remove((base + "/nul.ora").c_str());
    std::remove(zip_path.c_str());
    std::filesystem::remove(base);
    std::cout << "easy connect and tnsnames folder ok" << std::endl;
}

// Bounded LOB prefetch: materializing a prefetched value and sizing a fetch
// batch around it. Carried over from the 2026-10-11 driver transfer's
// standalone tests, so the protocol suite covers them on every platform.
namespace lob_prefetch {

static std::vector<uint8_t> Data(bool character, uint64_t units) {
    std::vector<uint8_t> data;
    for (uint64_t i = 0; i < units; ++i) {
        if (character) {
            data.push_back(0);
        }
        data.push_back(static_cast<uint8_t>(33 + i % 90));
    }
    return data;
}

static void RoundTrip(bool character, uint64_t total, uint64_t prefix, uint64_t response_limit) {
    const auto original = Data(character, total);
    const uint64_t width = character ? 2 : 1;
    OracleLobPrefetch lob;
    lob.character = character;
    lob.total_units = total;
    lob.prefix_units = prefix;
    lob.prefix.assign(original.begin(), original.begin() + static_cast<ptrdiff_t>(prefix * width));
    lob.locator = {11, 12};
    uint64_t next = prefix + 1;
    size_t calls = 0;
    const auto result = MaterializePrefetchedOracleLob(lob, 65536, 1U << 20U,
        [&](const std::vector<uint8_t> &locator, uint64_t offset, uint64_t requested) {
            CHECK(locator == lob.locator && offset == next && requested > 0);
            CHECK(requested <= (character ? 32767U : 65536U));
            CHECK(requested <= total - offset + 1);
            ++calls;
            TtcLobResponse response;
            response.amount = (std::min)(requested, response_limit);
            const auto begin = original.begin() + static_cast<ptrdiff_t>((offset - 1) * width);
            response.data.assign(begin, begin + static_cast<ptrdiff_t>(response.amount * width));
            next += response.amount;
            return response;
        });
    CHECK(result && *result == original && next == total + 1);
    const uint64_t chunk = (std::min)(response_limit, character ? uint64_t(32767) : uint64_t(65536));
    CHECK(calls == (total - prefix + chunk - 1) / chunk);
}

template <class Work>
static void Fails(ProtocolErrorKind kind, Work work) {
    try {
        work();
    } catch (const ProtocolError &error) {
        CHECK(error.Kind() == kind);
        return;
    }
    throw std::runtime_error("invalid LOB prefetch accepted");
}

static void InvalidMetadata() {
    size_t calls = 0;
    const auto read = [&](const std::vector<uint8_t> &, uint64_t, uint64_t) {
        ++calls;
        return TtcLobResponse {};
    };
    const auto verify = [&](const OracleLobPrefetch &lob, size_t prefix_budget, size_t content_budget,
                            ProtocolErrorKind kind) {
        Fails(kind, [&] { MaterializePrefetchedOracleLob(lob, prefix_budget, content_budget, read); });
        CHECK(calls == 0);
    };
    OracleLobPrefetch lob;
    verify(lob, 0, 100, ProtocolErrorKind::MALFORMED);
    verify(lob, 65537, 100, ProtocolErrorKind::MALFORMED);
    verify(lob, 100, 0, ProtocolErrorKind::MALFORMED);
    lob.total_units = 1;
    verify(lob, 100, 100, ProtocolErrorKind::MALFORMED); // missing fallback locator
    lob.locator = {1};
    lob.prefix_units = 2;
    lob.prefix = {1, 2};
    verify(lob, 100, 100, ProtocolErrorKind::MALFORMED);
    lob.prefix_units = 1;
    lob.prefix.clear();
    verify(lob, 100, 100, ProtocolErrorKind::MALFORMED);
    lob.prefix = {1};
    lob.character = true;
    verify(lob, 100, 100, ProtocolErrorKind::MALFORMED); // odd UTF-16 byte count
    lob.prefix = {0, 1};
    verify(lob, 1, 100, ProtocolErrorKind::LIMIT_EXCEEDED);
    verify(lob, 100, 1, ProtocolErrorKind::LIMIT_EXCEEDED);
    lob.locator.resize(4097);
    verify(lob, 100, 100, ProtocolErrorKind::LIMIT_EXCEEDED);
    lob.locator = {1};
    lob.total_units = (std::numeric_limits<uint64_t>::max)();
    lob.prefix_units = 0;
    lob.prefix.clear();
    verify(lob, 100, (std::numeric_limits<size_t>::max)(), ProtocolErrorKind::LIMIT_EXCEEDED);
    lob.character = false;
    verify(lob, 100, (std::numeric_limits<size_t>::max)(), ProtocolErrorKind::LIMIT_EXCEEDED);
}

static void InvalidRemainder() {
    OracleLobPrefetch lob;
    lob.total_units = 2;
    lob.prefix_units = 1;
    lob.prefix = {1};
    lob.locator = {1};
    const auto verify = [&](const TtcLobResponse &response, ProtocolErrorKind kind) {
        size_t calls = 0;
        Fails(kind, [&] { MaterializePrefetchedOracleLob(lob, 100, 100,
            [&](const std::vector<uint8_t> &, uint64_t, uint64_t) { ++calls; return response; }); });
        CHECK(calls == 1);
    };
    verify({}, ProtocolErrorKind::TRUNCATED);
    TtcLobResponse bad;
    bad.amount = 2;
    bad.data = {1, 2};
    verify(bad, ProtocolErrorKind::MALFORMED);
    bad.amount = 1;
    verify(bad, ProtocolErrorKind::MALFORMED);
    bad.data.clear();
    verify(bad, ProtocolErrorKind::MALFORMED);
    bad.amount = (std::numeric_limits<uint64_t>::max)();
    verify(bad, ProtocolErrorKind::MALFORMED);
    size_t calls = 0;
    Fails(ProtocolErrorKind::INVALID_STATE, [&] { MaterializePrefetchedOracleLob(lob, 100, 100,
        [&](const std::vector<uint8_t> &, uint64_t, uint64_t) -> TtcLobResponse {
            ++calls;
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "closed test session");
        }); });
    CHECK(calls == 1);
}

static void UnicodeBoundary() {
    // The prefix ends at a high surrogate. Decode only after joining the
    // low surrogate and remainder, including NUL and a Japanese character.
    OracleLobPrefetch lob;
    lob.character = true;
    lob.total_units = 5;
    lob.prefix_units = 2;
    lob.prefix = {0, 'A', 0xd8, 0x3d};
    lob.locator = {1};
    const auto content = MaterializePrefetchedOracleLob(lob, 4, 10,
        [&](const std::vector<uint8_t> &, uint64_t offset, uint64_t amount) {
            CHECK(offset == 3 && amount == 3);
            TtcLobResponse response;
            response.amount = 3;
            response.data = {0xde, 0x00, 0, 0, 0x65, 0xe5};
            return response;
        });
    const std::vector<uint8_t> expected = {'A', 0xf0, 0x9f, 0x98, 0x80, 0, 0xe6, 0x97, 0xa5};
    CHECK(content && DecodeUtf16BeToUtf8(*content) == expected);
}

} // namespace lob_prefetch

static void TestLobPrefetchMaterializer() {
    using namespace lob_prefetch;
    size_t null_calls = 0;
    const auto null_value = MaterializePrefetchedOracleLob(std::nullopt, 4096, 100,
        [&](const std::vector<uint8_t> &, uint64_t, uint64_t) { ++null_calls; return TtcLobResponse {}; });
    CHECK(!null_value && null_calls == 0);
    for (bool character : {false, true}) {
        for (uint64_t total : {uint64_t(0), uint64_t(1), uint64_t(4095), uint64_t(4096), uint64_t(4097),
                               uint64_t(32767), uint64_t(32768), uint64_t(65535), uint64_t(65536),
                               uint64_t(65537), uint64_t(131073)}) {
            RoundTrip(character, total, (std::min)(total, uint64_t(4096)), 65536);
        }
        RoundTrip(character, 1, 0, 65536); // metadata-only prefix
        RoundTrip(character, 10000, 4096, 1000); // partial reads remain contiguous
        RoundTrip(character, 12000, 12000, 65536); // entire value: zero LOB calls
    }
    InvalidMetadata();
    InvalidRemainder();
    UnicodeBoundary();
}

static void TestLobPrefetchScalarBudget() {
    OracleColumn lob;
    lob.oracle_type = 112;
    lob.character_set_form = 1;
    OracleColumn text;
    text.oracle_type = 1;
    text.character_set_form = 1;
    text.byte_width = 4000;
    OracleLobPrefetchLimits limits;
    std::vector<OracleColumn> columns(240, text);
    columns.push_back(lob);
    CHECK(BoundedLobPrefetchRows(columns, 128, limits) == 4);
    columns.insert(columns.end(), 40, text);
    bool refused = false;
    try { BoundedLobPrefetchRows(columns, 2, limits); }
    catch (const ProtocolError &error) { refused = error.Kind() == ProtocolErrorKind::LIMIT_EXCEEDED; }
    CHECK(refused);
    text.byte_width = 0;
    CHECK(BoundedLobPrefetchRows({lob, text}, 128, limits) == 29);
    text.omitted_from_row_data = true;
    CHECK(BoundedLobPrefetchRows({lob, text}, 128, limits) == 128);
    text.omitted_from_row_data = false;
    text.byte_width = (std::numeric_limits<uint32_t>::max)();
    refused = false;
    try { BoundedLobPrefetchRows({lob, text}, 2, limits); }
    catch (const ProtocolError &error) { refused = error.Kind() == ProtocolErrorKind::LIMIT_EXCEEDED; }
    CHECK(refused);
}

// A prefetched LOB batch arrives in fragments as a scalar fetch does, and the
// decoder resumes after the last finished row. The result, and the batch byte
// budget, must be exactly what one pass over the joined response gives.
static void TestLobPrefetchDecoderResumes() {
    OracleColumn text;
    text.name = "T";
    text.oracle_type = 1;
    text.character_set_form = 1;
    text.byte_width = 16;
    OracleColumn blob;
    blob.name = "B";
    blob.oracle_type = 113;
    const std::vector<OracleColumn> columns = {text, blob};
    const auto blob_cell = [](ByteWriter &writer, const std::vector<uint8_t> &prefix, bool with_prefix) {
        const std::vector<uint8_t> locator = {0x11, 0x22, 0x33};
        writer.WriteUB4(static_cast<uint32_t>(locator.size())).WriteUB8(prefix.size()).WriteUB4(0);
        if (with_prefix) {
            writer.WriteLengthPrefixed(prefix);
        }
        writer.WriteLengthPrefixed(locator);
    };

    OracleLobPrefetchLimits limits;
    ByteWriter response;
    for (uint8_t row = 1; row <= 5; row++) {
        response.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(std::vector<uint8_t>(row, 't'));
        blob_cell(response, std::vector<uint8_t>(row * 3U, row), true);
        // Only the text changes, then only the BLOB, in both count forms.
        response.WriteByte(21).WriteUInt16LE(1).WriteByte(0x01);
        response.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(std::vector<uint8_t> {'u', row});
        response.WriteByte(21).WriteUB2(1).WriteByte(0x02);
        response.WriteByte(TTC_MESSAGE_ROW_DATA).WriteUB4(0);
    }
    // A repeated row, then a row header waiting over a continuation.
    response.WriteByte(6).WriteByte(0).WriteUB2(0).WriteUB4(0).WriteUB4(0).WriteUB2(0);
    response.WriteUB4(1).WriteLengthPrefixed(std::vector<uint8_t> {0x00}).WriteUB4(0);
    response.WriteByte(TTC_MESSAGE_ROW_DATA);
    response.WriteByte(6).WriteByte(0).WriteUB2(0).WriteUB4(0).WriteUB4(0).WriteUB2(0);
    response.WriteUB4(1).WriteLengthPrefixed(std::vector<uint8_t> {0x02}).WriteUB4(0);
    response.WriteByte(21).WriteUInt16LE(1).WriteByte(0x01);
    response.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(std::vector<uint8_t> {'h'});
    response.WriteByte(TTC_MESSAGE_ROW_DATA);
    blob_cell(response, {9, 9}, true);
    response.WriteByte(9).WriteUB4(0).WriteUB2(0);
    const auto &bytes = response.Data();

    const auto expected = DecodeLobPrefetchFetchResponse(bytes, columns, limits);
    CHECK(expected.completed && expected.bytes_consumed == bytes.size() && expected.rows.size() == 18 &&
           expected.used_row_header_selection && expected.used_row_continuation);
    CHECK(expected.rows[0][0].value() == std::vector<uint8_t>({'t'}) && expected.rows[0][1].has_value() &&
           expected.rows[1][1] == expected.rows[0][1] && !expected.rows[2][1] &&
           expected.rows[2][0].value() == std::vector<uint8_t>({'u', 1}));
    CHECK(expected.rows[15] == expected.rows[14] && expected.rows[16][0].value() == std::vector<uint8_t>({'h'}) &&
           !expected.rows[16][1] && expected.rows[17][1].has_value());

    for (size_t step = 1; step <= 17; step++) {
        LobPrefetchFetchResponseDecoder decoder(columns, limits, 12, std::nullopt);
        bool complete = false;
        for (size_t size = (std::min)(step, bytes.size());; size = (std::min)(size + step, bytes.size())) {
            const std::vector<uint8_t> received(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(size));
            try {
                complete = decoder.Decode(received);
            } catch (const ProtocolError &error) {
                CHECK(error.Kind() == ProtocolErrorKind::TRUNCATED);
            }
            if (complete || size == bytes.size()) {
                break;
            }
        }
        CHECK(complete);
        const auto resumed = decoder.Take();
        CHECK(resumed.rows == expected.rows && resumed.last_row == expected.last_row &&
               resumed.bytes_consumed == expected.bytes_consumed &&
               resumed.used_row_header_selection == expected.used_row_header_selection &&
               resumed.used_row_continuation == expected.used_row_continuation);
    }

    // The batch budget spans the whole response, not one fragment of it: rows
    // of 250-byte text overrun a 4200-byte batch however they are split.
    OracleLobPrefetchLimits tight;
    tight.prefix_units = 0;
    tight.maximum_row_bytes = 4200;
    tight.maximum_batch_bytes = 4200;
    ByteWriter large;
    for (size_t row = 0; row < 20; row++) {
        large.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(std::vector<uint8_t>(250, 'w'));
        blob_cell(large, {}, false);
    }
    large.WriteByte(9).WriteUB4(0).WriteUB2(0);
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { (void)DecodeLobPrefetchFetchResponse(large.Data(), columns, tight); });
    for (const size_t step : {size_t {1}, size_t {97}, size_t {1000}}) {
        LobPrefetchFetchResponseDecoder decoder(columns, tight, 12, std::nullopt);
        bool refused = false;
        for (size_t size = step;; size = (std::min)(size + step, large.Data().size())) {
            const std::vector<uint8_t> received(large.Data().begin(),
                                                large.Data().begin() + static_cast<std::ptrdiff_t>(size));
            try {
                (void)decoder.Decode(received);
            } catch (const ProtocolError &error) {
                refused = error.Kind() == ProtocolErrorKind::LIMIT_EXCEEDED;
                CHECK(refused || error.Kind() == ProtocolErrorKind::TRUNCATED);
            }
            if (refused || size == large.Data().size()) {
                break;
            }
        }
        CHECK(refused);
    }
}

// The attached catalog's pool of transaction sessions. A fake session here
// records every statement it is sent, so a test can show which ones reached
// it, and can die while idle, the way a session killed on the server does.
namespace transaction_pool {

struct Log {
    std::vector<std::string> statements;
    size_t closes = 0;
};

class OneRowCursor final : public OracleCursor {
public:
    const std::vector<OracleColumn> &Columns() const override {
        return columns;
    }
    OracleBatch Fetch(size_t) override {
        OracleBatch batch;
        batch.rows.push_back({EncodeOracleNumber("1")});
        batch.exhausted = true;
        return batch;
    }
    void Close() override {
    }
    void Cancel() override {
    }

private:
    std::vector<OracleColumn> columns;
};

struct SessionState {
    int id = 0;
    bool dead = false;
    bool reusable = true;
    bool bindable = true;
    bool closed = false;
    std::vector<std::shared_ptr<OracleIoDeadline>> bound;
};

// Owned only by the pool and the code under test, as a real session is; what a
// test observes lives in SessionState, so the test holds no extra reference
// that would make every session look borrowed.
class PoolSession final : public TestSession {
public:
    PoolSession(std::shared_ptr<Log> log_p, std::shared_ptr<SessionState> state_p)
        : log(std::move(log_p)), state(std::move(state_p)) {
    }
    std::unique_ptr<OracleCursor> Query(const std::string &sql, const std::vector<OracleBind> &) override {
        log->statements.push_back(std::to_string(state->id) + ":" + sql);
        if (state->dead) {
            throw ProtocolError(ProtocolErrorKind::TRUNCATED, "Oracle TCP connection closed");
        }
        return std::make_unique<OneRowCursor>();
    }
    uint64_t Execute(const std::string &sql, const std::vector<OracleBind> &) override {
        log->statements.push_back(std::to_string(state->id) + ":" + sql);
        if (state->dead) {
            throw ProtocolError(ProtocolErrorKind::TRUNCATED, "Oracle TCP connection closed");
        }
        return 1;
    }
    void Close() override {
        log->closes++;
        state->closed = true;
    }
    bool ReadyForReuse() const override {
        return state->reusable && !state->closed;
    }
    bool BindIoDeadline(std::shared_ptr<OracleIoDeadline> source) override {
        state->bound.push_back(source);
        return state->bindable;
    }

    std::shared_ptr<Log> log;
    std::shared_ptr<SessionState> state;
};

int Id(const std::shared_ptr<OracleSession> &session) {
    return static_cast<PoolSession &>(*session).state->id;
}

struct Fixture {
    std::shared_ptr<Log> log = std::make_shared<Log>();
    std::vector<std::shared_ptr<SessionState>> opened;
    std::vector<std::shared_ptr<OracleIoDeadlineBinding>> bindings;
    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
    bool fail_open = false;

    std::shared_ptr<OracleTransactionSessionPool> Pool(size_t maximum_idle) {
        return std::make_shared<OracleTransactionSessionPool>(
            maximum_idle,
            [this](std::shared_ptr<OracleIoDeadlineBinding> binding) -> std::shared_ptr<OracleSession> {
                if (fail_open) {
                    throw ProtocolError(ProtocolErrorKind::TRUNCATED, "Oracle listener unreachable");
                }
                bindings.push_back(binding);
                auto state = std::make_shared<SessionState>();
                state->id = static_cast<int>(opened.size());
                opened.push_back(state);
                return std::make_shared<PoolSession>(log, state);
            },
            OracleTransactionSessionPool::SelectFromDual, std::chrono::seconds(300), [this] { return now; });
    }
};

} // namespace transaction_pool

// A session comes back after a confirmed end only, and is then handed to the
// next transaction instead of a fresh connect.
static void TestTransactionPoolReusesAfterAConfirmedEnd() {
    using namespace transaction_pool;
    Fixture fixture;
    auto pool = fixture.Pool(2);
    auto first = pool->Acquire(nullptr);
    CHECK(fixture.opened.size() == 1);
    CHECK(pool->Release(std::move(first)));
    auto second = pool->Acquire(nullptr);
    CHECK(fixture.opened.size() == 1 && Id(second) == 0);
    // The probe is the only thing the reused session was sent before it was
    // handed out: nothing of the next transaction.
    CHECK(fixture.log->statements.size() == 1 && fixture.log->statements[0] == "0:SELECT 1 FROM DUAL");
    const auto counters = pool->Counters();
    CHECK(counters.opened == 1 && counters.reused == 1 && counters.returned == 1 && counters.leased == 1);
    CHECK(pool->Release(std::move(second)));
}

// What must never be reused is closed instead: a session that says it is not
// clean, one somebody else still holds, one that cannot follow a new caller's
// deadline, and one discarded outright.
static void TestTransactionPoolClosesWhatIsNotClean() {
    using namespace transaction_pool;
    Fixture fixture;
    auto pool = fixture.Pool(4);

    auto dirty = pool->Acquire(nullptr);
    fixture.opened.back()->reusable = false;
    CHECK(!pool->Release(std::move(dirty)));
    CHECK(fixture.opened[0]->closed);

    auto shared = pool->Acquire(nullptr);
    const auto borrower = shared;
    (void)borrower;
    CHECK(!pool->Release(std::move(shared)));
    CHECK(fixture.opened[1]->closed);

    auto unbindable = pool->Acquire(nullptr);
    fixture.opened.back()->bindable = false;
    CHECK(!pool->Release(std::move(unbindable)));
    CHECK(fixture.opened[2]->closed);

    auto poisoned = pool->Acquire(nullptr);
    pool->Discard(std::move(poisoned));
    CHECK(fixture.opened[3]->closed);

    CHECK(pool->Counters().idle == 0 && pool->Counters().leased == 0);
    auto fresh = pool->Acquire(nullptr);
    CHECK(fixture.opened.size() == 5 && pool->Counters().reused == 0);
    pool->Discard(std::move(fresh));
}

// A session killed while it sat idle fails its probe and is replaced before
// the transaction sends anything; the dead session saw the probe and nothing
// else, so no statement of the transaction can have run twice.
static void TestTransactionPoolReplacesASessionThatDiedIdle() {
    using namespace transaction_pool;
    Fixture fixture;
    auto pool = fixture.Pool(2);
    auto first = pool->Acquire(nullptr);
    CHECK(pool->Release(std::move(first)));
    fixture.opened[0]->dead = true;

    auto replacement = pool->Acquire(nullptr);
    CHECK(fixture.opened.size() == 2 && Id(replacement) == 1);
    CHECK(fixture.opened[0]->closed);
    CHECK(fixture.log->statements.size() == 1 && fixture.log->statements[0] == "0:SELECT 1 FROM DUAL");
    CHECK(pool->Counters().probe_failures == 1);

    // Once handed out, a failure is the transaction's: the pool does not
    // retry anything, it only learns the outcome when the caller discards it.
    fixture.opened[1]->dead = true;
    bool failed = false;
    try {
        replacement->Execute("INSERT INTO t VALUES (1)", {});
    } catch (const ProtocolError &error) {
        failed = error.Kind() == ProtocolErrorKind::TRUNCATED;
    }
    CHECK(failed);
    pool->Discard(std::move(replacement));
    size_t inserts = 0;
    for (const auto &statement : fixture.log->statements) {
        inserts += statement.find("INSERT") != std::string::npos ? 1 : 0;
    }
    CHECK(inserts == 1 && fixture.opened.size() == 2);

    // A failure to open is reported, and leaves nothing leased.
    fixture.fail_open = true;
    bool refused = false;
    try {
        (void)pool->Acquire(nullptr);
    } catch (const ProtocolError &error) {
        refused = error.Kind() == ProtocolErrorKind::TRUNCATED;
    }
    CHECK(refused && pool->Counters().leased == 0);
}

// Bounded: never more idle sessions than its size, none idle longer than its
// limit, and none at all once its owner closes it.
static void TestTransactionPoolIsBounded() {
    using namespace transaction_pool;
    Fixture fixture;
    auto pool = fixture.Pool(2);
    auto a = pool->Acquire(nullptr);
    auto b = pool->Acquire(nullptr);
    auto c = pool->Acquire(nullptr);
    CHECK(pool->Counters().leased == 3);
    CHECK(pool->Release(std::move(a)) && pool->Release(std::move(b)));
    CHECK(!pool->Release(std::move(c)));
    CHECK(pool->Counters().idle == 2 && fixture.opened[2]->closed);

    fixture.now += std::chrono::seconds(301);
    auto after_idle_limit = pool->Acquire(nullptr);
    CHECK(fixture.opened.size() == 4 && fixture.opened[0]->closed && fixture.opened[1]->closed);
    CHECK(pool->Release(std::move(after_idle_limit)));

    pool->Close();
    CHECK(fixture.opened[3]->closed && pool->Counters().idle == 0);
    auto after_close = pool->Acquire(nullptr);
    CHECK(!pool->Release(std::move(after_close)));
    CHECK(fixture.opened.back()->closed);

    auto disabled = fixture.Pool(0);
    auto only = disabled->Acquire(nullptr);
    CHECK(!disabled->Release(std::move(only)));
}

// Each lease follows its own caller's deadline, and a returned session
// follows nobody's. The binding is what the transport reads, so a deadline set
// by the current caller reaches the socket, and the previous caller's no
// longer does.
static void TestTransactionPoolFollowsEachCallersDeadline() {
    using namespace transaction_pool;
    Fixture fixture;
    auto pool = fixture.Pool(2);
    auto first_caller = std::make_shared<OracleIoDeadline>();
    auto second_caller = std::make_shared<OracleIoDeadline>();
    auto session = pool->Acquire(first_caller);
    CHECK(fixture.bindings.size() == 1);
    auto &binding = *fixture.bindings[0];
    CHECK(binding.Bound());
    const auto soon = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    first_caller->Set(soon);
    CHECK(binding.Get() == OracleIoDeadline::Deadline(soon));
    CHECK(pool->Release(std::move(session)));
    CHECK(fixture.opened[0]->bound.back() == nullptr);

    auto reused = pool->Acquire(second_caller);
    CHECK(fixture.opened[0]->bound.back() == second_caller);
    pool->Discard(std::move(reused));

    // The binding itself: rebinding moves the deadline the stream enforces.
    auto bound = std::make_shared<OracleIoDeadlineBinding>(first_caller);
    CHECK(bound->Get() == OracleIoDeadline::Deadline(soon));
    bound->Bind(second_caller);
    CHECK(!bound->Get());
    second_caller->Set(std::chrono::steady_clock::now() - std::chrono::seconds(1));
    class Sink final : public ByteStream {
    public:
        size_t Read(uint8_t *, size_t) override {
            return 0;
        }
        size_t Write(const uint8_t *, size_t size) override {
            return size;
        }
        void Close() override {
        }
    };
    OracleBoundDeadlineStream stream(std::make_unique<Sink>(), bound);
    const uint8_t byte = 0;
    bool expired = false;
    try {
        (void)stream.Write(&byte, 1);
    } catch (const ProtocolError &error) {
        expired = error.Kind() == ProtocolErrorKind::TRUNCATED;
    }
    CHECK(expired);
    bound->Bind(nullptr);
    CHECK(stream.Write(&byte, 1) == 1);
}

// The whole response to a LOB read: data, return parameter and the end-of-call
// behind them. A response is complete only with all three, so a response cut
// anywhere — inside the data, exactly before the end-of-call, inside it —
// reads as TRUNCATED and never as success. That last case is what a CLOB of
// 8069 characters met live on 19c and Free: the data and the parameter fit
// one packet, the end-of-call did not, and its remainder was decoded as if the
// message had ended.
namespace lob_completion {

// The live 19c CLOB read of TestLobReadResponseIsUtf16ForAClob: ten Cyrillic
// characters, the return parameter, and a 19c end-of-call (field version 12).
std::vector<uint8_t> LiveClobRead() {
    return {0x0e, 0xfe, 0x01, 0x14, 0x04, 0x3f, 0x04, 0x40, 0x04, 0x38, 0x04, 0x32, 0x04, 0x35, 0x04, 0x42, 0x00, 0x20,
            0x04, 0x3c, 0x04, 0x38, 0x04, 0x40, 0x00, 0x08, 0x00, 0x70, 0x00, 0x02, 0x02, 0x0c, 0x82, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x7e, 0x3f, 0x00, 0x01, 0x24, 0x91, 0x00, 0x01, 0x24, 0x90,
            0x00, 0x02, 0x00, 0x02, 0x03, 0x69, 0x6d, 0xb1, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x55, 0xbe, 0x13,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x00, 0x22, 0x00, 0x00, 0x00, 0x01,
            0x00, 0xf6, 0xfe, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x24, 0x90, 0x00, 0x40, 0x86, 0xe9, 0x00, 0x03, 0x01, 0x0a, 0x04, 0x01,
            0x01, 0x02, 0x32, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
}

// The same response up to and including its return parameter.
std::vector<uint8_t> LobPart() {
    const auto whole = LiveClobRead();
    const auto decoded = DecodeTtcLobResponse(whole, 114);
    return std::vector<uint8_t>(whole.begin(), whole.begin() + static_cast<std::ptrdiff_t>(decoded.bytes_consumed));
}

// An end-of-call as a field-version-12 server writes one; nonzero errors carry
// their text, as in TestTtcErrorCarriesTheFailingIteration.
std::vector<uint8_t> EndOfCall(uint32_t error_number, const std::string &text = std::string()) {
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_ERROR).WriteUB4(error_number ? 2 : 0).WriteUB2(0).WriteUB4(0);
    writer.WriteUB2(error_number ? 1 : 0).WriteUB2(0).WriteUB2(0).WriteUB4(0).WriteUB4(0);
    writer.WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0);
    writer.WriteUB4(0).WriteUB2(0).WriteByte(0).WriteUB4(0).WriteUB2(0);
    writer.WriteUB4(0);
    writer.WriteByte(0).WriteByte(0).WriteUB2(0);
    writer.WriteUB4(0).WriteUB4(0);
    writer.WriteByte(0).WriteByte(0).WriteByte(0);
    writer.WriteUB4(error_number).WriteUB8(0);
    if (error_number) {
        writer.WriteLengthPrefixed(std::vector<uint8_t>(text.begin(), text.end()));
    }
    return writer.Data();
}

std::vector<uint8_t> Concat(std::vector<uint8_t> left, const std::vector<uint8_t> &right) {
    left.insert(left.end(), right.begin(), right.end());
    return left;
}

void ExpectOracleError(uint32_t code, const std::function<void()> &work) {
    try {
        work();
    } catch (const ProtocolError &error) {
        CHECK(error.Kind() == ProtocolErrorKind::INVALID_STATE && error.OracleCode() == code);
        return;
    }
    CHECK(false && "expected an Oracle error");
}

// A server end of the channel: every inbound message as its own TTC message,
// optionally stopping early; what the client sent is kept to count requests.
struct ScriptedLobServer {
    explicit ScriptedLobServer(const std::vector<std::vector<uint8_t>> &messages) {
        for (const auto &message : messages) {
            for (const auto &packet : EncodeTnsDataPackets(message, true, 2048)) {
                wire.insert(wire.end(), packet.begin(), packet.end());
            }
        }
    }
    size_t Requests(FragmentedStream &stream) const {
        FragmentedStream sent_stream(stream.output, 7);
        TnsPacketStream sent_packets(sent_stream, true, 2048);
        size_t requests = 0;
        while (sent_stream.read_offset < sent_stream.input.size()) {
            const auto packet = sent_packets.Receive();
            requests += packet.type == TnsPacketType::DATA ? 1 : 0;
        }
        return requests;
    }
    std::vector<uint8_t> wire;
};

TtcLobRequest ReadRequest() {
    TtcLobRequest request;
    request.sequence = 3;
    request.locator.assign(114, 0x11);
    request.operation = LOB_OP_READ;
    request.offset = 1;
    request.amount = 10;
    return request;
}

TtcLobResponse Run(FragmentedStream &stream) {
    TnsPacketStream packets(stream, true, 2048);
    TtcChannel channel(packets, 2048);
    OracleStatementRegistry registry;
    TtcStatementChannel statements(channel, registry);
    return statements.LobOperation(ReadRequest(), 12);
}

} // namespace lob_completion

static void TestLobCallIsCompleteOnlyWithItsEndOfCall() {
    using namespace lob_completion;
    const auto whole = LiveClobRead();
    const auto decoded = DecodeCompleteTtcLobCall(whole, 114, 12);
    CHECK(decoded.amount == 10 && decoded.data.size() == 20 && decoded.bytes_consumed == whole.size());
    // Every cut, including exactly at the end of the return parameter, which
    // the decoder used to accept as the whole response.
    CHECK(LobPart().size() < whole.size());
    for (size_t length = 1; length < whole.size(); length++) {
        const std::vector<uint8_t> partial(whole.begin(), whole.begin() + static_cast<std::ptrdiff_t>(length));
        ExpectError(ProtocolErrorKind::TRUNCATED, [&] { (void)DecodeCompleteTtcLobCall(partial, 114, 12); });
    }
    ExpectError(ProtocolErrorKind::TRUNCATED, [] { (void)DecodeCompleteTtcLobCall({}, 114, 12); });
    // STATUS and END_OF_REQUEST end a call as they do for fetch and PL/SQL.
    CHECK(DecodeCompleteTtcLobCall(Concat(LobPart(), {TTC_MESSAGE_STATUS, 0, 0}), 114, 12).amount == 10);
    CHECK(DecodeCompleteTtcLobCall(Concat(LobPart(), {29}), 114, 12).amount == 10);
}

static void TestLobCallRefusalsKeepTheirOracleError() {
    using namespace lob_completion;
    const auto refusal = EndOfCall(22922, "ORA-22922: nonexistent LOB value\n");
    CHECK(DecodeTtcErrorPrefix(refusal, 12).error_number == 22922);
    // A refusal alone, and a refusal after data: the server's own number.
    ExpectOracleError(22922, [&] { (void)DecodeCompleteTtcLobCall(refusal, 114, 12); });
    ExpectOracleError(22922, [&] { (void)DecodeCompleteTtcLobCall(Concat(LobPart(), refusal), 114, 12); });
    // Cut short, either is still only incomplete.
    for (size_t length = 1; length < refusal.size(); length++) {
        const std::vector<uint8_t> partial(refusal.begin(), refusal.begin() + static_cast<std::ptrdiff_t>(length));
        ExpectError(ProtocolErrorKind::TRUNCATED, [&] { (void)DecodeCompleteTtcLobCall(partial, 114, 12); });
        ExpectError(ProtocolErrorKind::TRUNCATED,
                    [&] { (void)DecodeCompleteTtcLobCall(Concat(LobPart(), partial), 114, 12); });
    }
    // Something other than an end-of-call after the parameter is not a reason
    // to wait for more: it is not a LOB response.
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)DecodeCompleteTtcLobCall(Concat(LobPart(), {0x63}), 114, 12); });
    ExpectError(ProtocolErrorKind::MALFORMED,
                [] { (void)DecodeCompleteTtcLobCall(Concat(LobPart(), {TTC_MESSAGE_LOB_DATA, 0}), 114, 12); });
}

static void TestLobOperationReadsTheWholeResponse() {
    using namespace lob_completion;
    const auto lob = LobPart();
    const auto end = EndOfCall(0);
    // The end-of-call in a message of its own, and then split in two: the
    // operation reads on, and sends its request exactly once.
    for (const auto &messages : std::vector<std::vector<std::vector<uint8_t>>> {
             {lob, end},
             {lob, std::vector<uint8_t>(end.begin(), end.begin() + 9), std::vector<uint8_t>(end.begin() + 9, end.end())},
             {std::vector<uint8_t>(lob.begin(), lob.begin() + 30), std::vector<uint8_t>(lob.begin() + 30, lob.end()), end},
             // The 8069-character case: data, parameter and the start of the
             // end-of-call in one message, the rest of it in the next.
             {Concat(lob, std::vector<uint8_t>(end.begin(), end.begin() + 9)), std::vector<uint8_t>(end.begin() + 9, end.end())}}) {
        ScriptedLobServer server(messages);
        FragmentedStream stream(server.wire, 5);
        const auto decoded = Run(stream);
        CHECK(decoded.amount == 10 && DecodeUtf16BeToUtf8(decoded.data).size() == 19);
        CHECK(server.Requests(stream) == 1);
        // And the end-of-call was read: nothing of this call is left in the
        // channel for the next one to trip over.
        CHECK(stream.read_offset == stream.input.size());
    }
    // A refusal in its own message keeps its number.
    {
        ScriptedLobServer server({lob, EndOfCall(22922, "ORA-22922: nonexistent LOB value\n")});
        FragmentedStream stream(server.wire, 5);
        ExpectOracleError(22922, [&] { (void)Run(stream); });
        CHECK(server.Requests(stream) == 1);
    }
    // The transport ends before the end-of-call: an error, not a success and
    // not a second request.
    {
        ScriptedLobServer server({lob});
        FragmentedStream stream(server.wire, 5);
        ExpectError(ProtocolErrorKind::TRUNCATED, [&] { (void)Run(stream); });
        CHECK(server.Requests(stream) == 1);
    }
    // A response that never completes is bounded by the message limit.
    {
        std::vector<std::vector<uint8_t>> messages = {{TTC_MESSAGE_LOB_DATA, 0xfe}};
        for (size_t index = 0; index < 4100; index++) {
            std::vector<uint8_t> chunk = {0x01, 0x14};
            chunk.insert(chunk.end(), 20, 0x00);
            messages.push_back(chunk);
        }
        ScriptedLobServer server(messages);
        FragmentedStream stream(server.wire, 4096);
        ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { (void)Run(stream); });
        CHECK(server.Requests(stream) == 1);
    }
}

// The caller's deadline expiring while the end-of-call is still to come ends
// the operation with that error; nothing is sent again.
static void TestLobOperationObeysTheDeadlineMidResponse() {
    using namespace lob_completion;
    class ExpiringStream final : public FragmentedStream {
    public:
        ExpiringStream(std::vector<uint8_t> wire, size_t first_message, std::shared_ptr<OracleIoDeadline> source_p)
            : FragmentedStream(std::move(wire), 5), boundary(first_message), source(std::move(source_p)) {
        }
        size_t Read(uint8_t *destination, size_t maximum_size) override {
            if (read_offset >= boundary) {
                source->Set(std::chrono::steady_clock::now() - std::chrono::seconds(1));
            }
            return FragmentedStream::Read(destination, maximum_size);
        }
        size_t boundary;
        std::shared_ptr<OracleIoDeadline> source;
    };
    const auto lob = LobPart();
    ScriptedLobServer first({lob});
    ScriptedLobServer server({lob, EndOfCall(0)});
    auto source = std::make_shared<OracleIoDeadline>();
    auto inner = std::make_unique<ExpiringStream>(server.wire, first.wire.size(), source);
    auto &raw = *inner;
    OracleBoundDeadlineStream stream(std::move(inner), std::make_shared<OracleIoDeadlineBinding>(source));
    TnsPacketStream packets(stream, true, 2048);
    TtcChannel channel(packets, 2048);
    OracleStatementRegistry registry;
    TtcStatementChannel statements(channel, registry);
    bool expired = false;
    try {
        (void)statements.LobOperation(ReadRequest(), 12);
    } catch (const ProtocolError &error) {
        expired = error.Kind() == ProtocolErrorKind::TRUNCATED &&
                  std::string(error.what()).find("deadline expired") != std::string::npos;
    }
    CHECK(expired);
    CHECK(server.Requests(raw) == 1);
}

// BOOLEAN, TIMESTAMP WITH LOCAL TIME ZONE, and the binds that write national
// text, intervals and BOOLEAN. Recorded from Free 23ai (the server's values)
// and from python-oracledb 4.0.1 Thin against Free (its bind metadata and
// values); PROVENANCE.md lists them with hashes.
//
// boolean_value_bytes: the values a 23ai server sends for type 252, TRUE then
//     FALSE, to a client advertising TTC field version 17.
// ltz_value_bytes: a TIMESTAMP(6) WITH LOCAL TIME ZONE, 2026-03-04
//     05:06:07.123456, read from a session whose time zone is +00:00.
// python_*_bind: the bind metadata and value python-oracledb sent for an
//     NCHAR 'ab', an NVARCHAR2 N'Zq<e acute><CJK>', a BOOLEAN TRUE and an
//     INTERVAL DAY TO SECOND '3 4:5:6.000007'. Each starts at the bind's type
//     byte and ends with its value; its buffer size is python's own, which is
//     larger than the value, so the test swaps in this client's.
static void TestBooleanLocalZoneAndWrites() {
    const std::vector<uint8_t> boolean_value_bytes {0x01, 0x00};
    const std::vector<uint8_t> ltz_value_bytes {0x78, 0x7e, 0x03, 0x04, 0x06, 0x07, 0x08, 0x07, 0x5b, 0xca, 0x00};
    const std::vector<uint8_t> python_nchar_bind {
        0x60, 0x01, 0x00, 0x00, 0x02, 0x1f, 0x40, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x69, 0x02, 0x00, 0x00,
        0x07, 0x04, 0x00, 0x61, 0x00, 0x62
    };
    const std::vector<uint8_t> python_nvarchar_bind {
        0x01, 0x01, 0x00, 0x00, 0x02, 0x3e, 0x80, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x69, 0x02, 0x00, 0x00,
        0x07, 0x08, 0x00, 0x5a, 0x00, 0x71, 0x00, 0xe9, 0x4e, 0x2d
    };
    const std::vector<uint8_t> python_boolean_bind {
        0xfc, 0x01, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x02, 0x01, 0x01
    };
    const std::vector<uint8_t> python_interval_ds_bind {
        0xb7, 0x01, 0x00, 0x00, 0x01, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x0b, 0x80, 0x00,
        0x00, 0x03, 0x40, 0x41, 0x42, 0x80, 0x00, 0x1b, 0x58
    };

    // Reading: the last byte says which, and the LTZ value is an ordinary
    // TIMESTAMP with no offset, which the UTC session makes an instant.
    CHECK(boolean_value_bytes[0] == 1 && boolean_value_bytes[1] == 0);
    const auto ltz = DecodeOracleTimestamp(ltz_value_bytes);
    CHECK(!ltz.has_offset && ltz.year == 2026 && ltz.month == 3 && ltz.day == 4 && ltz.hour == 5 &&
          ltz.minute == 6 && ltz.second == 7 && ltz.nanosecond == 123456000);

    // Writing: this client's bind must be the captured one, byte for byte,
    // except where python sized its buffer for a larger value than it sent.
    const auto encode_tail = [](OracleBind bind, size_t tail_size) {
        TtcExecuteBindsRequest request;
        request.sql = "INSERT INTO T VALUES (:1)";
        request.binds = {std::move(bind)};
        request.ttc_field_version = 17;
        const auto encoded = EncodeTtcExecuteBindsRequest(request);
        return std::vector<uint8_t>(encoded.end() - static_cast<std::ptrdiff_t>(tail_size), encoded.end());
    };
    const auto with_size = [](std::vector<uint8_t> captured, size_t python_size_bytes, uint32_t size) {
        ByteWriter writer;
        writer.WriteUB4(size);
        const auto replacement = writer.Take();
        captured.erase(captured.begin() + 4, captured.begin() + 4 + static_cast<std::ptrdiff_t>(python_size_bytes));
        captured.insert(captured.begin() + 4, replacement.begin(), replacement.end());
        return captured;
    };
    OracleBind nchar;
    nchar.oracle_type = 96;
    nchar.character_set_form = 2;
    nchar.value = std::vector<uint8_t> {0x00, 0x61, 0x00, 0x62};
    auto expected = with_size(python_nchar_bind, 3, 4);
    CHECK(encode_tail(nchar, expected.size()) == expected);

    OracleBind nvarchar;
    nvarchar.oracle_type = 1;
    nvarchar.character_set_form = 2;
    nvarchar.value = EncodeUtf8ToUtf16Be("Zq\xc3\xa9\xe4\xb8\xad");
    CHECK(nvarchar.value && *nvarchar.value == std::vector<uint8_t>(python_nvarchar_bind.end() - 8, python_nvarchar_bind.end()));
    expected = with_size(python_nvarchar_bind, 3, 8);
    CHECK(encode_tail(nvarchar, expected.size()) == expected);

    OracleBind boolean;
    boolean.oracle_type = 252;
    boolean.value = std::vector<uint8_t> {1, 1};
    expected = with_size(python_boolean_bind, 2, 2);
    CHECK(encode_tail(boolean, expected.size()) == expected);

    OracleBind interval;
    interval.oracle_type = 183;
    interval.value = EncodeOracleIntervalDaySecond(3, 4, 5, 6, 7000);
    CHECK(*interval.value == std::vector<uint8_t>(python_interval_ds_bind.end() - 11, python_interval_ds_bind.end()));
    expected = with_size(python_interval_ds_bind, 2, 11);
    CHECK(encode_tail(interval, expected.size()) == expected);

    // A long bind's value follows every short bind's in the row, though its
    // metadata keeps its place. python_long_bind_row is python-oracledb's
    // insert of (id, clob, nclob) = (42, 40000 characters, 'abc'): three binds'
    // metadata, then the row, cut after the first chunk header of the CLOB.
    const std::vector<uint8_t> python_long_bind_row {
        0x02, 0x01, 0x00, 0x00, 0x01, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x00, 0x04, 0x00, 0x02, 0x71, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x69, 0x01, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x00, 0x01, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x69, 0x01, 0x00, 0x00,
        0x07, 0x02, 0xc1, 0x2a, 0x03, 0x61, 0x62, 0x63, 0xfe, 0x02, 0x7f, 0xff
    };
    {
        const std::string clob_text(40000, 'y');
        TtcExecuteBindsRequest request;
        request.sql = "INSERT INTO T VALUES (:1, :2, :3)";
        request.ttc_field_version = 17;
        OracleBind id;
        id.oracle_type = 2;
        id.value = std::vector<uint8_t> {0xc1, 0x2a};
        OracleBind clob;
        clob.oracle_type = 1;
        clob.value = std::vector<uint8_t>(clob_text.begin(), clob_text.end());
        OracleBind nclob;
        nclob.oracle_type = 1;
        nclob.value = std::vector<uint8_t> {'a', 'b', 'c'};
        request.binds = {id, clob, nclob};
        const auto encoded = EncodeTtcExecuteBindsRequest(request);

        // Rebuild python's bytes with this client's buffer sizes, then require the
        // request to end with them: the same metadata, the short values, then the
        // long one, which here chunks at 32768 where python chunks at 32767.
        ByteReader captured(python_long_bind_row);
        ByteWriter expected;
        const std::vector<uint32_t> sizes {2, 40000, 3};
        const std::vector<size_t> fixed_tail {8, 10, 10};
        for (size_t index = 0; index < 3; index++) {
            for (int step = 0; step < 4; step++) {
                expected.WriteByte(captured.ReadByte());
            }
            (void)captured.ReadUB4();
            expected.WriteUB4(sizes[index]);
            for (size_t step = 0; step < fixed_tail[index]; step++) {
                expected.WriteByte(captured.ReadByte());
            }
        }
        for (int step = 0; step < 8; step++) { // the marker, id, and the short NCLOB
            expected.WriteByte(captured.ReadByte());
        }
        auto want = expected.Take();
        want.push_back(0xfe);
        want.insert(want.end(), {0x02, 0x80, 0x00}); // this client's first chunk header: 32768
        const auto found = std::search(encoded.begin(), encoded.end(), want.begin(), want.end());
        CHECK(found != encoded.end());
        // Nothing but the CLOB's two chunks (32768 and 7232 bytes, each behind
        // its length) and the closing zero follows.
        CHECK(static_cast<size_t>(encoded.end() - found) == want.size() + 32768 + 3 + 7232 + 1);
    }

    // The default form of a character bind is untouched.
    OracleBind plain;
    plain.oracle_type = 1;
    plain.value = std::vector<uint8_t> {'a'};
    CHECK(encode_tail(plain, 19).at(13) == 1 && encode_tail(plain, 19).at(0) == 1);

    // UTF-8 to UTF-16BE: BMP, a surrogate pair, and every malformed shape.
    CHECK(EncodeUtf8ToUtf16Be("") == std::vector<uint8_t>());
    CHECK(EncodeUtf8ToUtf16Be("\xf0\x9f\x98\x80") == (std::vector<uint8_t> {0xd8, 0x3d, 0xde, 0x00}));
    CHECK(DecodeUtf16BeToUtf8(EncodeUtf8ToUtf16Be("h\xc3\xa9llo \xd0\x9f \xf0\x9f\x98\x80")).size() == 14);
    for (const char *bad : {"\x80", "\xc0\x80", "\xc3", "\xe0\x80\x80", "\xed\xa0\x80", "\xf4\x90\x80\x80",
                            "\xf8\x88\x80\x80\x80", "\xe4\xb8", "a\xff"}) {
        ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)EncodeUtf8ToUtf16Be(bad); });
    }
    std::mt19937 random(7);
    for (int round = 0; round < 5000; round++) {
        std::string text;
        for (int count = random() % 6; count > 0; count--) {
            uint32_t code_point = random() % 3 == 0 ? 0x10000 + random() % 0x100000 : random() % 0xD000;
            if (code_point == 0) {
                code_point = 1;
            }
            if (code_point < 0x80) {
                text += static_cast<char>(code_point);
            } else if (code_point < 0x800) {
                text += static_cast<char>(0xC0 | (code_point >> 6));
                text += static_cast<char>(0x80 | (code_point & 0x3F));
            } else if (code_point < 0x10000) {
                text += static_cast<char>(0xE0 | (code_point >> 12));
                text += static_cast<char>(0x80 | ((code_point >> 6) & 0x3F));
                text += static_cast<char>(0x80 | (code_point & 0x3F));
            } else {
                text += static_cast<char>(0xF0 | (code_point >> 18));
                text += static_cast<char>(0x80 | ((code_point >> 12) & 0x3F));
                text += static_cast<char>(0x80 | ((code_point >> 6) & 0x3F));
                text += static_cast<char>(0x80 | (code_point & 0x3F));
            }
        }
        const auto round_trip = DecodeUtf16BeToUtf8(EncodeUtf8ToUtf16Be(text));
        CHECK(std::string(round_trip.begin(), round_trip.end()) == text);
    }

    // The data-types request advertises ORACLE_CLIENT_TTC_FIELD_VERSION and is otherwise the
    // recorded template, byte for byte.
    const auto request = BuildTtcDataTypesRequest(TtcNegotiationOptions());
    CHECK(request.size() == ORACLE_19C_TTC_DATA_TYPES_TEMPLATE.size());
    CHECK(request.at(TTC_DATA_TYPES_CAPABILITIES_OFFSET + TTC_CAPABILITY_FIELD_VERSION_INDEX) ==
          ORACLE_CLIENT_TTC_FIELD_VERSION);
    size_t differing = 0;
    for (size_t index = 0; index < request.size(); index++) {
        differing += request[index] != ORACLE_19C_TTC_DATA_TYPES_TEMPLATE[index] ? 1 : 0;
    }
    CHECK(differing == 1);
    std::cout << "boolean, local zone and write binds ok" << std::endl;
}

// What the types added in 0.6.0 look like on the wire. Every byte sequence
// below was recorded from Oracle 19c, and the INTERVAL, NVARCHAR2 and ROWID
// values read the same from Free 23ai; PROVENANCE.md lists them with hashes.
//
// interval_ym_value_bytes: INTERVAL YEAR TO MONTH '2-3', '-5-11', '0-0'.
// interval_ds_value_bytes: INTERVAL DAY TO SECOND '3 04:05:06.789012345',
//     '-12 23:59:59.5', '0 0:0:0'.
// nvarchar_value_bytes: N'héllo Привет 😀' as NVARCHAR2, UTF-16BE, ending in a
//     surrogate pair.
// The *_fetch sets are the ROW_DATA and end of call of
// `SELECT id, <column> FROM <table>`, with the describe left out. A LONG
// carries an indicator and a return code behind its value, and a NULL LONG
// carries -1 and 1405 (ORA-01405), which is what `81 01 ... 05 7d` is.
// long_middle_fetch is `SELECT a, l, b` over rows (1,'xy','p'), (2,NULL,'q'),
// (3,'z',NULL), with the third row behind a BIT_VECTOR.
static void TestNewTypeValues() {
    const std::vector<uint8_t> plain_rowid_fetch {
        0x07, 0x02, 0xc1, 0x02, 0x0e, 0x03, 0x08, 0x35, 0xb4, 0x01, 0x01, 0x00, 0x02, 0x89, 0x89, 0x00, 0x07, 0x02,
        0xc1, 0x03, 0x00, 0x08, 0x01, 0x06, 0x04, 0x01, 0xf2, 0x0e, 0x9b, 0x01, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x02, 0xa0, 0x9a, 0x01, 0x02, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x19,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02
    };

    const std::vector<uint8_t> physical_urowid_fetch {
        0x07, 0x02, 0xc1, 0x02, 0x01, 0x0d, 0x0d, 0x01, 0x00, 0x08, 0x35, 0xb4, 0x00, 0x01, 0x00, 0x00, 0x89, 0x89,
        0x00, 0x00, 0x07, 0x02, 0xc1, 0x03, 0x00, 0x08, 0x01, 0x06, 0x04, 0x01, 0xf2, 0x0f, 0x18, 0x01, 0x01, 0x01,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x02, 0xa0, 0x9f, 0x01, 0x02, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x01, 0x19, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02
    };

    const std::vector<uint8_t> logical_urowid_fetch {
        0x07, 0x02, 0xc1, 0x02, 0x01, 0x0d, 0x0d, 0x02, 0x04, 0x00, 0x40, 0x89, 0xa1, 0x05, 0x61, 0x6c, 0x70, 0x68,
        0x61, 0xfe, 0x07, 0x02, 0xc1, 0x03, 0x01, 0x09, 0x09, 0x02, 0x04, 0x00, 0x40, 0x89, 0xa1, 0x01, 0x62, 0xfe,
        0x08, 0x01, 0x06, 0x04, 0x01, 0xf2, 0x0f, 0xa5, 0x01, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x01, 0x01, 0x02, 0x69, 0xe5, 0x01, 0x02, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x19, 0x03, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x02
    };

    const std::vector<uint8_t> long_fetch {
        0x07, 0x02, 0xc1, 0x02, 0xfe, 0x01, 0x05, 0x73, 0x68, 0x6f, 0x72, 0x74, 0x00, 0x00, 0x00, 0x07, 0x02, 0xc1,
        0x03, 0x00, 0x81, 0x01, 0x02, 0x05, 0x7d, 0x04, 0x01, 0x01, 0x02, 0xa0, 0xa4, 0x01, 0x02, 0x02, 0x05, 0x7b,
        0x00, 0x00, 0x01, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x05, 0x7b, 0x01, 0x02, 0x19, 0x4f, 0x52, 0x41, 0x2d, 0x30,
        0x31, 0x34, 0x30, 0x33, 0x3a, 0x20, 0x6e, 0x6f, 0x20, 0x64, 0x61, 0x74, 0x61, 0x20, 0x66, 0x6f, 0x75, 0x6e,
        0x64, 0x0a
    };

    const std::vector<uint8_t> long_raw_fetch {
        0x07, 0x02, 0xc1, 0x02, 0xfe, 0x01, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x02,
        0xa0, 0xa9, 0x01, 0x01, 0x02, 0x05, 0x7b, 0x00, 0x00, 0x01, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x05, 0x7b, 0x01,
        0x01, 0x19, 0x4f, 0x52, 0x41, 0x2d, 0x30, 0x31, 0x34, 0x30, 0x33, 0x3a, 0x20, 0x6e, 0x6f, 0x20, 0x64, 0x61,
        0x74, 0x61, 0x20, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x0a
    };

    const std::vector<uint8_t> long_middle_fetch {
        0x07, 0x02, 0xc1, 0x02, 0xfe, 0x01, 0x02, 0x78, 0x79, 0x00, 0x00, 0x00, 0x01, 0x70, 0x07, 0x02, 0xc1, 0x03,
        0x00, 0x81, 0x01, 0x02, 0x05, 0x7d, 0x01, 0x71, 0x15, 0x01, 0x03, 0x07, 0x07, 0x02, 0xc1, 0x04, 0xfe, 0x01,
        0x01, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x02, 0xa1, 0x64, 0x01, 0x03, 0x02, 0x05, 0x7b, 0x00,
        0x00, 0x01, 0x02, 0x00, 0x03, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x05, 0x7b, 0x01, 0x03, 0x19, 0x4f, 0x52, 0x41, 0x2d, 0x30, 0x31,
        0x34, 0x30, 0x33, 0x3a, 0x20, 0x6e, 0x6f, 0x20, 0x64, 0x61, 0x74, 0x61, 0x20, 0x66, 0x6f, 0x75, 0x6e, 0x64,
        0x0a
    };

    const std::vector<uint8_t> interval_ym_value_bytes {
        0x80, 0x00, 0x00, 0x02, 0x3f, 0x7f, 0xff, 0xff, 0xfb, 0x31, 0x80, 0x00, 0x00, 0x00, 0x3c
    };
    const std::vector<uint8_t> interval_ds_value_bytes {
        0x80, 0x00, 0x00, 0x03, 0x40, 0x41, 0x42, 0xaf, 0x07, 0x5f, 0x79, 0x7f, 0xff, 0xff, 0xf4, 0x25, 0x01, 0x01,
        0x62, 0x32, 0x9b, 0x00, 0x80, 0x00, 0x00, 0x00, 0x3c, 0x3c, 0x3c, 0x80, 0x00, 0x00, 0x00
    };
    const std::vector<uint8_t> nvarchar_value_bytes {
        0x00, 0x68, 0x00, 0xe9, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x20, 0x04, 0x1f, 0x04, 0x40, 0x04, 0x38,
        0x04, 0x32, 0x04, 0x35, 0x04, 0x42, 0x00, 0x20, 0xd8, 0x3d, 0xde, 0x00
    };

    // INTERVAL YEAR TO MONTH.
    const std::vector<int64_t> expected_months = {27, -71, 0};
    for (size_t index = 0; index < 3; index++) {
        const std::vector<uint8_t> wire(interval_ym_value_bytes.begin() + 5 * static_cast<std::ptrdiff_t>(index),
                                        interval_ym_value_bytes.begin() + 5 * static_cast<std::ptrdiff_t>(index + 1));
        CHECK(DecodeOracleIntervalYearMonth(wire).months == expected_months[index]);
    }
    CHECK(EncodeOracleIntervalYearMonth(2, 3) ==
          std::vector<uint8_t>(interval_ym_value_bytes.begin(), interval_ym_value_bytes.begin() + 5));
    CHECK(EncodeOracleIntervalYearMonth(-5, -11) ==
          std::vector<uint8_t>(interval_ym_value_bytes.begin() + 5, interval_ym_value_bytes.begin() + 10));
    ExpectError(ProtocolErrorKind::MALFORMED, [] { DecodeOracleIntervalYearMonth({0x80, 0, 0, 2}); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { DecodeOracleIntervalYearMonth({0x80, 0, 0, 2, 0x3f, 0}); });
    ExpectError(ProtocolErrorKind::MALFORMED, [] { DecodeOracleIntervalYearMonth({0x80, 0, 0, 2, 0x4c}); });

    // INTERVAL DAY TO SECOND.
    const auto day_second = [&](size_t index) {
        return std::vector<uint8_t>(interval_ds_value_bytes.begin() + 11 * static_cast<std::ptrdiff_t>(index),
                                    interval_ds_value_bytes.begin() + 11 * static_cast<std::ptrdiff_t>(index + 1));
    };
    const auto first = DecodeOracleIntervalDaySecond(day_second(0));
    CHECK(first.days == 3 && first.nanoseconds == ((4 * 60 + 5) * 60 + 6) * 1000000000LL + 789012345);
    const auto second = DecodeOracleIntervalDaySecond(day_second(1));
    CHECK(second.days == -12 && second.nanoseconds == -(((23 * 60 + 59) * 60 + 59) * 1000000000LL + 500000000));
    const auto zero = DecodeOracleIntervalDaySecond(day_second(2));
    CHECK(zero.days == 0 && zero.nanoseconds == 0);
    CHECK(EncodeOracleIntervalDaySecond(3, 4, 5, 6, 789012345) == day_second(0));
    CHECK(EncodeOracleIntervalDaySecond(-12, -23, -59, -59, -500000000) == day_second(1));
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { DecodeOracleIntervalDaySecond({0x80, 0, 0, 3}); });
    auto bad_hour = day_second(0);
    bad_hour[4] = 60 + 24;
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { DecodeOracleIntervalDaySecond(bad_hour); });
    auto bad_fraction = day_second(0);
    bad_fraction[7] = 0xc0;
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { DecodeOracleIntervalDaySecond(bad_fraction); });
    // Every value an Oracle interval can hold survives encode and decode.
    std::mt19937_64 random(20261022);
    for (int round = 0; round < 20000; round++) {
        const auto sign = (random() & 1U) ? 1 : -1;
        const auto days = sign * static_cast<int32_t>(random() % 1000000000U);
        const auto hours = sign * static_cast<int32_t>(random() % 24U);
        const auto minutes = sign * static_cast<int32_t>(random() % 60U);
        const auto seconds = sign * static_cast<int32_t>(random() % 60U);
        const auto nanoseconds = sign * static_cast<int32_t>(random() % 1000000000U);
        const auto decoded = DecodeOracleIntervalDaySecond(EncodeOracleIntervalDaySecond(days, hours, minutes, seconds, nanoseconds));
        CHECK(decoded.days == days);
        CHECK(decoded.nanoseconds == ((static_cast<int64_t>(hours) * 60 + minutes) * 60 + seconds) * 1000000000LL + nanoseconds);
        const auto years = sign * static_cast<int32_t>(random() % 1000000000U);
        const auto months = sign * static_cast<int32_t>(random() % 12U);
        CHECK(DecodeOracleIntervalYearMonth(EncodeOracleIntervalYearMonth(years, months)).months ==
              static_cast<int64_t>(years) * 12 + months);
    }

    // NVARCHAR2 travels as UTF-16BE.
    const auto utf8 = DecodeUtf16BeToUtf8(nvarchar_value_bytes);
    CHECK(std::string(utf8.begin(), utf8.end()) == "h\xc3\xa9llo \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82 \xf0\x9f\x98\x80");

    // ROWID text, against what ROWIDTOCHAR returned for the same rows.
    const std::vector<uint8_t> physical = {0x00, 0x08, 0x35, 0xb4, 0x00, 0x01, 0x00, 0x00, 0x89, 0x89, 0x00, 0x00};
    CHECK(TryDecodeOracleRowid(physical).value() == "AACDW0AABAAAImJAAA");
    auto with_code = physical;
    with_code.insert(with_code.begin(), 0x01);
    CHECK(TryDecodeOracleRowid(with_code).value() == "AACDW0AABAAAImJAAA");
    with_code[0] = 0x02;
    CHECK(!TryDecodeOracleRowid(with_code));
    CHECK(!TryDecodeOracleRowid({}) && !TryDecodeOracleRowid(std::vector<uint8_t>(11, 0)));
    CHECK(TryDecodeOracleRowid(std::vector<uint8_t>(12, 0)).value() == "AAAAAAAAAAAAAAAAAA");
    CHECK(TryDecodeOracleRowid(std::vector<uint8_t>(12, 0xff)).value() == "D/////P//D/////P//");

    // ROW_DATA framed as a ROWID, a UROWID and a LONG.
    OracleColumn id;
    id.name = "ID";
    id.oracle_type = 2;
    id.precision = 5;
    const auto column = [](const char *name, uint16_t type) {
        OracleColumn result;
        result.name = name;
        result.oracle_type = type;
        result.character_set_form = type == 8 ? 1 : 0;
        return result;
    };
    const auto rowid = DecodeTtcFetchResponse(plain_rowid_fetch, {id, column("R", 11)}, 12);
    CHECK(rowid.rows.size() == 2 && rowid.rows[0][1] && rowid.rows[0][1]->size() == 12 && !rowid.rows[1][1]);
    CHECK(TryDecodeOracleRowid(*rowid.rows[0][1]).value() == "AACDW0AABAAAImJAAA");

    const auto urowid = DecodeTtcFetchResponse(physical_urowid_fetch, {id, column("U", 208)}, 12);
    CHECK(urowid.rows.size() == 2 && urowid.rows[0][1] && urowid.rows[0][1]->size() == 13 && !urowid.rows[1][1]);
    CHECK(TryDecodeOracleRowid(*urowid.rows[0][1]).value() == "AACDW0AABAAAImJAAA");

    // An index-organized table's UROWID is logical: it frames the same way and
    // is not decoded.
    const auto logical = DecodeTtcFetchResponse(logical_urowid_fetch, {id, column("U", 208)}, 12);
    CHECK(logical.rows.size() == 2 && logical.rows[0][1] && (*logical.rows[0][1])[0] == 2 && logical.rows[1][1]);
    CHECK(!TryDecodeOracleRowid(*logical.rows[0][1]));

    const auto text = DecodeTtcFetchResponse(long_fetch, {id, column("L", 8)}, 12);
    CHECK(text.rows.size() == 2 && text.rows[0][1] && !text.rows[1][1]);
    CHECK(std::string(text.rows[0][1]->begin(), text.rows[0][1]->end()) == "short");
    const auto raw = DecodeTtcFetchResponse(long_raw_fetch, {id, column("L", 24)}, 12);
    CHECK(raw.rows.size() == 1 && raw.rows[0][1].value() == std::vector<uint8_t>({0xde, 0xad, 0xbe, 0xef}));

    OracleColumn a = id;
    a.name = "A";
    OracleColumn b = column("B", 1);
    b.character_set_form = 1;
    const std::vector<OracleColumn> middle_columns = {a, column("L", 8), b};
    const auto middle = DecodeTtcFetchResponse(long_middle_fetch, middle_columns, 12);
    CHECK(middle.rows.size() == 3 && middle.used_row_continuation);
    CHECK(std::string(middle.rows[0][1]->begin(), middle.rows[0][1]->end()) == "xy" && middle.rows[0][2].value()[0] == 'p');
    CHECK(!middle.rows[1][1] && middle.rows[1][2].value()[0] == 'q');
    CHECK(std::string(middle.rows[2][1]->begin(), middle.rows[2][1]->end()) == "z" && !middle.rows[2][2]);

    // A response cut anywhere, and fed in pieces, decodes to the same rows.
    const std::vector<std::pair<const std::vector<uint8_t> *, std::vector<OracleColumn>>> cases = {
        {&plain_rowid_fetch, {id, column("R", 11)}},
        {&physical_urowid_fetch, {id, column("U", 208)}},
        {&logical_urowid_fetch, {id, column("U", 208)}},
        {&long_fetch, {id, column("L", 8)}},
        {&long_raw_fetch, {id, column("L", 24)}},
        {&long_middle_fetch, middle_columns}};
    for (const auto &entry : cases) {
        const auto &bytes = *entry.first;
        const auto expected = DecodeTtcFetchResponse(bytes, entry.second, 12);
        for (size_t step = 1; step <= 7; step++) {
            TtcFetchResponseDecoder decoder(entry.second, 12, std::nullopt);
            for (size_t size = (std::min)(step, bytes.size());; size = (std::min)(size + step, bytes.size())) {
                const std::vector<uint8_t> received(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(size));
                try {
                    decoder.Decode(received);
                } catch (const ProtocolError &error) {
                    CHECK(error.Kind() == ProtocolErrorKind::TRUNCATED);
                }
                if (size == bytes.size()) {
                    break;
                }
            }
            CHECK(decoder.Take().rows == expected.rows);
        }
        // Every prefix is either a whole message sequence or reported as cut.
        for (size_t size = 1; size < bytes.size(); size++) {
            const std::vector<uint8_t> cut(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(size));
            try {
                (void)DecodeTtcFetchResponse(cut, entry.second, 12);
            } catch (const ProtocolError &error) {
                CHECK(error.Kind() == ProtocolErrorKind::TRUNCATED || error.Kind() == ProtocolErrorKind::MALFORMED);
            }
        }
    }

    // Bounds: a UROWID that states a size its bytes do not, or an absurd one,
    // and a LONG whose indicator is wider than any integer.
    const std::vector<TtcColumnFraming> urowid_only = {TtcColumnFraming::UROWID};
    ExpectError(ProtocolErrorKind::MALFORMED,
                [&] { DecodeTtcRowDataPrefix(std::vector<uint8_t> {7, 1, 5, 2, 1, 2}, urowid_only); });
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED,
                [&] { DecodeTtcRowDataPrefix(std::vector<uint8_t> {7, 2, 0x7f, 0xff}, urowid_only); });
    const std::vector<TtcColumnFraming> long_only = {TtcColumnFraming::LONG};
    ExpectError(ProtocolErrorKind::MALFORMED,
                [&] { DecodeTtcRowDataPrefix(std::vector<uint8_t> {7, 0, 0x85, 1, 2, 3, 4, 5, 0}, long_only); });
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] {
        DecodeTtcRowDataPrefix(std::vector<uint8_t> {7, 0xfe, 1, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0}, long_only, 8);
    });
}



// JSON and VECTOR: the images a 23ai server stores them in, decoded to JSON
// text and to typed elements, and the define-and-fetch that brings them with
// their rows. Every byte sequence below was captured from Free 23ai (see
// PROVENANCE.md); the expectations are the documents and vectors that were
// inserted, not what this decoder printed.
static void TestJsonAndVectorImages() {
    // Free 23ai, a JSON column holding {"a":{"b":[1,2,{"c":"x"}]}}
    const std::vector<uint8_t> oson_nested_object {
        0xff, 0x4a, 0x5a, 0x01, 0x21, 0x06, 0x03, 0x00, 0x06, 0x00, 0x1f, 0x00,
        0x00, 0x2c, 0x52, 0xe5, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x01, 0x61,
        0x01, 0x62, 0x01, 0x63, 0x84, 0x01, 0x01, 0x00, 0x05, 0x84, 0x01, 0x03,
        0x00, 0x0a, 0xc0, 0x03, 0x00, 0x12, 0x00, 0x15, 0x00, 0x18, 0x21, 0xc1,
        0x02, 0x21, 0xc1, 0x03, 0x84, 0x01, 0x02, 0x00, 0x1d, 0x01, 0x78,
    };

    // Free 23ai, a JSON column holding [{"a":1,"b":2},{"a":3,"b":4},{"b":5,"a":6}]
    const std::vector<uint8_t> oson_shared_fields {
        0xff, 0x4a, 0x5a, 0x01, 0x21, 0x06, 0x02, 0x00, 0x04, 0x00, 0x31, 0x00,
        0x01, 0x2c, 0xe5, 0x00, 0x00, 0x00, 0x02, 0x01, 0x61, 0x01, 0x62, 0xc0,
        0x03, 0x00, 0x08, 0x00, 0x16, 0x00, 0x23, 0x86, 0x02, 0x01, 0x02, 0x00,
        0x10, 0x00, 0x13, 0x21, 0xc1, 0x02, 0x21, 0xc1, 0x03, 0x9c, 0x00, 0x08,
        0x00, 0x1d, 0x00, 0x20, 0x21, 0xc1, 0x04, 0x21, 0xc1, 0x05, 0x84, 0x02,
        0x02, 0x01, 0x00, 0x2b, 0x00, 0x2e, 0x21, 0xc1, 0x06, 0x21, 0xc1, 0x07,
    };

    // Free 23ai, a JSON column holding [null x 256]
    const std::vector<uint8_t> oson_u16_count {
        0xff, 0x4a, 0x5a, 0x01, 0x60, 0x26, 0x00, 0x00, 0x00, 0x02, 0x07, 0x02,
        0x03, 0xc8, 0x01, 0x00, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06, 0x02, 0x06,
        0x01, 0x00, 0x00, 0x30,
    };

    // Free 23ai, a JSON column holding strings, escapes, numbers, booleans and a null
    const std::vector<uint8_t> oson_text_and_numbers {
        0xff, 0x4a, 0x5a, 0x01, 0x21, 0x06, 0x06, 0x00, 0x16, 0x00, 0x3b, 0x00,
        0x00, 0x06, 0x31, 0x99, 0xa3, 0xad, 0xb9, 0x00, 0x00, 0x00, 0x0a, 0x00,
        0x0e, 0x00, 0x0c, 0x00, 0x10, 0x00, 0x12, 0x09, 0xc3, 0xa9, 0xe2, 0x82,
        0xac, 0xf0, 0x9f, 0x98, 0x80, 0x01, 0x6e, 0x01, 0x74, 0x01, 0x66, 0x01,
        0x7a, 0x03, 0x62, 0x69, 0x67, 0x84, 0x06, 0x01, 0x02, 0x04, 0x03, 0x05,
        0x06, 0x00, 0x14, 0x00, 0x21, 0x00, 0x26, 0x00, 0x27, 0x00, 0x28, 0x00,
        0x29, 0x0c, 0xc3, 0xa9, 0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x98, 0x80, 0x0a,
        0x01, 0x22, 0x23, 0x3e, 0x59, 0x33, 0x66, 0x31, 0x32, 0x30, 0x34, 0x10,
        0xcf, 0x0d, 0x23, 0x39, 0x4f, 0x5b, 0x0d, 0x23, 0x39, 0x4f, 0x5b, 0x0d,
        0x23, 0x39, 0x4f, 0x5b,
    };

    // Free 23ai, a JSON column holding json_object() over a TIMESTAMP, DATE, BINARY_DOUBLE, BINARY_FLOAT, RAW, two intervals and a TIMESTAMP WITH TIME ZONE
    const std::vector<uint8_t> oson_native_scalars {
        0xff, 0x4a, 0x5a, 0x01, 0x31, 0x06, 0x08, 0x00, 0x16, 0x00, 0x00, 0x00,
        0x62, 0x00, 0x00, 0x00, 0x13, 0x15, 0x39, 0x70, 0x73, 0x9b, 0xdb, 0x00,
        0x10, 0x00, 0x05, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x00,
        0x13, 0x00, 0x0d, 0x02, 0x74, 0x73, 0x01, 0x64, 0x02, 0x62, 0x64, 0x02,
        0x62, 0x66, 0x01, 0x72, 0x02, 0x79, 0x6d, 0x02, 0x64, 0x73, 0x02, 0x74,
        0x7a, 0x84, 0x08, 0x05, 0x06, 0x02, 0x04, 0x03, 0x08, 0x01, 0x07, 0x00,
        0x1a, 0x00, 0x26, 0x00, 0x2e, 0x00, 0x37, 0x00, 0x3c, 0x00, 0x42, 0x00,
        0x48, 0x00, 0x54, 0x39, 0x78, 0x78, 0x01, 0x02, 0x04, 0x05, 0x06, 0x07,
        0x5b, 0xca, 0x00, 0x3c, 0x78, 0x78, 0x01, 0x02, 0x01, 0x01, 0x01, 0x36,
        0xbf, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xbd, 0xcc, 0xcc,
        0xcd, 0x3a, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0x3d, 0x80, 0x00, 0x00, 0x01,
        0x3e, 0x3e, 0x80, 0x00, 0x00, 0x01, 0x3e, 0x3f, 0x40, 0x9d, 0xcd, 0x65,
        0x00, 0x7c, 0x78, 0x78, 0x01, 0x02, 0x01, 0x05, 0x06, 0x1d, 0xcd, 0x65,
        0x00, 0x17, 0x3c,
    };

    // Free 23ai, a JSON column holding a 256-byte field name and a short one
    const std::vector<uint8_t> oson_long_field_name {
        0xff, 0x4a, 0x5a, 0x03, 0x21, 0x06, 0x01, 0x00, 0x02, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x00, 0x0e, 0x00, 0x00, 0x2c,
        0x00, 0x00, 0x01, 0x61, 0xc5, 0xba, 0x00, 0x00, 0x01, 0x00, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0x6b, 0x84, 0x02, 0x02, 0x01, 0x00, 0x08, 0x00, 0x0b, 0x21, 0xc1,
        0x02, 0x21, 0xc1, 0x03,
    };

    // Free 23ai, a JSON column holding json_object() over a dense FLOAT32 and a sparse FLOAT32 VECTOR
    const std::vector<uint8_t> oson_embedded_vectors {
        0xff, 0x4a, 0x5a, 0x01, 0x21, 0x06, 0x02, 0x00, 0x04, 0x00, 0x54, 0x00,
        0x00, 0x82, 0xc9, 0x00, 0x02, 0x00, 0x00, 0x01, 0x76, 0x01, 0x73, 0x84,
        0x02, 0x02, 0x01, 0x00, 0x08, 0x00, 0x2b, 0x7b, 0x01, 0x00, 0x00, 0x00,
        0x1d, 0xdb, 0x00, 0x00, 0x16, 0x02, 0x00, 0x00, 0x00, 0x03, 0xc0, 0x0f,
        0x3d, 0xb2, 0x17, 0x4e, 0x74, 0x68, 0xbf, 0xc0, 0x00, 0x00, 0xc0, 0x00,
        0x00, 0x00, 0x3f, 0xbf, 0xff, 0xff, 0x7b, 0x01, 0x00, 0x00, 0x00, 0x23,
        0xdb, 0x02, 0x00, 0x32, 0x02, 0x00, 0x00, 0x00, 0x05, 0xc0, 0x07, 0x52,
        0xe5, 0x0d, 0xb3, 0xa3, 0xa2, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x03, 0xbf, 0xc0, 0x00, 0x00, 0xc0, 0x20, 0x00, 0x00,
    };

    // Free 23ai, VECTOR(3,FLOAT32) [1.5, 2, 3]
    const std::vector<uint8_t> vector_float32_value {
        0xdb, 0x00, 0x00, 0x12, 0x02, 0x00, 0x00, 0x00, 0x03, 0xc0, 0x0f, 0x3d,
        0xb2, 0x17, 0x4e, 0x74, 0x68, 0xbf, 0xc0, 0x00, 0x00, 0xc0, 0x00, 0x00,
        0x00, 0xc0, 0x40, 0x00, 0x00,
    };

    // Free 23ai, VECTOR(4,INT8) [1, 2, 3, 4]
    const std::vector<uint8_t> vector_int8_value {
        0xdb, 0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x04, 0xc0, 0x15, 0xe8,
        0xad, 0xd2, 0x36, 0xa5, 0x8f, 0x01, 0x02, 0x03, 0x04,
    };

    // Free 23ai, VECTOR(8,BINARY) [5]
    const std::vector<uint8_t> vector_binary_value {
        0xdb, 0x01, 0x00, 0x10, 0x05, 0x00, 0x00, 0x00, 0x08, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    };

    // Free 23ai, VECTOR(3,FLOAT64) [1.5, -2, 0.1]
    const std::vector<uint8_t> vector_float64_value {
        0xdb, 0x00, 0x00, 0x12, 0x03, 0x00, 0x00, 0x00, 0x03, 0xc0, 0x04, 0x04,
        0x18, 0x28, 0x2a, 0xe9, 0xe0, 0xbf, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0xb9, 0x99,
        0x99, 0x99, 0x99, 0x99, 0x9a,
    };

    // Free 23ai, VECTOR(5,FLOAT32,SPARSE) [5,[1,3],[1.5,2.5]]
    const std::vector<uint8_t> vector_sparse_value {
        0xdb, 0x02, 0x00, 0x32, 0x02, 0x00, 0x00, 0x00, 0x05, 0xc0, 0x07, 0x52,
        0xe5, 0x0d, 0xb3, 0xa3, 0xa2, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x03, 0xbf, 0xc0, 0x00, 0x00, 0xc0, 0x20, 0x00, 0x00,
    };

    // python-oracledb 4.0.1 Thin against Free 23ai, sequence 4, the define-and-fetch it sends for 'select id, j from QO_J' (a NUMBER and a JSON column) once the describe has come back: cursor 2, two rows, JSON asked for 32 MiB of prefix
    const std::vector<uint8_t> python_inline_define_json {
        0x03, 0x5e, 0x04, 0x00, 0x02, 0x80, 0x10, 0x01, 0x02, 0x00, 0x00, 0x01,
        0x01, 0x0d, 0x00, 0x00, 0x00, 0x01, 0x02, 0x04, 0x7f, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x01,
        0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77, 0x01, 0x00,
        0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00,
    };

    // the same client's define for a 23-column query: NUMBER, VARCHAR2, CHAR, DATE, the TIMESTAMP family, RAW, BINARY_FLOAT/DOUBLE, NVARCHAR2, NCHAR, BOOLEAN, the intervals, CLOB, BLOB, NCLOB, JSON and VECTOR
    const std::vector<uint8_t> python_inline_define_mixed {
        0x03, 0x5e, 0x04, 0x00, 0x02, 0x80, 0x10, 0x01, 0x02, 0x00, 0x00, 0x01,
        0x01, 0x0d, 0x00, 0x00, 0x00, 0x01, 0x02, 0x04, 0x7f, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x17, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x01,
        0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00,
        0x00, 0x01, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x01, 0x00, 0x00, 0x01, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x50, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x03, 0x69, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x02, 0x3e, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x69, 0x01, 0x00, 0x00, 0x60, 0x01,
        0x00, 0x00, 0x01, 0x14, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x69, 0x01,
        0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x01, 0x07, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xb4, 0x01, 0x00, 0x00, 0x01, 0x0b, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb5, 0x01, 0x00, 0x00, 0x01, 0x0d,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe7, 0x01, 0x00, 0x00,
        0x01, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x01,
        0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x64, 0x01, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x65, 0x01, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x28, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x03, 0x69, 0x02, 0x00, 0x00, 0x60, 0x01, 0x00, 0x00,
        0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x69, 0x02, 0x00, 0x00,
        0xfc, 0x01, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xb6, 0x01, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xb7, 0x01, 0x00, 0x00, 0x01, 0x0b, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x01, 0x00, 0x00, 0x01, 0x70,
        0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x69, 0x01,
        0x00, 0x00, 0x71, 0x01, 0x00, 0x00, 0x01, 0x70, 0x00, 0x04, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x01, 0x00, 0x00,
        0x01, 0x70, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03,
        0x69, 0x02, 0x00, 0x00, 0x77, 0x01, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x01, 0x00, 0x00, 0x04, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x10, 0x00, 0x00, 0x00,
    };

    // the server's answer to it: two rows, the first with every column set, the second NULL but for its first column
    const std::vector<uint8_t> python_inline_rows_mixed {
        0x06, 0x22, 0x01, 0x17, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x07, 0x02,
        0xc1, 0x02, 0x02, 0xc1, 0x03, 0x03, 0xc1, 0x04, 0x33, 0x03, 0x61, 0x62,
        0x63, 0x04, 0x6c, 0x6f, 0x6e, 0x67, 0x05, 0x78, 0x79, 0x20, 0x20, 0x20,
        0x07, 0x78, 0x78, 0x01, 0x02, 0x01, 0x01, 0x01, 0x0b, 0x78, 0x78, 0x01,
        0x02, 0x04, 0x05, 0x06, 0x07, 0x5b, 0xca, 0x00, 0x0d, 0x78, 0x78, 0x01,
        0x02, 0x01, 0x05, 0x06, 0x1d, 0xcd, 0x65, 0x00, 0x17, 0x3c, 0x07, 0x78,
        0x78, 0x01, 0x01, 0x18, 0x05, 0x06, 0x02, 0xaa, 0xbb, 0x04, 0xbf, 0xc0,
        0x00, 0x00, 0x08, 0xc0, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x6e, 0x00, 0x76, 0x08, 0x00, 0x6e, 0x00, 0x63, 0x00, 0x20, 0x00,
        0x20, 0x02, 0x01, 0x01, 0x05, 0x80, 0x00, 0x00, 0x01, 0x3e, 0x0b, 0x80,
        0x00, 0x00, 0x01, 0x3e, 0x3f, 0x40, 0x9d, 0xcd, 0x65, 0x00, 0x01, 0x72,
        0x01, 0x04, 0x02, 0x1f, 0x7c, 0x72, 0x00, 0x70, 0x00, 0x02, 0x02, 0x0c,
        0x82, 0x80, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0xd0,
        0x46, 0x81, 0x00, 0x0b, 0xf4, 0xfd, 0x00, 0x0b, 0xf4, 0xfc, 0x00, 0x13,
        0x00, 0x13, 0x03, 0x69, 0x01, 0x00, 0xd1, 0x1a, 0x01, 0x00, 0x08, 0x00,
        0x00, 0x02, 0x6a, 0xdb, 0x19, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xec, 0x1e, 0xab, 0xb1, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x00, 0x22,
        0x00, 0x00, 0x00, 0x01, 0x03, 0x6c, 0x41, 0xbc, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x0b, 0xf4, 0xfc, 0x06, 0x00, 0xa0, 0x5f, 0x00, 0x00,
        0x01, 0x72, 0x01, 0x01, 0x02, 0x1f, 0x7c, 0x72, 0x00, 0x70, 0x00, 0x02,
        0x01, 0x0c, 0x02, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x04, 0xd0, 0x46, 0x82, 0x00, 0x0b, 0xf4, 0xff, 0x00, 0x0b, 0xf4, 0xfc,
        0x00, 0x14, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x6a, 0xdb, 0x19, 0x4f, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xec, 0x1e, 0xab, 0xb1,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
        0x00, 0x22, 0x00, 0x00, 0x00, 0x01, 0x03, 0x6c, 0x41, 0xbc, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0xf4, 0xfc, 0x06, 0x00, 0xa0, 0x5f,
        0x00, 0x00, 0x01, 0x72, 0x01, 0x05, 0x02, 0x1f, 0x7c, 0x72, 0x00, 0x70,
        0x00, 0x02, 0x04, 0x4c, 0x02, 0x80, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x04, 0xd0, 0x46, 0x83, 0x00, 0x0b, 0xf5, 0x01, 0x00, 0x0b,
        0xf4, 0xfc, 0x00, 0x15, 0x00, 0x15, 0x07, 0xd0, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x6a, 0xdb, 0x19, 0x4f, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xec, 0x1e,
        0xab, 0xb1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
        0x00, 0x01, 0x00, 0x22, 0x00, 0x00, 0x00, 0x01, 0x03, 0x6c, 0x41, 0xbc,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0xf4, 0xfc, 0x06, 0x00,
        0xa0, 0x5f, 0x00, 0x00, 0x01, 0x28, 0x01, 0x1a, 0x02, 0x7f, 0x58, 0x1a,
        0xff, 0x4a, 0x5a, 0x01, 0x21, 0x06, 0x01, 0x00, 0x02, 0x00, 0x08, 0x00,
        0x00, 0x2c, 0x00, 0x00, 0x01, 0x61, 0x84, 0x01, 0x01, 0x00, 0x05, 0x21,
        0xc1, 0x02, 0x28, 0x00, 0x26, 0x00, 0x04, 0x61, 0x08, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x28, 0x01, 0x1d, 0x02,
        0x7f, 0x58, 0x1d, 0xdb, 0x00, 0x00, 0x12, 0x02, 0x00, 0x00, 0x00, 0x03,
        0xc0, 0x0d, 0xee, 0xea, 0x11, 0x68, 0x3f, 0x49, 0xbf, 0x80, 0x00, 0x00,
        0xc0, 0x00, 0x00, 0x00, 0xc0, 0x40, 0x00, 0x00, 0x28, 0x00, 0x26, 0x00,
        0x04, 0x61, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x07, 0x02, 0xc1, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x08, 0x01, 0x06, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x02, 0x37, 0xaf, 0x01, 0x02,
        0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x03, 0x00, 0x1d,
    };

    // OSON -> JSON text.
    CHECK(DecodeOsonToJson(oson_nested_object) == R"({"a":{"b":[1,2,{"c":"x"}]}})");
    // Objects with the same fields share one list of field numbers.
    CHECK(DecodeOsonToJson(oson_shared_fields) == R"([{"a":1,"b":2},{"a":3,"b":4},{"b":5,"a":6}])");
    {
        std::string nulls = "[null";
        for (int index = 1; index < 256; index++) {
            nulls += ",null";
        }
        CHECK(DecodeOsonToJson(oson_u16_count) == nulls + "]");
    }
    CHECK(DecodeOsonToJson(oson_text_and_numbers) ==
          "{\"\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80\":\"\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80\\n\\u0001\\\"\","
          "\"n\":-12.5,\"t\":true,\"f\":false,\"z\":null,\"big\":123456789012345678901234567890}");
    CHECK(DecodeOsonToJson(oson_native_scalars) ==
          R"({"ts":"2020-01-02T03:04:05.123456","d":"2020-01-02T00:00:00","bd":1.5,"bf":0.1,)"
          R"("r":"AABBCC","ym":"P1Y2M","ds":"P1DT2H3M4.500000S","tz":"2020-01-02T03:04:05.500000+03:00"})");
    // A field name over 255 bytes puts the image in the version that has room for it.
    CHECK(oson_long_field_name[3] == 3);
    CHECK(DecodeOsonToJson(oson_long_field_name) == "{\"" + std::string(256, 'k') + "\":1,\"a\":2}");
    // A vector inside a document prints the way the server prints it.
    CHECK(DecodeOsonToJson(oson_embedded_vectors) == R"({"v":[1.5,2,-3],"s":[5,[1,3],[1.5,2.5]]})");

    // Damage is reported, never read past: every prefix of an image is
    // refused, and an image with one byte changed either decodes to something
    // or is refused, but does not run off the end.
    for (const auto *image : {&oson_nested_object, &oson_shared_fields, &oson_native_scalars, &oson_long_field_name,
                              &oson_embedded_vectors}) {
        for (size_t length = 0; length < image->size(); length++) {
            bool refused = false;
            try {
                (void)DecodeOsonToJson(image->data(), length);
            } catch (const ProtocolError &) {
                refused = true;
            }
            CHECK(refused);
        }
        for (size_t position = 0; position < image->size(); position++) {
            auto damaged = *image;
            damaged[position] ^= 0xFF;
            try {
                (void)DecodeOsonToJson(damaged);
            } catch (const ProtocolError &) {
            }
        }
    }
    auto bad_magic = oson_nested_object;
    bad_magic[0] = 0;
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { DecodeOsonToJson(bad_magic); });
    auto unknown_version = oson_nested_object;
    unknown_version[3] = 9;
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [&] { DecodeOsonToJson(unknown_version); });
    OsonLimits tiny;
    tiny.maximum_output_bytes = 8;
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { DecodeOsonToJson(oson_nested_object, tiny); });
    OsonLimits shallow;
    shallow.maximum_depth = 2;
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { DecodeOsonToJson(oson_nested_object, shallow); });
    // An array whose only child is itself would recurse for ever.
    const std::vector<uint8_t> loop {0xff, 0x4a, 0x5a, 0x01, 0x20, 0x06, 0x00, 0x00, 0x00, 0x00,
                                     0x04, 0x00, 0x00, 0xc0, 0x01, 0x00, 0x00};
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { DecodeOsonToJson(loop); });

    // VECTOR images.
    const auto float32 = DecodeOracleVector(vector_float32_value);
    CHECK(float32.format == ORACLE_VECTOR_FLOAT32 && float32.dimensions == 3 && !float32.sparse);
    CHECK(float32.float32 == std::vector<float>({1.5F, 2.0F, 3.0F}));
    const auto float64 = DecodeOracleVector(vector_float64_value);
    CHECK(float64.format == ORACLE_VECTOR_FLOAT64 && float64.float64 == std::vector<double>({1.5, -2.0, 0.1}));
    const auto int8 = DecodeOracleVector(vector_int8_value);
    CHECK(int8.format == ORACLE_VECTOR_INT8 && int8.int8 == std::vector<int8_t>({1, 2, 3, 4}));
    const auto binary = DecodeOracleVector(vector_binary_value);
    CHECK(binary.format == ORACLE_VECTOR_BINARY && binary.dimensions == 8 && binary.binary == std::vector<uint8_t>({5}));
    const auto sparse = DecodeOracleVector(vector_sparse_value);
    CHECK(sparse.sparse && sparse.dimensions == 5 && sparse.indices == std::vector<uint32_t>({1, 3}) &&
          sparse.float32 == std::vector<float>({1.5F, 2.5F}));
    for (const auto *image : {&vector_float32_value, &vector_float64_value, &vector_int8_value, &vector_binary_value,
                              &vector_sparse_value}) {
        for (size_t length = 0; length < image->size(); length++) {
            bool refused = false;
            try {
                (void)DecodeOracleVector(image->data(), length);
            } catch (const ProtocolError &) {
                refused = true;
            }
            CHECK(refused);
        }
        auto longer = *image;
        longer.push_back(0);
        ExpectError(ProtocolErrorKind::MALFORMED, [&] { DecodeOracleVector(longer); });
    }
    auto not_a_vector = vector_float32_value;
    not_a_vector[0] = 0;
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { DecodeOracleVector(not_a_vector); });
    auto unknown_format = vector_float32_value;
    unknown_format[4] = 9;
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [&] { DecodeOracleVector(unknown_format); });

    // The columns the mixed query describes.
    const auto column = [](const char *name, uint16_t type, uint32_t width = 0, uint8_t form = 0) {
        OracleColumn result;
        result.name = name;
        result.oracle_type = type;
        result.byte_width = width;
        result.character_set_form = form;
        return result;
    };
    std::vector<OracleColumn> mixed = {
        column("N", 2),        column("N2", 2),          column("N3", 2),       column("V", 1, 20, 1),
        column("V2", 1, 4000, 1), column("C", 96, 5, 1), column("D", 12),       column("TS", 180),
        column("TSTZ", 181),   column("LTZ", 231),       column("R", 23, 16),   column("BF", 100),
        column("BD", 101),     column("NV", 1, 10, 2),   column("NC", 96, 4, 2), column("B", 252),
        column("IYM", 182),    column("IDS", 183),       column("CL", 112, 0, 1), column("BL", 113),
        column("NL", 112, 0, 2), column("J", 119),       column("VEC", 127)};
    mixed.back().vector_dimensions = 3;
    mixed.back().vector_format = ORACLE_VECTOR_FLOAT32;
    CHECK(SupportsInlineLobDefine(mixed, 24));
    CHECK(!SupportsInlineLobDefine(mixed, 12));
    {
        auto without_json = mixed;
        without_json.erase(without_json.begin() + 21, without_json.end());
        CHECK(!SupportsInlineLobDefine(without_json, 24));
        auto with_rowid = mixed;
        with_rowid.push_back(column("RID", 11));
        CHECK(!SupportsInlineLobDefine(with_rowid, 24));
    }

    // The define-and-fetch is the one python-oracledb sends: a header, then
    // one record per column. python asks for more of a JSON or VECTOR value
    // than this client does, so those two records are compared by their
    // fields; every byte before them is the captured one.
    const auto with_token = [](std::vector<uint8_t> message) {
        message.insert(message.begin() + 3, 0);
        return message;
    };
    const auto ours = with_token(EncodeInlineLobDefine(4, 2, mixed, 2));
    {
        ByteWriter record;
        record.WriteByte(119).WriteByte(1).WriteByte(0).WriteByte(0).WriteUB4(INLINE_LOB_PREFIX_BYTES).WriteUB4(0);
        record.WriteUB8(0x02000000).WriteUB4(0).WriteUB2(0).WriteUB2(0).WriteByte(0);
        record.WriteUB4(INLINE_LOB_PREFIX_BYTES).WriteUB4(0);
        record.WriteByte(127).WriteByte(1).WriteByte(0).WriteByte(0).WriteUB4(INLINE_LOB_PREFIX_BYTES).WriteUB4(0);
        record.WriteUB8(0x02000000).WriteUB4(0).WriteUB2(0).WriteUB2(0).WriteByte(0);
        record.WriteUB4(INLINE_LOB_PREFIX_BYTES).WriteUB4(0);
        const auto tail = record.Take();
        CHECK(ours.size() > tail.size());
        CHECK(std::vector<uint8_t>(ours.end() - static_cast<std::ptrdiff_t>(tail.size()), ours.end()) == tail);
        const auto head_size = ours.size() - tail.size();
        CHECK(std::vector<uint8_t>(ours.begin(), ours.begin() + static_cast<std::ptrdiff_t>(head_size)) ==
              std::vector<uint8_t>(python_inline_define_mixed.begin(),
                                   python_inline_define_mixed.begin() + static_cast<std::ptrdiff_t>(head_size)));
    }
    {
        // The two-column JSON query: the same header, the NUMBER record, then the JSON one.
        std::vector<OracleColumn> pair = {column("ID", 2), column("J", 119)};
        const auto pair_ours = with_token(EncodeInlineLobDefine(4, 2, pair, 2));
        const size_t json_record = python_inline_define_json.size() - 25;
        CHECK(std::equal(pair_ours.begin(), pair_ours.begin() + static_cast<std::ptrdiff_t>(json_record),
                         python_inline_define_json.begin()));
    }
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { EncodeInlineLobDefine(0, 2, mixed, 2); });
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { EncodeInlineLobDefine(4, 0, mixed, 2); });
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { EncodeInlineLobDefine(4, 2, mixed, 0); });
    // Two columns that may each send a prefix bound the response sooner than one.
    CHECK(InlineLobRows(mixed, 2048) == 96 && InlineLobRows(mixed, 5) == 5 && InlineLobRows(mixed, 1) == 1);
    CHECK(InlineLobRows({column("ID", 2), column("J", 119)}, 2048) == 128);

    // The rows that answer it carry JSON and VECTOR with their first bytes, a
    // CLOB, BLOB and NCLOB with only a size, and a locator after each.
    for (auto &described : mixed) {
        described.inline_lob_cells = IsOracleLocatorType(described.oracle_type);
    }
    const auto answered = DecodeTtcFetchResponse(python_inline_rows_mixed, mixed, 24);
    CHECK(answered.rows.size() == 2);
    const auto &first = answered.rows[0];
    CHECK(first.size() == mixed.size());
    CHECK(first[3] && std::string(first[3]->begin(), first[3]->end()) == "abc");
    CHECK(first[15] && first[15]->back() == 1);
    const auto clob = DecodeTtcInlineLob(*first[18]);
    CHECK(clob.total == 4 && clob.prefix.empty() && clob.locator.size() == 114);
    const auto blob = DecodeTtcInlineLob(*first[19]);
    CHECK(blob.total == 1 && blob.prefix.empty() && !blob.locator.empty());
    const auto nclob = DecodeTtcInlineLob(*first[20]);
    CHECK(nclob.total == 5 && nclob.prefix.empty());
    const auto json = DecodeTtcInlineLob(*first[21]);
    CHECK(json.prefix.size() == json.total && json.locator.size() == 40);
    CHECK(DecodeOsonToJson(json.prefix) == R"({"a":1})");
    const auto vector = DecodeTtcInlineLob(*first[22]);
    CHECK(vector.prefix.size() == vector.total);
    CHECK(DecodeOracleVector(vector.prefix).float32 == std::vector<float>({1.0F, 2.0F, 3.0F}));
    // The second row has a value for N and NULL for everything else.
    CHECK(answered.rows[1][0].has_value());
    for (size_t index = 1; index < answered.rows[1].size(); index++) {
        CHECK(!answered.rows[1][index]);
    }
    // Two rows were asked for and two came, so the cursor is not at its end.
    CHECK(answered.completed && !answered.exhausted);
    // The same bytes read without the flag are not a row: cells framed one way
    // cannot be read the other, and the decoder says so.
    {
        auto unflagged = mixed;
        for (auto &described : unflagged) {
            described.inline_lob_cells = false;
        }
        bool refused = false;
        try {
            (void)DecodeTtcFetchResponse(python_inline_rows_mixed, unflagged, 24);
        } catch (const ProtocolError &) {
            refused = true;
        }
        CHECK(refused);
    }
    std::cout << "JSON and VECTOR images decode; the define matches python-oracledb's" << std::endl;
}

// From TTC field version 18 every function call and piggyback header has a
// token number after its sequence number; this client never uses one.
static void TestRequestHeadersCarryATokenFromFieldVersion18() {
    const auto send_with = [](uint8_t field_version) {
        FragmentedStream stream({}, 3);
        TnsPacketStream packets(stream, true, 64);
        TtcChannel channel(packets, 64);
        channel.SetWireFieldVersion(field_version);
        channel.QueueCloseCursor(42);
        channel.Send(EncodeTtcFetchRequest({7, 42, 10}));
        FragmentedStream sent_stream(stream.output, 3);
        TnsPacketStream sent_packets(sent_stream, true, 64);
        std::vector<uint8_t> sent;
        while (sent_stream.read_offset < sent_stream.input.size()) {
            const auto packet = sent_packets.Receive();
            sent.insert(sent.end(), packet.payload.begin() + 2, packet.payload.end());
        }
        return sent;
    };
    const auto plain = send_with(17);
    const auto tokened = send_with(18);
    CHECK(tokened.size() == plain.size() + 2);
    // piggyback: type, function, sequence, [token], the rest
    CHECK(plain[0] == TTC_MESSAGE_PIGGYBACK && tokened[0] == TTC_MESSAGE_PIGGYBACK);
    CHECK(tokened[3] == 0);
    CHECK(std::vector<uint8_t>(tokened.begin() + 4, tokened.begin() + 8) ==
          std::vector<uint8_t>(plain.begin() + 3, plain.begin() + 7));
    // the fetch after it: type, function, sequence, [token], the rest
    const std::vector<uint8_t> plain_fetch(plain.begin() + 8, plain.end());
    const std::vector<uint8_t> tokened_fetch(tokened.begin() + 9, tokened.end());
    CHECK(plain_fetch[0] == TTC_MESSAGE_FUNCTION && tokened_fetch[0] == TTC_MESSAGE_FUNCTION);
    CHECK(tokened_fetch[3] == 0);
    CHECK(std::vector<uint8_t>(tokened_fetch.begin() + 4, tokened_fetch.end()) ==
          std::vector<uint8_t>(plain_fetch.begin() + 3, plain_fetch.end()));
    std::cout << "request headers carry a token from field version 18" << std::endl;
}

// A value past what an ordinary bind carries is written into a temporary LOB,
// and the statement binds its locator. Every request here is checked against
// python-oracledb Thin 4.0.1 creating, writing and releasing temporary LOBs and
// inserting them (see PROVENANCE.md).
static void TestTemporaryLobsMatchPython() {
    const std::vector<uint8_t> python_lob_create_temp_clob {
        0x03, 0x60, 0x03, 0x00, 0x01, 0x01, 0x28, 0x00, 0x01, 0x0a, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x02, 0x01, 0x10, 0x00, 0x00, 0x01, 0x01, 0x01, 0x70,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x03, 0x69,
    };
    const std::vector<uint8_t> python_lob_create_temp_blob {
        0x03, 0x60, 0x05, 0x00, 0x01, 0x01, 0x28, 0x00, 0x01, 0x0a, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x02, 0x01, 0x10, 0x00, 0x00, 0x00, 0x01, 0x71, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03,
        0x69,
    };
    const std::vector<uint8_t> python_lob_create_temp_response {
        0x08, 0x00, 0x26, 0x00, 0x01, 0x82, 0x08, 0x80, 0x03, 0x00, 0x02, 0xe9,
        0xb9, 0x00, 0x00, 0x00, 0xdf, 0x00, 0x00, 0x00, 0x01, 0x03, 0x69, 0x00,
        0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xec, 0x1e, 0xab, 0xb1, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x03, 0x69, 0x20, 0x04, 0x01, 0x01,
        0x02, 0x97, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1d,
    };
    const std::vector<uint8_t> python_lob_write_clob_request {
        0x03, 0x60, 0x04, 0x00, 0x01, 0x01, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x00, 0x01, 0x82, 0x08, 0x80, 0x03,
        0x00, 0x02, 0xe9, 0xb9, 0x00, 0x00, 0x00, 0xdf, 0x00, 0x00, 0x00, 0x01,
        0x03, 0x69, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xec, 0x1e,
        0xab, 0xb1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0e, 0xc8, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
        0x00, 0x78, 0x00, 0x78, 0x00, 0x78,
    };
    const std::vector<uint8_t> python_lob_write_response {
        0x08, 0x00, 0x26, 0x00, 0x01, 0x82, 0x08, 0x80, 0x03, 0x00, 0x02, 0xe9,
        0xb9, 0x00, 0x00, 0x00, 0xdf, 0x00, 0x00, 0x00, 0x01, 0x03, 0x69, 0x00,
        0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xec, 0x1e, 0xab, 0xb1, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x01, 0x02, 0x97, 0x13, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x1d,
    };
    const std::vector<uint8_t> python_lob_free_piggyback {
        0x11, 0x60, 0x09, 0x00, 0x01, 0x01, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00, 0x08, 0x01, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x00, 0x01, 0x82, 0x08,
        0x80, 0x03, 0x00, 0x02, 0x31, 0x31, 0x00, 0x00, 0x00, 0x39, 0x00, 0x00,
        0x00, 0x01, 0x03, 0x69, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0xec, 0x1e, 0xab, 0xb1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x26,
        0x00, 0x01, 0x81, 0x08, 0x00, 0x03, 0x00, 0x01, 0x31, 0x31, 0x00, 0x00,
        0x00, 0x39, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0xec, 0x1e, 0xab, 0xb1, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00,
    };
    const std::vector<uint8_t> python_lob_locator_binds {
        0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0x16, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x01, 0x00, 0x00, 0x01,
        0x70, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x69,
        0x01, 0x00, 0x00, 0x71, 0x01, 0x00, 0x00, 0x01, 0x70, 0x00, 0x04, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x02, 0xc1,
        0x4e, 0x01, 0x28, 0x28, 0x00, 0x26, 0x00, 0x01, 0x82, 0x08, 0x80, 0x03,
        0x00, 0x02, 0x31, 0x31, 0x00, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x01,
        0x03, 0x69, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xec, 0x1e,
        0xab, 0xb1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x28, 0x28, 0x00,
        0x26, 0x00, 0x01, 0x81, 0x08, 0x00, 0x03, 0x00, 0x01, 0x31, 0x31, 0x00,
        0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0a, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0xec, 0x1e, 0xab, 0xb1, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00,
    };

    // python writes a token byte after the sequence number; this client's
    // channel adds it when it sends, so the encoders leave it out.
    const auto without_token = [](std::vector<uint8_t> bytes) {
        bytes.erase(bytes.begin() + 3);
        return bytes;
    };
    CHECK(EncodeTtcCreateTempLob(3, TtcTempLobKind::CLOB) == without_token(python_lob_create_temp_clob));
    CHECK(EncodeTtcCreateTempLob(5, TtcTempLobKind::BLOB) == without_token(python_lob_create_temp_blob));

    const std::vector<uint8_t> created_locator(python_lob_create_temp_response.begin() + 1,
                                               python_lob_create_temp_response.begin() + 41);
    CHECK(DecodeCompleteTtcLocatorCall(python_lob_create_temp_response, 1, true, 27) == created_locator);
    // The reply must be whole: half of it is a request for more, not a locator.
    ExpectError(ProtocolErrorKind::TRUNCATED, [&] {
        (void)DecodeCompleteTtcLocatorCall(std::vector<uint8_t>(python_lob_create_temp_response.begin(),
                                                                python_lob_create_temp_response.begin() + 60),
                                           1, true, 27);
    });

    const std::vector<uint8_t> locator(python_lob_write_clob_request.begin() + 28, python_lob_write_clob_request.begin() + 68);
    std::vector<uint8_t> hundred_x;
    for (size_t index = 0; index < 100; index++) {
        hundred_x.push_back(0x00);
        hundred_x.push_back('x');
    }
    CHECK(EncodeTtcWriteLob(4, locator, 1, hundred_x) == without_token(python_lob_write_clob_request));
    const std::vector<uint8_t> written_locator(python_lob_write_response.begin() + 1, python_lob_write_response.begin() + 41);
    CHECK(DecodeCompleteTtcLocatorCall(python_lob_write_response, 1, false, 27) == written_locator);

    // Releasing two at once: python sends the same body in a piggyback.
    const std::vector<uint8_t> first_free(python_lob_free_piggyback.end() - 80, python_lob_free_piggyback.end() - 40);
    const std::vector<uint8_t> second_free(python_lob_free_piggyback.end() - 40, python_lob_free_piggyback.end());
    const auto release = EncodeTtcFreeTempLobs(9, {first_free, second_free});
    // python writes the operation code 0x80111 as four bytes with a leading
    // zero; this client writes the shortest form, which is the same number.
    std::vector<uint8_t> piggyback_body(python_lob_free_piggyback.begin() + 4, python_lob_free_piggyback.end());
    const std::vector<uint8_t> wide_operation {0x04, 0x00, 0x08, 0x01, 0x11};
    const auto operation_at = std::search(piggyback_body.begin(), piggyback_body.end(), wide_operation.begin(),
                                          wide_operation.end());
    CHECK(operation_at != piggyback_body.end());
    const auto narrowed_at =
        piggyback_body.erase(operation_at, operation_at + static_cast<std::ptrdiff_t>(wide_operation.size()));
    piggyback_body.insert(narrowed_at, {0x03, 0x08, 0x01, 0x11});
    CHECK(release[1] == python_lob_free_piggyback[1] && release[2] == python_lob_free_piggyback[2]);
    CHECK(std::vector<uint8_t>(release.begin() + 3, release.end()) == piggyback_body);

    // An INSERT of (id, CLOB, BLOB) binding the two locators.
    const auto &binds_tail = python_lob_locator_binds;
    const std::vector<uint8_t> clob_locator(binds_tail.end() - 83, binds_tail.end() - 43);
    const std::vector<uint8_t> blob_locator(binds_tail.end() - 40, binds_tail.end());
    OracleBind id_bind;
    id_bind.oracle_type = 2;
    id_bind.value = EncodeOracleNumber("77");
    id_bind.maximum_bytes = 22;
    OracleBind clob_bind;
    clob_bind.oracle_type = 112;
    clob_bind.value = clob_locator;
    OracleBind blob_bind;
    blob_bind.oracle_type = 113;
    blob_bind.value = blob_locator;
    TtcExecuteBindsRequest request;
    request.sql = "insert into bl values (:1, :2, :3)";
    request.binds = {id_bind, clob_bind, blob_bind};
    request.ttc_field_version = 24;
    const auto encoded = EncodeTtcExecuteBindsRequest(request);
    CHECK(encoded.size() >= binds_tail.size());
    CHECK(std::vector<uint8_t>(encoded.end() - static_cast<std::ptrdiff_t>(binds_tail.size()), encoded.end()) == binds_tail);

    // A locator is exactly 40 bytes.
    clob_bind.value = std::vector<uint8_t>(39, 0);
    request.binds = {id_bind, clob_bind, blob_bind};
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)EncodeTtcExecuteBindsRequest(request); });
    std::cout << "temporary LOB requests match python-oracledb's" << std::endl;
}

namespace {

// Stands in for the server: hands out locators that change with every write,
// as a real one does, and remembers what it was asked.
class ScriptedLobWriter final : public TemporaryLobWriter {
public:
    std::vector<uint8_t> Create(TtcTempLobKind kind) override {
        kinds.push_back(kind);
        std::vector<uint8_t> locator(40, 0);
        locator[0] = static_cast<uint8_t>(kinds.size());
        return locator;
    }
    std::vector<uint8_t> Write(const std::vector<uint8_t> &locator, uint64_t offset,
                               const std::vector<uint8_t> &data) override {
        if (fail_write_after != 0 && writes.size() + 1 >= fail_write_after) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "scripted write failure");
        }
        writes.push_back({locator[0], offset, data.size()});
        auto updated = locator;
        updated[1]++;
        return updated;
    }
    void Free(const std::vector<std::vector<uint8_t>> &locators) override {
        if (fail_free) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "scripted free failure");
        }
        freed.insert(freed.end(), locators.begin(), locators.end());
    }

    struct WriteCall {
        uint8_t owner;
        uint64_t offset;
        size_t size;
    };
    std::vector<TtcTempLobKind> kinds;
    std::vector<WriteCall> writes;
    std::vector<std::vector<uint8_t>> freed;
    size_t fail_write_after = 0;
    bool fail_free = false;
};

OracleBind LobContentBind(uint8_t kind, std::optional<std::vector<uint8_t>> value) {
    OracleBind bind;
    bind.name = "1";
    bind.oracle_type = kind == 113 ? 23 : 1;
    bind.value = std::move(value);
    bind.lob_content = kind;
    return bind;
}

} // namespace

// What goes through a temporary LOB, in what pieces, and what is released.
static void TestTemporaryLobScope() {
    const size_t big = TEMP_LOB_THRESHOLD_BYTES + 1;
    {
        // Under the threshold nothing changes: the ordinary bind is the proven form.
        std::vector<OracleBind> binds {LobContentBind(112, std::vector<uint8_t>(TEMP_LOB_THRESHOLD_BYTES, 'a'))};
        CHECK(!TemporaryLobScope::Needed(binds));
    }
    {
        // A CLOB is written as UTF-16: offsets count UTF-16 units, so a character
        // outside the BMP moves the offset by two, and pieces never split a character.
        std::string text;
        while (text.size() <= big) {
            text += "ð";
        }
        std::vector<OracleBind> binds {LobContentBind(112, std::vector<uint8_t>(text.begin(), text.end()))};
        CHECK(TemporaryLobScope::Needed(binds));
        ScriptedLobWriter writer;
        TemporaryLobScope scope(writer);
        scope.Convert(binds);
        CHECK(binds[0].oracle_type == 112 && binds[0].lob_content == 0 && binds[0].value && binds[0].value->size() == 40);
        CHECK(writer.kinds.size() == 1 && writer.kinds[0] == TtcTempLobKind::CLOB);
        CHECK(writer.writes.size() >= 4);
        uint64_t expected_offset = 1;
        size_t total_bytes = 0;
        for (const auto &call : writer.writes) {
            CHECK(call.offset == expected_offset);
            CHECK(call.size % 4 == 0 && call.size <= TEMP_LOB_WRITE_CHUNK_BYTES * 2);
            expected_offset += call.size / 2;
            total_bytes += call.size;
        }
        CHECK(total_bytes == text.size()); // 4 UTF-8 bytes become 4 UTF-16 bytes
        // The locator the bind carries is the one the last write returned.
        CHECK((*binds[0].value)[1] == writer.writes.size());
        CHECK(writer.freed.empty());
        scope.Release();
        CHECK(writer.freed.size() == 1);
        scope.Release();
        CHECK(writer.freed.size() == 1);
    }
    {
        // A BLOB's offsets are bytes.
        std::vector<OracleBind> binds {LobContentBind(113, std::vector<uint8_t>(big, 0x5a))};
        ScriptedLobWriter writer;
        TemporaryLobScope scope(writer);
        scope.Convert(binds);
        CHECK(binds[0].oracle_type == 113 && writer.kinds[0] == TtcTempLobKind::BLOB);
        uint64_t expected_offset = 1;
        for (const auto &call : writer.writes) {
            CHECK(call.offset == expected_offset);
            expected_offset += call.size;
        }
        CHECK(expected_offset == big + 1);
    }
    {
        // Array DML declares one set of bind metadata for every row of a group, so a
        // column that needs a temporary LOB in one row is bound by locator in all of them.
        std::vector<std::vector<OracleBind>> rows {
            {LobContentBind(112, std::vector<uint8_t>(big, 'x'))},
            {LobContentBind(112, std::vector<uint8_t>(3, 'y'))},
            {LobContentBind(112, std::nullopt)},
        };
        CHECK(TemporaryLobScope::NeededRows(rows, 0, 3) && !TemporaryLobScope::NeededRows(rows, 1, 3));
        ScriptedLobWriter writer;
        TemporaryLobScope scope(writer);
        scope.ConvertRows(rows);
        CHECK(rows[0][0].oracle_type == 112 && rows[1][0].oracle_type == 112 && rows[2][0].oracle_type == 112);
        CHECK(rows[0][0].value->size() == 40 && rows[1][0].value->size() == 40 && !rows[2][0].value);
        CHECK(writer.kinds.size() == 2);
        scope.Release();
        CHECK(writer.freed.size() == 2);
    }
    {
        // A write that fails still releases what exists, without throwing.
        std::vector<OracleBind> binds {LobContentBind(112, std::vector<uint8_t>(big, 'x'))};
        ScriptedLobWriter writer;
        writer.fail_write_after = 2;
        TemporaryLobScope scope(writer);
        ExpectError(ProtocolErrorKind::INVALID_STATE, [&] { scope.Convert(binds); });
        scope.ReleaseQuietly();
        CHECK(writer.freed.size() == 1);
        // And a refused release is swallowed on that path, reported on the normal one.
        ScriptedLobWriter refusing;
        refusing.fail_free = true;
        std::vector<OracleBind> more {LobContentBind(113, std::vector<uint8_t>(big, 1))};
        TemporaryLobScope second(refusing);
        second.Convert(more);
        ExpectError(ProtocolErrorKind::INVALID_STATE, [&] { second.Release(); });
        TemporaryLobScope third(refusing);
        std::vector<OracleBind> again {LobContentBind(113, std::vector<uint8_t>(big, 1))};
        third.Convert(again);
        third.ReleaseQuietly();
    }
    {
        // Text that is not UTF-8 is refused rather than written.
        std::vector<uint8_t> broken(big, 'a');
        broken[10] = 0xFF;
        std::vector<OracleBind> binds {LobContentBind(112, broken)};
        ScriptedLobWriter writer;
        TemporaryLobScope scope(writer);
        ExpectError(ProtocolErrorKind::MALFORMED, [&] { scope.Convert(binds); });
        scope.ReleaseQuietly();
    }
    std::cout << "temporary LOB scope converts, chunks and releases" << std::endl;
}

// Session attributes travel as a piggyback in front of the next call, in the
// shape python-oracledb Thin 4.0.1 sends when `module`, `action`,
// `client_identifier` or `clientinfo` is set (see PROVENANCE.md).
static void TestEndToEndAttributesMatchPython() {
    const std::vector<uint8_t> python_end_to_end_module {
        0x11, 0x87, 0x03, 0x00, 0x00, 0x00, 0x01, 0x18, 0x00, 0x00, 0x01, 0x01,
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x6d,
    };
    const std::vector<uint8_t> python_end_to_end_all {
        0x11, 0x87, 0x03, 0x00, 0x00, 0x00, 0x02, 0x01, 0x19, 0x01, 0x01, 0x03,
        0x01, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x63, 0x63, 0x63, 0x02,
        0x6d, 0x6d, 0x03, 0x61, 0x61, 0x61, 0x04, 0x69, 0x69, 0x69, 0x69,
    };
    const std::vector<uint8_t> python_end_to_end_client_info {
        0x11, 0x87, 0x03, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x69, 0x6e, 0x66, 0x6f,
    };
    const auto without_token = [](std::vector<uint8_t> bytes) {
        bytes.erase(bytes.begin() + 3);
        return bytes;
    };
    TtcEndToEndAttributes module_only;
    module_only.module = "m";
    CHECK(EncodeTtcEndToEndPiggyback(3, module_only) == without_token(python_end_to_end_module));
    TtcEndToEndAttributes everything;
    everything.client_identifier = "ccc";
    everything.module = "mm";
    everything.action = "aaa";
    everything.client_info = "iiii";
    CHECK(EncodeTtcEndToEndPiggyback(3, everything) == without_token(python_end_to_end_all));
    TtcEndToEndAttributes info_only;
    info_only.client_info = "info";
    CHECK(EncodeTtcEndToEndPiggyback(3, info_only) == without_token(python_end_to_end_client_info));
    ExpectError(ProtocolErrorKind::MALFORMED, [] { (void)EncodeTtcEndToEndPiggyback(1, TtcEndToEndAttributes()); });
    TtcEndToEndAttributes too_long;
    too_long.action = std::string(33, 'x');
    ExpectError(ProtocolErrorKind::LIMIT_EXCEEDED, [&] { (void)EncodeTtcEndToEndPiggyback(1, too_long); });
    std::cout << "end-to-end attributes match python-oracledb's" << std::endl;
}

// An anonymous block is sent as written, less a SQL*Plus terminator, and its
// binds are matched to its placeholders by first mention.
static void TestAnonymousBlocks() {
    CHECK(NormalizeOracleAnonymousBlock("BEGIN NULL; END;") == "BEGIN NULL; END;");
    CHECK(NormalizeOracleAnonymousBlock("  -- c\n declare x number; begin x := 1; end;  \n") ==
          "  -- c\n declare x number; begin x := 1; end;");
    CHECK(NormalizeOracleAnonymousBlock("BEGIN\n  NULL;\nEND;\n/\n") == "BEGIN\n  NULL;\nEND;");
    // Not blocks, or not whole ones.
    for (const char *text : {"SELECT 1 FROM dual", "CALL p()", "BEGIN NULL; END", "BEGIN NULL; END; /", ""}) {
        ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)NormalizeOracleAnonymousBlock(text); });
    }
    OracleCallRequest request;
    request.kind = OracleCallableKind::ANONYMOUS_BLOCK;
    request.block = "BEGIN :b := :a || 'x'; END;";
    OracleBind a;
    a.name = "a";
    a.oracle_type = 1;
    a.value = std::vector<uint8_t> {'1'};
    OracleBind b;
    b.name = "b";
    b.oracle_type = 1;
    b.direction = BindDirection::BIND_OUT;
    b.maximum_bytes = 100;
    request.arguments = {a, b};
    CHECK(BuildOracleCallBlock(request) == "BEGIN :b := :a || 'x'; END;");
    const auto ordered = OrderOracleStatementBinds(request.block, request.arguments, OracleBindUse::CALL);
    CHECK(ordered.size() == 2 && ordered[0].name == "b" && ordered[1].name == "a");
    // A bind the block does not mention, or a placeholder without a bind, is refused.
    ExpectError(ProtocolErrorKind::MALFORMED, [&] {
        (void)OrderOracleStatementBinds(request.block, {a}, OracleBindUse::CALL);
    });
    request.qualified_name = "P";
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)BuildOracleCallBlock(request); });
    request.qualified_name.clear();
    request.kind = OracleCallableKind::PROCEDURE;
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { (void)BuildOracleCallBlock(request); });
    std::cout << "anonymous PL/SQL blocks are normalised and their binds ordered" << std::endl;
}

// The server reports the session state it changed in a message of its own (type
// 23), and 23ai sends one inside a PL/SQL response, in front of its end-of-call.
// The report below is what python-oracledb received after setting module, action,
// client identifier and client info (see PROVENANCE.md).
static void TestServerPiggybacksAreSkipped() {
    const std::vector<uint8_t> python_server_piggyback {
        0x17, 0x05, 0x01, 0x01, 0x10, 0x01, 0x04, 0x16, 0x01, 0x02, 0x02, 0x6d,
        0x6d, 0x00, 0x01, 0xb8, 0x01, 0x03, 0x03, 0x61, 0x61, 0x61, 0x00, 0x01,
        0xb9, 0x01, 0x04, 0x04, 0x69, 0x69, 0x69, 0x69, 0x00, 0x01, 0xba, 0x01,
        0x03, 0x03, 0x63, 0x63, 0x63, 0x00, 0x01, 0xc6, 0x00,
    };
    CHECK(SkippedTtcServerPiggybackBytes(python_server_piggyback.data(), python_server_piggyback.size()) ==
          python_server_piggyback.size());
    // Followed by a status and the end of the call, as in the response to a ping.
    auto message = python_server_piggyback;
    message.insert(message.end(), {0x09, 0x01, 0x01, 0x02, 0xc6, 0x10, 0x1d});
    CHECK(SkippedTtcServerPiggybackBytes(message.data(), message.size()) == python_server_piggyback.size());
    const auto decoded = DecodeTtcCallResponse(message, {}, 24, 27);
    // The status completes the call; the end-of-request marker behind it is the caller's.
    CHECK(decoded.completed && decoded.bytes_consumed == python_server_piggyback.size() + 6);
    // Cut short, it is a request for more; a report of a session change is not skipped.
    ExpectError(ProtocolErrorKind::TRUNCATED, [&] {
        (void)SkippedTtcServerPiggybackBytes(python_server_piggyback.data(), python_server_piggyback.size() - 20);
    });
    auto changed = python_server_piggyback;
    changed.back() = 0x01; // flags: a length of one byte ...
    changed.push_back(0x01); // ... holding 1, a session change
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [&] { (void)SkippedTtcServerPiggybackBytes(changed.data(), changed.size()); });
    ExpectError(ProtocolErrorKind::UNSUPPORTED, [&] {
        const std::vector<uint8_t> other {0x17, 0x01, 0x00};
        (void)SkippedTtcServerPiggybackBytes(other.data(), other.size());
    });
    std::cout << "a server piggyback inside a response is skipped" << std::endl;
}

// A VECTOR is written as its image in a locator, as python-oracledb Thin does,
// and keeps its place among the binds when the statement has short ones after it.
static void TestVectorBindsMatchPython() {
    // python-oracledb 4.0.1 Thin against Free 23ai, an insert of one VECTOR column, `array('f', [1.5, 2, 3])`: the bind's metadata, then the row (a locator that states the image's length, then the image)
    const std::vector<uint8_t> python_vector_float32_bind {
        0x00,
    };

    // python-oracledb 4.0.1 Thin against Free 23ai, the same, `array('b', [1, -2, 3])`: the bind's metadata, then the row (a locator that states the image's length, then the image)
    const std::vector<uint8_t> python_vector_int8_bind {
        0x03,
    };

    // python-oracledb 4.0.1 Thin against Free 23ai, the same, `SparseVector(5, [1, 3], array('f', [1.5, 2.5]))`: the bind's metadata, then the row (a locator that states the image's length, then the image)
    const std::vector<uint8_t> python_vector_sparse_bind {
        0x00,
    };

    // the same client's UPDATE that sets six VECTOR columns, a JSON text, the id and a rowid: the row, in which the six vectors come first, in the order the binds are declared, ahead of the short binds declared after them
    const std::vector<uint8_t> python_vector_update_row {
        0x07, 0x01, 0x28, 0x28, 0x00, 0x26, 0x00, 0x04, 0x61, 0x08, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1d, 0xdb, 0x00, 0x00,
        0x12, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xc1, 0x10, 0x00, 0x00, 0xc1, 0x00, 0x00, 0x00, 0xc0, 0xe0,
        0x00, 0x00, 0x01, 0x28, 0x28, 0x00, 0x26, 0x00, 0x04, 0x61, 0x08, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0xdb, 0x02,
        0x00, 0x32, 0x02, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x28, 0x28, 0x00, 0x26, 0x00, 0x04,
        0x61, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x19, 0xdb, 0x00, 0x00, 0x12, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x1c, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x28, 0x28, 0x00, 0x26, 0x00, 0x04, 0x61, 0x08, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0xdb, 0x01,
        0x00, 0x10, 0x05, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x28, 0x28, 0x00, 0x26, 0x00, 0x04,
        0x61, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x15, 0xdb, 0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x01, 0x28,
        0x28, 0x00, 0x26, 0x00, 0x04, 0x61, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0xdb, 0x00, 0x00, 0x12, 0x03, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81,
        0xa5, 0x6e, 0x1f, 0xc2, 0xf8, 0xf3, 0x59, 0xc0, 0x08, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x07, 0x7b, 0x22, 0x75, 0x22, 0x3a, 0x31, 0x7d, 0x02,
        0xc1, 0x04, 0x12, 0x41, 0x41, 0x43, 0x2f, 0x56, 0x50, 0x41, 0x41, 0x59,
        0x41, 0x41, 0x41, 0x43, 0x6e, 0x73, 0x41, 0x41, 0x43,
    };

    // python writes the 1 MiB buffer size as four bytes, a leading zero among
    // them; this client writes the shortest form, which is the same number.
    const auto minimal = [](std::vector<uint8_t> captured) {
        const std::vector<uint8_t> wide {0x04, 0x00, 0x10, 0x00, 0x00};
        const std::vector<uint8_t> narrow {0x03, 0x10, 0x00, 0x00};
        for (size_t at = 0; at + wide.size() <= captured.size();) {
            if (std::equal(wide.begin(), wide.end(), captured.begin() + static_cast<std::ptrdiff_t>(at))) {
                captured.erase(captured.begin() + static_cast<std::ptrdiff_t>(at),
                               captured.begin() + static_cast<std::ptrdiff_t>(at + wide.size()));
                captured.insert(captured.begin() + static_cast<std::ptrdiff_t>(at), narrow.begin(), narrow.end());
                at += narrow.size();
            } else {
                at++;
            }
        }
        return captured;
    };
    const auto encode_tail = [](std::vector<OracleBind> binds, size_t tail_size) {
        TtcExecuteBindsRequest request;
        request.sql = "X";
        request.binds = std::move(binds);
        request.ttc_field_version = 24;
        const auto encoded = EncodeTtcExecuteBindsRequest(request);
        return std::vector<uint8_t>(encoded.end() - static_cast<std::ptrdiff_t>(tail_size), encoded.end());
    };
    const auto vector_bind = [](const OracleVector &vector) {
        OracleBind bind;
        bind.oracle_type = ORACLE_WIRE_TYPE_VECTOR;
        bind.value = EncodeOracleVector(vector);
        return bind;
    };
    OracleVector dense;
    dense.format = ORACLE_VECTOR_FLOAT32;
    dense.dimensions = 3;
    dense.float32 = {1.5F, 2.0F, 3.0F};
    auto expected = minimal(python_vector_float32_bind);
    CHECK(encode_tail({vector_bind(dense)}, expected.size()) == expected);

    OracleVector int8_vector;
    int8_vector.format = ORACLE_VECTOR_INT8;
    int8_vector.dimensions = 3;
    int8_vector.int8 = {1, -2, 3};
    expected = minimal(python_vector_int8_bind);
    CHECK(encode_tail({vector_bind(int8_vector)}, expected.size()) == expected);

    OracleVector sparse;
    sparse.format = ORACLE_VECTOR_FLOAT32;
    sparse.sparse = true;
    sparse.dimensions = 5;
    sparse.indices = {1, 3};
    sparse.float32 = {1.5F, 2.5F};
    expected = minimal(python_vector_sparse_bind);
    CHECK(encode_tail({vector_bind(sparse)}, expected.size()) == expected);

    // Six vectors, then the short binds declared after them: the row has the
    // vectors first.
    OracleVector empty_sparse;
    empty_sparse.format = ORACLE_VECTOR_FLOAT32;
    empty_sparse.sparse = true;
    empty_sparse.dimensions = 6;
    OracleVector f32;
    f32.format = ORACLE_VECTOR_FLOAT32;
    f32.dimensions = 3;
    f32.float32 = {9.0F, 8.0F, 7.0F};
    OracleVector f64_one;
    f64_one.format = ORACLE_VECTOR_FLOAT64;
    f64_one.dimensions = 1;
    f64_one.float64 = {7.0};
    OracleVector binary;
    binary.format = ORACLE_VECTOR_BINARY;
    binary.dimensions = 16;
    binary.binary = {0, 0};
    OracleVector i8;
    i8.format = ORACLE_VECTOR_INT8;
    i8.dimensions = 4;
    i8.int8 = {1, 2, 3, 4};
    OracleVector f64_two;
    f64_two.format = ORACLE_VECTOR_FLOAT64;
    f64_two.dimensions = 2;
    f64_two.float64 = {1e-300, 3.0};
    OracleBind json_text;
    json_text.oracle_type = 1;
    json_text.value = std::vector<uint8_t> {'{', '"', 'u', '"', ':', '1', '}'};
    OracleBind id;
    id.oracle_type = 2;
    id.value = EncodeOracleNumber("3");
    OracleBind rowid;
    rowid.oracle_type = 1;
    const std::string rowid_text = "AAC/VPAAYAAACnsAAC";
    rowid.value = std::vector<uint8_t>(rowid_text.begin(), rowid_text.end());
    CHECK(encode_tail({vector_bind(f32), vector_bind(empty_sparse), vector_bind(f64_one), vector_bind(binary), vector_bind(i8),
                       vector_bind(f64_two), json_text, id, rowid},
                      python_vector_update_row.size()) == python_vector_update_row);

    // A vector too long for the buffer it is declared with is refused.
    OracleBind too_long;
    too_long.oracle_type = ORACLE_WIRE_TYPE_VECTOR;
    too_long.value = std::vector<uint8_t>((1U << 20U) + 1, 0);
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { encode_tail({too_long}, 1); });

    // The encoder refuses a vector that disagrees with itself.
    OracleVector wrong_count = dense;
    wrong_count.dimensions = 4;
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { EncodeOracleVector(wrong_count); });
    OracleVector backwards = sparse;
    backwards.indices = {3, 1};
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { EncodeOracleVector(backwards); });
    OracleVector outside = sparse;
    outside.indices = {1, 5};
    ExpectError(ProtocolErrorKind::MALFORMED, [&] { EncodeOracleVector(outside); });

    // What it writes it reads back.
    for (const auto *original : {&dense, &int8_vector, &sparse, &binary, &f64_two}) {
        const auto read = DecodeOracleVector(EncodeOracleVector(*original));
        CHECK(read.format == original->format && read.dimensions == original->dimensions && read.sparse == original->sparse &&
              read.indices == original->indices && read.float32 == original->float32 && read.float64 == original->float64 &&
              read.int8 == original->int8 && read.binary == original->binary);
    }
    std::cout << "VECTOR binds match python-oracledb's" << std::endl;
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
    TestStatementChannelJoinsFragmentedExecuteResponse();
    TestTtcCancellation();
    TestTtcErrorDiagnostics();
    TestTtcParameters();
    TestTtcAuthEncoding();
    TestTtcFetchCodec();
    TestTtcFetchResponse();
    TestFetchResponseDecoderResumes();
    TestOracleIntegerMatchesDecimalText();
    TestNewTypeValues();
    TestBooleanLocalZoneAndWrites();
    TestJsonAndVectorImages();
    TestRequestHeadersCarryATokenFromFieldVersion18();
    TestTemporaryLobsMatchPython();
    TestTemporaryLobScope();
    TestEndToEndAttributesMatchPython();
    TestAnonymousBlocks();
    TestServerPiggybacksAreSkipped();
    TestVectorBindsMatchPython();
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
    TestTlsReadFailureDoesNotKillTheProcess();
    TestTlsReadIgnoresUnrelatedErrorQueue();
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
    TestDmlCompositeBlock();
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
    TestReadWaitsThroughSignalsAndHighDescriptors();
#endif
    TestConnectRunsThroughTheTransportSeam();
    TestRedirectDataSplitting();
    TestRedirectPacketFraming();
    TestRefusalCarriesTheOracleCode();
    TestReconnectCarriesTheRedirectFlag();
    TestDescriptorRoutingParameters();
    TestRedirectAddressParsing();
    TestConnectOrderPolicy();
    TestRoutedConfigValidationAndDescriptors();
    TestConnectFailsOverToTheNextAddress();
    TestRefusalFailsOverAndKeepsTheCode();
    TestEveryAddressUnreachableIsListed();
    TestScanNameWithSeveralAddresses();
    TestScanListenerRedirectsToANode();
    TestRedirectWithoutReconnectDataIsRebuilt();
    TestUnreachableRedirectTargetFallsBack();
    TestRedirectCyclesAndLimits();
    TestRedirectCannotChangeTheProtocol();
    TestMalformedListenerAnswersAreNotFailedOver();
    TestUnresolvableNameFailsOver();
    TestRetriesDelaysAndTheBudget();
    TestCancellationStopsTheConnect();
    TestLoadBalanceShufflesEachConnection();
    TestRedirectChainKeepsEachLevelsAlternatives();
    TestListenerEchoOfTheClientsConnectData();
    TestOobProbeAfterRedirectAcceptsTheRedirectFlag();
    TestBudgetHoldsThroughTheListenerExchange();
    TestSlowNameResolutionIsCutOffByTheBudget();
    TestResolverWorkersAreBounded();
    TestBudgetHoldsUntilAuthentication();
    TestRedirectTextStaysOutOfErrors();
#if !defined(_WIN32)
    TestLoopbackListenersFailoverAndRedirect();
    TestSilentListenerIsBoundedByTheBudget();
    TestSilentServerAfterAcceptIsBoundedByTheBudget();
#endif
    TestTransportWithoutOutOfBandRefusesTheOobProbe();
    TestRepeatedRowsCarryNoValues();
    TestTtcErrorTailEndsTheResponse();
    TestNegotiatedTtcFieldVersion();
    TestEndOfResponseNegotiation();
    TestSessionFactory();
    TestSessionPool();
    TestSsoWallet();
    TestEasyConnectAndTnsNamesFolder();
    TestLobPrefetchMaterializer();
    TestLobPrefetchScalarBudget();
    TestLobPrefetchDecoderResumes();
    TestTransactionPoolReusesAfterAConfirmedEnd();
    TestTransactionPoolClosesWhatIsNotClean();
    TestTransactionPoolReplacesASessionThatDiedIdle();
    TestTransactionPoolIsBounded();
    TestTransactionPoolFollowsEachCallersDeadline();
    TestLobCallIsCompleteOnlyWithItsEndOfCall();
    TestLobCallRefusalsKeepTheirOracleError();
    TestLobOperationReadsTheWholeResponse();
    TestLobOperationObeysTheDeadlineMidResponse();
    std::cout << "oracle_scanner protocol tests passed\n";
    return 0;
}

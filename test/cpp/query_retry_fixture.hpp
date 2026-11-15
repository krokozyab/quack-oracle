#pragma once

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/byte_stream.hpp"
#include "oracle_scanner/ttc_statement_channel.hpp"
#include "oracle_scanner/value_codec.hpp"
#include <algorithm>
#include <cstring>

namespace oracle_scanner_test {
using namespace oracle_scanner;

// Synthetic TTC fields, not captured bytes. A NUMBER column and an end-of-call.
inline std::vector<uint8_t> QueryReply(uint32_t cursor, uint32_t error, bool describe, bool row) {
    ByteWriter out;
    if (describe) {
        out.WriteByte(16).WriteLengthPrefixed(std::nullopt).WriteUB4(0).WriteUB4(1).WriteByte(0);
        out.WriteByte(2).WriteByte(0).WriteByte(10).WriteByte(0);
        out.WriteUB4(22).WriteUB4(0).WriteUB8(0).WriteUB4(0);
        out.WriteUB2(0).WriteUB2(0).WriteByte(0).WriteUB4(0).WriteUB4(0);
        out.WriteByte(1).WriteByte(0).WriteUB4(1).WriteLengthPrefixed(std::vector<uint8_t>({'V'}));
        out.WriteUB4(0).WriteUB4(0).WriteUB2(0).WriteUB4(0);
        out.WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0).WriteUB4(0);
    }
    if (row) {
        out.WriteByte(TTC_MESSAGE_ROW_DATA).WriteLengthPrefixed(EncodeOracleNumber("7"));
    }
    out.WriteByte(TTC_MESSAGE_ERROR).WriteUB4(0).WriteUB2(0).WriteUB4(0);
    out.WriteUB2(0).WriteUB2(0).WriteUB2(0).WriteUB4(cursor).WriteUB4(0);
    out.WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0);
    out.WriteUB4(0).WriteUB2(0).WriteByte(0).WriteUB4(0).WriteUB2(0);
    out.WriteUB4(0).WriteByte(0).WriteByte(0).WriteUB2(0).WriteUB4(0).WriteByte(0);
    out.WriteUB2(0).WriteUB4(0).WriteUB2(0).WriteUB4(error).WriteUB8(row ? 1 : 0);
    if (error) {
        const std::string message = "ORA-" + std::to_string(error);
        out.WriteLengthPrefixed(std::vector<uint8_t>(message.begin(), message.end()));
    }
    return out.Take();
}

class ReplyStream final : public ByteStream {
public:
    std::vector<uint8_t> input, output;
    size_t position = 0;
    size_t Read(uint8_t *destination, size_t size) override {
        const auto count = (std::min)(size, input.size() - position);
        if (count) {
            std::memcpy(destination, input.data() + position, count);
            position += count;
        }
        return count;
    }
    size_t Write(const uint8_t *data, size_t size) override {
        output.insert(output.end(), data, data + size);
        return size;
    }
    void Close() override {}
    void Append(const std::vector<uint8_t> &message) {
        for (const auto &packet : EncodeTnsDataPackets(message, true, 512)) {
            input.insert(input.end(), packet.begin(), packet.end());
        }
    }
};

class QueryExchange {
public:
    ReplyStream stream;
    TnsPacketStream packets {stream, true, 512};
    TtcChannel ttc {packets, 512};
    OracleStatementRegistry registry;
    TtcStatementChannel channel {ttc, registry};
    OracleStatementHandle handle;
    std::vector<OracleColumn> columns {{"V", 2, 22, 10, 0}};
    uint8_t sequence = 0;
    bool allow_retry = true;
    QueryExchange() {
        handle = registry.Open(OracleSqlKind::QUERY);
        channel.CompleteExecute(handle, true, 42);
        channel.MarkFetchExhausted(handle);
    }
    TtcExecuteResponse Run(const std::vector<OracleBind> &binds = {}) {
        auto result = channel.ExecuteQuery(handle, binds.empty() ? "SELECT 7 V FROM dual" : "SELECT :n V FROM dual",
            binds, 2, 12, 12, [&] { return ++sequence; }, &columns, [&] { return allow_retry; });
        channel.CompleteExecute(handle, true, result.completion->cursor_id);
        return result;
    }
};
} // namespace oracle_scanner_test

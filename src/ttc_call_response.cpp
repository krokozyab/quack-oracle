#include "oracle_scanner/ttc_call_response.hpp"

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_parameter.hpp"
#include "oracle_scanner/ttc_row_data.hpp"

namespace oracle_scanner {

namespace {

constexpr uint8_t TTC_MESSAGE_STATUS = 9;
constexpr uint8_t TTC_MESSAGE_END_OF_REQUEST = 29;

std::vector<uint8_t> Tail(const std::vector<uint8_t> &message, size_t offset) {
    return {message.begin() + static_cast<std::ptrdiff_t>(offset), message.end()};
}

} // namespace

TtcCallResponse DecodeTtcCallResponse(const std::vector<uint8_t> &message, const std::vector<OracleBind> &binds,
                                      uint8_t ttc_field_version, uint8_t server_field_version) {
    TtcCallResponse result;
    std::optional<TtcIoVector> io_vector;
    std::vector<size_t> output_indexes;
    size_t offset = 0;
    while (offset < message.size() && !result.completed) {
        const auto tail = Tail(message, offset);
        switch (tail.front()) {
        case TTC_MESSAGE_IO_VECTOR:
            if (io_vector) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "PL/SQL response has more than one IO_VECTOR");
            }
            io_vector = DecodeTtcIoVectorPrefix(tail);
            output_indexes = GetTtcOutputBindIndexes(*io_vector, binds);
            offset += io_vector->bytes_consumed;
            break;
        case TTC_MESSAGE_ROW_DATA: {
            if (!io_vector || result.out_binds) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "PL/SQL response has an unexpected OUT-bind ROW_DATA");
            }
            auto values = DecodeTtcOutBindsRow(tail, binds, output_indexes, ttc_field_version);
            offset += values.bytes_consumed;
            result.out_binds = std::move(values);
            break;
        }
        case TTC_MESSAGE_IMPLICIT_RESULT_SET: {
            auto implicit = DecodeTtcImplicitResultSetPrefix(tail, ttc_field_version);
            result.implicit_cursors.insert(result.implicit_cursors.end(), std::make_move_iterator(implicit.cursors.begin()),
                                           std::make_move_iterator(implicit.cursors.end()));
            offset += implicit.bytes_consumed;
            break;
        }
        case TTC_MESSAGE_PARAMETER: {
            const auto parameter = DecodeTtcReturnParameterPrefix(tail);
            offset += parameter.bytes_consumed;
            break;
        }
        case TTC_MESSAGE_ERROR: {
            const auto completion = DecodeTtcErrorPrefix(tail, server_field_version);
            offset += completion.bytes_consumed;
            result.completion = completion;
            if (completion.error_number != 0) {
                throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                                    completion.message.empty() ? "Oracle returned a TTC execute error" : completion.message);
            }
            result.completed = completion.bytes_consumed == tail.size();
            break;
        }
        case TTC_MESSAGE_STATUS: {
            ByteReader reader(tail);
            reader.ReadByte();
            reader.ReadUB4();
            reader.ReadUB2();
            offset += reader.Position();
            result.completed = true;
            break;
        }
        case TTC_MESSAGE_END_OF_REQUEST:
            offset++;
            result.completed = true;
            break;
        default:
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "unknown TTC message in PL/SQL response");
        }
    }
    result.bytes_consumed = offset;
    return result;
}

} // namespace oracle_scanner

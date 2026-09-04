#include "oracle_scanner/ttc_execute_response.hpp"

#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_describe.hpp"
#include "oracle_scanner/ttc_fetch_response.hpp"
#include "oracle_scanner/ttc_parameter.hpp"

#include <string>

namespace oracle_scanner {

TtcExecuteResponse DecodeTtcExecuteResponse(const std::vector<uint8_t> &message, uint8_t ttc_field_version,
                                            uint8_t server_field_version) {
    TtcDescribeInfo describe;
    try {
        describe = DecodeTtcDescribeInfoPrefix(message, ttc_field_version);
    } catch (const ProtocolError &error) {
        throw ProtocolError(error.Kind(), std::string("TTC execute DESCRIBE_INFO: ") + error.what());
    }
    if (describe.bytes_consumed >= message.size()) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED, "TTC execute response ended after DESCRIBE_INFO");
    }
    std::vector<uint8_t> remainder(message.begin() + static_cast<std::ptrdiff_t>(describe.bytes_consumed), message.end());
    TtcFetchResponse fetch;
    try {
        fetch = DecodeTtcFetchResponse(remainder, describe.columns, server_field_version);
    } catch (const ProtocolError &error) {
        throw ProtocolError(error.Kind(), std::string("TTC execute response after DESCRIBE_INFO: ") + error.what());
    }
    TtcExecuteResponse result;
    result.columns = describe.columns;
    result.rows = fetch.rows;
    result.completion = fetch.completion;
    result.exhausted = fetch.exhausted;
    result.completed = fetch.completed;
    result.bytes_consumed = describe.bytes_consumed + fetch.bytes_consumed;
    return result;
}

TtcErrorInfo DecodeTtcExecuteCompletion(const std::vector<uint8_t> &message, uint8_t ttc_field_version) {
    try {
        // Oracle puts RETURN_PARAMETER ahead of the final TTIOER for DML
        // too. Drain those prefixes but intentionally do not use the PL/SQL
        // success fallback: DML must preserve the TTIOER row count.
        size_t offset = 0;
        while (offset < message.size() && message[offset] == TTC_MESSAGE_PARAMETER) {
            const std::vector<uint8_t> tail(message.begin() + static_cast<std::ptrdiff_t>(offset), message.end());
            const auto parameter = DecodeTtcReturnParameterPrefix(tail);
            offset += parameter.bytes_consumed;
        }
        if (offset == message.size()) {
            throw ProtocolError(ProtocolErrorKind::TRUNCATED, "TTC non-query execute response has no completion");
        }
        const std::vector<uint8_t> completion(message.begin() + static_cast<std::ptrdiff_t>(offset), message.end());
        return DecodeTtcErrorPrefix(completion, ttc_field_version);
    } catch (const ProtocolError &error) {
        const auto message_type = message.empty() ? std::string("none") : std::to_string(message.front());
        throw ProtocolError(error.Kind(), std::string("TTC non-query execute completion (message type ") + message_type +
                                              "): " + error.what());
    }
}

} // namespace oracle_scanner

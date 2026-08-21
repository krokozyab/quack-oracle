#include "oracle_scanner/ttc_auth.hpp"
#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"

namespace oracle_scanner {

namespace {

constexpr size_t MAX_AUTH_PARAMETERS = 64;
constexpr size_t MAX_AUTH_VALUE_BYTES = 65535;

std::vector<uint8_t> ToBytes(const std::string &value) {
    return std::vector<uint8_t>(value.begin(), value.end());
}

void WriteTwoLengths(ByteWriter &writer, const std::string &value) {
    if (value.size() > MAX_AUTH_VALUE_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC authentication parameter is too large");
    }
    writer.WriteUB4(static_cast<uint32_t>(value.size()));
    if (!value.empty()) {
        writer.WriteLengthPrefixed(ToBytes(value));
    }
}

} // namespace

std::vector<uint8_t> EncodeTtcAuthFunction(uint8_t function_code, uint8_t sequence, const std::string &username,
                                           uint32_t auth_mode, const std::vector<TtcParameter> &parameters) {
    if ((function_code != TTC_FUNCTION_AUTH_PHASE_ONE && function_code != TTC_FUNCTION_AUTH_PHASE_TWO) ||
        username.size() > 252 || parameters.size() > MAX_AUTH_PARAMETERS) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC authentication function arguments are invalid");
    }
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_FUNCTION).WriteByte(function_code).WriteByte(sequence);
    writer.WriteByte(username.empty() ? 0 : 1); // username pointer
    writer.WriteUB4(static_cast<uint32_t>(username.size()));
    writer.WriteUB4(auth_mode);
    writer.WriteByte(1); // client authentication context is present
    writer.WriteUB4(static_cast<uint32_t>(parameters.size()));
    writer.WriteByte(1).WriteByte(1); // auth-out value and length descriptors
    if (!username.empty()) {
        writer.WriteLengthPrefixed(ToBytes(username));
    }
    for (const auto &parameter : parameters) {
        if (parameter.key.empty()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC authentication parameter key is empty");
        }
        WriteTwoLengths(writer, parameter.key);
        WriteTwoLengths(writer, parameter.value);
        writer.WriteUB4(parameter.flags);
    }
    return writer.Take();
}

std::vector<TtcParameter> BuildO5LogonPhaseTwoParameters(const O5LogonResponse &response) {
    if (response.client_session_key_hex.empty() || response.encrypted_password_hex.empty() || response.combo_key.size() != 32) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "O5LOGON response is incomplete");
    }
    return {{"AUTH_SESSKEY", response.client_session_key_hex, 1},
            {"AUTH_PBKDF2_SPEEDY_KEY", response.speedy_key_hex, 0},
            {"AUTH_PASSWORD", response.encrypted_password_hex, 0}};
}

} // namespace oracle_scanner

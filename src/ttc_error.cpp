#include "oracle_scanner/ttc_error.hpp"
#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <algorithm>
#include <cctype>

namespace oracle_scanner {

namespace {

constexpr size_t MAX_ERROR_TEXT_BYTES = 512;
constexpr size_t MAX_BATCH_ERRORS = 65535;
constexpr size_t MAX_TTC_ERROR_TEXT_BYTES = 65535;

std::string PrintableProjection(const std::vector<uint8_t> &message) {
    std::string output;
    output.reserve((std::min)(message.size(), MAX_ERROR_TEXT_BYTES));
    bool previous_space = true;
    for (size_t index = 1; index < message.size() && output.size() < MAX_ERROR_TEXT_BYTES; index++) {
        const auto character = message[index];
        if (character >= 0x20 && character <= 0x7e) {
            output.push_back(static_cast<char>(character));
            previous_space = false;
        } else if (!previous_space) {
            output.push_back(' ');
            previous_space = true;
        }
    }
    while (!output.empty() && output.back() == ' ') {
        output.pop_back();
    }
    return output;
}

std::optional<uint32_t> FindOraCode(const std::string &text, size_t &offset) {
    for (size_t index = 0; index + 9 <= text.size(); index++) {
        if (text.compare(index, 4, "ORA-") != 0) {
            continue;
        }
        uint32_t value = 0;
        bool digits = true;
        for (size_t digit = 0; digit < 5; digit++) {
            const auto character = static_cast<unsigned char>(text[index + 4 + digit]);
            if (!std::isdigit(character)) {
                digits = false;
                break;
            }
            value = value * 10 + static_cast<uint32_t>(character - '0');
        }
        if (digits) {
            offset = index;
            return value;
        }
    }
    return std::nullopt;
}

void SkipPackedUb2Array(ByteReader &reader) {
    const auto count = reader.ReadUB2();
    if (count == 0) {
        return;
    }
    const auto marker = reader.ReadByte();
    for (uint16_t index = 0; index < count; index++) {
        if (marker == TNS_LONG_LENGTH_INDICATOR) {
            reader.ReadUB4();
        }
        reader.ReadUB2();
    }
    if (marker == TNS_LONG_LENGTH_INDICATOR) {
        reader.Skip(1);
    }
}

void SkipPackedUb4Array(ByteReader &reader) {
    const auto count = reader.ReadUB4();
    if (count > MAX_BATCH_ERRORS) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC ERROR batch array exceeds supported bounds");
    }
    if (count == 0) {
        return;
    }
    const auto marker = reader.ReadByte();
    for (uint32_t index = 0; index < count; index++) {
        if (marker == TNS_LONG_LENGTH_INDICATOR) {
            reader.ReadUB4();
        }
        reader.ReadUB4();
    }
    if (marker == TNS_LONG_LENGTH_INDICATOR) {
        reader.Skip(1);
    }
}

void SkipBatchMessages(ByteReader &reader) {
    const auto count = reader.ReadUB2();
    if (count > MAX_BATCH_ERRORS) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC ERROR batch messages exceed supported bounds");
    }
    if (count == 0) {
        return;
    }
    reader.Skip(1);
    for (uint16_t index = 0; index < count; index++) {
        reader.ReadUB2();
        (void)reader.ReadLengthPrefixed(MAX_TTC_ERROR_TEXT_BYTES);
        reader.Skip(2);
    }
}

} // namespace

bool IsTtcErrorMessage(const std::vector<uint8_t> &message) {
    return !message.empty() && message.front() == TTC_MESSAGE_ERROR;
}

OracleServerError ParseTtcServerError(const std::vector<uint8_t> &message) {
    if (!IsTtcErrorMessage(message)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC server error message");
    }
    OracleServerError result;
    auto text = PrintableProjection(message);
    size_t code_offset = 0;
    result.ora_code = FindOraCode(text, code_offset);
    if (result.ora_code) {
        result.message = text.substr(code_offset);
    } else {
        result.message = "Oracle server returned a TTC error";
    }
    return result;
}

TtcErrorInfo DecodeTtcErrorPrefix(const std::vector<uint8_t> &message, uint8_t ttc_field_version) {
    ByteReader reader(message);
    try {
    if (reader.ReadByte() != TTC_MESSAGE_ERROR) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC ERROR message");
    }
    reader.ReadUB4(); // call status
    reader.ReadUB2(); // end-to-end sequence
    const auto current_row = reader.ReadUB4();
    reader.ReadUB2(); // legacy short error number
    reader.ReadUB2(); // array element error
    reader.ReadUB2(); // array element error
    const auto cursor_id = reader.ReadUB4();
    reader.ReadUB4(); // signed SQL offset; callers use server message text
    reader.Skip(6);   // sql type, fatal, flags, cursor options, UPI, warning
    reader.ReadUB4(); // rowid RBA
    reader.ReadUB2(); // rowid partition
    reader.Skip(1);   // rowid flag
    reader.ReadUB4(); // rowid block
    reader.ReadUB2(); // rowid slot
    reader.ReadUB4(); // OS error
    reader.Skip(1);   // statement number
    reader.Skip(1);   // call number
    // Padding is a universal UB2, one byte when it is zero — not two fixed
    // bytes. Skipping four here consumed one byte too many, which shifted the
    // extended error number into the batch-message count and is why the
    // structured decode of a real end-of-call always threw.
    reader.ReadUB2();
    reader.ReadUB4(); // successful iterations
    // oerrdd, the logical rowid of the row a DML touched, is a UB4 length
    // followed — only when that length is non-zero — by the buffer itself in
    // the ordinary chunked form. Reading the buffer unconditionally as one
    // length-prefixed field cannot be told apart from this while the field is
    // empty, which is every fetch end-of-call; a DML end-of-call carries a
    // 13-byte rowid and the two readings diverge there, shifting the batch
    // arrays and the row count that follow them.
    const auto logical_rowid_bytes = reader.ReadUB4();
    if (logical_rowid_bytes != 0) {
        (void)reader.ReadLengthPrefixed(MAX_TTC_ERROR_TEXT_BYTES);
    }
    SkipPackedUb2Array(reader);
    SkipPackedUb4Array(reader);
    SkipBatchMessages(reader);
    const auto error_number = reader.ReadUB4();
    const uint64_t row_count = reader.ReadUB8();
    // Above a field-version gate the end-of-call carries two more universal
    // integers before the message text. Live captures of the same ORA-01403:
    // Oracle 19c, which reports field version 12, ends `… 02 05 7b | 01 01 |
    // 19 <text>`, while Free 23ai and OCI Autonomous, which report 27, end
    // `… 02 05 7b | 01 01 | 01 03 00 | 19 <text>` — a SQL type of 3 and a
    // server checksum of 0.
    //
    // The gate is the server's own reported version, not the negotiated one.
    // Both of those servers negotiate down to this client's 12, yet 23ai still
    // sends the fields, so it does not adapt this part of the message to what
    // the client advertised.
    if (ttc_field_version >= TTC_FIELD_VERSION_ERROR_TRAILER) {
        reader.ReadUB4(); // SQL type
        reader.ReadUB4(); // server checksum
    }
    std::string error_message;
    if (error_number != 0) {
        std::optional<std::vector<uint8_t>> text;
        try {
            text = reader.ReadLengthPrefixed(MAX_TTC_ERROR_TEXT_BYTES);
        } catch (const ProtocolError &error) {
            throw ProtocolError(error.Kind(), "TTC ERROR text at offset " + std::to_string(reader.Position()) + ": " + error.what());
        }
        if (!text) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC ERROR has a null error-message field");
        }
        error_message.assign(text->begin(), text->end());
        // Oracle ends its message with a newline. Carrying it into an
        // exception hides whatever a caller appends and wraps the message in
        // any display that stops at the first line.
        while (!error_message.empty() &&
               (error_message.back() == '\n' || error_message.back() == '\r' || error_message.back() == ' ')) {
            error_message.pop_back();
        }
    }
    return {error_number, cursor_id, current_row, row_count, std::move(error_message), reader.Position()};
    } catch (const ProtocolError &error) {
        throw ProtocolError(error.Kind(), "TTC ERROR at offset " + std::to_string(reader.Position()) + ": " + error.what());
    }
}

[[noreturn]] void ThrowTtcServerError(const std::vector<uint8_t> &message) {
    const auto error = ParseTtcServerError(message);
    throw ProtocolError(ProtocolErrorKind::INVALID_STATE, error.message);
}

} // namespace oracle_scanner

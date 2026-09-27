#include "oracle_scanner/tns_handshake.hpp"
#include "oracle_scanner/connect_error.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <algorithm>
#include <cctype>

namespace oracle_scanner {

namespace {

constexpr size_t MAX_REFUSAL_MESSAGE = 1024;

uint16_t ReadUInt16(const std::vector<uint8_t> &value, size_t offset) {
    return static_cast<uint16_t>((static_cast<uint16_t>(value[offset]) << 8U) | value[offset + 1]);
}

uint32_t ReadUInt32(const std::vector<uint8_t> &value, size_t offset) {
    return (static_cast<uint32_t>(value[offset]) << 24U) | (static_cast<uint32_t>(value[offset + 1]) << 16U) |
           (static_cast<uint32_t>(value[offset + 2]) << 8U) | value[offset + 3];
}

// Redirect text is the listener's descriptor syntax. go-ora strips CR and LF
// from it before parsing, so a listener evidently may wrap it; any other
// control byte means the data is not descriptor text at all.
std::string RedirectText(std::vector<uint8_t>::const_iterator begin, std::vector<uint8_t>::const_iterator end,
                         const char *what) {
    std::string text;
    text.reserve(static_cast<size_t>(end - begin));
    for (auto iterator = begin; iterator != end; ++iterator) {
        const auto byte = *iterator;
        if (byte == '\r' || byte == '\n' || byte == '\t') {
            text.push_back(' ');
            continue;
        }
        if (byte < 0x20 || byte > 0x7e) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                std::string("Oracle redirect ") + what + " contains a non-printable byte");
        }
        text.push_back(static_cast<char>(byte));
    }
    size_t first = 0;
    while (first < text.size() && text[first] == ' ') {
        first++;
    }
    size_t last = text.size();
    while (last > first && text[last - 1] == ' ') {
        last--;
    }
    return text.substr(first, last - first);
}

// Reads the whole redirect data. The REDIRECT payload starts with its UB2
// length. The data itself may follow inline, or arrive in the DATA packets
// that come next — go-ora reads the next DATA packet when the REDIRECT carries
// nothing after the length, and python-oracledb reads the declared number of
// bytes across however many packets it takes. Both are handled: whatever is
// inline counts, and DATA packets supply the rest, each after its two-byte
// data flags.
std::vector<uint8_t> ReadRedirectData(TnsPacketStream &stream, const TnsPacket &redirect) {
    const auto &payload = redirect.payload;
    if (payload.size() < 2) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED, "Oracle REDIRECT packet has no data length");
    }
    const size_t declared = ReadUInt16(payload, 0);
    if (declared == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle REDIRECT declares no redirect data");
    }
    if (payload.size() - 2 > declared) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle REDIRECT carries more data than it declares");
    }
    std::vector<uint8_t> data(payload.begin() + 2, payload.end());
    size_t continuations = 0;
    while (data.size() < declared) {
        if (++continuations > TNS_MAX_REDIRECT_CONTINUATIONS) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,
                                "Oracle REDIRECT data spans too many continuation packets");
        }
        TnsPacket next {TnsPacketType::DATA, 0, {}};
        try {
            next = stream.Receive();
        } catch (const OracleConnectError &) {
            throw;
        } catch (const ProtocolError &error) {
            if (error.Kind() == ProtocolErrorKind::TRUNCATED) {
                throw OracleConnectError(ProtocolErrorKind::TRUNCATED, ConnectFailure::TRANSPORT_LOST,
                                         std::string("Oracle listener closed before its redirect data was complete: ") +
                                             error.what());
            }
            throw;
        }
        if (next.type != TnsPacketType::DATA) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                "Oracle REDIRECT data continues in a packet that is not DATA");
        }
        if (next.payload.size() < 2) {
            throw ProtocolError(ProtocolErrorKind::TRUNCATED, "Oracle REDIRECT continuation has no data flags");
        }
        if (next.payload.size() == 2) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle REDIRECT continuation carries no data");
        }
        if (data.size() + (next.payload.size() - 2) > declared) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                "Oracle REDIRECT continuation carries more data than was declared");
        }
        data.insert(data.end(), next.payload.begin() + 2, next.payload.end());
    }
    return data;
}

// Finds (ERR=NNNNN) the way go-ora's `\(\s*ERR\s*=\s*([0-9]+)\s*\)` does:
// case-insensitively, whitespace allowed around the name and the number.
uint32_t ExtractRefusalCode(const std::string &message) {
    for (size_t open = message.find('('); open != std::string::npos; open = message.find('(', open + 1)) {
        size_t position = open + 1;
        const auto skip_space = [&]() {
            while (position < message.size() && std::isspace(static_cast<unsigned char>(message[position]))) {
                position++;
            }
        };
        skip_space();
        if (position + 3 > message.size() ||
            std::toupper(static_cast<unsigned char>(message[position])) != 'E' ||
            std::toupper(static_cast<unsigned char>(message[position + 1])) != 'R' ||
            std::toupper(static_cast<unsigned char>(message[position + 2])) != 'R') {
            continue;
        }
        position += 3;
        skip_space();
        if (position >= message.size() || message[position] != '=') {
            continue;
        }
        position++;
        skip_space();
        uint64_t code = 0;
        size_t digits = 0;
        while (position < message.size() && std::isdigit(static_cast<unsigned char>(message[position])) &&
               digits < 9) {
            code = code * 10 + static_cast<uint64_t>(message[position] - '0');
            position++;
            digits++;
        }
        skip_space();
        if (digits == 0 || position >= message.size() || message[position] != ')') {
            continue;
        }
        return static_cast<uint32_t>(code);
    }
    return 0;
}

std::string RefusalDescription(const TnsRefusal &refusal) {
    std::string result = "Oracle listener refused the connection";
    if (refusal.oracle_error != 0) {
        const auto code = std::to_string(refusal.oracle_error);
        result += " (ORA-" + std::string(code.size() < 5 ? 5 - code.size() : 0, '0') + code + ")";
    }
    const auto ora = refusal.message.find("ORA-");
    if (ora != std::string::npos) {
        result += ": " + refusal.message.substr(ora);
    } else if (refusal.oracle_error == 0) {
        result += " (reason=" + std::to_string(refusal.user_reason) +
                  ", system_reason=" + std::to_string(refusal.system_reason) + ')';
    }
    return result;
}

} // namespace

TnsRedirect ParseTnsRedirectData(const std::vector<uint8_t> &data, uint8_t flags) {
    if (data.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle redirect data is empty");
    }
    const auto separator = std::find(data.begin(), data.end(), static_cast<uint8_t>(0));
    if (separator == data.end() && (flags & TNS_REDIRECT_FLAG_HAS_RECONNECT_DATA) != 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "Oracle redirect is flagged as carrying reconnect data but has no NUL separator");
    }
    TnsRedirect result;
    result.address = RedirectText(data.begin(), separator, "address");
    if (separator != data.end()) {
        // Trailing NULs after the reconnect data are padding, not content.
        auto end = data.end();
        while (end != separator + 1 && *(end - 1) == 0) {
            --end;
        }
        result.reconnect_data = RedirectText(separator + 1, end, "reconnect data");
    }
    // The address has to be descriptor syntax from its first byte. The earlier
    // parser skipped forward to the first '(' it found, which accepted any
    // prefix at all; nothing here looks for a start by skipping bytes.
    if (result.address.size() < 2 || result.address.front() != '(' || result.address.back() != ')') {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle redirect address is not a descriptor");
    }
    if (!result.reconnect_data.empty() &&
        (result.reconnect_data.front() != '(' || result.reconnect_data.back() != ')')) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle redirect reconnect data is not a descriptor");
    }
    return result;
}

TnsRefusal ParseTnsRefusal(const std::vector<uint8_t> &payload) {
    TnsRefusal result;
    if (payload.size() >= 2) {
        result.user_reason = payload[0];
        result.system_reason = payload[1];
    }
    if (payload.size() >= 4) {
        const size_t declared = ReadUInt16(payload, 2);
        const auto available = (std::min)(declared, payload.size() - 4);
        for (size_t index = 0; index < available && result.message.size() < MAX_REFUSAL_MESSAGE; index++) {
            const auto byte = payload[4 + index];
            if (byte == 0) {
                break;
            }
            // Printable only: this text ends up in an error message.
            result.message.push_back(byte >= 0x20 && byte <= 0x7e ? static_cast<char>(byte) : ' ');
        }
    }
    result.oracle_error = ExtractRefusalCode(result.message);
    return result;
}

TnsConnectResult RunTnsConnect(TnsPacketStream &stream, const std::string &descriptor,
                               const TnsConnectOptions &options) {
    const auto request = BuildTnsConnectPackets(descriptor, options);
    // Before ACCEPT a failed read or write means the listener, or the path to
    // it, went away. That is a fact about this address, which is what lets the
    // connect loop try another; it is not a protocol fault.
    const auto send = [&]() {
        try {
            stream.Send(request);
        } catch (const OracleConnectError &) {
            // Already classified — the connect budget or a cancellation,
            // raised by the stream the connect loop wrapped.
            throw;
        } catch (const ProtocolError &error) {
            throw OracleConnectError(ProtocolErrorKind::TRUNCATED, ConnectFailure::TRANSPORT_LOST,
                                     std::string("Oracle CONNECT could not be sent: ") + error.what());
        }
    };
    const auto receive = [&]() {
        try {
            return stream.Receive();
        } catch (const OracleConnectError &) {
            throw;
        } catch (const ProtocolError &error) {
            if (error.Kind() == ProtocolErrorKind::TRUNCATED) {
                throw OracleConnectError(ProtocolErrorKind::TRUNCATED, ConnectFailure::TRANSPORT_LOST,
                                         std::string("Oracle listener did not answer CONNECT: ") + error.what());
            }
            throw;
        }
    };
    send();
    auto response = receive();
    if (response.type == TnsPacketType::RESEND) {
        send();
        response = receive();
    }
    switch (response.type) {
    case TnsPacketType::ACCEPT: {
        // Oracle 19c's ACCEPT layout carries negotiated SDU at offset 26.
        // Future TTC packets must obey the server-selected SDU.
        if (response.payload.size() < 28) {
            throw ProtocolError(ProtocolErrorKind::TRUNCATED, "Oracle ACCEPT packet is truncated");
        }
        if (ReadUInt16(response.payload, 26) < 512) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle ACCEPT selected an invalid SDU");
        }
        // flags2 is optional on older ACCEPT forms. Bit 0 is CHECK_OOB and
        // commits a TCP client to the urgent-byte/marker probe before TTC.
        const auto check_oob = response.payload.size() >= 37 && (ReadUInt32(response.payload, 33) & 1U) != 0;
        // Live values: 19c answers version 318 with flags2 0x00000001, Free 23ai
        // and OCI Autonomous answer 319 with the end-of-response bit set.
        const auto accept_version = ReadUInt16(response.payload, 0);
        const auto flags2 = response.payload.size() >= 37 ? ReadUInt32(response.payload, 33) : 0U;
        const auto end_of_response =
            accept_version >= TNS_VERSION_MIN_END_OF_RESPONSE && (flags2 & TNS_ACCEPT_FLAG_HAS_END_OF_RESPONSE) != 0;
        return {TnsConnectDisposition::ACCEPTED, ReadUInt16(response.payload, 26), check_oob,
                accept_version,          end_of_response,                        {}};
    }
    case TnsPacketType::REDIRECT: {
        const auto data = ReadRedirectData(stream, response);
        TnsConnectResult result;
        result.disposition = TnsConnectDisposition::REDIRECTED;
        result.redirect = ParseTnsRedirectData(data, response.flags);
        return result;
    }
    case TnsPacketType::REFUSE: {
        const auto refusal = ParseTnsRefusal(response.payload);
        throw OracleConnectError(ProtocolErrorKind::INVALID_STATE, ConnectFailure::LISTENER_REFUSED,
                                 RefusalDescription(refusal), refusal.oracle_error);
    }
    default:
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle listener returned an unexpected TNS packet");
    }
}

} // namespace oracle_scanner

#include "oracle_scanner/tns_handshake.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <algorithm>
#include <cctype>

namespace oracle_scanner {

namespace {

uint16_t ReadUInt16(const std::vector<uint8_t> &value, size_t offset) {
    return static_cast<uint16_t>((static_cast<uint16_t>(value[offset]) << 8U) | value[offset + 1]);
}

uint32_t ReadUInt32(const std::vector<uint8_t> &value, size_t offset) {
    return (static_cast<uint32_t>(value[offset]) << 24U) | (static_cast<uint32_t>(value[offset + 1]) << 16U) |
           (static_cast<uint32_t>(value[offset + 2]) << 8U) | value[offset + 3];
}

std::string ExtractRedirectDescriptor(const std::vector<uint8_t> &payload) {
    if (payload.empty() || payload.size() > 65535) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle redirect descriptor has an invalid size");
    }
    size_t start = 0;
    while (start < payload.size() && payload[start] != '(') {
        start++;
    }
    if (start == payload.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle redirect does not contain a descriptor");
    }
    std::string descriptor;
    descriptor.reserve(payload.size() - start);
    for (size_t index = start; index < payload.size(); index++) {
        const auto byte = payload[index];
        if (byte == 0) {
            break;
        }
        if (byte < 0x20 || byte > 0x7e) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle redirect descriptor contains non-printable bytes");
        }
        descriptor.push_back(static_cast<char>(byte));
    }
    if (descriptor.size() < 2 || descriptor.front() != '(' || descriptor.back() != ')') {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle redirect descriptor is incomplete");
    }
    return descriptor;
}

std::string ExtractRefusalMessage(const std::vector<uint8_t> &payload) {
    constexpr size_t maximum_message_size = 1024;
    const std::string marker = "ORA-";
    const auto error_start = std::search(payload.begin(), payload.end(), marker.begin(), marker.end());
    if (error_start == payload.end()) {
        if (payload.size() >= 2) {
            return " (reason=" + std::to_string(payload[0]) + ", system_reason=" + std::to_string(payload[1]) + ')';
        }
        return {};
    }
    std::string message;
    for (auto iterator = error_start; iterator != payload.end() && message.size() < maximum_message_size; ++iterator) {
        const auto byte = *iterator;
        if (byte == 0 || byte < 0x20 || byte > 0x7e) {
            break;
        }
        message.push_back(static_cast<char>(byte));
    }
    return message.empty() ? std::string() : ": " + message;
}

} // namespace

TnsConnectResult RunTnsConnect(TnsPacketStream &stream, const std::string &descriptor,
                               const TnsConnectOptions &options) {
    const auto request = BuildTnsConnectPackets(descriptor, options);
    stream.Send(request);
    auto response = stream.Receive();
    if (response.type == TnsPacketType::RESEND) {
        stream.Send(request);
        response = stream.Receive();
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
    case TnsPacketType::REDIRECT:
        return {TnsConnectDisposition::REDIRECTED, 0, false, 0, false, ExtractRedirectDescriptor(response.payload)};
    case TnsPacketType::REFUSE:
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                            "Oracle listener refused the connection" + ExtractRefusalMessage(response.payload));
    default:
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle listener returned an unexpected TNS packet");
    }
}

} // namespace oracle_scanner

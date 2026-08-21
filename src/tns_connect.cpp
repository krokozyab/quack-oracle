#include "oracle_scanner/tns_connect.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <algorithm>
#include <limits>

namespace oracle_scanner {

namespace {

constexpr size_t CONNECT_FIXED_PAYLOAD_SIZE = 66;
constexpr size_t CONNECT_HEADER_TOTAL_SIZE = TNS_PACKET_HEADER_SIZE + CONNECT_FIXED_PAYLOAD_SIZE;
constexpr size_t MAX_INLINE_CONNECT_DATA = 230;

void StoreUInt16(std::vector<uint8_t> &target, size_t offset, uint16_t value) {
    target[offset] = static_cast<uint8_t>(value >> 8U);
    target[offset + 1] = static_cast<uint8_t>(value);
}

void StoreUInt32(std::vector<uint8_t> &target, size_t offset, uint32_t value) {
    target[offset] = static_cast<uint8_t>(value >> 24U);
    target[offset + 1] = static_cast<uint8_t>(value >> 16U);
    target[offset + 2] = static_cast<uint8_t>(value >> 8U);
    target[offset + 3] = static_cast<uint8_t>(value);
}

} // namespace

std::vector<TnsPacket> BuildTnsConnectPackets(const std::string &descriptor, const TnsConnectOptions &options) {
    if (descriptor.empty() || descriptor.size() > (std::numeric_limits<uint16_t>::max)() - TNS_PACKET_HEADER_SIZE - 2 ||
        options.desired_version < options.minimum_version || options.requested_sdu < 512 ||
        options.requested_tdu < options.requested_sdu) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TNS CONNECT parameters are invalid");
    }
    const auto descriptor_is_inline = descriptor.size() <= MAX_INLINE_CONNECT_DATA;
    std::vector<uint8_t> payload(CONNECT_FIXED_PAYLOAD_SIZE + (descriptor_is_inline ? descriptor.size() : 0), 0);
    StoreUInt16(payload, 0, options.desired_version);
    StoreUInt16(payload, 2, options.minimum_version);
    StoreUInt16(payload, 4, static_cast<uint16_t>(0x0001 | (options.supports_oob ? 0x0400 : 0)));
    StoreUInt16(payload, 6, options.requested_sdu);
    StoreUInt16(payload, 8, options.requested_tdu);
    StoreUInt16(payload, 10, 0x4f98); // current thin-client protocol characteristics
    StoreUInt16(payload, 14, 0x0001); // connect value
    StoreUInt16(payload, 16, static_cast<uint16_t>(descriptor.size()));
    StoreUInt16(payload, 18, static_cast<uint16_t>(CONNECT_HEADER_TOTAL_SIZE));
    StoreUInt32(payload, 20, 0); // no extra receive buffer reservation
    payload[24] = 0x84;
    payload[25] = 0x84; // protocol capabilities used by current thin clients
    payload[52] = 0x20;
    payload[56] = 0x20;
    payload[25] = 0x84; // security renegotiation plus no native authentication
    payload[65] = options.supports_oob ? 0x01 : 0x00;
    if (descriptor_is_inline) {
        std::copy(descriptor.begin(), descriptor.end(), payload.begin() + CONNECT_FIXED_PAYLOAD_SIZE);
    }
    std::vector<TnsPacket> packets;
    packets.push_back({TnsPacketType::CONNECT, 0, std::move(payload)});
    if (!descriptor_is_inline) {
        // The client must not duplicate long connect data: the listener reads
        // it from the DATA continuation before it sends ACCEPT.
        std::vector<uint8_t> continuation(2 + descriptor.size());
        std::copy(descriptor.begin(), descriptor.end(), continuation.begin() + 2);
        packets.push_back({TnsPacketType::DATA, 0, std::move(continuation)});
    }
    return packets;
}

} // namespace oracle_scanner

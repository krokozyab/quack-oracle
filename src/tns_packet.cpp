#include "oracle_scanner/tns_packet.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <algorithm>
#include <limits>

namespace oracle_scanner {

static uint16_t ReadUInt16BE(const uint8_t *data) {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8U) | data[1]);
}

static uint32_t ReadUInt32BE(const uint8_t *data) {
    return (static_cast<uint32_t>(data[0]) << 24U) | (static_cast<uint32_t>(data[1]) << 16U) |
           (static_cast<uint32_t>(data[2]) << 8U) | data[3];
}

TnsPacket DecodeTnsPacket(const std::vector<uint8_t> &wire, bool large_length, size_t packet_limit) {
    if (wire.size() < TNS_PACKET_HEADER_SIZE) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED, "TNS packet header is truncated");
    }
    auto declared_length = large_length ? static_cast<size_t>(ReadUInt32BE(wire.data()))
                                        : static_cast<size_t>(ReadUInt16BE(wire.data()));
    if (declared_length < TNS_PACKET_HEADER_SIZE) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TNS packet length is smaller than its header");
    }
    if (declared_length > packet_limit || declared_length > MAX_TNS_PACKET_LENGTH) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TNS packet exceeds configured limit");
    }
    if (wire.size() < declared_length) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED, "TNS packet payload is truncated");
    }
    if (wire.size() != declared_length) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "TNS packet buffer contains trailing bytes (buffer " + std::to_string(wire.size()) +
                                ", declared " + std::to_string(declared_length) + ")");
    }
    return {static_cast<TnsPacketType>(wire[4]), wire[5],
            std::vector<uint8_t>(wire.begin() + TNS_PACKET_HEADER_SIZE, wire.end())};
}

std::vector<uint8_t> EncodeTnsPacket(TnsPacketType type, uint8_t flags, const std::vector<uint8_t> &payload,
                                     bool large_length) {
    auto total_size = TNS_PACKET_HEADER_SIZE + payload.size();
    if (total_size > MAX_TNS_PACKET_LENGTH || (!large_length && total_size > (std::numeric_limits<uint16_t>::max)())) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TNS packet is too large to encode");
    }
    std::vector<uint8_t> result(total_size, 0);
    if (large_length) {
        auto value = static_cast<uint32_t>(total_size);
        result[0] = static_cast<uint8_t>(value >> 24U);
        result[1] = static_cast<uint8_t>(value >> 16U);
        result[2] = static_cast<uint8_t>(value >> 8U);
        result[3] = static_cast<uint8_t>(value);
    } else {
        auto value = static_cast<uint16_t>(total_size);
        result[0] = static_cast<uint8_t>(value >> 8U);
        result[1] = static_cast<uint8_t>(value);
    }
    result[4] = static_cast<uint8_t>(type);
    result[5] = flags;
    std::copy(payload.begin(), payload.end(), result.begin() + TNS_PACKET_HEADER_SIZE);
    return result;
}

std::vector<std::vector<uint8_t>> EncodeTnsDataPackets(const std::vector<uint8_t> &ttc_payload, bool large_length,
                                                       size_t negotiated_sdu, uint16_t final_flags) {
    if (negotiated_sdu <= TNS_PACKET_HEADER_SIZE + 2) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "negotiated SDU is too small for a DATA packet");
    }
    auto maximum_chunk = negotiated_sdu - TNS_PACKET_HEADER_SIZE - 2;
    std::vector<std::vector<uint8_t>> result;
    size_t offset = 0;
    do {
        auto count = (std::min)(maximum_chunk, ttc_payload.size() - offset);
        auto last = offset + count == ttc_payload.size();
        auto data_flags = last ? final_flags : uint16_t(0);
        std::vector<uint8_t> payload(2 + count);
        payload[0] = static_cast<uint8_t>(data_flags >> 8U);
        payload[1] = static_cast<uint8_t>(data_flags);
        const auto chunk_begin = ttc_payload.begin() + static_cast<std::ptrdiff_t>(offset);
        std::copy(chunk_begin, chunk_begin + static_cast<std::ptrdiff_t>(count), payload.begin() + 2);
        result.push_back(EncodeTnsPacket(TnsPacketType::DATA, 0, payload, large_length));
        offset += count;
    } while (offset < ttc_payload.size());
    return result;
}

} // namespace oracle_scanner

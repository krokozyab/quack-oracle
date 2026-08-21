#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace oracle_scanner {

constexpr size_t TNS_PACKET_HEADER_SIZE = 8;
constexpr size_t MAX_TNS_PACKET_LENGTH = 16U << 20U;
constexpr uint16_t TNS_DATA_FLAG_EOF = 0x0040;
constexpr uint16_t TNS_DATA_FLAG_END_OF_RESPONSE = 0x2000;

enum class TnsPacketType : uint8_t {
    CONNECT = 1,
    ACCEPT = 2,
    REFUSE = 4,
    REDIRECT = 5,
    DATA = 6,
    RESEND = 11,
    MARKER = 12,
    CONTROL = 14,
    DATA_DESCRIPTOR = 15
};

struct TnsPacket {
    TnsPacketType type;
    uint8_t flags;
    std::vector<uint8_t> payload;
};

TnsPacket DecodeTnsPacket(const std::vector<uint8_t> &wire, bool large_length,
                          size_t packet_limit = MAX_TNS_PACKET_LENGTH);
std::vector<uint8_t> EncodeTnsPacket(TnsPacketType type, uint8_t flags, const std::vector<uint8_t> &payload,
                                     bool large_length);
std::vector<std::vector<uint8_t>> EncodeTnsDataPackets(const std::vector<uint8_t> &ttc_payload, bool large_length,
                                                       size_t negotiated_sdu,
                                                       uint16_t final_flags = TNS_DATA_FLAG_END_OF_RESPONSE);

} // namespace oracle_scanner

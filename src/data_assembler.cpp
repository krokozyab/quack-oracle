#include "oracle_scanner/data_assembler.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <string>

namespace oracle_scanner {

TnsDataAssembler::TnsDataAssembler(size_t maximum_message_size_p) : maximum_message_size(maximum_message_size_p) {
    if (maximum_message_size == 0) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "maximum TTC message size must be positive");
    }
}

std::optional<std::vector<uint8_t>> TnsDataAssembler::Push(const TnsPacket &packet) {
    if (packet.type != TnsPacketType::DATA) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                            "non-DATA TNS packet passed to TTC data assembler (type " +
                                std::to_string(static_cast<uint8_t>(packet.type)) + ')');
    }
    if (packet.payload.size() < 2) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED, "TNS DATA packet has no data-flags field");
    }
    auto flags = static_cast<uint16_t>((static_cast<uint16_t>(packet.payload[0]) << 8U) | packet.payload[1]);
    auto bytes = packet.payload.size() - 2;
    if (bytes > maximum_message_size - buffered.size()) {
        Reset();
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "reassembled TTC message exceeds configured limit");
    }
    buffered.insert(buffered.end(), packet.payload.begin() + 2, packet.payload.end());
    if ((flags & (TNS_DATA_FLAG_END_OF_RESPONSE | TNS_DATA_FLAG_EOF)) == 0) {
        return std::nullopt;
    }
    auto result = std::move(buffered);
    buffered.clear();
    return result;
}

std::vector<uint8_t> TnsDataAssembler::TakeBuffered() {
    if (buffered.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "cannot complete an empty TTC message");
    }
    auto result = std::move(buffered);
    buffered.clear();
    return result;
}

void TnsDataAssembler::Reset() {
    buffered.clear();
}

size_t TnsDataAssembler::BufferedBytes() const {
    return buffered.size();
}

} // namespace oracle_scanner

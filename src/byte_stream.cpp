#include "oracle_scanner/byte_stream.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <vector>

namespace oracle_scanner {

// A transport with no out-of-band channel is the normal case, not an error in
// the transport: TLS has none, and neither does anything tunnelled. Saying so
// as UNSUPPORTED lets the handshake decide, since the CHECK_OOB probe only runs
// when the server asks for it.
void ByteStream::SendUrgent(uint8_t value) {
    (void)value;
    throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "this Oracle transport has no out-of-band channel");
}

void ReadExact(ByteStream &stream, uint8_t *destination, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        auto count = stream.Read(destination + offset, size - offset);
        if (count == 0 || count > size - offset) {
            throw ProtocolError(count == 0 ? ProtocolErrorKind::TRUNCATED : ProtocolErrorKind::MALFORMED,
                                "byte stream ended or returned an invalid read count");
        }
        offset += count;
    }
}

void WriteAll(ByteStream &stream, const uint8_t *source, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        auto count = stream.Write(source + offset, size - offset);
        if (count == 0 || count > size - offset) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "byte stream failed to make write progress");
        }
        offset += count;
    }
}

TnsPacketStream::TnsPacketStream(ByteStream &stream_p, bool large_length_p, size_t packet_limit_p)
    : stream(stream_p), large_length(large_length_p), packet_limit(packet_limit_p) {
    if (packet_limit < TNS_PACKET_HEADER_SIZE || packet_limit > MAX_TNS_PACKET_LENGTH) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TNS packet stream limit is invalid");
    }
}

void TnsPacketStream::Send(const TnsPacket &packet) {
    auto wire = EncodeTnsPacket(packet.type, packet.flags, packet.payload, large_length);
    if (wire.size() > packet_limit) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "outbound TNS packet exceeds configured limit");
    }
    WriteAll(stream, wire.data(), wire.size());
}

void TnsPacketStream::Send(const std::vector<TnsPacket> &packets) {
    if (packets.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TNS packet group is empty");
    }
    std::vector<uint8_t> wire;
    for (const auto &packet : packets) {
        auto encoded = EncodeTnsPacket(packet.type, packet.flags, packet.payload, large_length);
        if (encoded.size() > packet_limit) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "outbound TNS packet exceeds configured limit");
        }
        wire.insert(wire.end(), encoded.begin(), encoded.end());
    }
    WriteAll(stream, wire.data(), wire.size());
}

TnsPacket TnsPacketStream::Receive() {
    std::vector<uint8_t> wire(TNS_PACKET_HEADER_SIZE);
    ReadExact(stream, wire.data(), wire.size());
    size_t declared_length;
    if (large_length) {
        declared_length = (static_cast<size_t>(wire[0]) << 24U) | (static_cast<size_t>(wire[1]) << 16U) |
                          (static_cast<size_t>(wire[2]) << 8U) | wire[3];
    } else {
        declared_length = (static_cast<size_t>(wire[0]) << 8U) | wire[1];
    }
    if (declared_length < TNS_PACKET_HEADER_SIZE) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TNS packet length is smaller than its header");
    }
    if (declared_length > packet_limit || declared_length > MAX_TNS_PACKET_LENGTH) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "inbound TNS packet exceeds configured limit");
    }
    wire.resize(declared_length);
    ReadExact(stream, wire.data() + TNS_PACKET_HEADER_SIZE, declared_length - TNS_PACKET_HEADER_SIZE);
    return DecodeTnsPacket(wire, large_length, packet_limit);
}

} // namespace oracle_scanner

#include "oracle_scanner/ttc_channel.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_piggyback.hpp"

#include <string>

namespace oracle_scanner {

TtcChannel::TtcChannel(TnsPacketStream &packets_p, size_t negotiated_sdu_p, size_t maximum_message_size,
                       bool cancellation_supported_p)
    : packets(packets_p), negotiated_sdu(negotiated_sdu_p), assembler(maximum_message_size),
      cancellation_supported(cancellation_supported_p) {
    if (negotiated_sdu <= TNS_PACKET_HEADER_SIZE + 2 || negotiated_sdu > MAX_TNS_PACKET_LENGTH) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC negotiated SDU is invalid");
    }
}

void TtcChannel::QueueCloseCursor(uint32_t cursor_id) {
    if (cursor_id == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "cannot queue Oracle cursor id zero for close");
    }
    pending_close_cursors.push_back(cursor_id);
}

size_t TtcChannel::PendingCloseCursorCount() const {
    return pending_close_cursors.size();
}

TtcTransactionStatus TtcChannel::Commit(uint8_t sequence) {
    Send(EncodeTtcCommitRequest(sequence));
    return DecodeTtcTransactionStatus(Receive());
}

TtcTransactionStatus TtcChannel::Rollback(uint8_t sequence) {
    Send(EncodeTtcRollbackRequest(sequence));
    return DecodeTtcTransactionStatus(Receive());
}

void TtcChannel::Cancel() {
    if (!cancellation_supported) {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "native Oracle cancellation is not capture-verified over TCPS");
    }
    bool expected = false;
    if (!cancellation_requested.compare_exchange_strong(expected, true)) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "an Oracle cancellation is already in progress");
    }
    try {
        std::lock_guard<std::mutex> lock(outbound_mutex);
        packets.Send({TnsPacketType::MARKER, 0, {0x01, 0x00, 0x03}}); // INTERRUPT
    } catch (...) {
        cancellation_requested.store(false);
        throw;
    }
}

void TtcChannel::Send(const std::vector<uint8_t> &message) {
    if (message.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "empty TTC messages are not valid");
    }
    std::lock_guard<std::mutex> lock(outbound_mutex);
    // END_OF_RESPONSE marks Oracle's response boundary; a client request
    // carries no response flag. Setting it here leaves 19c waiting for a
    // valid request terminator after TTIPRO.
    std::vector<uint8_t> outbound;
    if (!pending_close_cursors.empty()) {
        outbound = EncodeTtcCloseCursorsPiggyback(next_piggyback_sequence, pending_close_cursors);
        outbound.insert(outbound.end(), message.begin(), message.end());
    } else {
        outbound = message;
    }
    for (const auto &packet : EncodeTnsDataPackets(outbound, true, negotiated_sdu, 0)) {
        packets.Send(DecodeTnsPacket(packet, true, negotiated_sdu));
    }
    if (!pending_close_cursors.empty()) {
        pending_close_cursors.clear();
        ++next_piggyback_sequence;
    }
}

std::vector<uint8_t> TtcChannel::Receive() {
    size_t reset_count = 0;
    while (true) {
        const auto packet = packets.Receive();
        if (packet.type == TnsPacketType::MARKER) {
            if (packet.payload.size() != 3 || packet.payload[0] != 1 || packet.payload[1] != 0) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                    "Oracle sent an invalid TNS marker (bytes " +
                                        std::to_string(packet.payload.size()) + ", type " +
                                        (packet.payload.empty() ? std::string("none") : std::to_string(packet.payload.back())) + ")");
            }
            if (packet.payload[2] == 2) {
                if (cancellation_requested.exchange(false)) {
                    // Python Thin's captured cancellation sequence is
                    // INTERRUPT -> server RESET -> client RESET -> TTIOER.
                    std::lock_guard<std::mutex> lock(outbound_mutex);
                    packets.Send({TnsPacketType::MARKER, packet.flags, {0x01, 0x00, 0x02}});
                }
                continue;
            }
            if ((packet.payload[2] != 1 && packet.payload[2] != 3) || ++reset_count > 2) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle sent a repeated TNS break marker");
            }
            std::lock_guard<std::mutex> lock(outbound_mutex);
            packets.Send({TnsPacketType::MARKER, packet.flags, {0x01, 0x00, 0x02}});
            continue;
        }
        auto complete = assembler.Push(packet);
        if (complete) {
            if (complete->empty()) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle sent an empty TTC message");
            }
            return std::move(*complete);
        }
        // Oracle 19c sends the initial TTIPRO response in a short DATA packet
        // without END_OF_RESPONSE. A short packet cannot be an SDU-sized
        // continuation, so its TNS boundary completes this bootstrap message.
        if (packet.type == TnsPacketType::DATA && packet.payload.size() + TNS_PACKET_HEADER_SIZE < negotiated_sdu) {
            return assembler.TakeBuffered();
        }
    }
}

} // namespace oracle_scanner

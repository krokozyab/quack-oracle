#include "oracle_scanner/ttc_channel.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_piggyback.hpp"
#include "oracle_scanner/ttc_auth.hpp"
#include "oracle_scanner/ttc_error.hpp"
#include "oracle_scanner/ttc_negotiation.hpp"

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

void TtcChannel::QueueEndToEndAttributes(const TtcEndToEndAttributes &attributes) {
    std::lock_guard<std::mutex> lock(outbound_mutex);
    if (attributes.client_identifier) {
        pending_end_to_end.client_identifier = attributes.client_identifier;
    }
    if (attributes.module) {
        pending_end_to_end.module = attributes.module;
    }
    if (attributes.action) {
        pending_end_to_end.action = attributes.action;
    }
    if (attributes.client_info) {
        pending_end_to_end.client_info = attributes.client_info;
    }
}

size_t TtcChannel::PendingCloseCursorCount() const {
    return pending_close_cursors.size();
}

// What the server puts ahead of an acknowledgement: the report of attributes just
// set, ahead of a ping's; Transaction Guard's LTXID, ahead of a COMMIT's.
static void SkipLeadingServerPiggybacks(std::vector<uint8_t> &response) {
    size_t offset = 0;
    while (offset < response.size() && response[offset] == TTC_MESSAGE_SERVER_PIGGYBACK) {
        offset = SkipTtcServerPiggyback(response, offset);
    }
    response.erase(response.begin(), response.begin() + static_cast<std::ptrdiff_t>(offset));
}

TtcTransactionStatus TtcChannel::ReceiveTransactionStatus(uint8_t server_field_version) {
    auto response = Receive();
    SkipLeadingServerPiggybacks(response);
    // Transaction calls can fail just like DML. Use the existing structured
    // error decoder and negotiated server version; never guess from text or
    // mistake a rejected COMMIT for a malformed STATUS acknowledgement.
    if (IsTtcErrorMessage(response)) {
        const auto error = DecodeTtcErrorPrefix(response,server_field_version);
        if (error.error_number != 0) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                                error.message.empty() ? "Oracle transaction call failed" : error.message,
                                error.error_number);
        }
    }
    return DecodeTtcTransactionStatus(response);
}

void TtcChannel::Ping(uint8_t sequence, uint8_t server_field_version) {
    Send({TTC_MESSAGE_FUNCTION, TTC_FUNCTION_PING, sequence});
    auto response = Receive();
    SkipLeadingServerPiggybacks(response);
    if (IsTtcErrorMessage(response)) {
        const auto error = DecodeTtcErrorPrefix(response, server_field_version);
        if (error.error_number != 0) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                                error.message.empty() ? "Oracle ping failed" : error.message, error.error_number);
        }
    }
    (void)DecodeTtcTransactionStatus(response);
}

TtcTransactionStatus TtcChannel::Commit(uint8_t sequence, uint8_t server_field_version) {
    Send(EncodeTtcCommitRequest(sequence));
    return ReceiveTransactionStatus(server_field_version);
}

TtcTransactionStatus TtcChannel::Rollback(uint8_t sequence, uint8_t server_field_version) {
    Send(EncodeTtcRollbackRequest(sequence));
    return ReceiveTransactionStatus(server_field_version);
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

namespace {
// From TTC field version 18 every function call and piggyback header carries a
// token number after the sequence number. This client never uses one, so it is
// always zero — python-oracledb sends the same single 0x00.
std::vector<uint8_t> WithHeaderToken(std::vector<uint8_t> message, uint8_t field_version) {
    if (field_version >= TTC_FIELD_VERSION_HEADER_TOKEN && message.size() >= 3 &&
        (message[0] == TTC_MESSAGE_FUNCTION || message[0] == TTC_MESSAGE_PIGGYBACK)) {
        message.insert(message.begin() + 3, 0);
    }
    return message;
}
} // namespace

void TtcChannel::Send(const std::vector<uint8_t> &request) {
    if (request.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "empty TTC messages are not valid");
    }
    const auto message = WithHeaderToken(request, wire_field_version);
    std::lock_guard<std::mutex> lock(outbound_mutex);
    // END_OF_RESPONSE marks Oracle's response boundary; a client request
    // carries no response flag. Setting it here leaves 19c waiting for a
    // valid request terminator after TTIPRO.
    std::vector<uint8_t> outbound;
    const bool end_to_end = !pending_end_to_end.Empty();
    uint8_t piggyback_sequence = next_piggyback_sequence;
    if (end_to_end) {
        outbound = WithHeaderToken(EncodeTtcEndToEndPiggyback(piggyback_sequence++, pending_end_to_end),
                                   wire_field_version);
    }
    if (!pending_close_cursors.empty()) {
        const auto close = WithHeaderToken(EncodeTtcCloseCursorsPiggyback(piggyback_sequence++, pending_close_cursors),
                                           wire_field_version);
        outbound.insert(outbound.end(), close.begin(), close.end());
    }
    outbound.insert(outbound.end(), message.begin(), message.end());
    for (const auto &packet : EncodeTnsDataPackets(outbound, true, negotiated_sdu, 0)) {
        packets.Send(DecodeTnsPacket(packet, true, negotiated_sdu));
    }
    if (!pending_close_cursors.empty()) {
        pending_close_cursors.clear();
    }
    if (end_to_end) {
        pending_end_to_end = TtcEndToEndAttributes();
    }
    next_piggyback_sequence = piggyback_sequence;
}

std::vector<uint8_t> TtcChannel::Receive() {
    size_t reset_count = 0;
    size_t empty_fragment_count = 0;
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
        // A non-final DATA fragment containing only flags cannot complete a
        // TTC response, even if earlier fragments have buffered bytes. Keep
        // waiting under the existing IO deadline; never return empty success.
        // Bound empty fragments per Receive independently of message size.
        if (packet.type == TnsPacketType::DATA && packet.payload.size() == 2) {
            if (++empty_fragment_count > 16) {
                throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,
                                    "Oracle sent too many non-final empty DATA fragments");
            }
            continue;
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

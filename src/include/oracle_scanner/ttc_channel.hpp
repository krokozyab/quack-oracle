#pragma once

#include "oracle_scanner/byte_stream.hpp"
#include "oracle_scanner/data_assembler.hpp"
#include "oracle_scanner/ttc_piggyback.hpp"
#include "oracle_scanner/ttc_transaction.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

namespace oracle_scanner {

// TNS DATA packetisation for one bidirectional TTC message stream. Calls are
// synchronous by design: Oracle TTC has one active request per session.
class TtcChannel {
public:
    // oob_probed: the connection ran the CHECK_OOB probe. Until the server
    // acknowledges it, out-of-band breaks stay in effect (see Cancel).
    TtcChannel(TnsPacketStream &packets, size_t negotiated_sdu, size_t maximum_message_size = 16U << 20U,
               bool cancellation_supported = true, bool oob_probed = false);

    // Queues a server cursor release for the next TTC function call. Oracle
    // defines CLOSE_CURSORS as a piggyback, so sending it independently would
    // leave the session waiting for a function body that never arrives.
    void QueueCloseCursor(uint32_t cursor_id);
    size_t PendingCloseCursorCount() const;
    // Queues the session's end-to-end attributes (module, action, ...) for the
    // next function call, where they travel as a piggyback.
    void QueueEndToEndAttributes(const TtcEndToEndAttributes &attributes);
    // A round trip that does nothing but carry what is queued (the end-to-end
    // attributes) and hear the server acknowledge it.
    void Ping(uint8_t sequence, uint8_t server_field_version = 12);
    TtcTransactionStatus Commit(uint8_t sequence, uint8_t server_field_version = 12);
    TtcTransactionStatus Rollback(uint8_t sequence, uint8_t server_field_version = 12);
    // Sends the capture-verified TCP interrupt: the in-band INTERRUPT marker, or,
    // while out-of-band breaks are in effect, a TCP urgent byte, as
    // python-oracledb Thin does; a server with OOB on does not read in-band
    // markers during a call. The reader that owns the in-flight response
    // completes the subsequent RESET exchange.
    void Cancel();
    // The negotiated TTC field version, which decides the shape of every request header.
    void SetWireFieldVersion(uint8_t field_version) { wire_field_version = field_version; }
    void Send(const std::vector<uint8_t> &message);
    std::vector<uint8_t> Receive();

    // One TTC call is a request and the response that answers it, and the two
    // are only a pair because nothing else uses the channel in between. A
    // session shared by two DuckDB pipelines has no such guarantee, so every
    // caller that sends and then reads holds this for both halves. It is
    // deliberately not taken by Cancel: an interrupt exists to reach a call
    // that is already blocked on its own response.
    std::unique_lock<std::recursive_mutex> LockCall() {
        return std::unique_lock<std::recursive_mutex>(call_mutex);
    }

private:
    TtcTransactionStatus ReceiveTransactionStatus(uint8_t server_field_version);
    TnsPacketStream &packets;
    size_t negotiated_sdu;
    TnsDataAssembler assembler;
    std::vector<uint32_t> pending_close_cursors;
    TtcEndToEndAttributes pending_end_to_end;
    uint8_t next_piggyback_sequence = 1;
    uint8_t wire_field_version = 0;
    bool cancellation_supported;
    std::atomic<bool> oob_breaks;
    std::atomic<bool> cancellation_requested {false};
    std::mutex outbound_mutex;
    std::recursive_mutex call_mutex;
};

} // namespace oracle_scanner

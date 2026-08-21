#pragma once

#include "oracle_scanner/byte_stream.hpp"
#include "oracle_scanner/data_assembler.hpp"
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
    TtcChannel(TnsPacketStream &packets, size_t negotiated_sdu, size_t maximum_message_size = 16U << 20U,
               bool cancellation_supported = true);

    // Queues a server cursor release for the next TTC function call. Oracle
    // defines CLOSE_CURSORS as a piggyback, so sending it independently would
    // leave the session waiting for a function body that never arrives.
    void QueueCloseCursor(uint32_t cursor_id);
    size_t PendingCloseCursorCount() const;
    TtcTransactionStatus Commit(uint8_t sequence);
    TtcTransactionStatus Rollback(uint8_t sequence);
    // Sends the capture-verified TCP interrupt marker. The reader that owns
    // the in-flight response completes the subsequent RESET exchange.
    void Cancel();
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
    TnsPacketStream &packets;
    size_t negotiated_sdu;
    TnsDataAssembler assembler;
    std::vector<uint32_t> pending_close_cursors;
    uint8_t next_piggyback_sequence = 1;
    bool cancellation_supported;
    std::atomic<bool> cancellation_requested {false};
    std::mutex outbound_mutex;
    std::recursive_mutex call_mutex;
};

} // namespace oracle_scanner

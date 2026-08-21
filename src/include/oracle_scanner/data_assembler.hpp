#pragma once

#include "oracle_scanner/tns_packet.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace oracle_scanner {

class TnsDataAssembler {
public:
    explicit TnsDataAssembler(size_t maximum_message_size);

    std::optional<std::vector<uint8_t>> Push(const TnsPacket &packet);
    // Transfers bytes accumulated from an implicitly bounded short DATA
    // packet. Callers must establish that boundary from TNS framing first.
    std::vector<uint8_t> TakeBuffered();
    void Reset();
    size_t BufferedBytes() const;

private:
    size_t maximum_message_size;
    std::vector<uint8_t> buffered;
};

} // namespace oracle_scanner

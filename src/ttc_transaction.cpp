#include "oracle_scanner/ttc_transaction.hpp"
#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_auth.hpp"

namespace oracle_scanner {
namespace {
std::vector<uint8_t> EncodeTransaction(uint8_t function_code, uint8_t sequence) {
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_FUNCTION).WriteByte(function_code).WriteByte(sequence);
    return writer.Take();
}
} // namespace

std::vector<uint8_t> EncodeTtcCommitRequest(uint8_t sequence) { return EncodeTransaction(TTC_FUNCTION_COMMIT, sequence); }
std::vector<uint8_t> EncodeTtcRollbackRequest(uint8_t sequence) { return EncodeTransaction(TTC_FUNCTION_ROLLBACK, sequence); }

TtcTransactionStatus DecodeTtcTransactionStatus(const std::vector<uint8_t> &message) {
    ByteReader reader(message);
    if (reader.ReadByte() != TTC_MESSAGE_STATUS) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC STATUS transaction acknowledgement");
    }
    TtcTransactionStatus result;
    result.call_status = reader.ReadUB4();
    result.end_to_end_sequence = reader.ReadUB2();
    if (reader.Remaining() != 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC transaction STATUS has trailing bytes");
    }
    return result;
}
} // namespace oracle_scanner

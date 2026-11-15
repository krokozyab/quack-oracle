#pragma once
#include "oracle_scanner/row_batch.hpp"

#include "oracle_scanner/session.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

// LOB_OP, the call a client makes to read a LOB it holds a locator for. A LOB
// column's row data carries no content at all — only the locator — so without
// this a LOB can be described and never read.
constexpr uint8_t TTC_FUNCTION_LOB_OP = 96;
constexpr uint8_t TTC_MESSAGE_LOB_DATA = 14;

// Operation codes. Only the two reads are used: the lifecycle operations
// (OPEN/CLOSE/IS_OPEN) exist for writing and for temporary LOBs, neither of
// which this client does.
constexpr uint32_t LOB_OP_GET_LENGTH = 0x0001;
constexpr uint32_t LOB_OP_READ = 0x0002;
// Writing, and the temporary LOBs a write larger than a bind can carry needs.
constexpr uint32_t LOB_OP_WRITE = 0x0040;
constexpr uint32_t LOB_OP_CREATE_TEMP = 0x0110;
constexpr uint32_t LOB_OP_FREE_TEMP = 0x0111;
// Marks a release that names several locators at once.
constexpr uint32_t LOB_OP_ARRAY = 0x80000;
constexpr size_t LOB_LOCATOR_BYTES = 40;

struct TtcLobRequest {
    uint8_t sequence = 1;
    std::vector<uint8_t> locator;
    uint32_t operation = LOB_OP_READ;
    //! 1-based, in characters for a CLOB and bytes for a BLOB.
    uint64_t offset = 1;
    //! Zero means the request carries no amount, which is what GET_LENGTH does.
    uint64_t amount = 0;
};

std::vector<uint8_t> EncodeTtcLobRequest(const TtcLobRequest &request);

struct TtcLobResponse {
    //! The slice a READ returned; empty for GET_LENGTH.
    std::vector<uint8_t> data;
    //! What the server says it served, or the LOB's length for GET_LENGTH. In
    //! the same unit as the request's offset.
    uint64_t amount = 0;
    size_t bytes_consumed = 0;
};

// Decodes the LOB_DATA and return-parameter prefix of a LOB_OP response. The
// end-of-call that follows is left to the caller, which is the same division
// the execute and fetch paths use.
// A temporary LOB: BLOB, CLOB in the database character set, or NCLOB.
enum class TtcTempLobKind { BLOB, CLOB, NCLOB };

// Creates a temporary LOB that lasts until the session ends. The reply carries
// the locator to write to and to bind. Shapes recorded from python-oracledb
// Thin 4.0.1 (see PROVENANCE.md).
std::vector<uint8_t> EncodeTtcCreateTempLob(uint8_t sequence, TtcTempLobKind kind);
//! `offset` is 1-based, in characters for a CLOB and bytes for a BLOB. A CLOB's
//! data is UTF-16BE. The reply returns an updated locator, which the next
//! operation and the bind must use instead of the old one.
std::vector<uint8_t> EncodeTtcWriteLob(uint8_t sequence, const std::vector<uint8_t> &locator, uint64_t offset,
                                       const std::vector<uint8_t> &data);
std::vector<uint8_t> EncodeTtcFreeTempLobs(uint8_t sequence, const std::vector<std::vector<uint8_t>> &locators);

//! The whole response to a create, write or release: the locator the server
//! returned (empty for a release that returns none) and the end-of-call.
//! `created` is true for CREATE_TEMP, whose reply carries two extra fields.
std::vector<uint8_t> DecodeCompleteTtcLocatorCall(const std::vector<uint8_t> &response, size_t locator_count,
                                                  bool created, uint8_t server_field_version);

TtcLobResponse DecodeTtcLobResponse(const std::vector<uint8_t> &message, size_t locator_size);

//! The whole response to one LOB operation: the data, the return parameter and
//! the end-of-call that closes it. TRUNCATED means more of it has yet to arrive
//! and nothing else does; a refusal throws INVALID_STATE with Oracle's error
//! number. bytes_consumed covers the end-of-call too.
TtcLobResponse DecodeCompleteTtcLobCall(const std::vector<uint8_t> &response, size_t locator_size,
                                        uint8_t server_field_version);

// A CLOB read comes back as AL16UTF16 — two bytes per BMP character, surrogate
// pairs above it — whatever the database character set is and whatever the
// content holds. Live 19c, verified with ASCII and with Cyrillic: ten
// characters arrive as twenty bytes either way, so the width is the encoding
// and not an accident of the sample. Every other character value on this wire
// is UTF-8, so a CLOB is converted here and reaches the rest of the client
// looking like a VARCHAR2.
std::vector<uint8_t> DecodeUtf16BeToUtf8(OracleByteView utf16);
inline std::vector<uint8_t> DecodeUtf16BeToUtf8(const std::vector<uint8_t> &utf16) {
    return DecodeUtf16BeToUtf8(OracleByteView(utf16));
}
// The reverse, for a value written to a national character column. The input
// must be well-formed UTF-8 (no overlong forms, surrogates or code points past
// U+10FFFF); anything else is MALFORMED rather than repaired.
std::vector<uint8_t> EncodeUtf8ToUtf16Be(const std::string &utf8);

} // namespace oracle_scanner

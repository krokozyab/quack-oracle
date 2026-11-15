#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>
#include "oracle_scanner/row_batch.hpp"

namespace oracle_scanner {

constexpr uint8_t TTC_MESSAGE_ROW_DATA = 7;

// Decodes one scalar TTC ROW_DATA frame after a describe response has fixed
// the column count. Type conversion is intentionally left to value_codec.
using TtcRowData = OracleRowData;
struct TtcRowDataPrefix {
    TtcRowData values;
    size_t bytes_consumed = 0;
};

// A LOB column does not send its value. It sends a locator, and it frames that
// locator differently from every other value: a universal-integer length
// instead of the single length byte a scalar uses, and one trailing byte after
// it. Reading it as a scalar consumes the length's own first byte as the value
// and then treats the next byte as a message type, which is how this announced
// itself — "unknown TTC message 114", 114 being the locator's length.
// Captured from 19c for CLOB and BLOB alike; a NULL LOB is a single zero, the
// same as any other NULL.
constexpr uint16_t ORACLE_WIRE_TYPE_CLOB = 112;
constexpr uint16_t ORACLE_WIRE_TYPE_BLOB = 113;

inline bool IsOracleLobType(uint16_t oracle_type) {
    return oracle_type == ORACLE_WIRE_TYPE_CLOB || oracle_type == ORACLE_WIRE_TYPE_BLOB;
}

// JSON (an OSON image) and VECTOR arrive exactly as a BLOB does: a locator in
// ROW_DATA, the image behind it. They are binary, never character, LOBs.
constexpr uint16_t ORACLE_WIRE_TYPE_JSON = 119;
constexpr uint16_t ORACLE_WIRE_TYPE_VECTOR = 127;

inline bool IsOracleLocatorType(uint16_t oracle_type) {
    return IsOracleLobType(oracle_type) || oracle_type == ORACLE_WIRE_TYPE_JSON ||
           oracle_type == ORACLE_WIRE_TYPE_VECTOR;
}

// LONG and LONG RAW declare no maximum: the describe reports zero, which for
// every other type means a column that can only ever be NULL and is left out of
// ROW_DATA. These two are sent, as a chunked value, so a zero maximum must not
// be read as absence for them.
constexpr uint16_t ORACLE_WIRE_TYPE_LONG = 8;
constexpr uint16_t ORACLE_WIRE_TYPE_LONG_RAW = 24;

inline bool IsOracleLongType(uint16_t oracle_type) {
    return oracle_type == ORACLE_WIRE_TYPE_LONG || oracle_type == ORACLE_WIRE_TYPE_LONG_RAW;
}

// How a column's value is framed in ROW_DATA. A scalar is a length byte and its
// bytes; a LOB is a locator. A ROWID is five universal integers behind a length
// byte, and a UROWID a universal-integer length followed by its bytes. Both
// come out of the decoder as the bytes a codec reads: a ROWID as twelve (data
// object 4, file 2, block 4, row 2, big-endian), a UROWID as the bytes it
// carries, a physical one being 13 with a leading 1. Captured from 19c, and
// the decoded text compared with ROWIDTOCHAR on 19c and Free.
constexpr uint16_t ORACLE_WIRE_TYPE_ROWID = 11;
constexpr uint16_t ORACLE_WIRE_TYPE_UROWID = 208;

// A LONG or LONG RAW is a chunked value followed by a signed indicator (0, or
// -1 for NULL) and a return code (0, or 1405 for NULL), both universal
// integers that carry nothing the value does not already say. Captured from
// 19c: `fe 01 02 78 79 00 00 00` for 'xy', and `00 81 01 02 05 7d` for NULL.
//
// A cursor that has asked for LOB values ahead of their locators gets cells
// framed differently: the locator's size, the value's total size, a chunk size,
// then either the first bytes of the value (JSON and VECTOR, whose define says
// how many to send) or nothing (CLOB and BLOB, which it asks for none), and
// the locator. Captured from a 23ai server answering python-oracledb Thin.
enum class TtcColumnFraming : uint8_t { SCALAR, LOB, ROWID, UROWID, LONG, LOB_WITH_PREFIX, LOB_WITHOUT_PREFIX };

// What a cell framed that way is kept as until the session resolves it: the
// value's total size, the leading bytes the server sent, and the locator.
struct TtcInlineLob {
    uint64_t total = 0;
    std::vector<uint8_t> prefix;
    std::vector<uint8_t> locator;
};
std::vector<uint8_t> EncodeTtcInlineLob(const TtcInlineLob &lob);
TtcInlineLob DecodeTtcInlineLob(OracleByteView cell);
inline TtcInlineLob DecodeTtcInlineLob(const std::vector<uint8_t> &cell) {
    return DecodeTtcInlineLob(OracleByteView(cell));
}

inline TtcColumnFraming TtcFramingForType(uint16_t oracle_type) {
    if (IsOracleLocatorType(oracle_type)) {
        return TtcColumnFraming::LOB;
    }
    if (oracle_type == ORACLE_WIRE_TYPE_ROWID) {
        return TtcColumnFraming::ROWID;
    }
    if (oracle_type == ORACLE_WIRE_TYPE_UROWID) {
        return TtcColumnFraming::UROWID;
    }
    if (IsOracleLongType(oracle_type)) {
        return TtcColumnFraming::LONG;
    }
    return TtcColumnFraming::SCALAR;
}

TtcRowDataPrefix DecodeTtcRowDataPrefix(const std::vector<uint8_t> &message,
                                        const std::vector<TtcColumnFraming> &framing,
                                        size_t maximum_value_bytes = (1U << 20U));
// The same, reading from a position inside a larger response rather than from
// a copy of what is left of it.
TtcRowDataPrefix DecodeTtcRowDataPrefix(const uint8_t *data, size_t size, const std::vector<TtcColumnFraming> &framing,
                                        size_t maximum_value_bytes = (1U << 20U),
                                        OracleRowData::ArenaPtr arena = nullptr);

TtcRowDataPrefix DecodeTtcRowDataPrefix(const std::vector<uint8_t> &message, size_t column_count,
                                        size_t maximum_value_bytes = 16U << 20U);
class ByteReader;
void AppendTtcScalarCell(ByteReader &reader, const uint8_t *data, OracleRowData &row, size_t maximum_value_bytes);

TtcRowData DecodeTtcRowData(const std::vector<uint8_t> &message, size_t column_count,
                            size_t maximum_value_bytes = 16U << 20U);

} // namespace oracle_scanner

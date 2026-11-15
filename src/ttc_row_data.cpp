#include "oracle_scanner/ttc_row_data.hpp"
#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include <array>

namespace oracle_scanner {

// The maximum locator this accepts. Oracle's own are 40 (python-oracledb) to
// 114 (what 19c sends here) bytes; a declared length far past that is a
// misread rather than a locator, and it would otherwise become an allocation.
constexpr size_t MAX_LOB_LOCATOR_BYTES = 4096;

// The longest UROWID Oracle allows is 4000 bytes; anything past this is a
// misread, not a rowid.
constexpr size_t MAX_UROWID_BYTES = 4096;

namespace {

// A ROWID column: a length byte that is 0 or 0xFF for NULL, then the data
// object, the file, one skipped byte, the block and the row as universal
// integers. They are returned as twelve big-endian bytes so that the codec
// sees one fixed shape, whatever width each integer was sent in.
std::optional<std::array<uint8_t, 12>> ReadRowid(ByteReader &reader) {
    const auto length = reader.ReadByte();
    if (length == 0 || length == TNS_NULL_LENGTH_INDICATOR) {
        return std::nullopt;
    }
    const auto object = reader.ReadUB4();
    const auto file = reader.ReadUB2();
    reader.ReadByte();
    const auto block = reader.ReadUB4();
    const auto row = reader.ReadUB2();
    std::array<uint8_t, 12> result {};
    size_t position = 0;
    for (int shift = 24; shift >= 0; shift -= 8) {
        result[position++] = static_cast<uint8_t>(object >> shift);
    }
    result[position++] = static_cast<uint8_t>(file >> 8U);
    result[position++] = static_cast<uint8_t>(file);
    for (int shift = 24; shift >= 0; shift -= 8) {
        result[position++] = static_cast<uint8_t>(block >> shift);
    }
    result[position++] = static_cast<uint8_t>(row >> 8U);
    result[position++] = static_cast<uint8_t>(row);
    return result;
}

// A UROWID column: its size as a universal integer, zero for NULL, and then the
// bytes in the ordinary length-prefixed form, so the size is stated twice.
void AppendUrowid(ByteReader &reader, const uint8_t *data, OracleRowData &row) {
    const auto size = reader.ReadUB4();
    if (!size) {
        row.Append(std::nullopt);
        return;
    }
    if (size > MAX_UROWID_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC UROWID length is implausible");
    }
    AppendTtcScalarCell(reader, data, row, MAX_UROWID_BYTES);
    if (!row.back() || row.back()->size() != size) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC UROWID length disagrees with its prefix");
    }
}

// The indicator and return code behind a LONG value. Neither is kept: a NULL
// is already the empty value in front of them. The indicator is signed, so its
// length byte may carry the sign in the high bit.
void SkipLongTrailer(ByteReader &reader) {
    const auto indicator_length = reader.ReadByte() & 0x7FU;
    if (indicator_length > 4) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC LONG indicator is implausibly wide");
    }
    reader.Skip(indicator_length);
    (void)reader.ReadUB2();
}

} // namespace

std::vector<uint8_t> EncodeTtcInlineLob(const TtcInlineLob &lob) {
    std::vector<uint8_t> cell;
    cell.reserve(12 + lob.prefix.size() + lob.locator.size());
    for (int shift = 56; shift >= 0; shift -= 8) {
        cell.push_back(static_cast<uint8_t>(lob.total >> static_cast<unsigned>(shift)));
    }
    const auto prefix_size = static_cast<uint32_t>(lob.prefix.size());
    for (int shift = 24; shift >= 0; shift -= 8) {
        cell.push_back(static_cast<uint8_t>(prefix_size >> static_cast<unsigned>(shift)));
    }
    cell.insert(cell.end(), lob.prefix.begin(), lob.prefix.end());
    cell.insert(cell.end(), lob.locator.begin(), lob.locator.end());
    return cell;
}

TtcInlineLob DecodeTtcInlineLob(OracleByteView cell) {
    if (cell.size() < 12) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "a stored LOB cell is too short");
    }
    TtcInlineLob lob;
    for (size_t index = 0; index < 8; index++) {
        lob.total = (lob.total << 8U) | cell[index];
    }
    uint32_t prefix_size = 0;
    for (size_t index = 8; index < 12; index++) {
        prefix_size = (prefix_size << 8U) | cell[index];
    }
    if (prefix_size > cell.size() - 12) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "a stored LOB cell's prefix runs past its end");
    }
    lob.prefix.assign(cell.begin() + 12, cell.begin() + 12 + prefix_size);
    lob.locator.assign(cell.begin() + 12 + prefix_size, cell.end());
    return lob;
}

void AppendTtcScalarCell(ByteReader &reader, const uint8_t *data, OracleRowData &row, size_t maximum_value_bytes) {
    const auto first = reader.ReadByte();
    if (!first || first == TNS_NULL_LENGTH_INDICATOR) {
        row.Append(std::nullopt);
        return;
    }
    if (first != TNS_LONG_LENGTH_INDICATOR) {
        if (first > maximum_value_bytes) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC value exceeds configured limit");
        }
        const auto offset = reader.Position();
        reader.Skip(first);
        row.Append(OracleByteView(data + offset, first));
        return;
    }
    row.Append(std::nullopt);
    size_t size = 0;
    for (;;) {
        const auto count = reader.ReadUB4();
        if (!count) {
            return;
        }
        if (count > maximum_value_bytes - size) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "chunked TTC value exceeds configured limit");
        }
        const auto offset = reader.Position();
        reader.Skip(count);
        row.AppendCellBytes(row.size() - 1, OracleByteView(data + offset, count));
        size += count;
    }
}

TtcRowDataPrefix DecodeTtcRowDataPrefix(const std::vector<uint8_t> &message, const std::vector<TtcColumnFraming> &framing,
                                        size_t maximum_value_bytes) {
    return DecodeTtcRowDataPrefix(message.data(), message.size(), framing, maximum_value_bytes);
}

TtcRowDataPrefix DecodeTtcRowDataPrefix(const uint8_t *data, size_t size, const std::vector<TtcColumnFraming> &framing,
                                        size_t maximum_value_bytes, OracleRowData::ArenaPtr arena) {
    if (framing.empty() || framing.size() > 4096 || maximum_value_bytes == 0 || maximum_value_bytes > (16U << 20U)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC row-data decoder bounds are invalid");
    }
    ByteReader reader(data, size);
    if (reader.ReadByte() != TTC_MESSAGE_ROW_DATA) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC ROW_DATA message");
    }
    TtcRowData result(0, std::move(arena));
    const auto checkpoint = result.Arena()->Size();
    try {
        result.reserve(framing.size());
        for (size_t column = 0; column < framing.size(); column++) {
            if (framing[column] == TtcColumnFraming::SCALAR) {
                AppendTtcScalarCell(reader, data, result, maximum_value_bytes);
                continue;
            }
            if (framing[column] == TtcColumnFraming::ROWID) {
                const auto rowid = ReadRowid(reader);
                result.Append(rowid ? std::optional<OracleByteView>(OracleByteView(rowid->data(), rowid->size()))
                                    : std::nullopt);
                continue;
            }
            if (framing[column] == TtcColumnFraming::UROWID) {
                AppendUrowid(reader, data, result);
                continue;
            }
            if (framing[column] == TtcColumnFraming::LONG) {
                AppendTtcScalarCell(reader, data, result, maximum_value_bytes);
                SkipLongTrailer(reader);
                continue;
            }
            const auto locator_size = reader.ReadUB4();
            if (locator_size == 0) {
                // A NULL LOB, framed like any other NULL.
                result.emplace_back(std::nullopt);
                continue;
            }
            if (locator_size > MAX_LOB_LOCATOR_BYTES) {
                throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC LOB locator length is implausible");
            }
            if (framing[column] == TtcColumnFraming::LOB_WITH_PREFIX ||
                framing[column] == TtcColumnFraming::LOB_WITHOUT_PREFIX) {
                TtcInlineLob lob;
                lob.total = reader.ReadUB8();
                (void)reader.ReadUB4(); // the server's chunk size, not an allocation request
                if (framing[column] == TtcColumnFraming::LOB_WITH_PREFIX) {
                    auto prefix = reader.ReadLengthPrefixed(maximum_value_bytes);
                    if (prefix) {
                        lob.prefix = std::move(*prefix);
                    }
                    if (lob.prefix.size() > lob.total) {
                        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC LOB prefix is longer than the LOB");
                    }
                }
                auto locator = reader.ReadLengthPrefixed(MAX_LOB_LOCATOR_BYTES);
                if (!locator || locator->size() != locator_size) {
                    throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                        "TTC LOB locator length disagrees with its prefix");
                }
                lob.locator = std::move(*locator);
                result.emplace_back(EncodeTtcInlineLob(lob));
                continue;
            }
            // The ub4 above is the locator's size, and the locator then follows in
            // the ordinary length-prefixed form — so its length is stated twice.
            // Reading the ub4 and then `locator_size` raw bytes consumes exactly as
            // many bytes as this does, which is why the wrong reading stays in
            // frame across every column and only shows up as ORA-22275 when the
            // locator is sent back one byte out of place.
            AppendTtcScalarCell(reader, data, result, MAX_LOB_LOCATOR_BYTES);
            if (!result.back() || result.back()->size() != locator_size) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC LOB locator length disagrees with its prefix");
            }
        }
        return {std::move(result), reader.Position()};
    } catch (...) {
        result.Arena()->Truncate(checkpoint);
        throw;
    }
}

TtcRowDataPrefix DecodeTtcRowDataPrefix(const std::vector<uint8_t> &message, size_t column_count,
                                        size_t maximum_value_bytes) {
    if (column_count == 0 || column_count > 4096 || maximum_value_bytes == 0 || maximum_value_bytes > (16U << 20U)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC row-data decoder bounds are invalid");
    }
    return DecodeTtcRowDataPrefix(message.data(), message.size(),
                                  std::vector<TtcColumnFraming>(column_count, TtcColumnFraming::SCALAR),
                                  maximum_value_bytes);
}

TtcRowData DecodeTtcRowData(const std::vector<uint8_t> &message, size_t column_count, size_t maximum_value_bytes) {
    auto result = DecodeTtcRowDataPrefix(message, column_count, maximum_value_bytes);
    if (result.bytes_consumed != message.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC ROW_DATA has trailing bytes");
    }
    return std::move(result.values);
}

} // namespace oracle_scanner

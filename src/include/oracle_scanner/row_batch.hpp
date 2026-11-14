#pragma once

#include "oracle_scanner/protocol_error.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace oracle_scanner {

// A borrowed scalar value. The owning batch must outlive the view; mutating
// the batch invalidates existing views.
class OracleByteView {
public:
    OracleByteView(const uint8_t *bytes, size_t count) : bytes(bytes), count(count) {}
    OracleByteView(const std::vector<uint8_t> &value) : OracleByteView(value.data(), value.size()) {}
    const uint8_t *data() const { return bytes; }
    size_t size() const { return count; }
    bool empty() const { return count == 0; }
    const uint8_t *begin() const { return bytes; }
    const uint8_t *end() const { return count ? bytes + count : bytes; }
    uint8_t operator[](size_t index) const { return bytes[index]; }
    uint8_t back() const { return bytes[count - 1]; }
private:
    const uint8_t *bytes;
    size_t count;
};

// Transport-neutral scalar batch. Offsets survive arena growth, and a row
// continuation copies only descriptors. No cell owns a separate allocation.
class OraclePackedBatch {
public:
    static constexpr size_t MAXIMUM_BYTES = 64U << 20U;
    explicit OraclePackedBatch(size_t columns = 0) : columns(columns) {
        if (columns > 4096) { throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle packed batch has too many columns"); }
    }
    size_t ColumnCount() const { return columns; }
    size_t RowCount() const { return columns ? cells.size() / columns : 0; }
    size_t ByteCount() const { return bytes.size(); }
    void ReserveRows(size_t rows) {
        if (!columns || rows > MAXIMUM_BYTES / sizeof(Cell) / columns) { return; }
        const auto count = (std::min)(rows * columns, size_t(65536));
        cells.reserve(count);
        validity.reserve((count + 7) / 8);
        bytes.reserve((std::min)(MAXIMUM_BYTES / 2, count * 8));
    }
    void AppendRow(bool copy_previous = false) {
        if (!columns || (copy_previous && cells.empty())) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle packed row has no preceding row");
        }
        CheckBudget(0, columns);
        const auto start = cells.size();
        validity.resize((start + columns + 7) / 8, 0);
        for (size_t i = 0; i < columns; i++) {
            const auto cell = copy_previous ? cells[start - columns + i] : Cell {0, 0};
            const bool valid = copy_previous && IsValid(start - columns + i);
            cells.push_back(cell);
            SetValid(start + i, valid);
        }
    }
    void AppendCellBytes(size_t column, const uint8_t *source, size_t count) {
        if (column >= columns || cells.empty()) { throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle packed cell is outside its row"); }
        CheckBudget(count, 0);
        const auto index = cells.size() - columns + column;
        auto &cell = cells[index];
        if (!IsValid(index)) { cell = {static_cast<uint32_t>(bytes.size()), 0}; }
        if (cell.offset + cell.length != bytes.size()) { throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle packed cell chunks are not contiguous"); }
        if (count) { bytes.insert(bytes.end(), source, source + count); }
        cell.length += static_cast<uint32_t>(count);
        SetValid(index, true);
    }
    // A changed column must not append to the previous row's shared bytes.
    void ClearCell(size_t column) {
        if (column >= columns || cells.empty()) { throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle packed cell is outside its row"); }
        const auto index = cells.size() - columns + column;
        cells[index] = {0, 0}; SetValid(index, false);
    }
    std::optional<OracleByteView> Get(size_t row, size_t column) const {
        if (column >= columns || row >= RowCount()) { throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle packed cell index is out of range"); }
        const auto index = row * columns + column;
        if (!IsValid(index)) { return std::nullopt; }
        const auto &cell = cells[index];
        if (cell.offset > bytes.size() || cell.length > bytes.size() - cell.offset) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle packed cell exceeds its arena");
        }
        // A non-NULL empty value still needs a valid empty range.
        static constexpr uint8_t empty = 0;
        return OracleByteView(bytes.empty() ? &empty : bytes.data() + cell.offset, cell.length);
    }
    std::vector<std::optional<std::vector<uint8_t>>> MaterializeRow(size_t row) const {
        std::vector<std::optional<std::vector<uint8_t>>> result;
        result.reserve(columns);
        for (size_t i = 0; i < columns; i++) {
            const auto value = Get(row, i);
            if (value) { result.emplace_back(std::vector<uint8_t>(value->begin(), value->end())); }
            else { result.emplace_back(std::nullopt); }
        }
        return result;
    }
    void Truncate(size_t rows, size_t byte_count) {
        if (rows > RowCount() || byte_count > bytes.size()) { throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle packed checkpoint is outside its batch"); }
        cells.resize(rows * columns); validity.resize((cells.size() + 7) / 8); bytes.resize(byte_count);
    }
    void RemoveFirstRow() {
        if (cells.empty()) { return; }
        const auto remaining = cells.size() - columns;
        for (size_t i = 0; i < remaining; i++) { SetValid(i, IsValid(i + columns)); }
        cells.erase(cells.begin(), cells.begin() + static_cast<std::ptrdiff_t>(columns));
        validity.resize((remaining + 7) / 8);
    }
private:
    struct Cell { uint32_t offset; uint32_t length; };
    bool IsValid(size_t index) const { return (validity[index / 8] & (1U << (index % 8))) != 0; }
    void SetValid(size_t index, bool valid) {
        const auto mask = static_cast<uint8_t>(1U << (index % 8));
        if (valid) { validity[index / 8] |= mask; } else { validity[index / 8] &= static_cast<uint8_t>(~mask); }
    }
    void CheckBudget(size_t extra_bytes, size_t extra_cells) const {
        if (extra_cells > MAXIMUM_BYTES / sizeof(Cell) - cells.size() || extra_bytes > MAXIMUM_BYTES - bytes.size()) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle packed batch exceeds its memory limit");
        }
        const auto count = cells.size() + extra_cells;
        if (count * sizeof(Cell) + (count + 7) / 8 + bytes.size() + extra_bytes > MAXIMUM_BYTES) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle packed batch exceeds its memory limit");
        }
    }
    size_t columns;
    std::vector<uint8_t> bytes;
    std::vector<Cell> cells;
    std::vector<uint8_t> validity;
};

} // namespace oracle_scanner

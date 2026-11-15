#pragma once

#include "oracle_scanner/protocol_error.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <vector>
#include <utility>

namespace oracle_scanner {

// A borrowed scalar value. The owning batch must outlive the view; mutating
// the batch invalidates existing views.
class OracleByteView {
public:
    OracleByteView(const uint8_t *bytes, size_t count) : bytes(bytes), count(count) {
    }
    explicit OracleByteView(const std::vector<uint8_t> &value) : OracleByteView(value.data(), value.size()) {
    }
    OracleByteView(std::vector<uint8_t> &&) = delete;
    OracleByteView(const std::vector<uint8_t> &&) = delete;
    const uint8_t *data() const {
        return bytes;
    }
    size_t size() const {
        return count;
    }
    bool empty() const {
        return count == 0;
    }
    const uint8_t *begin() const {
        return bytes;
    }
    const uint8_t *end() const {
        return count ? bytes + count : bytes;
    }
    uint8_t operator[](size_t index) const {
        return bytes[index];
    }
    uint8_t back() const {
        return bytes[count - 1];
    }

private:
    const uint8_t *bytes;
    size_t count;
};

inline bool operator==(OracleByteView left, OracleByteView right) {
    return left.size() == right.size() && (!left.size() || std::memcmp(left.data(), right.data(), left.size()) == 0);
}
inline bool operator==(OracleByteView left, const std::vector<uint8_t> &right) {
    return left == OracleByteView(right);
}
inline bool operator==(const std::vector<uint8_t> &left, OracleByteView right) {
    return OracleByteView(left) == right;
}
inline bool operator!=(OracleByteView left, OracleByteView right) {
    return !(left == right);
}

// One response owns the bytes; row/cell copies copy only offsets. Views are
// borrowed until the next append. Offsets remain valid across arena growth.
class OracleRowArena {
public:
    size_t Size() const {
        return bytes.size();
    }
    void Truncate(size_t count) {
        if (count > bytes.size()) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle row arena checkpoint is outside its bytes");
        }
        bytes.resize(count);
    }
    size_t Append(OracleByteView value) {
        if (value.size() > bytes.max_size() - bytes.size()) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle row arena exceeds addressable storage");
        }
        const auto offset = bytes.size();
        // A cell may be copied from this arena while it grows (LOB assembly,
        // or reassigning a column). Rebase the source after any reallocation.
        const auto address = reinterpret_cast<uintptr_t>(value.data());
        const auto base = reinterpret_cast<uintptr_t>(bytes.data());
        const bool internal = value.size() && address >= base && address - base < bytes.size() &&
                              value.size() <= bytes.size() - (address - base);
        const auto source_offset = internal ? address - base : 0;
        if (internal) {
            bytes.resize(offset + value.size());
            std::memmove(bytes.data() + offset, bytes.data() + source_offset, value.size());
        } else if (value.size()) {
            bytes.insert(bytes.end(), value.begin(), value.end());
        }
        return offset;
    }
    OracleByteView Get(size_t offset, size_t count) const {
        if (offset > bytes.size() || count > bytes.size() - offset) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle row cell exceeds its arena");
        }
        static constexpr uint8_t empty = 0;
        return OracleByteView(bytes.empty() ? &empty : bytes.data() + offset, count);
    }

private:
    std::vector<uint8_t> bytes;
};

class OracleRowData {
public:
    using ArenaPtr = std::shared_ptr<OracleRowArena>;
    OracleRowData() : OracleRowData(0, nullptr) {
    }
    explicit OracleRowData(size_t columns, ArenaPtr arena = nullptr)
        : arena(arena ? std::move(arena) : std::make_shared<OracleRowArena>()) {
        CheckColumns(columns);
        cells.resize(columns);
    }
    OracleRowData(std::initializer_list<std::optional<std::vector<uint8_t>>> values) : OracleRowData() {
        reserve(values.size());
        for (const auto &value : values) {
            push_back(value);
        }
    }
    OracleRowData(size_t count, const std::vector<uint8_t> &value) : OracleRowData(count) {
        if (count) {
            Set(0, OracleByteView(value));
            for (size_t i = 1; i < count; i++) {
                CopyCell(i, *this, 0);
            }
        }
    }
    size_t size() const {
        return cells.size();
    }
    bool empty() const {
        return cells.empty();
    }
    const ArenaPtr &Arena() const {
        return arena;
    }
    void reserve(size_t count) {
        CheckColumns(count);
        cells.reserve(count);
    }
    void resize(size_t count) {
        CheckColumns(count);
        cells.resize(count);
    }
    // const prvalues deliberately forbid the old row[i] = value spelling:
    // mutating a temporary view would otherwise silently do nothing.
    const std::optional<OracleByteView> operator[](size_t index) const {
        const auto &cell = CellAt(index);
        return cell.length == NULL_LENGTH ? std::nullopt
                                          : std::optional<OracleByteView>(arena->Get(cell.offset, cell.length));
    }
    const std::optional<OracleByteView> back() const {
        return (*this)[size() - 1];
    }
    void Set(size_t index, const std::optional<OracleByteView> &value) {
        auto &cell = CellAt(index);
        cell = value ? Cell {arena->Append(*value), value->size()} : Cell {};
    }
    void Set(size_t index, const std::vector<uint8_t> &value) {
        Set(index, OracleByteView(value));
    }
    void SetOwned(size_t index, const std::optional<std::vector<uint8_t>> &value) {
        Set(index, value ? std::optional<OracleByteView>(OracleByteView(*value)) : std::nullopt);
    }
    void CopyCell(size_t index, const OracleRowData &source, size_t column) {
        if (arena == source.arena) {
            CellAt(index) = source.CellAt(column);
        } else {
            Set(index, source[column]);
        }
    }
    void Append(const std::optional<OracleByteView> &value) {
        CheckColumns(cells.size() + 1);
        cells.emplace_back();
        Set(cells.size() - 1, value);
    }
    void AppendCellBytes(size_t index, OracleByteView value) {
        auto &cell = CellAt(index);
        if (cell.length == NULL_LENGTH) {
            cell = {arena->Size(), 0};
        }
        if (cell.offset + cell.length != arena->Size()) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle row cell chunks are not contiguous");
        }
        arena->Append(value);
        cell.length += value.size();
    }
    void push_back(const std::optional<std::vector<uint8_t>> &value) {
        Append(value ? std::optional<OracleByteView>(OracleByteView(*value)) : std::nullopt);
    }
    void emplace_back(const std::optional<std::vector<uint8_t>> &value) {
        push_back(value);
    }
    OracleRowData Clone(ArenaPtr target = nullptr) const {
        OracleRowData result(size(), std::move(target));
        if (result.arena == arena) {
            result.cells = cells;
            return result;
        }
        size_t logical_bytes = 0;
        for (const auto &cell : cells) {
            if (cell.length != NULL_LENGTH) {
                logical_bytes += (std::min)(cell.length, arena->Size() - logical_bytes);
            }
        }
        if (arena->Size() <= logical_bytes) {
            // Preserve shared ranges when copying the arena is no larger than
            // copying this logical row. Repeated large cells stay shared.
            const auto base = result.arena->Append(arena->Get(0, arena->Size()));
            result.cells = cells;
            for (auto &cell : result.cells) {
                if (cell.length != NULL_LENGTH) {
                    cell.offset += base;
                }
            }
        } else {
            for (size_t i = 0; i < size(); i++) {
                result.CopyCell(i, *this, i);
            }
        }
        return result;
    }
    class Iterator {
    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = std::optional<OracleByteView>;
        using difference_type = std::ptrdiff_t;
        using pointer = void;
        using reference = value_type;
        Iterator() = default;
        Iterator(const OracleRowData *row, size_t index) : row(row), index(index) {
        }
        value_type operator*() const {
            return (*row)[index];
        }
        Iterator &operator++() {
            index++;
            return *this;
        }
        Iterator operator++(int) {
            auto copy = *this;
            ++*this;
            return copy;
        }
        bool operator!=(const Iterator &other) const {
            return row != other.row || index != other.index;
        }
        bool operator==(const Iterator &other) const {
            return !(*this != other);
        }

    private:
        const OracleRowData *row = nullptr;
        size_t index = 0;
    };
    Iterator begin() const {
        return Iterator(this, 0);
    }
    Iterator end() const {
        return Iterator(this, size());
    }
    bool operator!=(const OracleRowData &other) const {
        return !(*this == other);
    }
    bool operator==(const OracleRowData &other) const {
        if (size() != other.size()) {
            return false;
        }
        for (size_t i = 0; i < size(); i++) {
            if ((*this)[i] != other[i]) {
                return false;
            }
        }
        return true;
    }

private:
    static void CheckColumns(size_t columns) {
        if (columns > 4096) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle row has too many columns");
        }
    }
    static constexpr size_t NULL_LENGTH = (std::numeric_limits<size_t>::max)();
    struct Cell {
        size_t offset = 0;
        size_t length = NULL_LENGTH;
    };
    Cell &CellAt(size_t index) {
        if (index >= cells.size()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle row cell index is out of range");
        }
        return cells[index];
    }
    const Cell &CellAt(size_t index) const {
        if (index >= cells.size()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle row cell index is out of range");
        }
        return cells[index];
    }
    ArenaPtr arena;
    std::vector<Cell> cells;
};

// Transport-neutral scalar batch. Offsets survive arena growth, and a row
// continuation copies only descriptors. No cell owns a separate allocation.
class OraclePackedBatch {
public:
    static constexpr size_t MAXIMUM_BYTES = 64U << 20U;
    explicit OraclePackedBatch(size_t columns = 0) : columns(columns) {
        if (columns > 4096) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle packed batch has too many columns");
        }
    }
    size_t ColumnCount() const {
        return columns;
    }
    size_t RowCount() const {
        return columns ? cells.size() / columns : 0;
    }
    size_t ByteCount() const {
        return bytes.size();
    }
    void ReserveRows(size_t rows) {
        if (!columns || rows > MAXIMUM_BYTES / sizeof(Cell) / columns) {
            return;
        }
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
        if (column >= columns || cells.empty()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle packed cell is outside its row");
        }
        CheckBudget(count, 0);
        const auto index = cells.size() - columns + column;
        auto &cell = cells[index];
        if (!IsValid(index)) {
            cell = {static_cast<uint32_t>(bytes.size()), 0};
        }
        if (cell.offset + cell.length != bytes.size()) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle packed cell chunks are not contiguous");
        }
        if (count) {
            bytes.insert(bytes.end(), source, source + count);
        }
        cell.length += static_cast<uint32_t>(count);
        SetValid(index, true);
    }
    // A changed column must not append to the previous row's shared bytes.
    void ClearCell(size_t column) {
        if (column >= columns || cells.empty()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle packed cell is outside its row");
        }
        const auto index = cells.size() - columns + column;
        cells[index] = {0, 0};
        SetValid(index, false);
    }
    std::optional<OracleByteView> Get(size_t row, size_t column) const {
        if (column >= columns || row >= RowCount()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle packed cell index is out of range");
        }
        const auto index = row * columns + column;
        if (!IsValid(index)) {
            return std::nullopt;
        }
        const auto &cell = cells[index];
        if (cell.offset > bytes.size() || cell.length > bytes.size() - cell.offset) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle packed cell exceeds its arena");
        }
        // A non-NULL empty value still needs a valid empty range.
        static constexpr uint8_t empty = 0;
        return OracleByteView(bytes.empty() ? &empty : bytes.data() + cell.offset, cell.length);
    }
    OracleRowData MaterializeRow(size_t row) const {
        OracleRowData result;
        result.reserve(columns);
        for (size_t i = 0; i < columns; i++) {
            const auto value = Get(row, i);
            if (value) {
                result.Append(value);
            } else {
                result.emplace_back(std::nullopt);
            }
        }
        return result;
    }
    void Truncate(size_t rows, size_t byte_count) {
        if (rows > RowCount() || byte_count > bytes.size()) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle packed checkpoint is outside its batch");
        }
        cells.resize(rows * columns);
        validity.resize((cells.size() + 7) / 8);
        bytes.resize(byte_count);
    }
    void RemoveFirstRow() {
        if (cells.empty()) {
            return;
        }
        const auto remaining = cells.size() - columns;
        for (size_t i = 0; i < remaining; i++) {
            SetValid(i, IsValid(i + columns));
        }
        cells.erase(cells.begin(), cells.begin() + static_cast<std::ptrdiff_t>(columns));
        validity.resize((remaining + 7) / 8);
    }

private:
    struct Cell {
        uint32_t offset;
        uint32_t length;
    };
    bool IsValid(size_t index) const {
        return (validity[index / 8] & (1U << (index % 8))) != 0;
    }
    void SetValid(size_t index, bool valid) {
        const auto mask = static_cast<uint8_t>(1U << (index % 8));
        if (valid) {
            validity[index / 8] |= mask;
        } else {
            validity[index / 8] &= static_cast<uint8_t>(~mask);
        }
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

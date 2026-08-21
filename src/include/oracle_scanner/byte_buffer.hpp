#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace oracle_scanner {

constexpr uint8_t TNS_LONG_LENGTH_INDICATOR = 254;
constexpr uint8_t TNS_NULL_LENGTH_INDICATOR = 255;
constexpr size_t TNS_MAX_SHORT_LENGTH = 252;

class ByteReader {
public:
    ByteReader(const uint8_t *data, size_t size);
    explicit ByteReader(const std::vector<uint8_t> &data);

    size_t Position() const;
    size_t Remaining() const;
    uint8_t ReadByte();
    uint8_t PeekByte() const;
    std::vector<uint8_t> ReadRaw(size_t count);
    void Skip(size_t count);
    uint16_t ReadUInt16BE();
    uint16_t ReadUInt16LE();
    uint32_t ReadUInt32BE();
    uint16_t ReadUB2();
    uint32_t ReadUB4();
    uint64_t ReadUB8();
    std::optional<std::vector<uint8_t>> ReadLengthPrefixed(size_t maximum_size);
    std::string ReadNullTerminated(size_t maximum_size);

private:
    uint64_t ReadUniversal(size_t maximum_bytes);

    const uint8_t *data;
    size_t size;
    size_t position;
};

class ByteWriter {
public:
    ByteWriter &WriteByte(uint8_t value);
    ByteWriter &WriteUInt16BE(uint16_t value);
    ByteWriter &WriteUInt16LE(uint16_t value);
    ByteWriter &WriteUInt32BE(uint32_t value);
    ByteWriter &WriteRaw(const uint8_t *value, size_t size);
    ByteWriter &WriteRaw(const std::vector<uint8_t> &value);
    ByteWriter &WriteUB2(uint16_t value);
    ByteWriter &WriteUB4(uint32_t value);
    ByteWriter &WriteUB8(uint64_t value);
    ByteWriter &WriteLengthPrefixed(const std::optional<std::vector<uint8_t>> &value);
    ByteWriter &WriteNullTerminated(const std::string &value);

    const std::vector<uint8_t> &Data() const;
    std::vector<uint8_t> Take();

private:
    ByteWriter &WriteUniversal(uint64_t value, size_t maximum_bytes);
    std::vector<uint8_t> data;
};

} // namespace oracle_scanner

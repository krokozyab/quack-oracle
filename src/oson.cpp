#include "oracle_scanner/oson.hpp"

#include "oracle_scanner/oracle_vector.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/value_codec.hpp"

#include <cmath>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace oracle_scanner {
namespace {

// The image is a header, a table of field names, and a tree of nodes. Every
// number below was read off images a 23ai server produced for documents built
// to exercise one feature at a time, and the layout they describe was then
// checked against JSON_SERIALIZE over generated documents. Anything outside
// what was seen is refused by name, never decoded on a guess.
//
//   FF 4A 5A  version(1)  flags(2, big-endian)
//   scalar document:  tree size (2, or 4 with TREE_SEG_UINT32), then the tree.
//   otherwise:        field count   (1, or 2 with NUM_FNAMES_UINT16)
//                     name segment size (2, or 4 with FNAMES_SEG_UINT32)
//                     tree segment size (2, or 4 with TREE_SEG_UINT32)
//                     tiny-node statistic (2, unused here)
//                     one hash byte per field, then one name offset per field
//                     (2, or 4 with FNAMES_SEG_UINT32), the names (length byte
//                     and UTF-8), and the tree.
// Version 3 is the same with room for field names longer than 255 bytes: after
// the name segment size come a byte that is 1 when the long names' offsets are
// two bytes wide and 0 when four, three zero bytes, the count of those long
// names (2) and their segment size (4); after the ordinary names, a second
// table of 2-byte hashes, offsets and names with a 2-byte length. Field numbers run through the ordinary names and on
// through the long ones.
//
// A tree node starts with a type byte. Below 0x20 it is a string of that many
// bytes; 0x20..0x2F a NUMBER of (low nibble + 1) bytes; 0x80 and above a
// container. In a container 0x40 marks an array and 0x20 gives child offsets
// four bytes instead of two. The 0x18 bits say how the child count is held: 0
// for one byte, 0x08 two, 0x10 four, and 0x18 for an object with exactly the
// fields of another, which holds that object's offset in place of a count and
// field numbers. An object lists its field numbers (1-based into the name
// table, as wide as the field count) before its child offsets. Offsets are
// positions in the tree segment, so two parents may share a child.
constexpr uint8_t OSON_MAGIC[3] = {0xFF, 0x4A, 0x5A};
constexpr uint8_t OSON_VERSION_MAX_FIELD_NAME_255 = 1;
constexpr uint8_t OSON_VERSION_MAX_FIELD_NAME_65535 = 3;

constexpr uint16_t FLAG_INLINE_LEAF = 0x0002;
constexpr uint16_t FLAG_LENGTH_IN_TYPE_CODE = 0x0004;
constexpr uint16_t FLAG_NUM_FIELDS_UINT32 = 0x0008;
constexpr uint16_t FLAG_IS_SCALAR = 0x0010;
constexpr uint16_t FLAG_SHARED_TREE = 0x0020;
constexpr uint16_t FLAG_HASH_ID_UINT8 = 0x0100;
constexpr uint16_t FLAG_HASH_ID_UINT16 = 0x0200;
constexpr uint16_t FLAG_NUM_FIELDS_UINT16 = 0x0400;
constexpr uint16_t FLAG_NAMES_SEGMENT_UINT32 = 0x0800;
constexpr uint16_t FLAG_TREE_SEGMENT_UINT32 = 0x1000;
constexpr uint16_t FLAG_TINY_NODE_STATISTIC = 0x2000;
constexpr uint16_t FLAG_NESTED = 0x4000;
// 0x0100 on a scalar tells only that its NUMBER does not fit a binary double.
constexpr uint16_t KNOWN_FLAGS = FLAG_INLINE_LEAF | FLAG_LENGTH_IN_TYPE_CODE | FLAG_NUM_FIELDS_UINT32 | FLAG_IS_SCALAR |
                                 FLAG_SHARED_TREE | FLAG_HASH_ID_UINT8 | FLAG_HASH_ID_UINT16 |
                                 FLAG_NUM_FIELDS_UINT16 | FLAG_NAMES_SEGMENT_UINT32 | FLAG_TREE_SEGMENT_UINT32 |
                                 FLAG_TINY_NODE_STATISTIC | FLAG_NESTED;

constexpr uint8_t NODE_NULL = 0x30;
constexpr uint8_t NODE_TRUE = 0x31;
constexpr uint8_t NODE_FALSE = 0x32;
constexpr uint8_t NODE_STRING_UINT8 = 0x33;
constexpr uint8_t NODE_NUMBER_UINT8 = 0x34;
constexpr uint8_t NODE_BINARY_DOUBLE = 0x36;
constexpr uint8_t NODE_STRING_UINT16 = 0x37;
constexpr uint8_t NODE_STRING_UINT32 = 0x38;
constexpr uint8_t NODE_TIMESTAMP = 0x39;
constexpr uint8_t NODE_BINARY_UINT16 = 0x3A;
constexpr uint8_t NODE_BINARY_UINT32 = 0x3B;
constexpr uint8_t NODE_DATE = 0x3C;
constexpr uint8_t NODE_INTERVAL_YM = 0x3D;
constexpr uint8_t NODE_INTERVAL_DS = 0x3E;
constexpr uint8_t NODE_EXTENDED = 0x7B;
constexpr uint8_t NODE_TIMESTAMP_TZ = 0x7C;
constexpr uint8_t NODE_TIMESTAMP_NO_FRACTION = 0x7D;
constexpr uint8_t NODE_BINARY_FLOAT = 0x7F;

[[noreturn]] void Fail(ProtocolErrorKind kind, const std::string &what) {
    throw ProtocolError(kind, "OSON image " + what);
}

uint64_t ReadBigEndian(const uint8_t *data, size_t width) {
    uint64_t value = 0;
    for (size_t index = 0; index < width; index++) {
        value = (value << 8U) | data[index];
    }
    return value;
}

bool IsValidUtf8(const uint8_t *data, size_t size) {
    size_t index = 0;
    while (index < size) {
        const uint8_t lead = data[index];
        size_t length;
        uint32_t code;
        if (lead < 0x80) {
            index++;
            continue;
        } else if (lead >= 0xC2 && lead <= 0xDF) {
            length = 2;
            code = lead & 0x1FU;
        } else if (lead >= 0xE0 && lead <= 0xEF) {
            length = 3;
            code = lead & 0x0FU;
        } else if (lead >= 0xF0 && lead <= 0xF4) {
            length = 4;
            code = lead & 0x07U;
        } else {
            return false;
        }
        if (size - index < length) {
            return false;
        }
        for (size_t offset = 1; offset < length; offset++) {
            if ((data[index + offset] & 0xC0U) != 0x80U) {
                return false;
            }
            code = (code << 6U) | (data[index + offset] & 0x3FU);
        }
        if ((length == 3 && (code < 0x800 || (code >= 0xD800 && code <= 0xDFFF))) ||
            (length == 4 && (code < 0x10000 || code > 0x10FFFF))) {
            return false;
        }
        index += length;
    }
    return true;
}

class OsonDecoder {
public:
    OsonDecoder(const uint8_t *data_p, size_t size_p, const OsonLimits &limits_p)
        : data(data_p), size(size_p), limits(limits_p) {
    }

    std::string Decode() {
        ParseHeader();
        Node(0, 0);
        return std::move(output);
    }

private:
    void Need(size_t position, size_t length, const char *what) const {
        if (position > size || length > size - position) {
            Fail(ProtocolErrorKind::TRUNCATED, std::string("ends inside ") + what);
        }
    }

    // One table of field names: a hash byte (or two) per name, then the offset
    // of each name inside the segment, then the segment, in which a name is its
    // byte length and its UTF-8. Returns the position after the segment.
    size_t ReadNameTable(size_t position, uint64_t count, size_t hash_width, size_t offset_width, size_t length_width,
                         uint64_t segment_size) {
        if (count > size) {
            Fail(ProtocolErrorKind::MALFORMED, "declares more field names than it has bytes");
        }
        Need(position, static_cast<size_t>(count) * (hash_width + offset_width), "its field-name table");
        const size_t offsets_at = position + static_cast<size_t>(count) * hash_width;
        position = offsets_at + static_cast<size_t>(count) * offset_width;
        Need(position, static_cast<size_t>(segment_size), "its field names");
        const uint8_t *names = data + position;
        field_names.reserve(field_names.size() + static_cast<size_t>(count));
        for (uint64_t index = 0; index < count; index++) {
            const auto name_offset = ReadBigEndian(data + offsets_at + index * offset_width, offset_width);
            if (name_offset > segment_size || segment_size - name_offset < length_width) {
                Fail(ProtocolErrorKind::MALFORMED, "has a field name outside its name segment");
            }
            const uint64_t length = ReadBigEndian(names + name_offset, length_width);
            if (segment_size - name_offset - length_width < length) {
                Fail(ProtocolErrorKind::MALFORMED, "has a field name running past its name segment");
            }
            const uint8_t *text = names + name_offset + length_width;
            if (!IsValidUtf8(text, static_cast<size_t>(length))) {
                Fail(ProtocolErrorKind::MALFORMED, "has a field name that is not UTF-8");
            }
            field_names.emplace_back(reinterpret_cast<const char *>(text), static_cast<size_t>(length));
        }
        return position + static_cast<size_t>(segment_size);
    }

    void ParseHeader() {
        Need(0, 6, "its header");
        if (std::memcmp(data, OSON_MAGIC, sizeof(OSON_MAGIC)) != 0) {
            Fail(ProtocolErrorKind::MALFORMED, "does not start with the OSON magic bytes");
        }
        const uint8_t version = data[3];
        if (version != OSON_VERSION_MAX_FIELD_NAME_255 && version != OSON_VERSION_MAX_FIELD_NAME_65535) {
            Fail(ProtocolErrorKind::UNSUPPORTED, "has version " + std::to_string(version) + ", which this decoder has not been shown");
        }
        const bool long_names = version == OSON_VERSION_MAX_FIELD_NAME_65535;
        const auto flags = static_cast<uint16_t>(ReadBigEndian(data + 4, 2));
        if ((flags & ~KNOWN_FLAGS) != 0) {
            char text[16];
            std::snprintf(text, sizeof(text), "0x%04x", flags);
            Fail(ProtocolErrorKind::UNSUPPORTED, std::string("has flags ") + text + ", which this decoder has not been shown");
        }
        size_t position = 6;
        const size_t tree_width = (flags & FLAG_TREE_SEGMENT_UINT32) != 0 ? 4 : 2;
        if ((flags & FLAG_IS_SCALAR) != 0) {
            Need(position, tree_width, "its tree size");
            const auto tree_size = ReadBigEndian(data + position, tree_width);
            position += tree_width;
            SetTree(position, tree_size);
            return;
        }
        const size_t field_count_width = (flags & FLAG_NUM_FIELDS_UINT32) != 0 ? 4 : (flags & FLAG_NUM_FIELDS_UINT16) != 0 ? 2 : 1;
        const size_t names_width = (flags & FLAG_NAMES_SEGMENT_UINT32) != 0 ? 4 : 2;
        Need(position, field_count_width + names_width, "its header");
        const auto field_count = ReadBigEndian(data + position, field_count_width);
        position += field_count_width;
        const auto names_size = ReadBigEndian(data + position, names_width);
        position += names_width;
        uint64_t long_count = 0;
        uint64_t long_names_size = 0;
        size_t long_offset_width = 2;
        if (long_names) {
            // After the ordinary names' size: whether the long names' offsets
            // are two bytes (1) or four (0), three zero bytes, the count of
            // names over 255 bytes (2) and the size of their segment (4).
            Need(position, 10, "its long field-name header");
            const uint8_t *header = data + position;
            if (header[0] > 1 || header[1] != 0 || header[2] != 0 || header[3] != 0) {
                Fail(ProtocolErrorKind::UNSUPPORTED, "has a long field-name header this decoder has not been shown");
            }
            long_offset_width = header[0] == 1 ? 2 : 4;
            long_count = ReadBigEndian(header + 4, 2);
            long_names_size = ReadBigEndian(header + 6, 4);
            position += 10;
        }
        Need(position, tree_width + 2, "its header");
        const auto tree_size = ReadBigEndian(data + position, tree_width);
        position += tree_width + 2; // the tiny-node statistic carries nothing a reader needs
        field_id_width = field_count_width;
        size_t hash_width = 0;
        if (field_count != 0) {
            if ((flags & FLAG_HASH_ID_UINT16) != 0) {
                hash_width = 2;
            } else if ((flags & FLAG_HASH_ID_UINT8) != 0) {
                hash_width = 1;
            } else {
                Fail(ProtocolErrorKind::UNSUPPORTED, "has field names with no hash width flag");
            }
        }
        position = ReadNameTable(position, field_count, hash_width, names_width, 1, names_size);
        if (long_names) {
            if (field_count + long_count > 255 && field_id_width == 1) {
                Fail(ProtocolErrorKind::UNSUPPORTED, "has field names over 255 bytes that push the field count past one byte");
            }
            position = ReadNameTable(position, long_count, 2, long_offset_width, 2, long_names_size);
        }
        SetTree(position, tree_size);
    }

    void SetTree(size_t position, uint64_t tree_size) {
        Need(position, static_cast<size_t>(tree_size), "its tree");
        if (tree_size == 0) {
            Fail(ProtocolErrorKind::MALFORMED, "has an empty tree");
        }
        tree = data + position;
        tree_bytes = static_cast<size_t>(tree_size);
    }

    void TreeNeed(uint64_t position, uint64_t length, const char *what) const {
        if (position > tree_bytes || length > tree_bytes - position) {
            Fail(ProtocolErrorKind::MALFORMED, std::string("has a node running past its tree in ") + what);
        }
    }

    void Append(const char *text, size_t length) {
        if (length > limits.maximum_output_bytes - output.size()) {
            Fail(ProtocolErrorKind::LIMIT_EXCEEDED, "expands past the JSON output limit");
        }
        output.append(text, length);
    }
    void Append(const std::string &text) {
        Append(text.data(), text.size());
    }
    void Append(char character) {
        Append(&character, 1);
    }

    void AppendEscaped(const uint8_t *text, size_t length) {
        if (!IsValidUtf8(text, length)) {
            Fail(ProtocolErrorKind::MALFORMED, "has a string that is not UTF-8");
        }
        Append('"');
        size_t run = 0;
        const auto flush = [&](size_t end) {
            if (end > run) {
                Append(reinterpret_cast<const char *>(text) + run, end - run);
            }
        };
        for (size_t index = 0; index < length; index++) {
            const uint8_t byte = text[index];
            const char *replacement = nullptr;
            char control[8];
            if (byte == '"') {
                replacement = "\\\"";
            } else if (byte == '\\') {
                replacement = "\\\\";
            } else if (byte == '\n') {
                replacement = "\\n";
            } else if (byte == '\r') {
                replacement = "\\r";
            } else if (byte == '\t') {
                replacement = "\\t";
            } else if (byte == '\b') {
                replacement = "\\b";
            } else if (byte == '\f') {
                replacement = "\\f";
            } else if (byte < 0x20) {
                std::snprintf(control, sizeof(control), "\\u%04x", byte);
                replacement = control;
            }
            if (replacement != nullptr) {
                flush(index);
                Append(replacement, std::strlen(replacement));
                run = index + 1;
            }
        }
        flush(length);
        Append('"');
    }

    // A NUMBER as JSON. DecodeOracleNumber writes every digit in place, which
    // for 1E-130 or 1E+100 is a hundred zeros; those go to exponent form, the
    // way Oracle prints them. Anything within a sensible span stays plain.
    static std::string NumberText(const std::string &plain) {
        size_t start = !plain.empty() && plain[0] == '-' ? 1 : 0;
        std::string digits;
        int64_t point = -1;
        for (size_t index = start; index < plain.size(); index++) {
            if (plain[index] == '.') {
                point = static_cast<int64_t>(digits.size());
            } else {
                digits.push_back(plain[index]);
            }
        }
        if (point < 0) {
            point = static_cast<int64_t>(digits.size());
        }
        const auto first = digits.find_first_not_of('0');
        if (first == std::string::npos) {
            return "0";
        }
        const int64_t exponent = point - static_cast<int64_t>(first) - 1;
        if (exponent >= -20 && exponent <= 40) {
            return plain;
        }
        std::string mantissa = digits.substr(first);
        while (mantissa.size() > 1 && mantissa.back() == '0') {
            mantissa.pop_back();
        }
        std::string text = plain.substr(0, start) + mantissa.substr(0, 1);
        if (mantissa.size() > 1) {
            text += "." + mantissa.substr(1);
        }
        return text + "E" + (exponent < 0 ? "-" : "+") + std::to_string(exponent < 0 ? -exponent : exponent);
    }

    static std::string FloatingText(double value, bool single) {
        if (std::isnan(value)) {
            return "\"Nan\"";
        }
        if (std::isinf(value)) {
            return value < 0 ? "\"-Inf\"" : "\"Inf\"";
        }
        char text[40];
        for (int precision = single ? 6 : 15; precision <= (single ? 9 : 17); precision++) {
            std::snprintf(text, sizeof(text), "%.*g", precision, value);
            const double back = single ? static_cast<double>(std::strtof(text, nullptr)) : std::strtod(text, nullptr);
            if (back == value) {
                break;
            }
        }
        return text;
    }

    // A vector inside a document is its elements as an array, the way the
    // server prints it; a sparse one is `[dimensions,[indices],[values]]`.
    static std::string VectorText(const OracleVector &vector) {
        std::string text;
        const auto elements = [&](const char *separator) {
            std::string list = "[";
            bool first = true;
            const auto add = [&](const std::string &element) {
                list += (first ? "" : separator) + element;
                first = false;
            };
            switch (vector.format) {
            case ORACLE_VECTOR_FLOAT32:
                for (const auto element : vector.float32) {
                    add(FloatingText(static_cast<double>(element), true));
                }
                break;
            case ORACLE_VECTOR_FLOAT64:
                for (const auto element : vector.float64) {
                    add(FloatingText(element, false));
                }
                break;
            case ORACLE_VECTOR_INT8:
                for (const auto element : vector.int8) {
                    add(std::to_string(element));
                }
                break;
            default:
                for (const auto element : vector.binary) {
                    add(std::to_string(element));
                }
                break;
            }
            return list + "]";
        };
        if (!vector.sparse) {
            return elements(",");
        }
        // [dimensions,[indices],[values]]
        std::string indices = "[";
        for (size_t index = 0; index < vector.indices.size(); index++) {
            indices += (index == 0 ? "" : ",") + std::to_string(vector.indices[index]);
        }
        indices += "]";
        return "[" + std::to_string(vector.dimensions) + "," + indices + "," + elements(",") + "]";
    }

    static std::string Pad(int64_t value, int width) {
        char text[32];
        std::snprintf(text, sizeof(text), "%0*" PRId64, width, value);
        return text;
    }

    static std::string FractionText(uint32_t nanoseconds) {
        if (nanoseconds == 0) {
            return std::string();
        }
        return "." + (nanoseconds % 1000 == 0 ? Pad(nanoseconds / 1000, 6) : Pad(nanoseconds, 9));
    }

    static std::string DateTimeText(const OracleDateTime &value, bool fraction) {
        return Pad(value.year, 4) + "-" + Pad(value.month, 2) + "-" + Pad(value.day, 2) + "T" + Pad(value.hour, 2) +
               ":" + Pad(value.minute, 2) + ":" + Pad(value.second, 2) + (fraction ? FractionText(value.nanosecond) : "");
    }

    // A TIMESTAMP WITH TIME ZONE is stored as UTC plus the zone's offset, and
    // printed in the zone it was written in.
    static std::string ZonedText(OracleDateTime value) {
        value = OracleZonedWallClock(value);
        const int offset = value.offset_minutes;
        const int magnitude = offset < 0 ? -offset : offset;
        return DateTimeText(value, true) + (offset < 0 ? "-" : "+") + Pad(magnitude / 60, 2) + ":" + Pad(magnitude % 60, 2);
    }

    static std::string HexText(const uint8_t *data_p, size_t length) {
        static const char digits[] = "0123456789ABCDEF";
        std::string text;
        text.reserve(length * 2);
        for (size_t index = 0; index < length; index++) {
            text.push_back(digits[data_p[index] >> 4U]);
            text.push_back(digits[data_p[index] & 0x0FU]);
        }
        return text;
    }

    void Scalar(uint64_t offset, uint8_t type) {
        const uint8_t *node = tree + offset;
        const auto number = [&](size_t length, size_t header) {
            TreeNeed(offset, header + length, "a NUMBER");
            Append(NumberText(DecodeOracleNumber(std::vector<uint8_t>(node + header, node + header + length))));
        };
        const auto fixed = [&](size_t length, const char *what) {
            TreeNeed(offset, 1 + length, what);
            return std::vector<uint8_t>(node + 1, node + 1 + length);
        };
        if (type < 0x20) {
            TreeNeed(offset, 1 + static_cast<size_t>(type), "a string");
            AppendEscaped(node + 1, type);
            return;
        }
        if (type >= 0x20 && type < 0x30) {
            number(static_cast<size_t>(type & 0x0FU) + 1, 1);
            return;
        }
        switch (type) {
        case NODE_NULL:
            Append("null", 4);
            return;
        case NODE_TRUE:
            Append("true", 4);
            return;
        case NODE_FALSE:
            Append("false", 5);
            return;
        case NODE_STRING_UINT8: {
            TreeNeed(offset, 2, "a string length");
            const size_t length = node[1];
            TreeNeed(offset, 2 + length, "a string");
            AppendEscaped(node + 2, length);
            return;
        }
        case NODE_STRING_UINT16: {
            TreeNeed(offset, 3, "a string length");
            const size_t length = ReadBigEndian(node + 1, 2);
            TreeNeed(offset, 3 + length, "a string");
            AppendEscaped(node + 3, length);
            return;
        }
        case NODE_STRING_UINT32: {
            TreeNeed(offset, 5, "a string length");
            const uint64_t length = ReadBigEndian(node + 1, 4);
            TreeNeed(offset, 5 + length, "a string");
            AppendEscaped(node + 5, static_cast<size_t>(length));
            return;
        }
        case NODE_NUMBER_UINT8: {
            TreeNeed(offset, 2, "a NUMBER length");
            number(node[1], 2);
            return;
        }
        case NODE_BINARY_UINT16: {
            TreeNeed(offset, 3, "a binary length");
            const size_t length = ReadBigEndian(node + 1, 2);
            TreeNeed(offset, 3 + length, "a binary value");
            Append("\"" + HexText(node + 3, length) + "\"");
            return;
        }
        case NODE_BINARY_UINT32: {
            TreeNeed(offset, 5, "a binary length");
            const uint64_t length = ReadBigEndian(node + 1, 4);
            TreeNeed(offset, 5 + length, "a binary value");
            Append("\"" + HexText(node + 5, static_cast<size_t>(length)) + "\"");
            return;
        }
        case NODE_BINARY_DOUBLE:
            Append(FloatingText(DecodeOracleBinaryDouble(fixed(8, "a BINARY_DOUBLE")), false));
            return;
        case NODE_BINARY_FLOAT:
            Append(FloatingText(static_cast<double>(DecodeOracleBinaryFloat(fixed(4, "a BINARY_FLOAT"))), true));
            return;
        case NODE_EXTENDED: {
            // 0x7B, a subtype byte (1: a VECTOR), a 4-byte length and that many
            // bytes of the value's own image.
            TreeNeed(offset, 6, "an extended value");
            const uint64_t length = ReadBigEndian(node + 2, 4);
            TreeNeed(offset, 6 + length, "an extended value");
            if (node[1] != 1) {
                Fail(ProtocolErrorKind::UNSUPPORTED, "has an extended node of subtype " + std::to_string(node[1]) +
                                                         ", which this decoder has not been shown");
            }
            Append(VectorText(DecodeOracleVector(node + 6, static_cast<size_t>(length))));
            return;
        }
        case NODE_DATE:
            Append("\"" + DateTimeText(DecodeOracleDate(fixed(7, "a DATE")), false) + "\"");
            return;
        case NODE_TIMESTAMP_NO_FRACTION:
            Append("\"" + DateTimeText(DecodeOracleTimestamp(fixed(7, "a TIMESTAMP")), false) + "\"");
            return;
        case NODE_TIMESTAMP:
            Append("\"" + DateTimeText(DecodeOracleTimestamp(fixed(11, "a TIMESTAMP")), true) + "\"");
            return;
        case NODE_TIMESTAMP_TZ:
            Append("\"" + ZonedText(DecodeOracleTimestamp(fixed(13, "a TIMESTAMP WITH TIME ZONE"))) + "\"");
            return;
        case NODE_INTERVAL_YM: {
            const auto months = DecodeOracleIntervalYearMonth(fixed(5, "an INTERVAL YEAR TO MONTH")).months;
            const auto magnitude = months < 0 ? -months : months;
            Append(std::string("\"") + (months < 0 ? "-" : "") + "P" + std::to_string(magnitude / 12) + "Y" +
                   std::to_string(magnitude % 12) + "M\"");
            return;
        }
        case NODE_INTERVAL_DS: {
            const auto value = DecodeOracleIntervalDaySecond(fixed(11, "an INTERVAL DAY TO SECOND"));
            const bool negative = value.days < 0 || value.nanoseconds < 0;
            const int64_t days = value.days < 0 ? -static_cast<int64_t>(value.days) : value.days;
            int64_t nanoseconds = value.nanoseconds < 0 ? -value.nanoseconds : value.nanoseconds;
            const int64_t hours = nanoseconds / 3600000000000LL;
            nanoseconds %= 3600000000000LL;
            const int64_t minutes = nanoseconds / 60000000000LL;
            nanoseconds %= 60000000000LL;
            const int64_t seconds = nanoseconds / 1000000000LL;
            const auto fraction = static_cast<uint32_t>(nanoseconds % 1000000000LL);
            Append(std::string("\"") + (negative ? "-" : "") + "P" + std::to_string(days) + "DT" + std::to_string(hours) +
                   "H" + std::to_string(minutes) + "M" + std::to_string(seconds) +
                   (fraction != 0 ? FractionText(fraction) : std::string()) + "S\"");
            return;
        }
        default: {
            char text[8];
            std::snprintf(text, sizeof(text), "0x%02x", type);
            Fail(ProtocolErrorKind::UNSUPPORTED, std::string("has a node of type ") + text + ", which this decoder has not been shown");
        }
        }
    }

    // The count and field numbers of the object at `reference`, following a
    // chain of objects that share their list with another. The chain is bounded
    // so a loop cannot hold the decoder.
    void ResolveFieldList(uint64_t reference, uint64_t &count, const uint8_t *&ids) const {
        for (int hops = 0; hops < 16; hops++) {
            TreeNeed(reference, 1, "a shared field list");
            const uint8_t type = tree[reference];
            if ((type & 0xC0U) != 0x80U) {
                Fail(ProtocolErrorKind::MALFORMED, "shares field numbers with a node that is not an object");
            }
            const size_t offset_width = (type & 0x20U) != 0 ? 4 : 2;
            uint64_t position = reference + 1;
            const unsigned count_kind = (type >> 3U) & 3U;
            if (count_kind == 3) {
                TreeNeed(position, offset_width, "a shared field list");
                reference = ReadBigEndian(tree + position, offset_width);
                continue;
            }
            const size_t count_width = count_kind == 2 ? 4 : count_kind == 1 ? 2 : 1;
            TreeNeed(position, count_width, "a child count");
            count = ReadBigEndian(tree + position, count_width);
            position += count_width;
            if (count > tree_bytes || count * field_id_width > tree_bytes - position) {
                Fail(ProtocolErrorKind::MALFORMED, "has a shared field list longer than its tree");
            }
            ids = tree + position;
            return;
        }
        Fail(ProtocolErrorKind::MALFORMED, "chains shared field lists too deeply");
    }

    void Node(uint64_t offset, uint32_t depth) {
        if (depth > limits.maximum_depth) {
            Fail(ProtocolErrorKind::LIMIT_EXCEEDED, "nests deeper than the depth limit");
        }
        if (++nodes > limits.maximum_nodes) {
            Fail(ProtocolErrorKind::LIMIT_EXCEEDED, "has more nodes than the node limit");
        }
        TreeNeed(offset, 1, "a node type");
        const uint8_t type = tree[offset];
        if ((type & 0x80U) == 0) {
            Scalar(offset, type);
            return;
        }
        const bool is_array = (type & 0x40U) != 0;
        const size_t offset_width = (type & 0x20U) != 0 ? 4 : 2;
        uint64_t position = offset + 1;
        uint64_t count;
        const uint8_t *ids = nullptr;
        const size_t id_width = is_array ? 0 : field_id_width;
        const unsigned count_kind = (type >> 3U) & 3U;
        if (count_kind == 3) {
            // An object with the same fields as one already in the tree names
            // that object instead of repeating the count and the field numbers.
            if (is_array) {
                Fail(ProtocolErrorKind::MALFORMED, "has an array that shares field numbers");
            }
            TreeNeed(position, offset_width, "a shared field list");
            const auto reference = ReadBigEndian(tree + position, offset_width);
            position += offset_width;
            ResolveFieldList(reference, count, ids);
        } else {
            const size_t count_width = count_kind == 2 ? 4 : count_kind == 1 ? 2 : 1;
            TreeNeed(position, count_width, "a child count");
            count = ReadBigEndian(tree + position, count_width);
            position += count_width;
            if (count > tree_bytes || count * id_width > tree_bytes - position) {
                Fail(ProtocolErrorKind::MALFORMED, "has a container with more children than its tree can hold");
            }
            ids = tree + position;
            position += count * id_width;
        }
        if (count > tree_bytes || count * offset_width > tree_bytes - position) {
            Fail(ProtocolErrorKind::MALFORMED, "has a container with more children than its tree can hold");
        }
        const uint8_t *offsets = tree + position;
        Append(is_array ? '[' : '{');
        for (uint64_t index = 0; index < count; index++) {
            if (index != 0) {
                Append(',');
            }
            if (!is_array) {
                const auto id = ReadBigEndian(ids + index * id_width, id_width);
                if (id == 0 || id > field_names.size()) {
                    Fail(ProtocolErrorKind::MALFORMED, "names a field that is not in its name table");
                }
                const auto &name = field_names[static_cast<size_t>(id - 1)];
                AppendEscaped(reinterpret_cast<const uint8_t *>(name.data()), name.size());
                Append(':');
            }
            Node(ReadBigEndian(offsets + index * offset_width, offset_width), depth + 1);
        }
        Append(is_array ? ']' : '}');
    }

    const uint8_t *data;
    size_t size;
    OsonLimits limits;
    const uint8_t *tree = nullptr;
    size_t tree_bytes = 0;
    size_t field_id_width = 1;
    std::vector<std::string> field_names;
    uint64_t nodes = 0;
    std::string output;
};

} // namespace

std::string DecodeOsonToJson(const uint8_t *data, size_t size, const OsonLimits &limits) {
    return OsonDecoder(data, size, limits).Decode();
}

std::string DecodeOsonToJson(const std::vector<uint8_t> &image, const OsonLimits &limits) {
    return DecodeOsonToJson(image.data(), image.size(), limits);
}

} // namespace oracle_scanner

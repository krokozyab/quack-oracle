#include "oracle_scanner/value_codec.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>
#include <string>

namespace oracle_scanner {

static bool IsLeapYear(int32_t year) {
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static uint8_t DaysInMonth(int32_t year, uint8_t month) {
    static constexpr uint8_t days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month == 2 && IsLeapYear(year)) {
        return 29;
    }
    return days[month - 1];
}

static void ValidateDateTime(const OracleDateTime &value) {
    if (value.year < -4712 || value.year > 9999 || value.month < 1 || value.month > 12 || value.day < 1 ||
        value.day > DaysInMonth(value.year, value.month) || value.hour > 23 || value.minute > 59 ||
        value.second > 59 || value.nanosecond >= 1000000000U) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "invalid Oracle date/time fields");
    }
    if (value.has_offset && (value.offset_minutes < -15 * 60 || value.offset_minutes > 15 * 60)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle time-zone offset is outside +/-15 hours");
    }
}

std::vector<uint8_t> EncodeOracleDate(const OracleDateTime &value) {
    ValidateDateTime(value);
    auto century = value.year / 100;
    auto year_in_century = value.year - century * 100;
    return {static_cast<uint8_t>(century + 100), static_cast<uint8_t>(year_in_century + 100), value.month,
            value.day, static_cast<uint8_t>(value.hour + 1), static_cast<uint8_t>(value.minute + 1),
            static_cast<uint8_t>(value.second + 1)};
}

OracleDateTime DecodeOracleDate(const std::vector<uint8_t> &wire) {
    if (wire.size() != 7) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle DATE must contain exactly 7 bytes");
    }
    OracleDateTime result;
    result.year = (static_cast<int32_t>(wire[0]) - 100) * 100 + static_cast<int32_t>(wire[1]) - 100;
    result.month = wire[2];
    result.day = wire[3];
    if (wire[4] == 0 || wire[5] == 0 || wire[6] == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle DATE time fields have invalid bias");
    }
    result.hour = static_cast<uint8_t>(wire[4] - 1);
    result.minute = static_cast<uint8_t>(wire[5] - 1);
    result.second = static_cast<uint8_t>(wire[6] - 1);
    ValidateDateTime(result);
    return result;
}

std::vector<uint8_t> EncodeOracleTimestamp(const OracleDateTime &value, bool with_time_zone) {
    ValidateDateTime(value);
    if (with_time_zone && !value.has_offset) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "timestamp with time zone requires an offset");
    }
    auto result = EncodeOracleDate(value);
    result.push_back(static_cast<uint8_t>(value.nanosecond >> 24U));
    result.push_back(static_cast<uint8_t>(value.nanosecond >> 16U));
    result.push_back(static_cast<uint8_t>(value.nanosecond >> 8U));
    result.push_back(static_cast<uint8_t>(value.nanosecond));
    if (with_time_zone) {
        auto hours = value.offset_minutes / 60;
        auto minutes = value.offset_minutes - hours * 60;
        result.push_back(static_cast<uint8_t>(hours + 20));
        result.push_back(static_cast<uint8_t>(minutes + 60));
    }
    return result;
}

OracleDateTime DecodeOracleTimestamp(const std::vector<uint8_t> &wire) {
    if (wire.size() != 7 && wire.size() != 11 && wire.size() != 13) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle TIMESTAMP must contain 7, 11, or 13 bytes");
    }
    auto result = DecodeOracleDate(std::vector<uint8_t>(wire.begin(), wire.begin() + 7));
    if (wire.size() >= 11) {
        result.nanosecond = (static_cast<uint32_t>(wire[7]) << 24U) | (static_cast<uint32_t>(wire[8]) << 16U) |
                            (static_cast<uint32_t>(wire[9]) << 8U) | wire[10];
    }
    if (wire.size() == 13) {
        if ((wire[11] & 0x80U) != 0) {
            throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "Oracle named time-zone regions are not supported");
        }
        auto hour = static_cast<int16_t>(wire[11] & ~uint8_t(0x40U)) - 20;
        auto minute = static_cast<int16_t>(wire[12]) - 60;
        result.offset_minutes = static_cast<int16_t>(hour * 60 + minute);
        result.has_offset = true;
    }
    ValidateDateTime(result);
    return result;
}

template <class FLOAT, class INTEGER>
static std::vector<uint8_t> EncodeBinary(FLOAT value) {
    INTEGER bits;
    std::memcpy(&bits, &value, sizeof(bits));
    std::vector<uint8_t> result(sizeof(bits));
    for (size_t index = 0; index < sizeof(bits); index++) {
        result[index] = static_cast<uint8_t>(bits >> ((sizeof(bits) - index - 1) * 8U));
    }
    if ((result[0] & 0x80U) == 0) {
        result[0] |= 0x80U;
    } else {
        for (auto &byte : result) {
            byte = static_cast<uint8_t>(~byte);
        }
    }
    return result;
}

template <class FLOAT, class INTEGER>
static FLOAT DecodeBinary(const std::vector<uint8_t> &wire) {
    if (wire.size() != sizeof(INTEGER)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle binary floating-point value has wrong size");
    }
    auto bytes = wire;
    if ((bytes[0] & 0x80U) != 0) {
        bytes[0] &= 0x7fU;
    } else {
        for (auto &byte : bytes) {
            byte = static_cast<uint8_t>(~byte);
        }
    }
    INTEGER bits = 0;
    for (auto byte : bytes) {
        bits = static_cast<INTEGER>((bits << 8U) | byte);
    }
    FLOAT result;
    std::memcpy(&result, &bits, sizeof(result));
    return result;
}

std::vector<uint8_t> EncodeOracleBinaryFloat(float value) {
    return EncodeBinary<float, uint32_t>(value);
}

std::vector<uint8_t> EncodeOracleBinaryDouble(double value) {
    return EncodeBinary<double, uint64_t>(value);
}

float DecodeOracleBinaryFloat(const std::vector<uint8_t> &wire) {
    return DecodeBinary<float, uint32_t>(wire);
}

double DecodeOracleBinaryDouble(const std::vector<uint8_t> &wire) {
    return DecodeBinary<double, uint64_t>(wire);
}

static int64_t ParseExponent(const std::string &text, size_t &position) {
    if (position == text.size()) {
        return 0;
    }
    if (text[position] != 'e' && text[position] != 'E') {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "invalid character in Oracle NUMBER text");
    }
    position++;
    bool negative = false;
    if (position < text.size() && (text[position] == '+' || text[position] == '-')) {
        negative = text[position++] == '-';
    }
    if (position == text.size() || !std::isdigit(static_cast<unsigned char>(text[position]))) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle NUMBER exponent has no digits");
    }
    int64_t result = 0;
    while (position < text.size() && std::isdigit(static_cast<unsigned char>(text[position]))) {
        auto digit = text[position++] - '0';
        if (result > 100000) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle NUMBER exponent is too large");
        }
        result = result * 10 + digit;
    }
    if (position != text.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "invalid character after Oracle NUMBER exponent");
    }
    return negative ? -result : result;
}

static int64_t FloorDivideByTwo(int64_t value) {
    return value >= 0 ? value / 2 : -((-value + 1) / 2);
}

std::vector<uint8_t> EncodeOracleNumber(const std::string &decimal) {
    if (decimal.empty() || decimal.size() > 256) {
        throw ProtocolError(decimal.empty() ? ProtocolErrorKind::MALFORMED : ProtocolErrorKind::LIMIT_EXCEEDED,
                            "Oracle NUMBER text has an invalid size");
    }
    size_t position = 0;
    bool negative = false;
    if (decimal[position] == '+' || decimal[position] == '-') {
        negative = decimal[position++] == '-';
    }
    std::string digits;
    int64_t decimal_position = 0;
    bool saw_point = false;
    while (position < decimal.size() && decimal[position] != 'e' && decimal[position] != 'E') {
        auto character = decimal[position++];
        if (character == '.') {
            if (saw_point) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle NUMBER text has multiple decimal points");
            }
            saw_point = true;
            decimal_position = static_cast<int64_t>(digits.size());
        } else if (std::isdigit(static_cast<unsigned char>(character))) {
            digits.push_back(character);
        } else {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "invalid character in Oracle NUMBER text");
        }
    }
    if (!saw_point) {
        decimal_position = static_cast<int64_t>(digits.size());
    }
    if (digits.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle NUMBER text has no digits");
    }
    decimal_position += ParseExponent(decimal, position);

    const auto first_nonzero = digits.find_first_not_of('0');
    if (first_nonzero == std::string::npos) {
        return {0x80};
    }
    decimal_position -= static_cast<int64_t>(first_nonzero);
    digits.erase(0, first_nonzero);
    while (!digits.empty() && digits.back() == '0') {
        digits.pop_back();
    }

    const int64_t highest_power_ten = decimal_position - 1;
    const int64_t exponent_100 = FloorDivideByTwo(highest_power_ten);
    if (exponent_100 < -65 || exponent_100 > 62) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle NUMBER exponent is outside its wire range");
    }
    const size_t first_width = static_cast<size_t>(highest_power_ten - exponent_100 * 2 + 1);
    std::vector<uint8_t> groups;
    size_t digit_offset = 0;
    size_t width = first_width;
    while (digit_offset < digits.size()) {
        uint8_t group = static_cast<uint8_t>(digits[digit_offset++] - '0');
        if (width == 2) {
            group = static_cast<uint8_t>(group * 10);
            if (digit_offset < digits.size()) {
                group = static_cast<uint8_t>(group + digits[digit_offset++] - '0');
            }
        }
        groups.push_back(group);
        width = 2;
    }
    while (!groups.empty() && groups.back() == 0) {
        groups.pop_back();
    }
    if (groups.empty() || groups.size() > 20) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle NUMBER exceeds 40 decimal digits");
    }

    std::vector<uint8_t> result;
    result.reserve(groups.size() + 2);
    result.push_back(static_cast<uint8_t>(negative ? 62 - exponent_100 : exponent_100 + 193));
    for (auto group : groups) {
        result.push_back(static_cast<uint8_t>(negative ? 101 - group : group + 1));
    }
    if (negative && result.size() < 21) {
        result.push_back(102);
    }
    return result;
}

std::string DecodeOracleNumber(const std::vector<uint8_t> &wire) {
    if (wire.empty() || wire.size() > 21) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle NUMBER wire value has an invalid size");
    }
    if (wire.size() == 1 && wire[0] == 0x80) {
        return "0";
    }
    const bool negative = wire[0] < 0x80;
    const int64_t exponent_100 = negative ? 62 - wire[0] : static_cast<int64_t>(wire[0]) - 193;
    if (exponent_100 < -65 || exponent_100 > 62 || wire.size() == 1) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle NUMBER exponent or mantissa is invalid");
    }
    size_t end = wire.size();
    if (negative && wire.back() == 102) {
        end--;
    }
    if (end == 1) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle NUMBER mantissa is empty");
    }
    std::vector<uint8_t> groups;
    for (size_t index = 1; index < end; index++) {
        const int value = negative ? 101 - wire[index] : wire[index] - 1;
        if (value < 0 || value > 99 || (index + 1 == end && value == 0)) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle NUMBER contains an invalid base-100 digit");
        }
        groups.push_back(static_cast<uint8_t>(value));
    }

    std::string digits = std::to_string(groups[0]);
    for (size_t index = 1; index < groups.size(); index++) {
        digits.push_back(static_cast<char>('0' + groups[index] / 10));
        digits.push_back(static_cast<char>('0' + groups[index] % 10));
    }
    const int64_t decimal_position = static_cast<int64_t>(std::to_string(groups[0]).size()) + exponent_100 * 2;
    std::string result;
    if (decimal_position <= 0) {
        result = "0." + std::string(static_cast<size_t>(-decimal_position), '0') + digits;
    } else if (decimal_position >= static_cast<int64_t>(digits.size())) {
        result = digits + std::string(static_cast<size_t>(decimal_position - digits.size()), '0');
    } else {
        result = digits.substr(0, static_cast<size_t>(decimal_position)) + "." +
                 digits.substr(static_cast<size_t>(decimal_position));
    }
    if (result.find('.') != std::string::npos) {
        while (result.back() == '0') {
            result.pop_back();
        }
        if (result.back() == '.') {
            result.pop_back();
        }
    }
    return negative ? "-" + result : result;
}

} // namespace oracle_scanner

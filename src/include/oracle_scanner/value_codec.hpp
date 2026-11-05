#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace oracle_scanner {

struct OracleDateTime {
    int32_t year = 1970;
    uint8_t month = 1;
    uint8_t day = 1;
    uint8_t hour = 0;
    uint8_t minute = 0;
    uint8_t second = 0;
    uint32_t nanosecond = 0;
    int16_t offset_minutes = 0;
    bool has_offset = false;
};

std::vector<uint8_t> EncodeOracleDate(const OracleDateTime &value);
OracleDateTime DecodeOracleDate(const std::vector<uint8_t> &wire);
std::vector<uint8_t> EncodeOracleTimestamp(const OracleDateTime &value, bool with_time_zone);
OracleDateTime DecodeOracleTimestamp(const std::vector<uint8_t> &wire);

// A TIMESTAMP WITH TIME ZONE carries its date and time as UTC with the offset
// beside them (captured from 19c: 05:06:07 at +04:00 arrives as 01:06:07), so
// the decoded fields are UTC. This is the same instant on the wall clock of
// that offset, which is how Oracle prints it. A value with no offset is
// returned unchanged.
OracleDateTime OracleZonedWallClock(const OracleDateTime &utc);

std::vector<uint8_t> EncodeOracleBinaryFloat(float value);
std::vector<uint8_t> EncodeOracleBinaryDouble(double value);
float DecodeOracleBinaryFloat(const std::vector<uint8_t> &wire);
double DecodeOracleBinaryDouble(const std::vector<uint8_t> &wire);

// Converts through decimal text so Oracle NUMBER values never pass through a
// binary floating-point representation. The encoder accepts ordinary or
// scientific decimal notation and emits the canonical base-100 wire form.
std::vector<uint8_t> EncodeOracleNumber(const std::string &decimal);
std::string DecodeOracleNumber(const std::vector<uint8_t> &wire);

// The same value as an integer, without the text: present only when the wire
// form is well formed, holds a whole number and fits int64_t. A caller falls
// back to DecodeOracleNumber for everything else, which is also where a
// malformed value is reported.
std::optional<int64_t> TryDecodeOracleInteger(const std::vector<uint8_t> &wire);

// INTERVAL YEAR TO MONTH is 5 bytes: the year as a big-endian uint32 offset by
// 0x80000000 and the month plus 60. INTERVAL DAY TO SECOND is 11: the day in the
// same form, then hour, minute and second each plus 60, then the fractional
// seconds as nanoseconds in the same offset form. Both signs ride on every
// component, so -5-11 is year -5 and month -11. Captured from 19c and Free.
struct OracleIntervalYearMonth {
    int64_t months = 0;
};
struct OracleIntervalDaySecond {
    int32_t days = 0;
    // The hours, minutes, seconds and fraction as one signed count of nanoseconds.
    int64_t nanoseconds = 0;
};
std::vector<uint8_t> EncodeOracleIntervalYearMonth(int32_t years, int32_t months);
OracleIntervalYearMonth DecodeOracleIntervalYearMonth(const std::vector<uint8_t> &wire);
std::vector<uint8_t> EncodeOracleIntervalDaySecond(int32_t days, int32_t hours, int32_t minutes, int32_t seconds,
                                                   int32_t nanoseconds);
OracleIntervalDaySecond DecodeOracleIntervalDaySecond(const std::vector<uint8_t> &wire);

// A ROWID as the 18 characters Oracle itself prints (ROWIDTOCHAR): data object,
// file, block and row in the base-64 alphabet A-Za-z0-9+/. The input is the twelve
// bytes of a physical rowid (4 for the data object, 2 for the file, 4 for the
// block, 2 for the row, all big-endian), or the thirteen of a UROWID whose first
// byte is 1.
// A logical UROWID, which an index-organized table has, is not decoded and
// yields no value.
std::optional<std::string> TryDecodeOracleRowid(const std::vector<uint8_t> &wire);

} // namespace oracle_scanner

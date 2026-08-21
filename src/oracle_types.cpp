// Oracle-to-DuckDB value and type conversion. The support policy lives here:
// a column this client cannot read is refused rather than decoded into
// something wrong, and both the table functions and the attached catalog go
// through it.

#include "oracle_adapter.hpp"

#include "duckdb/common/exception/conversion_exception.hpp"
#include "duckdb/common/types/time.hpp"

#include <cstdlib>
#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>

namespace duckdb {

// An Oracle type this client cannot read must be refused while binding, before
// any fetch, rather than decoded into something wrong. Without this every
// unmapped type fell through to the textual default and produced garbage: the
// live 19c matrix showed NCHAR and NVARCHAR2 emitting their UTF-16 bytes as if
// they were UTF-8, INTERVAL YEAR TO MONTH and DAY TO SECOND emitting binary
// that DuckDB then rejected as invalid unicode, and LOB columns failing much
// later with an opaque wire error. Each rejection below names what was found
// and why it is not supported, so the message is actionable.
void RequireReadableColumn(const OracleColumn &column) {
    const auto refuse = [&](const std::string &reason) {
        throw NotImplementedException("Oracle column \"%s\" cannot be read: %s", column.name, reason);
    };
    // NCHAR, NVARCHAR2 and NCLOB share their type codes with the database
    // character set forms and differ only here.
    if (column.character_set_form == 2 && column.oracle_type != 112) {
        refuse("national character set values (NCHAR, NVARCHAR2) are UTF-16 on the wire and are not decoded");
    }
    switch (column.oracle_type) {
    case 1:   // VARCHAR2
    case 2:   // NUMBER
    case 12:  // DATE
    case 23:  // RAW
    case 96:  // CHAR
    case 100: // BINARY_FLOAT
    case 101: // BINARY_DOUBLE
    case 180: // TIMESTAMP
        return;
    case 181: // TIMESTAMP WITH TIME ZONE
        // Readable because the value carries its own offset; nothing has to be
        // assumed about a session zone.
        return;
    case 231:
        refuse("TIMESTAMP WITH LOCAL TIME ZONE is relative to a session time zone this client does not negotiate");
        break;
    case 112: // CLOB
    case 113: // BLOB
        // The value in the row is a locator, not content; the fetch resolves it
        // through LOB_OP before the row ever reaches this layer, so by the time
        // a value is converted a LOB is bytes like any other.
        return;
    case 182:
    case 183:
        refuse("INTERVAL values have no decoder yet");
        break;
    default:
        break;
    }
    refuse("Oracle type " + std::to_string(column.oracle_type) + " has no mapping in this version");
}

// The DuckDB type an Oracle column maps to, with no support check. Only the
// attached catalog uses this directly, so that a table carrying a column this
// version cannot read is still listed; reading it goes through TypeFor and is
// refused there.
LogicalType MappedType(const OracleColumn &column) {
    switch (column.oracle_type) {
    case 2: // NUMBER
        // Only integral NUMBER values with a representable declared precision
        // are widened. Unconstrained and fractional NUMBER stay textual so no
        // Oracle value is rounded or silently narrowed.
        if (column.scale == 0 && column.precision >= 1 && column.precision <= 18) {
            return LogicalType::BIGINT;
        }
        if (column.precision >= 1 && column.precision <= 38 && column.scale >= 1 && column.scale <= column.precision) {
            return LogicalType::DECIMAL(static_cast<uint8_t>(column.precision), static_cast<uint8_t>(column.scale));
        }
        return LogicalType::VARCHAR;
    case 23:  // RAW
    case 113: // BLOB
        return LogicalType::BLOB;
    case 112: // CLOB
        // A CLOB read comes back as the session's character set, which this
        // client negotiates as UTF-8 — the same bytes a VARCHAR2 arrives in.
        return LogicalType::VARCHAR;
    case 100: // BINARY_FLOAT
        return LogicalType::FLOAT;
    case 101: // BINARY_DOUBLE
        return LogicalType::DOUBLE;
    case 12:
        // An Oracle DATE is a date *and* a time to the second, never just a
        // date, so DuckDB's DATE would silently drop half of it.
        return LogicalType::TIMESTAMP;
    case 180:
        // The declared fractional-seconds precision decides the resolution.
        // DuckDB's microsecond TIMESTAMP cannot hold a TIMESTAMP(7..9), and
        // its nanosecond type only spans 1677..2262, so neither is right for
        // every column and the column itself has to say which.
        return column.scale > 6 ? LogicalType::TIMESTAMP_NS : LogicalType::TIMESTAMP;
    default:
        // NUMBER remains decimal text until its precision/scale mapping is
        // complete; this preserves every Oracle value rather than rounding it.
        // TIMESTAMP WITH TIME ZONE stays textual because it carries an offset
        // that DuckDB's TIMESTAMPTZ, an instant in UTC, does not keep.
        return LogicalType::VARCHAR;
    }
}

// Refuses any column this client cannot read, so no caller maps an unsupported
// type by accident, then returns its DuckDB type.
LogicalType TypeFor(const OracleColumn &column) {
    RequireReadableColumn(column);
    return MappedType(column);
}

std::string FormatDateTime(const oracle_scanner::OracleDateTime &value) {
    std::ostringstream result;
    result << std::setfill('0') << std::setw(4) << value.year << '-' << std::setw(2)
           << static_cast<unsigned>(value.month) << '-' << std::setw(2) << static_cast<unsigned>(value.day) << ' '
           << std::setw(2) << static_cast<unsigned>(value.hour) << ':' << std::setw(2)
           << static_cast<unsigned>(value.minute) << ':' << std::setw(2) << static_cast<unsigned>(value.second);
    if (value.nanosecond != 0) {
        result << '.' << std::setw(9) << value.nanosecond;
    }
    if (value.has_offset) {
        const auto offset = value.offset_minutes;
        const auto absolute = static_cast<unsigned>(offset < 0 ? -offset : offset);
        result << (offset < 0 ? '-' : '+') << std::setw(2) << absolute / 60 << ':' << std::setw(2) << absolute % 60;
    }
    return result.str();
}

// One Oracle date or timestamp as the DuckDB value its column maps to. The
// nanosecond form spans only 1677..2262, so a value outside it is reported
// rather than wrapped into a different instant.
Value TimestampValueFor(const OracleColumn &column, const oracle_scanner::OracleDateTime &value) {
    date_t date;
    if (!Date::TryFromDate(value.year, value.month, value.day, date)) {
        throw ConversionException("Oracle date %s is outside the range DuckDB can represent",
                                  FormatDateTime(value));
    }
    const auto time = Time::FromTime(value.hour, value.minute, value.second, 0);
    timestamp_t timestamp;
    if (!Timestamp::TryFromDatetime(date, time, timestamp)) {
        throw ConversionException("Oracle timestamp %s is outside the range DuckDB can represent",
                                  FormatDateTime(value));
    }
    if (MappedType(column).id() != LogicalTypeId::TIMESTAMP_NS) {
        // Microsecond resolution. Oracle keeps nanoseconds, so a column
        // declared to a precision this cannot hold is a mapping error, not a
        // value to round.
        if (value.nanosecond % 1000U != 0) {
            throw ConversionException(
                "Oracle column \"%s\" carries sub-microsecond precision its declared scale %d does not allow",
                column.name, static_cast<int>(column.scale));
        }
        return Value::TIMESTAMP(timestamp_t(timestamp.value + static_cast<int64_t>(value.nanosecond / 1000U)));
    }
    int64_t nanoseconds = 0;
    if (!Timestamp::TryGetEpochNanoSeconds(timestamp, nanoseconds)) {
        throw ConversionException("Oracle timestamp %s is outside the nanosecond range DuckDB can represent",
                                  FormatDateTime(value));
    }
    return Value::TIMESTAMPNS(timestamp_ns_t(nanoseconds + static_cast<int64_t>(value.nanosecond)));
}

Value ValueFor(const OracleColumn &column, const std::optional<std::vector<uint8_t>> &wire) {
    if (!wire) {
        return Value();
    }
    switch (column.oracle_type) {
    case 2: {
        if (column.scale == 0 && column.precision >= 1 && column.precision <= 18) {
            try {
                return Value::BIGINT(std::stoll(oracle_scanner::DecodeOracleNumber(*wire)));
            } catch (const std::exception &) {
                throw InvalidInputException("Oracle NUMBER value exceeds its declared BIGINT mapping");
            }
        }
        const auto number = oracle_scanner::DecodeOracleNumber(*wire);
        if (column.precision >= 1 && column.precision <= 38 && column.scale >= 1 && column.scale <= column.precision) {
            return Value(number).DefaultCastAs(
                LogicalType::DECIMAL(static_cast<uint8_t>(column.precision), static_cast<uint8_t>(column.scale)), true);
        }
        return Value(number);
    }
    case 12:
        return TimestampValueFor(column, oracle_scanner::DecodeOracleDate(*wire));
    case 180:
        return TimestampValueFor(column, oracle_scanner::DecodeOracleTimestamp(*wire));
    case 181:
    case 231:
        return Value(FormatDateTime(oracle_scanner::DecodeOracleTimestamp(*wire)));
    case 23:
    case 113:
        return Value::BLOB(wire->data(), wire->size());
    case 100:
        return Value::FLOAT(oracle_scanner::DecodeOracleBinaryFloat(*wire));
    case 101:
        return Value::DOUBLE(oracle_scanner::DecodeOracleBinaryDouble(*wire));
    default:
        return Value(std::string(wire->begin(), wire->end()));
    }
}

std::string FormatCallScalar(uint16_t oracle_type, const std::vector<uint8_t> &wire) {
    switch (oracle_type) {
    case 2:
        return oracle_scanner::DecodeOracleNumber(wire);
    case 12:
        return FormatDateTime(oracle_scanner::DecodeOracleDate(wire));
    case 180:
        return FormatDateTime(oracle_scanner::DecodeOracleTimestamp(wire));
    case 23:
        return oracle_scanner::UpperHex(wire);
    case 100: {
        std::ostringstream result;
        result << std::setprecision(std::numeric_limits<float>::max_digits10)
               << oracle_scanner::DecodeOracleBinaryFloat(wire);
        return result.str();
    }
    case 101: {
        std::ostringstream result;
        result << std::setprecision(std::numeric_limits<double>::max_digits10)
               << oracle_scanner::DecodeOracleBinaryDouble(wire);
        return result.str();
    }
    default:
        return std::string(wire.begin(), wire.end());
    }
}

std::string OutputName(const OracleColumn &column, idx_t index, std::unordered_set<std::string> &used) {
    auto result = column.name.empty() ? "column_" + std::to_string(index + 1) : column.name;
    if (used.insert(result).second) {
        return result;
    }
    const auto base = result;
    do {
        result = base + "_" + std::to_string(index + 1);
    } while (!used.insert(result).second);
    return result;
}

} // namespace duckdb

// Oracle-to-DuckDB value and type conversion. The support policy lives here:
// a column this client cannot read is refused rather than decoded into
// something wrong, and both the table functions and the attached catalog go
// through it.

#include "oracle_adapter.hpp"

#include "duckdb/common/exception/conversion_exception.hpp"
#include "duckdb/common/vector/array_vector.hpp"
#include "duckdb/common/vector/list_vector.hpp"
#include "duckdb/common/operator/decimal_cast_operators.hpp"
#include "duckdb/common/types/time.hpp"
#include "oracle_scanner/oracle_vector.hpp"
#include "oracle_scanner/oson.hpp"
#include "oracle_scanner/ttc_lob.hpp"

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
// later with an opaque wire error. Each of those now has a decoder; what is
// still refused below is refused for the same reason it always was. Each
// rejection below names what was found and why it is not supported, so the
// message is actionable.
void RequireReadableColumn(const OracleColumn &column) {
    const auto refuse = [&](const std::string &reason) {
        throw NotImplementedException("Oracle column \"%s\" cannot be read: %s", column.name, reason);
    };
    // NCHAR, NVARCHAR2 and NCLOB share their type codes with the database
    // character set forms and differ only in this one. NCHAR and NVARCHAR2
    // travel in the row as UTF-16BE, the national character set this client
    // negotiates, and are converted to UTF-8 when read. Any other type that
    // claims the national form is not one this version has seen.
    if (column.character_set_form == 2 && column.oracle_type != 1 && column.oracle_type != 96 &&
        column.oracle_type != 112) {
        refuse("a national character set form on Oracle type " + std::to_string(column.oracle_type) +
               " has no decoder");
    }
    switch (column.oracle_type) {
    case 1:   // VARCHAR2
    case 2:   // NUMBER
    case 8:   // LONG
    case 11:  // ROWID
    case 12:  // DATE
    case 23:  // RAW
    case 24:  // LONG RAW
    case 96:  // CHAR
    case 100: // BINARY_FLOAT
    case 101: // BINARY_DOUBLE
    case 180: // TIMESTAMP
        return;
    case 181: // TIMESTAMP WITH TIME ZONE
        // Readable because the value carries its own offset; nothing has to be
        // assumed about a session zone.
        return;
    case 231: // TIMESTAMP WITH LOCAL TIME ZONE
        // Readable because the session time zone is fixed at UTC when the
        // session is opened, which turns the wall-clock time on the wire into
        // an instant.
        return;
    case 252: // BOOLEAN, which a 23ai server sends as itself to a client that
              // advertises TTC field version 17
        return;
    case 112: // CLOB
    case 113: // BLOB
        // The value in the row is a locator, not content; the fetch resolves it
        // through LOB_OP before the row ever reaches this layer, so by the time
        // a value is converted a LOB is bytes like any other.
        return;
    case 182: // INTERVAL YEAR TO MONTH
    case 183: // INTERVAL DAY TO SECOND
    case 208: // UROWID
        return;
    case 119: // JSON, an OSON image behind a locator; decoded to JSON text
    case 127: // VECTOR, an image behind a locator; decoded to a list or array
        return;
    default:
        break;
    }
    refuse("Oracle type " + std::to_string(column.oracle_type) + " has no mapping in this version");
}

// The DuckDB type an Oracle column maps to, with no support check. Only the
// attached catalog uses this directly, so that a table carrying a column this
// version cannot read is still listed; reading it goes through TypeFor and is
// refused there.
LogicalType VectorElementType(uint8_t format) {
    switch (format) {
    case oracle_scanner::ORACLE_VECTOR_FLOAT32:
        return LogicalType::FLOAT;
    case oracle_scanner::ORACLE_VECTOR_INT8:
        return LogicalType::TINYINT;
    case oracle_scanner::ORACLE_VECTOR_BINARY:
        return LogicalType::UTINYINT;
    default:
        // FLOAT64 and a column whose elements may be any format: every format
        // but BINARY widens into a DOUBLE without losing a digit.
        return LogicalType::DOUBLE;
    }
}

// A VECTOR column maps by the shape its describe or its dictionary entry
// gives. Dense: an ARRAY of the declared dimension count when there is one, a
// LIST when the column leaves it open. A BINARY vector's elements are its
// packed bytes, so its dimensions are bits / 8. Sparse: the three parts a
// SparseVector has.
LogicalType VectorType(const OracleColumn &column) {
    const auto element = VectorElementType(column.vector_format);
    if ((column.vector_flags & oracle_scanner::ORACLE_VECTOR_COLUMN_SPARSE) != 0) {
        return LogicalType::STRUCT({{"dimensions", LogicalType::UINTEGER},
                                    {"indices", LogicalType::LIST(LogicalType::UINTEGER)},
                                    {"values", LogicalType::LIST(element)}});
    }
    auto dimensions = column.vector_dimensions;
    if (column.vector_format == oracle_scanner::ORACLE_VECTOR_BINARY) {
        dimensions /= 8;
    }
    if (dimensions == 0) {
        return LogicalType::LIST(element);
    }
    return LogicalType::ARRAY(element, dimensions);
}

// How a NUMBER column is held in DuckDB. A declared precision and scale give an
// exact integer or decimal; anything else is text, which never loses a digit,
// unless the user chose a lossy target for NUMBER with no declared precision
// (oracle_unconstrained_number).
NumberMapping MapNumber(const OracleColumn &column) {
    NumberMapping result;
    const int precision = column.precision;
    const int scale = column.scale;
    if (precision >= 1) {
        if (scale == 0 && precision <= 18) {
            result.kind = NumberMapping::BIGINT;
        } else if (scale < 0 && scale > -128 && precision - scale <= 18) {
            // NUMBER(10,-2) holds whole numbers rounded to hundreds.
            result.kind = NumberMapping::BIGINT;
        } else if (precision <= 38 && scale >= 1 && scale <= precision) {
            result.kind = NumberMapping::DECIMAL;
            result.width = static_cast<uint8_t>(precision);
            result.scale = static_cast<uint8_t>(scale);
        } else if (scale > precision && scale <= 38) {
            // NUMBER(2,4) holds 0.0012: four digits after the point, none before.
            result.kind = NumberMapping::DECIMAL;
            result.width = static_cast<uint8_t>(scale);
            result.scale = static_cast<uint8_t>(scale);
        }
        return result;
    }
    if (column.unconstrained_number == OracleColumn::UNCONSTRAINED_DOUBLE) {
        result.kind = NumberMapping::DOUBLE;
    } else if (column.unconstrained_number == OracleColumn::UNCONSTRAINED_DECIMAL) {
        result.kind = NumberMapping::DECIMAL;
        result.width = column.unconstrained_precision;
        result.scale = column.unconstrained_scale;
    }
    return result;
}

// A NUMBER with no declared precision that the user mapped to DECIMAL or DOUBLE
// (oracle_unconstrained_number) reads as a rounding of what Oracle stores: 1.21
// and 1.24 both read as 1.2 under decimal(10,1). Oracle compares, groups, joins
// and ranks the stored values, so a filter, group key, join key or sort key on
// such a column means something different there than in DuckDB.
bool OracleColumnRoundsOnRead(const OracleColumn &column) {
    if (column.oracle_type != 2 || column.precision >= 1) {
        return false;
    }
    const auto kind = MapNumber(column).kind;
    return kind == NumberMapping::DECIMAL || kind == NumberMapping::DOUBLE;
}

LogicalType MappedType(const OracleColumn &column) {
    switch (column.oracle_type) {
    case 119: // JSON
        return LogicalType::JSON();
    case 127: // VECTOR
        return VectorType(column);
    case 2: // NUMBER
        // Only integral NUMBER values with a representable declared precision
        // are widened. Unconstrained and fractional NUMBER stay textual so no
        // Oracle value is rounded or silently narrowed.
        switch (const auto mapping = MapNumber(column); mapping.kind) {
        case NumberMapping::BIGINT:
            return LogicalType::BIGINT;
        case NumberMapping::DECIMAL:
            return LogicalType::DECIMAL(mapping.width, mapping.scale);
        case NumberMapping::DOUBLE:
            return LogicalType::DOUBLE;
        default:
            return LogicalType::VARCHAR;
        }
    case 23:  // RAW
    case 24:  // LONG RAW
    case 113: // BLOB
        return LogicalType::BLOB;
    case 182: // INTERVAL YEAR TO MONTH
    case 183: // INTERVAL DAY TO SECOND
        return LogicalType::INTERVAL;
    case 252: // BOOLEAN
        return LogicalType::BOOLEAN;
    case 231: // TIMESTAMP WITH LOCAL TIME ZONE, an instant: the session is UTC
        return LogicalType::TIMESTAMP_TZ;
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


// The JSON text of one OSON image, with the column named when it cannot be read.
std::string OsonToJson(const OracleColumn &column, const std::vector<uint8_t> &image) {
    try {
        return oracle_scanner::DecodeOsonToJson(image);
    } catch (const oracle_scanner::ProtocolError &error) {
        throw ConversionException("Oracle JSON column \"%s\" cannot be read: %s", column.name, error.what());
    }
}

template <class T>
vector<Value> VectorElements(const std::vector<T> &elements) {
    vector<Value> values;
    values.reserve(elements.size());
    for (const auto element : elements) {
        values.push_back(Value::CreateValue<T>(element));
    }
    return values;
}

// One VECTOR as the DuckDB value its column maps to. A column whose elements
// may be in any format maps to DOUBLE, which every format but BINARY fits
// exactly; a BINARY value there is reported rather than turned into numbers
// that are not its elements.
Value VectorValueFor(const OracleColumn &column, const std::vector<uint8_t> &image) {
    oracle_scanner::OracleVector decoded;
    try {
        decoded = oracle_scanner::DecodeOracleVector(image);
    } catch (const oracle_scanner::ProtocolError &error) {
        throw ConversionException("Oracle VECTOR column \"%s\" cannot be read: %s", column.name, error.what());
    }
    const auto type = VectorType(column);
    const bool sparse = (column.vector_flags & oracle_scanner::ORACLE_VECTOR_COLUMN_SPARSE) != 0;
    if (decoded.sparse != sparse) {
        throw ConversionException("Oracle VECTOR column \"%s\" holds a %s vector in a column declared %s", column.name,
                                  decoded.sparse ? "sparse" : "dense", sparse ? "sparse" : "dense");
    }
    const auto element_type = sparse ? ListType::GetChildType(StructType::GetChildType(type, 2))
                                     : (type.id() == LogicalTypeId::ARRAY ? ArrayType::GetChildType(type)
                                                                          : ListType::GetChildType(type));
    if (column.vector_format != 0 && decoded.format != column.vector_format) {
        throw ConversionException("Oracle VECTOR column \"%s\" holds a vector of storage format %d where %d was declared",
                                  column.name, static_cast<int>(decoded.format), static_cast<int>(column.vector_format));
    }
    vector<Value> elements;
    switch (decoded.format) {
    case oracle_scanner::ORACLE_VECTOR_FLOAT32:
        if (element_type.id() == LogicalTypeId::DOUBLE) {
            for (const auto element : decoded.float32) {
                elements.push_back(Value::DOUBLE(static_cast<double>(element)));
            }
        } else {
            elements = VectorElements(decoded.float32);
        }
        break;
    case oracle_scanner::ORACLE_VECTOR_FLOAT64:
        elements = VectorElements(decoded.float64);
        break;
    case oracle_scanner::ORACLE_VECTOR_INT8:
        if (element_type.id() == LogicalTypeId::DOUBLE) {
            for (const auto element : decoded.int8) {
                elements.push_back(Value::DOUBLE(static_cast<double>(element)));
            }
        } else {
            elements = VectorElements(decoded.int8);
        }
        break;
    default:
        if (element_type.id() != LogicalTypeId::UTINYINT) {
            throw ConversionException(
                "Oracle VECTOR column \"%s\" holds a BINARY vector in a column of mixed storage formats; "
                "read it with VECTOR_SERIALIZE or declare the column's format",
                column.name);
        }
        elements = VectorElements(decoded.binary);
        break;
    }
    if (sparse) {
        vector<Value> indices;
        indices.reserve(decoded.indices.size());
        for (const auto index : decoded.indices) {
            indices.push_back(Value::UINTEGER(index));
        }
        return Value::STRUCT(type, {Value::UINTEGER(decoded.dimensions), Value::LIST(LogicalType::UINTEGER, std::move(indices)),
                                    Value::LIST(element_type, std::move(elements))});
    }
    const auto expected = type.id() == LogicalTypeId::ARRAY ? ArrayType::GetSize(type) : elements.size();
    if (elements.size() != expected) {
        throw ConversionException("Oracle VECTOR column \"%s\" holds %llu elements where %llu were declared", column.name,
                                  static_cast<uint64_t>(elements.size()), static_cast<uint64_t>(expected));
    }
    return type.id() == LogicalTypeId::ARRAY ? Value::ARRAY(element_type, std::move(elements))
                                             : Value::LIST(element_type, std::move(elements));
}

Value ValueFor(const OracleColumn &column, const std::optional<std::vector<uint8_t>> &wire) {
    if (!wire) {
        return Value();
    }
    switch (column.oracle_type) {
    case 2: {
        const auto mapping = MapNumber(column);
        if (mapping.kind == NumberMapping::BIGINT) {
            try {
                return Value::BIGINT(std::stoll(oracle_scanner::DecodeOracleNumber(*wire)));
            } catch (const std::exception &) {
                throw InvalidInputException("Oracle NUMBER value exceeds its declared BIGINT mapping");
            }
        }
        const auto number = oracle_scanner::DecodeOracleNumber(*wire);
        if (mapping.kind == NumberMapping::DECIMAL) {
            return Value(number).DefaultCastAs(LogicalType::DECIMAL(mapping.width, mapping.scale), true);
        }
        if (mapping.kind == NumberMapping::DOUBLE) {
            try {
                return Value::DOUBLE(std::stod(number));
            } catch (const std::exception &) {
                throw InvalidInputException("Oracle NUMBER value does not fit a DOUBLE");
            }
        }
        return Value(number);
    }
    case 12:
        return TimestampValueFor(column, oracle_scanner::DecodeOracleDate(*wire));
    case 180:
        return TimestampValueFor(column, oracle_scanner::DecodeOracleTimestamp(*wire));
    case 181:
        // Printed on the wall clock of its own offset, as Oracle prints it.
        return Value(
            FormatDateTime(oracle_scanner::OracleZonedWallClock(oracle_scanner::DecodeOracleTimestamp(*wire))));
    case 231: {
        // The session time zone is UTC (see the auth parameters), so this wall
        // time is the instant. DuckDB's TIMESTAMPTZ keeps microseconds.
        const auto timestamp = TimestampValueFor(column, oracle_scanner::DecodeOracleTimestamp(*wire));
        return Value::TIMESTAMPTZ(timestamp_tz_t(timestamp.GetValue<timestamp_t>().value));
    }
    case 252:
        if (wire->empty()) {
            throw InvalidInputException("Oracle BOOLEAN value is empty");
        }
        return Value::BOOLEAN(wire->back() == 1);
    case 119:
        return Value(OsonToJson(column, *wire)).WithType(LogicalType::JSON());
    case 127:
        return VectorValueFor(column, *wire);
    case 23:
    case 24:
    case 113:
        return Value::BLOB(wire->data(), wire->size());
    case 182: {
        const auto months = oracle_scanner::DecodeOracleIntervalYearMonth(*wire).months;
        if (months < NumericLimits<int32_t>::Minimum() || months > NumericLimits<int32_t>::Maximum()) {
            throw ConversionException("Oracle INTERVAL YEAR TO MONTH of %d months is outside the range DuckDB can represent",
                                      months);
        }
        return Value::INTERVAL(static_cast<int32_t>(months), 0, 0);
    }
    case 183: {
        const auto interval = oracle_scanner::DecodeOracleIntervalDaySecond(*wire);
        // DuckDB keeps microseconds. Oracle keeps nanoseconds, and a column
        // declared past six fractional digits that actually uses them is a
        // value this cannot hold, so it is reported rather than rounded.
        if (interval.nanoseconds % 1000 != 0) {
            throw ConversionException(
                "Oracle column \"%s\" carries sub-microsecond precision an INTERVAL cannot hold in DuckDB", column.name);
        }
        return Value::INTERVAL(0, interval.days, interval.nanoseconds / 1000);
    }
    case 11:
    case 208: {
        auto text = oracle_scanner::TryDecodeOracleRowid(*wire);
        if (!text) {
            throw NotImplementedException(
                "Oracle column \"%s\" holds a logical UROWID, which an index-organized table has; only physical "
                "rowids are decoded",
                column.name);
        }
        return Value(*text);
    }
    case 100:
        return Value::FLOAT(oracle_scanner::DecodeOracleBinaryFloat(*wire));
    case 101:
        return Value::DOUBLE(oracle_scanner::DecodeOracleBinaryDouble(*wire));
    default:
        if (column.character_set_form == 2 && (column.oracle_type == 1 || column.oracle_type == 96)) {
            // NCHAR and NVARCHAR2: UTF-16BE in the row. An NCLOB is already UTF-8 here.
            const auto utf8 = oracle_scanner::DecodeUtf16BeToUtf8(*wire);
            return Value(std::string(utf8.begin(), utf8.end()));
        }
        return Value(std::string(wire->begin(), wire->end()));
    }
}

// Copies a dense vector's elements into the child of a LIST or ARRAY vector
// without a Value per element. Returns false for anything this does not cover,
// and the caller then takes the Value path, which also raises every refusal.
template <class FROM, class TO>
void CopyElements(const std::vector<FROM> &source, TO *target) {
    for (size_t index = 0; index < source.size(); index++) {
        target[index] = static_cast<TO>(source[index]);
    }
}

bool TryWriteDenseVector(Vector &vector, idx_t row, const OracleColumn &column, const oracle_scanner::OracleVector &decoded) {
    const auto &type = vector.GetType();
    if (decoded.sparse || (column.vector_flags & oracle_scanner::ORACLE_VECTOR_COLUMN_SPARSE) != 0 ||
        (column.vector_format != 0 && decoded.format != column.vector_format)) {
        return false;
    }
    const bool is_array = type.id() == LogicalTypeId::ARRAY;
    if (!is_array && type.id() != LogicalTypeId::LIST) {
        return false;
    }
    const auto &child_type = is_array ? ArrayType::GetChildType(type) : ListType::GetChildType(type);
    const idx_t count = decoded.format == oracle_scanner::ORACLE_VECTOR_BINARY ? decoded.binary.size()
                        : decoded.format == oracle_scanner::ORACLE_VECTOR_FLOAT32 ? decoded.float32.size()
                        : decoded.format == oracle_scanner::ORACLE_VECTOR_FLOAT64 ? decoded.float64.size()
                                                                                  : decoded.int8.size();
    if (is_array && count != ArrayType::GetSize(type)) {
        return false;
    }
    // The element type the column maps to must be what this format fills; a
    // format that does not fit it (BINARY into DOUBLE) takes the Value path to be refused.
    const auto id = child_type.id();
    const auto fill = [&](data_ptr_t target) {
        switch (decoded.format) {
        case oracle_scanner::ORACLE_VECTOR_FLOAT32:
            if (id == LogicalTypeId::FLOAT) {
                CopyElements(decoded.float32, reinterpret_cast<float *>(target));
            } else if (id == LogicalTypeId::DOUBLE) {
                CopyElements(decoded.float32, reinterpret_cast<double *>(target));
            } else {
                return false;
            }
            return true;
        case oracle_scanner::ORACLE_VECTOR_FLOAT64:
            if (id != LogicalTypeId::DOUBLE) {
                return false;
            }
            CopyElements(decoded.float64, reinterpret_cast<double *>(target));
            return true;
        case oracle_scanner::ORACLE_VECTOR_INT8:
            if (id == LogicalTypeId::TINYINT) {
                CopyElements(decoded.int8, reinterpret_cast<int8_t *>(target));
            } else if (id == LogicalTypeId::DOUBLE) {
                CopyElements(decoded.int8, reinterpret_cast<double *>(target));
            } else {
                return false;
            }
            return true;
        default:
            if (id != LogicalTypeId::UTINYINT) {
                return false;
            }
            CopyElements(decoded.binary, reinterpret_cast<uint8_t *>(target));
            return true;
        }
    };
    if (is_array) {
        auto &child = ArrayVector::GetChildMutable(vector);
        if (child.GetVectorType() != VectorType::FLAT_VECTOR) {
            return false;
        }
        const auto width = GetTypeIdSize(child_type.InternalType());
        if (!fill(FlatVector::GetDataMutable(child) + static_cast<idx_t>(row) * count * width)) {
            return false;
        }
        for (idx_t element = 0; element < count; element++) {
            FlatVector::SetNull(child, row * count + element, false);
        }
        FlatVector::SetNull(vector, row, false);
        return true;
    }
    const idx_t offset = ListVector::GetListSize(vector);
    ListVector::Reserve(vector, offset + count);
    auto &child = ListVector::GetChildMutable(vector);
    if (child.GetVectorType() != VectorType::FLAT_VECTOR) {
        return false;
    }
    const auto width = GetTypeIdSize(child_type.InternalType());
    if (!fill(FlatVector::GetDataMutable(child) + offset * width)) {
        return false;
    }
    for (idx_t element = 0; element < count; element++) {
        FlatVector::SetNull(child, offset + element, false);
    }
    ListVector::SetListSize(vector, offset + count);
    FlatVector::GetDataMutable<list_entry_t>(vector)[row] = list_entry_t(offset, count);
    FlatVector::SetNull(vector, row, false);
    return true;
}

// A scan used to store each fetched value as SetValue(ValueFor(...)): a Value
// built per cell — a heap string for text, a string-to-DECIMAL cast through
// the generic cast machinery for DECIMAL — and then copied into the vector.
// That boxing was the larger part of a scan's client CPU. This stores the same
// bytes the same way SetValue does (the validity bit, the slot, AddBlob for
// strings) without the Value. Whatever it does not handle — a vector that is
// not flat, a type it does not cover, and every value that would be refused —
// takes the SetValue(ValueFor(...)) path itself, so a refusal raises exactly
// the error it always did.
void WriteOracleValue(Vector &vector, idx_t row, const OracleColumn &column,
                      const std::optional<std::vector<uint8_t>> &wire) {
    const auto through_value = [&] { vector.SetValue(row, ValueFor(column, wire)); };
    if (vector.GetVectorType() != VectorType::FLAT_VECTOR) {
        through_value();
        return;
    }
    if (!wire) {
        FlatVector::SetNull(vector, row, true);
        return;
    }
    const auto &type = vector.GetType();
    const auto store_string = [&](const char *data, idx_t size) {
        FlatVector::SetNull(vector, row, false);
        FlatVector::GetDataMutable<string_t>(vector)[row] = StringVector::AddStringOrBlob(vector, data, size);
    };
    switch (column.oracle_type) {
    case 2: {
        const auto mapping = MapNumber(column);
        if (type.id() == LogicalTypeId::BIGINT && mapping.kind == NumberMapping::BIGINT) {
            // Most values are whole numbers that fit, and need no text at all.
            if (const auto integer = oracle_scanner::TryDecodeOracleInteger(*wire)) {
                FlatVector::SetNull(vector, row, false);
                FlatVector::GetDataMutable<int64_t>(vector)[row] = *integer;
                return;
            }
            int64_t value = 0;
            try {
                value = std::stoll(oracle_scanner::DecodeOracleNumber(*wire));
            } catch (const std::exception &) {
                through_value();
                return;
            }
            FlatVector::SetNull(vector, row, false);
            FlatVector::GetDataMutable<int64_t>(vector)[row] = value;
            return;
        }
        if (type.id() == LogicalTypeId::DECIMAL && mapping.kind == NumberMapping::DECIMAL &&
            DecimalType::GetWidth(type) == mapping.width && DecimalType::GetScale(type) == mapping.scale) {
            // The cast DuckDB's VARCHAR-to-DECIMAL conversion runs, called
            // directly; it writes the slot only when it succeeds.
            const auto number = oracle_scanner::DecodeOracleNumber(*wire);
            const string_t text(number.data(), static_cast<uint32_t>(number.size()));
            const auto width = DecimalType::GetWidth(type);
            const auto scale = DecimalType::GetScale(type);
            // With somewhere to put its message the cast reports a failure
            // instead of throwing its own error, and the Value path below then
            // raises the one a scan always raised.
            string cast_error;
            CastParameters parameters(false, &cast_error);
            bool stored = false;
            switch (type.InternalType()) {
            case PhysicalType::INT16:
                stored = TryCastToDecimal::Operation(text, FlatVector::GetDataMutable<int16_t>(vector)[row],
                                                     parameters, width, scale);
                break;
            case PhysicalType::INT32:
                stored = TryCastToDecimal::Operation(text, FlatVector::GetDataMutable<int32_t>(vector)[row],
                                                     parameters, width, scale);
                break;
            case PhysicalType::INT64:
                stored = TryCastToDecimal::Operation(text, FlatVector::GetDataMutable<int64_t>(vector)[row],
                                                     parameters, width, scale);
                break;
            case PhysicalType::INT128:
                stored = TryCastToDecimal::Operation(text, FlatVector::GetDataMutable<hugeint_t>(vector)[row],
                                                     parameters, width, scale);
                break;
            default:
                break;
            }
            if (!stored) {
                through_value();
                return;
            }
            FlatVector::SetNull(vector, row, false);
            return;
        }
        if (type.id() == LogicalTypeId::VARCHAR && MappedType(column).id() == LogicalTypeId::VARCHAR) {
            // Decimal text is ASCII, so it is always valid UTF-8.
            const auto number = oracle_scanner::DecodeOracleNumber(*wire);
            store_string(number.data(), number.size());
            return;
        }
        break;
    }
    case 12:
    case 180:
        // A timestamp Value holds no heap data, so building one costs little,
        // and its range and precision checks stay in one place.
        break;
    case 23:
    case 24:
    case 113:
        if (type.id() == LogicalTypeId::BLOB) {
            store_string(reinterpret_cast<const char *>(wire->data()), wire->size());
            return;
        }
        break;
    case 100:
        if (type.id() == LogicalTypeId::FLOAT) {
            FlatVector::SetNull(vector, row, false);
            FlatVector::GetDataMutable<float>(vector)[row] = oracle_scanner::DecodeOracleBinaryFloat(*wire);
            return;
        }
        break;
    case 101:
        if (type.id() == LogicalTypeId::DOUBLE) {
            FlatVector::SetNull(vector, row, false);
            FlatVector::GetDataMutable<double>(vector)[row] = oracle_scanner::DecodeOracleBinaryDouble(*wire);
            return;
        }
        break;
    case 252:
        if (type.id() == LogicalTypeId::BOOLEAN && !wire->empty()) {
            FlatVector::SetNull(vector, row, false);
            FlatVector::GetDataMutable<bool>(vector)[row] = wire->back() == 1;
            return;
        }
        break;
    case 119:
        if (type.IsJSONType()) {
            // The decoder writes valid UTF-8 by construction.
            const auto json = OsonToJson(column, *wire);
            store_string(json.data(), json.size());
            return;
        }
        break;
    case 127: {
        // Decoded once here; a vector this cannot place goes through ValueFor,
        // which decodes it again and says why if it must be refused.
        oracle_scanner::OracleVector decoded;
        try {
            decoded = oracle_scanner::DecodeOracleVector(*wire);
        } catch (const oracle_scanner::ProtocolError &) {
            through_value();
            return;
        }
        if (TryWriteDenseVector(vector, row, column, decoded)) {
            return;
        }
        break;
    }
    case 181:
    case 231:
    case 182:
    case 183:
    case 11:
    case 208:
        break;
    default:
        // Text. A Value refuses bytes that are not valid UTF-8, and so does
        // this, by letting that Value be built and refuse them. National
        // character columns are UTF-16 on the wire and take the Value path,
        // which converts them.
        if (type.id() == LogicalTypeId::VARCHAR && column.character_set_form != 2) {
            const auto *data = reinterpret_cast<const char *>(wire->data());
            if (!Value::StringIsValid(data, wire->size())) {
                through_value();
                return;
            }
            store_string(data, wire->size());
            return;
        }
        break;
    }
    through_value();
}

std::string FormatCallScalar(uint16_t oracle_type, const std::vector<uint8_t> &wire, uint8_t character_set_form) {
    if (oracle_type == 1 && character_set_form == 2) {
        const auto text = oracle_scanner::DecodeUtf16BeToUtf8(wire);
        return std::string(text.begin(), text.end());
    }
    switch (oracle_type) {
    case 181:
    case 182:
    case 183:
    case 252: {
        // The column reader already knows how these print.
        OracleColumn column;
        column.oracle_type = oracle_type;
        return ValueFor(column, wire).ToString();
    }
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

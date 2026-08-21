// Resolving a callable's signature from the data dictionary.
//
// Without this a caller has to state every argument's direction and type by
// hand, and a mistake there is not caught until Oracle rejects the call — or
// worse, accepts it and reads the value as something else. `ALL_ARGUMENTS`
// already knows all of it, so one query answers what the call should look like.
//
// The support policy lives here too, and it is the same shape as the column
// policy in oracle_types.cpp: an argument this client cannot bind is named as
// unsupported with the reason, rather than being mapped to whatever is closest.

#include "oracle_adapter.hpp"

#include "duckdb/common/types/time.hpp"

#include "oracle_scanner/call_builder.hpp"
#include "oracle_scanner/ttc_execute.hpp"

#include <algorithm>
#include <cmath>
#include <string>
#include <vector>

namespace duckdb {

using oracle_scanner::BindDirection;
using oracle_scanner::OracleBind;

namespace {

// Every scalar family this client can put on the wire, and the buffer an OUT
// value of it needs. The sizes match the ones `oracle_call_named` already uses
// for a hand-written bind, so an automatic bind and a hand-written one are the
// same bind.
struct BindableType {
    uint16_t oracle_type;
    uint32_t maximum_bytes;
    const char *bind_type_name;
};

bool BindableFor(const std::string &dictionary_type, BindableType &result) {
    if (dictionary_type == "NUMBER" || dictionary_type == "FLOAT" || dictionary_type == "BINARY_INTEGER" ||
        dictionary_type == "PL/SQL BINARY INTEGER" || dictionary_type == "PL/SQL PLS INTEGER") {
        // Oracle FLOAT and the PL/SQL integer families are all NUMBER on the
        // wire, so they bind exactly as NUMBER does and keep their exactness.
        result = {2, 22, "number"};
        return true;
    }
    if (dictionary_type == "VARCHAR2" || dictionary_type == "CHAR" || dictionary_type == "VARCHAR") {
        result = {1, 32767, "varchar"};
        return true;
    }
    if (dictionary_type == "DATE") {
        result = {12, 7, "date"};
        return true;
    }
    if (dictionary_type == "TIMESTAMP") {
        result = {180, 11, "timestamp"};
        return true;
    }
    if (dictionary_type == "RAW") {
        result = {23, 32767, "raw"};
        return true;
    }
    if (dictionary_type == "BINARY_FLOAT") {
        result = {100, 4, "float"};
        return true;
    }
    if (dictionary_type == "BINARY_DOUBLE") {
        result = {101, 8, "double"};
        return true;
    }
    if (dictionary_type == "REF CURSOR") {
        result = {oracle_scanner::ORACLE_WIRE_TYPE_CURSOR, 4, "cursor"};
        return true;
    }
    return false;
}

// Why an argument cannot be bound, in the same words the column policy uses for
// the same families, so the two answers agree.
std::string UnsupportedReason(const std::string &dictionary_type) {
    if (dictionary_type == "CLOB" || dictionary_type == "BLOB" || dictionary_type == "NCLOB" ||
        dictionary_type == "BFILE") {
        return "LOB locators are outside this version's boundary";
    }
    if (dictionary_type == "NCHAR" || dictionary_type == "NVARCHAR2") {
        return "national character set values are UTF-16 on the wire and are not decoded";
    }
    if (dictionary_type == "OBJECT" || dictionary_type == "TABLE" || dictionary_type == "VARRAY" ||
        dictionary_type == "PL/SQL RECORD" || dictionary_type == "PL/SQL TABLE" ||
        dictionary_type == "REF" || dictionary_type == "OPAQUE/XMLTYPE") {
        return "object, record and collection types are outside this version's boundary";
    }
    if (dictionary_type == "PL/SQL BOOLEAN") {
        return "PL/SQL BOOLEAN has no SQL wire representation";
    }
    if (dictionary_type.rfind("INTERVAL", 0) == 0) {
        return "INTERVAL values have no decoder yet";
    }
    if (dictionary_type.rfind("TIMESTAMP WITH", 0) == 0) {
        // The column policy reads TIMESTAMP WITH TIME ZONE, but a bind also has
        // to be written, and nothing on the DuckDB side of this mapping carries
        // an offset to write from.
        return "TIMESTAMP WITH TIME ZONE and WITH LOCAL TIME ZONE cannot be bound in this version";
    }
    if (dictionary_type.empty()) {
        return "the dictionary reports no type for this argument";
    }
    return "Oracle type " + dictionary_type + " has no bind mapping in this version";
}

std::string TextOf(const std::optional<std::vector<uint8_t>> &wire) {
    if (!wire) {
        return {};
    }
    return std::string(wire->begin(), wire->end());
}

int64_t IntegerOf(const std::optional<std::vector<uint8_t>> &wire, const char *field) {
    if (!wire) {
        return -1;
    }
    const auto text = TranslatingOracleErrors("oracle callable metadata could not be decoded",
                                              [&] { return oracle_scanner::DecodeOracleNumber(*wire); });
    try {
        size_t consumed = 0;
        const auto value = std::stoll(text, &consumed);
        if (consumed != text.size()) {
            throw std::invalid_argument("trailing");
        }
        return value;
    } catch (const std::exception &) {
        throw IOException("Oracle callable metadata field %s is not an integer", field);
    }
}

} // namespace

// One argument's wire form, from the text spelling both the hand-written and the
// resolved paths use. Keeping it in one place is the point: two encoders for the
// same type names would drift, and a drift here is a value Oracle reads as
// something the caller did not write.
OracleCallableBind EncodeOracleCallableArgument(const std::string &type_name,
                                                oracle_scanner::BindDirection direction, const Value &value,
                                                const std::string &name, const char *function_name) {
    const auto require_out_is_null = [&](const char *upper) {
        if (direction == BindDirection::OUT && !value.IsNull()) {
            throw BinderException("%s OUT %s %s must have NULL value", function_name, upper, name);
        }
        return direction == BindDirection::OUT;
    };
    const auto require_value = [&](const char *upper) {
        if (value.IsNull()) {
            throw BinderException("%s %s requires a %s value", function_name, name, upper);
        }
        return value.GetValue<std::string>();
    };
    if (type_name == "number") {
        if (require_out_is_null("NUMBER")) {
            return {2, 22, std::nullopt};
        }
        return {2, 22, oracle_scanner::EncodeOracleNumber(require_value("NUMBER"))};
    }
    if (type_name == "varchar") {
        if (require_out_is_null("VARCHAR")) {
            return {1, 32767, std::nullopt};
        }
        const auto text = require_value("VARCHAR");
        return {1, 32767, std::vector<uint8_t>(text.begin(), text.end())};
    }
    if (type_name == "date") {
        if (require_out_is_null("DATE")) {
            return {12, 7, std::nullopt};
        }
        const auto text = require_value("DATE");
        try {
            const auto date = Date::FromString(text, true);
            int32_t year;
            int32_t month;
            int32_t day;
            Date::Convert(date, year, month, day);
            return {12, 7,
                    oracle_scanner::EncodeOracleDate({year, static_cast<uint8_t>(month), static_cast<uint8_t>(day)})};
        } catch (const std::exception &) {
            throw BinderException("%s DATE %s must be a valid YYYY-MM-DD value", function_name, name);
        }
    }
    if (type_name == "timestamp") {
        if (require_out_is_null("TIMESTAMP")) {
            return {180, 11, std::nullopt};
        }
        const auto text = require_value("TIMESTAMP");
        try {
            const auto timestamp = Timestamp::FromString(text, false);
            if (!Timestamp::IsFinite(timestamp)) {
                throw BinderException("infinite TIMESTAMP");
            }
            date_t date;
            dtime_t time;
            Timestamp::Convert(timestamp, date, time);
            int32_t year;
            int32_t month;
            int32_t day;
            int32_t hour;
            int32_t minute;
            int32_t second;
            int32_t microseconds;
            Date::Convert(date, year, month, day);
            Time::Convert(time, hour, minute, second, microseconds);
            return {180, 11,
                    oracle_scanner::EncodeOracleTimestamp(
                        {year, static_cast<uint8_t>(month), static_cast<uint8_t>(day), static_cast<uint8_t>(hour),
                         static_cast<uint8_t>(minute), static_cast<uint8_t>(second),
                         static_cast<uint32_t>(microseconds) * 1000U},
                        false)};
        } catch (const std::exception &) {
            throw BinderException("%s TIMESTAMP %s must be a valid timezone-free YYYY-MM-DD HH:MM:SS[.ffffff] value",
                                  function_name, name);
        }
    }
    if (type_name == "raw") {
        if (require_out_is_null("RAW")) {
            return {23, 32767, std::nullopt};
        }
        const auto text = require_value("RAW hexadecimal");
        try {
            return {23, 32767, oracle_scanner::DecodeHex(text, 32767)};
        } catch (const std::exception &) {
            throw BinderException("%s RAW %s must be an even-length hexadecimal value up to 32767 bytes",
                                  function_name, name);
        }
    }
    if (type_name == "float" || type_name == "double") {
        const auto is_float = type_name == "float";
        const auto oracle_type = static_cast<uint16_t>(is_float ? 100 : 101);
        const auto maximum_bytes = static_cast<uint32_t>(is_float ? 4 : 8);
        const auto *const upper = is_float ? "FLOAT" : "DOUBLE";
        if (require_out_is_null(upper)) {
            return {oracle_type, maximum_bytes, std::nullopt};
        }
        const auto text = require_value(upper);
        try {
            size_t parsed = 0;
            const auto number = is_float ? static_cast<double>(std::stof(text, &parsed)) : std::stod(text, &parsed);
            if (parsed != text.size() || !std::isfinite(number)) {
                throw BinderException("not a finite number");
            }
            return {oracle_type, maximum_bytes,
                    is_float ? oracle_scanner::EncodeOracleBinaryFloat(static_cast<float>(number))
                             : oracle_scanner::EncodeOracleBinaryDouble(number)};
        } catch (const std::exception &) {
            throw BinderException("%s %s %s must be a finite decimal value", function_name, upper, name);
        }
    }
    if (type_name == "cursor") {
        if (direction != BindDirection::OUT || !value.IsNull()) {
            throw BinderException("%s cursor %s must be OUT with NULL value", function_name, name);
        }
        return {oracle_scanner::ORACLE_WIRE_TYPE_CURSOR, 4, std::nullopt};
    }
    throw BinderException("%s type for %s must be number, varchar, date, timestamp, raw, float, double, or cursor",
                          function_name, name);
}

// Reads a query that returns text columns, bounded.
std::vector<std::vector<std::optional<std::vector<uint8_t>>>> ReadMetadataRows(OracleSession &session,
                                                                              const std::string &sql,
                                                                              const std::vector<OracleBind> &binds,
                                                                              size_t minimum_columns,
                                                                              const char *what) {
    std::vector<std::vector<std::optional<std::vector<uint8_t>>>> rows;
    auto cursor = TranslatingOracleErrors(what, [&] { return session.Query(sql, binds); });
    for (;;) {
        const auto batch = TranslatingOracleErrors(what, [&] { return cursor->Fetch(STANDARD_VECTOR_SIZE); });
        for (const auto &row : batch.rows) {
            if (row.size() < minimum_columns) {
                throw IOException("%s returned an incomplete row", what);
            }
            rows.push_back(row);
        }
        if (batch.exhausted || rows.size() > 4096) {
            break;
        }
    }
    cursor->Close();
    return rows;
}

std::vector<OracleCallableSignature> ResolveOracleCallables(OracleSession &session, const std::string &qualified_name) {
    const auto components = TranslatingOracleErrors("oracle callable name is invalid", [&] {
        return oracle_scanner::SplitOracleCallableName(qualified_name);
    });

    // One query per name, with the possible readings of a two-part name folded
    // into the predicate: `A.B` is either this schema's package A holding B, or
    // schema A's standalone B, and finding both is an ambiguity to report
    // rather than a choice to make.
    std::string predicate;
    std::vector<OracleBind> binds;
    const auto bind_text = [&](const std::string &value) {
        binds.push_back({std::to_string(binds.size() + 1), 1, BindDirection::IN,
                         std::vector<uint8_t>(value.begin(), value.end()), 0});
        return ":" + std::to_string(binds.size());
    };
    if (components.size() == 1) {
        predicate = "owner = USER AND package_name IS NULL AND object_name = " + bind_text(components[0]);
    } else if (components.size() == 2) {
        predicate = "(owner = USER AND package_name = " + bind_text(components[0]) +
                    " AND object_name = " + bind_text(components[1]) + ") OR (owner = " + bind_text(components[0]) +
                    " AND package_name IS NULL AND object_name = " + bind_text(components[1]) + ")";
    } else {
        predicate = "owner = " + bind_text(components[0]) + " AND package_name = " + bind_text(components[1]) +
                    " AND object_name = " + bind_text(components[2]);
    }
    const auto sql = "SELECT owner, package_name, object_name, overload, position, argument_name, data_type, "
                     "in_out, data_level FROM all_arguments WHERE (" +
                     predicate + ") ORDER BY owner, package_name, object_name, overload, sequence";

    constexpr auto reading = "oracle callable metadata could not be read";
    auto rows = ReadMetadataRows(session, sql, binds, 9, reading);
    if (rows.empty() && components.size() < 3) {
        // ALL_ARGUMENTS stores the object's real owner, and a name reached
        // through a synonym does not carry it — which is every DBMS_ package,
        // where the row says SYS and the caller wrote DBMS_UTILITY. Resolving
        // the leading component through ALL_SYNONYMS is what turns the name the
        // caller can actually use into the name the dictionary indexes.
        std::vector<OracleBind> synonym_binds {
            {"1", 1, BindDirection::IN, std::vector<uint8_t>(components[0].begin(), components[0].end()), 0}};
        const auto synonym_rows = ReadMetadataRows(
            session,
            "SELECT table_owner, table_name FROM all_synonyms WHERE synonym_name = :1 AND owner IN (USER, 'PUBLIC') "
            "AND table_owner IS NOT NULL ORDER BY DECODE(owner, USER, 0, 1)",
            synonym_binds, 2, reading);
        if (!synonym_rows.empty()) {
            const auto synonym_owner = TextOf(synonym_rows.front()[0]);
            const auto synonym_object = TextOf(synonym_rows.front()[1]);
            std::vector<OracleBind> retry_binds;
            const auto bind_retry = [&](const std::string &value) {
                retry_binds.push_back({std::to_string(retry_binds.size() + 1), 1, BindDirection::IN,
                                       std::vector<uint8_t>(value.begin(), value.end()), 0});
                return ":" + std::to_string(retry_binds.size());
            };
            std::string retry_predicate;
            if (components.size() == 1) {
                retry_predicate = "owner = " + bind_retry(synonym_owner) + " AND package_name IS NULL AND object_name = " +
                                  bind_retry(synonym_object);
            } else {
                retry_predicate = "owner = " + bind_retry(synonym_owner) + " AND package_name = " +
                                  bind_retry(synonym_object) + " AND object_name = " + bind_retry(components[1]);
            }
            const auto retry_sql =
                "SELECT owner, package_name, object_name, overload, position, argument_name, data_type, "
                "in_out, data_level FROM all_arguments WHERE (" +
                retry_predicate + ") ORDER BY owner, package_name, object_name, overload, sequence";
            rows = ReadMetadataRows(session, retry_sql, retry_binds, 9, reading);
        }
    }
    if (rows.empty()) {
        throw BinderException("Oracle callable '%s' was not found, or the connected user cannot see it. A procedure "
                              "with no arguments has no ALL_ARGUMENTS rows either.",
                              qualified_name);
    }

    const auto owner = TextOf(rows.front()[0]);
    const auto package = TextOf(rows.front()[1]);
    const auto object = TextOf(rows.front()[2]);
    for (const auto &row : rows) {
        if (TextOf(row[0]) != owner || TextOf(row[1]) != package || TextOf(row[2]) != object) {
            // Two different objects answering to one name is an ambiguity the
            // caller can fix by qualifying it. An overload is not: only the
            // argument list can settle that, so overloads are all returned.
            throw BinderException("Oracle callable '%s' matches more than one object; qualify it with its owner",
                                  qualified_name);
        }
    }

    std::vector<OracleCallableSignature> overloads;
    std::string current_overload;
    for (const auto &row : rows) {
        const auto row_overload = TextOf(row[3]);
        if (overloads.empty() || row_overload != current_overload) {
            current_overload = row_overload;
            OracleCallableSignature next;
            next.owner = owner;
            next.package = package;
            next.object = object;
            next.overload = row_overload;
            overloads.push_back(std::move(next));
        }
        auto &signature = overloads.back();
        OracleCallableArgument argument;
        argument.position = static_cast<int32_t>(IntegerOf(row[4], "POSITION"));
        argument.name = TextOf(row[5]);
        argument.dictionary_type = TextOf(row[6]);
        const auto direction = TextOf(row[7]);
        const auto data_level = IntegerOf(row[8], "DATA_LEVEL");
        if (argument.position == 0) {
            // Position zero is a function's return value; it is always OUT and
            // it has no name of its own.
            signature.is_function = true;
            argument.direction = BindDirection::OUT;
            argument.name = "return_value";
        } else if (direction == "IN") {
            argument.direction = BindDirection::IN;
        } else if (direction == "OUT") {
            argument.direction = BindDirection::OUT;
        } else if (direction == "IN/OUT") {
            argument.direction = BindDirection::IN_OUT;
        } else {
            argument.unsupported_reason = "the dictionary reports direction '" + direction + "'";
        }
        if (data_level > 0) {
            // This row describes a component of a composite argument, not an
            // argument. The argument itself is the row above it at level zero,
            // whose own type — TABLE, OBJECT, PL/SQL RECORD — is what the
            // support policy refuses; counting its components as arguments
            // would shift every position after them.
            continue;
        }
        if (argument.unsupported_reason.empty()) {
            BindableType bindable {};
            if (BindableFor(argument.dictionary_type, bindable)) {
                argument.oracle_type = bindable.oracle_type;
                argument.maximum_bytes = bindable.maximum_bytes;
                argument.bind_type_name = bindable.bind_type_name;
                if (argument.oracle_type == oracle_scanner::ORACLE_WIRE_TYPE_CURSOR &&
                    argument.direction == BindDirection::IN) {
                    argument.oracle_type = 0;
                    argument.bind_type_name.clear();
                    argument.unsupported_reason = "a REF CURSOR argument can only be OUT";
                }
            } else {
                argument.unsupported_reason = UnsupportedReason(argument.dictionary_type);
            }
        }
        if (argument.name.empty()) {
            // A positional argument of a standalone procedure can be unnamed in
            // the dictionary; the call block binds by name, so give it one.
            argument.name = "arg" + std::to_string(argument.position);
        }
        signature.arguments.push_back(std::move(argument));
    }
    return overloads;
}

const OracleCallableSignature &SelectOracleCallableOverload(const std::vector<OracleCallableSignature> &overloads,
                                                            size_t input_count, const std::string &qualified_name) {
    const OracleCallableSignature *chosen = nullptr;
    std::string available;
    for (const auto &candidate : overloads) {
        if (!available.empty()) {
            available += ", ";
        }
        available += std::to_string(candidate.InputCount());
        if (candidate.InputCount() != input_count) {
            continue;
        }
        if (chosen) {
            // Two overloads of the same arity differ only in their argument
            // types, and nothing in a list of values says which was meant.
            throw BinderException(
                "Oracle callable '%s' has more than one overload taking %llu arguments; this version cannot "
                "choose between them",
                qualified_name, static_cast<uint64_t>(input_count));
        }
        chosen = &candidate;
    }
    if (!chosen) {
        throw BinderException("Oracle callable '%s' takes %s arguments, not %llu", qualified_name, available,
                              static_cast<uint64_t>(input_count));
    }
    return *chosen;
}

} // namespace duckdb

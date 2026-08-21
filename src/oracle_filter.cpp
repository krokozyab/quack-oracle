// Translating DuckDB table filters into an Oracle WHERE clause.
//
// The contract this has to meet is strict: DuckDB removes a filter from the
// plan once it hands it to the scan, so whatever arrives here must be applied,
// and applying it means translating it exactly. A filter whose Oracle meaning
// is not provably identical is therefore refused rather than approximated,
// because approximating it silently changes the answer.
//
// The proven subset and the reasons for each exclusion are in
// DUCKDB_POSTGRES_IDEAS.md and repeated at each refusal below.

#include "oracle_adapter.hpp"

#include "duckdb/common/types/time.hpp"
#include "duckdb/planner/filter/conjunction_filter.hpp"
#include "duckdb/planner/filter/constant_filter.hpp"
#include "duckdb/planner/filter/in_filter.hpp"
#include "duckdb/planner/filter/null_filter.hpp"
#include "duckdb/planner/filter/optional_filter.hpp"
#include "duckdb/planner/table_filter.hpp"

#include <cstdio>
#include <optional>
#include <string>

namespace duckdb {

namespace {

// Oracle refuses an expression list longer than 1,000 entries, so a longer one
// could not be sent even if every value were provable.
constexpr size_t MAX_IN_LIST_VALUES = 1000;

[[noreturn]] void Refuse(const std::string &reason) {
    throw NotImplementedException(
        "Oracle filter pushdown cannot translate %s. Run SET oracle_filter_pushdown = false to evaluate filters in "
        "DuckDB instead.",
        reason);
}

// Renders a constant as an Oracle literal, refusing anything whose Oracle
// meaning would differ from DuckDB's.
std::string OracleLiteral(const Value &constant, const OracleColumn &column) {
    if (constant.IsNull()) {
        // `col = NULL` is never true in Oracle and never true in DuckDB, but a
        // comparison against NULL should have been folded away long before
        // here; refusing keeps the translator from having to reason about it.
        Refuse("a comparison against NULL");
    }
    switch (constant.type().id()) {
    case LogicalTypeId::TINYINT:
    case LogicalTypeId::SMALLINT:
    case LogicalTypeId::INTEGER:
    case LogicalTypeId::BIGINT:
    case LogicalTypeId::HUGEINT:
    case LogicalTypeId::UTINYINT:
    case LogicalTypeId::USMALLINT:
    case LogicalTypeId::UINTEGER:
    case LogicalTypeId::UBIGINT:
    case LogicalTypeId::DECIMAL:
        // Oracle NUMBER is exact decimal and so is the DuckDB side, so the
        // literal round-trips and the comparison means the same thing.
        if (column.oracle_type != 2) {
            Refuse("a numeric constant compared against a column that is not NUMBER");
        }
        return constant.ToString();
    case LogicalTypeId::TIMESTAMP:
    case LogicalTypeId::TIMESTAMP_NS: {
        if (column.oracle_type != 12 && column.oracle_type != 180) {
            Refuse("a timestamp constant compared against a column that is not DATE or TIMESTAMP");
        }
        // TO_DATE and TO_TIMESTAMP with an explicit format carry no session
        // dependence at all: the format is in the statement, so NLS_DATE_FORMAT
        // cannot change what the literal means. That is what makes a date
        // pushable where a bare string is not.
        int32_t year;
        int32_t month;
        int32_t day;
        int32_t hour;
        int32_t minute;
        int32_t second;
        int32_t microseconds;
        int64_t nanoseconds = 0;
        if (constant.type().id() == LogicalTypeId::TIMESTAMP_NS) {
            const auto value = TimestampNSValue::Get(constant).value;
            auto whole = value / 1000;
            auto remainder = value % 1000;
            if (remainder < 0) {
                remainder += 1000;
                whole -= 1;
            }
            nanoseconds = remainder;
            const auto micros = timestamp_t(whole);
            if (!micros.IsFinite()) {
                Refuse("an infinite timestamp");
            }
            date_t date;
            dtime_t time;
            Timestamp::Convert(micros, date, time);
            Date::Convert(date, year, month, day);
            Time::Convert(time, hour, minute, second, microseconds);
        } else {
            const auto value = TimestampValue::Get(constant);
            if (!value.IsFinite()) {
                Refuse("an infinite timestamp");
            }
            date_t date;
            dtime_t time;
            Timestamp::Convert(value, date, time);
            Date::Convert(date, year, month, day);
            Time::Convert(time, hour, minute, second, microseconds);
        }
        if (year < 1 || year > 9999) {
            Refuse("a timestamp outside the years Oracle's four-digit literal can name");
        }
        char rendered[40];
        if (column.oracle_type == 12) {
            if (microseconds != 0 || nanoseconds != 0) {
                // An Oracle DATE holds whole seconds, so no DATE value can
                // equal this constant and no boundary sits where it says.
                Refuse("a sub-second constant compared against a DATE column, which stores whole seconds");
            }
            std::snprintf(rendered, sizeof(rendered), "%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, minute,
                          second);
            return "TO_DATE('" + std::string(rendered) + "', 'YYYY-MM-DD HH24:MI:SS')";
        }
        std::snprintf(rendered, sizeof(rendered), "%04d-%02d-%02d %02d:%02d:%02d.%09lld", year, month, day, hour,
                      minute, second,
                      static_cast<long long>(static_cast<int64_t>(microseconds) * 1000 + nanoseconds));
        return "TO_TIMESTAMP('" + std::string(rendered) + "', 'YYYY-MM-DD HH24:MI:SS.FF9')";
    }
    case LogicalTypeId::VARCHAR: {
        const auto text = constant.ToString();
        if (text.empty()) {
            // Oracle stores '' as NULL, so `col = ''` matches nothing there
            // while DuckDB would match empty strings. The two are not the same
            // predicate and this one must not be sent.
            Refuse("a comparison against an empty string, which Oracle treats as NULL");
        }
        if (column.oracle_type == 12 || column.oracle_type == 180 || column.oracle_type == 181) {
            // A date column now reads back as a real TIMESTAMP, so a string
            // constant here is a comparison the query wrote against text and
            // Oracle would have to convert through NLS_DATE_FORMAT.
            Refuse("a text comparison on a date or timestamp column");
        }
        if (column.oracle_type != 1) {
            // CHAR is blank-padded in Oracle's comparison, so `c = 'ab'` also
            // matches a CHAR(4) holding 'ab  ' — but the value handed to DuckDB
            // is the padded one, so its own filter is on the padded string.
            Refuse("a string comparison against a column that is not VARCHAR2");
        }
        std::string literal = "'";
        for (const auto character : text) {
            if (character == '\'') {
                literal.push_back('\'');
            }
            if (character == '\0') {
                Refuse("a string constant containing a NUL");
            }
            literal.push_back(character);
        }
        literal.push_back('\'');
        return literal;
    }
    default:
        Refuse("a constant of type " + constant.type().ToString());
    }
}

std::string ComparisonOperator(ExpressionType comparison, const OracleColumn &column) {
    switch (comparison) {
    case ExpressionType::COMPARE_EQUAL:
        return "=";
    case ExpressionType::COMPARE_NOTEQUAL:
        return "<>";
    case ExpressionType::COMPARE_LESSTHAN:
    case ExpressionType::COMPARE_LESSTHANOREQUALTO:
    case ExpressionType::COMPARE_GREATERTHAN:
    case ExpressionType::COMPARE_GREATERTHANOREQUALTO:
        if (column.oracle_type != 2 && column.oracle_type != 12 && column.oracle_type != 180) {
            // Ordering of character values follows NLS_SORT and NLS_COMP, which
            // this client never negotiates, so a range comparison on text has
            // no provable meaning here. Equality does not depend on collation.
            // Chronological order does not depend on anything a session sets.
            Refuse("an ordered comparison on a column that is not NUMBER, DATE or TIMESTAMP");
        }
        switch (comparison) {
        case ExpressionType::COMPARE_LESSTHAN:
            return "<";
        case ExpressionType::COMPARE_LESSTHANOREQUALTO:
            return "<=";
        case ExpressionType::COMPARE_GREATERTHAN:
            return ">";
        default:
            return ">=";
        }
    default:
        Refuse("comparison " + ExpressionTypeToString(comparison));
    }
}

// Returns the translated predicate, or nothing when the filter is optional and
// could not be translated. An optional filter is a hint DuckDB does not rely on
// for correctness, so dropping one is allowed where dropping a required filter
// would change the answer.
std::optional<std::string> TranslateOptional(const TableFilter &filter, const OracleColumn &column,
                                             const std::string &quoted_name);

std::string TranslateFilter(const TableFilter &filter, const OracleColumn &column, const std::string &quoted_name) {
    switch (filter.filter_type) {
    case TableFilterType::OPTIONAL_FILTER: {
        // Reached only as a child of a required filter, where dropping it is
        // not allowed, so here it must translate or refuse like any other.
        const auto &optional = filter.Cast<OptionalFilter>();
        if (!optional.child_filter) {
            Refuse("an optional filter with no child");
        }
        return TranslateFilter(*optional.child_filter, column, quoted_name);
    }
    case TableFilterType::IS_NULL:
        // Identical in both engines.
        return quoted_name + " IS NULL";
    case TableFilterType::IS_NOT_NULL:
        return quoted_name + " IS NOT NULL";
    case TableFilterType::CONSTANT_COMPARISON: {
        const auto &comparison = filter.Cast<ConstantFilter>();
        const auto oracle_operator = ComparisonOperator(comparison.comparison_type, column);
        return quoted_name + " " + oracle_operator + " " + OracleLiteral(comparison.constant, column);
    }
    case TableFilterType::IN_FILTER: {
        // An IN list is a disjunction of equalities, and equality carries the
        // same proof: exact for NUMBER, collation-independent for VARCHAR2, and
        // refused for an empty string. Each value goes through the same literal
        // check, so a list containing one unprovable value refuses as a whole
        // rather than being partly applied.
        const auto &in_filter = filter.Cast<InFilter>();
        if (in_filter.values.empty()) {
            Refuse("an empty IN list");
        }
        if (in_filter.values.size() > MAX_IN_LIST_VALUES) {
            // Oracle's own limit on an expression list is 1000.
            Refuse("an IN list longer than " + std::to_string(MAX_IN_LIST_VALUES) + " values");
        }
        std::string list;
        for (const auto &value : in_filter.values) {
            if (!list.empty()) {
                list += ", ";
            }
            list += OracleLiteral(value, column);
        }
        return quoted_name + " IN (" + list + ")";
    }
    case TableFilterType::CONJUNCTION_AND:
    case TableFilterType::CONJUNCTION_OR: {
        const auto &conjunction = filter.filter_type == TableFilterType::CONJUNCTION_AND
                                      ? static_cast<const ConjunctionFilter &>(filter.Cast<ConjunctionAndFilter>())
                                      : static_cast<const ConjunctionFilter &>(filter.Cast<ConjunctionOrFilter>());
        const std::string separator = filter.filter_type == TableFilterType::CONJUNCTION_AND ? " AND " : " OR ";
        std::string result;
        for (const auto &child : conjunction.child_filters) {
            if (!result.empty()) {
                result += separator;
            }
            result += TranslateFilter(*child, column, quoted_name);
        }
        // An empty conjunction would silently become no predicate at all.
        if (result.empty()) {
            Refuse("an empty conjunction");
        }
        return "(" + result + ")";
    }
    default:
        Refuse("filter kind " + std::to_string(static_cast<int>(filter.filter_type)));
    }
}

std::optional<std::string> TranslateOptional(const TableFilter &filter, const OracleColumn &column,
                                             const std::string &quoted_name) {
    if (filter.filter_type != TableFilterType::OPTIONAL_FILTER) {
        return TranslateFilter(filter, column, quoted_name);
    }
    const auto &optional = filter.Cast<OptionalFilter>();
    if (!optional.child_filter) {
        return std::nullopt;
    }
    try {
        return TranslateFilter(*optional.child_filter, column, quoted_name);
    } catch (const NotImplementedException &) {
        // DuckDB does not need this one, so not sending it is correct rather
        // than merely convenient.
        return std::nullopt;
    }
}

} // namespace

std::string OracleWhereClause(const TableFilterSet &filters, const std::vector<OracleColumn> &columns,
                              const std::vector<column_t> &scanned_columns) {
    std::string predicate;
    for (const auto &entry : filters.filters) {
        if (entry.first >= scanned_columns.size()) {
            Refuse("a filter on a column this scan does not read");
        }
        const auto column_index = scanned_columns[entry.first];
        if (column_index >= columns.size()) {
            Refuse("a filter on a virtual column");
        }
        const auto &column = columns[column_index];
        // A column this client cannot read cannot be reasoned about either.
        RequireReadableColumn(column);
        const auto quoted_name = KeywordHelper::WriteQuoted(column.name, '"');
        const auto translated = TranslateOptional(*entry.second, column, quoted_name);
        if (!translated) {
            continue;
        }
        if (!predicate.empty()) {
            predicate += " AND ";
        }
        predicate += *translated;
    }
    return predicate;
}

} // namespace duckdb

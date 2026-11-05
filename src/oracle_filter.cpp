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
#include "duckdb/planner/expression/bound_comparison_expression.hpp"
#include "duckdb/planner/expression/bound_conjunction_expression.hpp"
#include "duckdb/planner/expression/bound_constant_expression.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "duckdb/planner/expression/bound_operator_expression.hpp"
#include "duckdb/planner/expression/bound_reference_expression.hpp"
#include "duckdb/planner/expression_iterator.hpp"
#include "duckdb/planner/filter/expression_filter.hpp"
#include "duckdb/planner/filter/table_filter_functions.hpp"
#include "duckdb/planner/table_filter.hpp"
#include "duckdb/planner/table_filter_set.hpp"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <optional>
#include <string>

namespace duckdb {

namespace {

// JSON paths. A native JSON column filtered with json_extract_string(col, '$.a.b')
// is not translated: DuckDB returns the text of whatever the path finds (a number
// as written in the document, an object as JSON text), and Oracle's JSON_VALUE
// returns its own rendering of a scalar and nothing for an object. What can be
// sent is a *superset*: a predicate Oracle makes true for every row DuckDB's is
// true for. The scan keeps DuckDB's filter and applies it to what comes back, so
// Oracle only has to leave out rows that cannot match, which is where the saving
// is, and the answer is DuckDB's.
bool SimpleJsonPath(const std::string &path) {
    if (path.size() < 2 || path[0] != '$') {
        return false;
    }
    size_t position = 1;
    while (position < path.size()) {
        if (path[position] == '.') {
            position++;
            const auto start = position;
            while (position < path.size() && (std::isalnum(static_cast<unsigned char>(path[position])) || path[position] == '_')) {
                position++;
            }
            if (position == start || std::isdigit(static_cast<unsigned char>(path[start]))) {
                return false;
            }
        } else if (path[position] == '[') {
            position++;
            const auto start = position;
            while (position < path.size() && std::isdigit(static_cast<unsigned char>(path[position]))) {
                position++;
            }
            if (position == start || position >= path.size() || path[position] != ']') {
                return false;
            }
            position++;
        } else {
            return false;
        }
    }
    return true;
}

// A string constant whose text no JSON number, literal, object or array can be
// written as, so that a value DuckDB renders as text equal to it is a JSON string
// and Oracle renders it the same way.
bool PlainJsonText(const std::string &text) {
    if (text.empty() || text.size() > 2000 || text == "true" || text == "false" || text == "null" ||
        text[0] == '{' || text[0] == '[') {
        return false;
    }
    if (text.find('\0') != std::string::npos) {
        return false;
    }
    char *end = nullptr;
    std::strtod(text.c_str(), &end);
    return end == text.c_str();
}

// The JSON path of a json_extract_string(column, 'path') call, or nothing.
std::optional<std::string> ExtractedPath(const Expression &expression) {
    if (expression.GetExpressionClass() != ExpressionClass::BOUND_FUNCTION) {
        return std::nullopt;
    }
    const auto &call = expression.Cast<BoundFunctionExpression>();
    const auto &name = call.Function().GetName().GetIdentifierName();
    if (name != "json_extract_string" && name != "->>") {
        return std::nullopt;
    }
    const auto &arguments = call.GetChildren();
    if (arguments.size() != 2 || arguments[0]->GetExpressionClass() != ExpressionClass::BOUND_REF ||
        arguments[0]->Cast<BoundReferenceExpression>().Index() != 0 ||
        arguments[1]->GetExpressionClass() != ExpressionClass::BOUND_CONSTANT) {
        return std::nullopt;
    }
    const auto &path = arguments[1]->Cast<BoundConstantExpression>().GetValue();
    if (path.IsNull() || path.type().id() != LogicalTypeId::VARCHAR || !SimpleJsonPath(path.ToString())) {
        return std::nullopt;
    }
    return path.ToString();
}

std::string JsonStringLiteral(const std::string &text) {
    std::string literal = "'";
    for (const auto character : text) {
        literal += character == '\'' ? std::string("''") : std::string(1, character);
    }
    return literal + "'";
}

std::optional<std::string> JsonPrefilter(const Expression &piece, const OracleColumn &column,
                                         const std::string &quoted_name) {
    if (column.oracle_type != 119) {
        return std::nullopt;
    }
    const auto value_of = [&](const std::string &path) {
        return "JSON_VALUE(" + quoted_name + ", " + JsonStringLiteral(path) + " RETURNING VARCHAR2(4000) NULL ON ERROR)";
    };
    if (BoundComparisonExpression::IsComparison(piece) && piece.GetExpressionType() == ExpressionType::COMPARE_EQUAL) {
        const auto &comparison = piece.Cast<BoundFunctionExpression>();
        const auto path = ExtractedPath(BoundComparisonExpression::Left(comparison));
        const auto &right = BoundComparisonExpression::Right(comparison);
        if (!path || right.GetExpressionClass() != ExpressionClass::BOUND_CONSTANT) {
            return std::nullopt;
        }
        const auto &constant = right.Cast<BoundConstantExpression>().GetValue();
        if (constant.IsNull() || constant.type().id() != LogicalTypeId::VARCHAR || !PlainJsonText(constant.ToString())) {
            return std::nullopt;
        }
        return value_of(*path) + " = " + JsonStringLiteral(constant.ToString());
    }
    if (piece.GetExpressionClass() == ExpressionClass::BOUND_CONJUNCTION &&
        piece.GetExpressionType() == ExpressionType::CONJUNCTION_OR) {
        // An IN list arrives as a disjunction of equalities: narrowed only if every
        // branch is, since one branch left out would drop rows it matches.
        std::string joined;
        for (const auto &child : piece.Cast<BoundConjunctionExpression>().GetChildren()) {
            const auto branch = JsonPrefilter(*child, column, quoted_name);
            if (!branch) {
                return std::nullopt;
            }
            joined += (joined.empty() ? "" : " OR ") + *branch;
        }
        return "(" + joined + ")";
    }
    if (piece.GetExpressionClass() == ExpressionClass::BOUND_OPERATOR) {
        const auto &op = piece.Cast<BoundOperatorExpression>();
        const auto &children = op.GetChildren();
        if (op.GetExpressionType() == ExpressionType::OPERATOR_IS_NOT_NULL && children.size() == 1) {
            const auto path = ExtractedPath(*children[0]);
            if (path) {
                // True for a null, an object and an array too, which DuckDB's test also is for the last two.
                return "JSON_EXISTS(" + quoted_name + ", " + JsonStringLiteral(*path) + ")";
            }
        }
        if (op.GetExpressionType() == ExpressionType::COMPARE_IN && children.size() >= 2 && children.size() <= 1001) {
            const auto path = ExtractedPath(*children[0]);
            if (!path) {
                return std::nullopt;
            }
            std::string list;
            for (size_t index = 1; index < children.size(); index++) {
                if (children[index]->GetExpressionClass() != ExpressionClass::BOUND_CONSTANT) {
                    return std::nullopt;
                }
                const auto &constant = children[index]->Cast<BoundConstantExpression>().GetValue();
                if (constant.IsNull() || constant.type().id() != LogicalTypeId::VARCHAR ||
                    !PlainJsonText(constant.ToString())) {
                    return std::nullopt;
                }
                list += (list.empty() ? "" : ", ") + JsonStringLiteral(constant.ToString());
            }
            return value_of(*path) + " IN (" + list + ")";
        }
    }
    return std::nullopt;
}

// Oracle refuses an expression list longer than 1,000 entries, so a longer one
// could not be sent even if every value were provable.
constexpr size_t MAX_IN_LIST_VALUES = 1000;
// How many values an IN list may carry in all, as several lists of the size above.
constexpr size_t MAX_IN_VALUES = 16384;

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
        if (OracleColumnRoundsOnRead(column)) {
            // DuckDB compares the rounded value it read and Oracle the stored
            // one: under decimal(10,1), 1.21 > 1.2 holds there and not here.
            Refuse("a comparison on a NUMBER that oracle_unconstrained_number rounds when it is read");
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
        if (column.character_set_form == 2) {
            // An NVARCHAR2 compares in the national character set, and the
            // literal would have to be converted into it; that conversion is
            // not one this translator has shown to be the same predicate.
            Refuse("a string comparison against a national character set column");
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

// DuckDB 2.0 hands a scan one kind of filter: an ExpressionFilter wrapping a
// bound expression tree. The legacy filter classes still exist, but
// LogicalGet converts every one of them to an expression before a scan ever
// sees it, so there is exactly one input shape to translate and it is this one.
//
// The shapes the planner produces for the predicates this translator accepts,
// taken from how each legacy filter's ToExpression builds them:
//
//   col = C            BoundFunctionExpression whose GetExpressionType() is a
//                      COMPARE_*; operands via BoundComparisonExpression::Left/Right
//   col IS [NOT] NULL  BoundOperatorExpression(OPERATOR_IS_[NOT_]NULL) with one child
//   col IN (C, ...)    BoundOperatorExpression(COMPARE_IN), children [col, C, C, ...]
//   a AND b / a OR b   BoundConjunctionExpression
//   optional(f)        BoundFunctionExpression named OptionalFilterScalarFun::NAME,
//                      the real filter in its BindInfo()->child_filter_expr
//
// The column itself is a BoundReferenceExpression. A single-column filter
// refers to index 0; anything else is a multi-column filter this translator
// does not attempt.

bool IsOptionalWrapper(const Expression &expression) {
    if (expression.GetExpressionClass() != ExpressionClass::BOUND_FUNCTION) {
        return false;
    }
    const auto &name = expression.Cast<BoundFunctionExpression>().Function().GetName();
    return name == OptionalFilterScalarFun::NAME || name == SelectivityOptionalFilterScalarFun::NAME;
}

// The expression an optional wrapper carries, or null when it carries none.
const Expression *OptionalChild(const Expression &expression) {
    const auto &function = expression.Cast<BoundFunctionExpression>();
    if (!function.BindInfo()) {
        return nullptr;
    }
    const auto &name = function.Function().GetName();
    if (name == OptionalFilterScalarFun::NAME) {
        return function.BindInfo()->Cast<OptionalFilterFunctionData>().child_filter_expr.get();
    }
    return function.BindInfo()->Cast<SelectivityOptionalFilterFunctionData>().child_filter_expr.get();
}

void RequireColumnReference(const Expression &expression) {
    if (expression.GetExpressionClass() != ExpressionClass::BOUND_REF) {
        Refuse("a predicate whose subject is not the column itself");
    }
    if (expression.Cast<BoundReferenceExpression>().Index() != 0) {
        // A filter over several columns binds them as references 0, 1, ...;
        // this translator is handed one column and proves things about that
        // column only.
        Refuse("a predicate over more than one column");
    }
}

const Value &RequireConstant(const Expression &expression) {
    if (expression.GetExpressionClass() != ExpressionClass::BOUND_CONSTANT) {
        Refuse("a comparison against something other than a constant");
    }
    return expression.Cast<BoundConstantExpression>().GetValue();
}

std::string TranslateExpression(const Expression &expression, const OracleColumn &column,
                                const std::string &quoted_name);

std::string TranslateComparison(const BoundFunctionExpression &comparison, const OracleColumn &column,
                                const std::string &quoted_name) {
    const auto &left = BoundComparisonExpression::Left(comparison);
    const auto &right = BoundComparisonExpression::Right(comparison);
    // The planner puts the column on the left for a pushed filter. A constant
    // on the left would need the operator flipped, and nothing observed
    // produces that shape, so it is refused rather than guessed at.
    RequireColumnReference(left);
    const auto &constant = RequireConstant(right);
    const auto oracle_operator = ComparisonOperator(comparison.GetExpressionType(), column);
    return quoted_name + " " + oracle_operator + " " + OracleLiteral(constant, column);
}

std::string TranslateExpression(const Expression &expression, const OracleColumn &column,
                                const std::string &quoted_name) {
    if (IsOptionalWrapper(expression)) {
        // Reached only beneath a required predicate, where dropping it is not
        // allowed, so here it must translate or refuse like any other.
        const auto *child = OptionalChild(expression);
        if (!child) {
            Refuse("an optional filter with no child");
        }
        return TranslateExpression(*child, column, quoted_name);
    }
    switch (expression.GetExpressionClass()) {
    case ExpressionClass::BOUND_FUNCTION: {
        if (!BoundComparisonExpression::IsComparison(expression)) {
            Refuse("a function call");
        }
        return TranslateComparison(expression.Cast<BoundFunctionExpression>(), column, quoted_name);
    }
    case ExpressionClass::BOUND_OPERATOR: {
        const auto &op = expression.Cast<BoundOperatorExpression>();
        const auto &children = op.GetChildren();
        switch (op.GetExpressionType()) {
        case ExpressionType::OPERATOR_IS_NULL:
        case ExpressionType::OPERATOR_IS_NOT_NULL:
            if (children.size() != 1) {
                Refuse("a malformed null test");
            }
            RequireColumnReference(*children[0]);
            // Identical in both engines.
            return quoted_name +
                   (op.GetExpressionType() == ExpressionType::OPERATOR_IS_NULL ? " IS NULL" : " IS NOT NULL");
        case ExpressionType::COMPARE_IN: {
            // An IN list is a disjunction of equalities, and equality carries
            // the same proof: exact for NUMBER, collation-independent for
            // VARCHAR2, and refused for an empty string. Each value goes
            // through the same literal check, so a list containing one
            // unprovable value refuses as a whole rather than being partly
            // applied.
            if (children.size() < 2) {
                Refuse("an empty IN list");
            }
            RequireColumnReference(*children[0]);
            if (children.size() - 1 > MAX_IN_VALUES) {
                Refuse("an IN list longer than " + std::to_string(MAX_IN_VALUES) + " values");
            }
            // Oracle refuses more than 1000 entries in one list, so a longer one is
            // sent as a disjunction of lists, which is the same predicate.
            std::string result;
            std::string list;
            size_t in_list = 0;
            const auto flush = [&] {
                if (in_list > 0) {
                    result += (result.empty() ? "" : " OR ") + quoted_name + " IN (" + list + ")";
                }
                list.clear();
                in_list = 0;
            };
            for (size_t index = 1; index < children.size(); index++) {
                if (in_list == MAX_IN_LIST_VALUES) {
                    flush();
                }
                list += (in_list == 0 ? "" : ", ") + OracleLiteral(RequireConstant(*children[index]), column);
                in_list++;
            }
            flush();
            return children.size() - 1 > MAX_IN_LIST_VALUES ? "(" + result + ")" : result;
        }
        default:
            Refuse("operator " + ExpressionTypeToString(op.GetExpressionType()));
        }
    }
    case ExpressionClass::BOUND_CONJUNCTION: {
        const auto &conjunction = expression.Cast<BoundConjunctionExpression>();
        const std::string separator =
            conjunction.GetExpressionType() == ExpressionType::CONJUNCTION_AND ? " AND " : " OR ";
        std::string result;
        for (const auto &child : conjunction.GetChildren()) {
            if (!result.empty()) {
                result += separator;
            }
            result += TranslateExpression(*child, column, quoted_name);
        }
        // An empty conjunction would silently become no predicate at all.
        if (result.empty()) {
            Refuse("an empty conjunction");
        }
        return "(" + result + ")";
    }
    default:
        Refuse("expression class " + ExpressionClassToString(expression.GetExpressionClass()));
    }
}

// A join's build side reaches a scan as a prefix-range filter: a bitmap over the
// span of the keys, which cannot be written as SQL as it is but can be asked
// whether any key lies in a range. Asking it that, and halving the ranges that
// say yes, recovers the key ranges as intervals — exactly, when there are few
// enough, and as a superset otherwise. A superset is all an optional filter
// needs, and Oracle then reads only those ranges instead of the table.
constexpr size_t MAX_KEY_INTERVALS = 2048;
constexpr size_t MAX_RANGE_QUESTIONS = 16384;

// The middle of two int64 values without computing their sum or difference, which for
// the ends of the BIGINT domain overflows: signed overflow is undefined, and it made the
// search below loop forever under GCC while Clang happened to wrap.
int64_t FloorMidpoint(int64_t a, int64_t b) {
    return (a & b) + ((a ^ b) >> 1);
}

int64_t CeilMidpoint(int64_t a, int64_t b) {
    return FloorMidpoint(a, b) + ((a ^ b) & 1);
}

std::optional<std::string> PrefixRangeSql(const BoundFunctionExpression &function, const OracleColumn &column,
                                          const std::string &quoted_name) {
    if (function.Function().GetName() != PrefixRangeScalarFun::NAME || !function.BindInfo() ||
        function.GetChildren().size() != 1 || function.GetChildren()[0]->GetExpressionClass() != ExpressionClass::BOUND_REF) {
        return std::nullopt;
    }
    const auto &data = function.BindInfo()->Cast<PrefixRangeFunctionData>();
    if (!data.filter || !data.filter->IsInitialized()) {
        return std::nullopt;
    }
    int64_t domain_low;
    int64_t domain_high;
    switch (data.key_type.id()) {
    case LogicalTypeId::TINYINT:
        domain_low = NumericLimits<int8_t>::Minimum();
        domain_high = NumericLimits<int8_t>::Maximum();
        break;
    case LogicalTypeId::SMALLINT:
        domain_low = NumericLimits<int16_t>::Minimum();
        domain_high = NumericLimits<int16_t>::Maximum();
        break;
    case LogicalTypeId::INTEGER:
        domain_low = NumericLimits<int32_t>::Minimum();
        domain_high = NumericLimits<int32_t>::Maximum();
        break;
    case LogicalTypeId::BIGINT:
        domain_low = NumericLimits<int64_t>::Minimum();
        domain_high = NumericLimits<int64_t>::Maximum();
        break;
    default:
        return std::nullopt;
    }
    size_t questions = 0;
    const auto may_hold = [&](int64_t low, int64_t high) {
        questions++;
        return data.filter->LookupRange(Value::Numeric(data.key_type, low), Value::Numeric(data.key_type, high)) !=
               FilterPropagateResult::FILTER_ALWAYS_FALSE;
    };
    if (!may_hold(domain_low, domain_high)) {
        return std::nullopt;
    }
    // The smallest and the largest key: the first point from which every range
    // up to the top (or down from the bottom) still holds one.
    int64_t low = domain_low;
    int64_t high = domain_high;
    {
        int64_t lo = domain_low;
        int64_t hi = domain_high;
        while (lo < hi) {
            const int64_t mid = CeilMidpoint(lo, hi);
            if (may_hold(mid, domain_high)) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        high = lo; // the largest x such that [x, top] holds a key is the largest key
    }
    {
        int64_t lo = domain_low;
        int64_t hi = domain_high;
        while (lo < hi) {
            const int64_t mid = FloorMidpoint(lo, hi);
            if (may_hold(domain_low, mid)) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        low = lo;
    }
    std::vector<std::pair<int64_t, int64_t>> intervals {{low, high}};
    for (;;) {
        // One level: halve every interval that has more than one point, and
        // keep the halves that may hold a key. Stop before the list outgrows
        // what is worth sending, or when nothing is left to halve.
        std::vector<std::pair<int64_t, int64_t>> next;
        bool split_any = false;
        bool over_budget = false;
        for (const auto &interval : intervals) {
            if (interval.first == interval.second) {
                next.push_back(interval);
                continue;
            }
            split_any = true;
            const int64_t mid = FloorMidpoint(interval.first, interval.second);
            if (questions + 2 > MAX_RANGE_QUESTIONS) {
                over_budget = true;
                break;
            }
            if (may_hold(interval.first, mid)) {
                next.emplace_back(interval.first, mid);
            }
            if (may_hold(mid + 1, interval.second)) {
                next.emplace_back(mid + 1, interval.second);
            }
        }
        if (over_budget || next.size() > MAX_KEY_INTERVALS) {
            break;
        }
        intervals = std::move(next);
        if (!split_any) {
            break;
        }
    }
    // Neighbours that touch are one range.
    std::vector<std::pair<int64_t, int64_t>> merged;
    for (const auto &interval : intervals) {
        if (!merged.empty() && merged.back().second != NumericLimits<int64_t>::Maximum() &&
            merged.back().second + 1 == interval.first) {
            merged.back().second = interval.second;
        } else {
            merged.push_back(interval);
        }
    }
    const auto literal = [&](int64_t value) { return OracleLiteral(Value::BIGINT(value), column); };
    // Single keys go in IN lists, as many to a list as Oracle allows; runs of
    // keys are BETWEEN ranges.
    std::vector<std::string> terms;
    std::string list;
    size_t in_list_size = 0;
    const auto flush_list = [&] {
        if (in_list_size > 0) {
            terms.push_back(quoted_name + (in_list_size == 1 ? " = " + list : " IN (" + list + ")"));
        }
        list.clear();
        in_list_size = 0;
    };
    for (const auto &interval : merged) {
        if (interval.first == interval.second) {
            if (in_list_size == MAX_IN_LIST_VALUES) {
                flush_list();
            }
            list += (in_list_size == 0 ? "" : ", ") + literal(interval.first);
            in_list_size++;
        } else {
            terms.push_back(quoted_name + " BETWEEN " + literal(interval.first) + " AND " + literal(interval.second));
        }
    }
    flush_list();
    std::string sql;
    for (const auto &term : terms) {
        sql += (sql.empty() ? "" : " OR ") + term;
    }
    return terms.size() == 1 ? sql : "(" + sql + ")";
}

// One conjunct of a filter, translated, or nothing when it is an optional hint
// that could not be. A required conjunct that cannot be translated refuses.
std::optional<std::string> TranslatePiece(const Expression &expression, const OracleColumn &column,
                                          const std::string &quoted_name) {
    if (!IsOptionalWrapper(expression)) {
        return TranslateExpression(expression, column, quoted_name);
    }
    const auto *child = OptionalChild(expression);
    if (!child) {
        return std::nullopt;
    }
    if (child->GetExpressionClass() == ExpressionClass::BOUND_FUNCTION) {
        if (const auto ranges = PrefixRangeSql(child->Cast<BoundFunctionExpression>(), column, quoted_name)) {
            return ranges;
        }
    }
    try {
        return TranslateExpression(*child, column, quoted_name);
    } catch (const NotImplementedException &) {
        // DuckDB does not need this one, so not sending it is correct rather
        // than merely convenient.
        return std::nullopt;
    }
}

// Returns the translated predicate, or nothing when the filter is optional and
// could not be translated. An optional filter is a hint DuckDB does not rely on
// for correctness, so dropping one is allowed where dropping a required filter
// would change the answer.
std::optional<std::string> TranslateOptional(const TableFilter &filter, const OracleColumn &column,
                                             const std::string &quoted_name) {
    if (filter.filter_type != TableFilterType::EXPRESSION_FILTER) {
        // LogicalGet converts every legacy filter before a scan sees it, so
        // one arriving here is a planner path this code has not met.
        Refuse("a filter that is not an expression (kind " + std::to_string(static_cast<int>(filter.filter_type)) +
               ")");
    }
    return TranslatePiece(*filter.Cast<ExpressionFilter>().expr, column, quoted_name);
}

} // namespace

namespace {

// A filter as an expression over the scan's output chunk, for the filters that
// are not sent to Oracle. The filter was written over a placeholder column
// (index 0), or for a multi-column filter over indexes that column_indexes maps
// to the scan's projection; either way they become positions in the output.
unique_ptr<Expression> LocalExpression(const ExpressionFilter &filter, const Expression &source, bool multi_column,
                                       idx_t projection) {
    auto expression = source.Copy();
    ExpressionIterator::EnumerateExpression(expression, [&](unique_ptr<Expression> &node) {
        if (node->GetExpressionClass() != ExpressionClass::BOUND_REF) {
            return;
        }
        const auto &reference = node->Cast<BoundReferenceExpression>();
        const auto position = multi_column ? filter.column_indexes.at(reference.Index()).GetIndex() : projection;
        node = make_uniq<BoundReferenceExpression>(reference.GetReturnType(), position);
    });
    return expression;
}

} // namespace

// Whether DuckDB may hand the scan this expression as a filter on one column. Only
// tests of a JSON path are asked for: the scan narrows them in Oracle where it can
// (JsonPrefilter) and always applies the expression itself, so a shape it cannot
// narrow costs nothing but the pushdown.
bool OraclePushdownExpression(ClientContext &, const LogicalGet &, Expression &expression) {
    bool json_path = false;
    std::function<void(const Expression &)> visit = [&](const Expression &node) {
        if (node.GetExpressionClass() == ExpressionClass::BOUND_FUNCTION) {
            const auto &name = node.Cast<BoundFunctionExpression>().Function().GetName().GetIdentifierName();
            if (name == "json_extract_string" || name == "->>") {
                json_path = true;
            }
        }
        ExpressionIterator::EnumerateChildren(node, [&](const Expression &child) { visit(child); });
    };
    visit(expression);
    return json_path;
}

OracleFilterSplit SplitOracleFilters(const TableFilterSet &filters, const std::vector<OracleColumn> &columns,
                                     const std::vector<column_t> &scanned_columns) {
    OracleFilterSplit result;
    // What Oracle is not sent, DuckDB's own expression evaluates over the rows
    // that come back. That is what makes a refusal here cost speed and nothing
    // else: DuckDB has already taken the filter out of its plan, and the scan
    // applies it instead.
    for (const auto &filter : filters.GetMultiColumnFilters()) {
        if (filter->filter_type != TableFilterType::EXPRESSION_FILTER) {
            Refuse("a filter that is not an expression");
        }
        result.local.push_back(
            LocalExpression(filter->Cast<ExpressionFilter>(), *filter->Cast<ExpressionFilter>().expr, true, 0));
    }
    for (const auto &entry : filters) {
        const auto projection = entry.GetIndex().GetIndex();
        if (projection >= scanned_columns.size()) {
            Refuse("a filter on a column this scan does not read");
        }
        const auto column_index = scanned_columns[projection];
        const auto &filter = entry.Filter();
        if (filter.filter_type != TableFilterType::EXPRESSION_FILTER) {
            Refuse("a filter that is not an expression");
        }
        const auto &expression_filter = filter.Cast<ExpressionFilter>();
        // A filter that is an AND of conjuncts is taken one conjunct at a time.
        // A join hands the scan its key range, an IN list and a bloom filter
        // that way, all optional: the ones Oracle can be sent go, the rest are
        // dropped, and a required conjunct that cannot be sent is evaluated here.
        std::vector<const Expression *> pieces;
        std::function<void(const Expression &)> flatten = [&](const Expression &expression) {
            if (expression.GetExpressionClass() == ExpressionClass::BOUND_CONJUNCTION &&
                expression.GetExpressionType() == ExpressionType::CONJUNCTION_AND) {
                for (const auto &child : expression.Cast<BoundConjunctionExpression>().GetChildren()) {
                    flatten(*child);
                }
            } else {
                pieces.push_back(&expression);
            }
        };
        flatten(*expression_filter.expr);
        for (const auto *piece : pieces) {
            std::optional<std::string> translated;
            bool local = false;
            if (column_index >= columns.size()) {
                local = true; // the ROWID pseudo-column
            } else {
                const auto &column = columns[column_index];
                // A column this client cannot read cannot be reasoned about either.
                RequireReadableColumn(column);
                const auto quoted_name = KeywordHelper::WriteQuotedAndEscaped(column.name, '"');
                try {
                    translated = TranslatePiece(*piece, column, quoted_name);
                } catch (const NotImplementedException &) {
                    local = true;
                }
            }
            if (local && column_index < columns.size()) {
                // A JSON path test Oracle can narrow but not decide: the narrower
                // predicate goes to Oracle and the real one stays here.
                if (const auto narrowed =
                        JsonPrefilter(*piece, columns[column_index],
                                      KeywordHelper::WriteQuotedAndEscaped(columns[column_index].name, '"'))) {
                    result.where += (result.where.empty() ? "" : " AND ") + *narrowed;
                }
            }
            if (local) {
                // An optional filter is a hint DuckDB does not rely on.
                if (!IsOptionalWrapper(*piece)) {
                    result.local.push_back(LocalExpression(expression_filter, *piece, false, projection));
                }
                continue;
            }
            if (!translated) {
                continue;
            }
            if (!result.where.empty()) {
                result.where += " AND ";
            }
            result.where += *translated;
        }
    }
    return result;
}

std::string OracleWhereClause(const TableFilterSet &filters, const std::vector<OracleColumn> &columns,
                              const std::vector<column_t> &scanned_columns) {
    // The strict form: what cannot be translated is an error rather than left
    // for the scan. It is the translator's contract, kept testable on its own.
    const auto strict = [&]() {
        for (const auto &entry : filters) {
            const auto projection = entry.GetIndex().GetIndex();
            if (projection >= scanned_columns.size() || scanned_columns[projection] >= columns.size()) {
                Refuse("a filter on a column this scan does not read");
            }
            const auto &column = columns[scanned_columns[projection]];
            RequireReadableColumn(column);
            (void)TranslateOptional(entry.Filter(), column, KeywordHelper::WriteQuotedAndEscaped(column.name, '"'));
        }
        if (filters.HasMultiColumnFilters()) {
            Refuse("a predicate over more than one column");
        }
    };
    strict();
    return SplitOracleFilters(filters, columns, scanned_columns).where;
}

} // namespace duckdb

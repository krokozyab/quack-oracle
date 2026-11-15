// Plan rewrites for an attached Oracle table, before and after DuckDB optimizers.
//
// Top-N. `SELECT ... FROM o.T ORDER BY k LIMIT n` plans as a TOP_N over the
// scan, and the scan reads the whole table. When every sort key is a column the
// scan reads and Oracle orders it exactly as DuckDB does, the scan can ask for
// `ORDER BY k FETCH FIRST n ROWS ONLY` and read n rows. The TOP_N stays in the
// plan, which is what keeps this safe: DuckDB sorts what comes back and keeps the
// first n again, so Oracle only has to return rows that include the true first
// n, and ties at the boundary are the ties any ORDER BY ... LIMIT leaves open.
//
// What "orders it exactly as DuckDB does" is limited on purpose: numbers, dates
// and timestamps, where both engines compare values; and NULL placement is
// always spelled out. Text sorts by the session's collation in Oracle and by
// bytes in DuckDB, so a text key is left alone.

#include "oracle_adapter.hpp"
#include "duckdb/planner/operator/logical_any_join.hpp"
#include "duckdb/planner/expression/bound_comparison_expression.hpp"
#include "duckdb/planner/expression/bound_conjunction_expression.hpp"
#include "duckdb/planner/expression/bound_constant_expression.hpp"
#include "duckdb/planner/expression_iterator.hpp"
#include "duckdb/storage/table_storage_info.hpp"
#include <functional>
#include <map>
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/planner/operator/logical_merge_into.hpp"
#include "duckdb/planner/operator/logical_insert.hpp"
#include "duckdb/planner/logical_operator_visitor.hpp"

#include "duckdb/main/config.hpp"
#include "duckdb/optimizer/column_binding_replacer.hpp"
#include "duckdb/optimizer/optimizer.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/optimizer/optimizer_extension.hpp"
#include "duckdb/optimizer/filter_pushdown.hpp"
#include "duckdb/planner/expression/bound_aggregate_expression.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "duckdb/planner/expression/bound_cast_expression.hpp"
#include "duckdb/planner/operator/logical_aggregate.hpp"
#include "duckdb/planner/operator/logical_comparison_join.hpp"
#include "duckdb/planner/expression/bound_columnref_expression.hpp"
#include "duckdb/planner/operator/logical_get.hpp"
#include "duckdb/planner/operator/logical_projection.hpp"
#include "duckdb/planner/operator/logical_top_n.hpp"
#include "duckdb/planner/operator/logical_limit.hpp"

namespace duckdb {

namespace {

// Rows past this are not worth asking Oracle to rank for: the statement says how
// many rows to return, and a client-side heap of that size is no longer cheap.
constexpr idx_t MAX_PUSHED_TOP_N = 100000;

bool OrderableInOracle(const OracleColumn &column) {
	if (OracleColumnRoundsOnRead(column)) {
		// Oracle would rank the stored values, and a later sort key can then
		// order rows differently from the rounded values DuckDB sorts.
		return false;
	}
	switch (MappedType(column).id()) {
	case LogicalTypeId::BIGINT:
	case LogicalTypeId::DECIMAL:
	case LogicalTypeId::TIMESTAMP:
	case LogicalTypeId::TIMESTAMP_NS:
	case LogicalTypeId::TIMESTAMP_TZ:
		return true;
	default:
		return false;
	}
}

// Follows a column binding down through projections that pass columns on
// unchanged, to a column of the scan. Anything else on the way, such as a
// computed column, is not something Oracle could be asked to sort by.
bool ResolveToScanColumn(const vector<LogicalProjection *> &projections, const LogicalGet &get, ColumnBinding binding,
                         column_t &column) {
	for (const auto *projection : projections) {
		if (binding.table_index != projection->table_index) {
			return false;
		}
		const auto &expression = projection->GetExpression(binding);
		if (expression.GetExpressionClass() != ExpressionClass::BOUND_COLUMN_REF) {
			return false;
		}
		binding = expression.Cast<BoundColumnRefExpression>().Binding();
	}
	if (binding.table_index != get.table_index) {
		return false;
	}
	const auto &column_ids = get.GetColumnIds();
	const auto position = binding.column_index.GetIndex();
	if (position >= column_ids.size() || column_ids[position].HasChildren()) {
		return false;
	}
	column = column_ids[position].GetPrimaryIndex();
	return true;
}

void PushTopN(ClientContext &context, LogicalTopN &top) {
	Value enabled;
	if (context.TryGetCurrentSetting("oracle_top_n_pushdown", enabled) && !enabled.IsNull() && !BooleanValue::Get(enabled)) {
		return;
	}
	if (top.limit > MAX_PUSHED_TOP_N || top.offset > MAX_PUSHED_TOP_N) {
		return;
	}
	vector<LogicalProjection *> projections;
	auto *node = top.children[0].get();
	while (node->type == LogicalOperatorType::LOGICAL_PROJECTION) {
		projections.push_back(&node->Cast<LogicalProjection>());
		node = node->children[0].get();
	}
	if (node->type != LogicalOperatorType::LOGICAL_GET) {
		return;
	}
	auto &get = node->Cast<LogicalGet>();
	auto *bind = get.bind_data ? dynamic_cast<OracleQueryBindData *>(get.bind_data.get()) : nullptr;
	if (!bind || !bind->deferred_scan) {
		return;
	}
	vector<OracleTopNKey> keys;
	for (const auto &order : top.orders) {
		if (order.expression->GetExpressionClass() != ExpressionClass::BOUND_COLUMN_REF) {
			return;
		}
		if (order.null_order != OrderByNullType::NULLS_FIRST && order.null_order != OrderByNullType::NULLS_LAST) {
			return;
		}
		column_t column;
		if (!ResolveToScanColumn(projections, get, order.expression->Cast<BoundColumnRefExpression>().Binding(), column) ||
		    column >= bind->columns.size() || !OrderableInOracle(bind->columns[column])) {
			return;
		}
		keys.push_back({column, order.type == OrderType::DESCENDING, order.null_order == OrderByNullType::NULLS_FIRST});
	}
	if (keys.empty()) {
		return;
	}
	bind->top_n = std::move(keys);
	bind->top_n_rows = top.limit + top.offset;
}

// Keep LIMIT in DuckDB as well: Oracle only bounds how many rows cross the wire.
void PushLimit(ClientContext &context, LogicalLimit &limit) {
    Value enabled;
    if (context.TryGetCurrentSetting("oracle_top_n_pushdown", enabled) && !enabled.IsNull() &&
        !BooleanValue::Get(enabled)) {
        return;
    }
    if (limit.limit_val.Type() != LimitNodeType::CONSTANT_VALUE ||
        (limit.offset_val.Type() != LimitNodeType::UNSET && limit.offset_val.Type() != LimitNodeType::CONSTANT_VALUE)) {
        return;
    }
    const auto rows = limit.limit_val.GetConstantValue();
    const auto offset =
        limit.offset_val.Type() == LimitNodeType::CONSTANT_VALUE ? limit.offset_val.GetConstantValue() : 0;
    auto *node = limit.children[0].get();
    while (node->type == LogicalOperatorType::LOGICAL_PROJECTION) {
        node = node->children[0].get();
    }
    if (node->type != LogicalOperatorType::LOGICAL_GET) {
        return;
    }
    auto &get = node->Cast<LogicalGet>();
    auto *bind = get.bind_data ? dynamic_cast<OracleQueryBindData *>(get.bind_data.get()) : nullptr;
    if (bind && bind->deferred_scan && !bind->for_update) {
        bind->limit_rows = rows + offset;
    }
}

// Aggregates. `SELECT g, count(*), sum(x) FROM o.T WHERE ... GROUP BY g` plans as
// an AGGREGATE over the scan, and the scan reads every row for DuckDB to add up.
// When the aggregate is one Oracle computes exactly as DuckDB does, the AGGREGATE
// and the scan are replaced by a scan of the statement
// `SELECT g, COUNT(*), SUM(x) FROM T WHERE ... GROUP BY g`, so the groups travel
// and not the rows.
//
// What counts as "exactly as DuckDB does" is narrow on purpose:
//  - COUNT(*), COUNT(column), COUNT(DISTINCT column), SUM, MIN and MAX, with no
//    FILTER or ORDER BY; no GROUPING SETS or GROUPING();
//  - SUM only of an exact number (integer or fixed-scale decimal), whose result
//    type matches DuckDB's; MIN and MAX only of numbers, dates and timestamps,
//    which order the same in both engines, and group keys of those and of the
//    VARCHAR2 columns Oracle compares by bytes (OracleColumn::compared_as_bytes).
//    Other text is left out: Oracle may compare it by a collation (NLS_COMP, a
//    column's COLLATE, blank-padded CHAR) where DuckDB compares bytes, and text
//    order follows NLS_SORT; floating point is left out because the order of
//    addition changes the result (COUNT DISTINCT needs only equality);
//  - every filter was translated into the WHERE clause, none is left for DuckDB
//    to apply to the rows (it would then see groups instead of rows), and the
//    scan has no sample and no filter a join will add later.
// Anything else leaves the plan as it was.

struct PushedAggregate {
	std::string sql;
	std::vector<OracleColumn> columns;
	vector<LogicalType> types;      // what the scan returns
	vector<LogicalType> wanted;     // what the AGGREGATE returned, groups first
    // AVG expands into SUM and COUNT on the wire, but one local result.
    std::map<idx_t, std::pair<double, bool>> averages;
};

bool KeyType(const LogicalType &type) {
	switch (type.id()) {
	case LogicalTypeId::BIGINT:
	case LogicalTypeId::DECIMAL:
	case LogicalTypeId::TIMESTAMP:
	case LogicalTypeId::TIMESTAMP_NS:
		return true;
	default:
		return false;
	}
}

std::string Quoted(const OracleColumn &column) {
	return KeywordHelper::WriteQuotedAndEscaped(column.name, '"');
}

bool PlanPushedAggregate(ClientContext &context, LogicalAggregate &aggregate, LogicalGet &get,
                         const vector<LogicalProjection *> &projections, OracleQueryBindData &bind,
                         PushedAggregate &result) {
	if (!aggregate.grouping_functions.empty() || aggregate.grouping_sets.size() > 1 ||
	    (aggregate.grouping_sets.size() == 1 && aggregate.grouping_sets[0].size() != aggregate.groups.size()) ||
	    get.extra_info.sample_options || (get.dynamic_filters && get.dynamic_filters->HasFilters())) {
		return false;
	}
	const auto &column_ids = get.GetColumnIds();
	std::vector<column_t> scanned;
	for (const auto &id : column_ids) {
		if (id.HasChildren()) {
			return false;
		}
		scanned.push_back(id.GetPrimaryIndex());
	}
	std::string where;
	if (get.table_filters.HasFilters() || get.table_filters.HasMultiColumnFilters()) {
		try {
			auto split = SplitOracleFilters(get.table_filters, bind.columns, scanned);
			if (!split.local.empty()) {
				return false;
			}
			where = std::move(split.where);
		} catch (const std::exception &) {
			return false;
		}
	}
	const auto resolve = [&](const Expression &expression, column_t &column) {
		if (expression.GetExpressionClass() != ExpressionClass::BOUND_COLUMN_REF) {
			return false;
		}
		return ResolveToScanColumn(projections, get, expression.Cast<BoundColumnRefExpression>().Binding(), column) &&
		       column < bind.columns.size();
	};
	std::string select_list;
	std::string group_list;
	const auto add = [&](const std::string &expression, OracleColumn declared, const LogicalType &type,
	                     const LogicalType &wanted) {
		declared.name = "C" + std::to_string(result.columns.size());
		select_list += (select_list.empty() ? "" : ", ") + expression + " " + KeywordHelper::WriteQuotedAndEscaped(declared.name, '"');
		result.columns.push_back(std::move(declared));
		result.types.push_back(type);
		result.wanted.push_back(wanted);
	};
	for (const auto &group : aggregate.groups) {
		column_t column;
		if (!resolve(*group, column)) {
			return false;
		}
		const auto &source = bind.columns[column];
		const auto type = MappedType(source);
		// Grouping needs only equality, so a VARCHAR2 Oracle compares by bytes
		// groups as DuckDB would: the same values together, and no empty string
		// on either side, since Oracle stores '' as NULL.
		const bool text_key = type.id() == LogicalTypeId::VARCHAR && source.oracle_type == 1 &&
		                      source.character_set_form != 2 && !source.xml && source.compared_as_bytes;
		if ((!KeyType(type) && !text_key) || type != group->GetReturnType() || OracleColumnRoundsOnRead(source)) {
			return false;
		}
		add(Quoted(source), source, type, type);
		group_list += (group_list.empty() ? "" : ", ") + Quoted(source);
	}
	for (const auto &expression : aggregate.expressions) {
		if (expression->GetExpressionClass() != ExpressionClass::BOUND_AGGREGATE) {
			return false;
		}
		const auto &call = expression->Cast<BoundAggregateExpression>();
        if (call.GetFilter() || call.GetOrderBys() || call.GetChildren().size() > 1) {
            return false;
        }
        const auto name = StringUtil::Lower(call.Function().GetName().GetIdentifierName());
        if (call.IsDistinct() && name != "count") {
            return false;
        }
        const auto &wanted = call.GetReturnType();
		OracleColumn count_column;
		count_column.oracle_type = 2;
		count_column.precision = 18;
		count_column.scale = 0;
		count_column.nullable = false;
		if (name == "count_star" && call.GetChildren().empty()) {
			add("CAST(COUNT(*) AS NUMBER(18,0))", count_column, LogicalType::BIGINT, wanted);
			continue;
		}
		column_t column;
		if (call.GetChildren().size() != 1 || !resolve(*call.GetChildren()[0], column)) {
			return false;
		}
		const auto &source = bind.columns[column];
		const auto type = MappedType(source);
		if (name == "count" && wanted == LogicalType::BIGINT) {
            if (call.IsDistinct()) {
                const bool text_key = type.id() == LogicalTypeId::VARCHAR && source.oracle_type == 1 &&
                                      source.character_set_form != 2 && !source.xml && source.compared_as_bytes;
                // DISTINCT needs equality, not an ordering or floating-point addition.
                // NUMBER rounded by a read mapping can merge distinct stored values.
                const bool numeric_or_date =
                    KeyType(type) || type.id() == LogicalTypeId::FLOAT || type.id() == LogicalTypeId::DOUBLE;
                if ((!numeric_or_date && !text_key) || OracleColumnRoundsOnRead(source)) {
                    return false;
                }
            }
            add("CAST(COUNT(" + std::string(call.IsDistinct() ? "DISTINCT " : "") + Quoted(source) +
                    ") AS NUMBER(18,0))",
                count_column, LogicalType::BIGINT, wanted);
        } else if ((name == "min" || name == "max") && KeyType(type) && wanted == type) {
			add(name == "min" ? "MIN(" + Quoted(source) + ")" : "MAX(" + Quoted(source) + ")", source, type, type);
        } else if (name == "avg" && wanted == LogicalType::DOUBLE && source.oracle_type == 2 && source.precision >= 1 &&
                   source.precision <= 18 && source.scale >= 0 && source.scale <= source.precision &&
                   !OracleColumnRoundsOnRead(source)) {
            // With <=18 input digits and an 18-digit COUNT, the exact scaled sum
            // fits both Oracle NUMBER and DuckDB HUGEINT. Floating sums stay local.
            const auto scale = type.id() == LogicalTypeId::DECIMAL ? DecimalType::GetScale(type) : 0;
            const auto multiplier = Hugeint::Cast<double>(Hugeint::POWERS_OF_TEN[scale]);
            const bool narrow = type.id() == LogicalTypeId::DECIMAL && DecimalType::GetWidth(type) <= 4;
            result.averages.emplace(result.types.size(), std::make_pair(multiplier, narrow));
            OracleColumn text;
            add("TO_CHAR(SUM(" + Quoted(source) + ") * " + std::to_string(uint64_t(multiplier)) + ", 'TM9')", text,
                LogicalType::VARCHAR, LogicalType::HUGEINT);
            add("CAST(COUNT(" + Quoted(source) + ") AS NUMBER(18,0))", count_column, LogicalType::BIGINT,
                LogicalType::BIGINT);
        } else if (name == "sum" && source.oracle_type == 2 && source.precision >= 1 && source.scale >= 0 &&
                   source.scale <= source.precision && source.precision <= 38) {
            if (type.id() == LogicalTypeId::BIGINT && wanted == LogicalType::HUGEINT) {
				// A sum of integers can pass 18 digits, which no NUMBER this client maps to a
				// number can hold; Oracle spells it out and DuckDB reads it as a HUGEINT.
				OracleColumn text;
				add("TO_CHAR(SUM(" + Quoted(source) + "), 'TM9')", text, LogicalType::VARCHAR, wanted);
			} else if (type.id() == LogicalTypeId::DECIMAL && wanted == LogicalType::DECIMAL(38, source.scale)) {
				OracleColumn sum;
				sum.oracle_type = 2;
				sum.precision = 38;
				sum.scale = source.scale;
				add("CAST(SUM(" + Quoted(source) + ") AS NUMBER(38," + std::to_string(source.scale) + "))", sum, wanted,
				    wanted);
			} else {
				return false;
			}
        } else {
            return false;
        }
    }
	if (result.columns.empty()) {
		return false;
	}
    result.sql = "SELECT " + select_list + " FROM " + OracleObjectReference(bind.schema_name, bind.object_name) + " /*SCN*/";
    if (!where.empty()) {
		result.sql += " WHERE " + where;
	}
	if (!group_list.empty()) {
		result.sql += " GROUP BY " + group_list;
	}
	return true;
}

// Match the pinned DuckDB AVG finalizers, including the platform's extended
// precision for BIGINT and DECIMAL backed by INT32/INT64. Do not replace this
// with a SQL DOUBLE division: it rounds the numerator too early.
void FinalizeOracleAverage(DataChunk &input, ExpressionState &, Vector &result) {
    using Extended = decltype(0.0L);
    for (idx_t row = 0; row < input.size(); row++) {
        const auto count = input.GetValue(1, row).GetValue<int64_t>();
        if (!count) {
            result.SetValue(row, Value(LogicalType::DOUBLE));
            continue;
        }
        const auto sum = input.GetValue(0, row).GetValue<hugeint_t>();
        const auto scale = input.GetValue(2, row).GetValue<double>();
        const auto narrow = input.GetValue(3, row).GetValue<bool>();
        const auto value = narrow ? Hugeint::Cast<double>(sum) / (double(count) * scale)
                                  : double(Hugeint::Cast<Extended>(sum) / (Extended(count) * Extended(scale)));
        result.SetValue(row, Value::DOUBLE(value));
    }
}

void PushAggregate(ClientContext &context, unique_ptr<LogicalOperator> &op, ColumnBindingReplacer &replacer) {
	auto &aggregate = op->Cast<LogicalAggregate>();
	vector<LogicalProjection *> projections;
	auto *node = aggregate.children[0].get();
	while (node->type == LogicalOperatorType::LOGICAL_PROJECTION) {
		projections.push_back(&node->Cast<LogicalProjection>());
		node = node->children[0].get();
	}
	if (node->type != LogicalOperatorType::LOGICAL_GET) {
		return;
	}
	auto &get = node->Cast<LogicalGet>();
	auto *bind = get.bind_data ? dynamic_cast<OracleQueryBindData *>(get.bind_data.get()) : nullptr;
    if (!bind || !bind->deferred_scan) {
        return;
    }
    PushedAggregate pushed;
	if (!PlanPushedAggregate(context, aggregate, get, projections, *bind, pushed)) {
		return;
	}
	auto scan_bind = make_uniq<OracleQueryBindData>();
	scan_bind->statement_scan = true;
	scan_bind->statement_sql = std::move(pushed.sql);
	scan_bind->columns = std::move(pushed.columns);
	scan_bind->types = pushed.types;
	scan_bind->config = bind->config;
	scan_bind->password = bind->password;
	scan_bind->object_name = bind->object_name;
	scan_bind->schema_name = bind->schema_name;
	scan_bind->secret_name = bind->secret_name;
	scan_bind->catalog_name = bind->catalog_name;
	vector<Identifier> names;
	for (const auto &column : scan_bind->columns) {
		names.emplace_back(column.name);
	}
	BoundTableFunction function(get.function);
	function.filter_pushdown = false;
	function.projection_pushdown = false;
	function.sampling_pushdown = false;
	function.cardinality = nullptr;
	function.statistics = nullptr;
	function.get_table_entry = nullptr;
    function.get_bind_info = nullptr;
    function.pushdown_expression = nullptr;
    const auto get_index = get.table_index;
	auto scan = make_uniq<LogicalGet>(get_index, std::move(function), std::move(scan_bind), pushed.types, names);
	vector<ColumnIndex> ids;
	for (idx_t index = 0; index < pushed.types.size(); index++) {
		ids.emplace_back(index);
	}
	scan->SetColumnIds(std::move(ids));
	// The AGGREGATE's own types, reached by a cast where the scan's differ (a sum
	// of integers arrives as text and is a HUGEINT here).
	vector<unique_ptr<Expression>> select;
    for (idx_t index = 0; index < pushed.types.size(); index++) {
        unique_ptr<Expression> reference =
            make_uniq<BoundColumnRefExpression>(pushed.types[index], ColumnBinding(get_index, ProjectionIndex(index)));
        if (pushed.types[index] != pushed.wanted[index]) {
            reference = BoundCastExpression::AddCastToType(context, std::move(reference), pushed.wanted[index]);
        }
        const auto average = pushed.averages.find(index);
        if (average != pushed.averages.end()) {
            vector<unique_ptr<Expression>> arguments;
            arguments.push_back(std::move(reference));
            arguments.push_back(make_uniq<BoundColumnRefExpression>(
                LogicalType::BIGINT, ColumnBinding(get_index, ProjectionIndex(++index))));
            arguments.push_back(make_uniq<BoundConstantExpression>(Value::DOUBLE(average->second.first)));
            arguments.push_back(make_uniq<BoundConstantExpression>(Value::BOOLEAN(average->second.second)));
            ScalarFunction function(
                "oracle_finalize_average",
                {LogicalType::HUGEINT, LogicalType::BIGINT, LogicalType::DOUBLE, LogicalType::BOOLEAN},
                LogicalType::DOUBLE, FinalizeOracleAverage);
            function.SetNullHandling(FunctionNullHandling::SPECIAL_HANDLING);
            reference =
                make_uniq<BoundFunctionExpression>(BoundScalarFunction(function), std::move(arguments), nullptr);
        }
        select.push_back(std::move(reference));
    }
    const auto groups = aggregate.groups.size();
	const auto group_index = aggregate.group_index;
	const auto aggregate_index = aggregate.aggregate_index;
	const auto aggregates = aggregate.expressions.size();
	const auto estimate = aggregate.has_estimated_cardinality ? aggregate.estimated_cardinality : 1;
	auto projection = make_uniq<LogicalProjection>(group_index, std::move(select));
	projection->children.push_back(std::move(scan));
	projection->SetEstimatedCardinality(estimate);
	op = std::move(projection);
	// Whatever read the aggregates by (aggregate_index, n) now reads them from the projection.
	for (idx_t index = 0; index < aggregates; index++) {
		replacer.replacement_bindings.emplace_back(ColumnBinding(aggregate_index, ProjectionIndex(index)),
		                                           ColumnBinding(group_index, ProjectionIndex(groups + index)));
	}
}

// Joins. An inner join of two attached tables of one Oracle database is one
// statement there: `FROM (SELECT ... WHERE ...) a JOIN (SELECT ... WHERE ...) b ON ...`,
// so the join's result travels and not both tables. Each side keeps its own
// filters inside its own inline view, where its column names mean what they did.
// Only comparisons of numbers, dates and timestamps are sent (the same reason as
// for aggregates), all filters must be Oracle's, and neither side may be a sample
// or hold a column this path cannot read as itself (LOB, JSON, VECTOR, XML, ROWID).

bool PlainColumn(const OracleColumn &column) {
	switch (column.oracle_type) {
	case 112: case 113: case 119: case 127: case 8: case 24:
		return false;
	default:
		return !column.xml;
	}
}

struct JoinSide {
	LogicalGet *get = nullptr;
	OracleQueryBindData *bind = nullptr;
	std::string where;
	std::vector<column_t> selected; // table columns the view selects, in order
};

bool PrepareSide(LogicalOperator &child, JoinSide &side) {
	if (child.type != LogicalOperatorType::LOGICAL_GET) {
		return false;
	}
	side.get = &child.Cast<LogicalGet>();
	side.bind = side.get->bind_data ? dynamic_cast<OracleQueryBindData *>(side.get->bind_data.get()) : nullptr;
	if (!side.bind || !side.bind->deferred_scan || side.get->extra_info.sample_options) {
		return false;
	}
	std::vector<column_t> scanned;
	for (const auto &id : side.get->GetColumnIds()) {
		if (id.HasChildren() || id.GetPrimaryIndex() >= side.bind->columns.size()) {
			return false;
		}
		scanned.push_back(id.GetPrimaryIndex());
	}
	if (side.get->table_filters.HasFilters() || side.get->table_filters.HasMultiColumnFilters()) {
		try {
			auto split = SplitOracleFilters(side.get->table_filters, side.bind->columns, scanned);
			if (!split.local.empty()) {
				return false;
			}
			side.where = std::move(split.where);
		} catch (const std::exception &) {
			return false;
		}
	}
	return true;
}

size_t Select(JoinSide &side, column_t column) {
	for (size_t index = 0; index < side.selected.size(); index++) {
		if (side.selected[index] == column) {
			return index;
		}
	}
	side.selected.push_back(column);
	return side.selected.size() - 1;
}

std::string SideView(const JoinSide &side) {
	std::string list;
	for (const auto column : side.selected) {
		list += (list.empty() ? "" : ", ") + Quoted(side.bind->columns[column]);
	}
	auto sql = "(SELECT " + list + " FROM " + OracleObjectReference(side.bind->schema_name, side.bind->object_name) +
	           " /*SCN*/";
	if (!side.where.empty()) {
		sql += " WHERE " + side.where;
	}
	return sql + ")";
}

const char *ComparisonSql(ExpressionType type) {
	switch (type) {
	case ExpressionType::COMPARE_EQUAL:
		return "=";
	case ExpressionType::COMPARE_NOTEQUAL:
		return "<>";
	case ExpressionType::COMPARE_LESSTHAN:
		return "<";
	case ExpressionType::COMPARE_LESSTHANOREQUALTO:
		return "<=";
	case ExpressionType::COMPARE_GREATERTHAN:
		return ">";
	case ExpressionType::COMPARE_GREATERTHANOREQUALTO:
		return ">=";
	default:
		return nullptr;
	}
}

void PushJoin(OptimizerExtensionInput &input, unique_ptr<LogicalOperator> &op, ColumnBindingReplacer &replacer) {
	auto &join = op->Cast<LogicalComparisonJoin>();
	if (join.join_type != JoinType::INNER || join.conditions.empty() || !join.mark_types.empty() ||
	    !join.duplicate_eliminated_columns.empty() || join.children.size() != 2) {
		return;
	}
	JoinSide sides[2];
	for (idx_t index = 0; index < 2; index++) {
		if (!PrepareSide(*join.children[index], sides[index])) {
			return;
		}
	}
	const auto &first = *sides[0].bind;
	const auto &second = *sides[1].bind;
	if (first.catalog_name.empty() || first.catalog_name != second.catalog_name ||
	    first.secret_name != second.secret_name) {
		return;
	}
	// A column of a side, by the binding the plan names it with.
	const auto column_of = [&](idx_t side, const ColumnBinding &binding, column_t &column) {
		if (binding.table_index != sides[side].get->table_index) {
			return false;
		}
		column = sides[side].get->GetColumnIndex(binding).GetPrimaryIndex();
		return column < sides[side].bind->columns.size() && PlainColumn(sides[side].bind->columns[column]);
	};
	struct Condition {
		size_t left, right;
		const char *comparison;
	};
	std::vector<Condition> conditions;
	for (const auto &condition : join.conditions) {
		const auto *comparison = condition.IsComparison() ? ComparisonSql(condition.GetComparisonType()) : nullptr;
		if (!comparison || condition.GetLHS().GetExpressionClass() != ExpressionClass::BOUND_COLUMN_REF ||
		    condition.GetRHS().GetExpressionClass() != ExpressionClass::BOUND_COLUMN_REF) {
			return;
		}
		column_t left, right;
		if (!column_of(0, condition.GetLHS().Cast<BoundColumnRefExpression>().Binding(), left) ||
		    !column_of(1, condition.GetRHS().Cast<BoundColumnRefExpression>().Binding(), right)) {
			return;
		}
		const auto left_type = MappedType(sides[0].bind->columns[left]);
		if (!KeyType(left_type) || left_type != MappedType(sides[1].bind->columns[right]) ||
		    OracleColumnRoundsOnRead(sides[0].bind->columns[left]) ||
		    OracleColumnRoundsOnRead(sides[1].bind->columns[right])) {
			return;
		}
		conditions.push_back({Select(sides[0], left), Select(sides[1], right), comparison});
	}
	// What the join hands upward, in its own order.
	struct Output {
		idx_t side;
		size_t position;
		ColumnBinding old_binding;
		LogicalType type;
	};
	std::vector<Output> outputs;
	for (const auto &binding : join.GetColumnBindings()) {
		bool found = false;
		for (idx_t side = 0; side < 2 && !found; side++) {
			column_t column;
			if (binding.table_index != sides[side].get->table_index) {
				continue;
			}
			if (!column_of(side, binding, column)) {
				return;
			}
			outputs.push_back({side, Select(sides[side], column), binding, MappedType(sides[side].bind->columns[column])});
			found = true;
		}
		if (!found) {
			return;
		}
	}
	if (outputs.empty()) {
		return;
	}
	auto scan_bind = make_uniq<OracleQueryBindData>();
	scan_bind->statement_scan = true;
	std::string list;
	vector<LogicalType> types;
	vector<Identifier> names;
	for (const auto &output : outputs) {
		auto declared = sides[output.side].bind->columns[sides[output.side].selected[output.position]];
		const auto &source = declared;
		const auto expression = std::string(output.side == 0 ? "a." : "b.") + Quoted(source);
		declared.name = "C" + std::to_string(scan_bind->columns.size());
		list += (list.empty() ? "" : ", ") + expression + " " + KeywordHelper::WriteQuotedAndEscaped(declared.name, '"');
		names.emplace_back(declared.name);
		types.push_back(output.type);
		scan_bind->columns.push_back(std::move(declared));
	}
	std::string on;
	for (const auto &condition : conditions) {
		on += (on.empty() ? "" : " AND ") + std::string("a.") + Quoted(sides[0].bind->columns[sides[0].selected[condition.left]]) +
		      " " + condition.comparison + " b." + Quoted(sides[1].bind->columns[sides[1].selected[condition.right]]);
	}
	scan_bind->statement_sql = "SELECT " + list + " FROM " + SideView(sides[0]) + " a JOIN " + SideView(sides[1]) +
	                           " b ON " + on;
	scan_bind->types = types;
	scan_bind->config = first.config;
	scan_bind->password = first.password;
	scan_bind->object_name = first.object_name;
	scan_bind->schema_name = first.schema_name;
	scan_bind->secret_name = first.secret_name;
	scan_bind->catalog_name = first.catalog_name;
	BoundTableFunction function(sides[0].get->function);
	function.filter_pushdown = false;
	function.projection_pushdown = false;
	function.sampling_pushdown = false;
	function.cardinality = nullptr;
	function.statistics = nullptr;
	function.get_table_entry = nullptr;
	const auto index = input.optimizer.binder.GenerateTableIndex();
	auto scan = make_uniq<LogicalGet>(index, std::move(function), std::move(scan_bind), types, names);
	vector<ColumnIndex> ids;
	for (idx_t position = 0; position < types.size(); position++) {
		ids.emplace_back(position);
	}
	scan->SetColumnIds(std::move(ids));
	if (join.has_estimated_cardinality) {
		scan->SetEstimatedCardinality(join.estimated_cardinality);
	}
	for (idx_t position = 0; position < outputs.size(); position++) {
		replacer.replacement_bindings.emplace_back(outputs[position].old_binding,
		                                           ColumnBinding(index, ProjectionIndex(position)));
	}
	op = std::move(scan);
}

void Walk(OptimizerExtensionInput &input, unique_ptr<LogicalOperator> &op, ColumnBindingReplacer &replacer,
          bool aggregates, bool joins) {
	auto &context = input.context;
    if (op->type == LogicalOperatorType::LOGICAL_LIMIT) {
        PushLimit(context, op->Cast<LogicalLimit>());
    }
    if (op->type == LogicalOperatorType::LOGICAL_TOP_N) {
		PushTopN(context, op->Cast<LogicalTopN>());
	}
	for (auto &child : op->children) {
		Walk(input, child, replacer, aggregates, joins);
	}
	if (joins && op->type == LogicalOperatorType::LOGICAL_COMPARISON_JOIN) {
		PushJoin(input, op, replacer);
	}
	if (aggregates && op->type == LogicalOperatorType::LOGICAL_AGGREGATE_AND_GROUP_BY) {
		PushAggregate(context, op, replacer);
	}
}

[[noreturn]] void RefuseOracleMerge() {
    throw NotImplementedException("Oracle MERGE/upsert supports equality on enforced keys, one INSERT and optional "
                                  "UPDATE of source columns or constants. Conditions, old-row expressions, key changes "
                                  "and RETURNING are not supported; use oracle_execute with Oracle MERGE SQL");
}

void RejectOracleMergeSourceDefaults(LogicalOperator &source) {
    // A DEFAULT inside VALUES lives in the expression get, not in the
    // INSERT action projection. Inspect the complete source before rewriting.
    if (source.type == LogicalOperatorType::LOGICAL_EXPRESSION_GET) {
        LogicalOperatorVisitor::EnumerateExpressions(source, [&](unique_ptr<Expression> *expression) {
            ExpressionIterator::EnumerateExpression(*expression, [&](unique_ptr<Expression> &part) {
                if (part->GetExpressionClass() == ExpressionClass::BOUND_FUNCTION &&
                    part->Cast<BoundFunctionExpression>().Function().GetName() ==
                        Identifier("__oracle_scanner_default")) {
                    throw NotImplementedException("Oracle MERGE/upsert does not support explicit DEFAULT values; "
                                                  "omit the column or use oracle_execute with Oracle SQL");
                }
            });
        });
    }
    for (auto &child : source.children) {
        RejectOracleMergeSourceDefaults(*child);
    }
}

void RewriteOracleMerges(OptimizerExtensionInput &input, unique_ptr<LogicalOperator> &plan) {
    if (plan->type != LogicalOperatorType::LOGICAL_MERGE_INTO ||
        plan->Cast<LogicalMergeInto>().table.catalog.GetCatalogType() != "oracle_scanner") {
        for (auto &child : plan->children) {
            RewriteOracleMerges(input, child);
        }
        return;
    }
    auto &merge = plan->Cast<LogicalMergeInto>();
    if (merge.return_chunk || merge.children.size() != 1 ||
        merge.children[0]->type != LogicalOperatorType::LOGICAL_PROJECTION) {
        RefuseOracleMerge();
    }
    auto &projection = merge.children[0]->Cast<LogicalProjection>();
    auto &root = *projection.children[0];
    if (root.children.size() != 2) {
        RefuseOracleMerge();
    }
    idx_t target_side = 2;
    OracleQueryBindData *bind = nullptr;
    LogicalGet *get = nullptr;
    for (idx_t i = 0; i < 2; i++) {
        if (root.children[i]->type != LogicalOperatorType::LOGICAL_GET) {
            continue;
        }
        auto &candidate = root.children[i]->Cast<LogicalGet>();
        auto *data = candidate.bind_data ? dynamic_cast<OracleQueryBindData *>(candidate.bind_data.get()) : nullptr;
        if (data && data->table_entry == &merge.table) {
            target_side = i;
            bind = data;
            get = &candidate;
        }
    }
    if (!bind || target_side == 2) {
        RefuseOracleMerge();
    }
    auto &source = root.children[1 - target_side];
    RejectOracleMergeSourceDefaults(*source);
    const auto source_bindings = source->GetColumnBindings();
    const auto is_source = [&](const Expression &expression) {
        bool valid = true;
        auto copy = expression.Copy();
        ExpressionIterator::EnumerateExpression(copy, [&](unique_ptr<Expression> &part) {
            if (part->GetExpressionClass() == ExpressionClass::BOUND_COLUMN_REF) {
                const auto binding = part->Cast<BoundColumnRefExpression>().Binding();
                if (std::find(source_bindings.begin(), source_bindings.end(), binding) == source_bindings.end()) {
                    valid = false;
                }
            }
            if (part->HasSubquery() || part->IsVolatile()) {
                valid = false;
            }
        });
        return valid;
    };
    const auto expanded = [&](const Expression &expression) {
        auto result = expression.Copy();
        ExpressionIterator::EnumerateExpression(result, [&](unique_ptr<Expression> &part) {
            if (part->GetExpressionClass() == ExpressionClass::BOUND_COLUMN_REF) {
                const auto &ref = part->Cast<BoundColumnRefExpression>();
                if (ref.Binding().table_index == projection.table_index) {
                    part = projection.GetExpression(ref.Binding()).Copy();
                }
            }
        });
        if (!is_source(*result)) {
            RefuseOracleMerge();
        }
        return result;
    };
    struct Key {
        column_t column;
        unique_ptr<Expression> value;
    };
    using Keys = vector<Key>;
    using Branches = vector<Keys>;
    const auto target_column = [&](const Expression &expression) -> optional_idx {
        const Expression *part = &expression;
        // A cast of the target can change equality, so leave it unsupported.
        if (part->GetExpressionClass() != ExpressionClass::BOUND_COLUMN_REF) {
            return optional_idx();
        }
        const auto binding = part->Cast<BoundColumnRefExpression>().Binding();
        if (binding.table_index != get->table_index) {
            return optional_idx();
        }
        return get->GetColumnIndex(binding).GetPrimaryIndex();
    };
    std::function<Branches(const Expression &)> parse;
    parse = [&](const Expression &expression) -> Branches {
        if (expression.GetExpressionClass() == ExpressionClass::BOUND_CONJUNCTION) {
            const auto &conjunction = expression.Cast<BoundConjunctionExpression>();
            Branches result;
            for (const auto &child : conjunction.GetChildren()) {
                auto next = parse(*child);
                if (result.empty()) {
                    result = std::move(next);
                    continue;
                }
                if (expression.GetExpressionType() == ExpressionType::CONJUNCTION_OR) {
                    for (auto &branch : next) {
                        result.push_back(std::move(branch));
                    }
                } else {
                    Branches combined;
                    for (const auto &a : result) {
                        for (const auto &b : next) {
                            Keys keys;
                            for (const auto &key : a) {
                                keys.push_back({key.column, key.value->Copy()});
                            }
                            for (const auto &key : b) {
                                keys.push_back({key.column, key.value->Copy()});
                            }
                            combined.push_back(std::move(keys));
                        }
                    }
                    result = std::move(combined);
                }
                if (result.size() > 64) {
                    RefuseOracleMerge();
                }
            }
            return result;
        }
        if (!BoundComparisonExpression::IsComparison(expression) ||
            expression.GetExpressionType() != ExpressionType::COMPARE_EQUAL) {
            RefuseOracleMerge();
        }
        const auto &comparison = expression.Cast<BoundFunctionExpression>();
        const Expression *a = &BoundComparisonExpression::Left(comparison);
        const Expression *b = &BoundComparisonExpression::Right(comparison);
        auto column = target_column(*a);
        if (!column.IsValid()) {
            std::swap(a, b);
            column = target_column(*a);
        }
        if (!column.IsValid() || column.GetIndex() >= bind->columns.size() || !is_source(*b)) {
            RefuseOracleMerge();
        }
        Branches result;
        Keys keys;
        keys.push_back({column.GetIndex(), b->Copy()});
        result.push_back(std::move(keys));
        return result;
    };
    Branches branches;
    if (root.type == LogicalOperatorType::LOGICAL_ANY_JOIN) {
        branches = parse(*root.Cast<LogicalAnyJoin>().condition);
    } else if (root.type == LogicalOperatorType::LOGICAL_COMPARISON_JOIN) {
        Keys keys;
        for (const auto &condition : root.Cast<LogicalComparisonJoin>().conditions) {
            if (!condition.IsComparison() || condition.GetComparisonType() != ExpressionType::COMPARE_EQUAL) {
                RefuseOracleMerge();
            }
            auto expression = BoundComparisonExpression::Create(ExpressionType::COMPARE_EQUAL,
                                                                condition.GetLHS().Copy(), condition.GetRHS().Copy());
            auto parsed = parse(*expression);
            for (auto &key : parsed[0]) {
                keys.push_back(std::move(key));
            }
        }
        branches.push_back(std::move(keys));
    } else {
        RefuseOracleMerge();
    }
    const auto storage = merge.table.GetStorageInfo(input.context);
    for (const auto &branch : branches) {
        unordered_set<column_t> columns;
        for (const auto &key : branch) {
            const auto &column = bind->columns[key.column];
            // The duplicate check compares target-cast bind bytes. Refuse
            // keys whose Oracle equality can identify different encodings.
            if (column.oracle_type == 96 || column.oracle_type == 100 || column.oracle_type == 101 ||
                (column.oracle_type == 1 &&
                 (!column.compared_as_bytes || column.character_set_form == 2 || column.xml))) {
                throw NotImplementedException(
                    "Oracle MERGE/upsert cannot validate key equality for column \"%s\": "
                    "CHAR, national or nonbinary text, and BINARY_FLOAT/DOUBLE keys are not supported; "
                    "use oracle_execute with Oracle MERGE SQL",
                    column.name);
            }
            columns.insert(key.column);
        }
        bool enforced = false;
        for (const auto &index : storage.index_info) {
            enforced |= index.is_unique && columns == index.column_set;
        }
        if (!enforced) {
            RefuseOracleMerge();
        }
    }
    BoundMergeIntoAction *insert = nullptr, *update = nullptr;
    for (auto &entry : merge.actions) {
        for (auto &action : entry.second) {
            if (action->condition) {
                RefuseOracleMerge();
            }
            if (entry.first == MergeActionCondition::WHEN_NOT_MATCHED_BY_TARGET &&
                action->action_type == MergeActionType::MERGE_INSERT && !insert) {
                insert = action.get();
            } else if (entry.first == MergeActionCondition::WHEN_MATCHED &&
                       action->action_type == MergeActionType::MERGE_UPDATE && !update) {
                update = action.get();
            } else if (!(entry.first == MergeActionCondition::WHEN_MATCHED &&
                         action->action_type == MergeActionType::MERGE_DO_NOTHING)) {
                RefuseOracleMerge();
            }
        }
    }
    if (!insert || insert->expressions.size() != bind->columns.size()) {
        RefuseOracleMerge();
    }
    vector<unique_ptr<Expression>> values;
    std::vector<OracleColumn> columns;
    std::string select_list;
    const auto add = [&](unique_ptr<Expression> value, column_t column) {
        const auto alias = "C" + std::to_string(values.size());
        const auto &declared = bind->columns[column];
        select_list +=
            (select_list.empty() ? "" : ", ") + OracleBindExpression(declared, values.size() + 1) + " " + alias;
        values.push_back(BoundCastExpression::AddCastToType(input.context, std::move(value), MappedType(declared)));
        columns.push_back(declared);
        return "s." + alias;
    };
    std::string on;
    for (const auto &branch : branches) {
        std::string equal;
        for (const auto &key : branch) {
            auto rhs = add(key.value->Copy(), key.column);
            auto lhs = "t." + Quoted(bind->columns[key.column]);
            equal += std::string(equal.empty() ? "" : " AND ") + lhs + "=" + rhs;
        }
        on += std::string(on.empty() ? "" : " OR ") + "(" + equal + ")";
    }
    const auto key_count = values.size();
    std::vector<idx_t> key_groups;
    for (const auto &branch : branches) {
        key_groups.push_back(branch.size());
    }
    std::function<bool(const Expression &, LogicalOperator &)> is_default;
    is_default = [&](const Expression &expression, LogicalOperator &node) {
        const Expression *part = &expression;
        while (BoundCastExpression::IsCast(*part)) {
            part = &BoundCastExpression::Child(part->Cast<BoundFunctionExpression>());
        }
        if (part->GetExpressionClass() == ExpressionClass::BOUND_FUNCTION &&
            part->Cast<BoundFunctionExpression>().Function().GetName() == Identifier("__oracle_scanner_default")) {
            return true;
        }
        if (part->GetExpressionClass() != ExpressionClass::BOUND_COLUMN_REF) {
            return false;
        }
        auto binding = part->Cast<BoundColumnRefExpression>().Binding();
        if (node.type == LogicalOperatorType::LOGICAL_PROJECTION) {
            auto &proj = node.Cast<LogicalProjection>();
            if (binding.table_index == proj.table_index) {
                return is_default(proj.GetExpression(binding), *proj.children[0]);
            }
        }
        for (auto &child : node.children) {
            if (is_default(*part, *child)) {
                return true;
            }
        }
        return false;
    };
    std::string insert_columns, insert_values, assignments;
    for (idx_t i = 0; i < insert->expressions.size(); i++) {
        const auto &expr = *insert->expressions[i];
        // Missing columns have a direct NULL default; an explicit NULL is a reference to the source projection.
        if (expr.GetExpressionClass() == ExpressionClass::BOUND_CONSTANT &&
            expr.Cast<BoundConstantExpression>().GetValue().IsNull()) {
            continue;
        }
        if (is_default(expr, projection)) {
            continue;
        }
        auto value = expanded(expr);
        if (is_default(*value, *source)) {
            continue;
        }
        insert_values += (insert_values.empty() ? "" : ", ") + add(std::move(value), i);
        insert_columns += (insert_columns.empty() ? "" : ", ") + Quoted(bind->columns[i]);
    }
    if (insert_columns.empty()) {
        RefuseOracleMerge();
    }
    if (update) {
        for (idx_t i = 0; i < update->columns.size(); i++) {
            const auto column = update->columns[i].index;
            if (is_default(*update->expressions[i], projection)) {
                RefuseOracleMerge();
            }
            auto value = expanded(*update->expressions[i]);
            const Expression *plain = value.get();
            while (BoundCastExpression::IsCast(*plain)) {
                plain = &BoundCastExpression::Child(plain->Cast<BoundFunctionExpression>());
            }
            if (plain->GetExpressionClass() != ExpressionClass::BOUND_COLUMN_REF &&
                plain->GetExpressionClass() != ExpressionClass::BOUND_CONSTANT) {
                RefuseOracleMerge();
            }
            bool key_column = false;
            for (const auto &branch : branches) {
                for (const auto &key : branch) {
                    if (key.column == column) {
                        if (!Expression::Equals(*value, *key.value)) {
                            RefuseOracleMerge();
                        }
                        key_column = true;
                    }
                }
            }
            if (key_column) {
                continue;
            }
            assignments += std::string(assignments.empty() ? "" : ", ") + "t." + Quoted(bind->columns[column]) + "=" +
                           add(std::move(value), column);
        }
    }
    auto target = ResolveOracleWriteTarget(input.context, bind->catalog_name);
    target.schema_name = bind->schema_name;
    target.object_name = bind->object_name;
    auto sql = "MERGE INTO " + OracleObjectReference(bind->schema_name, bind->object_name) + " t USING (SELECT " +
               select_list + " FROM dual) s ON (" + on + ")";
    if (!assignments.empty()) {
        sql += " WHEN MATCHED THEN UPDATE SET " + assignments;
    }
    sql += " WHEN NOT MATCHED THEN INSERT (" + insert_columns + ") VALUES (" + insert_values + ")";
    auto projected = make_uniq<LogicalProjection>(input.optimizer.binder.GenerateTableIndex(), std::move(values));
    projected->children.push_back(std::move(source));
    plan = MakeOracleMergePlan(merge.table, merge.table_index, std::move(target), std::move(sql), std::move(columns),
                               key_count, std::move(key_groups), std::move(projected));
}

// DuckDB 2.0 expands DISTINCT aggregates before the post-optimizer hook.
// Resolve eligible original COUNTs first, using DuckDB's own filter pushdown
// so every remaining local filter still prevents the aggregate rewrite.
void PushDistinctCounts(OptimizerExtensionInput &input, unique_ptr<LogicalOperator> &op,
                        ColumnBindingReplacer &replacer) {
    for (auto &child : op->children) {
        PushDistinctCounts(input, child, replacer);
    }
    if (op->type != LogicalOperatorType::LOGICAL_AGGREGATE_AND_GROUP_BY) {
        return;
    }
    auto &aggregate = op->Cast<LogicalAggregate>();
    bool distinct_count = false;
    for (const auto &expression : aggregate.expressions) {
        if (expression->GetExpressionClass() == ExpressionClass::BOUND_AGGREGATE) {
            const auto &call = expression->Cast<BoundAggregateExpression>();
            distinct_count |=
                call.IsDistinct() && StringUtil::CIEquals(call.Function().GetName().GetIdentifierName(), "count");
        }
    }
    if (!distinct_count) {
        return;
    }
    auto *node = aggregate.children[0].get();
    while (node->type == LogicalOperatorType::LOGICAL_PROJECTION || node->type == LogicalOperatorType::LOGICAL_FILTER) {
        node = node->children[0].get();
    }
    if (node->type != LogicalOperatorType::LOGICAL_GET) {
        return;
    }
    auto &get = node->Cast<LogicalGet>();
    const auto *bind = get.bind_data ? dynamic_cast<const OracleQueryBindData *>(get.bind_data.get()) : nullptr;
    if (!bind || !bind->deferred_scan) {
        return;
    }
    FilterPushdown pushdown(input.optimizer);
    aggregate.children[0] = pushdown.Rewrite(std::move(aggregate.children[0]));
    PushAggregate(input.context, op, replacer);
}

void RejectExplicitOracleInsertDefaults(LogicalOperator &plan) {
    if (plan.type == LogicalOperatorType::LOGICAL_INSERT) {
        auto &insert = plan.Cast<LogicalInsert>();
        if (insert.table.catalog.GetCatalogType() == "oracle_scanner" && !insert.children.empty()) {
            auto &source = *insert.children[0];
            std::function<void(LogicalOperator &)> inspect;
            inspect = [&](LogicalOperator &node) {
                idx_t expression_index = 0;
                LogicalOperatorVisitor::EnumerateExpressions(node, [&](unique_ptr<Expression> *expression) {
                    const auto index = expression_index++;
                    // Omitted columns are represented by defaults in the outer
                    // projection. They are left out of the Oracle INSERT SQL.
                    if (&node == &source && node.type == LogicalOperatorType::LOGICAL_PROJECTION &&
                        index < insert.bound_defaults.size() && !insert.bound_defaults[index]) {
                        return;
                    }
                    ExpressionIterator::EnumerateExpression(*expression, [&](unique_ptr<Expression> &part) {
                        if (part->GetExpressionClass() == ExpressionClass::BOUND_FUNCTION &&
                            part->Cast<BoundFunctionExpression>().Function().GetName() ==
                                Identifier("__oracle_scanner_default")) {
                            throw NotImplementedException("Oracle INSERT does not support explicit DEFAULT values; "
                                                          "omit the column or use oracle_execute with Oracle SQL");
                        }
                    });
                });
                for (auto &child : node.children) {
                    inspect(*child);
                }
            };
            inspect(source);
        }
    }
    for (auto &child : plan.children) {
        RejectExplicitOracleInsertDefaults(*child);
    }
}

void PreOptimizeOraclePlan(OptimizerExtensionInput &input, unique_ptr<LogicalOperator> &plan) {
    RejectExplicitOracleInsertDefaults(*plan);
    RewriteOracleMerges(input, plan);
    Value enabled;
    if (input.context.TryGetCurrentSetting("oracle_aggregate_pushdown", enabled) && !enabled.IsNull() &&
        !BooleanValue::Get(enabled)) {
        return;
    }
    ColumnBindingReplacer replacer;
    PushDistinctCounts(input, plan, replacer);
    if (!replacer.replacement_bindings.empty()) {
        replacer.VisitOperator(*plan);
    }
}

void OptimizeOraclePlan(OptimizerExtensionInput &input, unique_ptr<LogicalOperator> &plan) {
	if (!plan) {
		return;
	}
	Value enabled;
	const auto aggregates = !input.context.TryGetCurrentSetting("oracle_aggregate_pushdown", enabled) || enabled.IsNull() ||
	                        BooleanValue::Get(enabled);
	const auto joins = !input.context.TryGetCurrentSetting("oracle_join_pushdown", enabled) || enabled.IsNull() ||
	                   BooleanValue::Get(enabled);
	ColumnBindingReplacer replacer;
	Walk(input, plan, replacer, aggregates, joins);
	if (!replacer.replacement_bindings.empty()) {
		replacer.VisitOperator(*plan);
	}
}

} // namespace

void RegisterOracleOptimizer(DatabaseInstance &db) {
	OptimizerExtension extension;
	extension.optimize_function = OptimizeOraclePlan;
    extension.pre_optimize_function = PreOptimizeOraclePlan;
    OptimizerExtension::Register(DBConfig::GetConfig(db), std::move(extension));
	DBConfig::GetConfig(db).AddExtensionOption(
	    "oracle_top_n_pushdown",
	    "Let Oracle rank and cut an ORDER BY ... LIMIT over an attached table (numbers, dates and timestamps) so only "
	    "the first rows are read. DuckDB still sorts what comes back.",
	    LogicalType::BOOLEAN, Value::BOOLEAN(true));
    DBConfig::GetConfig(db).AddExtensionOption(
        "oracle_aggregate_pushdown",
        "Let Oracle compute COUNT (including eligible DISTINCT), SUM, MIN, MAX and GROUP BY over an attached table "
        "so the groups travel and not the rows.",
        LogicalType::BOOLEAN, Value::BOOLEAN(true));
    DBConfig::GetConfig(db).AddExtensionOption(
	    "oracle_join_pushdown",
	    "Let Oracle join two attached tables of the same database (inner joins on numbers, dates and timestamps) so "
	    "the join's result travels and not both tables.",
	    LogicalType::BOOLEAN, Value::BOOLEAN(true));
}

// The ORDER BY ... FETCH FIRST clause for a pushed Top-N, or empty when the keys
// were not pushable after all (see OracleQueryInit).
std::string OracleTopNClause(const OracleQueryBindData &bind) {
    if (bind.for_update) {
        return std::string();
    }
    if (bind.top_n.empty()) {
        if (bind.limit_rows) {
            return " FETCH FIRST " + std::to_string(*bind.limit_rows) + " ROWS ONLY";
        }
        return std::string();
	}
	std::string clause = " ORDER BY ";
	for (size_t index = 0; index < bind.top_n.size(); index++) {
		const auto &key = bind.top_n[index];
		if (index > 0) {
			clause += ", ";
		}
		clause += KeywordHelper::WriteQuotedAndEscaped(bind.columns[key.column].name, '"');
		clause += key.descending ? " DESC" : " ASC";
		clause += key.nulls_first ? " NULLS FIRST" : " NULLS LAST";
	}
	return clause + " FETCH FIRST " + std::to_string(bind.top_n_rows) + " ROWS ONLY";
}

} // namespace duckdb

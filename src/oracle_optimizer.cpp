// Plan rewrites for an attached Oracle table, run after DuckDB's own optimizers.
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

#include "duckdb/main/config.hpp"
#include "duckdb/optimizer/column_binding_replacer.hpp"
#include "duckdb/optimizer/optimizer.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/optimizer/optimizer_extension.hpp"
#include "duckdb/planner/expression/bound_aggregate_expression.hpp"
#include "duckdb/planner/expression/bound_cast_expression.hpp"
#include "duckdb/planner/operator/logical_aggregate.hpp"
#include "duckdb/planner/operator/logical_comparison_join.hpp"
#include "duckdb/planner/expression/bound_columnref_expression.hpp"
#include "duckdb/planner/operator/logical_get.hpp"
#include "duckdb/planner/operator/logical_projection.hpp"
#include "duckdb/planner/operator/logical_top_n.hpp"

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

// Aggregates. `SELECT g, count(*), sum(x) FROM o.T WHERE ... GROUP BY g` plans as
// an AGGREGATE over the scan, and the scan reads every row for DuckDB to add up.
// When the aggregate is one Oracle computes exactly as DuckDB does, the AGGREGATE
// and the scan are replaced by a scan of the statement
// `SELECT g, COUNT(*), SUM(x) FROM T WHERE ... GROUP BY g`, so the groups travel
// and not the rows.
//
// What counts as "exactly as DuckDB does" is narrow on purpose:
//  - COUNT(*), COUNT(column), SUM, MIN and MAX of a column, not DISTINCT, with no
//    FILTER or ORDER BY; no GROUPING SETS or GROUPING();
//  - SUM only of an exact number (integer or fixed-scale decimal), whose result
//    type matches DuckDB's; MIN and MAX and the group keys only of numbers, dates
//    and timestamps, which compare the same in both engines. Text is left out:
//    Oracle may group and order it by a collation (NLS_COMP, blank-padded CHAR)
//    where DuckDB compares bytes; floating point is left out because the order of
//    addition changes the result;
//  - every filter was translated into the WHERE clause, none is left for DuckDB
//    to apply to the rows (it would then see groups instead of rows), and the
//    scan has no sample and no filter a join will add later.
// Anything else leaves the plan as it was.

struct PushedAggregate {
	std::string sql;
	std::vector<OracleColumn> columns;
	vector<LogicalType> types;      // what the scan returns
	vector<LogicalType> wanted;     // what the AGGREGATE returned, groups first
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
		if (!KeyType(type) || type != group->GetReturnType() || OracleColumnRoundsOnRead(source)) {
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
		if (call.IsDistinct() || call.GetFilter() || call.GetOrderBys() || call.GetChildren().size() > 1) {
			return false;
		}
		const auto name = StringUtil::Lower(call.Function().GetName().GetIdentifierName());
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
			add("CAST(COUNT(" + Quoted(source) + ") AS NUMBER(18,0))", count_column, LogicalType::BIGINT, wanted);
		} else if ((name == "min" || name == "max") && KeyType(type) && wanted == type) {
			add(name == "min" ? "MIN(" + Quoted(source) + ")" : "MAX(" + Quoted(source) + ")", source, type, type);
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
	OptimizerExtension::Register(DBConfig::GetConfig(db), std::move(extension));
	DBConfig::GetConfig(db).AddExtensionOption(
	    "oracle_top_n_pushdown",
	    "Let Oracle rank and cut an ORDER BY ... LIMIT over an attached table (numbers, dates and timestamps) so only "
	    "the first rows are read. DuckDB still sorts what comes back.",
	    LogicalType::BOOLEAN, Value::BOOLEAN(true));
	DBConfig::GetConfig(db).AddExtensionOption(
	    "oracle_aggregate_pushdown",
	    "Let Oracle compute COUNT, SUM, MIN, MAX and GROUP BY over an attached table (numbers, dates and timestamps) "
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
	if (bind.top_n.empty()) {
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

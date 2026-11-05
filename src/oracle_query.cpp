#include "oracle_io_deadline.hpp"
#include <algorithm>
#include <chrono>
#include <set>
#include <unordered_map>
#include <condition_variable>
#include <thread>
#include "oracle_adapter.hpp"

#include "duckdb/execution/expression_executor.hpp"
#include "duckdb/parallel/task_scheduler.hpp"
#include "duckdb/planner/expression/bound_reference_expression.hpp"
#include "duckdb/planner/expression_iterator.hpp"
#include "duckdb/planner/expression/bound_conjunction_expression.hpp"

#include "oracle_scanner/auth_crypto.hpp"
#include "oracle_scanner/call_registry.hpp"
#include "oracle_scanner/call_builder.hpp"
#include "oracle_scanner/descriptor_parser.hpp"
#include "oracle_scanner/oracle_vector.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/session_factory.hpp"
#include "oracle_scanner/sql_statement.hpp"
// Only for the ORACLE_WIRE_TYPE_CURSOR wire constant; the adapter names no
// session or channel type from the protocol layer.
#include "oracle_scanner/ttc_execute.hpp"
#include "oracle_scanner/value_codec.hpp"
#include "oracle_scanner/wallet_archive.hpp"

#include "duckdb.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/profiler/profiling_node.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/main/client_context_state.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/common/types/time.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/storage/storage_extension.hpp"
#include "duckdb/transaction/duck_transaction_manager.hpp"
#include "duckdb/catalog/duck_catalog.hpp"
#include "duckdb/catalog/catalog_entry/duck_schema_entry.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/catalog/default/default_generator.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "duckdb/parser/column_definition.hpp"
#include "duckdb/parser/keyword_helper.hpp"
#include "duckdb/storage/table_storage_info.hpp"

#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <unordered_set>
#include <cmath>

namespace duckdb {

namespace {

using oracle_scanner::ConnectionConfig;
using oracle_scanner::OpenOracleSession;
using oracle_scanner::OracleColumn;
using oracle_scanner::OracleCursor;
using oracle_scanner::OracleSession;


// The watcher touches only the caller's synchronized deadline, never its
// session, socket or TLS objects. Join before unwinding the adapter scope.
class OracleCallerInterruptScope {
public:
    explicit OracleCallerInterruptScope(ClientContext &context_p)
        : context(context_p), source(OracleIoDeadlineFor(context)), previous(source->Get()) {
        Check();
        watcher = std::thread([this] {
            std::unique_lock<std::mutex> guard(lock);
            while (!stop) {
                if (context.IsInterrupted()) {
                    const auto now = std::chrono::steady_clock::now();
                    const auto current = source->Get();
                    source->Set(current ? (std::min)(*current, now) : now);
                    signalled = true;
                    return;
                }
                wake.wait_for(guard, std::chrono::milliseconds(20), [this] { return stop; });
            }
        });
    }
    ~OracleCallerInterruptScope() {
        Stop();
        if (signalled) { source->Set(previous); }
    }
    void Stop() {
        { std::lock_guard<std::mutex> guard(lock); stop = true; }
        wake.notify_one();
        if (watcher.joinable()) { watcher.join(); }
    }
    void Check() const { if (context.IsInterrupted()) { throw InterruptException(); } }
private:
    ClientContext &context;
    std::shared_ptr<oracle_scanner::OracleIoDeadline> source;
    oracle_scanner::OracleIoDeadline::Deadline previous;
    std::mutex lock;
    std::condition_variable wake;
    std::thread watcher;
    bool stop = false;
    bool signalled = false;
};

struct OracleExecuteBindData final : TableFunctionData {
    std::string catalog_name;
    ConnectionConfig config;
    std::string password;
    std::string sql;
    std::vector<oracle_scanner::OracleBind> binds;
};

struct OracleExecuteManyBindData final : TableFunctionData {
    ConnectionConfig config;
    std::string password;
    std::string sql;
    std::vector<std::vector<oracle_scanner::OracleBind>> rows;
};

struct OracleExecuteGlobalState final : GlobalTableFunctionState {
    explicit OracleExecuteGlobalState(uint64_t affected_rows_p) : affected_rows(affected_rows_p) {
    }
    uint64_t affected_rows;
    bool emitted = false;
};

struct OracleCallNumberBindData final : TableFunctionData {
    ConnectionConfig config;
    std::string password;
    std::string function;
};

struct OracleCallNumberArgsBindData final : TableFunctionData {
    ConnectionConfig config;
    std::string password;
    std::string function;
    std::vector<oracle_scanner::OracleBind> arguments;
};

struct OracleCallScalarGlobalState final : GlobalTableFunctionState {
    explicit OracleCallScalarGlobalState(std::optional<std::string> value_p) : value(std::move(value_p)) {
    }
    std::optional<std::string> value;
    bool emitted = false;
};

struct OracleCallOutNumberBindData final : TableFunctionData {
    ConnectionConfig config;
    std::string password;
    std::string procedure;
    std::string argument;
};

struct OracleCallOutVarcharBindData final : TableFunctionData {
    ConnectionConfig config;
    std::string password;
    std::string procedure;
    std::string argument;
};

struct OracleCallInOutNumberBindData final : TableFunctionData {
    ConnectionConfig config;
    std::string password;
    std::string procedure;
    std::string argument;
    std::vector<uint8_t> value;
};

struct OracleCallInOutVarcharBindData final : TableFunctionData {
    ConnectionConfig config;
    std::string password;
    std::string procedure;
    std::string argument;
    std::vector<uint8_t> value;
};

class SessionOwningCursor final : public oracle_scanner::OracleCursor {
public:
    SessionOwningCursor(std::shared_ptr<OracleSession> session_p, std::unique_ptr<oracle_scanner::OracleCursor> cursor_p)
        : session(std::move(session_p)), cursor(std::move(cursor_p)) {
    }

    const std::vector<OracleColumn> &Columns() const override { return cursor->Columns(); }
    oracle_scanner::OracleBatch Fetch(size_t requested_rows) override {
        return TranslatingOracleErrors("oracle_cursor could not fetch from Oracle",
                                       [&] { return cursor->Fetch(requested_rows); });
    }
    void Cancel() override { cursor->Cancel(); }
    void Close() override { cursor->Close(); }

private:
    // Destruction is reverse declaration order: close the cursor while the
    // session that owns its TTC channel is still retained.
    std::shared_ptr<OracleSession> session;
    std::unique_ptr<oracle_scanner::OracleCursor> cursor;
};

struct OracleCallRegistryState final : ClientContextState {
    oracle_scanner::CallRegistry registry;
};

oracle_scanner::CallRegistry &CallRegistryFor(ClientContext &context) {
    return context.registered_state->GetOrCreate<OracleCallRegistryState>("oracle_scanner.call_registry")->registry;
}

struct OracleCallBindData final : TableFunctionData {
    ConnectionConfig config;
    std::string password;
    std::string procedure;
    std::string cursor_argument;
};

struct OracleCallGlobalState final : GlobalTableFunctionState {
    explicit OracleCallGlobalState(std::vector<std::string> handles_p) : handles(std::move(handles_p)) {
    }
    std::vector<std::string> handles;
    idx_t next_handle = 0;
};

struct OracleCallImplicitBindData final : TableFunctionData {
    ConnectionConfig config;
    std::string password;
    std::string procedure;
};

struct OracleCallCursorsBindData final : TableFunctionData {
    ConnectionConfig config;
    std::string password;
    std::string procedure;
    std::vector<std::string> cursor_arguments;
};

struct OracleCallNamedBindData final : TableFunctionData {
    ConnectionConfig config;
    std::string password;
    std::string procedure;
    std::vector<oracle_scanner::OracleBind> arguments;
};

struct OracleCallNamedFunctionBindData final : TableFunctionData {
    ConnectionConfig config;
    std::string password;
    std::string function;
    oracle_scanner::OracleBind return_bind;
    std::vector<oracle_scanner::OracleBind> arguments;
};

struct OracleCallNamedRow {
    std::string name;
    std::optional<std::string> value;
    std::optional<std::string> cursor_handle;
};

struct OracleCallNamedGlobalState final : GlobalTableFunctionState {
    explicit OracleCallNamedGlobalState(std::vector<OracleCallNamedRow> rows_p) : rows(std::move(rows_p)) {
    }
    std::vector<OracleCallNamedRow> rows;
    idx_t next_row = 0;
};

struct OracleCursorBindData final : TableFunctionData {
    std::unique_ptr<oracle_scanner::OracleCursor> cursor;
    std::vector<OracleColumn> columns;
    std::vector<LogicalType> types;
};


struct OracleCloseCallBindData final : TableFunctionData {
    shared_ptr<OracleCallRegistryState> state;
    uint64_t call_id = 0;
};

struct OracleCloseCallGlobalState final : GlobalTableFunctionState {
    explicit OracleCloseCallGlobalState(bool closed_p) : closed(closed_p) {
    }
    bool closed;
    bool emitted = false;
};



std::vector<oracle_scanner::OracleBind> NamedBinds(const Value &value, const char *function_name);
std::vector<oracle_scanner::OracleBind> PositionalBinds(const Value &value, const char *function_name);

// The parameter types the attached catalog writes but that have no Oracle
// counterpart of their own spelling: they go through the one encoder a column
// write uses, so a value means the same in a query parameter as in an INSERT.
// Returns false for a type that is not one of them.
bool ExtraBind(const Value &value, const std::string &name, oracle_scanner::OracleBind &bind) {
    OracleColumn column;
    column.name = "parameter " + name;
    Value effective = value;
    switch (value.type().id()) {
    case LogicalTypeId::BOOLEAN:
        column.oracle_type = 252;
        break;
    case LogicalTypeId::INTERVAL: {
        // Months alone are a year-to-month interval; days and time a day-to-second one.
        const auto interval = value.GetValue<interval_t>();
        column.oracle_type = interval.days == 0 && interval.micros == 0 && interval.months != 0 ? 182 : 183;
        break;
    }
    case LogicalTypeId::TIMESTAMP_TZ:
        // An instant: bound as the TIMESTAMP of its UTC wall time, which the
        // UTC session turns back into the same instant.
        column.oracle_type = 231;
        break;
    case LogicalTypeId::TIMESTAMP_NS:
        column.oracle_type = 180;
        break;
    case LogicalTypeId::TIMESTAMP_MS:
    case LogicalTypeId::TIMESTAMP_SEC:
        column.oracle_type = 180;
        effective = value.DefaultCastAs(LogicalType::TIMESTAMP);
        break;
    case LogicalTypeId::HUGEINT:
    case LogicalTypeId::UHUGEINT:
        column.oracle_type = 2;
        break;
    default:
        return false;
    }
    bind = OracleBindForColumn(effective, column, name);
    return true;
}

std::optional<uint16_t> OracleInputType(LogicalTypeId type) {
    switch (type) {
    case LogicalTypeId::BOOLEAN:
        return 252;
    case LogicalTypeId::INTERVAL:
        return 183;
    case LogicalTypeId::TIMESTAMP_TZ:
    case LogicalTypeId::TIMESTAMP_NS:
    case LogicalTypeId::TIMESTAMP_MS:
    case LogicalTypeId::TIMESTAMP_SEC:
        return 180;
    case LogicalTypeId::HUGEINT:
    case LogicalTypeId::UHUGEINT:
        return 2;
    case LogicalTypeId::VARCHAR:
        return 1;
    case LogicalTypeId::DATE:
        return 12;
    case LogicalTypeId::BLOB:
        return 23;
    case LogicalTypeId::FLOAT:
        return 100;
    case LogicalTypeId::DOUBLE:
        return 101;
    case LogicalTypeId::TIMESTAMP:
        return 180;
    case LogicalTypeId::TINYINT:
    case LogicalTypeId::SMALLINT:
    case LogicalTypeId::INTEGER:
    case LogicalTypeId::BIGINT:
    case LogicalTypeId::UTINYINT:
    case LogicalTypeId::USMALLINT:
    case LogicalTypeId::UINTEGER:
    case LogicalTypeId::UBIGINT:
    case LogicalTypeId::DECIMAL:
        return 2;
    default:
        return std::nullopt;
    }
}

std::vector<oracle_scanner::OracleBind> ParameterBinds(const TableFunctionBindInput &input,
                                                        const char *function_name) {
    if (input.inputs.size() == 2) {
        return {};
    }
    if (input.inputs.size() != 3) {
        throw BinderException("%s accepts at most one params argument", function_name);
    }
    if (input.inputs[2].type().id() == LogicalTypeId::STRUCT) {
        return NamedBinds(input.inputs[2], function_name);
    }
    return PositionalBinds(input.inputs[2], function_name);
}

std::vector<oracle_scanner::OracleBind> PositionalBinds(const Value &value, const char *function_name) {
    if (value.type().id() != LogicalTypeId::LIST) {
        throw BinderException("%s params must be a LIST or STRUCT", function_name);
    }
    const auto values = ListValue::GetChildren(value);
    std::vector<oracle_scanner::OracleBind> binds;
    binds.reserve(values.size());
    for (idx_t index = 0; index < values.size(); index++) {
        const auto type = values[index].type().id();
        if (values[index].IsNull()) {
            const auto oracle_type = OracleInputType(type);
            if (!oracle_type) {
                throw BinderException("%s parameter %llu cannot infer an Oracle type for NULL %s", function_name,
                                      index + 1, values[index].type().ToString());
            }
            binds.push_back(oracle_scanner::OracleBind {std::to_string(index + 1), *oracle_type, oracle_scanner::BindDirection::BIND_IN, std::nullopt});
            continue;
        }
        if (type == LogicalTypeId::VARCHAR) {
            const auto text = values[index].GetValue<std::string>();
            binds.push_back(oracle_scanner::OracleBind {std::to_string(index + 1), 1, oracle_scanner::BindDirection::BIND_IN,
                             std::vector<uint8_t>(text.begin(), text.end())});
        } else if (type == LogicalTypeId::BLOB) {
            const auto bytes = StringValue::Get(values[index]);
            binds.push_back(oracle_scanner::OracleBind {std::to_string(index + 1), 23, oracle_scanner::BindDirection::BIND_IN,
                             std::vector<uint8_t>(bytes.begin(), bytes.end())});
        } else if (type == LogicalTypeId::FLOAT) {
            const auto number = values[index].GetValue<float>();
            if (!std::isfinite(number)) {
                throw BinderException("%s parameter %llu cannot be a non-finite FLOAT", function_name, index + 1);
            }
            binds.push_back(oracle_scanner::OracleBind {std::to_string(index + 1), 100, oracle_scanner::BindDirection::BIND_IN,
                             oracle_scanner::EncodeOracleBinaryFloat(number)});
        } else if (type == LogicalTypeId::DOUBLE) {
            const auto number = values[index].GetValue<double>();
            if (!std::isfinite(number)) {
                throw BinderException("%s parameter %llu cannot be a non-finite DOUBLE", function_name, index + 1);
            }
            binds.push_back(oracle_scanner::OracleBind {std::to_string(index + 1), 101, oracle_scanner::BindDirection::BIND_IN,
                             oracle_scanner::EncodeOracleBinaryDouble(number)});
        } else if (type == LogicalTypeId::DATE) {
            const auto date = values[index].GetValue<date_t>();
            if (!date.IsFinite()) {
                throw BinderException("%s parameter %llu cannot be an infinite DATE", function_name, index + 1);
            }
            int32_t year;
            int32_t month;
            int32_t day;
            Date::Convert(date, year, month, day);
            binds.push_back(oracle_scanner::OracleBind {std::to_string(index + 1), 12, oracle_scanner::BindDirection::BIND_IN,
                             oracle_scanner::EncodeOracleDate({year, static_cast<uint8_t>(month),
                                                               static_cast<uint8_t>(day)})});
        } else if (type == LogicalTypeId::TIMESTAMP) {
            const auto timestamp = values[index].GetValue<timestamp_t>();
            if (!timestamp.IsFinite()) {
                throw BinderException("%s parameter %llu cannot be an infinite TIMESTAMP", function_name, index + 1);
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
            binds.push_back(oracle_scanner::OracleBind {std::to_string(index + 1), 180, oracle_scanner::BindDirection::BIND_IN,
                             oracle_scanner::EncodeOracleTimestamp(
                                  {year, static_cast<uint8_t>(month), static_cast<uint8_t>(day),
                                   static_cast<uint8_t>(hour), static_cast<uint8_t>(minute), static_cast<uint8_t>(second),
                                  static_cast<uint32_t>(microseconds) * 1000U}, false)});
        } else if (type == LogicalTypeId::TINYINT || type == LogicalTypeId::SMALLINT || type == LogicalTypeId::INTEGER ||
                   type == LogicalTypeId::BIGINT || type == LogicalTypeId::UTINYINT || type == LogicalTypeId::USMALLINT ||
                   type == LogicalTypeId::UINTEGER || type == LogicalTypeId::UBIGINT || type == LogicalTypeId::DECIMAL) {
            binds.push_back(oracle_scanner::OracleBind {std::to_string(index + 1), 2, oracle_scanner::BindDirection::BIND_IN,
                             oracle_scanner::EncodeOracleNumber(values[index].ToString())});
        } else if (oracle_scanner::OracleBind extra; ExtraBind(values[index], std::to_string(index + 1), extra)) {
            binds.push_back(std::move(extra));
        } else {
            throw BinderException("%s parameter %llu has unsupported DuckDB type %s", function_name, index + 1,
                                  values[index].type().ToString());
        }
    }
    return binds;
}

std::vector<oracle_scanner::OracleBind> NamedBinds(const Value &value, const char *function_name) {
    if (value.type().id() != LogicalTypeId::STRUCT) {
        throw BinderException("%s arguments must be a STRUCT", function_name);
    }
    const auto &values = StructValue::GetChildren(value);
    std::vector<oracle_scanner::OracleBind> binds;
    binds.reserve(values.size());
    for (idx_t index = 0; index < values.size(); index++) {
        const auto &argument = values[index];
        // GetChildName returns an Identifier now; the bind name is its text.
        const std::string name = static_cast<const std::string &>(StructType::GetChildName(value.type(), index));
        if (argument.IsNull()) {
            const auto oracle_type = OracleInputType(argument.type().id());
            if (!oracle_type) {
                throw BinderException("%s cannot infer an Oracle type for NULL argument %s of type %s", function_name,
                                      name, argument.type().ToString());
            }
            binds.push_back(oracle_scanner::OracleBind {name, *oracle_type, oracle_scanner::BindDirection::BIND_IN, std::nullopt});
            continue;
        }
        if (argument.type().id() == LogicalTypeId::VARCHAR) {
            const auto text = argument.GetValue<std::string>();
            binds.push_back(oracle_scanner::OracleBind {name, 1, oracle_scanner::BindDirection::BIND_IN,
                             std::vector<uint8_t>(text.begin(), text.end())});
        } else if (argument.type().id() == LogicalTypeId::BLOB) {
            const auto bytes = StringValue::Get(argument);
            binds.push_back(oracle_scanner::OracleBind {name, 23, oracle_scanner::BindDirection::BIND_IN,
                             std::vector<uint8_t>(bytes.begin(), bytes.end())});
        } else if (argument.type().id() == LogicalTypeId::FLOAT) {
            const auto number = argument.GetValue<float>();
            if (!std::isfinite(number)) {
                throw BinderException("%s argument %s cannot be a non-finite FLOAT", function_name, name);
            }
            binds.push_back(oracle_scanner::OracleBind {name, 100, oracle_scanner::BindDirection::BIND_IN,
                             oracle_scanner::EncodeOracleBinaryFloat(number)});
        } else if (argument.type().id() == LogicalTypeId::DOUBLE) {
            const auto number = argument.GetValue<double>();
            if (!std::isfinite(number)) {
                throw BinderException("%s argument %s cannot be a non-finite DOUBLE", function_name, name);
            }
            binds.push_back(oracle_scanner::OracleBind {name, 101, oracle_scanner::BindDirection::BIND_IN,
                             oracle_scanner::EncodeOracleBinaryDouble(number)});
        } else if (argument.type().id() == LogicalTypeId::DATE) {
            const auto date = argument.GetValue<date_t>();
            if (!date.IsFinite()) {
                throw BinderException("%s argument %s cannot be an infinite DATE", function_name, name);
            }
            int32_t year;
            int32_t month;
            int32_t day;
            Date::Convert(date, year, month, day);
            binds.push_back(oracle_scanner::OracleBind {name, 12, oracle_scanner::BindDirection::BIND_IN,
                             oracle_scanner::EncodeOracleDate({year, static_cast<uint8_t>(month),
                                                               static_cast<uint8_t>(day)})});
        } else if (argument.type().id() == LogicalTypeId::TIMESTAMP) {
            const auto timestamp = argument.GetValue<timestamp_t>();
            if (!timestamp.IsFinite()) {
                throw BinderException("%s argument %s cannot be an infinite TIMESTAMP", function_name, name);
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
            binds.push_back(oracle_scanner::OracleBind {name, 180, oracle_scanner::BindDirection::BIND_IN,
                             oracle_scanner::EncodeOracleTimestamp(
                                  {year, static_cast<uint8_t>(month), static_cast<uint8_t>(day),
                                   static_cast<uint8_t>(hour), static_cast<uint8_t>(minute), static_cast<uint8_t>(second),
                                  static_cast<uint32_t>(microseconds) * 1000U}, false)});
        } else if (oracle_scanner::OracleBind extra; ExtraBind(argument, name, extra)) {
            binds.push_back(std::move(extra));
        } else if (argument.type().IsNumeric()) {
            binds.push_back(oracle_scanner::OracleBind {name, 2, oracle_scanner::BindDirection::BIND_IN,
                             oracle_scanner::EncodeOracleNumber(argument.ToString())});
        } else {
            throw BinderException("%s argument %s has unsupported DuckDB type %s", function_name, name,
                                  argument.type().ToString());
        }
    }
    return binds;
}

std::vector<oracle_scanner::OracleBind> CallArguments(const Value &value) {
    if (value.type().id() != LogicalTypeId::LIST ||
        ListType::GetChildType(value.type()).id() != LogicalTypeId::STRUCT) {
        throw BinderException("oracle_call_named arguments must be a LIST of STRUCT(name, direction, type, value)");
    }
    std::vector<oracle_scanner::OracleBind> result;
    for (const auto &argument : ListValue::GetChildren(value)) {
        if (argument.IsNull()) {
            throw BinderException("oracle_call_named arguments cannot contain NULL entries");
        }
        const auto &argument_type = argument.type();
        const auto &children = StructValue::GetChildren(argument);
        if (children.size() != 4 || StructType::GetChildName(argument_type, 0) != "name" ||
            StructType::GetChildName(argument_type, 1) != "direction" ||
            StructType::GetChildName(argument_type, 2) != "type" ||
            StructType::GetChildName(argument_type, 3) != "value" || children[0].IsNull() || children[1].IsNull() ||
            children[2].IsNull() || children[0].type().id() != LogicalTypeId::VARCHAR ||
            children[1].type().id() != LogicalTypeId::VARCHAR || children[2].type().id() != LogicalTypeId::VARCHAR ||
            children[3].type().id() != LogicalTypeId::VARCHAR) {
            throw BinderException("oracle_call_named argument entries must be STRUCT(name VARCHAR, direction VARCHAR, type VARCHAR, value VARCHAR)");
        }
        const auto name = children[0].GetValue<std::string>();
        const auto direction = StringUtil::Lower(children[1].GetValue<std::string>());
        const auto type = StringUtil::Lower(children[2].GetValue<std::string>());
        const auto value_child = children[3];
        oracle_scanner::BindDirection bind_direction;
        if (direction == "in") {
            bind_direction = oracle_scanner::BindDirection::BIND_IN;
        } else if (direction == "out") {
            bind_direction = oracle_scanner::BindDirection::BIND_OUT;
        } else if (direction == "inout") {
            bind_direction = oracle_scanner::BindDirection::BIND_IN_OUT;
        } else {
            throw BinderException("oracle_call_named direction for %s must be in, out, or inout", name);
        }
        // The value encoding is shared with the signature-driven path so the
        // two cannot disagree about what a value means.
        auto encoded = EncodeOracleCallableArgument(type, bind_direction, value_child, name, "oracle_call_named");
        result.push_back({name, encoded.oracle_type, bind_direction, std::move(encoded.value), encoded.maximum_bytes,
                          encoded.character_set_form});
    }
    if (result.empty()) {
        throw BinderException("oracle_call_named requires at least one argument");
    }
    return result;
}

// Runs the statement to describe it, as oracle_query does, and returns the bind
// data a scan then reads from. Shared by every function that is a SELECT with
// a generated or supplied text.
unique_ptr<FunctionData> BindOracleSelect(ClientContext &context, const std::string &secret_name,
                                          const std::string &sql,
                                          const std::function<std::vector<oracle_scanner::OracleBind>()> &make_binds,
                                          vector<LogicalType> &return_types, vector<Identifier> &names,
                                          bool transactional);

unique_ptr<FunctionData> OracleQueryBindCommon(ClientContext &context, TableFunctionBindInput &input,
                                               vector<LogicalType> &return_types, vector<Identifier> &names,
                                               bool transactional) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull()) {
        throw BinderException("oracle_query secret and SQL cannot be NULL");
    }
    const auto secret_name = input.inputs[0].GetValue<std::string>();
    const auto sql = input.inputs[1].GetValue<std::string>();
    return BindOracleSelect(
        context, secret_name, sql, [&] { return ParameterBinds(input, "oracle_query"); }, return_types, names,
        transactional);
}

unique_ptr<FunctionData> BindOracleSelect(ClientContext &context, const std::string &secret_name,
                                          const std::string &sql,
                                          const std::function<std::vector<oracle_scanner::OracleBind>()> &make_binds,
                                          vector<LogicalType> &return_types, vector<Identifier> &names,
                                          bool transactional) {
    std::string password;
    // The secret is validated before the SQL, as it was before the transactional
    // form shared this bind: a misconfigured secret is reported for what it is.
    oracle_scanner::ConnectionConfig config;
    if (!transactional) {
        config = ConnectionFromSecret(context, secret_name, password);
    }
    const auto binds = make_binds();
    oracle_scanner::ValidateOracleQuery(sql, binds);
    auto result = make_uniq<OracleQueryBindData>();
    result->secret_name = secret_name;
    if (transactional) {
        result->transactional_query = true;
        result->query_sql = sql;
        result->query_binds = binds;
        auto target = ResolveOracleWriteTarget(context, secret_name);
        result->catalog_name = target.catalog_name;
        TransactionSession(context, target);
        result->session = AcquireOracleReadSession(context, std::string(), target.catalog_name,
                                                   target.config, target.password);
    } else {
        result->session = AcquireOracleReadSession(context, secret_name, std::string(), config, password);
    }
    // The transactional form describes by running the query, so a SELECT FOR
    // UPDATE waits on its lock here: the caller's interrupt must reach it.
    std::unique_ptr<OracleCallerInterruptScope> interrupt;
    if (transactional) {
        interrupt = std::make_unique<OracleCallerInterruptScope>(context);
    }
    try {
        result->cursor = result->session->Query(sql, binds);
    } catch (const std::exception &error) {
        // Join first, retain the expired caller deadline through cleanup.
        if (interrupt) {
            interrupt->Stop();
        }
        // A pooled session whose statement failed cannot be handed to the next
        // one: the failure may have left the channel mid-message.
        result->session.Poison();
        if (transactional) {
            PoisonTransactionSession(context, result->catalog_name);
        }
        ThrowOracleAdapterError("oracle_query could not open Oracle query", error);
    }
    result->columns = result->cursor->Columns();
    if (result->columns.empty()) {
        throw BinderException("oracle_query received no described Oracle columns");
    }
    ApplyUnconstrainedNumberSetting(context, result->columns);
    std::unordered_set<std::string> used_names;
    for (idx_t index = 0; index < result->columns.size(); index++) {
        names.push_back(Identifier(OutputName(result->columns[index], index, used_names)));
        result->types.push_back(TypeFor(result->columns[index]));
        return_types.push_back(result->types.back());
    }
    if (transactional) {
        // Keep only describe metadata in a reusable plan. Execution must
        // reacquire the current transaction, never retain a borrowed session
        // across COMMIT or consume a cursor opened by PREPARE.
        result->cursor.reset();
        result->session = OracleSessionHandle();
    }
    return std::move(result);
}



unique_ptr<FunctionData> OracleQueryBind(ClientContext &context, TableFunctionBindInput &input,
                                         vector<LogicalType> &return_types, vector<Identifier> &names) {
    return OracleQueryBindCommon(context, input, return_types, names, false);
}

// oracle_vector_search: the rows of a table nearest to a query vector, found by
// Oracle with VECTOR_DISTANCE so a vector index is used when the table has one,
// and only the k rows come back.
//
// A name written without quotes is an Oracle name, so it is read in upper case,
// as Oracle would read it; a name in double quotes is kept as written.
std::string VectorSearchIdentifier(const Value &value, const char *what) {
    if (value.IsNull()) {
        throw BinderException("oracle_vector_search %s cannot be NULL", what);
    }
    auto text = value.GetValue<std::string>();
    if (text.size() >= 2 && text.front() == '"' && text.back() == '"') {
        return text.substr(1, text.size() - 2);
    }
    return StringUtil::Upper(text);
}

struct VectorSearchTarget {
    std::string owner; // empty: the connected user's
    std::string name;
};

VectorSearchTarget VectorSearchTable(const Value &value) {
    // OWNER.TABLE, each part by the same rule.
    auto text = value.IsNull() ? std::string() : value.GetValue<std::string>();
    if (text.empty()) {
        throw BinderException("oracle_vector_search table cannot be empty");
    }
    const auto dot = text.find('.');
    if (dot != std::string::npos && text.front() != '"') {
        return {StringUtil::Upper(text.substr(0, dot)),
                VectorSearchIdentifier(Value(text.substr(dot + 1)), "table")};
    }
    return {std::string(), VectorSearchIdentifier(value, "table")};
}

std::string SqlLiteral(const std::string &text) {
    std::string result = "'";
    for (const auto character : text) {
        result += character == '\'' ? std::string("''") : std::string(1, character);
    }
    return result + "'";
}

// The storage format the column declares (FLOAT32, FLOAT64, INT8 or BINARY), from
// the dictionary's VECTOR_INFO, or 0 when it cannot be read or says `*`. Oracle
// will not compare vectors of different formats, so the query vector has to be
// sent in the column's own.
uint8_t VectorColumnFormat(const ConnectionConfig &config, const std::string &password, const VectorSearchTarget &table,
                           const std::string &column) {
    try {
        auto session = OpenOracleSession(config, password);
        const auto view = table.owner.empty() ? "user_tab_cols" : "all_tab_cols";
        const auto sql = std::string("SELECT vector_info FROM ") + view + " WHERE table_name = " + SqlLiteral(table.name) +
                         " AND column_name = " + SqlLiteral(column) +
                         (table.owner.empty() ? std::string() : " AND owner = " + SqlLiteral(table.owner));
        auto cursor = session->Query(sql, {});
        std::string info;
        for (;;) {
            const auto batch = cursor->Fetch(8);
            for (const auto &row : batch.rows) {
                if (!row.empty() && row[0]) {
                    info.assign(row[0]->begin(), row[0]->end());
                }
            }
            if (batch.exhausted) {
                break;
            }
        }
        cursor->Close();
        session->Close();
        info = StringUtil::Upper(info);
        if (info.find("FLOAT32") != std::string::npos) {
            return oracle_scanner::ORACLE_VECTOR_FLOAT32;
        }
        if (info.find("FLOAT64") != std::string::npos) {
            return oracle_scanner::ORACLE_VECTOR_FLOAT64;
        }
        if (info.find("INT8") != std::string::npos) {
            return oracle_scanner::ORACLE_VECTOR_INT8;
        }
        if (info.find("BINARY") != std::string::npos) {
            return oracle_scanner::ORACLE_VECTOR_BINARY;
        }
    } catch (const std::exception &) {
        // A server without VECTOR_INFO has no vector column to search either, and
        // the search itself then says so in Oracle's words.
    }
    return 0;
}

unique_ptr<FunctionData> OracleVectorSearchBind(ClientContext &context, TableFunctionBindInput &input,
                                                vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull()) {
        throw BinderException("oracle_vector_search secret cannot be NULL");
    }
    const auto secret_name = input.inputs[0].GetValue<std::string>();
    const auto target = VectorSearchTable(input.inputs[1]);
    const auto table = (target.owner.empty() ? std::string()
                                             : KeywordHelper::WriteQuotedAndEscaped(target.owner, '"') + ".") +
                       KeywordHelper::WriteQuotedAndEscaped(target.name, '"');
    const auto column_name = VectorSearchIdentifier(input.inputs[2], "column");
    const auto column = KeywordHelper::WriteQuotedAndEscaped(column_name, '"');
    const auto &query = input.inputs[3];
    if (query.IsNull() || (query.type().id() != LogicalTypeId::LIST && query.type().id() != LogicalTypeId::ARRAY)) {
        throw BinderException("oracle_vector_search query vector must be a list or array of numbers");
    }
    int64_t k = 10;
    std::string metric = "COSINE";
    bool approximate = true;
    for (const auto &parameter : input.named_parameters) {
        const auto &key = static_cast<const std::string &>(parameter.first);
        if (parameter.second.IsNull()) {
            throw BinderException("oracle_vector_search %s cannot be NULL", key);
        }
        if (key == "k") {
            k = parameter.second.GetValue<int64_t>();
        } else if (key == "metric") {
            metric = StringUtil::Upper(parameter.second.GetValue<std::string>());
        } else if (key == "approximate") {
            approximate = parameter.second.GetValue<bool>();
        }
    }
    if (k < 1 || k > 100000) {
        throw BinderException("oracle_vector_search k must be between 1 and 100000");
    }
    // Words, not text from the caller: the metric goes into the statement.
    static const char *const METRICS[] = {"COSINE", "EUCLIDEAN", "EUCLIDEAN_SQUARED", "DOT", "MANHATTAN", "HAMMING"};
    bool known = false;
    for (const auto *candidate : METRICS) {
        known = known || metric == candidate;
    }
    if (!known) {
        throw BinderException("oracle_vector_search metric must be COSINE, EUCLIDEAN, EUCLIDEAN_SQUARED, DOT, "
                              "MANHATTAN or HAMMING, not '%s'",
                              metric);
    }
    // The query vector is bound as the image Oracle stores, in the column's own
    // format: Oracle will not compare vectors of two. When the column does not
    // say (a `*` format), FLOAT32 if the caller's numbers are FLOAT, else FLOAT64.
    OracleColumn vector_column;
    vector_column.name = "query vector";
    vector_column.oracle_type = 127;
    const auto element_type = query.type().id() == LogicalTypeId::LIST ? ListType::GetChildType(query.type())
                                                                       : ArrayType::GetChildType(query.type());
    std::string password;
    const auto config = ConnectionFromSecret(context, secret_name, password);
    vector_column.vector_format = VectorColumnFormat(config, password, target, column_name);
    if (vector_column.vector_format == 0) {
        vector_column.vector_format = element_type.id() == LogicalTypeId::FLOAT
                                          ? oracle_scanner::ORACLE_VECTOR_FLOAT32
                                          : oracle_scanner::ORACLE_VECTOR_FLOAT64;
    }
    std::vector<oracle_scanner::OracleBind> binds {OracleBindForColumn(query, vector_column, "1")};
    const auto distance = "VECTOR_DISTANCE(t." + column + ", :1, " + metric + ")";
    // ORDER BY the alias: the expression is the same one, and naming it twice
    // would make the statement carry the vector twice.
    const auto sql = "SELECT t.*, " + distance + " AS \"DISTANCE\" FROM " + table + " t ORDER BY \"DISTANCE\" FETCH " +
                     (approximate ? "APPROX " : "") + "FIRST " + std::to_string(k) + " ROWS ONLY";
    return BindOracleSelect(
        context, secret_name, sql, [&] { return binds; }, return_types, names, false);
}

unique_ptr<FunctionData> OracleTransactionQueryBind(ClientContext &context, TableFunctionBindInput &input,
                                                    vector<LogicalType> &return_types, vector<Identifier> &names) {
    return OracleQueryBindCommon(context, input, return_types, names, true);
}

// Oracle allows at most 1000 columns in a select list.
constexpr idx_t ORACLE_DECLARED_COLUMNS_LIMIT = 1000;

// A declared column type has to be one an Oracle column can map to, or no
// describe could ever match it. DECIMAL keeps its width and scale; the others
// are plain types, so a collation or a nested type is refused here.
LogicalType DeclaredColumnType(ClientContext &context, const std::string &text) {
    LogicalType type;
    try {
        type = TransformStringToLogicalType(text, context);
    } catch (const std::exception &) {
        throw BinderException("oracle_query_transaction_typed column type \"%s\" is not a DuckDB type", text);
    }
    switch (type.id()) {
    case LogicalTypeId::DECIMAL:
        return type;
    case LogicalTypeId::VARCHAR:
    case LogicalTypeId::BIGINT:
    case LogicalTypeId::BLOB:
    case LogicalTypeId::FLOAT:
    case LogicalTypeId::DOUBLE:
    case LogicalTypeId::TIMESTAMP:
    case LogicalTypeId::TIMESTAMP_NS:
        if (type == LogicalType(type.id())) {
            return type;
        }
        break;
    default:
        break;
    }
    throw BinderException("oracle_query_transaction_typed column type %s is not one an Oracle column maps to; use "
                          "VARCHAR, BIGINT, DECIMAL(p,s), DOUBLE, FLOAT, BLOB, TIMESTAMP or TIMESTAMP_NS",
                          type.ToString());
}

// The caller states the result columns, so bind needs Oracle for nothing: it
// opens no session, takes no lock and runs no statement, and a PREPAREd plan
// carries only the SQL, its binds and the declared columns. Init runs the
// statement once, in whichever transaction is current then, and refuses a
// describe that does not match the declaration.
unique_ptr<FunctionData> OracleTransactionTypedQueryBind(ClientContext &context, TableFunctionBindInput &input,
                                                         vector<LogicalType> &return_types,
                                                         vector<Identifier> &names) {
    if (input.inputs.size() > 5) {
        throw BinderException("oracle_query_transaction_typed accepts at most one params argument");
    }
    for (idx_t index = 0; index < 4; index++) {
        if (input.inputs[index].IsNull()) {
            throw BinderException("oracle_query_transaction_typed catalog, SQL, column names and column types "
                                  "cannot be NULL");
        }
    }
    auto result = make_uniq<OracleQueryBindData>();
    result->transactional_query = true;
    result->declared_schema = true;
    result->query_sql = input.inputs[1].GetValue<std::string>();
    if (input.inputs.size() == 5) {
        result->query_binds = input.inputs[4].type().id() == LogicalTypeId::STRUCT
                                  ? NamedBinds(input.inputs[4], "oracle_query_transaction_typed")
                                  : PositionalBinds(input.inputs[4], "oracle_query_transaction_typed");
    }
    oracle_scanner::ValidateOracleQuery(result->query_sql, result->query_binds);
    const auto &declared_names = ListValue::GetChildren(input.inputs[2]);
    const auto &declared_types = ListValue::GetChildren(input.inputs[3]);
    if (declared_names.empty() || declared_names.size() != declared_types.size()) {
        throw BinderException("oracle_query_transaction_typed needs as many column types as column names, and at "
                              "least one of each");
    }
    if (declared_names.size() > ORACLE_DECLARED_COLUMNS_LIMIT) {
        throw BinderException("oracle_query_transaction_typed declares more than 1000 columns");
    }
    case_insensitive_set_t used_names;
    for (idx_t index = 0; index < declared_names.size(); index++) {
        if (declared_names[index].IsNull() || declared_types[index].IsNull()) {
            throw BinderException("oracle_query_transaction_typed column names and types cannot contain NULL");
        }
        auto name = declared_names[index].GetValue<std::string>();
        if (name.empty() || name.find('\0') != std::string::npos || !used_names.insert(name).second) {
            throw BinderException("oracle_query_transaction_typed column names must be non-empty and unique");
        }
        const auto type = DeclaredColumnType(context, declared_types[index].GetValue<std::string>());
        OracleColumn column;
        column.name = name;
        result->columns.push_back(std::move(column));
        result->types.push_back(type);
        names.push_back(Identifier(std::move(name)));
        return_types.push_back(type);
    }
    // Resolving the catalog reads the attached database's own state only.
    result->catalog_name = ResolveOracleWriteTarget(context, input.inputs[0].GetValue<std::string>()).catalog_name;
    return std::move(result);
}

unique_ptr<FunctionData> OracleTransactionExecuteBind(ClientContext &context, TableFunctionBindInput &input,
                                                      vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull()) {
        throw BinderException("oracle_execute_transaction catalog and SQL cannot be NULL");
    }
    auto result = make_uniq<OracleExecuteBindData>();
    result->sql = input.inputs[1].GetValue<std::string>();
    result->binds = ParameterBinds(input, "oracle_execute_transaction");
    oracle_scanner::ValidateOracleDml(result->sql, result->binds);
    auto target = ResolveOracleWriteTarget(context, input.inputs[0].GetValue<std::string>());
    if (Catalog::GetCatalog(context, Identifier(target.catalog_name)).GetAttached().IsReadOnly()) {
        throw TransactionException("Cannot write to an attached read-only Oracle catalog");
    }
    result->catalog_name = target.catalog_name;
    names.push_back("affected_rows");
    return_types.push_back(LogicalType::UBIGINT);
    return std::move(result);
}

unique_ptr<FunctionData> OracleExecuteBind(ClientContext &context, TableFunctionBindInput &input,
                                           vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull()) {
        throw BinderException("oracle_execute secret and SQL cannot be NULL");
    }
    RequireAutoCommit(context, "oracle_execute");
    auto result = make_uniq<OracleExecuteBindData>();
    result->sql = input.inputs[1].GetValue<std::string>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->binds = ParameterBinds(input, "oracle_execute");
    oracle_scanner::ValidateOracleDml(result->sql, result->binds);
    names.push_back(Identifier("affected_rows"));
    return_types.push_back(LogicalType::UBIGINT);
    return std::move(result);
}

unique_ptr<FunctionData> OracleAdminBind(ClientContext &context, TableFunctionBindInput &input,
                                        vector<LogicalType> &return_types, vector<Identifier> &names) {
    RequireAutoCommit(context, "oracle_execute_admin");
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull()) {
        throw BinderException("oracle_execute_admin secret and SQL cannot be NULL");
    }
    auto result = make_uniq<OracleExecuteBindData>();
    result->sql = input.inputs[1].GetValue<std::string>();
    oracle_scanner::ValidateOracleAdmin(result->sql);
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    names.push_back("completed");
    return_types.push_back(LogicalType::BOOLEAN);
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleAdminInit(ClientContext &context, TableFunctionInitInput &input) {
    // Recheck at execution: a prepared DDL plan can outlive its bind transaction.
    RequireAutoCommit(context, "oracle_execute_admin");
    const auto &bind = input.bind_data->Cast<OracleExecuteBindData>();
    try {
        auto session = OpenOracleSession(bind.config, bind.password);
        session->ExecuteAdmin(bind.sql);
        session->Close();
        return make_uniq<OracleExecuteGlobalState>(0);
    } catch (const std::exception &error) {
        ThrowOracleAdapterError("oracle_execute_admin failed", error);
    }
}

void OracleAdminFunction(ClientContext &, TableFunctionInput &input, DataChunk &output) {
    auto &state = input.global_state->Cast<OracleExecuteGlobalState>();
    if (state.emitted) {
        return;
    }
    output.data[0].SetValue(0, Value::BOOLEAN(true));
    output.SetChildCardinality(1);
    state.emitted = true;
}

struct OracleStatusBindData final : TableFunctionData {
    std::string catalog_name;
};

struct OracleStatusGlobalState final : GlobalTableFunctionState {
    OracleTransactionStatus status;
    bool emitted = false;
};

unique_ptr<FunctionData> OracleStatusBind(ClientContext &context, TableFunctionBindInput &input,
                                         vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull()) {
        throw BinderException("oracle_transaction_status catalog cannot be NULL");
    }
    auto result = make_uniq<OracleStatusBindData>();
    result->catalog_name = ResolveOracleWriteTarget(context, input.inputs[0].GetValue<std::string>()).catalog_name;
    names = {"commit_outcome", "connection_state", "oracle_error_code", "protocol_error_kind"};
    return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::UINTEGER, LogicalType::INTEGER};
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleStatusInit(ClientContext &context, TableFunctionInitInput &input) {
    auto state = make_uniq<OracleStatusGlobalState>();
    state->status = GetOracleTransactionStatus(context, input.bind_data->Cast<OracleStatusBindData>().catalog_name);
    return std::move(state);
}

void OracleStatusFunction(ClientContext &, TableFunctionInput &input, DataChunk &output) {
    auto &state = input.global_state->Cast<OracleStatusGlobalState>();
    if (state.emitted) {
        return;
    }
    output.data[0].SetValue(0, Value(state.status.commit_outcome));
    output.data[1].SetValue(0, Value(state.status.connection_state));
    output.data[2].SetValue(0, state.status.oracle_code ? Value::UINTEGER(*state.status.oracle_code) : Value(LogicalType::UINTEGER));
    output.data[3].SetValue(0, state.status.protocol_kind ? Value::INTEGER(*state.status.protocol_kind) : Value(LogicalType::INTEGER));
    output.SetChildCardinality(1);
    state.emitted = true;
}

unique_ptr<GlobalTableFunctionState> OracleExecuteInit(ClientContext &, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleExecuteBindData>();
    try {
        auto session = OpenOracleSession(bind.config, bind.password);
        const auto affected_rows = session->ExecuteWithRowCount(bind.sql, bind.binds);
        session->Commit();
        session->Close();
        return make_uniq<OracleExecuteGlobalState>(affected_rows);
    } catch (const std::exception &error) {
        throw IOException("oracle_execute failed: %s", error.what());
    }
}

unique_ptr<GlobalTableFunctionState> OracleTransactionExecuteInit(ClientContext &context, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleExecuteBindData>();
    auto target = ResolveOracleWriteTarget(context, bind.catalog_name);
    if (Catalog::GetCatalog(context, Identifier(target.catalog_name)).GetAttached().IsReadOnly()) {
        throw TransactionException("Cannot write to an attached read-only Oracle catalog");
    }
    OracleCallerInterruptScope interrupt(context);
    try {
        auto &session = TransactionSession(context, target);
        const auto affected_rows = session.ExecuteWithRowCount(bind.sql, bind.binds);
        interrupt.Check();
        return make_uniq<OracleExecuteGlobalState>(affected_rows);
    } catch (const std::exception &error) {
        // Join first, retain the expired caller deadline through cleanup.
        interrupt.Stop();
        PoisonTransactionSession(context, target.catalog_name);
        ThrowOracleAdapterError("oracle_execute_transaction failed", error);
    }
}

void OracleExecuteFunction(ClientContext &, TableFunctionInput &input, DataChunk &output) {
    auto &state = input.global_state->Cast<OracleExecuteGlobalState>();
    if (!state.emitted) {
        output.data[0].SetValue(0, Value::UBIGINT(state.affected_rows));
        output.SetChildCardinality(1);
        state.emitted = true;
    }
}

unique_ptr<FunctionData> OracleExecuteManyBind(ClientContext &context, TableFunctionBindInput &input,
                                               vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull()) {
        throw BinderException("oracle_execute_many secret, SQL, and rows cannot be NULL");
    }
    RequireAutoCommit(context, "oracle_execute_many");
    if (input.inputs[2].type().id() != LogicalTypeId::LIST) {
        throw BinderException("oracle_execute_many rows must be a non-empty LIST of STRUCT or LIST bind records");
    }
    const auto row_type = ListType::GetChildType(input.inputs[2].type()).id();
    if (row_type != LogicalTypeId::STRUCT && row_type != LogicalTypeId::LIST) {
        throw BinderException("oracle_execute_many rows must be a non-empty LIST of STRUCT or LIST bind records");
    }
    const bool named_rows = row_type == LogicalTypeId::STRUCT;
    const auto &row_values = ListValue::GetChildren(input.inputs[2]);
    if (row_values.empty()) {
        throw BinderException("oracle_execute_many rows must not be empty");
    }
    auto result = make_uniq<OracleExecuteManyBindData>();
    result->sql = input.inputs[1].GetValue<std::string>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->rows.reserve(row_values.size());
    for (idx_t index = 0; index < row_values.size(); index++) {
        if (row_values[index].IsNull()) {
            throw BinderException("oracle_execute_many rows cannot contain NULL entries");
        }
        auto binds = named_rows ? NamedBinds(row_values[index], "oracle_execute_many")
                                : PositionalBinds(row_values[index], "oracle_execute_many");
        try {
            oracle_scanner::ValidateOracleDml(result->sql, binds);
        } catch (const std::exception &error) {
            throw BinderException("oracle_execute_many row %llu is invalid: %s", index + 1, error.what());
        }
        result->rows.push_back(std::move(binds));
    }
    names.push_back(Identifier("affected_rows"));
    return_types.push_back(LogicalType::UBIGINT);
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleExecuteManyInit(ClientContext &, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleExecuteManyBindData>();
    std::unique_ptr<OracleSession> session;
    try {
        session = OpenOracleSession(bind.config, bind.password);
        const auto affected_rows = session->ExecuteBatch(bind.sql, bind.rows);
        session->Commit();
        session->Close();
        return make_uniq<OracleExecuteGlobalState>(affected_rows);
    } catch (const std::exception &error) {
        if (session) {
            try {
                session->Rollback();
            } catch (...) {
            }
            try {
                session->Close();
            } catch (...) {
            }
        }
        ThrowOracleAdapterError("oracle_execute_many failed", error);
    }
}

unique_ptr<FunctionData> OracleCallNumberBind(ClientContext &context, TableFunctionBindInput &input,
                                              vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull()) {
        throw BinderException("oracle_call_number secret and function cannot be NULL");
    }
    auto result = make_uniq<OracleCallNumberBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->function = input.inputs[1].GetValue<std::string>();
    names.push_back(Identifier("value"));
    return_types.push_back(LogicalType::VARCHAR);
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleCallNumberInit(ClientContext &, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleCallNumberBindData>();
    try {
        auto session = OpenOracleSession(bind.config, bind.password);
        oracle_scanner::OracleCallRequest request;
        request.kind = oracle_scanner::OracleCallableKind::FUNCTION;
        request.qualified_name = bind.function;
        request.return_bind = {"r", 2, oracle_scanner::BindDirection::BIND_OUT, std::nullopt, 22};
        auto result = session->Call(request);
        if (result.outputs.size() != 1 || !result.explicit_cursors.empty() || !result.implicit_cursors.empty() ||
            result.outputs[0].oracle_type != 2) {
            throw BinderException("oracle_call_number requires a scalar Oracle NUMBER result");
        }
        std::optional<std::string> value;
        if (result.outputs[0].value) {
            value = oracle_scanner::DecodeOracleNumber(*result.outputs[0].value);
        }
        session->Close();
        return make_uniq<OracleCallScalarGlobalState>(std::move(value));
    } catch (const std::exception &error) {
        throw IOException("oracle_call_number failed: %s", error.what());
    }
}

unique_ptr<FunctionData> OracleCallNumberArgsBind(ClientContext &context, TableFunctionBindInput &input,
                                                  vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull()) {
        throw BinderException("oracle_call_number_args secret, function, and arguments cannot be NULL");
    }
    auto result = make_uniq<OracleCallNumberArgsBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->function = input.inputs[1].GetValue<std::string>();
    result->arguments = NamedBinds(input.inputs[2], "oracle_call_number_args");
    names.push_back(Identifier("value"));
    return_types.push_back(LogicalType::VARCHAR);
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleCallNumberArgsInit(ClientContext &, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleCallNumberArgsBindData>();
    try {
        auto session = OpenOracleSession(bind.config, bind.password);
        oracle_scanner::OracleCallRequest request;
        request.kind = oracle_scanner::OracleCallableKind::FUNCTION;
        request.qualified_name = bind.function;
        request.return_bind = {"r", 2, oracle_scanner::BindDirection::BIND_OUT, std::nullopt, 22};
        request.arguments = bind.arguments;
        auto result = session->Call(request);
        if (result.outputs.size() != 1 || !result.explicit_cursors.empty() || !result.implicit_cursors.empty() ||
            result.outputs[0].oracle_type != 2) {
            throw BinderException("oracle_call_number_args requires a scalar Oracle NUMBER result");
        }
        std::optional<std::string> value;
        if (result.outputs[0].value) {
            value = oracle_scanner::DecodeOracleNumber(*result.outputs[0].value);
        }
        session->Close();
        return make_uniq<OracleCallScalarGlobalState>(std::move(value));
    } catch (const std::exception &error) {
        throw IOException("oracle_call_number_args failed: %s", error.what());
    }
}

void OracleCallNumberFunction(ClientContext &, TableFunctionInput &input, DataChunk &output) {
    auto &state = input.global_state->Cast<OracleCallScalarGlobalState>();
    if (!state.emitted) {
        output.data[0].SetValue(0, state.value ? Value(*state.value) : Value());
        output.SetChildCardinality(1);
        state.emitted = true;
    }
}

unique_ptr<FunctionData> OracleCallOutNumberBind(ClientContext &context, TableFunctionBindInput &input,
                                                 vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull()) {
        throw BinderException("oracle_call_out_number secret, procedure, and output argument cannot be NULL");
    }
    auto result = make_uniq<OracleCallOutNumberBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->procedure = input.inputs[1].GetValue<std::string>();
    result->argument = input.inputs[2].GetValue<std::string>();
    names.push_back(Identifier("value"));
    return_types.push_back(LogicalType::VARCHAR);
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleCallOutNumberInit(ClientContext &, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleCallOutNumberBindData>();
    try {
        auto session = OpenOracleSession(bind.config, bind.password);
        oracle_scanner::OracleCallRequest request;
        request.kind = oracle_scanner::OracleCallableKind::PROCEDURE;
        request.qualified_name = bind.procedure;
        request.arguments = {{bind.argument, 2, oracle_scanner::BindDirection::BIND_OUT, std::nullopt, 22}};
        auto result = session->Call(request);
        if (result.outputs.size() != 1 || !result.explicit_cursors.empty() || !result.implicit_cursors.empty() ||
            result.outputs[0].oracle_type != 2) {
            throw BinderException("oracle_call_out_number requires one scalar Oracle NUMBER OUT argument");
        }
        std::optional<std::string> value;
        if (result.outputs[0].value) {
            value = oracle_scanner::DecodeOracleNumber(*result.outputs[0].value);
        }
        session->Close();
        return make_uniq<OracleCallScalarGlobalState>(std::move(value));
    } catch (const std::exception &error) {
        throw IOException("oracle_call_out_number failed: %s", error.what());
    }
}

unique_ptr<FunctionData> OracleCallOutVarcharBind(ClientContext &context, TableFunctionBindInput &input,
                                                  vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull()) {
        throw BinderException("oracle_call_out_varchar secret, procedure, and output argument cannot be NULL");
    }
    auto result = make_uniq<OracleCallOutVarcharBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->procedure = input.inputs[1].GetValue<std::string>();
    result->argument = input.inputs[2].GetValue<std::string>();
    names.push_back(Identifier("value"));
    return_types.push_back(LogicalType::VARCHAR);
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleCallOutVarcharInit(ClientContext &, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleCallOutVarcharBindData>();
    try {
        auto session = OpenOracleSession(bind.config, bind.password);
        oracle_scanner::OracleCallRequest request;
        request.kind = oracle_scanner::OracleCallableKind::PROCEDURE;
        request.qualified_name = bind.procedure;
        request.arguments = {{bind.argument, 1, oracle_scanner::BindDirection::BIND_OUT, std::nullopt, 32767}};
        auto result = session->Call(request);
        if (result.outputs.size() != 1 || !result.explicit_cursors.empty() || !result.implicit_cursors.empty() ||
            result.outputs[0].oracle_type != 1) {
            throw BinderException("oracle_call_out_varchar requires one scalar Oracle VARCHAR2 OUT argument");
        }
        std::optional<std::string> value;
        if (result.outputs[0].value) {
            value = std::string(result.outputs[0].value->begin(), result.outputs[0].value->end());
        }
        session->Close();
        return make_uniq<OracleCallScalarGlobalState>(std::move(value));
    } catch (const std::exception &error) {
        throw IOException("oracle_call_out_varchar failed: %s", error.what());
    }
}

unique_ptr<FunctionData> OracleCallInOutNumberBind(ClientContext &context, TableFunctionBindInput &input,
                                                    vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull() || input.inputs[3].IsNull()) {
        throw BinderException("oracle_call_inout_number secret, procedure, argument, and value cannot be NULL");
    }
    auto result = make_uniq<OracleCallInOutNumberBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->procedure = input.inputs[1].GetValue<std::string>();
    result->argument = input.inputs[2].GetValue<std::string>();
    result->value = oracle_scanner::EncodeOracleNumber(input.inputs[3].GetValue<std::string>());
    names.push_back(Identifier("value"));
    return_types.push_back(LogicalType::VARCHAR);
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleCallInOutNumberInit(ClientContext &, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleCallInOutNumberBindData>();
    try {
        auto session = OpenOracleSession(bind.config, bind.password);
        oracle_scanner::OracleCallRequest request;
        request.kind = oracle_scanner::OracleCallableKind::PROCEDURE;
        request.qualified_name = bind.procedure;
        request.arguments = {{bind.argument, 2, oracle_scanner::BindDirection::BIND_IN_OUT, bind.value, 22}};
        auto result = session->Call(request);
        if (result.outputs.size() != 1 || !result.explicit_cursors.empty() || !result.implicit_cursors.empty() ||
            result.outputs[0].oracle_type != 2) {
            throw BinderException("oracle_call_inout_number requires one scalar Oracle NUMBER IN OUT argument");
        }
        std::optional<std::string> value;
        if (result.outputs[0].value) {
            value = oracle_scanner::DecodeOracleNumber(*result.outputs[0].value);
        }
        session->Close();
        return make_uniq<OracleCallScalarGlobalState>(std::move(value));
    } catch (const std::exception &error) {
        throw IOException("oracle_call_inout_number failed: %s", error.what());
    }
}

unique_ptr<FunctionData> OracleCallInOutVarcharBind(ClientContext &context, TableFunctionBindInput &input,
                                                     vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull() || input.inputs[3].IsNull()) {
        throw BinderException("oracle_call_inout_varchar secret, procedure, argument, and value cannot be NULL");
    }
    auto result = make_uniq<OracleCallInOutVarcharBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->procedure = input.inputs[1].GetValue<std::string>();
    result->argument = input.inputs[2].GetValue<std::string>();
    const auto value = input.inputs[3].GetValue<std::string>();
    result->value = std::vector<uint8_t>(value.begin(), value.end());
    names.push_back(Identifier("value"));
    return_types.push_back(LogicalType::VARCHAR);
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleCallInOutVarcharInit(ClientContext &, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleCallInOutVarcharBindData>();
    try {
        auto session = OpenOracleSession(bind.config, bind.password);
        oracle_scanner::OracleCallRequest request;
        request.kind = oracle_scanner::OracleCallableKind::PROCEDURE;
        request.qualified_name = bind.procedure;
        request.arguments = {{bind.argument, 1, oracle_scanner::BindDirection::BIND_IN_OUT, bind.value, 32767}};
        auto result = session->Call(request);
        if (result.outputs.size() != 1 || !result.explicit_cursors.empty() || !result.implicit_cursors.empty() ||
            result.outputs[0].oracle_type != 1) {
            throw BinderException("oracle_call_inout_varchar requires one scalar Oracle VARCHAR2 IN OUT argument");
        }
        std::optional<std::string> value;
        if (result.outputs[0].value) {
            value = std::string(result.outputs[0].value->begin(), result.outputs[0].value->end());
        }
        session->Close();
        return make_uniq<OracleCallScalarGlobalState>(std::move(value));
    } catch (const std::exception &error) {
        throw IOException("oracle_call_inout_varchar failed: %s", error.what());
    }
}

unique_ptr<FunctionData> OracleCallBind(ClientContext &context, TableFunctionBindInput &input,
                                        vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull()) {
        throw BinderException("oracle_call secret, procedure, and cursor argument cannot be NULL");
    }
    auto result = make_uniq<OracleCallBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->procedure = input.inputs[1].GetValue<std::string>();
    result->cursor_argument = input.inputs[2].GetValue<std::string>();
    names.push_back(Identifier("cursor_handle"));
    return_types.push_back(LogicalType::VARCHAR);
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleCallInit(ClientContext &context, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleCallBindData>();
    try {
        auto session = std::shared_ptr<OracleSession>(OpenOracleSession(bind.config, bind.password));
        oracle_scanner::OracleCallRequest request;
        request.kind = oracle_scanner::OracleCallableKind::PROCEDURE;
        request.qualified_name = bind.procedure;
        request.arguments = {{bind.cursor_argument, oracle_scanner::ORACLE_WIRE_TYPE_CURSOR,
                              oracle_scanner::BindDirection::BIND_OUT, std::nullopt, 4}};
        auto result = session->Call(request);
        if (result.explicit_cursors.size() != 1 || !result.implicit_cursors.empty()) {
            throw BinderException("oracle_call currently requires exactly one explicit SYS_REFCURSOR result");
        }
        std::vector<std::unique_ptr<oracle_scanner::OracleCursor>> owned;
        owned.reserve(1);
        for (auto &cursor : result.explicit_cursors) {
            owned.emplace_back(std::make_unique<SessionOwningCursor>(session, std::move(cursor)));
        }
        const auto handles = CallRegistryFor(context).Register(std::move(owned));
        std::vector<std::string> formatted;
        formatted.reserve(handles.size());
        for (const auto &handle : handles) {
            formatted.push_back(oracle_scanner::FormatCursorHandle(handle));
        }
        return make_uniq<OracleCallGlobalState>(std::move(formatted));
    } catch (const std::exception &error) {
        throw IOException("oracle_call failed: %s", error.what());
    }
}

void OracleCallFunction(ClientContext &, TableFunctionInput &input, DataChunk &output) {
    auto &state = input.global_state->Cast<OracleCallGlobalState>();
    const auto remaining = state.handles.size() - state.next_handle;
    const auto count = std::min<idx_t>(remaining, STANDARD_VECTOR_SIZE);
    for (idx_t index = 0; index < count; index++) {
        output.data[0].SetValue(index, Value(state.handles[state.next_handle + index]));
    }
    state.next_handle += count;
    output.SetChildCardinality(count);
}

unique_ptr<FunctionData> OracleCallImplicitBind(ClientContext &context, TableFunctionBindInput &input,
                                                vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull()) {
        throw BinderException("oracle_call_implicit secret and procedure cannot be NULL");
    }
    auto result = make_uniq<OracleCallImplicitBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->procedure = input.inputs[1].GetValue<std::string>();
    names.push_back(Identifier("cursor_handle"));
    return_types.push_back(LogicalType::VARCHAR);
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleCallImplicitInit(ClientContext &context, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleCallImplicitBindData>();
    try {
        auto session = std::shared_ptr<OracleSession>(OpenOracleSession(bind.config, bind.password));
        oracle_scanner::OracleCallRequest request;
        request.kind = oracle_scanner::OracleCallableKind::PROCEDURE;
        request.qualified_name = bind.procedure;
        auto result = session->Call(request);
        if (!result.explicit_cursors.empty() || result.implicit_cursors.empty()) {
            throw BinderException("oracle_call_implicit requires one or more implicit cursor results");
        }
        std::vector<std::unique_ptr<oracle_scanner::OracleCursor>> owned;
        owned.reserve(result.implicit_cursors.size());
        for (auto &cursor : result.implicit_cursors) {
            owned.emplace_back(std::make_unique<SessionOwningCursor>(session, std::move(cursor)));
        }
        const auto handles = CallRegistryFor(context).Register(std::move(owned));
        std::vector<std::string> formatted;
        formatted.reserve(handles.size());
        for (const auto &handle : handles) {
            formatted.push_back(oracle_scanner::FormatCursorHandle(handle));
        }
        return make_uniq<OracleCallGlobalState>(std::move(formatted));
    } catch (const std::exception &error) {
        throw IOException("oracle_call_implicit failed: %s", error.what());
    }
}

unique_ptr<FunctionData> OracleCallCursorsBind(ClientContext &context, TableFunctionBindInput &input,
                                               vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull()) {
        throw BinderException("oracle_call_cursors secret, procedure, and cursor arguments cannot be NULL");
    }
    if (input.inputs[2].type().id() != LogicalTypeId::LIST ||
        ListType::GetChildType(input.inputs[2].type()).id() != LogicalTypeId::VARCHAR) {
        throw BinderException("oracle_call_cursors cursor arguments must be a LIST of VARCHAR names");
    }
    auto result = make_uniq<OracleCallCursorsBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->procedure = input.inputs[1].GetValue<std::string>();
    for (const auto &argument : ListValue::GetChildren(input.inputs[2])) {
        if (argument.IsNull() || argument.GetValue<std::string>().empty()) {
            throw BinderException("oracle_call_cursors cursor argument names must be non-empty");
        }
        result->cursor_arguments.push_back(argument.GetValue<std::string>());
    }
    if (result->cursor_arguments.empty()) {
        throw BinderException("oracle_call_cursors requires at least one cursor argument");
    }
    names.push_back(Identifier("cursor_handle"));
    return_types.push_back(LogicalType::VARCHAR);
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleCallCursorsInit(ClientContext &context, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleCallCursorsBindData>();
    try {
        auto session = std::shared_ptr<OracleSession>(OpenOracleSession(bind.config, bind.password));
        oracle_scanner::OracleCallRequest request;
        request.kind = oracle_scanner::OracleCallableKind::PROCEDURE;
        request.qualified_name = bind.procedure;
        for (const auto &argument : bind.cursor_arguments) {
            request.arguments.push_back(
                {argument, oracle_scanner::ORACLE_WIRE_TYPE_CURSOR, oracle_scanner::BindDirection::BIND_OUT, std::nullopt, 4});
        }
        auto result = session->Call(request);
        if (result.explicit_cursors.size() != bind.cursor_arguments.size() || !result.implicit_cursors.empty()) {
            throw BinderException("oracle_call_cursors procedure did not return every requested SYS_REFCURSOR");
        }
        std::vector<std::unique_ptr<oracle_scanner::OracleCursor>> owned;
        owned.reserve(result.explicit_cursors.size());
        for (auto &cursor : result.explicit_cursors) {
            owned.emplace_back(std::make_unique<SessionOwningCursor>(session, std::move(cursor)));
        }
        const auto handles = CallRegistryFor(context).Register(std::move(owned));
        std::vector<std::string> formatted;
        formatted.reserve(handles.size());
        for (const auto &handle : handles) {
            formatted.push_back(oracle_scanner::FormatCursorHandle(handle));
        }
        return make_uniq<OracleCallGlobalState>(std::move(formatted));
    } catch (const std::exception &error) {
        throw IOException("oracle_call_cursors failed: %s", error.what());
    }
}

unique_ptr<FunctionData> OracleCallNamedBind(ClientContext &context, TableFunctionBindInput &input,
                                             vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull()) {
        throw BinderException("oracle_call_named secret, procedure, and arguments cannot be NULL");
    }
    auto result = make_uniq<OracleCallNamedBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->procedure = input.inputs[1].GetValue<std::string>();
    result->arguments = CallArguments(input.inputs[2]);
    names = {"name", "value", "cursor_handle"};
    return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR};
    return std::move(result);
}

struct OracleArgumentsBindData final : TableFunctionData {
    ConnectionConfig config;
    std::string password;
    std::string callable;
};

struct OracleArgumentsRow {
    std::string overload;
    OracleCallableArgument argument;
};

struct OracleArgumentsGlobalState final : GlobalTableFunctionState {
    explicit OracleArgumentsGlobalState(std::vector<OracleArgumentsRow> rows_p) : rows(std::move(rows_p)) {
    }
    std::vector<OracleArgumentsRow> rows;
    idx_t next_row = 0;
};

// What a callable's signature is, as the data dictionary describes it and as
// this client would bind it. `bind_type` is the spelling oracle_call_named
// takes for the same argument, and it is NULL exactly when `unsupported_reason`
// says why the argument cannot be bound at all.
unique_ptr<FunctionData> OracleArgumentsBind(ClientContext &context, TableFunctionBindInput &input,
                                             vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull()) {
        throw BinderException("oracle_arguments secret and callable name cannot be NULL");
    }
    auto result = make_uniq<OracleArgumentsBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->callable = input.inputs[1].GetValue<std::string>();
    names = {"overload", "position", "argument_name", "direction", "oracle_type", "bind_type", "unsupported_reason"};
    return_types = {LogicalType::VARCHAR, LogicalType::INTEGER, LogicalType::VARCHAR,  LogicalType::VARCHAR,
                    LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR};
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleArgumentsInit(ClientContext &, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleArgumentsBindData>();
    auto session = OpenOracleSession(bind.config, bind.password);
    const auto overloads = ResolveOracleCallables(*session, bind.callable);
    session->Close();
    // Every overload, rather than a refusal: which one a caller wants is
    // decided by the arguments they pass, and this is where they find out what
    // the choices are.
    std::vector<OracleArgumentsRow> rows;
    for (const auto &signature : overloads) {
        for (const auto &argument : signature.arguments) {
            rows.push_back({signature.overload, argument});
        }
    }
    return make_uniq<OracleArgumentsGlobalState>(std::move(rows));
}

void OracleArgumentsFunction(ClientContext &, TableFunctionInput &input, DataChunk &output) {
    auto &state = input.global_state->Cast<OracleArgumentsGlobalState>();
    const auto count = std::min<idx_t>(state.rows.size() - state.next_row, STANDARD_VECTOR_SIZE);
    for (idx_t index = 0; index < count; index++) {
        const auto &row = state.rows[state.next_row + index];
        const auto &argument = row.argument;
        const char *direction = "in";
        if (argument.direction == oracle_scanner::BindDirection::BIND_OUT) {
            direction = "out";
        } else if (argument.direction == oracle_scanner::BindDirection::BIND_IN_OUT) {
            direction = "inout";
        }
        output.data[0].SetValue(index, row.overload.empty() ? Value() : Value(row.overload));
        output.data[1].SetValue(index, Value::INTEGER(argument.position));
        output.data[2].SetValue(index, Value(argument.name));
        output.data[3].SetValue(index, Value(direction));
        output.data[4].SetValue(index, argument.dictionary_type.empty() ? Value() : Value(argument.dictionary_type));
        output.data[5].SetValue(index, argument.bind_type_name.empty() ? Value() : Value(argument.bind_type_name));
        output.data[6].SetValue(index,
                        argument.unsupported_reason.empty() ? Value() : Value(argument.unsupported_reason));
    }
    state.next_row += count;
    output.SetChildCardinality(count);
}

struct OracleCallAutoBindData final : TableFunctionData {
    ConnectionConfig config;
    std::string password;
    std::string callable;
    std::vector<Value> values;
};

// The callable's own name, rebuilt from what the dictionary actually matched.
// Every component is quoted: the resolved triple is unambiguous where the
// caller's spelling may not have been, and a synonym has already been followed
// to the object it names.
std::string ResolvedCallableName(const OracleCallableSignature &signature) {
    std::string result = KeywordHelper::WriteQuotedAndEscaped(signature.owner, '"');
    if (!signature.package.empty()) {
        result += "." + KeywordHelper::WriteQuotedAndEscaped(signature.package, '"');
    }
    return result + "." + KeywordHelper::WriteQuotedAndEscaped(signature.object, '"');
}

unique_ptr<FunctionData> OracleCallAutoBind(ClientContext &context, TableFunctionBindInput &input,
                                            vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull()) {
        throw BinderException("oracle_call_auto secret, callable name, and values cannot be NULL");
    }
    auto result = make_uniq<OracleCallAutoBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->callable = input.inputs[1].GetValue<std::string>();
    if (input.inputs[2].type().id() != LogicalTypeId::LIST) {
        throw BinderException("oracle_call_auto values must be a LIST of VARCHAR, one per argument");
    }
    for (const auto &child : ListValue::GetChildren(input.inputs[2])) {
        if (child.IsNull()) {
            result->values.emplace_back(LogicalType::VARCHAR);
            continue;
        }
        if (child.type().id() != LogicalTypeId::VARCHAR) {
            throw BinderException("oracle_call_auto values must be a LIST of VARCHAR, one per argument");
        }
        result->values.push_back(child);
    }
    names = {"name", "value", "cursor_handle"};
    return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR};
    return std::move(result);
}

// Calls a procedure or function whose signature comes from the dictionary, so
// the caller supplies only values. It is the same call the hand-written
// oracle_call_named makes — same binds, same encoding, same outputs — with the
// directions and types looked up instead of restated.
unique_ptr<GlobalTableFunctionState> OracleCallAutoInit(ClientContext &context, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleCallAutoBindData>();
    auto session = std::shared_ptr<OracleSession>(OpenOracleSession(bind.config, bind.password));
    // The value count is the only thing that can choose between overloads, and
    // the caller has already given it.
    const auto overloads = ResolveOracleCallables(*session, bind.callable);
    const auto &signature = SelectOracleCallableOverload(overloads, bind.values.size(), bind.callable);

    std::vector<oracle_scanner::OracleBind> arguments;
    std::optional<oracle_scanner::OracleBind> return_bind;
    size_t value_index = 0;
    for (const auto &argument : signature.arguments) {
        if (!argument.unsupported_reason.empty()) {
            throw NotImplementedException("Oracle argument \"%s\" of %s cannot be bound: %s", argument.name,
                                          bind.callable, argument.unsupported_reason);
        }
        if (argument.position == 0) {
            oracle_scanner::OracleBind result_bind;
            result_bind.name = argument.name;
            result_bind.direction = oracle_scanner::BindDirection::BIND_OUT;
            result_bind.oracle_type = argument.oracle_type;
            result_bind.maximum_bytes = argument.maximum_bytes;
            result_bind.character_set_form = argument.bind_type_name == "nvarchar" ? 2 : 0;
            return_bind = std::move(result_bind);
            continue;
        }
        if (value_index >= bind.values.size()) {
            throw BinderException("oracle_call_auto: %s takes %llu arguments but %llu values were supplied",
                                  bind.callable,
                                  static_cast<uint64_t>(signature.arguments.size() - (signature.is_function ? 1 : 0)),
                                  static_cast<uint64_t>(bind.values.size()));
        }
        auto encoded = EncodeOracleCallableArgument(argument.bind_type_name, argument.direction,
                                                    bind.values[value_index++], argument.name, "oracle_call_auto");
        arguments.push_back({argument.name, encoded.oracle_type, argument.direction, std::move(encoded.value),
                             encoded.maximum_bytes, encoded.character_set_form});
    }
    if (value_index != bind.values.size()) {
        throw BinderException("oracle_call_auto: %s takes %llu arguments but %llu values were supplied", bind.callable,
                              static_cast<uint64_t>(value_index), static_cast<uint64_t>(bind.values.size()));
    }

    try {
        oracle_scanner::OracleCallRequest request;
        request.kind = signature.is_function ? oracle_scanner::OracleCallableKind::FUNCTION
                                             : oracle_scanner::OracleCallableKind::PROCEDURE;
        request.qualified_name = ResolvedCallableName(signature);
        request.return_bind = return_bind;
        request.arguments = arguments;
        auto result = session->Call(request);
        if (!result.implicit_cursors.empty()) {
            throw BinderException("oracle_call_auto does not combine explicit and implicit cursor results");
        }
        std::vector<OracleCallNamedRow> rows;
        std::vector<std::unique_ptr<oracle_scanner::OracleCursor>> owned;
        std::vector<idx_t> cursor_rows;
        size_t scalar_index = 0;
        size_t cursor_index = 0;
        if (return_bind) {
            OracleCallNamedRow return_row;
            return_row.name = return_bind->name;
            if (return_bind->oracle_type == oracle_scanner::ORACLE_WIRE_TYPE_CURSOR) {
                // The return bind is the first bind of the call, so its cursor
                // is the first one the server sent back.
                if (result.explicit_cursors.empty()) {
                    throw BinderException("oracle_call_auto expected a REF CURSOR return value");
                }
                owned.emplace_back(
                    std::make_unique<SessionOwningCursor>(session, std::move(result.explicit_cursors[cursor_index++])));
                cursor_rows.push_back(rows.size());
            } else {
                if (result.outputs.empty() || result.outputs[0].oracle_type != return_bind->oracle_type) {
                    throw BinderException("oracle_call_auto return value disagrees with Oracle response");
                }
                if (result.outputs[0].value) {
                    return_row.value = FormatCallScalar(return_bind->oracle_type, *result.outputs[0].value, return_bind->character_set_form);
                }
                scalar_index = 1;
            }
            rows.push_back(std::move(return_row));
        }
        for (const auto &argument : arguments) {
            if (argument.direction == oracle_scanner::BindDirection::BIND_IN) {
                continue;
            }
            OracleCallNamedRow row;
            row.name = argument.name;
            if (argument.oracle_type == oracle_scanner::ORACLE_WIRE_TYPE_CURSOR) {
                if (cursor_index >= result.explicit_cursors.size()) {
                    throw BinderException("oracle_call_auto cursor output count disagrees with Oracle response");
                }
                owned.emplace_back(
                    std::make_unique<SessionOwningCursor>(session, std::move(result.explicit_cursors[cursor_index++])));
                cursor_rows.push_back(rows.size());
            } else {
                if (scalar_index >= result.outputs.size() ||
                    result.outputs[scalar_index].oracle_type != argument.oracle_type) {
                    throw BinderException("oracle_call_auto scalar output count disagrees with Oracle response");
                }
                const auto &output = result.outputs[scalar_index++];
                if (output.value) {
                    row.value = FormatCallScalar(argument.oracle_type, *output.value, argument.character_set_form);
                }
            }
            rows.push_back(std::move(row));
        }
        if (scalar_index != result.outputs.size() || cursor_index != result.explicit_cursors.size()) {
            throw BinderException("oracle_call_auto received unexpected Oracle output values");
        }
        if (!owned.empty()) {
            const auto handles = CallRegistryFor(context).Register(std::move(owned));
            for (idx_t index = 0; index < handles.size(); index++) {
                rows[cursor_rows[index]].cursor_handle = oracle_scanner::FormatCursorHandle(handles[index]);
            }
        }
        return make_uniq<OracleCallNamedGlobalState>(std::move(rows));
    } catch (const oracle_scanner::ProtocolError &error) {
        throw IOException("oracle_call_auto failed: %s", error.what());
    }
}


// These limits bound adapter bind/output materialization, not Oracle process PGA.
constexpr size_t ORACLE_TRANSACTION_ROWS_LIMIT = 2048;
constexpr size_t ORACLE_TRANSACTION_BIND_BYTES = 131072;

void AddTransactionBindBytes(size_t &bytes, size_t amount) {
    if (amount > ORACLE_TRANSACTION_BIND_BYTES - bytes) {
        throw BinderException("Oracle transaction bind/output budget exceeds 131072 bytes");
    }
    bytes += amount;
}

struct OracleTransactionManyBindData final : TableFunctionData {
    std::string catalog_name;
    std::string sql;
    std::vector<std::vector<oracle_scanner::OracleBind>> rows;
    bool exact_counts = true;
};

struct OracleTransactionManyState final : GlobalTableFunctionState {
    std::vector<uint64_t> counts;
    bool exact_counts = true;
    idx_t next = 0;
};

unique_ptr<FunctionData> OracleTransactionManyBind(ClientContext &context, TableFunctionBindInput &input,
                                                  vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull() ||
        input.inputs[2].type().id() != LogicalTypeId::LIST) {
        throw BinderException("oracle_execute_many_transaction requires catalog, SQL and non-NULL bind rows");
    }
    const auto &values = ListValue::GetChildren(input.inputs[2]);
    const auto type = ListType::GetChildType(input.inputs[2].type()).id();
    if (values.empty() || values.size() > ORACLE_TRANSACTION_ROWS_LIMIT ||
        (type != LogicalTypeId::STRUCT && type != LogicalTypeId::LIST)) {
        throw BinderException("oracle_execute_many_transaction needs 1..2048 STRUCT or LIST rows");
    }
    auto result = make_uniq<OracleTransactionManyBindData>();
    const auto option = input.named_parameters.find("exact_counts");
    if (option != input.named_parameters.end()) {
        if (option->second.IsNull()) {
            throw BinderException("oracle_execute_many_transaction exact_counts cannot be NULL");
        }
        result->exact_counts = option->second.GetValue<bool>();
    }
    result->sql = input.inputs[1].GetValue<std::string>();
    if (result->sql.size() > 65536) {
        throw BinderException("oracle_execute_many_transaction SQL exceeds 65536 bytes");
    }
    size_t bytes = 0;
    result->rows.reserve(values.size());
    for (idx_t index = 0; index < values.size(); ++index) {
        if (values[index].IsNull()) {
            throw BinderException("oracle_execute_many_transaction row %llu is NULL", index + 1);
        }
        auto binds = type == LogicalTypeId::STRUCT ? NamedBinds(values[index], "oracle_execute_many_transaction")
                                                  : PositionalBinds(values[index], "oracle_execute_many_transaction");
        try {
            oracle_scanner::ValidateOracleDml(result->sql, binds);
        } catch (const std::exception &error) {
            throw BinderException("oracle_execute_many_transaction row %llu is invalid: %s", index + 1, error.what());
        }
        for (const auto &bind : binds) {
            AddTransactionBindBytes(bytes, bind.name.size());
            AddTransactionBindBytes(bytes, bind.value ? bind.value->size() : 0);
        }
        result->rows.emplace_back(std::move(binds));
    }
    auto target = ResolveOracleWriteTarget(context, input.inputs[0].GetValue<std::string>());
    if (Catalog::GetCatalog(context, Identifier(target.catalog_name)).GetAttached().IsReadOnly()) {
        throw TransactionException("Cannot write to an attached read-only Oracle catalog");
    }
    result->catalog_name = target.catalog_name;
    names = {"row_index", "affected_rows", "exact_counts"};
    return_types = {LogicalType::UBIGINT, LogicalType::UBIGINT, LogicalType::BOOLEAN};
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleTransactionManyInit(ClientContext &context,
                                                               TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleTransactionManyBindData>();
    auto target = ResolveOracleWriteTarget(context, bind.catalog_name);
    if (Catalog::GetCatalog(context, Identifier(target.catalog_name)).GetAttached().IsReadOnly()) {
        throw TransactionException("Cannot write to an attached read-only Oracle catalog");
    }
    auto state = make_uniq<OracleTransactionManyState>();
    state->exact_counts = bind.exact_counts;
    OracleCallerInterruptScope interrupt(context);
    try {
        auto &session = TransactionSession(context, target);
        if (bind.exact_counts) {
            state->counts.reserve(bind.rows.size());
            for (idx_t index = 0; index < bind.rows.size(); ++index) {
                interrupt.Check();
                try {
                    state->counts.push_back(session.ExecuteWithRowCount(bind.sql, bind.rows[index]));
                } catch (const oracle_scanner::ProtocolError &error) {
                    throw oracle_scanner::ProtocolError(error.Kind(),
                        "Oracle exact batch row " + std::to_string(index + 1) + ": " + error.what(), error.OracleCode());
                }
            }
        } else {
            state->counts.push_back(session.ExecuteBatch(bind.sql, bind.rows));
        }
        interrupt.Check();
        return std::move(state);
    } catch (const std::exception &error) {
        // Join first, retain the expired caller deadline through cleanup.
        // Rollback cannot wait for a reply on the interrupted exchange.
        interrupt.Stop();
        PoisonTransactionSession(context, target.catalog_name);
        ThrowOracleAdapterError("oracle_execute_many_transaction failed", error);
    }
}

void OracleTransactionManyFunction(ClientContext &, TableFunctionInput &input, DataChunk &output) {
    auto &state = input.global_state->Cast<OracleTransactionManyState>();
    const auto count = std::min<idx_t>(state.counts.size() - state.next, STANDARD_VECTOR_SIZE);
    for (idx_t index = 0; index < count; ++index) {
        output.data[0].SetValue(index, state.exact_counts ? Value::UBIGINT(state.next + index + 1)
                                                   : Value(LogicalType::UBIGINT));
        output.data[1].SetValue(index, Value::UBIGINT(state.counts[state.next + index]));
        output.data[2].SetValue(index, Value::BOOLEAN(state.exact_counts));
    }
    output.SetChildCardinality(count);
    state.next += count;
}

struct OracleCompositeBindData final : TableFunctionData {
    std::string catalog_name;
    oracle_scanner::OracleCallRequest request;
    // The sum of the expected counts. The block raises unless every statement
    // affected exactly its count, so a block that returns affected this many.
    uint64_t affected_rows = 0;
};

unique_ptr<FunctionData> OracleCompositeBind(ClientContext &context, TableFunctionBindInput &input,
                                             vector<LogicalType> &return_types, vector<Identifier> &names) {
    for (const auto &value : input.inputs) {
        if (value.IsNull()) {
            throw BinderException("oracle_execute_composite_transaction arguments cannot be NULL");
        }
    }
    const auto params_type = input.inputs[2].type().id();
    if (params_type != LogicalTypeId::STRUCT && params_type != LogicalTypeId::LIST) {
        throw BinderException("oracle_execute_composite_transaction params must be a STRUCT of named binds or a LIST "
                              "of positional ones");
    }
    const auto &statements = ListValue::GetChildren(input.inputs[1]);
    const auto &counts = ListValue::GetChildren(input.inputs[3]);
    if (statements.empty() || statements.size() > oracle_scanner::ORACLE_DML_COMPOSITE_MAX_OPERATIONS) {
        throw BinderException("oracle_execute_composite_transaction needs 1..16 statements");
    }
    if (statements.size() != counts.size()) {
        throw BinderException("oracle_execute_composite_transaction needs one expected row count per statement");
    }
    auto result = make_uniq<OracleCompositeBindData>();
    result->request.kind = oracle_scanner::OracleCallableKind::DML_COMPOSITE;
    result->request.arguments = params_type == LogicalTypeId::STRUCT
                                    ? NamedBinds(input.inputs[2], "oracle_execute_composite_transaction")
                                    : PositionalBinds(input.inputs[2], "oracle_execute_composite_transaction");
    for (idx_t index = 0; index < statements.size(); index++) {
        if (statements[index].IsNull() || counts[index].IsNull()) {
            throw BinderException("oracle_execute_composite_transaction statement %llu or its count is NULL",
                                  index + 1);
        }
        const auto count = counts[index].GetValue<int64_t>();
        if (count < 0 || static_cast<uint64_t>(count) > oracle_scanner::ORACLE_DML_COMPOSITE_MAX_EXPECTED_ROWS) {
            throw BinderException("oracle_execute_composite_transaction expected row count %lld of statement %llu is "
                                  "outside 0..1000000",
                                  count, index + 1);
        }
        result->request.dml_operations.push_back({statements[index].GetValue<std::string>(),
                                                  static_cast<uint64_t>(count)});
        result->affected_rows += static_cast<uint64_t>(count);
    }
    // The whole block is built here once, so every refusal it can make is made
    // before a session is touched.
    try {
        oracle_scanner::BuildOracleCallBlock(result->request);
    } catch (const std::exception &error) {
        throw BinderException("oracle_execute_composite_transaction statements are invalid: %s", error.what());
    }
    auto target = ResolveOracleWriteTarget(context, input.inputs[0].GetValue<std::string>());
    if (Catalog::GetCatalog(context, Identifier(target.catalog_name)).GetAttached().IsReadOnly()) {
        throw TransactionException("Cannot write to an attached read-only Oracle catalog");
    }
    result->catalog_name = target.catalog_name;
    names.push_back(Identifier("affected_rows"));
    return_types.push_back(LogicalType::UBIGINT);
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleCompositeInit(ClientContext &context, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleCompositeBindData>();
    auto target = ResolveOracleWriteTarget(context, bind.catalog_name);
    if (Catalog::GetCatalog(context, Identifier(target.catalog_name)).GetAttached().IsReadOnly()) {
        throw TransactionException("Cannot write to an attached read-only Oracle catalog");
    }
    OracleCallerInterruptScope interrupt(context);
    try {
        auto &session = TransactionSession(context, target);
        // Sent once. A block that failed is never retried: the statements
        // before the failing one ran, and only the transaction's rollback
        // takes them back.
        auto result = session.Call(bind.request);
        if (!result.outputs.empty() || !result.explicit_cursors.empty() || !result.implicit_cursors.empty()) {
            for (auto &cursor : result.explicit_cursors) {
                cursor->Close();
            }
            for (auto &cursor : result.implicit_cursors) {
                cursor->Close();
            }
            throw IOException("oracle_execute_composite_transaction received results it did not ask for");
        }
        interrupt.Check();
        return make_uniq<OracleExecuteGlobalState>(bind.affected_rows);
    } catch (const std::exception &error) {
        // Join first, retain the expired caller deadline through cleanup.
        // Rollback cannot wait for a reply on the interrupted exchange.
        interrupt.Stop();
        PoisonTransactionSession(context, target.catalog_name);
        ThrowOracleAdapterError("oracle_execute_composite_transaction failed", error);
    }
}

struct OracleTransactionCallBindData final : TableFunctionData {
    std::string catalog_name;
    std::string procedure;
    std::vector<oracle_scanner::OracleBind> arguments;
};

unique_ptr<FunctionData> OracleTransactionCallBind(ClientContext &context, TableFunctionBindInput &input,
                                                  vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull() ||
        input.inputs[2].type().id() != LogicalTypeId::LIST || ListValue::GetChildren(input.inputs[2]).size() > 64) {
        throw BinderException("oracle_call_named_transaction requires catalog, procedure and 1..64 scalar arguments");
    }
    auto result = make_uniq<OracleTransactionCallBindData>();
    result->procedure = input.inputs[1].GetValue<std::string>();
    try {
        result->arguments = CallArguments(input.inputs[2]);
    } catch (const std::exception &error) {
        throw BinderException("oracle_call_named_transaction arguments are invalid: %s", error.what());
    }
    size_t bytes = 0;
    for (const auto &bind : result->arguments) {
        if (bind.oracle_type != 1 && bind.oracle_type != 2) {
            throw BinderException("oracle_call_named_transaction currently supports NUMBER and VARCHAR arguments only");
        }
        if (bind.value && bind.value->size() > 32767) {
            throw BinderException("oracle_call_named_transaction scalar value exceeds 32767 bytes");
        }
        AddTransactionBindBytes(bytes, bind.name.size());
        AddTransactionBindBytes(bytes, bind.value ? bind.value->size() : 0);
        if (bind.direction != oracle_scanner::BindDirection::BIND_IN) {
            AddTransactionBindBytes(bytes, bind.maximum_bytes);
        }
    }
    try {
        oracle_scanner::BuildOracleProcedureCallBlock(result->procedure, result->arguments);
    } catch (const std::exception &error) {
        throw BinderException("oracle_call_named_transaction name or arguments are invalid: %s", error.what());
    }
    auto target = ResolveOracleWriteTarget(context, input.inputs[0].GetValue<std::string>());
    if (Catalog::GetCatalog(context, Identifier(target.catalog_name)).GetAttached().IsReadOnly()) {
        throw TransactionException("Cannot call through an attached read-only Oracle catalog");
    }
    result->catalog_name = target.catalog_name;
    names = {"name", "value"};
    return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR};
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleTransactionCallInit(ClientContext &context, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleTransactionCallBindData>();
    auto target = ResolveOracleWriteTarget(context, bind.catalog_name);
    if (Catalog::GetCatalog(context, Identifier(target.catalog_name)).GetAttached().IsReadOnly()) {
        throw TransactionException("Cannot call through an attached read-only Oracle catalog");
    }
    OracleCallerInterruptScope interrupt(context);
    try {
        auto &session = TransactionSession(context, target);
        // A procedure can change package state, NLS or the current schema of
        // the session itself; the session ends closed rather than reused.
        TaintTransactionSession(context, target.catalog_name);
        auto result = session.Call(bind.procedure, bind.arguments);
        if (!result.explicit_cursors.empty() || !result.implicit_cursors.empty()) {
            for (auto &cursor : result.explicit_cursors) { cursor->Close(); }
            for (auto &cursor : result.implicit_cursors) { cursor->Close(); }
            throw BinderException("oracle_call_named_transaction cannot return cursors");
        }
        std::vector<OracleCallNamedRow> rows;
        size_t position = 0;
        for (const auto &argument : bind.arguments) {
            if (argument.direction == oracle_scanner::BindDirection::BIND_IN) { continue; }
            if (position == result.outputs.size() || result.outputs[position].oracle_type != argument.oracle_type) {
                throw BinderException("oracle_call_named_transaction output shape mismatch");
            }
            OracleCallNamedRow row;
            row.name = argument.name;
            const auto &value = result.outputs[position++].value;
            if (value) { row.value = FormatCallScalar(argument.oracle_type, *value, argument.character_set_form); }
            rows.emplace_back(std::move(row));
        }
        if (position != result.outputs.size()) {
            throw BinderException("oracle_call_named_transaction has unexpected outputs");
        }
        interrupt.Check();
        return make_uniq<OracleCallNamedGlobalState>(std::move(rows));
    } catch (const std::exception &error) {
        // Join first, retain the expired caller deadline through cleanup.
        // Rollback cannot wait for a reply on the interrupted exchange.
        interrupt.Stop();
        PoisonTransactionSession(context, target.catalog_name);
        ThrowOracleAdapterError("oracle_call_named_transaction failed", error);
    }
}

void OracleTransactionCallFunction(ClientContext &, TableFunctionInput &input, DataChunk &output) {
    auto &state = input.global_state->Cast<OracleCallNamedGlobalState>();
    const auto count = std::min<idx_t>(state.rows.size() - state.next_row, STANDARD_VECTOR_SIZE);
    for (idx_t index = 0; index < count; ++index) {
        const auto &row = state.rows[state.next_row + index];
        output.data[0].SetValue(index, Value(row.name));
        output.data[1].SetValue(index, row.value ? Value(*row.value) : Value(LogicalType::VARCHAR));
    }
    output.SetChildCardinality(count);
    state.next_row += count;
}

// Anonymous PL/SQL blocks. The binds are the same STRUCT(name, direction, type,
// value) oracle_call_named takes, matched to the block's `:name` placeholders
// by name; the rows that come back are the OUT and IN OUT ones, in the order
// the block first mentions them.
std::vector<oracle_scanner::OracleBind> PlsqlArguments(TableFunctionBindInput &input, const char *function_name) {
    if (input.inputs.size() < 3 || input.inputs[2].IsNull()) {
        return {};
    }
    const auto &value = input.inputs[2];
    if (value.type().id() == LogicalTypeId::LIST && ListValue::GetChildren(value).empty()) {
        return {};
    }
    try {
        return CallArguments(value);
    } catch (const std::exception &error) {
        throw BinderException("%s binds are invalid: %s", function_name, error.what());
    }
}

// Validates the block and its binds together and returns the binds in the order
// the block mentions them, which is the order the server returns the outputs in.
std::vector<oracle_scanner::OracleBind> OrderedPlsqlArguments(const std::string &block,
                                                              const std::vector<oracle_scanner::OracleBind> &arguments,
                                                              const char *function_name) {
    try {
        oracle_scanner::OracleCallRequest request;
        request.kind = oracle_scanner::OracleCallableKind::ANONYMOUS_BLOCK;
        request.block = block;
        request.arguments = arguments;
        const auto normalized = oracle_scanner::BuildOracleCallBlock(request);
        return oracle_scanner::OrderOracleStatementBinds(normalized, arguments, oracle_scanner::OracleBindUse::CALL);
    } catch (const std::exception &error) {
        throw BinderException("%s: %s", function_name, error.what());
    }
}

struct OraclePlsqlBindData final : TableFunctionData {
    ConnectionConfig config;
    std::string password;
    std::string block;
    std::vector<oracle_scanner::OracleBind> arguments;
};

unique_ptr<FunctionData> OraclePlsqlBind(ClientContext &context, TableFunctionBindInput &input,
                                         vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull()) {
        throw BinderException("oracle_plsql secret and block cannot be NULL");
    }
    auto result = make_uniq<OraclePlsqlBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->block = input.inputs[1].GetValue<std::string>();
    result->arguments = OrderedPlsqlArguments(result->block, PlsqlArguments(input, "oracle_plsql"), "oracle_plsql");
    names = {"name", "value", "cursor_handle"};
    return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR};
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OraclePlsqlInit(ClientContext &context, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OraclePlsqlBindData>();
    try {
        auto session = std::shared_ptr<OracleSession>(OpenOracleSession(bind.config, bind.password));
        oracle_scanner::OracleCallRequest request;
        request.kind = oracle_scanner::OracleCallableKind::ANONYMOUS_BLOCK;
        request.block = bind.block;
        request.arguments = bind.arguments;
        auto result = session->Call(request);
        if (!result.implicit_cursors.empty()) {
            for (auto &cursor : result.explicit_cursors) {
                cursor->Close();
            }
            for (auto &cursor : result.implicit_cursors) {
                cursor->Close();
            }
            throw BinderException("oracle_plsql does not return implicit result sets; bind a REF CURSOR instead");
        }
        std::vector<OracleCallNamedRow> rows;
        std::vector<std::unique_ptr<oracle_scanner::OracleCursor>> owned;
        std::vector<idx_t> cursor_rows;
        size_t scalar_index = 0;
        size_t cursor_index = 0;
        for (const auto &argument : bind.arguments) {
            if (argument.direction == oracle_scanner::BindDirection::BIND_IN) {
                continue;
            }
            OracleCallNamedRow row;
            row.name = argument.name;
            if (argument.oracle_type == oracle_scanner::ORACLE_WIRE_TYPE_CURSOR) {
                if (cursor_index >= result.explicit_cursors.size()) {
                    throw BinderException("oracle_plsql cursor output count disagrees with Oracle response");
                }
                owned.emplace_back(
                    std::make_unique<SessionOwningCursor>(session, std::move(result.explicit_cursors[cursor_index++])));
                cursor_rows.push_back(rows.size());
            } else {
                if (scalar_index >= result.outputs.size() ||
                    result.outputs[scalar_index].oracle_type != argument.oracle_type) {
                    throw BinderException("oracle_plsql scalar output count disagrees with Oracle response");
                }
                const auto &output = result.outputs[scalar_index++];
                if (output.value) {
                    row.value = FormatCallScalar(argument.oracle_type, *output.value, argument.character_set_form);
                }
            }
            rows.push_back(std::move(row));
        }
        if (scalar_index != result.outputs.size() || cursor_index != result.explicit_cursors.size()) {
            throw BinderException("oracle_plsql received unexpected Oracle output values");
        }
        // Like oracle_execute, the work is the caller's to keep: a block that
        // succeeded is committed, and one that failed is rolled back with the
        // session. A block that commits or rolls back itself has already said so.
        session->Commit();
        if (!owned.empty()) {
            const auto handles = CallRegistryFor(context).Register(std::move(owned));
            for (idx_t index = 0; index < handles.size(); index++) {
                rows[cursor_rows[index]].cursor_handle = oracle_scanner::FormatCursorHandle(handles[index]);
            }
        }
        return make_uniq<OracleCallNamedGlobalState>(std::move(rows));
    } catch (const std::exception &error) {
        throw IOException("oracle_plsql failed: %s", error.what());
    }
}

struct OracleTransactionPlsqlBindData final : TableFunctionData {
    std::string catalog_name;
    std::string block;
    std::vector<oracle_scanner::OracleBind> arguments;
};

unique_ptr<FunctionData> OracleTransactionPlsqlBind(ClientContext &context, TableFunctionBindInput &input,
                                                    vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull()) {
        throw BinderException("oracle_plsql_transaction catalog and block cannot be NULL");
    }
    auto result = make_uniq<OracleTransactionPlsqlBindData>();
    result->block = input.inputs[1].GetValue<std::string>();
    auto arguments = PlsqlArguments(input, "oracle_plsql_transaction");
    if (arguments.size() > 64) {
        throw BinderException("oracle_plsql_transaction takes at most 64 binds");
    }
    size_t bytes = 0;
    for (const auto &bind : arguments) {
        if (bind.oracle_type == oracle_scanner::ORACLE_WIRE_TYPE_CURSOR) {
            throw BinderException("oracle_plsql_transaction cannot return cursors; use oracle_plsql");
        }
        if (bind.value && bind.value->size() > 32767) {
            throw BinderException("oracle_plsql_transaction scalar value exceeds 32767 bytes");
        }
        AddTransactionBindBytes(bytes, bind.name.size());
        AddTransactionBindBytes(bytes, bind.value ? bind.value->size() : 0);
        if (bind.direction != oracle_scanner::BindDirection::BIND_IN) {
            AddTransactionBindBytes(bytes, bind.maximum_bytes);
        }
    }
    result->arguments = OrderedPlsqlArguments(result->block, arguments, "oracle_plsql_transaction");
    auto target = ResolveOracleWriteTarget(context, input.inputs[0].GetValue<std::string>());
    if (Catalog::GetCatalog(context, Identifier(target.catalog_name)).GetAttached().IsReadOnly()) {
        throw TransactionException("Cannot run PL/SQL through an attached read-only Oracle catalog");
    }
    result->catalog_name = target.catalog_name;
    names = {"name", "value"};
    return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR};
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleTransactionPlsqlInit(ClientContext &context, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleTransactionPlsqlBindData>();
    auto target = ResolveOracleWriteTarget(context, bind.catalog_name);
    if (Catalog::GetCatalog(context, Identifier(target.catalog_name)).GetAttached().IsReadOnly()) {
        throw TransactionException("Cannot run PL/SQL through an attached read-only Oracle catalog");
    }
    OracleCallerInterruptScope interrupt(context);
    try {
        auto &session = TransactionSession(context, target);
        // A block can change package state, NLS or the current schema of the
        // session itself; the session ends closed rather than reused.
        TaintTransactionSession(context, target.catalog_name);
        oracle_scanner::OracleCallRequest request;
        request.kind = oracle_scanner::OracleCallableKind::ANONYMOUS_BLOCK;
        request.block = bind.block;
        request.arguments = bind.arguments;
        auto result = session.Call(request);
        if (!result.explicit_cursors.empty() || !result.implicit_cursors.empty()) {
            for (auto &cursor : result.explicit_cursors) {
                cursor->Close();
            }
            for (auto &cursor : result.implicit_cursors) {
                cursor->Close();
            }
            throw BinderException("oracle_plsql_transaction cannot return cursors");
        }
        std::vector<OracleCallNamedRow> rows;
        size_t position = 0;
        for (const auto &argument : bind.arguments) {
            if (argument.direction == oracle_scanner::BindDirection::BIND_IN) {
                continue;
            }
            if (position == result.outputs.size() || result.outputs[position].oracle_type != argument.oracle_type) {
                throw BinderException("oracle_plsql_transaction output shape mismatch");
            }
            OracleCallNamedRow row;
            row.name = argument.name;
            const auto &value = result.outputs[position++].value;
            if (value) {
                row.value = FormatCallScalar(argument.oracle_type, *value, argument.character_set_form);
            }
            rows.emplace_back(std::move(row));
        }
        if (position != result.outputs.size()) {
            throw BinderException("oracle_plsql_transaction has unexpected outputs");
        }
        interrupt.Check();
        return make_uniq<OracleCallNamedGlobalState>(std::move(rows));
    } catch (const std::exception &error) {
        interrupt.Stop();
        PoisonTransactionSession(context, target.catalog_name);
        ThrowOracleAdapterError("oracle_plsql_transaction failed", error);
    }
}

unique_ptr<GlobalTableFunctionState> OracleCallNamedInit(ClientContext &context, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleCallNamedBindData>();
    try {
        auto session = std::shared_ptr<OracleSession>(OpenOracleSession(bind.config, bind.password));
        oracle_scanner::OracleCallRequest request;
        request.kind = oracle_scanner::OracleCallableKind::PROCEDURE;
        request.qualified_name = bind.procedure;
        request.arguments = bind.arguments;
        auto result = session->Call(request);
        if (!result.implicit_cursors.empty()) {
            throw BinderException("oracle_call_named does not combine explicit and implicit cursor results");
        }
        std::vector<OracleCallNamedRow> rows;
        std::vector<std::unique_ptr<oracle_scanner::OracleCursor>> owned;
        std::vector<idx_t> cursor_rows;
        size_t scalar_index = 0;
        size_t cursor_index = 0;
        for (const auto &argument : bind.arguments) {
            if (argument.direction == oracle_scanner::BindDirection::BIND_IN) {
                continue;
            }
            OracleCallNamedRow row;
            row.name = argument.name;
            if (argument.oracle_type == oracle_scanner::ORACLE_WIRE_TYPE_CURSOR) {
                if (cursor_index >= result.explicit_cursors.size()) {
                    throw BinderException("oracle_call_named cursor output count disagrees with Oracle response");
                }
                owned.emplace_back(std::make_unique<SessionOwningCursor>(session, std::move(result.explicit_cursors[cursor_index++])));
                cursor_rows.push_back(rows.size());
            } else {
                if (scalar_index >= result.outputs.size() || result.outputs[scalar_index].oracle_type != argument.oracle_type) {
                    throw BinderException("oracle_call_named scalar output count disagrees with Oracle response");
                }
                const auto &output = result.outputs[scalar_index++];
                if (output.value) {
                    row.value = FormatCallScalar(argument.oracle_type, *output.value, argument.character_set_form);
                }
            }
            rows.push_back(std::move(row));
        }
        if (scalar_index != result.outputs.size() || cursor_index != result.explicit_cursors.size()) {
            throw BinderException("oracle_call_named received unexpected Oracle output values");
        }
        if (!owned.empty()) {
            const auto handles = CallRegistryFor(context).Register(std::move(owned));
            for (idx_t index = 0; index < handles.size(); index++) {
                rows[cursor_rows[index]].cursor_handle = oracle_scanner::FormatCursorHandle(handles[index]);
            }
        }
        return make_uniq<OracleCallNamedGlobalState>(std::move(rows));
    } catch (const std::exception &error) {
        throw IOException("oracle_call_named failed: %s", error.what());
    }
}

void OracleCallNamedFunction(ClientContext &, TableFunctionInput &input, DataChunk &output) {
    auto &state = input.global_state->Cast<OracleCallNamedGlobalState>();
    const auto count = std::min<idx_t>(state.rows.size() - state.next_row, STANDARD_VECTOR_SIZE);
    for (idx_t index = 0; index < count; index++) {
        const auto &row = state.rows[state.next_row + index];
        output.data[0].SetValue(index, Value(row.name));
        output.data[1].SetValue(index, row.value ? Value(*row.value) : Value());
        output.data[2].SetValue(index, row.cursor_handle ? Value(*row.cursor_handle) : Value());
    }
    state.next_row += count;
    output.SetChildCardinality(count);
}

unique_ptr<FunctionData> OracleCallNamedFunctionBind(ClientContext &context, TableFunctionBindInput &input,
                                                     vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull() || input.inputs[3].IsNull()) {
        throw BinderException("oracle_call_named_function secret, function, return type, and arguments cannot be NULL");
    }
    const auto return_type = StringUtil::Lower(input.inputs[2].GetValue<std::string>());
    oracle_scanner::OracleBind return_bind;
    return_bind.name = "return_value";
    return_bind.direction = oracle_scanner::BindDirection::BIND_OUT;
    if (return_type == "number") {
        return_bind.oracle_type = 2;
        return_bind.maximum_bytes = 22;
    } else if (return_type == "varchar") {
        return_bind.oracle_type = 1;
        return_bind.maximum_bytes = 32767;
    } else if (return_type == "date") {
        return_bind.oracle_type = 12;
        return_bind.maximum_bytes = 7;
    } else if (return_type == "timestamp") {
        return_bind.oracle_type = 180;
        return_bind.maximum_bytes = 11;
    } else if (return_type == "raw") {
        return_bind.oracle_type = 23;
        return_bind.maximum_bytes = 32767;
    } else if (return_type == "float") {
        return_bind.oracle_type = 100;
        return_bind.maximum_bytes = 4;
    } else if (return_type == "double") {
        return_bind.oracle_type = 101;
        return_bind.maximum_bytes = 8;
    } else if (return_type == "cursor") {
        // A function returning SYS_REFCURSOR binds exactly as an OUT cursor
        // argument does; the result comes back as a handle rather than a value.
        return_bind.oracle_type = oracle_scanner::ORACLE_WIRE_TYPE_CURSOR;
        return_bind.maximum_bytes = 4;
    } else {
        throw BinderException("oracle_call_named_function return type must be number, varchar, date, timestamp, raw, "
                              "float, double, or cursor");
    }
    auto result = make_uniq<OracleCallNamedFunctionBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->function = input.inputs[1].GetValue<std::string>();
    result->return_bind = std::move(return_bind);
    result->arguments = CallArguments(input.inputs[3]);
    names = {"name", "value", "cursor_handle"};
    return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR};
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleCallNamedFunctionInit(ClientContext &context, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleCallNamedFunctionBindData>();
    try {
        auto session = std::shared_ptr<OracleSession>(OpenOracleSession(bind.config, bind.password));
        oracle_scanner::OracleCallRequest request;
        request.kind = oracle_scanner::OracleCallableKind::FUNCTION;
        request.qualified_name = bind.function;
        request.return_bind = bind.return_bind;
        request.arguments = bind.arguments;
        auto result = session->Call(request);
        if (!result.implicit_cursors.empty()) {
            throw BinderException("oracle_call_named_function does not combine explicit and implicit cursor results");
        }
        const auto returns_cursor = bind.return_bind.oracle_type == oracle_scanner::ORACLE_WIRE_TYPE_CURSOR;
        if (!returns_cursor &&
            (result.outputs.empty() || result.outputs[0].oracle_type != bind.return_bind.oracle_type)) {
            throw BinderException("oracle_call_named_function return value disagrees with Oracle response");
        }
        std::vector<OracleCallNamedRow> rows;
        std::vector<std::unique_ptr<oracle_scanner::OracleCursor>> owned;
        std::vector<idx_t> cursor_rows;
        size_t scalar_index = returns_cursor ? 0 : 1;
        size_t cursor_index = 0;
        OracleCallNamedRow return_row;
        return_row.name = bind.return_bind.name;
        if (returns_cursor) {
            // The return bind is the first bind of the call, so its cursor is
            // the first one the server sent back.
            if (result.explicit_cursors.empty()) {
                throw BinderException("oracle_call_named_function expected a REF CURSOR return value");
            }
            owned.emplace_back(
                std::make_unique<SessionOwningCursor>(session, std::move(result.explicit_cursors[cursor_index++])));
            cursor_rows.push_back(rows.size());
        } else if (result.outputs[0].value) {
            return_row.value = FormatCallScalar(bind.return_bind.oracle_type, *result.outputs[0].value, bind.return_bind.character_set_form);
        }
        rows.push_back(std::move(return_row));
        for (const auto &argument : bind.arguments) {
            if (argument.direction == oracle_scanner::BindDirection::BIND_IN) {
                continue;
            }
            OracleCallNamedRow row;
            row.name = argument.name;
            if (argument.oracle_type == oracle_scanner::ORACLE_WIRE_TYPE_CURSOR) {
                if (cursor_index >= result.explicit_cursors.size()) {
                    throw BinderException("oracle_call_named_function cursor output count disagrees with Oracle response");
                }
                owned.emplace_back(std::make_unique<SessionOwningCursor>(session, std::move(result.explicit_cursors[cursor_index++])));
                cursor_rows.push_back(rows.size());
            } else {
                if (scalar_index >= result.outputs.size() || result.outputs[scalar_index].oracle_type != argument.oracle_type) {
                    throw BinderException("oracle_call_named_function scalar output count disagrees with Oracle response");
                }
                const auto &output = result.outputs[scalar_index++];
                if (output.value) {
                    row.value = FormatCallScalar(argument.oracle_type, *output.value, argument.character_set_form);
                }
            }
            rows.push_back(std::move(row));
        }
        if (scalar_index != result.outputs.size() || cursor_index != result.explicit_cursors.size()) {
            throw BinderException("oracle_call_named_function received unexpected Oracle output values");
        }
        if (!owned.empty()) {
            const auto handles = CallRegistryFor(context).Register(std::move(owned));
            for (idx_t index = 0; index < handles.size(); index++) {
                rows[cursor_rows[index]].cursor_handle = oracle_scanner::FormatCursorHandle(handles[index]);
            }
        }
        return make_uniq<OracleCallNamedGlobalState>(std::move(rows));
    } catch (const std::exception &error) {
        throw IOException("oracle_call_named_function failed: %s", error.what());
    }
}

unique_ptr<FunctionData> OracleCloseCallBind(ClientContext &context, TableFunctionBindInput &input,
                                             vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull()) {
        throw BinderException("oracle_close_call handle cannot be NULL");
    }
    const auto handle = oracle_scanner::ParseCursorHandle(input.inputs[0].GetValue<std::string>());
    auto result = make_uniq<OracleCloseCallBindData>();
    result->state = context.registered_state->GetOrCreate<OracleCallRegistryState>("oracle_scanner.call_registry");
    result->call_id = handle.call_id;
    names.push_back(Identifier("closed"));
    return_types.push_back(LogicalType::BOOLEAN);
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleCloseCallInit(ClientContext &, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleCloseCallBindData>();
    return make_uniq<OracleCloseCallGlobalState>(bind.state->registry.Close(bind.call_id));
}

void OracleCloseCallFunction(ClientContext &, TableFunctionInput &input, DataChunk &output) {
    auto &state = input.global_state->Cast<OracleCloseCallGlobalState>();
    if (!state.emitted) {
        output.data[0].SetValue(0, Value::BOOLEAN(state.closed));
        output.SetChildCardinality(1);
        state.emitted = true;
    }
}

unique_ptr<FunctionData> OracleCursorBind(ClientContext &context, TableFunctionBindInput &input,
                                          vector<LogicalType> &return_types, vector<Identifier> &names) {
    if (input.inputs[0].IsNull()) {
        throw BinderException("oracle_cursor handle cannot be NULL");
    }
    auto result = make_uniq<OracleCursorBindData>();
    result->cursor = CallRegistryFor(context).Take(oracle_scanner::ParseCursorHandle(input.inputs[0].GetValue<std::string>()));
    result->columns = result->cursor->Columns();
    std::unordered_set<std::string> used_names;
    for (idx_t index = 0; index < result->columns.size(); index++) {
        names.push_back(Identifier(OutputName(result->columns[index], index, used_names)));
        result->types.push_back(TypeFor(result->columns[index]));
        return_types.push_back(result->types.back());
    }
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleCursorInit(ClientContext &, TableFunctionInitInput &input) {
    auto &bind = input.bind_data->CastNoConst<OracleCursorBindData>();
    // A cursor handle already owns its session; this scan only reads it.
    return make_uniq<OracleQueryGlobalState>(OracleSessionHandle(), std::move(bind.cursor), std::move(bind.columns),
                                             std::move(bind.types), std::move(input.column_ids), bind.columns.size());
}

} // namespace

// DuckDB hands a scan a system sample only when the scan has said it takes one
// and there are no filters (a sample is taken before a filter, not after). A
// percentage maps to the same percentage of Oracle's rows, or of its blocks for
// a table big enough to have thousands of them: block sampling reads a fraction
// of the table but takes whole runs of blocks at a time, so on a table of a few
// hundred thousand rows the same 1% came back as 0 rows in some runs and 3%
// in others. Row sampling reads every block and sends back only the sample. A row count arrives
// as the rate DuckDB worked out from the table's estimated size, doubled: block
// sampling is lumpy, and DuckDB puts a LIMIT of the requested rows on top, so
// a few too many rows cost nothing and too few would.
std::string OracleSampleClause(optional_ptr<SampleOptions> options, const std::optional<uint64_t> &estimated_rows) {
	if (!options || options->method != SampleMethod::SYSTEM_SAMPLE) {
		return std::string();
	}
	double percent;
	if (options->is_percentage) {
		percent = options->sample_size.GetValue<double>();
	} else {
		if (options->sample_rate < 0) {
			return std::string();
		}
		percent = options->sample_rate * 100.0 * 2.0;
	}
	if (percent >= 100.0) {
		return std::string();
	}
	percent = MaxValue<double>(percent, 0.000001);
	char text[64];
	std::snprintf(text, sizeof(text), "%.6f", percent);
	// Sampling by block starts to pay, and its lumpiness to average out, in the
	// tens of millions of rows.
	constexpr uint64_t BLOCK_SAMPLING_ROWS = 20000000;
	const bool by_block = estimated_rows && *estimated_rows >= BLOCK_SAMPLING_ROWS;
	std::string clause = std::string(by_block ? " SAMPLE BLOCK (" : " SAMPLE (") + text + ")";
	if (options->repeatable && options->seed.IsValid()) {
		clause += " SEED (" + std::to_string(static_cast<uint64_t>(options->GetSeed()) % 4294967296ULL) + ")";
	}
	return clause;
}

// Below this many rows (NUM_ROWS) an automatic parallel scan is not tried: the
// plan costs a few dictionary queries and a connection of its own.
constexpr uint64_t AUTOMATIC_PARALLEL_MINIMUM_ROWS = 500000;

static bool DeferrableColumn(const OracleColumn &column);

// Runs the statement an AGGREGATE was replaced with. The result columns are
// the plan's contract (declared when the optimizer rewrote it); Oracle's describe
// supplies the wire representation and has to map to the same types.
unique_ptr<GlobalTableFunctionState> OracleAggregateInit(ClientContext &context, OracleQueryBindData &bind,
                                                         TableFunctionInitInput &input) {
    OracleSessionHandle session;
    std::unique_ptr<OracleCursor> cursor;
    OracleScanOpening opened;
    try {
        session = AcquireOracleReadSession(context, bind.secret_name, bind.catalog_name, bind.config, bind.password);
        const auto before = session->IoStats();
        // The marker the optimizer left after each table name becomes the statement's snapshot.
        auto sql = bind.statement_sql;
        const auto scn = OracleQuerySnapshot(context, bind);
        const std::string marker = " /*SCN*/";
        for (auto at = sql.find(marker); at != std::string::npos; at = sql.find(marker, at)) {
            const auto replacement = scn.empty() ? std::string() : " AS OF SCN " + scn;
            sql.replace(at, marker.size(), replacement);
            at += replacement.size();
        }
        cursor = session->Query(sql, {});
        opened.sql = sql;
        opened.io = session->IoStats() - before;
    } catch (const std::exception &error) {
        session.Poison();
        throw IOException("Oracle could not aggregate table '%s': %s", bind.object_name, error.what());
    }
    auto columns = cursor->Columns();
    if (columns.size() != bind.columns.size()) {
        throw IOException("Oracle described %llu columns for an aggregate of %llu", static_cast<uint64_t>(columns.size()),
                          static_cast<uint64_t>(bind.columns.size()));
    }
    for (idx_t index = 0; index < columns.size(); index++) {
        const auto &declared = bind.columns[index];
        if (declared.oracle_type != 0) {
            columns[index].oracle_type = declared.oracle_type;
        }
        columns[index].byte_width = declared.byte_width;
        columns[index].precision = declared.precision;
        columns[index].scale = declared.scale;
        columns[index].nullable = declared.nullable;
        columns[index].unconstrained_number = declared.unconstrained_number;
        columns[index].unconstrained_precision = declared.unconstrained_precision;
        columns[index].unconstrained_scale = declared.unconstrained_scale;
        if (TypeFor(columns[index]) != bind.types[index]) {
            throw IOException("Oracle aggregate column %llu maps to %s where the plan expects %s",
                              static_cast<uint64_t>(index + 1), TypeFor(columns[index]).ToString(),
                              bind.types[index].ToString());
        }
    }
    const auto chunk_columns = columns.size();
    auto state = make_uniq<OracleQueryGlobalState>(std::move(session), std::move(cursor), std::move(columns),
                                                   bind.types, std::move(input.column_ids), chunk_columns);
    state->catalog_name = bind.catalog_name;
    state->sent_sql = opened.sql;
    state->metrics.Add(opened.io);
    state->metrics.sessions = 1;
    state->last_io = state->session ? state->session->IoStats() : OracleIoStats();
    return std::move(state);
}

unique_ptr<GlobalTableFunctionState> OracleQueryInit(ClientContext &context, TableFunctionInitInput &input) {
    auto &bind = input.bind_data->CastNoConst<OracleQueryBindData>();
    if (bind.statement_scan) {
        return OracleAggregateInit(context, bind, input);
    }
    if (bind.transactional_query) {
        auto target = ResolveOracleWriteTarget(context, bind.catalog_name);
        TransactionSession(context, target);
        auto session = AcquireOracleReadSession(context, std::string(), target.catalog_name,
                                                target.config, target.password);
        std::unique_ptr<OracleCursor> cursor;
        OracleCallerInterruptScope interrupt(context);
        try {
            cursor = session->Query(bind.query_sql, bind.query_binds);
            const auto &columns = cursor->Columns();
            if (bind.declared_schema) {
                // The declaration is the plan's contract: Oracle's describe has
                // to match it column for column, by name and by mapped type.
                if (columns.size() != bind.columns.size()) {
                    throw IOException("Oracle returned %llu columns where the declaration has %llu", columns.size(),
                                      bind.columns.size());
                }
                for (idx_t i = 0; i < columns.size(); i++) {
                    if (!StringUtil::CIEquals(columns[i].name, bind.columns[i].name)) {
                        throw IOException("Oracle column %llu is %s where %s was declared", i + 1, columns[i].name,
                                          bind.columns[i].name);
                    }
                    const auto type = TypeFor(columns[i]);
                    if (type != bind.types[i]) {
                        throw IOException("Oracle column %s maps to %s where %s was declared", columns[i].name,
                                          type.ToString(), bind.types[i].ToString());
                    }
                }
            } else if (columns.size() != bind.columns.size()) {
                throw IOException("Oracle query describe changed; prepare the query again");
            }
            for (idx_t i = 0; i < columns.size(); i++) {
                if (TypeFor(columns[i]) != bind.types[i]) {
                    throw IOException("Oracle query type changed; prepare the query again");
                }
            }
            auto state = make_uniq<OracleQueryGlobalState>(std::move(session), std::move(cursor),
                columns, bind.types, std::move(input.column_ids), columns.size());
            state->catalog_name = bind.catalog_name;
            return std::move(state);
        } catch (const std::exception &error) {
            interrupt.Stop();
            cursor.reset();
            session.Poison();
            PoisonTransactionSession(context, bind.catalog_name);
            ThrowOracleAdapterError(bind.declared_schema ? "oracle_query_transaction_typed failed"
                                                         : "oracle_query_transaction failed",
                                    error);
        }
    }
    for (const auto column_id : input.column_ids) {
        if (column_id >= bind.columns.size()) {
            // An attached table advertises Oracle's ROWID and the scan selects
            // it; oracle_query describes exactly the statement it was given and
            // has no such column to add.
            if (bind.deferred_scan && column_id == COLUMN_IDENTIFIER_ROW_ID) {
                continue;
            }
            throw NotImplementedException("oracle_query does not support virtual columns");
        }
    }
    if (!bind.deferred_scan) {
        // oracle_query's cursor is already open and describes every column, and
        // DuckDB sized the chunk to match, so each chunk vector is the column
        // beside it.
        auto chunk_columns = bind.columns.size();
        return make_uniq<OracleQueryGlobalState>(std::move(bind.session), std::move(bind.cursor),
                                                 std::move(bind.columns), std::move(bind.types),
                                                 std::move(input.column_ids), chunk_columns);
    }
    // Counting rows needs no column values, but Oracle needs a select list, so
    // one column is fetched and none is emitted.
    unique_ptr<Expression> local_filter;
    auto selected = input.column_ids;
    const auto chunk_columns = selected.size();
    if (selected.empty()) {
        selected.push_back(0);
    }
    if (input.filters) {
        // DuckDB drops a filter from the plan once it hands it over, so each
        // one is either translated exactly into the Oracle statement or
        // applied here to the rows that come back.
        auto split = SplitOracleFilters(*input.filters, bind.columns, selected);
        bind.where_clause = std::move(split.where);
        if (split.local.size() == 1) {
            local_filter = std::move(split.local[0]);
        } else if (!split.local.empty()) {
            local_filter = std::move(split.local[0]);
            for (idx_t index = 1; index < split.local.size(); index++) {
                local_filter = make_uniq<BoundConjunctionExpression>(ExpressionType::CONJUNCTION_AND,
                                                                     std::move(local_filter), std::move(split.local[index]));
            }
        }
    }
    // A statement's scans read one moment when the user asked for that; set anew on
    // every run, since a prepared statement keeps its bind data.
    const auto query_scn = OracleQuerySnapshot(context, bind);
    bind.sample_clause = OracleSampleClause(input.sample_options.get(), bind.estimated_rows);
    // A sample reads at that moment too: the SQL puts SAMPLE ahead of AS OF.
    bind.flashback_scn = query_scn;
    // A Top-N the optimizer found over this scan is applied by Oracle only when
    // every filter went to Oracle too: a filter DuckDB applies afterwards would
    // see the first n rows instead of the first n that pass it.
    bind.order_clause = (!local_filter && bind.sample_clause.empty()) ? OracleTopNClause(bind) : std::string();
    OracleSessionHandle session;
    std::unique_ptr<OracleCursor> cursor;
    std::vector<OracleColumn> columns;
    Value parallel_setting;
    idx_t sessions = 0;
    if (!selected.empty() && context.TryGetCurrentSetting("oracle_parallel_scan", parallel_setting) &&
        !parallel_setting.IsNull()) {
        const auto requested = parallel_setting.GetValue<int64_t>();
        if (requested >= 0) {
            sessions = static_cast<idx_t>(MinValue<int64_t>(64, requested));
        } else if (bind.estimated_rows && *bind.estimated_rows >= AUTOMATIC_PARALLEL_MINIMUM_ROWS) {
            // Automatic: a table Oracle's statistics say is big gets as many
            // sessions as DuckDB has threads, up to eight. The planner still reads
            // one stream when the extents, the change number or a flashback read
            // are not to be had.
            sessions = MinValue<idx_t>(8, static_cast<idx_t>(TaskScheduler::GetScheduler(context).NumberOfThreads()));
        }
    }
    auto chunks = PlanParallelAttachedScan(context, bind, selected, sessions);
    if (!chunks.empty()) {
        // Described once, with no row read: the chunks all have this shape.
        OracleScanOpening described;
        OpenProjectedScan(context, bind, selected, session, cursor, columns, true, &described);
        cursor->Close();
        cursor.reset();
        std::vector<LogicalType> chunk_types;
        chunk_types.reserve(columns.size());
        for (const auto &column : columns) {
            chunk_types.push_back(TypeFor(column));
        }
        auto state = make_uniq<OracleQueryGlobalState>(OracleSessionHandle(), nullptr, std::move(columns),
                                                       std::move(chunk_types), std::move(input.column_ids), chunk_columns);
        state->local_filter = std::move(local_filter);
        state->metrics.Add(described.io);
        state->parallel = true;
        state->thread_count = MinValue<idx_t>(sessions, chunks.size());
        state->chunk_sql = std::move(chunks);
        state->secret_name = bind.secret_name;
        state->config = bind.config;
        state->password = bind.password;
        state->sent_sql = state->chunk_sql.front() + (state->chunk_sql.size() > 1
                                                          ? " (and " + std::to_string(state->chunk_sql.size() - 1) +
                                                                " more ROWID ranges)"
                                                          : std::string());
        state->local_filter_text = state->local_filter ? state->local_filter->ToString() : std::string();
        return std::move(state);
    }
    OracleScanOpening opened;
    unique_ptr<OracleDeferredColumns> deferred;
    std::vector<LogicalType> types;
    Value defer_setting;
    // The columns DuckDB's own filter never looks at, and that are heavy, are read
    // for the rows that pass it and not for every row.
    if (local_filter && bind.sample_clause.empty() && bind.order_clause.empty() &&
        (!context.TryGetCurrentSetting("oracle_deferred_columns", defer_setting) || defer_setting.IsNull() ||
         BooleanValue::Get(defer_setting))) {
        std::set<idx_t> used;
        auto probe = local_filter->Copy();
        ExpressionIterator::EnumerateExpression(probe, [&](unique_ptr<Expression> &node) {
            if (node->GetExpressionClass() == ExpressionClass::BOUND_REF) {
                used.insert(node->Cast<BoundReferenceExpression>().Index());
            }
        });
        std::vector<idx_t> heavy;
        for (idx_t position = 0; position < selected.size(); position++) {
            if (selected[position] < bind.columns.size() && DeferrableColumn(bind.columns[selected[position]]) &&
                !used.count(position)) {
                heavy.push_back(position);
            }
        }
        const auto scn = (heavy.empty() || heavy.size() == selected.size()) ? std::string()
                                                                              : OracleSnapshotOfHeapTable(context, bind);
        if (!scn.empty()) {
            std::vector<column_t> light_selected;
            auto plan = make_uniq<OracleDeferredColumns>();
            std::string heavy_list;
            for (idx_t position = 0; position < selected.size(); position++) {
                if (std::find(heavy.begin(), heavy.end(), position) == heavy.end()) {
                    light_selected.push_back(selected[position]);
                    plan->light_vectors.push_back(position);
                } else {
                    plan->heavy_vectors.push_back(position);
                    plan->heavy_columns.push_back(bind.columns[selected[position]]);
                    heavy_list += ", " + OracleSelectExpression(bind.columns[selected[position]]);
                }
            }
            light_selected.push_back(COLUMN_IDENTIFIER_ROW_ID);
            plan->heavy_select = std::string(ORACLE_ROWID_EXPRESSION) + heavy_list;
            plan->source = OracleObjectReference(bind.schema_name, bind.object_name) + " AS OF SCN " + scn;
            bind.flashback_scn = scn;
            try {
                OpenProjectedScan(context, bind, light_selected, session, cursor, columns, false, &opened);
                for (idx_t position = 0; position < selected.size(); position++) {
                    const auto light = std::find(plan->light_vectors.begin(), plan->light_vectors.end(), position);
                    types.push_back(light == plan->light_vectors.end()
                                        ? MappedType(bind.columns[selected[position]])
                                        : TypeFor(columns[light - plan->light_vectors.begin()]));
                }
                deferred = std::move(plan);
            } catch (const std::exception &) {
                // No flashback on the table, or the snapshot is gone: read it whole.
                bind.flashback_scn = query_scn;
                cursor.reset();
                session = OracleSessionHandle();
                columns.clear();
                opened = OracleScanOpening();
                types.clear();
            }
        }
    }
    if (!deferred) {
        OpenProjectedScan(context, bind, selected, session, cursor, columns, false, &opened);
        types.reserve(columns.size());
        for (const auto &column : columns) {
            types.push_back(TypeFor(column));
        }
    }
    const auto io_after_open = session ? session->IoStats() : OracleIoStats();
    auto state = make_uniq<OracleQueryGlobalState>(std::move(session), std::move(cursor), std::move(columns),
                                                   std::move(types), std::move(input.column_ids), chunk_columns);
    state->local_filter = std::move(local_filter);
    state->deferred = std::move(deferred);
    state->sent_sql = opened.sql;
    state->local_filter_text = state->local_filter ? state->local_filter->ToString() : std::string();
    state->metrics.Add(opened.io);
    state->metrics.sessions = 1;
    state->last_io = io_after_open;
    return std::move(state);
}

// What an attached scan reports in EXPLAIN ANALYZE: the statement Oracle was
// sent, what came back and how much of the time went where. The counts are
// the scan's own — the rows Oracle returned before any filter DuckDB applies
// to them, and the bytes and round trips on the connections it used.
void OracleQueryMetrics(TableFunctionGetMetricsInput &input) {
	if (!input.global_state) {
		return;
	}
	const auto *state = dynamic_cast<const OracleQueryGlobalState *>(input.global_state.get());
	if (!state) {
		return;
	}
	auto &metrics = input.operator_metrics;
	const auto &counters = state->metrics;
	const auto seconds = [](uint64_t nanoseconds) {
		char text[32];
		std::snprintf(text, sizeof(text), "%.3f s", static_cast<double>(nanoseconds) / 1e9);
		return std::string(text);
	};
	if (!state->sent_sql.empty()) {
		metrics.AddExtraInfo("Oracle SQL", state->sent_sql);
	}
	metrics.AddExtraInfo("Oracle sessions", std::to_string(counters.sessions.load()));
	if (state->parallel) {
		metrics.AddExtraInfo("Oracle ROWID ranges", std::to_string(counters.chunks_read.load()) + " read of " +
		                                                std::to_string(state->chunk_sql.size()));
	}
	metrics.AddExtraInfo("Oracle rows returned", std::to_string(counters.rows_fetched.load()));
	metrics.AddExtraInfo("Oracle network", StringUtil::BytesToHumanReadableString(counters.bytes_received.load()) +
	                                           " received, " +
	                                           StringUtil::BytesToHumanReadableString(counters.bytes_sent.load()) +
	                                           " sent, " + std::to_string(counters.round_trips.load()) + " round trips");
	metrics.AddExtraInfo("Oracle fetch time", seconds(counters.fetch_nanoseconds.load()));
	metrics.AddExtraInfo("Value conversion time", seconds(counters.convert_nanoseconds.load()));
	if (state->deferred) {
		metrics.AddExtraInfo("Columns read after the filter", std::to_string(state->deferred->heavy_columns.size()) +
		                                                         ", for " + std::to_string(counters.deferred_rows.load()) +
		                                                         " rows");
	}
	if (!state->local_filter_text.empty()) {
		metrics.AddExtraInfo("Filters applied after fetching", state->local_filter_text);
	}
	metrics.rows_scanned = counters.rows_fetched.load();
}

unique_ptr<LocalTableFunctionState> OracleQueryInitLocal(ExecutionContext &, TableFunctionInitInput &,
                                                         GlobalTableFunctionState *) {
    return make_uniq<OracleQueryLocalState>();
}

static bool DeferrableColumn(const OracleColumn &column) {
    switch (column.oracle_type) {
    case 112: // CLOB
    case 113: // BLOB
    case 119: // JSON
    case 127: // VECTOR
        return true;
    default:
        return column.xml;
    }
}

std::string RowIdText(const std::optional<std::vector<uint8_t>> &wire) {
    return wire ? std::string(wire->begin(), wire->end()) : std::string();
}

// Reads the heavy columns of the rows that passed the filter, by ROWID and at
// the change number the rows were read at, and writes them into the chunk at the
// rows' own positions. The rows that did not pass get NULL there; the caller
// slices them away.
void FillDeferredColumns(OracleQueryGlobalState &state, DataChunk &output, const oracle_scanner::OracleBatch &batch,
                         const SelectionVector &selection, idx_t kept) {
    auto &plan = *state.deferred;
    const auto rowid_position = plan.light_vectors.size();
    std::vector<bool> wanted(batch.rows.size(), false);
    std::unordered_map<std::string, idx_t> row_of;
    for (idx_t index = 0; index < kept; index++) {
        const auto row = selection.get_index(index);
        wanted[row] = true;
        row_of.emplace(RowIdText(batch.rows[row][rowid_position]), row);
    }
    for (idx_t row = 0; row < batch.rows.size(); row++) {
        if (!wanted[row]) {
            for (idx_t heavy = 0; heavy < plan.heavy_vectors.size(); heavy++) {
                WriteOracleValue(output.data[plan.heavy_vectors[heavy]], row, plan.heavy_columns[heavy], std::nullopt);
            }
        }
    }
    std::vector<std::string> rowids;
    rowids.reserve(row_of.size());
    for (const auto &entry : row_of) {
        rowids.push_back(entry.first);
    }
    size_t found = 0;
    constexpr size_t ROWIDS_PER_STATEMENT = 500;
    for (size_t first = 0; first < rowids.size(); first += ROWIDS_PER_STATEMENT) {
        std::string list;
        const auto last = MinValue<size_t>(rowids.size(), first + ROWIDS_PER_STATEMENT);
        for (size_t index = first; index < last; index++) {
            list += (list.empty() ? "" : ", ") + std::string("CHARTOROWID('") + rowids[index] + "')";
        }
        const auto sql = "SELECT " + plan.heavy_select + " FROM " + plan.source + " WHERE ROWID IN (" + list + ")";
        try {
            auto cursor = state.session->Query(sql, {});
            auto described = cursor->Columns();
            if (described.size() != plan.heavy_columns.size() + 1) {
                throw IOException("Oracle described %llu columns for a deferred read of %llu",
                                  static_cast<uint64_t>(described.size()),
                                  static_cast<uint64_t>(plan.heavy_columns.size() + 1));
            }
            for (size_t heavy = 0; heavy < plan.heavy_columns.size(); heavy++) {
                OverlayDictionaryColumn(described[heavy + 1], plan.heavy_columns[heavy]);
            }
            for (;;) {
                const auto fetched = TranslatingOracleErrors("oracle_query could not fetch from Oracle",
                                                             [&] { return cursor->Fetch(STANDARD_VECTOR_SIZE); });
                for (const auto &row : fetched.rows) {
                    const auto at = row_of.find(RowIdText(row[0]));
                    if (at == row_of.end()) {
                        throw IOException("Oracle returned a row that was not asked for in a deferred read");
                    }
                    for (size_t heavy = 0; heavy < plan.heavy_columns.size(); heavy++) {
                        TranslatingOracleErrors("oracle_query could not convert an Oracle value", [&] {
                            WriteOracleValue(output.data[plan.heavy_vectors[heavy]], at->second, described[heavy + 1],
                                             row[heavy + 1]);
                            return true;
                        });
                    }
                    found++;
                }
                if (fetched.exhausted) {
                    break;
                }
            }
        } catch (...) {
            state.session.Poison();
            throw;
        }
    }
    if (found != rowids.size()) {
        throw IOException("Oracle did not return %llu of the %llu rows asked for in a deferred read",
                          static_cast<uint64_t>(rowids.size() - found), static_cast<uint64_t>(rowids.size()));
    }
    state.metrics.deferred_rows += found;
}

void OracleQueryFunction(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
    auto &state = input.global_state->Cast<OracleQueryGlobalState>();
    // A parallel scan reads through the thread's own session and cursor, one
    // chunk of the table after another.
    OracleQueryLocalState *local = state.parallel ? &input.local_state->Cast<OracleQueryLocalState>() : nullptr;
    // A transaction's fetch obeys the caller's interrupt like its open does.
    std::unique_ptr<OracleCallerInterruptScope> interrupt;
    if (!state.catalog_name.empty()) {
        interrupt = std::make_unique<OracleCallerInterruptScope>(context);
    }
    const auto clock_now = [] { return std::chrono::steady_clock::now(); };
    const auto elapsed = [](std::chrono::steady_clock::time_point since) {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - since).count());
    };
    for (;;) {
        if (local && !local->cursor) {
            const auto chunk = state.next_chunk.fetch_add(1);
            if (chunk >= state.chunk_sql.size()) {
                output.SetChildCardinality(0);
                return;
            }
            try {
                if (!local->session) {
                    local->session = AcquireOracleReadSession(context, state.secret_name, std::string(), state.config,
                                                              state.password);
                    state.metrics.sessions++;
                    local->last_io = local->session->IoStats();
                }
                const auto opened_at = clock_now();
                local->cursor = local->session->Query(state.chunk_sql[chunk], {});
                state.metrics.fetch_nanoseconds += elapsed(opened_at);
                state.metrics.chunks_read++;
                const auto io_now = local->session->IoStats();
                state.metrics.Add(io_now - local->last_io);
                local->last_io = io_now;
            } catch (const std::exception &error) {
                local->session.Poison();
                throw IOException("Oracle ATTACH could not open a chunk of the table: %s", error.what());
            }
        }
        const auto fetch_started = clock_now();
        const auto batch = TranslatingOracleErrors("oracle_query could not fetch from Oracle", [&] {
            if (local) {
                try {
                    return local->cursor->Fetch(STANDARD_VECTOR_SIZE);
                } catch (...) {
                    local->session.Poison();
                    throw;
                }
            }
            try {
                return state.cursor->Fetch(STANDARD_VECTOR_SIZE);
            } catch (...) {
                if (interrupt) {
                    interrupt->Stop();
                }
                // Same rule as at bind: a failed fetch leaves the channel in a
                // state this side cannot describe, so the session is not reused.
                state.session.Poison();
                if (!state.catalog_name.empty()) {
                    state.cursor.reset();
                    PoisonTransactionSession(context, state.catalog_name);
                }
                throw;
            }
        });
        state.metrics.fetch_nanoseconds += elapsed(fetch_started);
        state.metrics.rows_fetched += batch.rows.size();
        if (local) {
            const auto io_now = local->session->IoStats();
            state.metrics.Add(io_now - local->last_io);
            local->last_io = io_now;
        } else if (state.session) {
            const auto io_now = state.session->IoStats();
            state.metrics.Add(io_now - state.last_io);
            state.last_io = io_now;
        }
        const auto convert_started = clock_now();
        // Every vector of the chunk has to be written: one left unset is
        // uninitialized memory that DuckDB reads back in DataChunk::Verify. The
        // fetched row and the chunk are in the same order, so vector i is column i;
        // a row can carry one more column than the chunk when nothing is projected
        // and only the row count is wanted.
        if (output.ColumnCount() != state.chunk_columns) {
            throw InternalException("oracle_query output chunk does not match its describe metadata");
        }
        for (idx_t row_index = 0; row_index < batch.rows.size(); row_index++) {
            const auto &row = batch.rows[row_index];
            if (row.size() != state.columns.size()) {
                throw InternalException("oracle_query row has a different column count from its describe metadata");
            }
            // A deferred scan fetches only the light columns, then the ROWID.
            const auto written = state.deferred ? state.deferred->light_vectors.size() : state.chunk_columns;
            for (idx_t column_index = 0; column_index < written; column_index++) {
                const auto vector_index = state.deferred ? state.deferred->light_vectors[column_index] : column_index;
                TranslatingOracleErrors("oracle_query could not convert an Oracle value", [&] {
                    WriteOracleValue(output.data[vector_index], row_index, state.columns[column_index],
                                     row[column_index]);
                    return true;
                });
            }
        }
        // SetChildCardinality, not SetCardinality. In DuckDB 2.0 every vector
        // carries its own size, and SetValue does not advance it; SetCardinality
        // sets the chunk's count only, leaving each vector at size 0. A consumer
        // then reads the validity mask by the vector's size and sees no NULL at
        // all: `col IS NULL` matched every row, and count(col) counted them. The
        // compiler cannot see that; the adapter suite now does.
        output.SetChildCardinality(batch.rows.size());
        state.metrics.convert_nanoseconds += elapsed(convert_started);
        if (local && batch.exhausted) {
            local->cursor->Close();
            local->cursor.reset();
        }
        if (state.local_filter && !batch.rows.empty()) {
            // The filters Oracle was not sent. A chunk they empty is not the end of
            // the scan — an empty chunk means that — so fetch on until one has rows
            // or Oracle has no more.
            ExpressionExecutor executor(context, *state.local_filter);
            SelectionVector selection(STANDARD_VECTOR_SIZE);
            const auto kept = executor.SelectExpression(output, selection);
            if (state.deferred) {
                const auto deferred_started = clock_now();
                FillDeferredColumns(state, output, batch, selection, kept);
                state.metrics.fetch_nanoseconds += elapsed(deferred_started);
                const auto io_now = state.session->IoStats();
                state.metrics.Add(io_now - state.last_io);
                state.last_io = io_now;
            }
            if (kept != batch.rows.size()) {
                output.Slice(selection, kept);
            }
            if (kept == 0 && !batch.exhausted) {
                output.Reset();
                continue;
            }
        }
        if (local && output.size() == 0) {
            // A chunk of the table ended with nothing left to hand over; the next
            // one is read before this thread says it is done.
            output.Reset();
            continue;
        }
        return;
    }
}


CreateTableFunctionInfo DocumentedTableFunctionInfo(TableFunction function, OracleFunctionDocumentation documentation) {
    // DuckDB 2.0 reports a parameter's name from the signature rather than from
    // the description, so the documented names go there too. Only the
    // positional-only parameters are renamed, which keeps them positional-only:
    // no call gains a keyword form it did not have.
    auto &signature = function.GetSignature();
    for (idx_t index = 0; index < signature.GetParameterCount() && index < documentation.parameter_names.size();
         index++) {
        auto &parameter = signature.GetParameter(index);
        if (parameter.GetKind() == FunctionParameterKind::POSITIONAL_ONLY) {
            parameter.SetName(Identifier(documentation.parameter_names[index]));
        }
    }
    CreateTableFunctionInfo info(std::move(function));
    info.on_conflict = OnCreateConflict::ALTER_ON_CONFLICT;
    FunctionDescription description;
    description.parameter_names = std::move(documentation.parameter_names);
    description.description = std::move(documentation.description);
    description.examples = {std::move(documentation.example)};
    description.categories = std::move(documentation.categories);
    info.descriptions.push_back(std::move(description));
    return info;
}

// Every example below assumes the extension is loaded, an Oracle secret named
// `demo` exists, and examples/demo_setup.sql has been run in that schema; see
// the "Function reference" section of README.md. oracle_cursor and
// oracle_close_call also need a handle stored in a DuckDB variable first, as
// that section shows. None of them runs against an empty DuckDB.
vector<CreateTableFunctionInfo> OracleQueryFunctionInfos() {
    vector<CreateTableFunctionInfo> infos;
    TableFunction status("oracle_transaction_status", {LogicalType::VARCHAR},
                         OracleStatusFunction, OracleStatusBind, OracleStatusInit);
    infos.push_back(DocumentedTableFunctionInfo(
        std::move(status),
        {{"catalog_name"},
         "Returns local structured status of the current or most recent Oracle transaction; opens no remote session.",
         "SELECT * FROM oracle_transaction_status('ora');", {"oracle", "transaction"}}));
    TableFunction admin("oracle_execute_admin", {LogicalType::VARCHAR, LogicalType::VARCHAR},
                        OracleAdminFunction, OracleAdminBind, OracleAdminInit);
    infos.push_back(DocumentedTableFunctionInfo(
        std::move(admin),
        {{"secret_name", "sql"},
         "Runs one administrative DDL command on a dedicated session, only outside an explicit DuckDB transaction.",
         "SELECT * FROM oracle_execute_admin('demo', 'CREATE TABLE QUACK_DEMO_SCRATCH (ID NUMBER)');",
         {"oracle", "administration"}}));
    TableFunction query("oracle_query", {LogicalType::VARCHAR, LogicalType::VARCHAR}, OracleQueryFunction, OracleQueryBind,
                        OracleQueryInit);
    // DuckDB 2.0 declares the optional bind collection as a "*params" parameter
    // of the signature, where 1.5 had a varargs type on the function.
    query.GetSignature().AddArgs("params", LogicalType::ANY);
    infos.push_back(DocumentedTableFunctionInfo(
        std::move(query),
        {{"secret_name", "sql", "params"},
         "Runs an Oracle SELECT query with optional positional or named bind parameters and returns its rows.",
         "SELECT * FROM oracle_query('demo', 'SELECT :1 AS value FROM dual', [42]);",
         {"oracle", "query"}}));

    {
        TableFunction vector_search("oracle_vector_search",
                                    {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::ANY},
                                    OracleQueryFunction, OracleVectorSearchBind, OracleQueryInit);
        vector_search.GetSignature().WithTypedKwargs("options", [](TypedKwargs &options) {
            options.Add("k", LogicalType::BIGINT);
            options.Add("metric", LogicalType::VARCHAR);
            options.Add("approximate", LogicalType::BOOLEAN);
        });
        infos.push_back(DocumentedTableFunctionInfo(
            std::move(vector_search),
            {{"secret_name", "table_name", "column_name", "query_vector", "k", "metric", "approximate"},
             "Returns the k rows of an Oracle 23ai table whose VECTOR column is nearest to the query vector, with their "
             "distance, ranked by Oracle's VECTOR_DISTANCE so a vector index is used when there is one.",
             "SELECT * FROM oracle_vector_search('demo', 'DOCS', 'EMBEDDING', [0.1, 0.2, 0.3]::FLOAT[3], k := 5, "
             "metric := 'COSINE');",
             {"oracle", "vector"}}));
    }
    TableFunction transaction_query("oracle_query_transaction", {LogicalType::VARCHAR, LogicalType::VARCHAR},
                                    OracleQueryFunction, OracleTransactionQueryBind, OracleQueryInit);
    transaction_query.GetSignature().AddArgs("params", LogicalType::ANY);
    infos.push_back(DocumentedTableFunctionInfo(
        std::move(transaction_query),
        {{"catalog_name", "sql", "params"},
         "Reads through the attached Oracle catalog's current transaction, pinning one session until COMMIT or ROLLBACK.",
         "SELECT * FROM oracle_query_transaction('ora', 'SELECT 1 FROM dual');",
         {"oracle", "transaction"}}));

    TableFunction typed_query("oracle_query_transaction_typed",
                              {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::LIST(LogicalType::VARCHAR),
                               LogicalType::LIST(LogicalType::VARCHAR)},
                              OracleQueryFunction, OracleTransactionTypedQueryBind, OracleQueryInit);
    typed_query.GetSignature().AddArgs("params", LogicalType::ANY);
    infos.push_back(DocumentedTableFunctionInfo(
        std::move(typed_query),
        {{"catalog_name", "sql", "column_names", "column_types", "params"},
         "Reads through the attached Oracle catalog's current transaction with caller-declared result columns, so "
         "binding runs nothing in Oracle and the query runs once against a describe that must match them.",
         "SELECT * FROM oracle_query_transaction_typed('ora', "
         "'SELECT DEPARTMENT_ID, DEPARTMENT_NAME FROM QUACK_DEMO_DEPARTMENTS ORDER BY DEPARTMENT_ID', "
         "['DEPARTMENT_ID', 'DEPARTMENT_NAME'], ['BIGINT', 'VARCHAR']);",
         {"oracle", "transaction"}}));

    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_execute_composite_transaction",
                      {LogicalType::VARCHAR, LogicalType::LIST(LogicalType::VARCHAR), LogicalType::ANY,
                       LogicalType::LIST(LogicalType::BIGINT)},
                      OracleExecuteFunction, OracleCompositeBind, OracleCompositeInit),
        {{"catalog_name", "statements", "params", "expected_row_counts"},
         "Runs up to 16 INSERT, UPDATE or DELETE statements in one round trip on the attached Oracle catalog's "
         "transaction, with Oracle checking each statement's exact row count and no COMMIT.",
         "SELECT * FROM oracle_execute_composite_transaction('ora', "
         "['INSERT INTO QUACK_DEMO_LOG (LABEL) VALUES (:label)', 'DELETE FROM QUACK_DEMO_LOG WHERE LABEL = :label'], "
         "{'label': 'composite example'}, [1, 1]);",
         {"oracle", "transaction"}}));

    TableFunction transaction_execute("oracle_execute_transaction", {LogicalType::VARCHAR, LogicalType::VARCHAR},
                                      OracleExecuteFunction, OracleTransactionExecuteBind, OracleTransactionExecuteInit);
    transaction_execute.GetSignature().AddArgs("params", LogicalType::ANY);
    infos.push_back(DocumentedTableFunctionInfo(
        std::move(transaction_execute),
        {{"catalog_name", "sql", "params"},
         "Runs one INSERT, UPDATE or DELETE in the attached Oracle catalog's transaction, without an independent COMMIT.",
         "SELECT * FROM oracle_execute_transaction('ora', "
         "'INSERT INTO QUACK_DEMO_LOG (LABEL) VALUES (:label)', {'label': 'example'});",
         {"oracle", "transaction"}}));


    TableFunction transaction_many("oracle_execute_many_transaction",
        {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::ANY},
        OracleTransactionManyFunction, OracleTransactionManyBind, OracleTransactionManyInit);
    transaction_many.GetSignature().WithTypedKwargs("options", [](TypedKwargs &options) {
        options.Add("exact_counts", LogicalType::BOOLEAN);
    });
    infos.push_back(DocumentedTableFunctionInfo(std::move(transaction_many),
        {{"catalog_name", "sql", "rows", "exact_counts"},
         "Executes bounded DML on the caller transaction. Exact per-row counts default to scalar execution; "
         "exact_counts=false uses native array DML and returns one explicitly aggregate count with NULL row_index.",
         "SELECT * FROM oracle_execute_many_transaction('ora', 'DELETE FROM QUACK_DEMO_LOG WHERE LOG_ID = :id', [{id: 1}]);",
         {"oracle", "transaction"}}));
    {
        TableFunction plsql("oracle_plsql", {LogicalType::VARCHAR, LogicalType::VARCHAR}, OracleCallNamedFunction,
                            OraclePlsqlBind, OraclePlsqlInit);
        plsql.GetSignature().AddArgs("binds", LogicalType::ANY);
        infos.push_back(DocumentedTableFunctionInfo(
            std::move(plsql),
            {{"secret_name", "block", "binds"},
             "Runs one anonymous PL/SQL block (BEGIN ... END; or DECLARE ... END;) on its own session and commits it "
             "when it succeeds. Binds are STRUCT(name, direction, type, value) matched to the block's :name "
             "placeholders; the OUT and IN OUT ones come back as rows, a REF CURSOR as a handle for oracle_cursor.",
             "SELECT * FROM oracle_plsql('demo', 'BEGIN :greeting := ''hello '' || :who; END;', "
             "[{name:'greeting',direction:'out',type:'varchar',value:NULL::VARCHAR}, "
             "{name:'who',direction:'in',type:'varchar',value:'world'}]);",
             {"oracle", "plsql"}}));
        TableFunction plsql_transaction("oracle_plsql_transaction", {LogicalType::VARCHAR, LogicalType::VARCHAR},
                                        OracleTransactionCallFunction, OracleTransactionPlsqlBind,
                                        OracleTransactionPlsqlInit);
        plsql_transaction.GetSignature().AddArgs("binds", LogicalType::ANY);
        infos.push_back(DocumentedTableFunctionInfo(
            std::move(plsql_transaction),
            {{"catalog_name", "block", "binds"},
             "Runs one anonymous PL/SQL block on the caller transaction, with no adapter COMMIT. The block must not "
             "commit, run DDL or use an autonomous transaction; REF CURSOR binds are refused.",
             "SELECT * FROM oracle_plsql_transaction('ora', 'BEGIN :n := 1 + 1; END;', "
             "[{name:'n',direction:'out',type:'number',value:NULL::VARCHAR}]);",
             {"oracle", "transaction"}}));
    }
    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_call_named_transaction", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::ANY},
            OracleTransactionCallFunction, OracleTransactionCallBind, OracleTransactionCallInit),
        {{"catalog_name", "procedure_name", "arguments"},
         "Calls a NUMBER/VARCHAR scalar procedure on the caller transaction, with no adapter COMMIT. "
         "The procedure itself must preserve transaction ownership.",
         "SELECT * FROM oracle_call_named_transaction('ora', 'QUACK_DEMO_MOTTO', "
         "[{name:'P_TEXT',direction:'out',type:'varchar',value:NULL::VARCHAR}]);",
         {"oracle", "transaction"}}));

    TableFunction execute("oracle_execute", {LogicalType::VARCHAR, LogicalType::VARCHAR}, OracleExecuteFunction,
                          OracleExecuteBind, OracleExecuteInit);
    execute.GetSignature().AddArgs("params", LogicalType::ANY);
    infos.push_back(DocumentedTableFunctionInfo(
        std::move(execute),
        {{"secret_name", "sql", "params"},
         "Runs one Oracle INSERT, UPDATE or DELETE with optional positional or named bind parameters, commits it in "
         "Oracle, and returns affected_rows.",
         "SELECT * FROM oracle_execute('demo', 'INSERT INTO QUACK_DEMO_LOG (LABEL, AMOUNT) VALUES (:label, :amount)', "
         "{'label': 'example', 'amount': 1.5});",
         {"oracle", "write"}}));

    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_execute_many", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::ANY},
                      OracleExecuteFunction, OracleExecuteManyBind, OracleExecuteManyInit),
        {{"secret_name", "sql", "rows"},
         "Runs one Oracle INSERT, UPDATE or DELETE once for each bind record in a list using array DML, "
         "commits it in Oracle, and returns the total affected_rows.",
         "SELECT * FROM oracle_execute_many('demo', 'INSERT INTO QUACK_DEMO_LOG (LABEL, AMOUNT) VALUES (:label, "
         ":amount)', [{'label': 'a', 'amount': 1.5}, {'label': 'b', 'amount': 2.5}]);",
         {"oracle", "write"}}));

    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_call_number", {LogicalType::VARCHAR, LogicalType::VARCHAR}, OracleCallNumberFunction,
                      OracleCallNumberBind, OracleCallNumberInit),
        {{"secret_name", "function_name"},
         "Calls an Oracle function that takes no arguments and returns NUMBER, and returns its result as text.",
         "SELECT * FROM oracle_call_number('demo', 'QUACK_DEMO_ANSWER');",
         {"oracle", "call"}}));
    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_call_number_args", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::ANY},
                      OracleCallNumberFunction, OracleCallNumberArgsBind, OracleCallNumberArgsInit),
        {{"secret_name", "function_name", "arguments"},
         "Calls an Oracle function that returns NUMBER with named IN arguments taken from a STRUCT, and returns its "
         "result as text.",
         "SELECT * FROM oracle_call_number_args('demo', 'QUACK_DEMO_ADD', {P_A: 2, P_B: 3});",
         {"oracle", "call"}}));
    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_call_out_number", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
                      OracleCallNumberFunction, OracleCallOutNumberBind, OracleCallOutNumberInit),
        {{"secret_name", "procedure_name", "argument_name"},
         "Calls an Oracle procedure whose only argument is a NUMBER OUT, and returns that value as text.",
         "SELECT * FROM oracle_call_out_number('demo', 'QUACK_DEMO_COUNT_DEPARTMENTS', 'P_COUNT');",
         {"oracle", "call"}}));
    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_call_out_varchar", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
                      OracleCallNumberFunction, OracleCallOutVarcharBind, OracleCallOutVarcharInit),
        {{"secret_name", "procedure_name", "argument_name"},
         "Calls an Oracle procedure whose only argument is a VARCHAR2 OUT, and returns that value.",
         "SELECT * FROM oracle_call_out_varchar('demo', 'QUACK_DEMO_MOTTO', 'P_TEXT');",
         {"oracle", "call"}}));
    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_call_inout_number",
                      {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
                      OracleCallNumberFunction, OracleCallInOutNumberBind, OracleCallInOutNumberInit),
        {{"secret_name", "procedure_name", "argument_name", "value"},
         "Passes a NUMBER, given as text, to an Oracle procedure's only argument, an IN OUT, and returns the updated "
         "value as text.",
         "SELECT * FROM oracle_call_inout_number('demo', 'QUACK_DEMO_DOUBLE', 'P_VALUE', '21');",
         {"oracle", "call"}}));
    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_call_inout_varchar",
                      {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
                      OracleCallNumberFunction, OracleCallInOutVarcharBind, OracleCallInOutVarcharInit),
        {{"secret_name", "procedure_name", "argument_name", "value"},
         "Passes a VARCHAR2 to an Oracle procedure's only argument, an IN OUT, and returns the updated value.",
         "SELECT * FROM oracle_call_inout_varchar('demo', 'QUACK_DEMO_SHOUT', 'P_TEXT', 'quack');",
         {"oracle", "call"}}));

    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_call", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
                      OracleCallFunction, OracleCallBind, OracleCallInit),
        {{"secret_name", "procedure_name", "cursor_argument"},
         "Calls an Oracle procedure whose only argument is an OUT SYS_REFCURSOR, and returns a cursor handle rather "
         "than the cursor's rows.",
         "SELECT * FROM oracle_call('demo', 'QUACK_DEMO_LIST', 'P_ROWS');",
         {"oracle", "call"}}));
    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_call_implicit", {LogicalType::VARCHAR, LogicalType::VARCHAR}, OracleCallFunction,
                      OracleCallImplicitBind, OracleCallImplicitInit),
        {{"secret_name", "procedure_name"},
         "Calls an Oracle procedure that takes no arguments and returns a cursor handle for each implicit result "
         "set it returns.",
         "SELECT * FROM oracle_call_implicit('demo', 'QUACK_DEMO_IMPLICIT');",
         {"oracle", "call"}}));
    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_call_cursors",
                      {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::LIST(LogicalType::VARCHAR)},
                      OracleCallFunction, OracleCallCursorsBind, OracleCallCursorsInit),
        {{"secret_name", "procedure_name", "cursor_arguments"},
         "Calls an Oracle procedure whose arguments are the listed OUT SYS_REFCURSORs, and returns a cursor handle "
         "for each.",
         "SELECT * FROM oracle_call_cursors('demo', 'QUACK_DEMO_LIST', ['P_ROWS']);",
         {"oracle", "call"}}));
    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_call_named", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::ANY},
                      OracleCallNamedFunction, OracleCallNamedBind, OracleCallNamedInit),
        {{"secret_name", "procedure_name", "arguments"},
         "Calls an Oracle procedure with arguments whose names, directions, types and values are given explicitly, "
         "and returns its OUT values and cursor handles.",
         "SELECT * FROM oracle_call_named('demo', 'QUACK_DEMO_GREET', [{'name': 'P_NAME', 'direction': 'in', "
         "'type': 'varchar', 'value': 'world'}, {'name': 'P_GREETING', 'direction': 'out', 'type': 'varchar', "
         "'value': NULL}]);",
         {"oracle", "call"}}));
    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_call_named_function",
                      {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::ANY},
                      OracleCallNamedFunction, OracleCallNamedFunctionBind, OracleCallNamedFunctionInit),
        {{"secret_name", "function_name", "return_type", "arguments"},
         "Calls an Oracle function with the given return type and explicitly described arguments, and returns its "
         "result and OUT values.",
         "SELECT * FROM oracle_call_named_function('demo', 'QUACK_DEMO_ADD', 'number', [{'name': 'P_A', "
         "'direction': 'in', 'type': 'number', 'value': '2'}, {'name': 'P_B', 'direction': 'in', 'type': 'number', "
         "'value': '3'}]);",
         {"oracle", "call"}}));
    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_arguments", {LogicalType::VARCHAR, LogicalType::VARCHAR}, OracleArgumentsFunction,
                      OracleArgumentsBind, OracleArgumentsInit),
        {{"secret_name", "callable_name"},
         "Lists the arguments of every overload of an Oracle procedure or function, with the reason for any "
         "argument type this client cannot bind.",
         "SELECT * FROM oracle_arguments('demo', 'QUACK_DEMO_ADD');",
         {"oracle", "metadata"}}));
    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_call_auto", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::ANY},
                      OracleCallNamedFunction, OracleCallAutoBind, OracleCallAutoInit),
        {{"secret_name", "callable_name", "values"},
         "Reads an Oracle procedure's or function's signature from the data dictionary and calls it with the given "
         "values in argument declaration order.",
         "SELECT * FROM oracle_call_auto('demo', 'QUACK_DEMO_ADD', ['2', '3']);",
         {"oracle", "call"}}));
    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_cursor", {LogicalType::VARCHAR}, OracleQueryFunction, OracleCursorBind,
                      OracleCursorInit),
        {{"cursor_handle"},
         "Consumes a cursor handle created earlier on the same DuckDB connection and returns the cursor's rows.",
         "SELECT * FROM oracle_cursor(getvariable('oracle_example_handle'));",
         {"oracle", "cursor"}}));
    infos.push_back(DocumentedTableFunctionInfo(
        TableFunction("oracle_close_call", {LogicalType::VARCHAR}, OracleCloseCallFunction, OracleCloseCallBind,
                      OracleCloseCallInit),
        {{"cursor_handle"},
         "Closes the remaining registered cursors of the whole call a cursor handle belongs to, and returns closed.",
         "SELECT * FROM oracle_close_call(getvariable('oracle_close_handle'));",
         {"oracle", "cursor"}}));
    return infos;
}

void RegisterOracleQuery(ExtensionLoader &loader) {
    for (auto &info : OracleQueryFunctionInfos()) {
        loader.RegisterFunction(std::move(info));
    }
}

} // namespace duckdb

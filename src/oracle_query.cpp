#include "oracle_adapter.hpp"

#include "oracle_scanner/auth_crypto.hpp"
#include "oracle_scanner/call_registry.hpp"
#include "oracle_scanner/descriptor_parser.hpp"
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


struct OracleExecuteBindData final : TableFunctionData {
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

std::optional<uint16_t> OracleInputType(LogicalTypeId type) {
    switch (type) {
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
            binds.push_back({std::to_string(index + 1), *oracle_type, oracle_scanner::BindDirection::IN, std::nullopt});
            continue;
        }
        if (type == LogicalTypeId::VARCHAR) {
            const auto text = values[index].GetValue<std::string>();
            binds.push_back({std::to_string(index + 1), 1, oracle_scanner::BindDirection::IN,
                             std::vector<uint8_t>(text.begin(), text.end())});
        } else if (type == LogicalTypeId::BLOB) {
            const auto bytes = StringValue::Get(values[index]);
            binds.push_back({std::to_string(index + 1), 23, oracle_scanner::BindDirection::IN,
                             std::vector<uint8_t>(bytes.begin(), bytes.end())});
        } else if (type == LogicalTypeId::FLOAT) {
            const auto number = values[index].GetValue<float>();
            if (!std::isfinite(number)) {
                throw BinderException("%s parameter %llu cannot be a non-finite FLOAT", function_name, index + 1);
            }
            binds.push_back({std::to_string(index + 1), 100, oracle_scanner::BindDirection::IN,
                             oracle_scanner::EncodeOracleBinaryFloat(number)});
        } else if (type == LogicalTypeId::DOUBLE) {
            const auto number = values[index].GetValue<double>();
            if (!std::isfinite(number)) {
                throw BinderException("%s parameter %llu cannot be a non-finite DOUBLE", function_name, index + 1);
            }
            binds.push_back({std::to_string(index + 1), 101, oracle_scanner::BindDirection::IN,
                             oracle_scanner::EncodeOracleBinaryDouble(number)});
        } else if (type == LogicalTypeId::DATE) {
            const auto date = values[index].GetValue<date_t>();
            if (!Date::IsFinite(date)) {
                throw BinderException("%s parameter %llu cannot be an infinite DATE", function_name, index + 1);
            }
            int32_t year;
            int32_t month;
            int32_t day;
            Date::Convert(date, year, month, day);
            binds.push_back({std::to_string(index + 1), 12, oracle_scanner::BindDirection::IN,
                             oracle_scanner::EncodeOracleDate({year, static_cast<uint8_t>(month),
                                                               static_cast<uint8_t>(day)})});
        } else if (type == LogicalTypeId::TIMESTAMP) {
            const auto timestamp = values[index].GetValue<timestamp_t>();
            if (!Timestamp::IsFinite(timestamp)) {
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
            binds.push_back({std::to_string(index + 1), 180, oracle_scanner::BindDirection::IN,
                             oracle_scanner::EncodeOracleTimestamp(
                                  {year, static_cast<uint8_t>(month), static_cast<uint8_t>(day),
                                   static_cast<uint8_t>(hour), static_cast<uint8_t>(minute), static_cast<uint8_t>(second),
                                  static_cast<uint32_t>(microseconds) * 1000U}, false)});
        } else if (type == LogicalTypeId::TINYINT || type == LogicalTypeId::SMALLINT || type == LogicalTypeId::INTEGER ||
                   type == LogicalTypeId::BIGINT || type == LogicalTypeId::UTINYINT || type == LogicalTypeId::USMALLINT ||
                   type == LogicalTypeId::UINTEGER || type == LogicalTypeId::UBIGINT || type == LogicalTypeId::DECIMAL) {
            binds.push_back({std::to_string(index + 1), 2, oracle_scanner::BindDirection::IN,
                             oracle_scanner::EncodeOracleNumber(values[index].ToString())});
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
        const auto &name = StructType::GetChildName(value.type(), index);
        if (argument.IsNull()) {
            const auto oracle_type = OracleInputType(argument.type().id());
            if (!oracle_type) {
                throw BinderException("%s cannot infer an Oracle type for NULL argument %s of type %s", function_name,
                                      name, argument.type().ToString());
            }
            binds.push_back({name, *oracle_type, oracle_scanner::BindDirection::IN, std::nullopt});
            continue;
        }
        if (argument.type().id() == LogicalTypeId::VARCHAR) {
            const auto text = argument.GetValue<std::string>();
            binds.push_back({name, 1, oracle_scanner::BindDirection::IN,
                             std::vector<uint8_t>(text.begin(), text.end())});
        } else if (argument.type().id() == LogicalTypeId::BLOB) {
            const auto bytes = StringValue::Get(argument);
            binds.push_back({name, 23, oracle_scanner::BindDirection::IN,
                             std::vector<uint8_t>(bytes.begin(), bytes.end())});
        } else if (argument.type().id() == LogicalTypeId::FLOAT) {
            const auto number = argument.GetValue<float>();
            if (!std::isfinite(number)) {
                throw BinderException("%s argument %s cannot be a non-finite FLOAT", function_name, name);
            }
            binds.push_back({name, 100, oracle_scanner::BindDirection::IN,
                             oracle_scanner::EncodeOracleBinaryFloat(number)});
        } else if (argument.type().id() == LogicalTypeId::DOUBLE) {
            const auto number = argument.GetValue<double>();
            if (!std::isfinite(number)) {
                throw BinderException("%s argument %s cannot be a non-finite DOUBLE", function_name, name);
            }
            binds.push_back({name, 101, oracle_scanner::BindDirection::IN,
                             oracle_scanner::EncodeOracleBinaryDouble(number)});
        } else if (argument.type().id() == LogicalTypeId::DATE) {
            const auto date = argument.GetValue<date_t>();
            if (!Date::IsFinite(date)) {
                throw BinderException("%s argument %s cannot be an infinite DATE", function_name, name);
            }
            int32_t year;
            int32_t month;
            int32_t day;
            Date::Convert(date, year, month, day);
            binds.push_back({name, 12, oracle_scanner::BindDirection::IN,
                             oracle_scanner::EncodeOracleDate({year, static_cast<uint8_t>(month),
                                                               static_cast<uint8_t>(day)})});
        } else if (argument.type().id() == LogicalTypeId::TIMESTAMP) {
            const auto timestamp = argument.GetValue<timestamp_t>();
            if (!Timestamp::IsFinite(timestamp)) {
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
            binds.push_back({name, 180, oracle_scanner::BindDirection::IN,
                             oracle_scanner::EncodeOracleTimestamp(
                                  {year, static_cast<uint8_t>(month), static_cast<uint8_t>(day),
                                   static_cast<uint8_t>(hour), static_cast<uint8_t>(minute), static_cast<uint8_t>(second),
                                  static_cast<uint32_t>(microseconds) * 1000U}, false)});
        } else if (argument.type().IsNumeric()) {
            binds.push_back({name, 2, oracle_scanner::BindDirection::IN,
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
            bind_direction = oracle_scanner::BindDirection::IN;
        } else if (direction == "out") {
            bind_direction = oracle_scanner::BindDirection::OUT;
        } else if (direction == "inout") {
            bind_direction = oracle_scanner::BindDirection::IN_OUT;
        } else {
            throw BinderException("oracle_call_named direction for %s must be in, out, or inout", name);
        }
        // The value encoding is shared with the signature-driven path so the
        // two cannot disagree about what a value means.
        auto encoded = EncodeOracleCallableArgument(type, bind_direction, value_child, name, "oracle_call_named");
        result.push_back({name, encoded.oracle_type, bind_direction, std::move(encoded.value), encoded.maximum_bytes});
    }
    if (result.empty()) {
        throw BinderException("oracle_call_named requires at least one argument");
    }
    return result;
}

unique_ptr<FunctionData> OracleQueryBind(ClientContext &context, TableFunctionBindInput &input,
                                         vector<LogicalType> &return_types, vector<string> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull()) {
        throw BinderException("oracle_query secret and SQL cannot be NULL");
    }
    const auto secret_name = input.inputs[0].GetValue<std::string>();
    const auto sql = input.inputs[1].GetValue<std::string>();
    std::string password;
    auto config = ConnectionFromSecret(context, secret_name, password);

    const auto binds = ParameterBinds(input, "oracle_query");
    oracle_scanner::ValidateOracleQuery(sql, binds);
    auto result = make_uniq<OracleQueryBindData>();
    result->secret_name = secret_name;
    try {
        result->session = AcquireOracleReadSession(context, secret_name, std::string(), config, password);
        result->cursor = result->session->Query(sql, binds);
    } catch (const std::exception &error) {
        // A pooled session whose statement failed cannot be handed to the next
        // one: the failure may have left the channel mid-message.
        result->session.Poison();
        throw IOException("oracle_query could not open Oracle query: %s", error.what());
    }
    result->columns = result->cursor->Columns();
    if (result->columns.empty()) {
        throw BinderException("oracle_query received no described Oracle columns");
    }
    std::unordered_set<std::string> used_names;
    for (idx_t index = 0; index < result->columns.size(); index++) {
        names.push_back(OutputName(result->columns[index], index, used_names));
        result->types.push_back(TypeFor(result->columns[index]));
        return_types.push_back(result->types.back());
    }
    return std::move(result);
}



unique_ptr<FunctionData> OracleExecuteBind(ClientContext &context, TableFunctionBindInput &input,
                                           vector<LogicalType> &return_types, vector<string> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull()) {
        throw BinderException("oracle_execute secret and SQL cannot be NULL");
    }
    RequireAutoCommit(context, "oracle_execute");
    auto result = make_uniq<OracleExecuteBindData>();
    result->sql = input.inputs[1].GetValue<std::string>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->binds = ParameterBinds(input, "oracle_execute");
    oracle_scanner::ValidateOracleDml(result->sql, result->binds);
    names.push_back("affected_rows");
    return_types.push_back(LogicalType::UBIGINT);
    return std::move(result);
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

void OracleExecuteFunction(ClientContext &, TableFunctionInput &input, DataChunk &output) {
    auto &state = input.global_state->Cast<OracleExecuteGlobalState>();
    if (!state.emitted) {
        output.SetValue(0, 0, Value::UBIGINT(state.affected_rows));
        output.SetCardinality(1);
        state.emitted = true;
    }
}

unique_ptr<FunctionData> OracleExecuteManyBind(ClientContext &context, TableFunctionBindInput &input,
                                               vector<LogicalType> &return_types, vector<string> &names) {
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
    names.push_back("affected_rows");
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
        throw IOException("oracle_execute_many failed: %s", error.what());
    }
}

unique_ptr<FunctionData> OracleCallNumberBind(ClientContext &context, TableFunctionBindInput &input,
                                              vector<LogicalType> &return_types, vector<string> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull()) {
        throw BinderException("oracle_call_number secret and function cannot be NULL");
    }
    auto result = make_uniq<OracleCallNumberBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->function = input.inputs[1].GetValue<std::string>();
    names.push_back("value");
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
        request.return_bind = {"r", 2, oracle_scanner::BindDirection::OUT, std::nullopt, 22};
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
                                                  vector<LogicalType> &return_types, vector<string> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull()) {
        throw BinderException("oracle_call_number_args secret, function, and arguments cannot be NULL");
    }
    auto result = make_uniq<OracleCallNumberArgsBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->function = input.inputs[1].GetValue<std::string>();
    result->arguments = NamedBinds(input.inputs[2], "oracle_call_number_args");
    names.push_back("value");
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
        request.return_bind = {"r", 2, oracle_scanner::BindDirection::OUT, std::nullopt, 22};
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
        output.SetValue(0, 0, state.value ? Value(*state.value) : Value());
        output.SetCardinality(1);
        state.emitted = true;
    }
}

unique_ptr<FunctionData> OracleCallOutNumberBind(ClientContext &context, TableFunctionBindInput &input,
                                                 vector<LogicalType> &return_types, vector<string> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull()) {
        throw BinderException("oracle_call_out_number secret, procedure, and output argument cannot be NULL");
    }
    auto result = make_uniq<OracleCallOutNumberBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->procedure = input.inputs[1].GetValue<std::string>();
    result->argument = input.inputs[2].GetValue<std::string>();
    names.push_back("value");
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
        request.arguments = {{bind.argument, 2, oracle_scanner::BindDirection::OUT, std::nullopt, 22}};
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
                                                  vector<LogicalType> &return_types, vector<string> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull()) {
        throw BinderException("oracle_call_out_varchar secret, procedure, and output argument cannot be NULL");
    }
    auto result = make_uniq<OracleCallOutVarcharBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->procedure = input.inputs[1].GetValue<std::string>();
    result->argument = input.inputs[2].GetValue<std::string>();
    names.push_back("value");
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
        request.arguments = {{bind.argument, 1, oracle_scanner::BindDirection::OUT, std::nullopt, 32767}};
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
                                                    vector<LogicalType> &return_types, vector<string> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull() || input.inputs[3].IsNull()) {
        throw BinderException("oracle_call_inout_number secret, procedure, argument, and value cannot be NULL");
    }
    auto result = make_uniq<OracleCallInOutNumberBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->procedure = input.inputs[1].GetValue<std::string>();
    result->argument = input.inputs[2].GetValue<std::string>();
    result->value = oracle_scanner::EncodeOracleNumber(input.inputs[3].GetValue<std::string>());
    names.push_back("value");
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
        request.arguments = {{bind.argument, 2, oracle_scanner::BindDirection::IN_OUT, bind.value, 22}};
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
                                                     vector<LogicalType> &return_types, vector<string> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull() || input.inputs[3].IsNull()) {
        throw BinderException("oracle_call_inout_varchar secret, procedure, argument, and value cannot be NULL");
    }
    auto result = make_uniq<OracleCallInOutVarcharBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->procedure = input.inputs[1].GetValue<std::string>();
    result->argument = input.inputs[2].GetValue<std::string>();
    const auto value = input.inputs[3].GetValue<std::string>();
    result->value = std::vector<uint8_t>(value.begin(), value.end());
    names.push_back("value");
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
        request.arguments = {{bind.argument, 1, oracle_scanner::BindDirection::IN_OUT, bind.value, 32767}};
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
                                        vector<LogicalType> &return_types, vector<string> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull()) {
        throw BinderException("oracle_call secret, procedure, and cursor argument cannot be NULL");
    }
    auto result = make_uniq<OracleCallBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->procedure = input.inputs[1].GetValue<std::string>();
    result->cursor_argument = input.inputs[2].GetValue<std::string>();
    names.push_back("cursor_handle");
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
                              oracle_scanner::BindDirection::OUT, std::nullopt, 4}};
        auto result = session->Call(request);
        if (result.explicit_cursors.size() != 1 || !result.implicit_cursors.empty()) {
            throw BinderException("oracle_call currently requires exactly one explicit SYS_REFCURSOR result");
        }
        std::vector<std::unique_ptr<oracle_scanner::OracleCursor>> owned;
        owned.reserve(1);
        for (auto &cursor : result.explicit_cursors) {
            owned.push_back(std::make_unique<SessionOwningCursor>(session, std::move(cursor)));
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
        output.SetValue(0, index, Value(state.handles[state.next_handle + index]));
    }
    state.next_handle += count;
    output.SetCardinality(count);
}

unique_ptr<FunctionData> OracleCallImplicitBind(ClientContext &context, TableFunctionBindInput &input,
                                                vector<LogicalType> &return_types, vector<string> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull()) {
        throw BinderException("oracle_call_implicit secret and procedure cannot be NULL");
    }
    auto result = make_uniq<OracleCallImplicitBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);
    result->procedure = input.inputs[1].GetValue<std::string>();
    names.push_back("cursor_handle");
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
            owned.push_back(std::make_unique<SessionOwningCursor>(session, std::move(cursor)));
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
                                               vector<LogicalType> &return_types, vector<string> &names) {
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
    names.push_back("cursor_handle");
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
                {argument, oracle_scanner::ORACLE_WIRE_TYPE_CURSOR, oracle_scanner::BindDirection::OUT, std::nullopt, 4});
        }
        auto result = session->Call(request);
        if (result.explicit_cursors.size() != bind.cursor_arguments.size() || !result.implicit_cursors.empty()) {
            throw BinderException("oracle_call_cursors procedure did not return every requested SYS_REFCURSOR");
        }
        std::vector<std::unique_ptr<oracle_scanner::OracleCursor>> owned;
        owned.reserve(result.explicit_cursors.size());
        for (auto &cursor : result.explicit_cursors) {
            owned.push_back(std::make_unique<SessionOwningCursor>(session, std::move(cursor)));
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
                                             vector<LogicalType> &return_types, vector<string> &names) {
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
                                             vector<LogicalType> &return_types, vector<string> &names) {
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
        if (argument.direction == oracle_scanner::BindDirection::OUT) {
            direction = "out";
        } else if (argument.direction == oracle_scanner::BindDirection::IN_OUT) {
            direction = "inout";
        }
        output.SetValue(0, index, row.overload.empty() ? Value() : Value(row.overload));
        output.SetValue(1, index, Value::INTEGER(argument.position));
        output.SetValue(2, index, Value(argument.name));
        output.SetValue(3, index, Value(direction));
        output.SetValue(4, index, argument.dictionary_type.empty() ? Value() : Value(argument.dictionary_type));
        output.SetValue(5, index, argument.bind_type_name.empty() ? Value() : Value(argument.bind_type_name));
        output.SetValue(6, index,
                        argument.unsupported_reason.empty() ? Value() : Value(argument.unsupported_reason));
    }
    state.next_row += count;
    output.SetCardinality(count);
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
    std::string result = KeywordHelper::WriteQuoted(signature.owner, '"');
    if (!signature.package.empty()) {
        result += "." + KeywordHelper::WriteQuoted(signature.package, '"');
    }
    return result + "." + KeywordHelper::WriteQuoted(signature.object, '"');
}

unique_ptr<FunctionData> OracleCallAutoBind(ClientContext &context, TableFunctionBindInput &input,
                                            vector<LogicalType> &return_types, vector<string> &names) {
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
            result->values.push_back(Value(LogicalType::VARCHAR));
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
            result_bind.direction = oracle_scanner::BindDirection::OUT;
            result_bind.oracle_type = argument.oracle_type;
            result_bind.maximum_bytes = argument.maximum_bytes;
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
                             encoded.maximum_bytes});
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
                owned.push_back(
                    std::make_unique<SessionOwningCursor>(session, std::move(result.explicit_cursors[cursor_index++])));
                cursor_rows.push_back(rows.size());
            } else {
                if (result.outputs.empty() || result.outputs[0].oracle_type != return_bind->oracle_type) {
                    throw BinderException("oracle_call_auto return value disagrees with Oracle response");
                }
                if (result.outputs[0].value) {
                    return_row.value = FormatCallScalar(return_bind->oracle_type, *result.outputs[0].value);
                }
                scalar_index = 1;
            }
            rows.push_back(std::move(return_row));
        }
        for (const auto &argument : arguments) {
            if (argument.direction == oracle_scanner::BindDirection::IN) {
                continue;
            }
            OracleCallNamedRow row;
            row.name = argument.name;
            if (argument.oracle_type == oracle_scanner::ORACLE_WIRE_TYPE_CURSOR) {
                if (cursor_index >= result.explicit_cursors.size()) {
                    throw BinderException("oracle_call_auto cursor output count disagrees with Oracle response");
                }
                owned.push_back(
                    std::make_unique<SessionOwningCursor>(session, std::move(result.explicit_cursors[cursor_index++])));
                cursor_rows.push_back(rows.size());
            } else {
                if (scalar_index >= result.outputs.size() ||
                    result.outputs[scalar_index].oracle_type != argument.oracle_type) {
                    throw BinderException("oracle_call_auto scalar output count disagrees with Oracle response");
                }
                const auto &output = result.outputs[scalar_index++];
                if (output.value) {
                    row.value = FormatCallScalar(argument.oracle_type, *output.value);
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
            if (argument.direction == oracle_scanner::BindDirection::IN) {
                continue;
            }
            OracleCallNamedRow row;
            row.name = argument.name;
            if (argument.oracle_type == oracle_scanner::ORACLE_WIRE_TYPE_CURSOR) {
                if (cursor_index >= result.explicit_cursors.size()) {
                    throw BinderException("oracle_call_named cursor output count disagrees with Oracle response");
                }
                owned.push_back(std::make_unique<SessionOwningCursor>(session, std::move(result.explicit_cursors[cursor_index++])));
                cursor_rows.push_back(rows.size());
            } else {
                if (scalar_index >= result.outputs.size() || result.outputs[scalar_index].oracle_type != argument.oracle_type) {
                    throw BinderException("oracle_call_named scalar output count disagrees with Oracle response");
                }
                const auto &output = result.outputs[scalar_index++];
                if (output.value) {
                    row.value = FormatCallScalar(argument.oracle_type, *output.value);
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
        output.SetValue(0, index, Value(row.name));
        output.SetValue(1, index, row.value ? Value(*row.value) : Value());
        output.SetValue(2, index, row.cursor_handle ? Value(*row.cursor_handle) : Value());
    }
    state.next_row += count;
    output.SetCardinality(count);
}

unique_ptr<FunctionData> OracleCallNamedFunctionBind(ClientContext &context, TableFunctionBindInput &input,
                                                     vector<LogicalType> &return_types, vector<string> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull() || input.inputs[3].IsNull()) {
        throw BinderException("oracle_call_named_function secret, function, return type, and arguments cannot be NULL");
    }
    const auto return_type = StringUtil::Lower(input.inputs[2].GetValue<std::string>());
    oracle_scanner::OracleBind return_bind;
    return_bind.name = "return_value";
    return_bind.direction = oracle_scanner::BindDirection::OUT;
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
            owned.push_back(
                std::make_unique<SessionOwningCursor>(session, std::move(result.explicit_cursors[cursor_index++])));
            cursor_rows.push_back(rows.size());
        } else if (result.outputs[0].value) {
            return_row.value = FormatCallScalar(bind.return_bind.oracle_type, *result.outputs[0].value);
        }
        rows.push_back(std::move(return_row));
        for (const auto &argument : bind.arguments) {
            if (argument.direction == oracle_scanner::BindDirection::IN) {
                continue;
            }
            OracleCallNamedRow row;
            row.name = argument.name;
            if (argument.oracle_type == oracle_scanner::ORACLE_WIRE_TYPE_CURSOR) {
                if (cursor_index >= result.explicit_cursors.size()) {
                    throw BinderException("oracle_call_named_function cursor output count disagrees with Oracle response");
                }
                owned.push_back(std::make_unique<SessionOwningCursor>(session, std::move(result.explicit_cursors[cursor_index++])));
                cursor_rows.push_back(rows.size());
            } else {
                if (scalar_index >= result.outputs.size() || result.outputs[scalar_index].oracle_type != argument.oracle_type) {
                    throw BinderException("oracle_call_named_function scalar output count disagrees with Oracle response");
                }
                const auto &output = result.outputs[scalar_index++];
                if (output.value) {
                    row.value = FormatCallScalar(argument.oracle_type, *output.value);
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
                                             vector<LogicalType> &return_types, vector<string> &names) {
    if (input.inputs[0].IsNull()) {
        throw BinderException("oracle_close_call handle cannot be NULL");
    }
    const auto handle = oracle_scanner::ParseCursorHandle(input.inputs[0].GetValue<std::string>());
    auto result = make_uniq<OracleCloseCallBindData>();
    result->state = context.registered_state->GetOrCreate<OracleCallRegistryState>("oracle_scanner.call_registry");
    result->call_id = handle.call_id;
    names.push_back("closed");
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
        output.SetValue(0, 0, Value::BOOLEAN(state.closed));
        output.SetCardinality(1);
        state.emitted = true;
    }
}

unique_ptr<FunctionData> OracleCursorBind(ClientContext &context, TableFunctionBindInput &input,
                                          vector<LogicalType> &return_types, vector<string> &names) {
    if (input.inputs[0].IsNull()) {
        throw BinderException("oracle_cursor handle cannot be NULL");
    }
    auto result = make_uniq<OracleCursorBindData>();
    result->cursor = CallRegistryFor(context).Take(oracle_scanner::ParseCursorHandle(input.inputs[0].GetValue<std::string>()));
    result->columns = result->cursor->Columns();
    std::unordered_set<std::string> used_names;
    for (idx_t index = 0; index < result->columns.size(); index++) {
        names.push_back(OutputName(result->columns[index], index, used_names));
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

unique_ptr<GlobalTableFunctionState> OracleQueryInit(ClientContext &context, TableFunctionInitInput &input) {
    auto &bind = input.bind_data->CastNoConst<OracleQueryBindData>();
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
    auto selected = input.column_ids;
    const auto chunk_columns = selected.size();
    if (selected.empty()) {
        selected.push_back(0);
    }
    if (input.filters) {
        // DuckDB drops a filter from the plan once it hands it over, so a
        // filter that reaches here has to be translated exactly or refused.
        bind.where_clause = OracleWhereClause(*input.filters, bind.columns, selected);
    }
    OracleSessionHandle session;
    std::unique_ptr<OracleCursor> cursor;
    std::vector<OracleColumn> columns;
    OpenProjectedScan(context, bind, selected, session, cursor, columns);
    std::vector<LogicalType> types;
    for (const auto &column : columns) {
        types.push_back(TypeFor(column));
    }
    return make_uniq<OracleQueryGlobalState>(std::move(session), std::move(cursor), std::move(columns),
                                             std::move(types), std::move(input.column_ids), chunk_columns);
}

void OracleQueryFunction(ClientContext &, TableFunctionInput &input, DataChunk &output) {
    auto &state = input.global_state->Cast<OracleQueryGlobalState>();
    const auto batch = TranslatingOracleErrors("oracle_query could not fetch from Oracle", [&] {
        try {
            return state.cursor->Fetch(STANDARD_VECTOR_SIZE);
        } catch (...) {
            // Same rule as at bind: a failed fetch leaves the channel in a
            // state this side cannot describe, so the session is not reused.
            state.session.Poison();
            throw;
        }
    });
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
        for (idx_t vector_index = 0; vector_index < state.chunk_columns; vector_index++) {
            output.SetValue(vector_index, row_index,
                            TranslatingOracleErrors("oracle_query could not convert an Oracle value", [&] {
                                return ValueFor(state.columns[vector_index], row[vector_index]);
                            }));
        }
    }
    output.SetCardinality(batch.rows.size());
}


void RegisterOracleQuery(ExtensionLoader &loader) {
    TableFunction function("oracle_query", {LogicalType::VARCHAR, LogicalType::VARCHAR}, OracleQueryFunction, OracleQueryBind,
                           OracleQueryInit);
    function.varargs = LogicalType::ANY;
    loader.RegisterFunction(function);

    TableFunction execute("oracle_execute", {LogicalType::VARCHAR, LogicalType::VARCHAR}, OracleExecuteFunction,
                          OracleExecuteBind, OracleExecuteInit);
    execute.varargs = LogicalType::ANY;
    loader.RegisterFunction(execute);

    loader.RegisterFunction(TableFunction("oracle_execute_many",
                                          {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::ANY},
                                          OracleExecuteFunction, OracleExecuteManyBind, OracleExecuteManyInit));

    loader.RegisterFunction(TableFunction("oracle_call_number", {LogicalType::VARCHAR, LogicalType::VARCHAR},
                                          OracleCallNumberFunction, OracleCallNumberBind, OracleCallNumberInit));
    loader.RegisterFunction(TableFunction("oracle_call_number_args",
                                          {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::ANY},
                                          OracleCallNumberFunction, OracleCallNumberArgsBind, OracleCallNumberArgsInit));
    loader.RegisterFunction(TableFunction("oracle_call_out_number",
                                          {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
                                          OracleCallNumberFunction, OracleCallOutNumberBind, OracleCallOutNumberInit));
    loader.RegisterFunction(TableFunction("oracle_call_out_varchar",
                                          {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
                                          OracleCallNumberFunction, OracleCallOutVarcharBind, OracleCallOutVarcharInit));
    loader.RegisterFunction(TableFunction("oracle_call_inout_number",
                                          {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR,
                                           LogicalType::VARCHAR},
                                          OracleCallNumberFunction, OracleCallInOutNumberBind, OracleCallInOutNumberInit));
    loader.RegisterFunction(TableFunction("oracle_call_inout_varchar",
                                          {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR,
                                           LogicalType::VARCHAR},
                                          OracleCallNumberFunction, OracleCallInOutVarcharBind, OracleCallInOutVarcharInit));

    loader.RegisterFunction(TableFunction("oracle_call", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
                                          OracleCallFunction, OracleCallBind, OracleCallInit));
    loader.RegisterFunction(TableFunction("oracle_call_implicit", {LogicalType::VARCHAR, LogicalType::VARCHAR},
                                          OracleCallFunction, OracleCallImplicitBind, OracleCallImplicitInit));
    loader.RegisterFunction(TableFunction("oracle_call_cursors",
                                          {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::LIST(LogicalType::VARCHAR)},
                                          OracleCallFunction, OracleCallCursorsBind, OracleCallCursorsInit));
    loader.RegisterFunction(TableFunction("oracle_call_named",
                                          {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::ANY},
                                          OracleCallNamedFunction, OracleCallNamedBind, OracleCallNamedInit));
    loader.RegisterFunction(TableFunction("oracle_call_named_function",
                                          {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR,
                                           LogicalType::ANY},
                                          OracleCallNamedFunction, OracleCallNamedFunctionBind,
                                          OracleCallNamedFunctionInit));
    loader.RegisterFunction(TableFunction("oracle_arguments", {LogicalType::VARCHAR, LogicalType::VARCHAR},
                                          OracleArgumentsFunction, OracleArgumentsBind, OracleArgumentsInit));
    loader.RegisterFunction(TableFunction("oracle_call_auto",
                                          {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::ANY},
                                          OracleCallNamedFunction, OracleCallAutoBind, OracleCallAutoInit));
    loader.RegisterFunction(TableFunction("oracle_cursor", {LogicalType::VARCHAR}, OracleQueryFunction, OracleCursorBind,
                                          OracleCursorInit));
    loader.RegisterFunction(TableFunction("oracle_close_call", {LogicalType::VARCHAR}, OracleCloseCallFunction,
                                          OracleCloseCallBind, OracleCloseCallInit));
}

} // namespace duckdb

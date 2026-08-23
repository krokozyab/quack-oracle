// Reading one Oracle table through several sessions at once.
//
// A single scan is one session and one thread, which for a migration is the
// whole cost: the pipeline streams, but at one session's throughput. Splitting
// the table by ranges of a numeric key gives DuckDB something to parallelise,
// and gives a failed transfer somewhere to resume from.
//
// The part that is easy to get wrong is not the parallelism, it is the
// consistency. Separate sessions read separate snapshots, so a row inserted
// while the scan runs can land in one shard's snapshot and not another's, and
// a row moved across the key boundary can be read twice or not at all. Every
// shard therefore reads `AS OF SCN` at one system change number taken before
// any of them start. Without that this would not be a copy of a table, it would
// be a copy of several different moments, and nothing about the result would
// say so.

#include "oracle_adapter.hpp"

#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"

#include "oracle_scanner/call_builder.hpp"
#include "oracle_scanner/session_factory.hpp"

#include <atomic>
#include <memory>
#include <string>
#include <vector>

namespace duckdb {

using oracle_scanner::OpenOracleSession;

namespace {

constexpr idx_t MAX_SHARDS = 256;

struct OracleParallelBindData final : TableFunctionData {
    ConnectionConfig config;
    std::string password;
    //! One statement per shard, each already pinned to the same SCN.
    std::vector<std::string> shard_sql;
    std::vector<OracleColumn> columns;
    std::vector<LogicalType> types;
};

struct OracleParallelGlobalState final : GlobalTableFunctionState {
    explicit OracleParallelGlobalState(idx_t shards_p) : shards(shards_p) {
    }

    idx_t MaxThreads() const override {
        return shards;
    }

    //! Handed out once each; a thread that finishes a shard takes the next.
    std::atomic<idx_t> next_shard {0};
    idx_t shards;
};

struct OracleParallelLocalState final : LocalTableFunctionState {
    OracleSessionHandle session;
    std::unique_ptr<OracleCursor> cursor;
    bool finished = false;
};

// Reads one scalar from a statement that returns exactly one row.
std::string ScalarOf(OracleSession &session, const std::string &sql, const char *what) {
    auto cursor = TranslatingOracleErrors(what, [&] { return session.Query(sql, {}); });
    const auto batch = TranslatingOracleErrors(what, [&] { return cursor->Fetch(1); });
    cursor->Close();
    if (batch.rows.empty() || batch.rows[0].empty()) {
        throw IOException("%s returned no row", what);
    }
    if (!batch.rows[0][0]) {
        return {};
    }
    const auto &column = cursor->Columns()[0];
    if (column.oracle_type == 2) {
        return TranslatingOracleErrors(what, [&] { return oracle_scanner::DecodeOracleNumber(*batch.rows[0][0]); });
    }
    return std::string(batch.rows[0][0]->begin(), batch.rows[0][0]->end());
}

// ORA-01466 is what a flashback read gives back when the snapshot is at or
// before a change to the table's definition, which is what happens to anyone
// who tries this on a table they just created. The server's own wording says
// nothing about the SCN this scan chose, so it is worth saying.
[[noreturn]] void RethrowFlashbackFailure(const std::string &message, const char *what) {
    if (message.find("ORA-01466") != std::string::npos) {
        throw IOException("%s: the consistent snapshot this scan took is at or before a change to the table's "
                          "definition, so Oracle will not read the table as of it. A table created or altered moments "
                          "ago cannot be read as of an earlier moment; wait, or scan it without sharding. (%s)",
                          what, message);
    }
    throw IOException("%s: %s", what, message);
}

// The key bounds have to be exact integers, because a range boundary computed
// in floating point can fall between two keys and drop or duplicate a row.
int64_t IntegralKey(const std::string &text, const std::string &column_name, const char *which) {
    if (text.empty()) {
        throw BinderException("Oracle key column \"%s\" has no %s value; the table appears to be empty", column_name,
                              which);
    }
    try {
        size_t consumed = 0;
        const auto value = std::stoll(text, &consumed);
        if (consumed != text.size()) {
            throw std::invalid_argument("not integral");
        }
        return value;
    } catch (const std::exception &) {
        throw BinderException("Oracle key column \"%s\" has a non-integral %s value, so ranges cannot be split without "
                              "rounding a boundary between two keys",
                              column_name, which);
    }
}

unique_ptr<FunctionData> OracleParallelBind(ClientContext &context, TableFunctionBindInput &input,
                                            vector<LogicalType> &return_types, vector<string> &names) {
    if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull()) {
        throw BinderException("oracle_scan_parallel secret, table, and key column cannot be NULL");
    }
    auto result = make_uniq<OracleParallelBindData>();
    result->config = ConnectionFromSecret(context, input.inputs[0].GetValue<std::string>(), result->password);

    // Validated as identifiers rather than pasted: both go into a statement.
    const auto object_parts = TranslatingOracleErrors("oracle_scan_parallel table name is invalid", [&] {
        return oracle_scanner::SplitOracleCallableName(input.inputs[1].GetValue<std::string>());
    });
    if (object_parts.size() > 2) {
        throw BinderException("oracle_scan_parallel takes a table as TABLE or SCHEMA.TABLE");
    }
    std::string object;
    for (const auto &part : object_parts) {
        if (!object.empty()) {
            object += ".";
        }
        object += KeywordHelper::WriteQuoted(part, '"');
    }
    const auto key_parts = TranslatingOracleErrors("oracle_scan_parallel key column is invalid", [&] {
        return oracle_scanner::SplitOracleCallableName(input.inputs[2].GetValue<std::string>());
    });
    if (key_parts.size() != 1) {
        throw BinderException("oracle_scan_parallel takes one key column");
    }
    const auto &key_name = key_parts[0];
    const auto key = KeywordHelper::WriteQuoted(key_name, '"');

    idx_t shards = 0;
    for (const auto &parameter : input.named_parameters) {
        if (StringUtil::CIEquals(parameter.first, "shards")) {
            const auto requested = BigIntValue::Get(parameter.second);
            if (requested < 1 || static_cast<idx_t>(requested) > MAX_SHARDS) {
                throw BinderException("oracle_scan_parallel shards must be between 1 and %llu",
                                      static_cast<uint64_t>(MAX_SHARDS));
            }
            shards = static_cast<idx_t>(requested);
        } else {
            throw BinderException("oracle_scan_parallel does not accept parameter '%s'", parameter.first);
        }
    }
    if (shards == 0) {
        shards = MinValue<idx_t>(MAX_SHARDS, MaxValue<idx_t>(1, context.db->NumberOfThreads()));
    }

    auto session = OpenOracleSession(result->config, result->password);
    // One system change number, taken before any shard reads anything. Every
    // shard is pinned to it, so together they are one snapshot rather than
    // several moments. If the database will not give one out, that is a
    // refusal: a silently unpinned parallel scan is a wrong answer that looks
    // like a right one.
    std::string scn;
    try {
        scn = ScalarOf(*session, "SELECT dbms_flashback.get_system_change_number AS scn FROM dual",
                       "oracle_scan_parallel could not read the current system change number");
    } catch (const std::exception &error) {
        throw BinderException(
            "oracle_scan_parallel needs a consistent snapshot and could not take one: %s. It reads "
            "DBMS_FLASHBACK.GET_SYSTEM_CHANGE_NUMBER, which needs EXECUTE on SYS.DBMS_FLASHBACK, and each shard then "
            "reads AS OF SCN, which needs FLASHBACK on the table.",
            error.what());
    }
    (void)IntegralKey(scn, "SCN", "current");
    const auto as_of = object + " AS OF SCN " + scn;

    // The describe of a row-free query is what names the columns, so the shards
    // and DuckDB agree on the shape without a dictionary round trip.
    try {
        auto cursor = session->Query("SELECT * FROM " + as_of + " WHERE 1 = 0", {});
        result->columns = cursor->Columns();
        cursor->Close();
    } catch (const std::exception &error) {
        RethrowFlashbackFailure(error.what(), "oracle_scan_parallel could not describe the table");
    }
    if (result->columns.empty()) {
        throw BinderException("oracle_scan_parallel found no columns on '%s'", input.inputs[1].GetValue<std::string>());
    }
    const OracleColumn *key_column = nullptr;
    for (const auto &column : result->columns) {
        if (column.name == key_name) {
            key_column = &column;
        }
    }
    if (!key_column) {
        throw BinderException("Oracle table has no column \"%s\" to shard on", key_name);
    }
    if (key_column->oracle_type != 2) {
        throw BinderException("Oracle key column \"%s\" is not NUMBER; only a numeric key can be split into ranges",
                              key_name);
    }

    const auto bounds_sql = "SELECT MIN(" + key + ") AS lo, MAX(" + key + ") AS hi, COUNT(*) - COUNT(" + key +
                            ") AS nulls FROM " + as_of;
    std::string low_text;
    std::string high_text;
    std::string null_text;
    {
        auto cursor = TranslatingOracleErrors("oracle_scan_parallel could not read the key range",
                                              [&] { return session->Query(bounds_sql, {}); });
        const auto batch = TranslatingOracleErrors("oracle_scan_parallel could not read the key range",
                                                    [&] { return cursor->Fetch(1); });
        cursor->Close();
        if (batch.rows.empty() || batch.rows[0].size() < 3) {
            throw IOException("Oracle returned no key range for '%s'", input.inputs[1].GetValue<std::string>());
        }
        const auto decode = [&](const std::optional<std::vector<uint8_t>> &wire) {
            return wire ? TranslatingOracleErrors("oracle_scan_parallel could not decode the key range",
                                                  [&] { return oracle_scanner::DecodeOracleNumber(*wire); })
                        : std::string();
        };
        low_text = decode(batch.rows[0][0]);
        high_text = decode(batch.rows[0][1]);
        null_text = decode(batch.rows[0][2]);
    }
    session->Close();

    const auto low = IntegralKey(low_text, key_name, "minimum");
    const auto high = IntegralKey(high_text, key_name, "maximum");
    if (high < low) {
        throw BinderException("Oracle key column \"%s\" has a maximum below its minimum", key_name);
    }

    std::string select_list;
    for (const auto &column : result->columns) {
        RequireReadableColumn(column);
        if (!select_list.empty()) {
            select_list += ", ";
        }
        select_list += KeywordHelper::WriteQuoted(column.name, '"');
    }

    // Ranges are half-open except the last, which closes on the maximum, so
    // every key belongs to exactly one shard.
    const auto span = static_cast<uint64_t>(high - low) + 1;
    if (static_cast<uint64_t>(shards) > span) {
        shards = static_cast<idx_t>(span);
    }
    for (idx_t shard = 0; shard < shards; shard++) {
        const auto begin = low + static_cast<int64_t>(span * shard / shards);
        const auto end = low + static_cast<int64_t>(span * (shard + 1) / shards) - 1;
        auto predicate = key + " >= " + std::to_string(begin) + " AND " + key + " <= " + std::to_string(end);
        result->shard_sql.push_back("SELECT " + select_list + " FROM " + as_of + " WHERE " + predicate);
    }
    // A NULL key is in no range, and dropping those rows would make this scan
    // quietly return fewer rows than the table has.
    if (!null_text.empty() && null_text != "0") {
        result->shard_sql.push_back("SELECT " + select_list + " FROM " + as_of + " WHERE " + key + " IS NULL");
    }

    std::unordered_set<std::string> used_names;
    for (idx_t index = 0; index < result->columns.size(); index++) {
        names.push_back(OutputName(result->columns[index], index, used_names));
        result->types.push_back(TypeFor(result->columns[index]));
    }
    for (const auto &type : result->types) {
        return_types.push_back(type);
    }
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> OracleParallelInitGlobal(ClientContext &, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<OracleParallelBindData>();
    return make_uniq<OracleParallelGlobalState>(bind.shard_sql.size());
}

unique_ptr<LocalTableFunctionState> OracleParallelInitLocal(ExecutionContext &, TableFunctionInitInput &,
                                                            GlobalTableFunctionState *) {
    // The session is opened when the thread takes its first shard, so a thread
    // DuckDB never schedules costs no connection.
    return make_uniq<OracleParallelLocalState>();
}

void OracleParallelFunction(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
    const auto &bind = input.bind_data->Cast<OracleParallelBindData>();
    auto &global_state = input.global_state->Cast<OracleParallelGlobalState>();
    auto &local_state = input.local_state->Cast<OracleParallelLocalState>();
    while (!local_state.finished) {
        if (!local_state.cursor) {
            const auto shard = global_state.next_shard.fetch_add(1);
            if (shard >= bind.shard_sql.size()) {
                local_state.finished = true;
                break;
            }
            try {
                if (!local_state.session) {
                    local_state.session = AcquireOracleReadSession(context, std::string(), std::string(), bind.config,
                                                                   bind.password);
                }
                local_state.cursor = local_state.session->Query(bind.shard_sql[shard], {});
            } catch (const std::exception &error) {
                local_state.session.Poison();
                RethrowFlashbackFailure(error.what(), "oracle_scan_parallel could not open a shard");
            }
        }
        const auto batch = TranslatingOracleErrors("oracle_scan_parallel could not fetch from Oracle", [&] {
            try {
                return local_state.cursor->Fetch(STANDARD_VECTOR_SIZE);
            } catch (...) {
                local_state.session.Poison();
                throw;
            }
        });
        for (idx_t row_index = 0; row_index < batch.rows.size(); row_index++) {
            const auto &row = batch.rows[row_index];
            if (row.size() != bind.columns.size()) {
                throw IOException("Oracle returned %llu values for %llu described columns",
                                  static_cast<uint64_t>(row.size()), static_cast<uint64_t>(bind.columns.size()));
            }
            for (idx_t column_index = 0; column_index < bind.columns.size(); column_index++) {
                output.SetValue(column_index, row_index,
                                TranslatingOracleErrors("oracle_scan_parallel could not convert an Oracle value", [&] {
                                    return ValueFor(bind.columns[column_index], row[column_index]);
                                }));
            }
        }
        output.SetCardinality(batch.rows.size());
        if (batch.exhausted) {
            local_state.cursor->Close();
            local_state.cursor.reset();
        }
        if (!batch.rows.empty()) {
            return;
        }
    }
    output.SetCardinality(0);
}

} // namespace

void RegisterOracleParallelScan(ExtensionLoader &loader) {
    TableFunction function("oracle_scan_parallel",
                           {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
                           OracleParallelFunction, OracleParallelBind, OracleParallelInitGlobal,
                           OracleParallelInitLocal);
    function.named_parameters["shards"] = LogicalType::BIGINT;
    loader.RegisterFunction(function);
}

} // namespace duckdb

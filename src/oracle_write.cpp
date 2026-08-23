// Writing to an attached Oracle table: the transaction-pinned session, the
// value-to-bind conversion, and the INSERT operator.
//
// Two rules shape all of it. First, a write and its COMMIT must happen on one
// Oracle session, because Oracle's transaction is a property of the session and
// nothing else; so the session is pinned to the DuckDB transaction rather than
// to the statement, which is what every read still does. Second, the Oracle
// column type decides how a value is encoded — never the DuckDB type alone —
// because handing Oracle a string for it to convert makes the result depend on
// NLS_NUMERIC_CHARACTERS or NLS_DATE_FORMAT, session settings this client does
// not negotiate.

#include "oracle_adapter.hpp"

#include "duckdb/execution/physical_operator.hpp"
#include "duckdb/execution/physical_plan_generator.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_state.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/common/exception/conversion_exception.hpp"
#include "duckdb/common/types/time.hpp"
#include "duckdb/planner/expression/bound_reference_expression.hpp"
#include "duckdb/common/types/column/column_data_collection.hpp"
#include "duckdb/planner/operator/logical_delete.hpp"
#include "duckdb/planner/operator/logical_insert.hpp"
#include "duckdb/planner/operator/logical_update.hpp"

#include "oracle_scanner/session_factory.hpp"

#include <cmath>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace duckdb {

using oracle_scanner::BindDirection;
using oracle_scanner::OracleBind;
using oracle_scanner::OpenOracleSession;

namespace {

// One pinned session per attached Oracle catalog, for the life of the DuckDB
// transaction. In autocommit each statement is its own transaction, so this
// opens and commits one session per statement, which is what the read path
// already does per scan.
struct OracleWriteState final : ClientContextState {
    std::mutex lock;
    // Shared rather than owned outright because a read in the same transaction
    // borrows it, and a write that fails discards it while that read may still
    // hold an open cursor on it. The last user decides when it dies.
    std::unordered_map<std::string, std::shared_ptr<OracleSession>> pinned;

    OracleSession &Pin(const OracleWriteTarget &target) {
        std::lock_guard<std::mutex> guard(lock);
        const auto existing = pinned.find(target.catalog_name);
        if (existing != pinned.end()) {
            return *existing->second;
        }
        auto session = TranslatingOracleErrors("Oracle write could not open a session", [&] {
            return std::shared_ptr<OracleSession>(OpenOracleSession(target.config, target.password));
        });
        auto &reference = *session;
        pinned.emplace(target.catalog_name, std::move(session));
        return reference;
    }

    void Discard(const std::string &catalog_name) noexcept {
        std::shared_ptr<OracleSession> session;
        {
            std::lock_guard<std::mutex> guard(lock);
            const auto entry = pinned.find(catalog_name);
            if (entry == pinned.end()) {
                return;
            }
            session = std::move(entry->second);
            pinned.erase(entry);
        }
        // Never let a failed cleanup escape: this runs from a failure path and
        // from DuckDB's rollback notification, neither of which can take one.
        try {
            session->Rollback();
        } catch (...) {
        }
        try {
            session->Close();
        } catch (...) {
        }
    }

    std::vector<std::shared_ptr<OracleSession>> TakeAll() noexcept {
        std::lock_guard<std::mutex> guard(lock);
        std::vector<std::shared_ptr<OracleSession>> sessions;
        sessions.reserve(pinned.size());
        for (auto &entry : pinned) {
            sessions.push_back(std::move(entry.second));
        }
        pinned.clear();
        return sessions;
    }

    // DuckDB has already committed its own side by the time this runs, so a
    // failing Oracle COMMIT is reported to the user with Oracle's own error and
    // Oracle's own transaction is what did not happen. Oracle is the only
    // durable store here, so there is nothing else to undo.
    void TransactionCommit(MetaTransaction &, ClientContext &) override {
        auto sessions = TakeAll();
        for (auto &session : sessions) {
            TranslatingOracleErrors("Oracle write could not commit", [&] {
                session->Commit();
                return 0;
            });
            try {
                session->Close();
            } catch (...) {
            }
        }
    }

    void TransactionRollback(MetaTransaction &, ClientContext &) override {
        RollbackAll();
    }

    void TransactionRollback(MetaTransaction &, ClientContext &, optional_ptr<ErrorData>) override {
        RollbackAll();
    }

    void RollbackAll() noexcept {
        auto sessions = TakeAll();
        for (auto &session : sessions) {
            try {
                session->Rollback();
            } catch (...) {
            }
            try {
                session->Close();
            } catch (...) {
            }
        }
    }
};

OracleWriteState &WriteStateFor(ClientContext &context) {
    return *context.registered_state->GetOrCreate<OracleWriteState>("oracle_scanner.write_state");
}

// Two different refusals, deliberately. A shape this version does not support
// is NotImplementedException; a value that simply cannot be that Oracle type is
// a conversion error, and calling it "not implemented" would suggest the value
// might work in a later version when it never can.
[[noreturn]] void RefuseBind(const OracleColumn &column, const Value &value, const std::string &reason) {
    throw NotImplementedException("Oracle column \"%s\" cannot take a %s value: %s", column.name,
                                  value.type().ToString(), reason);
}

[[noreturn]] void RefuseValue(const OracleColumn &column, const std::string &reason) {
    throw ConversionException("Oracle column \"%s\" cannot take this value: %s", column.name, reason);
}

// The codecs report a value they cannot represent as a ProtocolError, which is
// the transport layer's vocabulary; at this boundary it is the user's value
// that is wrong, not the connection.
template <class FUNCTION>
auto EncodingFor(const OracleColumn &column, FUNCTION function) -> decltype(function()) {
    try {
        return function();
    } catch (const oracle_scanner::ProtocolError &error) {
        RefuseValue(column, error.what());
    }
}

// Parses a value DuckDB is carrying as text back into a date or timestamp.
// Our own DATE and TIMESTAMP columns arrive as VARCHAR because that is how they
// are read today, so a row copied out of Oracle and back in goes through here.
// DuckDB's parser is ISO and NLS-independent, which is the whole point.
oracle_scanner::OracleDateTime DateTimeFromValue(const Value &value, const OracleColumn &column) {
    timestamp_t timestamp;
    // Oracle keeps nanoseconds and DuckDB's timestamp_t keeps microseconds, so
    // the sub-microsecond part is carried separately rather than truncated on
    // the way back into a column it came out of.
    int64_t extra_nanoseconds = 0;
    if (value.type().id() == LogicalTypeId::VARCHAR) {
        const auto text = value.GetValue<std::string>();
        timestamp_ns_t parsed;
        if (Timestamp::TryConvertTimestamp(text.c_str(), text.size(), parsed) != TimestampCastResult::SUCCESS) {
            RefuseValue(column, "'" + text + "' is not an ISO date or timestamp");
        }
        auto microseconds = parsed.value / 1000;
        auto remainder = parsed.value % 1000;
        if (remainder < 0) {
            // Truncating division rounds toward zero, which for a pre-1970
            // value would put the remainder on the wrong side of the second.
            remainder += 1000;
            microseconds -= 1;
        }
        timestamp = timestamp_t(microseconds);
        extra_nanoseconds = remainder;
    } else if (value.type().id() == LogicalTypeId::DATE) {
        timestamp = Timestamp::FromDatetime(value.GetValue<date_t>(), dtime_t(0));
    } else if (value.type().id() == LogicalTypeId::TIMESTAMP) {
        timestamp = value.GetValue<timestamp_t>();
    } else if (value.type().id() == LogicalTypeId::TIMESTAMP_NS) {
        // The type an Oracle TIMESTAMP(7..9) column reads back as, so a row
        // copied out and written back keeps every digit it started with.
        const auto nanoseconds = value.GetValue<timestamp_ns_t>().value;
        auto microseconds = nanoseconds / 1000;
        auto remainder = nanoseconds % 1000;
        if (remainder < 0) {
            remainder += 1000;
            microseconds -= 1;
        }
        timestamp = timestamp_t(microseconds);
        extra_nanoseconds = remainder;
    } else {
        RefuseBind(column, value,
                   "only DATE, TIMESTAMP, TIMESTAMP_NS and ISO text can be written to a date or timestamp column");
    }
    if (!Timestamp::IsFinite(timestamp)) {
        RefuseValue(column, "Oracle has no infinite date");
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
    oracle_scanner::OracleDateTime result;
    result.year = year;
    result.month = static_cast<uint8_t>(month);
    result.day = static_cast<uint8_t>(day);
    result.hour = static_cast<uint8_t>(hour);
    result.minute = static_cast<uint8_t>(minute);
    result.second = static_cast<uint8_t>(second);
    result.nanosecond = static_cast<uint32_t>(microseconds) * 1000U + static_cast<uint32_t>(extra_nanoseconds);
    return result;
}

} // namespace

OracleBind OracleBindForColumn(const Value &value, const OracleColumn &column, const std::string &name) {
    // A column this client cannot read is one it cannot reason about writing
    // either, and it refuses with the type named.
    RequireReadableColumn(column);
    OracleBind bind;
    bind.name = name;
    bind.oracle_type = column.oracle_type;
    bind.direction = BindDirection::BIND_IN;
    if (value.IsNull()) {
        return bind;
    }
    const auto type = value.type().id();
    switch (column.oracle_type) {
    case 1:   // VARCHAR2
    case 96: { // CHAR
        if (type != LogicalTypeId::VARCHAR) {
            RefuseBind(column, value, "a character column takes VARCHAR");
        }
        const auto text = value.GetValue<std::string>();
        if (text.empty()) {
            // Oracle stores an empty string as NULL, and this client reads it
            // back as NULL. Binding it explicitly says the same thing rather
            // than relying on the server to make the substitution.
            return bind;
        }
        bind.value = std::vector<uint8_t>(text.begin(), text.end());
        return bind;
    }
    case 2: { // NUMBER
        if (type == LogicalTypeId::VARCHAR) {
            // An unconstrained or fractional NUMBER is read as decimal text, so
            // this is the round trip of our own read. The codec parses the text
            // exactly and rejects anything that is not a decimal number.
            const auto text = value.GetValue<std::string>();
            bind.value = EncodingFor(column, [&] { return oracle_scanner::EncodeOracleNumber(text); });
            return bind;
        }
        if (!value.type().IsNumeric()) {
            RefuseBind(column, value, "a NUMBER column takes a numeric or decimal-text value");
        }
        if (type == LogicalTypeId::FLOAT || type == LogicalTypeId::DOUBLE) {
            // Going through binary floating point would round the value on its
            // way into an exact decimal column.
            RefuseBind(column, value, "FLOAT and DOUBLE are not exact; cast to DECIMAL or VARCHAR first");
        }
        bind.value = EncodingFor(column, [&] { return oracle_scanner::EncodeOracleNumber(value.ToString()); });
        return bind;
    }
    case 12: { // DATE
        bind.value = EncodingFor(column, [&] { return oracle_scanner::EncodeOracleDate(DateTimeFromValue(value, column)); });
        return bind;
    }
    case 180: { // TIMESTAMP
        bind.value = EncodingFor(
            column, [&] { return oracle_scanner::EncodeOracleTimestamp(DateTimeFromValue(value, column), false); });
        return bind;
    }
    case 181:
        // Readable because the value carries its own offset, but nothing on the
        // DuckDB side of this mapping carries one to write back.
        RefuseBind(column, value,
                   "TIMESTAMP WITH TIME ZONE cannot be written until the type mapping carries an offset");
    case 23: { // RAW
        if (type != LogicalTypeId::BLOB) {
            RefuseBind(column, value, "a RAW column takes BLOB");
        }
        const auto bytes = StringValue::Get(value);
        bind.value = std::vector<uint8_t>(bytes.begin(), bytes.end());
        return bind;
    }
    case 100: { // BINARY_FLOAT
        if (type != LogicalTypeId::FLOAT) {
            RefuseBind(column, value, "a BINARY_FLOAT column takes FLOAT");
        }
        const auto number = value.GetValue<float>();
        if (!std::isfinite(number)) {
            RefuseValue(column, "Oracle BINARY_FLOAT has no infinity in this codec");
        }
        bind.value = oracle_scanner::EncodeOracleBinaryFloat(number);
        return bind;
    }
    case 101: { // BINARY_DOUBLE
        if (type != LogicalTypeId::DOUBLE) {
            RefuseBind(column, value, "a BINARY_DOUBLE column takes DOUBLE");
        }
        const auto number = value.GetValue<double>();
        if (!std::isfinite(number)) {
            RefuseValue(column, "Oracle BINARY_DOUBLE has no infinity in this codec");
        }
        bind.value = oracle_scanner::EncodeOracleBinaryDouble(number);
        return bind;
    }
    default:
        break;
    }
    RefuseBind(column, value, "Oracle type " + std::to_string(column.oracle_type) + " cannot be written");
}

OracleSession &TransactionSession(ClientContext &context, const OracleWriteTarget &target) {
    return WriteStateFor(context).Pin(target);
}

std::shared_ptr<OracleSession> TryTransactionSession(ClientContext &context, const std::string &catalog_name) {
    auto &state = WriteStateFor(context);
    std::lock_guard<std::mutex> guard(state.lock);
    const auto pinned = state.pinned.find(catalog_name);
    if (pinned == state.pinned.end()) {
        return nullptr;
    }
    return pinned->second;
}

void PoisonTransactionSession(ClientContext &context, const std::string &catalog_name) noexcept {
    try {
        WriteStateFor(context).Discard(catalog_name);
    } catch (...) {
    }
}

// Oracle's ROWID has its own wire type and no decoder here. Selecting it
// through ROWIDTOCHAR makes it an ordinary VARCHAR2 both ways: the scan reads a
// string, and CHARTOROWID turns that string back into the row address Oracle
// addresses the UPDATE or DELETE by. It is the cheapest stable row identity
// Oracle offers, and unlike a primary key it exists on every table.
const char *const ORACLE_ROWID_EXPRESSION = "ROWIDTOCHAR(ROWID)";
const char *const ORACLE_ROWID_COLUMN_NAME = "rowid";

OracleColumn OracleRowIdColumn() {
    OracleColumn column;
    column.name = ORACLE_ROWID_COLUMN_NAME;
    column.oracle_type = 1; // VARCHAR2
    column.character_set_form = 1;
    column.nullable = false;
    return column;
}

namespace {

class OracleInsertGlobalState final : public GlobalSinkState {
public:
    uint64_t inserted_rows = 0;
    // Filled only for RETURNING: the table rows as Oracle made them, which is
    // the whole point — a DEFAULT, a sequence or a trigger is exactly what the
    // caller could not have known before the insert.
    unique_ptr<ColumnDataCollection> returned;
};

class OracleInsertSourceState final : public GlobalSourceState {
public:
    bool emitted = false;
    ColumnDataScanState scan;
    bool scan_started = false;
};

// Not a parallel sink: one Oracle session carries the transaction, and one TTC
// channel carries one statement at a time.
class OracleInsertOperator final : public PhysicalOperator {
public:
    OracleInsertOperator(PhysicalPlan &physical_plan, vector<LogicalType> types, idx_t estimated_cardinality,
                         OracleWriteTarget target_p, std::string sql_p, std::vector<idx_t> source_indexes_p,
                         std::vector<OracleColumn> bound_columns_p, std::vector<OracleColumn> returned_columns_p)
        : PhysicalOperator(physical_plan, PhysicalOperatorType::EXTENSION, std::move(types), estimated_cardinality),
          target(std::move(target_p)), sql(std::move(sql_p)), source_indexes(std::move(source_indexes_p)),
          bound_columns(std::move(bound_columns_p)), returned_columns(std::move(returned_columns_p)) {
    }

    string GetName() const override {
        return "ORACLE_INSERT";
    }

    bool IsSink() const override {
        return true;
    }

    bool IsSource() const override {
        return true;
    }

    unique_ptr<GlobalSinkState> GetGlobalSinkState(ClientContext &context) const override {
        auto state = make_uniq<OracleInsertGlobalState>();
        if (!returned_columns.empty()) {
            state->returned = make_uniq<ColumnDataCollection>(context, types);
        }
        return std::move(state);
    }

    unique_ptr<GlobalSourceState> GetGlobalSourceState(ClientContext &) const override {
        return make_uniq<OracleInsertSourceState>();
    }

    SinkResultType Sink(ExecutionContext &context, DataChunk &chunk, OperatorSinkInput &input) const override {
        auto &global_state = input.global_state.Cast<OracleInsertGlobalState>();
        if (chunk.size() == 0) {
            return SinkResultType::NEED_MORE_INPUT;
        }
        chunk.Flatten();
        if (!returned_columns.empty()) {
            return SinkReturning(context, chunk, global_state);
        }
        std::vector<std::vector<OracleBind>> rows;
        rows.reserve(chunk.size());
        for (idx_t row_index = 0; row_index < chunk.size(); row_index++) {
            std::vector<OracleBind> binds;
            binds.reserve(source_indexes.size());
            for (idx_t column_index = 0; column_index < source_indexes.size(); column_index++) {
                binds.push_back(OracleBindForColumn(chunk.GetValue(source_indexes[column_index], row_index),
                                                    bound_columns[column_index], std::to_string(column_index + 1)));
            }
            rows.push_back(std::move(binds));
        }
        // A failed write leaves this session in a state we cannot classify from
        // here: an ORA- error and a transport failure reach the adapter as the
        // same exception. Discarding the session is the conservative reading of
        // both, and it discards exactly the uncommitted work a rollback would.
        try {
            auto &session = TransactionSession(context.client, target);
            global_state.inserted_rows += TranslatingOracleErrors(
                "Oracle could not insert", [&] { return session.ExecuteBatch(sql, rows); });
        } catch (...) {
            PoisonTransactionSession(context.client, target.catalog_name);
            throw;
        }
        return SinkResultType::NEED_MORE_INPUT;
    }

    SourceResultType GetDataInternal(ExecutionContext &, DataChunk &chunk, OperatorSourceInput &input) const override {
        auto &source_state = input.global_state.Cast<OracleInsertSourceState>();
        auto &global_state = sink_state->Cast<OracleInsertGlobalState>();
        if (global_state.returned) {
            if (!source_state.scan_started) {
                global_state.returned->InitializeScan(source_state.scan);
                source_state.scan_started = true;
            }
            global_state.returned->Scan(source_state.scan, chunk);
            return chunk.size() == 0 ? SourceResultType::FINISHED : SourceResultType::HAVE_MORE_OUTPUT;
        }
        if (source_state.emitted) {
            return SourceResultType::FINISHED;
        }
        source_state.emitted = true;
        chunk.SetCardinality(1);
        chunk.SetValue(0, 0, Value::BIGINT(NumericCast<int64_t>(global_state.inserted_rows)));
        return SourceResultType::FINISHED;
    }

private:
    // RETURNING runs one statement per row: Oracle's array form of it has no
    // capture-backed evidence here, and guessing at the shape of an array OUT
    // bind would put wrong values in front of the caller rather than fail.
    SinkResultType SinkReturning(ExecutionContext &context, DataChunk &chunk,
                                 OracleInsertGlobalState &global_state) const {
        DataChunk row_chunk;
        row_chunk.Initialize(Allocator::DefaultAllocator(), types);
        for (idx_t row_index = 0; row_index < chunk.size(); row_index++) {
            std::vector<OracleBind> binds;
            binds.reserve(source_indexes.size() + returned_columns.size());
            for (idx_t column_index = 0; column_index < source_indexes.size(); column_index++) {
                binds.push_back(OracleBindForColumn(chunk.GetValue(source_indexes[column_index], row_index),
                                                    bound_columns[column_index], std::to_string(column_index + 1)));
            }
            for (idx_t column_index = 0; column_index < returned_columns.size(); column_index++) {
                OracleBind output;
                output.name = "r" + std::to_string(column_index + 1);
                output.oracle_type = returned_columns[column_index].oracle_type;
                output.direction = BindDirection::BIND_OUT;
                output.maximum_bytes = 32767;
                binds.push_back(std::move(output));
            }
            std::vector<OracleBind> values;
            try {
                auto &session = TransactionSession(context.client, target);
                values = TranslatingOracleErrors("Oracle could not insert",
                                                 [&] { return session.ExecuteReturning(sql, binds); });
            } catch (...) {
                PoisonTransactionSession(context.client, target.catalog_name);
                throw;
            }
            if (values.size() != returned_columns.size()) {
                throw InternalException("Oracle RETURNING produced %llu values for %llu columns",
                                        static_cast<uint64_t>(values.size()),
                                        static_cast<uint64_t>(returned_columns.size()));
            }
            const auto row = row_chunk.size();
            for (idx_t column_index = 0; column_index < returned_columns.size(); column_index++) {
                row_chunk.SetValue(column_index, row,
                                   TranslatingOracleErrors("Oracle could not convert a RETURNING value", [&] {
                                       return ValueFor(returned_columns[column_index], values[column_index].value);
                                   }));
            }
            row_chunk.SetCardinality(row + 1);
            global_state.inserted_rows++;
            if (row_chunk.size() == STANDARD_VECTOR_SIZE) {
                global_state.returned->Append(row_chunk);
                row_chunk.Reset();
            }
        }
        if (row_chunk.size() != 0) {
            global_state.returned->Append(row_chunk);
        }
        return SinkResultType::NEED_MORE_INPUT;
    }

    OracleWriteTarget target;
    std::string sql;
    // Where in the incoming chunk each bound column's value sits, and which
    // Oracle column it is going into. The two are parallel by construction.
    std::vector<idx_t> source_indexes;
    std::vector<OracleColumn> bound_columns;
    //! Empty unless the statement has RETURNING; then the table's columns, in
    //! order, which is the shape DuckDB evaluates the RETURNING list over.
    std::vector<OracleColumn> returned_columns;
};

// UPDATE and DELETE share everything but how a row's binds are built: both send
// one statement per row, addressed by that row's ROWID, and both count what
// Oracle says they changed.
class OracleRowIdWriteOperator : public PhysicalOperator {
public:
    OracleRowIdWriteOperator(PhysicalPlan &physical_plan, vector<LogicalType> types, idx_t estimated_cardinality,
                             OracleWriteTarget target_p, std::string sql_p)
        : PhysicalOperator(physical_plan, PhysicalOperatorType::EXTENSION, std::move(types), estimated_cardinality),
          target(std::move(target_p)), sql(std::move(sql_p)) {
    }

    bool IsSink() const override {
        return true;
    }

    bool IsSource() const override {
        return true;
    }

    unique_ptr<GlobalSinkState> GetGlobalSinkState(ClientContext &) const override {
        return make_uniq<OracleInsertGlobalState>();
    }

    unique_ptr<GlobalSourceState> GetGlobalSourceState(ClientContext &) const override {
        return make_uniq<OracleInsertSourceState>();
    }

    SinkResultType Sink(ExecutionContext &context, DataChunk &chunk, OperatorSinkInput &input) const override {
        auto &global_state = input.global_state.Cast<OracleInsertGlobalState>();
        if (chunk.size() == 0) {
            return SinkResultType::NEED_MORE_INPUT;
        }
        chunk.Flatten();
        // PhysicalUpdate and PhysicalDelete both put the row identity last, and
        // reading it from the chunk keeps this independent of how wide the
        // projection above happened to be.
        const auto rowid_index = chunk.ColumnCount() - 1;
        std::vector<std::vector<OracleBind>> rows;
        rows.reserve(chunk.size());
        for (idx_t row_index = 0; row_index < chunk.size(); row_index++) {
            auto binds = LeadingBinds(chunk, row_index);
            const auto rowid = chunk.GetValue(rowid_index, row_index);
            if (rowid.IsNull()) {
                // Every scanned Oracle row has one, so this means the plan did
                // not carry the identity the statement addresses rows by.
                throw InternalException("Oracle row identity is missing for a row of \"%s\"", target.object_name);
            }
            binds.push_back(OracleBindForColumn(rowid, OracleRowIdColumn(), std::to_string(binds.size() + 1)));
            rows.push_back(std::move(binds));
        }
        try {
            auto &session = TransactionSession(context.client, target);
            global_state.inserted_rows +=
                TranslatingOracleErrors(FailureMessage(), [&] { return session.ExecuteBatch(sql, rows); });
        } catch (...) {
            PoisonTransactionSession(context.client, target.catalog_name);
            throw;
        }
        return SinkResultType::NEED_MORE_INPUT;
    }

    SourceResultType GetDataInternal(ExecutionContext &, DataChunk &chunk, OperatorSourceInput &input) const override {
        auto &source_state = input.global_state.Cast<OracleInsertSourceState>();
        if (source_state.emitted) {
            return SourceResultType::FINISHED;
        }
        source_state.emitted = true;
        auto &global_state = sink_state->Cast<OracleInsertGlobalState>();
        chunk.SetCardinality(1);
        chunk.SetValue(0, 0, Value::BIGINT(NumericCast<int64_t>(global_state.inserted_rows)));
        return SourceResultType::FINISHED;
    }

protected:
    //! The binds that come before the row identity, empty for a DELETE.
    virtual std::vector<OracleBind> LeadingBinds(DataChunk &chunk, idx_t row_index) const = 0;
    virtual const char *FailureMessage() const = 0;

    OracleWriteTarget target;
    std::string sql;
};

class OracleDeleteOperator final : public OracleRowIdWriteOperator {
public:
    using OracleRowIdWriteOperator::OracleRowIdWriteOperator;

    string GetName() const override {
        return "ORACLE_DELETE";
    }

protected:
    std::vector<OracleBind> LeadingBinds(DataChunk &, idx_t) const override {
        return {};
    }

    const char *FailureMessage() const override {
        return "Oracle could not delete";
    }
};

class OracleUpdateOperator final : public OracleRowIdWriteOperator {
public:
    OracleUpdateOperator(PhysicalPlan &physical_plan, vector<LogicalType> types, idx_t estimated_cardinality,
                         OracleWriteTarget target_p, std::string sql_p, std::vector<idx_t> source_indexes_p,
                         std::vector<OracleColumn> set_columns_p)
        : OracleRowIdWriteOperator(physical_plan, std::move(types), estimated_cardinality, std::move(target_p),
                                   std::move(sql_p)),
          source_indexes(std::move(source_indexes_p)), set_columns(std::move(set_columns_p)) {
    }

    string GetName() const override {
        return "ORACLE_UPDATE";
    }

protected:
    std::vector<OracleBind> LeadingBinds(DataChunk &chunk, idx_t row_index) const override {
        std::vector<OracleBind> binds;
        binds.reserve(source_indexes.size() + 1);
        for (idx_t index = 0; index < source_indexes.size(); index++) {
            binds.push_back(OracleBindForColumn(chunk.GetValue(source_indexes[index], row_index), set_columns[index],
                                                std::to_string(index + 1)));
        }
        return binds;
    }

    const char *FailureMessage() const override {
        return "Oracle could not update";
    }

private:
    // Parallel by construction: where each SET value sits in the chunk, and
    // which Oracle column it is going into.
    std::vector<idx_t> source_indexes;
    std::vector<OracleColumn> set_columns;
};

} // namespace

PhysicalOperator &PlanOracleInsert(ClientContext &, PhysicalPlanGenerator &planner, LogicalInsert &op,
                                   optional_ptr<PhysicalOperator> plan, const std::vector<OracleColumn> &columns,
                                   OracleWriteTarget target) {
    if (!plan) {
        throw NotImplementedException("Oracle INSERT requires a source of rows");
    }

    if (op.on_conflict_info.action_type != OnConflictAction::THROW) {
        // Oracle's MERGE is not this, and nothing here can prove the two agree.
        throw NotImplementedException("Oracle INSERT does not support ON CONFLICT");
    }
    // The columns the statement actually names. Columns the user left out are
    // left out of the statement too, so Oracle applies its own DEFAULT rather
    // than receiving an explicit NULL, which is a different thing entirely.
    std::vector<idx_t> source_indexes;
    std::vector<OracleColumn> bound_columns;
    std::string column_list;
    std::string value_list;
    for (auto &column : op.table.GetColumns().Physical()) {
        const auto position = column.Physical().index;
        if (position >= columns.size()) {
            throw InternalException("Oracle INSERT column %llu is outside the table's Oracle metadata", position);
        }
        idx_t source_index = position;
        if (!op.column_index_map.empty()) {
            const auto mapped = op.column_index_map[column.Physical()];
            if (mapped == DConstants::INVALID_INDEX) {
                continue;
            }
            source_index = mapped;
        }
        if (!column_list.empty()) {
            column_list += ", ";
            value_list += ", ";
        }
        column_list += KeywordHelper::WriteQuoted(columns[position].name, '"');
        value_list += ":" + std::to_string(bound_columns.size() + 1);
        source_indexes.push_back(source_index);
        bound_columns.push_back(columns[position]);
    }
    if (bound_columns.empty()) {
        throw NotImplementedException("Oracle INSERT needs at least one column");
    }
    auto sql = "INSERT INTO " + KeywordHelper::WriteQuoted(target.object_name, '"') + " (" + column_list +
              ") VALUES (" + value_list + ")";
    // RETURNING asks Oracle for the row it actually stored. Echoing back what
    // was sent would be wrong for exactly the cases the clause exists for: a
    // column left to its DEFAULT, a sequence, a trigger.
    std::vector<OracleColumn> returned_columns;
    if (op.return_chunk) {
        std::string returned_list;
        std::string into_list;
        for (auto &column : op.table.GetColumns().Physical()) {
            const auto position = column.Physical().index;
            if (position >= columns.size()) {
                throw InternalException("Oracle RETURNING column %llu is outside the table's Oracle metadata",
                                        static_cast<uint64_t>(position));
            }
            RequireReadableColumn(columns[position]);
            if (!returned_list.empty()) {
                returned_list += ", ";
                into_list += ", ";
            }
            returned_list += KeywordHelper::WriteQuoted(columns[position].name, '"');
            into_list += ":r" + std::to_string(returned_columns.size() + 1);
            returned_columns.push_back(columns[position]);
        }
        sql += " RETURNING " + returned_list + " INTO " + into_list;
    }
    auto &insert = planner.Make<OracleInsertOperator>(op.types, op.estimated_cardinality, std::move(target), sql,
                                                      std::move(source_indexes), std::move(bound_columns),
                                                      std::move(returned_columns));
    insert.children.push_back(*plan);
    return insert;
}

PhysicalOperator &PlanOracleDelete(ClientContext &, PhysicalPlanGenerator &planner, LogicalDelete &op,
                                   PhysicalOperator &plan, OracleWriteTarget target) {
    if (op.return_chunk) {
        throw NotImplementedException("Oracle DELETE does not support RETURNING yet");
    }
    const auto sql = "DELETE FROM " + KeywordHelper::WriteQuoted(target.object_name, '"') + " WHERE ROWID = " +
                     "CHARTOROWID(:1)";
    auto &deletion = planner.Make<OracleDeleteOperator>(op.types, op.estimated_cardinality, std::move(target), sql);
    deletion.children.push_back(plan);
    return deletion;
}

PhysicalOperator &PlanOracleUpdate(ClientContext &, PhysicalPlanGenerator &planner, LogicalUpdate &op,
                                   PhysicalOperator &plan, const std::vector<OracleColumn> &columns,
                                   OracleWriteTarget target) {
    if (op.return_chunk) {
        throw NotImplementedException("Oracle UPDATE does not support RETURNING yet");
    }
    if (op.columns.size() != op.expressions.size()) {
        throw InternalException("Oracle UPDATE received %llu columns for %llu expressions",
                               static_cast<uint64_t>(op.columns.size()),
                               static_cast<uint64_t>(op.expressions.size()));
    }
    std::vector<idx_t> source_indexes;
    std::vector<OracleColumn> set_columns;
    std::string assignments;
    for (idx_t index = 0; index < op.columns.size(); index++) {
        const auto position = op.columns[index].index;
        if (position >= columns.size()) {
            throw InternalException("Oracle UPDATE column %llu is outside the table's Oracle metadata",
                                    static_cast<uint64_t>(position));
        }
        if (!assignments.empty()) {
            assignments += ", ";
        }
        assignments += KeywordHelper::WriteQuoted(columns[position].name, '"') + " = ";
        if (op.expressions[index]->GetExpressionType() == ExpressionType::VALUE_DEFAULT) {
            // Oracle's own DEFAULT for the column, which is the right answer and
            // not the same as the NULL this catalog would otherwise supply: it
            // does not read DATA_DEFAULT from the dictionary.
            assignments += "DEFAULT";
            continue;
        }
        if (op.expressions[index]->GetExpressionType() != ExpressionType::BOUND_REF) {
            throw NotImplementedException("Oracle UPDATE cannot evaluate this SET expression");
        }
        assignments += ":" + std::to_string(set_columns.size() + 1);
        source_indexes.push_back(op.expressions[index]->Cast<BoundReferenceExpression>().index);
        set_columns.push_back(columns[position]);
    }
    if (assignments.empty()) {
        throw NotImplementedException("Oracle UPDATE needs at least one column to set");
    }
    const auto sql = "UPDATE " + KeywordHelper::WriteQuoted(target.object_name, '"') + " SET " + assignments +
                     " WHERE ROWID = CHARTOROWID(:" + std::to_string(set_columns.size() + 1) + ")";
    auto &update = planner.Make<OracleUpdateOperator>(op.types, op.estimated_cardinality, std::move(target), sql,
                                                      std::move(source_indexes), std::move(set_columns));
    update.children.push_back(plan);
    return update;
}

} // namespace duckdb

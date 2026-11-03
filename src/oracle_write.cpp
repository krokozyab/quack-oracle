#include "oracle_io_deadline.hpp"
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
#include "oracle_scanner/temp_lob.hpp"
#include "duckdb/catalog/catalog.hpp"

#include <optional>
#include "duckdb/execution/operator/projection/physical_projection.hpp"
#include "duckdb/planner/expression/bound_cast_expression.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"

#include "duckdb/execution/physical_operator.hpp"
#include "duckdb/execution/physical_plan_generator.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_state.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/common/exception/conversion_exception.hpp"
#include "duckdb/common/types/decimal.hpp"
#include "duckdb/common/types/time.hpp"
#include "duckdb/planner/expression/bound_reference_expression.hpp"
#include "duckdb/common/types/column/column_data_collection.hpp"
#include "duckdb/planner/operator/logical_delete.hpp"
#include "duckdb/planner/operator/logical_insert.hpp"
#include "duckdb/planner/operator/logical_update.hpp"
#include "duckdb/transaction/transaction.hpp"

#include "oracle_scanner/oracle_vector.hpp"
#include "oracle_scanner/ttc_lob.hpp"
#include "oracle_scanner/session_factory.hpp"

#include <cmath>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace duckdb {

using oracle_scanner::BindDirection;
using oracle_scanner::OracleBind;
using oracle_scanner::OpenOracleSession;

namespace {

// One pinned session per attached Oracle catalog, for the life of the DuckDB
// transaction. In autocommit each statement is its own transaction, so each
// statement pins one session and ends it at its COMMIT; with the attached
// catalog's transaction pool that session is a reused one rather than a new
// connect, but it is still one session per transaction, never shared.
struct PinnedOracleSession {
    // Shared rather than owned outright because a read in the same transaction
    // borrows it, and a write that fails discards it while that read may still
    // hold an open cursor on it. The last user decides when it dies.
    std::shared_ptr<OracleSession> session;
    // The attached catalog's pool, when the session came from one. Weak, so a
    // catalog detached mid-transaction leaves this session to be closed.
    std::weak_ptr<oracle_scanner::OracleTransactionSessionPool> pool;
    bool pooled = false;
    // Set once the transaction ran something that can change the session's
    // own state beyond its transaction, such as a stored procedure. Such a
    // session ends closed rather than reused.
    bool tainted = false;
};

struct OracleWriteState final : ClientContextState {
    std::mutex lock;
    std::unordered_map<std::string, PinnedOracleSession> pinned;
    std::unordered_set<std::string> failed;
    std::unordered_map<std::string, OracleTransactionStatus> status;

    OracleSession &Pin(const OracleWriteTarget &target) {
        std::lock_guard<std::mutex> guard(lock);
        if (failed.count(target.catalog_name)) {
            throw TransactionException("Oracle transaction failed; ROLLBACK is required");
        }
        const auto existing = pinned.find(target.catalog_name);
        if (existing != pinned.end()) {
            return *existing->second.session;
        }
        PinnedOracleSession entry;
        if (target.pool) {
            // Leased before any of the transaction's statements; a reused
            // session has just answered its probe, and one that did not was
            // replaced without anything of this transaction being sent.
            entry.session = TranslatingOracleErrors("Oracle write could not open a session", [&] {
                return target.pool->Acquire(target.config.io_deadline);
            });
            entry.pool = target.pool;
            entry.pooled = true;
        } else {
            entry.session = TranslatingOracleErrors("Oracle write could not open a session", [&] {
                return std::shared_ptr<OracleSession>(OpenOracleSession(target.config, target.password));
            });
        }
        auto &reference = *entry.session;
        pinned.emplace(target.catalog_name, std::move(entry));
        status[target.catalog_name] = OracleTransactionStatus();
        status[target.catalog_name].connection_state = "active";
        return reference;
    }

    void Taint(const std::string &catalog_name) {
        std::lock_guard<std::mutex> guard(lock);
        const auto entry = pinned.find(catalog_name);
        if (entry != pinned.end()) {
            entry->second.tainted = true;
        }
    }

    // After an acknowledged COMMIT or ROLLBACK only: back to the pool when the
    // session is clean, closed otherwise.
    static void End(PinnedOracleSession entry) noexcept {
        if (entry.pooled && !entry.tainted) {
            if (auto pool = entry.pool.lock()) {
                pool->Release(std::move(entry.session));
                return;
            }
        }
        Close(std::move(entry));
    }

    // Closed, never reused: poisoned, an unknown COMMIT, a failed rollback.
    static void Close(PinnedOracleSession entry) noexcept {
        if (entry.pooled) {
            if (auto pool = entry.pool.lock()) {
                pool->Discard(std::move(entry.session));
                return;
            }
        }
        try {
            entry.session->Close();
        } catch (...) {
        }
    }

    // Ends one transaction by ROLLBACK. Only an acknowledged rollback lets the
    // session be reused.
    static void RollBack(PinnedOracleSession entry) noexcept {
        try {
            entry.session->Rollback();
        } catch (...) {
            Close(std::move(entry));
            return;
        }
        End(std::move(entry));
    }

    void Discard(const std::string &catalog_name, bool poison = false) noexcept {
        PinnedOracleSession entry;
        {
            std::lock_guard<std::mutex> guard(lock);
            if (poison) {
                failed.insert(catalog_name);
                status[catalog_name].connection_state = "discarded";
            } else {
                failed.erase(catalog_name);
                if (status[catalog_name].commit_outcome != "unknown") {
                    status[catalog_name].connection_state = "idle";
                }
            }
            const auto found = pinned.find(catalog_name);
            if (found == pinned.end()) {
                return;
            }
            entry = std::move(found->second);
            pinned.erase(found);
        }
        // A poisoned exchange may have an unread response. Close it without
        // another transaction operation; disconnect rolls back server state.
        // Normal caller rollback keeps its explicit acknowledgement path.
        if (poison) {
            Close(std::move(entry));
        } else {
            RollBack(std::move(entry));
        }
    }

    std::vector<PinnedOracleSession> TakeAll() noexcept {
        std::lock_guard<std::mutex> guard(lock);
        std::vector<PinnedOracleSession> sessions;
        sessions.reserve(pinned.size());
        for (auto &entry : pinned) {
            sessions.push_back(std::move(entry.second));
        }
        pinned.clear();
        return sessions;
    }

    // The attached catalog's transaction manager calls this before committing
    // DuckDB's local catalog state. A failed statement cannot open a fresh
    // session and accidentally turn a partial transaction into success.
    void Commit(const std::string &catalog_name) {
        PinnedOracleSession entry;
        {
            std::lock_guard<std::mutex> guard(lock);
            if (failed.count(catalog_name)) {
                throw TransactionException("Oracle transaction failed; ROLLBACK is required");
            }
            const auto found = pinned.find(catalog_name);
            if (found == pinned.end()) {
                return;
            }
            entry = std::move(found->second);
            pinned.erase(found);
        }
        try {
            TranslatingOracleErrors("Oracle COMMIT failed", [&] {
                entry.session->Commit();
                return 0;
            });
        } catch (const std::exception &error) {
            Close(std::move(entry));
            // Without a confirmed rejection, a lost acknowledgement must not
            // invite replay or deletion of files possibly already published.
            auto info = OracleErrorInfo(error);
            info["oracle_commit_outcome"] = "unknown";
            {
                std::lock_guard<std::mutex> guard(lock);
                auto &last = status[catalog_name];
                last.commit_outcome = "unknown";
                last.connection_state = "discarded";
                if (info.count("oracle_error_code")) {
                    last.oracle_code = std::stoul(info.at("oracle_error_code"));
                }
                if (info.count("oracle_protocol_error_kind")) {
                    last.protocol_kind = std::stoi(info.at("oracle_protocol_error_kind"));
                }
            }
            throw IOException(info, "Oracle COMMIT outcome is unknown; do not replay the transaction or delete its files "
                              "without reconciling the catalog");
        }
        End(std::move(entry));
        {
            std::lock_guard<std::mutex> guard(lock);
            status[catalog_name].commit_outcome = "committed";
            status[catalog_name].connection_state = "idle";
        }
    }

    OracleTransactionStatus Status(const std::string &catalog_name) {
        std::lock_guard<std::mutex> guard(lock);
        const auto found = status.find(catalog_name);
        return found == status.end() ? OracleTransactionStatus() : found->second;
    }

    void TransactionRollback(MetaTransaction &, ClientContext &) override {
        RollbackAll();
    }

    void TransactionRollback(MetaTransaction &, ClientContext &, optional_ptr<ErrorData>) override {
        RollbackAll();
    }

    void RollbackAll() noexcept {
        {
            std::lock_guard<std::mutex> guard(lock);
            failed.clear();
            for (auto &entry : status) {
                if (entry.second.connection_state == "active") {
                    entry.second.connection_state = "idle";
                }
            }
        }
        for (auto &entry : TakeAll()) {
            RollBack(std::move(entry));
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
oracle_scanner::OracleDateTime DateTimeFromTimestamp(timestamp_t timestamp, int64_t extra_nanoseconds,
                                                     const OracleColumn &column);

oracle_scanner::OracleDateTime DateTimeFromValue(const Value &value, const OracleColumn &column) {
    timestamp_t timestamp;
    // Oracle keeps nanoseconds and DuckDB's timestamp_t keeps microseconds, so
    // the sub-microsecond part is carried separately rather than truncated on
    // the way back into a column it came out of.
    int64_t extra_nanoseconds = 0;
    if (value.type().id() == LogicalTypeId::VARCHAR) {
        const auto text = value.GetValue<std::string>();
        timestamp_ns_t parsed;
        if (Timestamp::TryConvertTimestamp(text.c_str(), text.size(), parsed, false) != TimestampCastResult::SUCCESS) {
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
    } else if (value.type().id() == LogicalTypeId::TIMESTAMP_TZ) {
        timestamp = timestamp_t(value.GetValue<timestamp_tz_t>().value);
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
    return DateTimeFromTimestamp(timestamp, extra_nanoseconds, column);
}

// The Oracle date-time of a DuckDB timestamp, plus the nanoseconds below its
// microsecond that a TIMESTAMP_NS or ISO text carried.
oracle_scanner::OracleDateTime DateTimeFromTimestamp(timestamp_t timestamp, int64_t extra_nanoseconds,
                                                     const OracleColumn &column) {
    if (!timestamp.IsFinite()) {
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

// One bind carries at most this much (the TTC bind limit). Writing a LOB through
// an ordinary bind therefore stops here.
constexpr size_t MAX_LOB_WRITE_BYTES = oracle_scanner::TEMP_LOB_MAXIMUM_BYTES;
constexpr size_t MAX_JSON_WRITE_BYTES = MAX_LOB_WRITE_BYTES;

namespace {
const vector<Value> &VectorChildren(const Value &list) {
    return list.type().id() == LogicalTypeId::ARRAY ? ArrayValue::GetChildren(list) : ListValue::GetChildren(list);
}

// The elements of a VECTOR value, in the storage format the column has. A
// column of any format is mapped to a list of DOUBLE, so that is written as
// FLOAT64 and the server converts it to whatever each row's format is.
void FillVectorElements(oracle_scanner::OracleVector &target, const vector<Value> &children, const OracleColumn &column) {
    for (const auto &child : children) {
        if (child.IsNull()) {
            RefuseValue(column, "a VECTOR has no NULL element");
        }
        try {
            switch (target.format) {
            case oracle_scanner::ORACLE_VECTOR_FLOAT32: {
                const float number = child.GetValue<float>();
                if (!std::isfinite(number)) {
                    RefuseValue(column, "a VECTOR has no infinity or NaN element");
                }
                target.float32.push_back(number);
                break;
            }
            case oracle_scanner::ORACLE_VECTOR_FLOAT64: {
                const double number = child.GetValue<double>();
                if (!std::isfinite(number)) {
                    RefuseValue(column, "a VECTOR has no infinity or NaN element");
                }
                target.float64.push_back(number);
                break;
            }
            case oracle_scanner::ORACLE_VECTOR_INT8: {
                const auto number = child.GetValue<int64_t>();
                if (number < -128 || number > 127) {
                    RefuseValue(column, "an INT8 VECTOR element must be between -128 and 127");
                }
                target.int8.push_back(static_cast<int8_t>(number));
                break;
            }
            default: {
                const auto number = child.GetValue<int64_t>();
                if (number < 0 || number > 255) {
                    RefuseValue(column, "a BINARY VECTOR holds bytes, 0 to 255");
                }
                target.binary.push_back(static_cast<uint8_t>(number));
                break;
            }
            }
        } catch (const ConversionException &) {
            RefuseValue(column, "a VECTOR element does not fit the column's storage format");
        }
    }
}

// A VECTOR value as the image a bind carries. A dense one is its list or array
// of numbers; a sparse one is STRUCT(dimensions, indices, values).
std::vector<uint8_t> VectorImage(const Value &value, const OracleColumn &column) {
    const auto type = value.type().id();
    const bool sparse = (column.vector_flags & oracle_scanner::ORACLE_VECTOR_COLUMN_SPARSE) != 0;
    oracle_scanner::OracleVector target;
    target.format = column.vector_format != 0 ? column.vector_format : oracle_scanner::ORACLE_VECTOR_FLOAT64;
    target.sparse = sparse;
    if (sparse) {
        if (type != LogicalTypeId::STRUCT) {
            RefuseBind(column, value, "a sparse VECTOR column takes STRUCT(dimensions, indices, values)");
        }
        const auto &children = StructValue::GetChildren(value);
        if (children.size() != 3 || children[0].IsNull() || children[1].IsNull() || children[2].IsNull()) {
            RefuseBind(column, value, "a sparse VECTOR needs its dimensions, indices and values");
        }
        target.dimensions = children[0].GetValue<uint32_t>();
        for (const auto &index : VectorChildren(children[1])) {
            if (index.IsNull()) {
                RefuseValue(column, "a sparse VECTOR has no NULL index");
            }
            target.indices.push_back(index.GetValue<uint32_t>());
        }
        FillVectorElements(target, VectorChildren(children[2]), column);
    } else {
        if (type != LogicalTypeId::LIST && type != LogicalTypeId::ARRAY) {
            RefuseBind(column, value, "a VECTOR column takes a list or array of numbers");
        }
        FillVectorElements(target, VectorChildren(value), column);
        target.dimensions = static_cast<uint32_t>(VectorChildren(value).size());
        if (target.format == oracle_scanner::ORACLE_VECTOR_BINARY) {
            target.dimensions *= 8;
        }
    }
    try {
        return oracle_scanner::EncodeOracleVector(target);
    } catch (const oracle_scanner::ProtocolError &error) {
        RefuseValue(column, error.what());
    }
}
} // namespace

namespace {

// The part of a column's bind that does not depend on the value: its name, how
// it goes on the wire, and whether it stands for a LOB.
OracleBind OracleBindSkeleton(const OracleColumn &column, const std::string &name) {
    // A column this client cannot read is one it cannot reason about writing
    // either, and it refuses with the type named.
    RequireReadableColumn(column);
    OracleBind bind;
    bind.name = name;
    bind.oracle_type = column.oracle_type;
    bind.direction = BindDirection::BIND_IN;
    // What goes on the wire is settled before the NULL test: a batch declares
    // its bind metadata once, so a NULL row has to describe its column exactly
    // as a row with a value does.
    if (column.oracle_type == 231) {
        // A local-zone column is written as a TIMESTAMP of UTC wall time.
        bind.oracle_type = 180;
    }
    if (column.oracle_type == 112) {
        // A LOB is written as the ordinary bind of its content, as
        // python-oracledb Thin does: a VARCHAR2 for a CLOB or NCLOB (the server
        // converts to the national set itself, so the bind stays in the
        // database set), a RAW for a BLOB. Oracle accepts one past the usual
        // 32767 bytes when the target is a LOB, and the value goes out in the
        // chunked form the length prefix already has.
        bind.oracle_type = 1;
    } else if (column.oracle_type == 113) {
        bind.oracle_type = 23;
    } else if (column.oracle_type == 119) {
        // JSON is written as its text, which the server converts: the form
        // python-oracledb falls back to for a string bound to one. A VECTOR is
        // bound as its image (see VectorImage).
        bind.oracle_type = 1;
    }
    if ((column.oracle_type == 1 || column.oracle_type == 96) && column.character_set_form == 2) {
        bind.character_set_form = 2;
    }
    // Set before the NULL test as well: array DML binds a column the same way in
    // every row, so a NULL row has to say it stands for a LOB too.
    if (column.oracle_type == 112 || column.oracle_type == 119) {
        bind.lob_content = 112;
    } else if (column.oracle_type == 113) {
        bind.lob_content = 113;
    }
    return bind;
}

} // namespace

OracleBind OracleBindForColumn(const Value &value, const OracleColumn &column, const std::string &name) {
    auto bind = OracleBindSkeleton(column, name);
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
        if (column.character_set_form == 2) {
            // NCHAR and NVARCHAR2: the bind says it is the national form and
            // the value is UTF-16BE, which is what python-oracledb sends for
            // DB_TYPE_NVARCHAR and what a read returns.
            bind.value = EncodingFor(column, [&] { return oracle_scanner::EncodeUtf8ToUtf16Be(text); });
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
        if ((type == LogicalTypeId::FLOAT || type == LogicalTypeId::DOUBLE) &&
            column.unconstrained_number != OracleColumn::UNCONSTRAINED_DOUBLE) {
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
    case 231: { // TIMESTAMP WITH LOCAL TIME ZONE
        // The session is UTC, so a TIMESTAMPTZ is bound as the TIMESTAMP of its
        // UTC wall time and Oracle files it as the instant it names. Only a
        // TIMESTAMPTZ says which instant is meant; a bare TIMESTAMP would
        // silently be read as UTC.
        if (type != LogicalTypeId::TIMESTAMP_TZ) {
            RefuseBind(column, value, "a TIMESTAMP WITH LOCAL TIME ZONE column takes TIMESTAMPTZ");
        }
        bind.value = EncodingFor(
            column, [&] { return oracle_scanner::EncodeOracleTimestamp(DateTimeFromValue(value, column), false); });
        return bind;
    }
    case 252: { // BOOLEAN
        if (type != LogicalTypeId::BOOLEAN) {
            RefuseBind(column, value, "a BOOLEAN column takes BOOLEAN");
        }
        // Two bytes, as python-oracledb sends them: a 1, then 1 for true and 0
        // for false.
        bind.value = std::vector<uint8_t> {1, static_cast<uint8_t>(value.GetValue<bool>() ? 1 : 0)};
        return bind;
    }
    case 182: { // INTERVAL YEAR TO MONTH
        if (type != LogicalTypeId::INTERVAL) {
            RefuseBind(column, value, "an INTERVAL YEAR TO MONTH column takes INTERVAL");
        }
        const auto interval = value.GetValue<interval_t>();
        if (interval.days != 0 || interval.micros != 0) {
            RefuseValue(column, "an INTERVAL YEAR TO MONTH holds whole months; this interval has days or time");
        }
        bind.value = EncodingFor(column, [&] {
            return oracle_scanner::EncodeOracleIntervalYearMonth(interval.months / 12, interval.months % 12);
        });
        return bind;
    }
    case 183: { // INTERVAL DAY TO SECOND
        if (type != LogicalTypeId::INTERVAL) {
            RefuseBind(column, value, "an INTERVAL DAY TO SECOND column takes INTERVAL");
        }
        const auto interval = value.GetValue<interval_t>();
        if (interval.months != 0) {
            // A month is not a fixed number of days, so there is no exact
            // DAY TO SECOND for it.
            RefuseValue(column, "an INTERVAL DAY TO SECOND cannot hold months");
        }
        constexpr int64_t MICROS_PER_DAY = 86400LL * 1000000LL;
        // Whole days inside the time part move to the day count, so the hour
        // field stays 0..23 as Oracle requires.
        const int64_t days = static_cast<int64_t>(interval.days) + interval.micros / MICROS_PER_DAY;
        const int64_t micros = interval.micros % MICROS_PER_DAY;
        if ((days > 0 && micros < 0) || (days < 0 && micros > 0)) {
            // Oracle's interval has one sign for every field.
            RefuseValue(column, "the days and the time part of this interval have opposite signs");
        }
        if (days > NumericLimits<int32_t>::Maximum() || days < NumericLimits<int32_t>::Minimum()) {
            RefuseValue(column, "the day count is out of range");
        }
        const int64_t seconds_total = micros / 1000000LL;
        bind.value = EncodingFor(column, [&] {
            return oracle_scanner::EncodeOracleIntervalDaySecond(
                static_cast<int32_t>(days), static_cast<int32_t>(seconds_total / 3600),
                static_cast<int32_t>(seconds_total / 60 % 60), static_cast<int32_t>(seconds_total % 60),
                static_cast<int32_t>(micros % 1000000LL * 1000));
        });
        return bind;
    }
    case 112:   // CLOB and NCLOB
    case 113: { // BLOB
        const bool character = column.oracle_type == 112;
        if (type != (character ? LogicalTypeId::VARCHAR : LogicalTypeId::BLOB)) {
            RefuseBind(column, value, character ? "a CLOB column takes VARCHAR" : "a BLOB column takes BLOB");
        }
        const auto bytes = character ? value.GetValue<std::string>() : StringValue::Get(value);
        if (bytes.empty()) {
            // An empty CLOB value is NULL on the way in, like any empty string.
            return bind;
        }
        if (bytes.size() > MAX_LOB_WRITE_BYTES) {
            RefuseValue(column, "a LOB value is limited to " + std::to_string(MAX_LOB_WRITE_BYTES >> 20U) + " MiB");
        }
        bind.value = std::vector<uint8_t>(bytes.begin(), bytes.end());
        return bind;
    }
    case 119: { // JSON
        if (type != LogicalTypeId::VARCHAR) {
            RefuseBind(column, value, "a JSON column takes VARCHAR or JSON text");
        }
        const auto text = value.GetValue<std::string>();
        if (text.empty()) {
            return bind;
        }
        if (text.size() > MAX_JSON_WRITE_BYTES) {
            RefuseValue(column, "a JSON value is limited to " + std::to_string(MAX_JSON_WRITE_BYTES >> 20U) +
                                    " MiB of text");
        }
        bind.value = std::vector<uint8_t>(text.begin(), text.end());
        return bind;
    }
    case 127: // VECTOR, bound as its image
        bind.value = VectorImage(value, column);
        return bind;
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

namespace {

// How AppendChunkBinds reads one column: straight from the vector for the
// pairings an attached table's own columns produce, value by value through
// OracleBindForColumn for everything else.
enum class ChunkBindPath { BY_VALUE, TEXT, SIGNED, UNSIGNED, DECIMAL, DATE_TIME, BINARY_DOUBLE, BINARY_FLOAT, BOOLEAN };

ChunkBindPath ChunkBindPathFor(const LogicalType &type, const OracleColumn &column) {
    const auto id = type.id();
    switch (column.oracle_type) {
    case 1:
    case 96:
        // The national form is re-encoded as UTF-16; that stays on the value path.
        return id == LogicalTypeId::VARCHAR && column.character_set_form != 2 ? ChunkBindPath::TEXT
                                                                              : ChunkBindPath::BY_VALUE;
    case 2:
        switch (id) {
        case LogicalTypeId::TINYINT:
        case LogicalTypeId::SMALLINT:
        case LogicalTypeId::INTEGER:
        case LogicalTypeId::BIGINT:
            return ChunkBindPath::SIGNED;
        case LogicalTypeId::UTINYINT:
        case LogicalTypeId::USMALLINT:
        case LogicalTypeId::UINTEGER:
        case LogicalTypeId::UBIGINT:
            return ChunkBindPath::UNSIGNED;
        case LogicalTypeId::DECIMAL:
            return ChunkBindPath::DECIMAL;
        default:
            return ChunkBindPath::BY_VALUE;
        }
    case 12:
    case 180:
        return id == LogicalTypeId::TIMESTAMP || id == LogicalTypeId::DATE ? ChunkBindPath::DATE_TIME
                                                                          : ChunkBindPath::BY_VALUE;
    case 101:
        return id == LogicalTypeId::DOUBLE ? ChunkBindPath::BINARY_DOUBLE : ChunkBindPath::BY_VALUE;
    case 100:
        return id == LogicalTypeId::FLOAT ? ChunkBindPath::BINARY_FLOAT : ChunkBindPath::BY_VALUE;
    case 252:
        return id == LogicalTypeId::BOOLEAN ? ChunkBindPath::BOOLEAN : ChunkBindPath::BY_VALUE;
    default:
        return ChunkBindPath::BY_VALUE;
    }
}

int64_t SignedAt(const Vector &vector, idx_t row) {
    switch (vector.GetType().id()) {
    case LogicalTypeId::TINYINT:
        return FlatVector::GetData<int8_t>(vector)[row];
    case LogicalTypeId::SMALLINT:
        return FlatVector::GetData<int16_t>(vector)[row];
    case LogicalTypeId::INTEGER:
        return FlatVector::GetData<int32_t>(vector)[row];
    default:
        return FlatVector::GetData<int64_t>(vector)[row];
    }
}

uint64_t UnsignedAt(const Vector &vector, idx_t row) {
    switch (vector.GetType().id()) {
    case LogicalTypeId::UTINYINT:
        return FlatVector::GetData<uint8_t>(vector)[row];
    case LogicalTypeId::USMALLINT:
        return FlatVector::GetData<uint16_t>(vector)[row];
    case LogicalTypeId::UINTEGER:
        return FlatVector::GetData<uint32_t>(vector)[row];
    default:
        return FlatVector::GetData<uint64_t>(vector)[row];
    }
}

// The decimal text DuckDB's own cast to VARCHAR gives, which is what the value
// path hands the NUMBER codec.
std::string DecimalTextAt(const Vector &vector, idx_t row) {
    const auto &type = vector.GetType();
    const auto width = DecimalType::GetWidth(type);
    const auto scale = DecimalType::GetScale(type);
    switch (type.InternalType()) {
    case PhysicalType::INT16:
        return Decimal::ToString(FlatVector::GetData<int16_t>(vector)[row], width, scale);
    case PhysicalType::INT32:
        return Decimal::ToString(FlatVector::GetData<int32_t>(vector)[row], width, scale);
    case PhysicalType::INT64:
        return Decimal::ToString(FlatVector::GetData<int64_t>(vector)[row], width, scale);
    default:
        return Decimal::ToString(FlatVector::GetData<hugeint_t>(vector)[row], width, scale);
    }
}

// The binds of every row of a flat chunk, appended to `rows`. The direct paths
// produce the same bytes OracleBindForColumn would for the same value; that
// function stays the one statement of the conversion rules, and any pairing not
// listed in ChunkBindPathFor goes through it.
void AppendChunkBinds(DataChunk &chunk, const std::vector<idx_t> &source_indexes,
                      const std::vector<OracleColumn> &columns, std::vector<std::vector<OracleBind>> &rows) {
    const auto first_row = rows.size();
    const auto count = chunk.size();
    rows.resize(first_row + count);
    for (idx_t row = 0; row < count; row++) {
        rows[first_row + row].reserve(source_indexes.size());
    }
    for (idx_t column_index = 0; column_index < source_indexes.size(); column_index++) {
        const auto &column = columns[column_index];
        auto &vector = chunk.data[source_indexes[column_index]];
        const auto name = std::to_string(column_index + 1);
        const auto path = ChunkBindPathFor(vector.GetType(), column);
        if (path == ChunkBindPath::BY_VALUE) {
            for (idx_t row = 0; row < count; row++) {
                rows[first_row + row].push_back(OracleBindForColumn(vector.GetValue(row), column, name));
            }
            continue;
        }
        const auto skeleton = OracleBindSkeleton(column, name);
        const auto &validity = FlatVector::Validity(vector);
        for (idx_t row = 0; row < count; row++) {
            auto bind = skeleton;
            if (validity.RowIsValid(row)) {
                switch (path) {
                case ChunkBindPath::TEXT: {
                    const auto text = FlatVector::GetData<string_t>(vector)[row];
                    // Empty text is NULL in Oracle, as on the value path.
                    if (text.GetSize() > 0) {
                        const auto data = reinterpret_cast<const uint8_t *>(text.GetData());
                        bind.value = std::vector<uint8_t>(data, data + text.GetSize());
                    }
                    break;
                }
                case ChunkBindPath::SIGNED: {
                    const auto text = std::to_string(SignedAt(vector, row));
                    bind.value = EncodingFor(column, [&] { return oracle_scanner::EncodeOracleNumber(text); });
                    break;
                }
                case ChunkBindPath::UNSIGNED: {
                    const auto text = std::to_string(UnsignedAt(vector, row));
                    bind.value = EncodingFor(column, [&] { return oracle_scanner::EncodeOracleNumber(text); });
                    break;
                }
                case ChunkBindPath::DECIMAL: {
                    const auto text = DecimalTextAt(vector, row);
                    bind.value = EncodingFor(column, [&] { return oracle_scanner::EncodeOracleNumber(text); });
                    break;
                }
                case ChunkBindPath::DATE_TIME: {
                    const auto timestamp =
                        vector.GetType().id() == LogicalTypeId::DATE
                            ? Timestamp::FromDatetime(FlatVector::GetData<date_t>(vector)[row], dtime_t(0))
                            : FlatVector::GetData<timestamp_t>(vector)[row];
                    const auto date_time = DateTimeFromTimestamp(timestamp, 0, column);
                    bind.value = EncodingFor(column, [&] {
                        return column.oracle_type == 12 ? oracle_scanner::EncodeOracleDate(date_time)
                                                        : oracle_scanner::EncodeOracleTimestamp(date_time, false);
                    });
                    break;
                }
                case ChunkBindPath::BINARY_DOUBLE: {
                    const auto number = FlatVector::GetData<double>(vector)[row];
                    if (!std::isfinite(number)) {
                        RefuseValue(column, "Oracle BINARY_DOUBLE has no infinity in this codec");
                    }
                    bind.value = oracle_scanner::EncodeOracleBinaryDouble(number);
                    break;
                }
                case ChunkBindPath::BINARY_FLOAT: {
                    const auto number = FlatVector::GetData<float>(vector)[row];
                    if (!std::isfinite(number)) {
                        RefuseValue(column, "Oracle BINARY_FLOAT has no infinity in this codec");
                    }
                    bind.value = oracle_scanner::EncodeOracleBinaryFloat(number);
                    break;
                }
                case ChunkBindPath::BOOLEAN:
                    bind.value =
                        std::vector<uint8_t> {1, static_cast<uint8_t>(FlatVector::GetData<bool>(vector)[row] ? 1 : 0)};
                    break;
                default:
                    break;
                }
            }
            rows[first_row + row].push_back(std::move(bind));
        }
    }
}

} // namespace

OracleSession &TransactionSession(ClientContext &context, const OracleWriteTarget &target) {
    auto &catalog = Catalog::GetCatalog(context, Identifier(target.catalog_name));
    Transaction::Get(context, catalog);
    // Attached catalog configuration is shared across callers. The pinned
    // session belongs to this transaction's caller, not the ATTACH context.
    auto caller_target = target;
    caller_target.config.io_deadline = OracleIoDeadlineFor(context);
    return WriteStateFor(context).Pin(caller_target);
}

std::shared_ptr<OracleSession> TryTransactionSession(ClientContext &context, const std::string &catalog_name) {
    auto &state = WriteStateFor(context);
    std::lock_guard<std::mutex> guard(state.lock);
    const auto pinned = state.pinned.find(catalog_name);
    if (pinned == state.pinned.end()) {
        return nullptr;
    }
    return pinned->second.session;
}

void TaintTransactionSession(ClientContext &context, const std::string &catalog_name) {
    WriteStateFor(context).Taint(catalog_name);
}

void PoisonTransactionSession(ClientContext &context, const std::string &catalog_name) noexcept {
    try {
        WriteStateFor(context).Discard(catalog_name, true);
    } catch (...) {
    }
}

void CommitOracleTransaction(ClientContext &context, const std::string &catalog_name) {
    WriteStateFor(context).Commit(catalog_name);
}

OracleTransactionStatus GetOracleTransactionStatus(ClientContext &context, const std::string &catalog_name) {
    return WriteStateFor(context).Status(catalog_name);
}

void RollbackOracleTransaction(ClientContext &context, const std::string &catalog_name) noexcept {
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

// The OUT binds that carry a RETURNING clause's values back, one per column.
std::vector<OracleBind> ReturningOutputs(const std::vector<OracleColumn> &returned_columns) {
    std::vector<OracleBind> outputs;
    for (idx_t column_index = 0; column_index < returned_columns.size(); column_index++) {
        OracleBind output;
        output.name = "r" + std::to_string(column_index + 1);
        output.oracle_type = returned_columns[column_index].oracle_type;
        if (output.oracle_type == 96) {
            // A CHAR OUT bind is blank-padded to the whole buffer (32767
            // here), not to the column's width. Asked for as VARCHAR2 the
            // value comes back as the column holds it, already padded to
            // the declared width.
            output.oracle_type = 1;
        }
        if ((returned_columns[column_index].oracle_type == 1 || returned_columns[column_index].oracle_type == 96) &&
            returned_columns[column_index].character_set_form == 2) {
            output.character_set_form = 2;
        }
        output.direction = BindDirection::BIND_OUT;
        output.maximum_bytes = 32767;
        outputs.push_back(std::move(output));
    }
    return outputs;
}

// The columns a RETURNING over the whole table covers, and the clause that asks
// for them. DuckDB evaluates RETURNING over every column of the table, so a
// column this client cannot hand back rules the clause out.
struct ReturningPlan {
    std::vector<OracleColumn> columns;
    std::string clause;
};

ReturningPlan PlanReturning(const TableCatalogEntry &table, const std::vector<OracleColumn> &columns,
                            const char *statement, const std::string &first_out_name_prefix = "r") {
    ReturningPlan plan;
    std::string returned_list;
    std::string into_list;
    for (auto &column : table.GetColumns().Physical()) {
        const auto position = column.Physical().index;
        if (position >= columns.size()) {
            throw InternalException("Oracle RETURNING column %llu is outside the table's Oracle metadata",
                                    static_cast<uint64_t>(position));
        }
        RequireReadableColumn(columns[position]);
        if (columns[position].oracle_type == 112 || columns[position].oracle_type == 113 ||
            columns[position].oracle_type == 119 || columns[position].oracle_type == 127) {
            // Oracle hands a LOB in RETURNING back as a locator, not as
            // content, and this client has no capture of that exchange.
            throw NotImplementedException("Oracle %s ... RETURNING cannot return the LOB, JSON or VECTOR column \"%s\"; "
                                          "run it without RETURNING and read the rows back",
                                          statement, columns[position].name);
        }
        if (!returned_list.empty()) {
            returned_list += ", ";
            into_list += ", ";
        }
        returned_list += KeywordHelper::WriteQuotedAndEscaped(columns[position].name, '"');
        into_list += ":" + first_out_name_prefix + std::to_string(plan.columns.size() + 1);
        plan.columns.push_back(columns[position]);
    }
    plan.clause = " RETURNING " + returned_list + " INTO " + into_list;
    return plan;
}

} // namespace

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
        AppendChunkBinds(chunk, source_indexes, bound_columns, rows);
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
        chunk.SetChildCardinality(1);
        chunk.data[0].SetValue(0, Value::BIGINT(NumericCast<int64_t>(global_state.inserted_rows)));
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
            for (auto &output : ReturningOutputs(returned_columns)) {
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
                row_chunk.data[column_index].SetValue(row,
                                   TranslatingOracleErrors("Oracle could not convert a RETURNING value", [&] {
                                       return ValueFor(returned_columns[column_index], values[column_index].value);
                                   }));
            }
            row_chunk.SetChildCardinality(row + 1);
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
                             OracleWriteTarget target_p, std::string sql_p,
                             std::vector<OracleColumn> returned_columns_p = {})
        : PhysicalOperator(physical_plan, PhysicalOperatorType::EXTENSION, std::move(types), estimated_cardinality),
          target(std::move(target_p)), sql(std::move(sql_p)), returned_columns(std::move(returned_columns_p)) {
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
        chunk.SetChildCardinality(1);
        chunk.data[0].SetValue(0, Value::BIGINT(NumericCast<int64_t>(global_state.inserted_rows)));
        return SourceResultType::FINISHED;
    }

protected:
    // With RETURNING, one statement per row: it names the row by ROWID, so it
    // changes one row or none. The statement also reports SQL%ROWCOUNT, because
    // a row deleted since the scan read it returns nothing, and the OUT binds
    // would then read as a row of NULLs.
    SinkResultType SinkReturning(ExecutionContext &context, DataChunk &chunk, OracleInsertGlobalState &global_state) const {
        const auto rowid_index = chunk.ColumnCount() - 1;
        DataChunk row_chunk;
        row_chunk.Initialize(Allocator::DefaultAllocator(), types);
        for (idx_t row_index = 0; row_index < chunk.size(); row_index++) {
            auto binds = LeadingBinds(chunk, row_index);
            const auto rowid = chunk.GetValue(rowid_index, row_index);
            if (rowid.IsNull()) {
                throw InternalException("Oracle row identity is missing for a row of \"%s\"", target.object_name);
            }
            binds.push_back(OracleBindForColumn(rowid, OracleRowIdColumn(), std::to_string(binds.size() + 1)));
            for (auto &output : ReturningOutputs(returned_columns)) {
                binds.push_back(std::move(output));
            }
            OracleBind count;
            count.name = "rc";
            count.oracle_type = 2;
            count.direction = BindDirection::BIND_OUT;
            count.maximum_bytes = 22;
            binds.push_back(std::move(count));
            std::vector<OracleBind> values;
            try {
                auto &session = TransactionSession(context.client, target);
                values = TranslatingOracleErrors(FailureMessage(), [&] { return session.ExecuteReturning(sql, binds); });
            } catch (...) {
                PoisonTransactionSession(context.client, target.catalog_name);
                throw;
            }
            if (values.size() != returned_columns.size() + 1 || !values.back().value) {
                throw InternalException("Oracle RETURNING produced %llu values for %llu columns and a row count",
                                        static_cast<uint64_t>(values.size()), static_cast<uint64_t>(returned_columns.size()));
            }
            if (oracle_scanner::DecodeOracleNumber(*values.back().value) == "0") {
                continue;
            }
            const auto row = row_chunk.size();
            for (idx_t column_index = 0; column_index < returned_columns.size(); column_index++) {
                row_chunk.data[column_index].SetValue(row,
                                   TranslatingOracleErrors("Oracle could not convert a RETURNING value", [&] {
                                       return ValueFor(returned_columns[column_index], values[column_index].value);
                                   }));
            }
            row_chunk.SetChildCardinality(row + 1);
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

    //! The binds that come before the row identity, empty for a DELETE.
    virtual std::vector<OracleBind> LeadingBinds(DataChunk &chunk, idx_t row_index) const = 0;
    virtual const char *FailureMessage() const = 0;

    OracleWriteTarget target;
    std::string sql;
    //! The table's columns, in order, when the statement has RETURNING.
    std::vector<OracleColumn> returned_columns;
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
                         std::vector<OracleColumn> set_columns_p, std::vector<OracleColumn> returned_columns_p = {})
        : OracleRowIdWriteOperator(physical_plan, std::move(types), estimated_cardinality, std::move(target_p),
                                   std::move(sql_p), std::move(returned_columns_p)),
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
    //
    // How "named" is known changed in DuckDB 2.0. The binder used to leave
    // op.column_index_map with INVALID_INDEX for an unnamed column; it now
    // leaves that map empty (plan_insert.cpp calls it deprecated) and instead
    // puts a projection over the source whose select list has, per physical
    // column, a reference into the source for a named column and the column's
    // bound default — a constant NULL for an Oracle table, which has no DuckDB
    // default — for an unnamed one. The default is moved out of
    // op.bound_defaults to do it, which is what says a column was left out:
    // the projection's expressions cannot, because the optimizer folds
    // constants into them and merges projections, so a named column can end up
    // as a constant or a computation. The old map is still honoured when
    // present, for a plan that reaches here some other way.
    std::vector<idx_t> source_indexes;
    std::vector<OracleColumn> bound_columns;
    std::string column_list;
    std::string value_list;
    const auto *projection =
        plan->type == PhysicalOperatorType::PROJECTION ? &plan->Cast<PhysicalProjection>() : nullptr;
    const auto names_column = [&](idx_t physical, idx_t storage) -> std::optional<idx_t> {
        if (!op.column_index_map.empty()) {
            const auto mapped = op.column_index_map[PhysicalIndex(physical)];
            if (mapped == DConstants::INVALID_INDEX) {
                return std::nullopt;
            }
            return mapped;
        }
        if (!projection || physical >= projection->select_list.size()) {
            // No projection means the source already matches the table
            // column for column, so every column is named and in order.
            return physical;
        }
        if (storage < op.bound_defaults.size()) {
            // The binder moves a column's bound default into the projection when
            // the statement does not name it and only reads it for one it does,
            // so a default that has gone is exactly an unnamed column. The
            // expression itself cannot say: the optimizer folds constants and
            // merges projections, and a column the user wrote as a constant or
            // a computation then looks no different from one left out.
            return op.bound_defaults[storage] ? std::optional<idx_t>(physical) : std::nullopt;
        }
        const Expression *expression = projection->select_list[physical].get();
        // A cast is a function expression of type OPERATOR_CAST in 2.0;
        // BoundCastExpression is only the set of helpers that reads one.
        while (BoundCastExpression::IsCast(*expression)) {
            expression = &BoundCastExpression::Child(expression->Cast<BoundFunctionExpression>());
        }
        if (expression->GetExpressionClass() != ExpressionClass::BOUND_REF) {
            return std::nullopt;
        }
        // The insert operator reads the projection's output, where this
        // column sits at its own physical position.
        return physical;
    };
    for (auto &column : op.table.GetColumns().Physical()) {
        const auto position = column.Physical().index;
        if (position >= columns.size()) {
            throw InternalException("Oracle INSERT column %llu is outside the table's Oracle metadata", position);
        }
        const auto named = names_column(position, column.StorageOid());
        if (!named) {
            continue;
        }
        const idx_t source_index = *named;
        if (!column_list.empty()) {
            column_list += ", ";
            value_list += ", ";
        }
        column_list += KeywordHelper::WriteQuotedAndEscaped(columns[position].name, '"');
        value_list += OracleBindExpression(columns[position], bound_columns.size() + 1);
        source_indexes.push_back(source_index);
        bound_columns.push_back(columns[position]);
    }
    if (bound_columns.empty()) {
        throw NotImplementedException("Oracle INSERT needs at least one column");
    }
    auto sql = "INSERT INTO " + OracleObjectReference(target.schema_name, target.object_name) + " (" + column_list +
              ") VALUES (" + value_list + ")";
    // RETURNING asks Oracle for the row it actually stored. Echoing back what
    // was sent would be wrong for exactly the cases the clause exists for: a
    // column left to its DEFAULT, a sequence, a trigger.
    std::vector<OracleColumn> returned_columns;
    if (op.return_chunk) {
        auto returning = PlanReturning(op.table, columns, "INSERT");
        sql += returning.clause;
        returned_columns = std::move(returning.columns);
    }
    auto &insert = planner.Make<OracleInsertOperator>(op.types, op.estimated_cardinality, std::move(target), sql,
                                                      std::move(source_indexes), std::move(bound_columns),
                                                      std::move(returned_columns));
    insert.children.push_back(*plan);
    return insert;
}

PhysicalOperator &PlanOracleDelete(ClientContext &, PhysicalPlanGenerator &planner, LogicalDelete &op,
                                   PhysicalOperator &plan, const std::vector<OracleColumn> &columns,
                                   OracleWriteTarget target) {
    auto sql = "DELETE FROM " + OracleObjectReference(target.schema_name, target.object_name) + " WHERE ROWID = " +
               "CHARTOROWID(:1)";
    std::vector<OracleColumn> returned_columns;
    if (op.return_chunk) {
        // The rows as they were just before Oracle deleted them.
        auto returning = PlanReturning(op.table, columns, "DELETE");
        sql += returning.clause + "; :rc := SQL%ROWCOUNT";
        returned_columns = std::move(returning.columns);
    }
    auto &deletion = planner.Make<OracleDeleteOperator>(op.types, op.estimated_cardinality, std::move(target), sql,
                                                        std::move(returned_columns));
    deletion.children.push_back(plan);
    return deletion;
}

PhysicalOperator &PlanOracleUpdate(ClientContext &, PhysicalPlanGenerator &planner, LogicalUpdate &op,
                                   PhysicalOperator &plan, const std::vector<OracleColumn> &columns,
                                   OracleWriteTarget target) {
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
        assignments += KeywordHelper::WriteQuotedAndEscaped(columns[position].name, '"') + " = ";
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
        assignments += OracleBindExpression(columns[position], set_columns.size() + 1);
        source_indexes.push_back(op.expressions[index]->Cast<BoundReferenceExpression>().Index());
        set_columns.push_back(columns[position]);
    }
    if (assignments.empty()) {
        throw NotImplementedException("Oracle UPDATE needs at least one column to set");
    }
    auto sql = "UPDATE " + OracleObjectReference(target.schema_name, target.object_name) + " SET " + assignments +
               " WHERE ROWID = CHARTOROWID(:" + std::to_string(set_columns.size() + 1) + ")";
    std::vector<OracleColumn> returned_columns;
    if (op.return_chunk) {
        // The rows as Oracle stored them, which a trigger or DEFAULT may have changed.
        auto returning = PlanReturning(op.table, columns, "UPDATE");
        sql += returning.clause + "; :rc := SQL%ROWCOUNT";
        returned_columns = std::move(returning.columns);
    }
    auto &update = planner.Make<OracleUpdateOperator>(op.types, op.estimated_cardinality, std::move(target), sql,
                                                      std::move(source_indexes), std::move(set_columns),
                                                      std::move(returned_columns));
    update.children.push_back(plan);
    return update;
}

} // namespace duckdb

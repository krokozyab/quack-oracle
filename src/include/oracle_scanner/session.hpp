#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/row_batch.hpp"

namespace oracle_scanner {
class OracleIoDeadline;
}

namespace oracle_scanner {

struct OracleError {
    uint32_t code = 0;
    std::string message;
    size_t sql_offset = 0;
    bool recoverable = false;
};

struct OracleColumn {
    std::string name;
    uint16_t oracle_type = 0;
    uint32_t byte_width = 0;
    int16_t precision = 0;
    int16_t scale = 0;
    bool nullable = true;
    // Oracle's `csfrm`: 1 for the database character set, 2 for the national
    // one, 0 where it does not apply. It is what separates VARCHAR2 from
    // NVARCHAR2 and CHAR from NCHAR, which share a type code but not an
    // encoding, so it decides whether a character column can be read at all.
    uint8_t character_set_form = 0;
    // Oracle declares a maximum byte length per column, and a column whose
    // maximum is zero can only ever be SQL NULL. The server then leaves it out
    // of ROW_DATA completely — no value and no NULL length byte — so the fetch
    // decoder must skip it rather than read a value for it. Only the describe
    // decoders can know this; the default means "expect bytes", which is what
    // every column built anywhere else should be treated as.
    bool omitted_from_row_data = false;
    // A VECTOR column's declared shape, which a server at TTC field version 24
    // or later sends with the describe: the dimension count (0 for an unbounded
    // `*`), the storage format (2 FLOAT32, 3 FLOAT64, 4 INT8, 5 BINARY; 0 for
    // `*`), and flags. Zero in every column that is not a VECTOR.
    uint32_t vector_dimensions = 0;
    uint8_t vector_format = 0;
    uint8_t vector_flags = 0;
    // Set by a cursor once it has asked the server to send a LOB-like column
    // (CLOB, BLOB, JSON, VECTOR) with its size, and for JSON and VECTOR the
    // first bytes of its value, ahead of the locator. A row's cell for such a
    // column is then framed differently, and this is what the row decoder
    // reads to know which way. Never set on a describe.
    bool inline_lob_cells = false;
    // Set by a catalog on a column whose dictionary type is XMLTYPE. It reaches
    // the wire as a CLOB: a scan selects XMLSERIALIZE(CONTENT col AS CLOB) and a
    // write binds a CLOB inside XMLTYPE(:n), so the column is only ever text on
    // this side. Never set on a describe.
    bool xml = false;
    // Set by a catalog on a character column Oracle compares byte by byte, as
    // DuckDB does: the session's NLS_COMP is BINARY and the column declares no
    // collation of its own, or declares BINARY. Any other column compares by a
    // collation, under which BINARY_CI makes 'a' equal 'A', so equality on it
    // is not DuckDB's. Never set on a describe.
    bool compared_as_bytes = false;
    // For TIMESTAMP WITH LOCAL TIME ZONE (231): a fetched value is the wall time
    // in the database time zone (DBTIMEZONE), the form Oracle stores it in, not
    // the session's. This is that zone's offset from UTC in minutes, set by the
    // session that described the column. database_zone_is_region says DBTIMEZONE
    // names a region instead, whose offset depends on the date.
    int16_t database_zone_minutes = 0;
    bool database_zone_is_region = false;
    // What a NUMBER with no declared precision becomes in DuckDB, chosen by the
    // oracle_unconstrained_number setting when the columns are described: text
    // (the default, which loses nothing), DOUBLE, or a fixed DECIMAL.
    enum : uint8_t { UNCONSTRAINED_TEXT = 0, UNCONSTRAINED_DOUBLE = 1, UNCONSTRAINED_DECIMAL = 2 };
    uint8_t unconstrained_number = UNCONSTRAINED_TEXT;
    uint8_t unconstrained_precision = 0;
    uint8_t unconstrained_scale = 0;
};

struct OracleBatch {
    std::vector<OracleColumn> columns;
    std::vector<std::vector<std::optional<std::vector<uint8_t>>>> rows;
    bool exhausted = false;
    std::optional<OraclePackedBatch> packed;
    size_t RowCount() const {
        return packed ? packed->RowCount() : rows.size();
    }
};

// The enumerators carry a BIND_ prefix because Windows defines IN and OUT as
// macros in its own headers, and an enum class does not protect against the
// preprocessor: `{ IN, OUT, IN_OUT }` expands to `{ , , IN_OUT }` and the file
// stops compiling. Undefining them instead would change macro state for every
// header included after this one, which is not ours to do.
enum class BindDirection { BIND_IN, BIND_OUT, BIND_IN_OUT };

struct OracleBind {
    std::string name;
    uint16_t oracle_type = 0;
    BindDirection direction = BindDirection::BIND_IN;
    std::optional<std::vector<uint8_t>> value;
    // Required for scalar OUT / IN OUT values when the input value does not
    // establish a buffer size. REF CURSOR has a fixed wire allocation.
    uint32_t maximum_bytes = 0;
    // Oracle's csfrm for a character bind: 0 means the default (the database
    // character set for a character type), 2 the national one, in which case
    // the value must be UTF-16BE.
    uint8_t character_set_form = 0;
    // Set on a bind that stands for the content of a LOB-like target: 112 for
    // text (a CLOB, or JSON and XML written as text), 113 for bytes. `value` is
    // then the content itself, `oracle_type` is how a small one is bound
    // (VARCHAR2 or RAW), and a native session sends one too large for that
    // through a temporary LOB, binding its locator instead.
    uint8_t lob_content = 0;
};

// Values are borrowed only during WriteRow. A sink must consume/copy them
// before returning and must not publish a partially received fetch on error.
class OracleRowSink {
public:
    virtual ~OracleRowSink() = default;
    virtual void WriteRow(size_t row, const std::vector<std::optional<OracleByteView>> &values) = 0;
};

struct OracleFetchResult {
    size_t rows = 0;
    bool exhausted = false;
};

class OracleCursor {
public:
    virtual ~OracleCursor() = default;
    virtual const std::vector<OracleColumn> &Columns() const = 0;
    virtual OracleBatch Fetch(size_t requested_rows) = 0;
    // Optional zero-per-cell-allocation scalar path; legacy consumers keep Fetch.
    virtual OracleBatch FetchPacked(size_t requested_rows) {
        return Fetch(requested_rows);
    }
    // false means unsupported, with no cursor/sink mutation or remote fetch.
    virtual bool FetchInto(size_t, OracleRowSink &, OracleFetchResult &) {
        return false;
    }
    virtual void Cancel() = 0;
    virtual void Close() = 0;
};

struct OracleCallResult {
    std::vector<OracleBind> outputs;
    std::vector<std::unique_ptr<OracleCursor>> explicit_cursors;
    std::vector<std::unique_ptr<OracleCursor>> implicit_cursors;
};

// DML_COMPOSITE is not a stored callable: it is a bounded sequence of
// validated INSERT, UPDATE and DELETE statements run as one anonymous block,
// each followed by a server-side check of its exact row count.
enum class OracleCallableKind { PROCEDURE, FUNCTION, DML_COMPOSITE, ANONYMOUS_BLOCK };

// One statement of a DML_COMPOSITE request and the SQL%ROWCOUNT it must report.
struct OracleDmlOperation {
    std::string sql;
    uint64_t expected_rows = 0;
};

struct OracleCallRequest {
    OracleCallableKind kind = OracleCallableKind::PROCEDURE;
    std::string qualified_name;
    std::optional<OracleBind> return_bind;
    std::vector<OracleBind> arguments;
    // DML_COMPOSITE only. The arguments are then the binds of every statement,
    // each name once, however many statements use it.
    std::vector<OracleDmlOperation> dml_operations;
    // ANONYMOUS_BLOCK only: a BEGIN ... END; or DECLARE ... BEGIN ... END; block
    // the caller wrote. The arguments are its binds, each by the name its
    // placeholder uses; the OUT and IN OUT ones come back in the order the
    // block first mentions them.
    std::string block;
};

// What has crossed one session's connection so far. Cumulative, so what an
// operation moved is the difference between two readings.
struct OracleIoStats {
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t round_trips = 0;

    OracleIoStats operator-(const OracleIoStats &earlier) const {
        return {bytes_sent - earlier.bytes_sent, bytes_received - earlier.bytes_received,
                round_trips - earlier.round_trips};
    }
    OracleIoStats &operator+=(const OracleIoStats &other) {
        bytes_sent += other.bytes_sent;
        bytes_received += other.bytes_received;
        round_trips += other.round_trips;
        return *this;
    }
};

class OracleSession {
public:
    virtual ~OracleSession() = default;
    virtual OracleIoStats IoStats() const {
        return {};
    }
    virtual std::unique_ptr<OracleCursor> Query(const std::string &sql, const std::vector<OracleBind> &binds) = 0;
    virtual uint64_t Execute(const std::string &sql, const std::vector<OracleBind> &binds) = 0;
    // One administrative DDL command on a dedicated autocommit session. This
    // must never be used on the metadata runtime transaction.
    virtual void ExecuteAdmin(const std::string &) {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "Oracle session does not implement administrative DDL");
    }
    // Executes the same single DML statement as Execute but guarantees the
    // returned count is Oracle's own SQL%ROWCOUNT rather than a count derived
    // from the DML response. The two are separate operations because they use
    // different wire paths, and only this one carries that guarantee; it is
    // what the public oracle_execute surface promises.
    virtual uint64_t ExecuteWithRowCount(const std::string &sql, const std::vector<OracleBind> &binds) = 0;
    virtual uint64_t ExecuteBatch(const std::string &sql, const std::vector<std::vector<OracleBind>> &rows) = 0;
    // Runs one DML statement that also produces values — Oracle's
    // `RETURNING ... INTO` — and hands back the OUT binds it filled, in the
    // order they were declared. It is a separate operation because it takes the
    // PL/SQL out-bind wire path rather than the plain DML one, and because it
    // runs a single row: the array form of RETURNING has no capture-backed
    // evidence here.
    virtual std::vector<OracleBind> ExecuteReturning(const std::string &sql, const std::vector<OracleBind> &binds) = 0;
    virtual OracleCallResult Call(const OracleCallRequest &request) = 0;
    OracleCallResult Call(const std::string &qualified_name, const std::vector<OracleBind> &arguments) {
        OracleCallRequest request;
        request.qualified_name = qualified_name;
        request.arguments = arguments;
        return Call(request);
    }
    virtual void Commit() = 0;
    virtual void Rollback() = 0;
    virtual void Cancel() = 0;
    virtual void Close() = 0;
    // Whether this session can serve another caller now: open, with no
    // cancel pending, no failed exchange that may have left a response unread,
    // and no statement still open. Only a session that answers true, after a
    // confirmed COMMIT or ROLLBACK, may be handed to the next transaction.
    virtual bool ReadyForReuse() const {
        return false;
    }
    // Points the session at another caller's IO deadline, or at none. Only a
    // session opened with a deadline binding can follow a new caller; it
    // answers false otherwise, and then it must not be reused. The source is
    // taken by value because an override keeps it.
    // NOLINTNEXTLINE(performance-unnecessary-value-param)
    virtual bool BindIoDeadline(std::shared_ptr<OracleIoDeadline>) {
        return false;
    }
};

} // namespace oracle_scanner

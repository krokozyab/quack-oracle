#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

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
};

struct OracleBatch {
    std::vector<OracleColumn> columns;
    std::vector<std::vector<std::optional<std::vector<uint8_t>>>> rows;
    bool exhausted = false;
};

enum class BindDirection { IN, OUT, IN_OUT };

struct OracleBind {
    std::string name;
    uint16_t oracle_type = 0;
    BindDirection direction = BindDirection::IN;
    std::optional<std::vector<uint8_t>> value;
    // Required for scalar OUT / IN OUT values when the input value does not
    // establish a buffer size. REF CURSOR has a fixed wire allocation.
    uint32_t maximum_bytes = 0;
};

class OracleCursor {
public:
    virtual ~OracleCursor() = default;
    virtual const std::vector<OracleColumn> &Columns() const = 0;
    virtual OracleBatch Fetch(size_t requested_rows) = 0;
    virtual void Cancel() = 0;
    virtual void Close() = 0;
};

struct OracleCallResult {
    std::vector<OracleBind> outputs;
    std::vector<std::unique_ptr<OracleCursor>> explicit_cursors;
    std::vector<std::unique_ptr<OracleCursor>> implicit_cursors;
};

enum class OracleCallableKind { PROCEDURE, FUNCTION };

struct OracleCallRequest {
    OracleCallableKind kind = OracleCallableKind::PROCEDURE;
    std::string qualified_name;
    std::optional<OracleBind> return_bind;
    std::vector<OracleBind> arguments;
};

class OracleSession {
public:
    virtual ~OracleSession() = default;
    virtual std::unique_ptr<OracleCursor> Query(const std::string &sql, const std::vector<OracleBind> &binds) = 0;
    virtual uint64_t Execute(const std::string &sql, const std::vector<OracleBind> &binds) = 0;
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
};

} // namespace oracle_scanner

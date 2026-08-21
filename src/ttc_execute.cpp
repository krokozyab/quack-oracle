#include "oracle_scanner/ttc_execute.hpp"
#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_auth.hpp"
#include "oracle_scanner/ttc_row_data.hpp"

#include <algorithm>

namespace oracle_scanner {

namespace {

constexpr size_t MAX_SQL_BYTES = 1U << 20U;
constexpr uint32_t MAX_PREFETCH_ROWS = 1U << 20U;
constexpr uint32_t MAX_BUFFER_BYTES = 16U << 20U;
constexpr uint32_t OALL8_PARSE = 0x01;
constexpr uint32_t OALL8_EXECUTE = 0x20;
constexpr uint32_t OALL8_FETCH = 0x40;
constexpr uint32_t OALL8_BIND = 0x08;
constexpr uint32_t OALL8_NOT_PLSQL = 0x8000;
constexpr uint32_t OALL8_PLSQL_BIND = 0x400;
constexpr uint32_t OALL8_IMPLICIT_RESULTSETS = 0x8000;
constexpr uint8_t TTC_FIELD_VERSION_12_2 = 8;
constexpr uint8_t TTC_FIELD_VERSION_12_2_EXT1 = 9;
constexpr size_t MAX_BINDS = 65535;
// One array-DML request is one TTC message; this keeps it from growing without
// a bound when a caller hands over an arbitrarily long batch. The session
// splits a larger batch into several executes and sums their row counts.
constexpr size_t MAX_ITERATIONS = 4096;

void Validate(const TtcExecuteNoBindsRequest &request) {
    if (request.sql.empty() || request.sql.size() > MAX_SQL_BYTES || request.sql.find('\0') != std::string::npos ||
        request.prefetch_buffer_bytes > MAX_BUFFER_BYTES || request.prefetch_rows == 0 ||
        request.prefetch_rows > MAX_PREFETCH_ROWS || request.maximum_long_bytes == 0 ||
        request.ttc_field_version < TTC_FIELD_VERSION_12_2 || (request.is_query && request.is_plsql)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC bind-free execute request is invalid");
    }
}

// The 12.2 Thin OALL8 capture has five null SQL-signature/SQL-ID fields and,
// for its field-version extension, two further null fields between the
// registration tail and SQL text.  They are positional even when null.
void WriteThinOall8Extension(ByteWriter &writer, uint8_t field_version) {
    writer.WriteByte(0).WriteUB4(0).WriteByte(0).WriteUB4(0).WriteByte(0);
    if (field_version >= TTC_FIELD_VERSION_12_2_EXT1) {
        writer.WriteByte(0).WriteUB4(0);
    }
}

uint32_t BindBufferSize(const OracleBind &bind) {
    if (bind.oracle_type == ORACLE_WIRE_TYPE_CURSOR) {
        return 4;
    }
    if (bind.maximum_bytes != 0) {
        return bind.maximum_bytes;
    }
    if (bind.value) {
        return std::max<uint32_t>(1, static_cast<uint32_t>(bind.value->size()));
    }
    if (bind.direction != BindDirection::BIND_IN) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "scalar Oracle OUT bind must declare maximum_bytes");
    }
    return 1;
}

bool IsCharacterType(uint16_t type) {
    return type == 1 || type == 9 || type == 96;
}

void ValidateBind(const OracleBind &bind) {
    if (bind.oracle_type == 0 || bind.oracle_type > 255 || (bind.value && bind.value->size() > MAX_BUFFER_BYTES)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC bind has invalid type or value size");
    }
    if (bind.oracle_type == ORACLE_WIRE_TYPE_CURSOR && bind.direction == BindDirection::BIND_IN) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC cursor bind must be OUT or IN OUT");
    }
    (void)BindBufferSize(bind);
}

void Validate(const TtcExecuteBindsRequest &request) {
    if (request.sql.empty() || request.sql.size() > MAX_SQL_BYTES || request.sql.find('\0') != std::string::npos ||
        request.binds.empty() || request.binds.size() > MAX_BINDS || request.prefetch_buffer_bytes > MAX_BUFFER_BYTES ||
        request.prefetch_rows == 0 ||
        request.prefetch_rows > MAX_PREFETCH_ROWS || request.maximum_long_bytes == 0 ||
        request.ttc_field_version < TTC_FIELD_VERSION_12_2 || (request.is_query && request.is_plsql)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC bound execute request is invalid");
    }
    for (const auto &bind : request.binds) {
        ValidateBind(bind);
    }
    if (request.additional_iterations.empty()) {
        return;
    }
    if (request.additional_iterations.size() + 1 > MAX_ITERATIONS) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC array DML exceeds its iteration bound");
    }
    if (request.is_query || request.is_plsql) {
        // A PL/SQL array bind is a different wire feature — one bind carrying
        // many elements, flagged TNS_BIND_ARRAY — and a query has no iterations
        // to run. Neither has evidence here, so neither is guessed at.
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                            "TTC array DML applies only to plain SQL DML, not to queries or PL/SQL");
    }
    for (const auto &iteration : request.additional_iterations) {
        if (iteration.size() != request.binds.size()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                "TTC array DML iteration has a different bind count than the first");
        }
        for (size_t index = 0; index < iteration.size(); index++) {
            // The metadata is written once and describes every iteration, so a
            // row that disagrees with it would be decoded by Oracle as the type
            // the first row declared.
            if (iteration[index].oracle_type != request.binds[index].oracle_type ||
                iteration[index].direction != request.binds[index].direction) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                    "TTC array DML iteration disagrees with the declared bind metadata");
            }
            if (iteration[index].direction != BindDirection::BIND_IN) {
                // Every iteration would write into the same OUT buffer, and
                // nothing here has evidence for how Oracle returns the set.
                throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "TTC array DML supports only IN binds");
            }
            ValidateBind(iteration[index]);
        }
    }
}

// One buffer size per bind, wide enough for that bind in every iteration.
// Oracle sizes its server-side buffer from this, so a later row longer than the
// first must still be declared here.
std::vector<uint32_t> IterationBufferSizes(const TtcExecuteBindsRequest &request) {
    std::vector<uint32_t> sizes;
    sizes.reserve(request.binds.size());
    for (const auto &bind : request.binds) {
        sizes.push_back(BindBufferSize(bind));
    }
    for (const auto &iteration : request.additional_iterations) {
        for (size_t index = 0; index < iteration.size(); index++) {
            sizes[index] = (std::max)(sizes[index], BindBufferSize(iteration[index]));
        }
    }
    return sizes;
}

void WriteBindMetadata(ByteWriter &writer, const std::vector<OracleBind> &binds,
                      const std::vector<uint32_t> &buffer_sizes, uint8_t field_version) {
    for (size_t index = 0; index < binds.size(); index++) {
        const auto &bind = binds[index];
        const auto character_type = IsCharacterType(bind.oracle_type);
        writer.WriteByte(static_cast<uint8_t>(bind.oracle_type)).WriteByte(1).WriteByte(0).WriteByte(0);
        // UB8 is one universal-length field, not two UB4 placeholders. The
        // previous four-zero tail inserted two phantom fields before OID and
        // made a bound SELECT's metadata impossible for Oracle to parse.
        writer.WriteUB4(buffer_sizes[index]).WriteUB4(0).WriteUB8(0);
        // The empty object-id slot is a distinct UB4 (encoded as one zero
        // byte). Omitting it shifts version/charset/form by one field; Oracle
        // then reports a nonsensical collation id for character binds.
        writer.WriteUB4(0).WriteUB2(0).WriteUB2(character_type ? 873 : 0).WriteByte(character_type ? 1 : 0).WriteUB4(0);
        // 12.2+ uses a separate OACCOLID after max-character-size even for
        // bind metadata. Its one-byte zero encoding keeps the following
        // ROW_DATA marker aligned with Oracle's bound OALL8 parser.
        if (field_version >= TTC_FIELD_VERSION_12_2) {
            writer.WriteUB4(0);
        }
    }
}

void WriteBindValues(ByteWriter &writer, const std::vector<OracleBind> &binds) {
    writer.WriteByte(TTC_MESSAGE_ROW_DATA);
    for (const auto &bind : binds) {
        if (bind.oracle_type == ORACLE_WIRE_TYPE_CURSOR) {
            // OUT SYS_REFCURSOR has metadata but no client-side value.
            writer.WriteByte(0);
        } else if (bind.value) {
            writer.WriteLengthPrefixed(*bind.value);
        } else {
            writer.WriteByte(0);
        }
    }
}

} // namespace

std::vector<uint8_t> EncodeTtcExecuteNoBindsRequest(const TtcExecuteNoBindsRequest &request) {
    Validate(request);
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_FUNCTION).WriteByte(TTC_FUNCTION_EXECUTE).WriteByte(request.sequence);
    uint32_t core_options = OALL8_PARSE | OALL8_EXECUTE;
    if (request.is_query) {
        core_options |= OALL8_FETCH | OALL8_IMPLICIT_RESULTSETS;
    }
    if (!request.is_plsql) {
        core_options |= OALL8_NOT_PLSQL;
    }
    writer.WriteUB4(request.options | core_options).WriteUB4(0); // fresh cursor id
    writer.WriteByte(1);                           // SQL text is present
    writer.WriteUB4(static_cast<uint32_t>(request.sql.size()));
    writer.WriteByte(1); // al8i4 vector is present
    writer.WriteUB4(13); // number of al8i4 words
    writer.WriteByte(0).WriteByte(0); // al8o4 and al8o4l pointers
    writer.WriteUB4(request.prefetch_buffer_bytes).WriteUB4(request.prefetch_rows);
    writer.WriteUB4(request.maximum_long_bytes).WriteByte(0); // no bind descriptors
    writer.WriteUB4(0);                                       // bind count
    writer.WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0); // transaction/vector auxiliaries
    writer.WriteByte(0); // al8doac pointer
    writer.WriteUB4(0); // define count
    writer.WriteUB4(0); // registration id LSB
    writer.WriteByte(0).WriteByte(0).WriteByte(0).WriteUB4(0).WriteByte(0).WriteUB4(0).WriteUB4(0);
    writer.WriteByte(0).WriteUB4(0).WriteByte(0); // array-DML and registration tail
    WriteThinOall8Extension(writer, request.ttc_field_version);
    writer.WriteLengthPrefixed(std::vector<uint8_t>(request.sql.begin(), request.sql.end()));
    writer.WriteUB4(1); // al8i4[0]: SQL must be parsed on a fresh cursor
    writer.WriteUB4(request.is_query ? 0 : 1); // al8i4[1]: query prefetch vs one DML/PLSQL iteration
    for (size_t index = 2; index < 13; index++) {
        writer.WriteUB4(index == 7 && request.is_query ? 1 : (index == 9 ? OALL8_IMPLICIT_RESULTSETS : 0));
    }
    return writer.Take();
}

std::vector<uint8_t> EncodeTtcExecuteBindsRequest(const TtcExecuteBindsRequest &request) {
    Validate(request);
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_FUNCTION).WriteByte(TTC_FUNCTION_EXECUTE).WriteByte(request.sequence);
    uint32_t options = OALL8_PARSE | OALL8_EXECUTE | OALL8_BIND;
    if (request.is_query) {
        options |= OALL8_FETCH | OALL8_IMPLICIT_RESULTSETS;
    }
    if (request.is_plsql) {
        options |= OALL8_PLSQL_BIND;
    } else {
        options |= OALL8_NOT_PLSQL;
    }
    writer.WriteUB4(options).WriteUB4(0).WriteByte(1).WriteUB4(static_cast<uint32_t>(request.sql.size()));
    writer.WriteByte(1).WriteUB4(13).WriteByte(0).WriteByte(0);
    writer.WriteUB4(request.prefetch_buffer_bytes).WriteUB4(request.prefetch_rows).WriteUB4(request.maximum_long_bytes);
    writer.WriteByte(1).WriteUB4(static_cast<uint32_t>(request.binds.size()));
    writer.WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0);
    writer.WriteByte(0).WriteUB4(0).WriteUB4(0);
    // Python Thin's bound OALL8 carries the second registration/vector
    // pointer; it is positional even though its following payload is null.
    writer.WriteByte(0).WriteByte(1).WriteByte(0).WriteUB4(0).WriteByte(0).WriteUB4(0).WriteUB4(0);
    writer.WriteByte(0).WriteUB4(0).WriteByte(0);
    WriteThinOall8Extension(writer, request.ttc_field_version);
    writer.WriteLengthPrefixed(std::vector<uint8_t>(request.sql.begin(), request.sql.end()));
    // al8i4[1] is the execution count: one DML iteration, or as many as the
    // batch carries. A query leaves it zero.
    writer.WriteUB4(1).WriteUB4(request.is_query
                                    ? 0
                                    : static_cast<uint32_t>(1 + request.additional_iterations.size()));
    for (size_t index = 2; index < 13; index++) {
        writer.WriteUB4(index == 7 && request.is_query ? 1 : (index == 9 ? OALL8_IMPLICIT_RESULTSETS : 0));
    }
    WriteBindMetadata(writer, request.binds, IterationBufferSizes(request), request.ttc_field_version);
    // One ROW_DATA message per iteration, in order. This is the whole of array
    // DML on the wire: the same parse, the same metadata, N rows of values.
    WriteBindValues(writer, request.binds);
    for (const auto &iteration : request.additional_iterations) {
        WriteBindValues(writer, iteration);
    }
    return writer.Take();
}

} // namespace oracle_scanner

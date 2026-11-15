#include "oracle_scanner/ttc_lob.hpp"

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_piggyback.hpp"
#include "oracle_scanner/ttc_error.hpp"
#include "oracle_scanner/ttc_transaction.hpp"
#include "oracle_scanner/ttc_auth.hpp"
#include "oracle_scanner/ttc_parameter.hpp"

namespace oracle_scanner {

namespace {

constexpr size_t MAX_LOCATOR_BYTES = 4096;
constexpr size_t MAX_LOB_CHUNK_BYTES = 16U << 20U;
constexpr size_t MAX_FREE_LOCATORS = 4096;
constexpr uint8_t TTC_MESSAGE_LOB_END_OF_REQUEST = 29;


// What follows a LOB operation's return parameter: the end-of-call, and only a
// whole one says the server is done. Nothing after the parameter, or part of an
// end-of-call, means more of the response is still to come — not that it ended.
// A refusal there is the server rejecting the operation (a stale locator, a
// missing privilege) and has to reach the caller.
size_t CompleteLobCall(const std::vector<uint8_t> &response, size_t offset, uint8_t server_field_version) {
    bool completed = false;
    while (offset < response.size()) {
        const std::vector<uint8_t> tail(response.begin() + static_cast<std::ptrdiff_t>(offset), response.end());
        switch (tail.front()) {
        case TTC_MESSAGE_ERROR: {
            const auto completion = DecodeTtcErrorPrefix(tail, server_field_version);
            if (completion.error_number != 0) {
                throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                                    completion.message.empty() ? "Oracle refused a LOB operation" : completion.message,
                                    completion.error_number);
            }
            offset += completion.bytes_consumed;
            completed = true;
            break;
        }
        case TTC_MESSAGE_STATUS: {
            ByteReader reader(tail);
            reader.ReadByte();
            reader.ReadUB4();
            reader.ReadUB2();
            offset += reader.Position();
            completed = true;
            break;
        }
        case TTC_MESSAGE_LOB_END_OF_REQUEST:
            offset++;
            completed = true;
            break;
        case TTC_MESSAGE_SERVER_PIGGYBACK:
            offset += SkippedTtcServerPiggybackBytes(tail.data(), tail.size());
            break;
        default:
            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                "unknown TTC message " + std::to_string(tail.front()) + " after a LOB return parameter");
        }
    }
    if (!completed) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED, "TTC LOB response has no end-of-call yet");
    }
    return offset;
}

// The fixed part every LOB_OP request shares, in the order a server has to read
// it. Offsets are UB8s whose meaning depends on the operation: a read or write
// puts the LOB position in the source offset, while CREATE_TEMP puts the
// character-set form there and the type number in the destination offset.
struct LobHeader {
    uint8_t sequence = 1;
    size_t source_locator_bytes = 0;
    uint32_t destination_length = 0;
    bool create_temp = false;
    uint32_t operation = 0;
    uint64_t source_offset = 0;
    uint64_t destination_offset = 0;
};

ByteWriter WriteLobHeader(const LobHeader &header) {
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_FUNCTION).WriteByte(TTC_FUNCTION_LOB_OP).WriteByte(header.sequence);
    writer.WriteByte(1).WriteUB4(static_cast<uint32_t>(header.source_locator_bytes)); // source locator
    writer.WriteByte(0).WriteUB4(header.destination_length);                         // destination locator
    writer.WriteUB4(0).WriteUB4(0);                                                  // short source, short dest offset
    writer.WriteByte(header.create_temp ? 1 : 0).WriteByte(0).WriteByte(header.create_temp ? 1 : 0);
    writer.WriteUB4(header.operation);
    writer.WriteByte(0).WriteByte(0);                                                // SCN array pointer and length
    writer.WriteUB8(header.source_offset).WriteUB8(header.destination_offset);
    writer.WriteByte(0);                                                             // no amount pointer
    writer.WriteUInt16BE(0).WriteUInt16BE(0).WriteUInt16BE(0);                       // array-LOB fields, unused
    return writer;
}

// The character set a temporary CLOB is created in. python-oracledb Thin sends
// UTF-8 for a CLOB and UTF-16 for an NCLOB; what it stores is AL16UTF16 either
// way, which is why a CLOB's content is written as UTF-16BE.
constexpr uint32_t TEMP_LOB_CHARSET_UTF8 = 873;
constexpr uint32_t TEMP_LOB_CHARSET_UTF16 = 2000;
// The lifetime of a temporary LOB: until the session ends.
constexpr uint32_t TEMP_LOB_DURATION_SESSION = 10;

} // namespace

// The field order is the one a server has to read to recover the operation,
// locator, offset and amount; the pointer/length pairs in between are present
// even when null, because the layout is positional.
std::vector<uint8_t> EncodeTtcLobRequest(const TtcLobRequest &request) {
    if (request.locator.empty() || request.locator.size() > MAX_LOCATOR_BYTES) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC LOB request has an invalid locator");
    }
    if (request.offset == 0) {
        // Oracle counts a LOB from 1. A zero offset is a caller's off-by-one,
        // and asking the server to reject it would cost a round trip.
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC LOB offsets are 1-based");
    }
    if (request.amount > MAX_LOB_CHUNK_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC LOB request amount is too large");
    }
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_FUNCTION).WriteByte(TTC_FUNCTION_LOB_OP).WriteByte(request.sequence);
    writer.WriteByte(1).WriteUB4(static_cast<uint32_t>(request.locator.size())); // source locator
    writer.WriteByte(0).WriteUB4(0);                                            // destination locator
    writer.WriteUB4(0).WriteUB4(0);                                             // short source, short dest offset
    writer.WriteByte(0).WriteByte(0).WriteByte(0);                              // charset, short amount, null lob
    writer.WriteUB4(request.operation);
    writer.WriteByte(0).WriteByte(0);                                           // SCN array pointer and length
    writer.WriteUB8(request.offset).WriteUB8(0);                                // source and destination offset
    writer.WriteByte(1); // amount pointer
    writer.WriteUInt16BE(0).WriteUInt16BE(0).WriteUInt16BE(0);                  // array-LOB fields, unused
    writer.WriteRaw(request.locator);
    writer.WriteUB8(request.amount);
    return writer.Take();
}

TtcLobResponse DecodeTtcLobResponse(const std::vector<uint8_t> &message, size_t locator_size) {
    if (locator_size == 0 || locator_size > MAX_LOCATOR_BYTES) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC LOB response decoder has an invalid locator size");
    }
    ByteReader reader(message);
    TtcLobResponse result;
    if (reader.Remaining() == 0) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED, "TTC LOB response is empty");
    }
    if (reader.PeekByte() == TTC_MESSAGE_LOB_DATA) {
        reader.ReadByte();
        const auto data = reader.ReadLengthPrefixed(MAX_LOB_CHUNK_BYTES);
        if (data) {
            result.data = *data;
        }
    }
    // The return parameter echoes the locator and then says how much the server
    // served. A read that returns nothing still carries it, which is how the
    // end of a LOB is recognised without asking for its length first.
    if (reader.Remaining() == 0) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED, "TTC LOB response has no return parameter");
    }
    if (reader.ReadByte() != TTC_MESSAGE_PARAMETER) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected a TTC return parameter after LOB data");
    }
    reader.Skip(locator_size);
    result.amount = reader.ReadUB8();
    result.bytes_consumed = reader.Position();
    return result;
}

TtcLobResponse DecodeCompleteTtcLobCall(const std::vector<uint8_t> &response, size_t locator_size,
                                        uint8_t server_field_version) {
    if (response.empty()) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED, "TTC LOB response is empty");
    }
    // A refused read answers with the end-of-call and nothing else, so this has
    // to be looked for before the data is decoded. Decoding first turns the
    // server's own reason into a complaint about the shape of its refusal. An
    // end-of-call cut short reads as TRUNCATED from the decoder itself.
    if (IsTtcErrorMessage(response)) {
        const auto completion = DecodeTtcErrorPrefix(response, server_field_version);
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                            completion.message.empty() ? "Oracle refused a LOB read" : completion.message,
                            completion.error_number);
    }
    auto decoded = DecodeTtcLobResponse(response, locator_size);
    decoded.bytes_consumed = CompleteLobCall(response, decoded.bytes_consumed, server_field_version);
    return decoded;
}

std::vector<uint8_t> DecodeUtf16BeToUtf8(OracleByteView utf16) {
    if (utf16.size() % 2 != 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "a CLOB read returned an odd number of UTF-16 bytes");
    }
    std::vector<uint8_t> result;
    result.reserve(utf16.size());
    const auto append = [&result](uint32_t code_point) {
        if (code_point < 0x80) {
            result.push_back(static_cast<uint8_t>(code_point));
        } else if (code_point < 0x800) {
            result.push_back(static_cast<uint8_t>(0xC0U | (code_point >> 6U)));
            result.push_back(static_cast<uint8_t>(0x80U | (code_point & 0x3FU)));
        } else if (code_point < 0x10000) {
            result.push_back(static_cast<uint8_t>(0xE0U | (code_point >> 12U)));
            result.push_back(static_cast<uint8_t>(0x80U | ((code_point >> 6U) & 0x3FU)));
            result.push_back(static_cast<uint8_t>(0x80U | (code_point & 0x3FU)));
        } else {
            result.push_back(static_cast<uint8_t>(0xF0U | (code_point >> 18U)));
            result.push_back(static_cast<uint8_t>(0x80U | ((code_point >> 12U) & 0x3FU)));
            result.push_back(static_cast<uint8_t>(0x80U | ((code_point >> 6U) & 0x3FU)));
            result.push_back(static_cast<uint8_t>(0x80U | (code_point & 0x3FU)));
        }
    };
    for (size_t index = 0; index + 1 < utf16.size(); index += 2) {
        const uint32_t unit = (static_cast<uint32_t>(utf16[index]) << 8U) | utf16[index + 1];
        if (unit >= 0xD800 && unit <= 0xDBFF) {
            // A high surrogate must be followed by its low half. An unpaired
            // one is not a character, and guessing a replacement would put
            // bytes in a column that the database does not hold.
            if (index + 3 >= utf16.size()) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "a CLOB read ended on an unpaired UTF-16 surrogate");
            }
            const uint32_t low = (static_cast<uint32_t>(utf16[index + 2]) << 8U) | utf16[index + 3];
            if (low < 0xDC00 || low > 0xDFFF) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "a CLOB read carried an unpaired UTF-16 surrogate");
            }
            append(0x10000U + ((unit - 0xD800U) << 10U) + (low - 0xDC00U));
            index += 2;
            continue;
        }
        if (unit >= 0xDC00 && unit <= 0xDFFF) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "a CLOB read carried a low UTF-16 surrogate first");
        }
        append(unit);
    }
    return result;
}

std::vector<uint8_t> EncodeUtf8ToUtf16Be(const std::string &utf8) {
    std::vector<uint8_t> result;
    result.reserve(utf8.size() * 2);
    const auto put = [&result](uint32_t unit) {
        result.push_back(static_cast<uint8_t>(unit >> 8U));
        result.push_back(static_cast<uint8_t>(unit & 0xFFU));
    };
    const auto malformed = [] { throw ProtocolError(ProtocolErrorKind::MALFORMED, "text is not valid UTF-8"); };
    size_t index = 0;
    while (index < utf8.size()) {
        const auto lead = static_cast<uint8_t>(utf8[index]);
        uint32_t code_point = 0;
        size_t extra = 0;
        uint32_t minimum = 0;
        if (lead < 0x80) {
            code_point = lead;
        } else if (lead >= 0xC2 && lead <= 0xDF) {
            code_point = lead & 0x1FU;
            extra = 1;
            minimum = 0x80;
        } else if (lead >= 0xE0 && lead <= 0xEF) {
            code_point = lead & 0x0FU;
            extra = 2;
            minimum = 0x800;
        } else if (lead >= 0xF0 && lead <= 0xF4) {
            code_point = lead & 0x07U;
            extra = 3;
            minimum = 0x10000;
        } else {
            malformed();
        }
        if (extra != 0 && index + extra >= utf8.size()) {
            malformed();
        }
        for (size_t step = 1; step <= extra; step++) {
            const auto next = static_cast<uint8_t>(utf8[index + step]);
            if ((next & 0xC0U) != 0x80U) {
                malformed();
            }
            code_point = (code_point << 6U) | (next & 0x3FU);
        }
        if (code_point < minimum || code_point > 0x10FFFF || (code_point >= 0xD800 && code_point <= 0xDFFF)) {
            malformed();
        }
        if (code_point >= 0x10000) {
            const auto offset = code_point - 0x10000U;
            put(0xD800U + (offset >> 10U));
            put(0xDC00U + (offset & 0x3FFU));
        } else {
            put(code_point);
        }
        index += extra + 1;
    }
    return result;
}


std::vector<uint8_t> EncodeTtcCreateTempLob(uint8_t sequence, TtcTempLobKind kind) {
    LobHeader header;
    header.sequence = sequence;
    header.source_locator_bytes = LOB_LOCATOR_BYTES;
    header.destination_length = TEMP_LOB_DURATION_SESSION;
    header.create_temp = true;
    header.operation = LOB_OP_CREATE_TEMP;
    header.source_offset = kind == TtcTempLobKind::BLOB ? 0 : (kind == TtcTempLobKind::NCLOB ? 2 : 1);
    header.destination_offset = kind == TtcTempLobKind::BLOB ? 113 : 112;
    auto writer = WriteLobHeader(header);
    writer.WriteRaw(std::vector<uint8_t>(LOB_LOCATOR_BYTES, 0));
    writer.WriteUB4(kind == TtcTempLobKind::NCLOB ? TEMP_LOB_CHARSET_UTF16 : TEMP_LOB_CHARSET_UTF8);
    return writer.Take();
}

std::vector<uint8_t> EncodeTtcWriteLob(uint8_t sequence, const std::vector<uint8_t> &locator, uint64_t offset,
                                       const std::vector<uint8_t> &data) {
    if (locator.size() != LOB_LOCATOR_BYTES || offset == 0 || data.empty() || data.size() > MAX_LOB_CHUNK_BYTES) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC LOB write has an invalid locator, offset or size");
    }
    LobHeader header;
    header.sequence = sequence;
    header.source_locator_bytes = locator.size();
    header.operation = LOB_OP_WRITE;
    header.source_offset = offset;
    auto writer = WriteLobHeader(header);
    writer.WriteRaw(locator);
    writer.WriteByte(TTC_MESSAGE_LOB_DATA);
    writer.WriteLengthPrefixed(data);
    return writer.Take();
}

std::vector<uint8_t> EncodeTtcFreeTempLobs(uint8_t sequence, const std::vector<std::vector<uint8_t>> &locators) {
    if (locators.empty() || locators.size() > MAX_FREE_LOCATORS) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC temporary LOB release has an invalid locator count");
    }
    LobHeader header;
    header.sequence = sequence;
    header.source_locator_bytes = locators.size() * LOB_LOCATOR_BYTES;
    header.operation = LOB_OP_FREE_TEMP | LOB_OP_ARRAY;
    auto writer = WriteLobHeader(header);
    for (const auto &locator : locators) {
        if (locator.size() != LOB_LOCATOR_BYTES) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC temporary LOB release has an invalid locator");
        }
        writer.WriteRaw(locator);
    }
    return writer.Take();
}

std::vector<uint8_t> DecodeCompleteTtcLocatorCall(const std::vector<uint8_t> &response, size_t locator_count,
                                                  bool created, uint8_t server_field_version) {
    if (response.empty()) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED, "TTC LOB response is empty");
    }
    if (IsTtcErrorMessage(response)) {
        const auto completion = DecodeTtcErrorPrefix(response, server_field_version);
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                            completion.message.empty() ? "Oracle refused a LOB operation" : completion.message,
                            completion.error_number);
    }
    size_t offset = 0;
    std::vector<uint8_t> locator;
    if (response.front() == TTC_MESSAGE_PARAMETER) {
        ByteReader reader(response);
        reader.ReadByte();
        const auto bytes = locator_count * LOB_LOCATOR_BYTES;
        locator = reader.ReadRaw(bytes);
        if (created) {
            // The character set the server chose, and a flags byte.
            reader.ReadUB2();
            reader.ReadByte();
        }
        offset = reader.Position();
    } else if (locator_count != 0 && created) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC CREATE_TEMP response has no locator");
    }
    (void)CompleteLobCall(response, offset, server_field_version);
    return locator;
}

} // namespace oracle_scanner

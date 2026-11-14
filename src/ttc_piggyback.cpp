#include "oracle_scanner/ttc_piggyback.hpp"
#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"

namespace oracle_scanner {

std::vector<uint8_t> EncodeTtcCloseCursorsPiggyback(uint8_t sequence, const std::vector<uint32_t> &cursor_ids) {
    if (cursor_ids.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC CLOSE_CURSORS piggyback has no cursor ids");
    }
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_PIGGYBACK).WriteByte(TTC_PIGGYBACK_CLOSE_CURSORS).WriteByte(sequence);
    // Python Thin capture (Oracle 19c) uses the non-null collection pointer
    // here: 11 69 <seq> 01 <count> <cursor ids>. A null marker makes 19c
    // discard the session before it reaches the following function call.
    writer.WriteByte(1).WriteUB4(static_cast<uint32_t>(cursor_ids.size()));
    for (const auto cursor_id : cursor_ids) {
        if (cursor_id == 0) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC CLOSE_CURSORS piggyback has a zero cursor id");
        }
        writer.WriteUB4(cursor_id);
    }
    return writer.Take();
}

std::vector<uint8_t> EncodeTtcEndToEndPiggyback(uint8_t sequence, const TtcEndToEndAttributes &attributes) {
    if (attributes.Empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC end-to-end piggyback has no attribute");
    }
    const auto check = [](const std::optional<std::string> &value, size_t maximum, const char *name) {
        if (value && value->size() > maximum) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,
                                std::string("Oracle ") + name + " is longer than " + std::to_string(maximum) + " bytes");
        }
    };
    check(attributes.client_identifier, TTC_CLIENT_IDENTIFIER_MAXIMUM, "CLIENT_IDENTIFIER");
    check(attributes.module, TTC_MODULE_MAXIMUM, "MODULE");
    check(attributes.action, TTC_ACTION_MAXIMUM, "ACTION");
    check(attributes.client_info, TTC_CLIENT_INFO_MAXIMUM, "CLIENT_INFO");
    // Setting the module resets the action, so the action is always sent with it.
    auto action = attributes.action;
    if (attributes.module && !action) {
        action = std::string();
    }
    uint32_t flags = 0;
    if (attributes.client_identifier) {
        flags |= 0x01;
    }
    if (attributes.module) {
        flags |= 0x08;
    }
    if (action) {
        flags |= 0x10;
    }
    if (attributes.client_info) {
        flags |= 0x100;
    }
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_PIGGYBACK).WriteByte(TTC_PIGGYBACK_END_TO_END).WriteByte(sequence);
    writer.WriteByte(0).WriteByte(0).WriteUB4(flags);
    const auto declare = [&writer](const std::optional<std::string> &value) {
        if (value) {
            writer.WriteByte(1).WriteUB4(static_cast<uint32_t>(value->size()));
        } else {
            writer.WriteByte(0).WriteUB4(0);
        }
    };
    declare(attributes.client_identifier);
    declare(attributes.module);
    declare(action);
    writer.WriteByte(0).WriteByte(0).WriteByte(0).WriteByte(0);
    declare(attributes.client_info);
    for (size_t index = 0; index < 6; index++) {
        writer.WriteByte(0);
    }
    const std::optional<std::string> &const_action = action;
    for (const auto *value : {&attributes.client_identifier, &attributes.module, &const_action, &attributes.client_info}) {
        if (*value && !(*value)->empty()) {
            writer.WriteLengthPrefixed(std::vector<uint8_t>((*value)->begin(), (*value)->end()));
        }
    }
    return writer.Take();
}

size_t SkippedTtcServerPiggybackBytes(const uint8_t *data, size_t size) {
    // The opcodes and their layouts as python-oracledb Thin and rust-oracledb
    // read them; the two agree field for field. Only SYNC (5) is in a capture of
    // this client's (19c, after the end-to-end attributes change); LTXID (7)
    // was seen live on 23ai Free, sent with a COMMIT on a service with
    // Transaction Guard. Each is skipped: nothing in them is used here.
    constexpr uint8_t QUERY_CACHE_INVALIDATION = 1;
    constexpr uint8_t OS_PID_MTS = 2;
    constexpr uint8_t TRACE_EVENT = 3;
    constexpr uint8_t SESSION_RETURN = 4;
    constexpr uint8_t SYNC = 5;
    constexpr uint8_t LTXID = 7;
    constexpr uint8_t AC_REPLAY_CONTEXT = 8;
    constexpr uint8_t EXT_SYNC = 9;
    constexpr uint8_t SESSION_SIGNATURE = 10;
    constexpr size_t MAX_ELEMENTS = 1024;
    constexpr size_t MAX_VALUE_BYTES = 64U << 10U;
    if (size == 0 || data[0] != TTC_MESSAGE_SERVER_PIGGYBACK) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected a TTC server piggyback");
    }
    ByteReader reader(data, size);
    reader.ReadByte();
    const auto opcode = reader.ReadByte();
    // A key and a value, each length-prefixed when present, and a flags field.
    const auto skip_pairs = [&](size_t elements) {
        if (elements > MAX_ELEMENTS) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC server piggyback has too many entries");
        }
        for (size_t index = 0; index < elements; index++) {
            if (reader.ReadUB2() > 0) {
                (void)reader.ReadLengthPrefixed(MAX_VALUE_BYTES);
            }
            if (reader.ReadUB2() > 0) {
                (void)reader.ReadLengthPrefixed(MAX_VALUE_BYTES);
            }
            reader.ReadUB2();
        }
    };
    // A UB4 length and, when it is not zero, the bytes with their own prefix.
    const auto skip_long_bytes = [&]() {
        if (reader.ReadUB4() > 0) {
            (void)reader.ReadLengthPrefixed(MAX_VALUE_BYTES);
        }
    };
    switch (opcode) {
    case QUERY_CACHE_INVALIDATION:
    case TRACE_EVENT:
        break;
    case OS_PID_MTS:
        reader.ReadUB2();
        (void)reader.ReadLengthPrefixed(MAX_VALUE_BYTES);
        break;
    case SYNC: {
        // The report of the session attributes just set, listing the values the
        // server now holds; it only echoes what the client sent.
        reader.ReadUB2(); // data types
        reader.ReadByte();
        const auto elements = reader.ReadUB2();
        reader.ReadByte();
        skip_pairs(elements);
        if (reader.ReadUB4() != 0) {
            throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "TTC session-return report carries a session change");
        }
        break;
    }
    case SESSION_RETURN: {
        reader.ReadUB2();
        reader.ReadByte();
        const auto elements = reader.ReadUB2();
        if (elements > 0) {
            reader.ReadByte();
            skip_pairs(elements);
        }
        reader.ReadUB4(); // flags
        reader.ReadUB4(); // session id
        reader.ReadUB2(); // serial number
        break;
    }
    case LTXID:
        // Transaction Guard's logical transaction id, sent with a COMMIT.
        skip_long_bytes();
        break;
    case AC_REPLAY_CONTEXT:
        // Application Continuity's replay context.
        reader.ReadUB2();
        reader.ReadByte();
        reader.ReadUB4(); // flags
        reader.ReadUB4(); // error code
        reader.ReadByte(); // queue
        skip_long_bytes();
        break;
    case EXT_SYNC:
        reader.ReadUB2();
        reader.ReadByte();
        break;
    case SESSION_SIGNATURE:
        reader.ReadUB2();
        reader.ReadByte();
        reader.ReadUB8(); // flags
        reader.ReadUB8(); // client signature
        reader.ReadUB8(); // server signature
        break;
    default:
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                            "TTC server piggyback " + std::to_string(opcode) + " is not supported");
    }
    return reader.Position();
}

size_t SkipTtcServerPiggyback(const std::vector<uint8_t> &message, size_t offset) {
    if (offset > message.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected a TTC server piggyback");
    }
    return offset + SkippedTtcServerPiggybackBytes(message.data() + offset, message.size() - offset);
}

} // namespace oracle_scanner

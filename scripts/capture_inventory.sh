#!/usr/bin/env bash
#
# Inventories the captured wire bytes that live in this repository.
#
# The project's rule is that no wire behavior ships without capture-backed
# evidence, and the corresponding obligation is that the evidence itself is
# accounted for: what it is, which server produced it, and a hash that says it
# has not drifted since it was written down. Without that, a fixture edited to
# make a test pass is indistinguishable from a fixture that records what a
# server actually sent.
#
# Prints `sha256  name  file` for every named capture. PROVENANCE.md holds the
# expected values and what each capture is; compare the two after touching a
# fixture, and if a hash moved, say why in PROVENANCE.md rather than restating
# the new number.

set -euo pipefail

hash_of() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | cut -d' ' -f1
    else
        sha256sum | cut -d' ' -f1
    fi
}

# Each entry is name:file:first-line:last-line, and the line range covers the
# initializer exactly. The ranges are checked below: a shifted range would
# silently hash the wrong bytes, which is the one failure this must not have.
inventory() {
    /usr/bin/python3 - "$@" <<'PYTHON'
import re
import sys

# name -> (file, the C++ identifier whose initializer holds the bytes)
captures = [
    ("zero_width_two_columns", "test/cpp/protocol_test.cpp", "mixed"),
    ("zero_width_one_column", "test/cpp/protocol_test.cpp", "lone"),
    ("repeated_rows_fetch", "test/cpp/protocol_test.cpp", "repeated"),
    ("dml_end_of_call_one_row", "test/cpp/protocol_test.cpp", "completion"),
    ("dml_end_of_call_three_rows", "test/cpp/protocol_test.cpp", "batched"),
    ("ttidty_negotiation_table", "src/include/oracle_scanner/ttc_data_types_template.hpp",
     "ORACLE_19C_TTC_DATA_TYPES_TEMPLATE"),
    ("lob_row_one_clob", "test/cpp/protocol_test.cpp", "lob_row_one_clob"),
    ("jdbc_lob_prefetch_define_char", "test/cpp/protocol_test.cpp", "jdbc_lob_prefetch_define_char"),
    ("lob_rows_with_bit_vector", "test/cpp/protocol_test.cpp", "lob_rows_with_bit_vector"),
    ("lob_get_length_response", "test/cpp/protocol_test.cpp", "lob_get_length_response"),
    ("lob_read_clob_response", "test/cpp/protocol_test.cpp", "lob_read_clob_response"),
    ("lob_read_blob_response", "test/cpp/protocol_test.cpp", "lob_read_blob_response"),
    ("plain_rowid_fetch", "test/cpp/protocol_test.cpp", "plain_rowid_fetch"),
    ("physical_urowid_fetch", "test/cpp/protocol_test.cpp", "physical_urowid_fetch"),
    ("logical_urowid_fetch", "test/cpp/protocol_test.cpp", "logical_urowid_fetch"),
    ("long_fetch", "test/cpp/protocol_test.cpp", "long_fetch"),
    ("long_raw_fetch", "test/cpp/protocol_test.cpp", "long_raw_fetch"),
    ("long_middle_fetch", "test/cpp/protocol_test.cpp", "long_middle_fetch"),
    ("interval_ym_value_bytes", "test/cpp/protocol_test.cpp", "interval_ym_value_bytes"),
    ("interval_ds_value_bytes", "test/cpp/protocol_test.cpp", "interval_ds_value_bytes"),
    ("nvarchar_value_bytes", "test/cpp/protocol_test.cpp", "nvarchar_value_bytes"),
    ("boolean_value_bytes", "test/cpp/protocol_test.cpp", "boolean_value_bytes"),
    ("ltz_value_bytes", "test/cpp/protocol_test.cpp", "ltz_value_bytes"),
    ("python_nchar_bind", "test/cpp/protocol_test.cpp", "python_nchar_bind"),
    ("python_nvarchar_bind", "test/cpp/protocol_test.cpp", "python_nvarchar_bind"),
    ("python_boolean_bind", "test/cpp/protocol_test.cpp", "python_boolean_bind"),
    ("python_interval_ds_bind", "test/cpp/protocol_test.cpp", "python_interval_ds_bind"),
    ("python_long_bind_row", "test/cpp/protocol_test.cpp", "python_long_bind_row"),
    ("oson_nested_object", "test/cpp/protocol_test.cpp", "oson_nested_object"),
    ("oson_shared_fields", "test/cpp/protocol_test.cpp", "oson_shared_fields"),
    ("oson_u16_count", "test/cpp/protocol_test.cpp", "oson_u16_count"),
    ("oson_text_and_numbers", "test/cpp/protocol_test.cpp", "oson_text_and_numbers"),
    ("oson_native_scalars", "test/cpp/protocol_test.cpp", "oson_native_scalars"),
    ("oson_long_field_name", "test/cpp/protocol_test.cpp", "oson_long_field_name"),
    ("oson_embedded_vectors", "test/cpp/protocol_test.cpp", "oson_embedded_vectors"),
    ("vector_float32_value", "test/cpp/protocol_test.cpp", "vector_float32_value"),
    ("vector_int8_value", "test/cpp/protocol_test.cpp", "vector_int8_value"),
    ("vector_binary_value", "test/cpp/protocol_test.cpp", "vector_binary_value"),
    ("vector_float64_value", "test/cpp/protocol_test.cpp", "vector_float64_value"),
    ("vector_sparse_value", "test/cpp/protocol_test.cpp", "vector_sparse_value"),
    ("python_inline_define_json", "test/cpp/protocol_test.cpp", "python_inline_define_json"),
    ("python_inline_define_mixed", "test/cpp/protocol_test.cpp", "python_inline_define_mixed"),
    ("python_inline_rows_mixed", "test/cpp/protocol_test.cpp", "python_inline_rows_mixed"),
    ("python_vector_float32_bind", "test/cpp/protocol_test.cpp", "python_vector_float32_bind"),
    ("python_vector_int8_bind", "test/cpp/protocol_test.cpp", "python_vector_int8_bind"),
    ("python_vector_sparse_bind", "test/cpp/protocol_test.cpp", "python_vector_sparse_bind"),
    ("python_vector_update_row", "test/cpp/protocol_test.cpp", "python_vector_update_row"),
    ("python_lob_create_temp_clob", "test/cpp/protocol_test.cpp", "python_lob_create_temp_clob"),
    ("python_lob_create_temp_blob", "test/cpp/protocol_test.cpp", "python_lob_create_temp_blob"),
    ("python_lob_create_temp_response", "test/cpp/protocol_test.cpp", "python_lob_create_temp_response"),
    ("python_lob_write_clob_request", "test/cpp/protocol_test.cpp", "python_lob_write_clob_request"),
    ("python_lob_write_response", "test/cpp/protocol_test.cpp", "python_lob_write_response"),
    ("python_lob_free_piggyback", "test/cpp/protocol_test.cpp", "python_lob_free_piggyback"),
    ("python_lob_locator_binds", "test/cpp/protocol_test.cpp", "python_lob_locator_binds"),
    ("python_end_to_end_module", "test/cpp/protocol_test.cpp", "python_end_to_end_module"),
    ("python_end_to_end_all", "test/cpp/protocol_test.cpp", "python_end_to_end_all"),
    ("python_end_to_end_client_info", "test/cpp/protocol_test.cpp", "python_end_to_end_client_info"),
    ("python_server_piggyback", "test/cpp/protocol_test.cpp", "python_server_piggyback"),
]

for name, path, identifier in captures:
    text = open(path).read()
    match = re.search(re.escape(identifier) + r"\s*(?:\[\s*\])?\s*(?:=\s*)?\{", text)
    if not match:
        sys.stderr.write("capture_inventory: %s not found in %s\n" % (identifier, path))
        sys.exit(2)
    start = match.end()
    depth = 1
    index = start
    while depth and index < len(text):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
        index += 1
    body = text[start:index - 1]
    values = re.findall(r"0[xX][0-9a-fA-F]{1,2}|(?<![\w.])\d{1,3}(?![\w.])|'(?:\\.|[^'\\])'", body)
    data = bytearray()
    for value in values:
        if value.startswith("'"):
            literal = value[1:-1]
            data.append(ord({"\\n": "\n", "\\r": "\r", "\\t": "\t", "\\0": "\0"}.get(literal, literal[-1])))
        else:
            data.append(int(value, 0) & 0xFF)
    if not data:
        sys.stderr.write("capture_inventory: %s in %s decoded to no bytes\n" % (identifier, path))
        sys.exit(2)
    sys.stdout.write("%s %s %s %d\n" % (name, path, data.hex(), len(data)))
PYTHON
}

inventory | while read -r name path hex length; do
    digest="$(printf '%s' "$hex" | xxd -r -p | hash_of)"
    printf '%s  %-28s %5s bytes  %s\n' "$digest" "$name" "$length" "$path"
done

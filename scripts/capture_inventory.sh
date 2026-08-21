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
    ("lob_rows_with_bit_vector", "test/cpp/protocol_test.cpp", "lob_rows_with_bit_vector"),
    ("lob_get_length_response", "test/cpp/protocol_test.cpp", "lob_get_length_response"),
    ("lob_read_clob_response", "test/cpp/protocol_test.cpp", "lob_read_clob_response"),
    ("lob_read_blob_response", "test/cpp/protocol_test.cpp", "lob_read_blob_response"),
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

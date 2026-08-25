PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=oracle_scanner
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Include the Makefile from extension-ci-tools
include extension-ci-tools/makefiles/duckdb_extension.Makefile

# Build DuckDB itself at the standard this extension's own sources need.
#
# DuckDB pins CMAKE_CXX_STANDARD to 11 in its cache, while our targets ask for
# 17 through target_compile_features. That mixture is not merely untidy: from
# C++17 a `static constexpr` member is implicitly inline, so a translation unit
# compiled at 17 emits a definition of, say, duckdb::LogicalType::VARCHAR that
# the C++11 library also defines, and GNU ld refuses the link with "multiple
# definition". macOS links it regardless, which is why this only ever appeared
# on Linux CI.
#
# EXT_FLAGS is the extension-ci-tools hook that reaches DuckDB's own configure,
# so raising the standard here raises it for both halves at once and the two
# stop disagreeing.
EXT_FLAGS+=-DCMAKE_CXX_STANDARD=17

# The reusable makefile is consumed as a quoted shell fragment in some
# environments. Normalize path variables here so its test recipes resolve the
# actual debug/release unittest binary rather than a path containing quotes.
TEST_PATH := /test/unittest
TESTS_BASE_DIRECTORY := test/

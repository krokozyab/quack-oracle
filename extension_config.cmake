# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
duckdb_extension_load(oracle_scanner
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    EXTENSION_VERSION 0.1.0-dev
)

# Any extra extensions that should be built
# e.g.: duckdb_extension_load(json)

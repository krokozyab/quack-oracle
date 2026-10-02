# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
duckdb_extension_load(oracle_scanner
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    EXTENSION_VERSION 0.3.1
)

# Any extra extensions that should be built
# e.g.: duckdb_extension_load(json)

# DuckDB 2.0 builds an extension and links it as separate decisions: one that is
# only loaded is built, not linked into unittest or the adapter test. Ask for the
# link where the function exists, with core_functions, which 1.5 linked by
# default; 1.5 links every loaded extension anyway.
if(COMMAND duckdb_extension_statically_link)
    duckdb_extension_statically_link(oracle_scanner core_functions)
endif()

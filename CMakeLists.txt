cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME oracle_scanner)

# DuckDB's extension distribution supports vcpkg. As such, dependencies can be added in ./vcpkg.json and then
# used in cmake with find_package. Feel free to remove or replace with other dependencies.
# Note that it should also be removed from vcpkg.json to prevent needlessly installing it..
find_package(OpenSSL REQUIRED)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD "17" CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(src/include)

set(EXTENSION_SOURCES
    src/oracle_scanner_extension.cpp
    src/oracle_secret.cpp
    src/client_identity.cpp
    src/byte_buffer.cpp
    src/byte_stream.cpp
    src/wallet_archive.cpp
    src/openssl_stream.cpp
    src/tns_packet.cpp
    src/tns_connect.cpp
    src/tns_handshake.cpp
    src/tns_client.cpp
    src/connect_descriptor.cpp
    src/descriptor_parser.cpp
    src/data_assembler.cpp
    src/ttc_channel.cpp
    src/ttc_error.cpp
    src/ttc_parameter.cpp
    src/ttc_auth.cpp
    src/ttc_fetch.cpp
    src/ttc_piggyback.cpp
    src/ttc_transaction.cpp
    src/ttc_lob.cpp
    src/native_session.cpp
    src/oracle_query.cpp
    src/oracle_catalog.cpp
    src/oracle_types.cpp
    src/oracle_connection.cpp
    src/oracle_filter.cpp
    src/oracle_write.cpp
    src/oracle_callable.cpp
    src/oracle_pool.cpp
    src/oracle_parallel.cpp
    src/ttc_fetch_response.cpp
    src/ttc_describe.cpp
    src/ttc_execute_response.cpp
    src/ttc_cursor.cpp
    src/ttc_call_response.cpp
    src/ttc_io_vector.cpp
    src/ttc_out_binds.cpp
    src/ttc_statement_channel.cpp
    src/ttc_row_data.cpp
    src/ttc_execute.cpp
    src/ttc_negotiation.cpp
    src/ttc_o5logon.cpp
    src/value_codec.cpp
    src/auth_crypto.cpp
    src/bind_validation.cpp
    src/sql_binds.cpp
    src/sql_statement.cpp
    src/call_builder.cpp
    src/validating_session.cpp
    src/session_factory.cpp
    src/transport_factory.cpp
    src/statement_registry.cpp
    src/call_registry.cpp
    src/transaction.cpp
    src/session_pool.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})
target_compile_features(${EXTENSION_NAME} PUBLIC cxx_std_17)
target_compile_features(${LOADABLE_EXTENSION_NAME} PUBLIC cxx_std_17)

# Link OpenSSL in both the static library as the loadable extension
target_link_libraries(${EXTENSION_NAME} OpenSSL::SSL OpenSSL::Crypto duckdb_miniz)
target_link_libraries(${LOADABLE_EXTENSION_NAME} OpenSSL::SSL OpenSSL::Crypto duckdb_miniz)
target_include_directories(${EXTENSION_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/duckdb/third_party/miniz)
target_include_directories(${LOADABLE_EXTENSION_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/duckdb/third_party/miniz)

option(ORACLE_SCANNER_BUILD_TESTS "Build oracle_scanner protocol unit tests" ON)
if(ORACLE_SCANNER_BUILD_TESTS)
  enable_testing()
  add_executable(oracle_scanner_protocol_test
                 test/cpp/protocol_test.cpp
                 src/client_identity.cpp
                 src/byte_buffer.cpp
                 src/byte_stream.cpp
                 src/wallet_archive.cpp
                 src/openssl_stream.cpp
                 src/tns_packet.cpp
                 src/tns_connect.cpp
                 src/tns_handshake.cpp
                 src/tns_client.cpp
                 src/connect_descriptor.cpp
                 src/descriptor_parser.cpp
                 src/data_assembler.cpp
                 src/ttc_channel.cpp
                 src/ttc_error.cpp
                 src/ttc_parameter.cpp
                 src/ttc_auth.cpp
                 src/ttc_fetch.cpp
                 src/ttc_piggyback.cpp
                 src/ttc_transaction.cpp
    src/ttc_lob.cpp
                 src/native_session.cpp
                 src/ttc_fetch_response.cpp
                 src/ttc_describe.cpp
                 src/ttc_execute_response.cpp
                 src/ttc_cursor.cpp
                 src/ttc_call_response.cpp
                 src/ttc_io_vector.cpp
                 src/ttc_out_binds.cpp
                 src/ttc_statement_channel.cpp
                 src/ttc_row_data.cpp
                 src/ttc_execute.cpp
                 src/ttc_negotiation.cpp
                 src/ttc_o5logon.cpp
                 src/value_codec.cpp
                 src/auth_crypto.cpp
                 src/bind_validation.cpp
                 src/sql_binds.cpp
                 src/sql_statement.cpp
                 src/call_builder.cpp
                 src/validating_session.cpp
                 src/session_factory.cpp
    src/transport_factory.cpp
                 src/statement_registry.cpp
                 src/call_registry.cpp
                 src/transaction.cpp
                 src/session_pool.cpp)
  target_link_libraries(oracle_scanner_protocol_test PRIVATE OpenSSL::SSL OpenSSL::Crypto duckdb_miniz)
  target_include_directories(oracle_scanner_protocol_test PRIVATE src/include ${CMAKE_CURRENT_SOURCE_DIR}/duckdb/third_party/miniz)
  target_compile_features(oracle_scanner_protocol_test PRIVATE cxx_std_17)
  add_test(NAME oracle_scanner_protocol_test COMMAND oracle_scanner_protocol_test)

  # Adapter tests link DuckDB itself so they can drive src/oracle_query.cpp
  # against a fake session installed through OpenOracleSession, with no database
  # and no network. duckdb_static is defined later in the DuckDB tree than this
  # file is processed, so it is named rather than probed with if(TARGET).
  add_executable(oracle_scanner_adapter_test test/cpp/adapter_test.cpp)
  # duckdb_static references ExtensionHelper::LoadAllExtensions, which lives in
  # the generated loader together with every statically linked extension. This
  # is the same helper DuckDB's own unittest binary uses to pull them in, and it
  # also carries this extension's own OpenSSL and miniz dependencies.
  target_link_libraries(oracle_scanner_adapter_test PRIVATE duckdb_static)
  link_extension_libraries(oracle_scanner_adapter_test PRIVATE)
  target_include_directories(oracle_scanner_adapter_test PRIVATE src/include)
  target_compile_features(oracle_scanner_adapter_test PRIVATE cxx_std_17)
  add_test(NAME oracle_scanner_adapter_test COMMAND oracle_scanner_adapter_test)
endif()

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")

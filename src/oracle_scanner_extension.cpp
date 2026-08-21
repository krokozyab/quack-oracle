#define DUCKDB_EXTENSION_MAIN

#include "oracle_scanner_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/function/scalar_function.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

namespace duckdb {

void RegisterOracleSecrets(ExtensionLoader &loader);
void RegisterOracleQuery(ExtensionLoader &loader);
void RegisterOracleAttachedCatalog(ExtensionLoader &loader);
void RegisterOracleSessionPool(ExtensionLoader &loader);
void RegisterOracleParallelScan(ExtensionLoader &loader);

static void OracleScannerVersion(DataChunk &args, ExpressionState &, Vector &result) {
	result.SetVectorType(VectorType::CONSTANT_VECTOR);
	ConstantVector::SetNull(result, false);
	ConstantVector::GetData<string_t>(result)[0] = StringVector::AddString(result, "0.1.0-dev");
}

static void LoadInternal(ExtensionLoader &loader) {
	loader.SetDescription("Native Oracle TNS/TTC connectivity for DuckDB");
	loader.RegisterFunction(ScalarFunction("oracle_scanner_version", {}, LogicalType::VARCHAR, OracleScannerVersion));
	RegisterOracleSecrets(loader);
	RegisterOracleQuery(loader);
	RegisterOracleAttachedCatalog(loader);
	RegisterOracleSessionPool(loader);
	RegisterOracleParallelScan(loader);
}

void OracleScannerExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}
std::string OracleScannerExtension::Name() {
	return "oracle_scanner";
}

std::string OracleScannerExtension::Version() const {
#ifdef EXT_VERSION_ORACLE_SCANNER
	return EXT_VERSION_ORACLE_SCANNER;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(oracle_scanner, loader) {
	duckdb::LoadInternal(loader);
}
}

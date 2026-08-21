// The Oracle catalog behind `ATTACH ... (TYPE oracle_scanner)`: schema and
// object discovery, lazy table entries, and the storage extension that
// registers it. It shares the scan's bind data and the type conversions with
// the table functions through oracle_adapter.hpp.

#include "oracle_adapter.hpp"

#include "duckdb/catalog/catalog_entry/duck_schema_entry.hpp"
#include "duckdb/parser/parsed_data/attach_info.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/catalog/default/default_generator.hpp"
#include "duckdb/catalog/duck_catalog.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/column_definition.hpp"
#include "duckdb/parser/constraints/not_null_constraint.hpp"
#include "duckdb/parser/constraints/unique_constraint.hpp"
#include "duckdb/parser/keyword_helper.hpp"
#include "duckdb/parser/parsed_data/create_schema_info.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/planner/operator/logical_delete.hpp"
#include "duckdb/planner/operator/logical_insert.hpp"
#include "duckdb/planner/operator/logical_update.hpp"
#include "duckdb/storage/storage_extension.hpp"
#include "duckdb/storage/table_storage_info.hpp"
#include "duckdb/transaction/duck_transaction_manager.hpp"

#include "oracle_scanner/session_factory.hpp"

#include <mutex>
#include <unordered_map>

namespace duckdb {

using oracle_scanner::OpenOracleSession;

namespace {

// ATTACH keeps no shared TTC channel. Metadata discovery and every scan open
// their own native session, matching oracle_query's proven ownership model.
// This makes the initial catalog explicitly read-only and avoids pretending
// that a DuckDB transaction spans an Oracle session.
struct OracleAttachedState {
    ConnectionConfig config;
    std::string password;
    // The name the ATTACH resolved, so scans of this catalog share one pool.
    std::string secret_name;
    std::string current_schema;
    mutable std::mutex metadata_lock;
    mutable bool objects_loaded = false;
    mutable std::vector<std::string> object_names;
    // Filled by one dictionary query for the whole schema. metadata_complete
    // says whether that query reached the end; when it did not, a cache miss
    // still has to ask about the one object.
    mutable bool metadata_loaded = false;
    mutable bool metadata_complete = false;
    mutable std::unordered_map<std::string, std::vector<OracleColumn>> column_cache;
    // Primary keys, read once for the whole schema. Absent is always safe;
    // claiming a key that does not hold is not, which is why a failed read
    // leaves this empty rather than falling back to anything.
    mutable bool primary_keys_loaded = false;
    mutable std::unordered_map<std::string, std::vector<std::string>> primary_key_cache;

    void ConnectAndDiscoverSchema() {
        auto session = OpenOracleSession(config, password);
        auto cursor = TranslatingOracleErrors("Oracle ATTACH could not read the current schema",
                                              [&] { return session->Query("SELECT USER FROM DUAL", {}); });
        const auto batch = TranslatingOracleErrors("Oracle ATTACH could not read the current schema",
                                                   [&] { return cursor->Fetch(1); });
        if (batch.rows.empty() || batch.rows[0].empty() || !batch.rows[0][0]) {
            throw IOException("Oracle ATTACH could not determine the current schema");
        }
        current_schema.assign(batch.rows[0][0]->begin(), batch.rows[0][0]->end());
        cursor->Close();
        session->Close();
        if (current_schema.empty()) {
            throw IOException("Oracle ATTACH received an empty current schema");
        }
    }

    // The cap existed because each object then cost a dictionary round trip on
    // first use. Metadata is now read for the whole schema in one query, so the
    // bound is only here to keep an enormous schema from being materialised.
    std::vector<std::string> ListObjects() const {
        constexpr size_t maximum_objects = 1U << 16U;
        std::lock_guard<std::mutex> lock(metadata_lock);
        if (objects_loaded) {
            return object_names;
        }
        const auto append_names = [&](const std::string &sql) {
            auto session = OpenOracleSession(config, password);
            auto cursor = TranslatingOracleErrors("Oracle ATTACH could not enumerate objects",
                                                  [&] { return session->Query(sql, {}); });
            for (;;) {
                const auto batch = TranslatingOracleErrors("Oracle ATTACH could not enumerate objects",
                                                           [&] { return cursor->Fetch(STANDARD_VECTOR_SIZE); });
                for (const auto &row : batch.rows) {
                    if (!row.empty() && row[0] && object_names.size() < maximum_objects) {
                        object_names.emplace_back(row[0]->begin(), row[0]->end());
                    }
                }
                if (batch.exhausted || object_names.size() == maximum_objects) {
                    break;
                }
            }
            cursor->Close();
            session->Close();
        };
        append_names("SELECT table_name FROM user_tables WHERE ROWNUM <= " + std::to_string(maximum_objects));
        if (object_names.size() < maximum_objects) {
            append_names("SELECT view_name FROM user_views WHERE ROWNUM <= " +
                         std::to_string(maximum_objects - object_names.size()));
        }
        objects_loaded = true;
        return object_names;
    }

    // Converts one USER_TAB_COLUMNS row. `offset` is where the column fields
    // start, so the same reader serves the whole-schema query, whose first
    // field is the table name, and the single-object one, which has no such
    // field.
    OracleColumn ColumnFromDictionaryRow(const std::vector<std::optional<std::vector<uint8_t>>> &row, size_t offset,
                                         const std::string &object_name) const {
        if (row.size() < offset + 6 || !row[offset] || !row[offset + 1] || !row[offset + 2] || !row[offset + 5]) {
            throw IOException("Oracle ATTACH received incomplete USER_TAB_COLUMNS metadata for '%s'", object_name);
        }
        const std::string name(row[offset]->begin(), row[offset]->end());
        const std::string type(row[offset + 1]->begin(), row[offset + 1]->end());
        const auto number = [](const std::optional<std::vector<uint8_t>> &value, int16_t fallback) {
            if (!value) {
                return fallback;
            }
            try {
                return static_cast<int16_t>(std::stoi(oracle_scanner::DecodeOracleNumber(*value)));
            } catch (const std::exception &) {
                throw IOException("Oracle ATTACH received non-integral USER_TAB_COLUMNS metadata");
            }
        };
        // USER_TAB_COLUMNS spells a timestamp's precision into the type name —
        // `TIMESTAMP(6)`, `TIMESTAMP(6) WITH TIME ZONE` — so an exact
        // comparison never matches one, and the old default sent every
        // unmatched name to VARCHAR2. That silently reinterpreted timestamps,
        // and any type outside the mapping, as text. Match the timestamp family
        // by shape and leave everything the mapping does not name at zero.
        uint16_t oracle_type = 0;
        if (type == "NUMBER") {
            oracle_type = 2;
        } else if (type == "DATE") {
            oracle_type = 12;
        } else if (type == "VARCHAR2" || type == "VARCHAR") {
            oracle_type = 1;
        } else if (type == "CHAR") {
            oracle_type = 96;
        } else if (type == "RAW") {
            oracle_type = 23;
        } else if (type == "BINARY_FLOAT") {
            oracle_type = 100;
        } else if (type == "BINARY_DOUBLE") {
            oracle_type = 101;
        } else if (StringUtil::StartsWith(type, "TIMESTAMP")) {
            if (StringUtil::EndsWith(type, "WITH LOCAL TIME ZONE")) {
                oracle_type = 231;
            } else if (StringUtil::EndsWith(type, "WITH TIME ZONE")) {
                oracle_type = 181;
            } else {
                oracle_type = 180;
            }
        }
        // A type this mapping does not name stays zero rather than becoming
        // VARCHAR2. OpenProjectedScan then keeps whatever the TTC describe
        // reported for that column, so a refusal names the real Oracle type,
        // and the table is still listed rather than making the whole catalog
        // unusable — the `system` schema alone has plenty of LOB columns.
        const auto byte_width = number(row[offset + 2], 0);
        if (byte_width < 0) {
            throw IOException("Oracle ATTACH received negative USER_TAB_COLUMNS DATA_LENGTH");
        }
        return {name,
                oracle_type,
                static_cast<uint32_t>(byte_width),
                number(row[offset + 3], 0),
                number(row[offset + 4], 0),
                std::string(row[offset + 5]->begin(), row[offset + 5]->end()) == "Y"};
    }

    // Reads the columns of every object in the schema in one dictionary query
    // rather than one per object. A schema of N tables used to cost N round
    // trips, paid the first time each table was touched; it now costs one.
    //
    // The row count is bounded. If the schema has more columns than the bound,
    // the load stops, the partially read object is discarded, and
    // metadata_complete stays false so a lookup that misses the cache still
    // falls back to asking about that one object.
    //
    // The same incomplete state absorbs a failed load, and today that is not
    // hypothetical: a fetch response larger than one TNS packet is not
    // reassembled, so this query fails on any schema past roughly a thousand
    // columns — see the multi-packet fetch defect in HANDOFF.md. Falling back is
    // correct rather than a papering-over, because the per-object query returns
    // exactly the same metadata; it is only slower. When the transport defect is
    // fixed, this catch becomes the bound-exceeded case alone.
    void LoadSchemaColumnsLocked() const {
        try {
            LoadSchemaColumnsOnceLocked();
        } catch (const std::exception &) {
            // A partial cache from a failed load would answer lookups with
            // truncated column lists, so it is discarded entirely.
            column_cache.clear();
            metadata_complete = false;
        }
    }

    void LoadSchemaColumnsOnceLocked() const {
        constexpr size_t maximum_columns = 1U << 16U;
        metadata_loaded = true;
        auto session = OpenOracleSession(config, password);
        auto cursor = TranslatingOracleErrors("Oracle ATTACH could not read schema metadata", [&] {
            return session->Query("SELECT table_name, column_name, data_type, data_length, data_precision, "
                                  "data_scale, nullable FROM user_tab_columns ORDER BY table_name, column_id",
                                  {});
        });
        size_t loaded_columns = 0;
        std::string current_object;
        bool truncated = false;
        for (;;) {
            const auto batch = TranslatingOracleErrors("Oracle ATTACH could not read schema metadata",
                                                       [&] { return cursor->Fetch(STANDARD_VECTOR_SIZE); });
            for (const auto &row : batch.rows) {
                if (row.empty() || !row[0]) {
                    throw IOException("Oracle ATTACH received a USER_TAB_COLUMNS row with no table name");
                }
                if (loaded_columns == maximum_columns) {
                    // Drop the object being read: its column list is a prefix,
                    // and a prefix is worse than no entry at all.
                    column_cache.erase(current_object);
                    truncated = true;
                    break;
                }
                const std::string object_name(row[0]->begin(), row[0]->end());
                current_object = object_name;
                column_cache[object_name].push_back(ColumnFromDictionaryRow(row, 1, object_name));
                loaded_columns++;
            }
            if (truncated || batch.exhausted) {
                break;
            }
        }
        cursor->Close();
        session->Close();
        metadata_complete = !truncated;
    }

    // Reads one object's columns, for the case where the bulk load was
    // truncated and this name was not among the objects it reached.
    std::vector<OracleColumn> DescribeOneLocked(const std::string &object_name) const {
        std::string name_literal;
        name_literal.reserve(object_name.size() + 2);
        for (const auto character : object_name) {
            name_literal.push_back(character);
            if (character == '\'') {
                name_literal.push_back('\'');
            }
        }
        auto session = OpenOracleSession(config, password);
        const auto metadata_sql = "SELECT column_name, data_type, data_length, data_precision, data_scale, nullable "
                                  "FROM user_tab_columns WHERE table_name = '" +
                                  name_literal + "' ORDER BY column_id";
        auto cursor = TranslatingOracleErrors("Oracle ATTACH could not read column metadata",
                                              [&] { return session->Query(metadata_sql, {}); });
        std::vector<OracleColumn> columns;
        for (;;) {
            const auto batch = TranslatingOracleErrors("Oracle ATTACH could not read column metadata",
                                                       [&] { return cursor->Fetch(STANDARD_VECTOR_SIZE); });
            for (const auto &row : batch.rows) {
                columns.push_back(ColumnFromDictionaryRow(row, 0, object_name));
            }
            if (batch.exhausted) {
                break;
            }
        }
        cursor->Close();
        session->Close();
        return columns;
    }

    // Oracle enforces a primary key only while the constraint is enabled and
    // validated; a DISABLED or NOVALIDATE one can have rows that violate it.
    // Telling DuckDB about those would let it eliminate a DISTINCT or reshape a
    // join on a uniqueness that does not hold, so only the enforced ones count.
    void LoadPrimaryKeysLocked() const {
        primary_keys_loaded = true;
        try {
            auto session = OpenOracleSession(config, password);
            auto cursor = TranslatingOracleErrors("Oracle ATTACH could not read primary keys", [&] {
                return session->Query("SELECT c.table_name, k.column_name FROM user_constraints c JOIN "
                                      "user_cons_columns k ON k.constraint_name = c.constraint_name AND "
                                      "k.table_name = c.table_name WHERE c.constraint_type = 'P' AND "
                                      "c.status = 'ENABLED' AND c.validated = 'VALIDATED' ORDER BY c.table_name, "
                                      "k.position",
                                      {});
            });
            for (;;) {
                const auto batch = TranslatingOracleErrors("Oracle ATTACH could not read primary keys",
                                                           [&] { return cursor->Fetch(STANDARD_VECTOR_SIZE); });
                for (const auto &row : batch.rows) {
                    if (row.size() < 2 || !row[0] || !row[1]) {
                        continue;
                    }
                    const std::string object_name(row[0]->begin(), row[0]->end());
                    primary_key_cache[object_name].emplace_back(row[1]->begin(), row[1]->end());
                }
                if (batch.exhausted) {
                    break;
                }
            }
            cursor->Close();
            session->Close();
        } catch (const std::exception &) {
            // A partial key list would name some columns of a composite key,
            // which is a different and false constraint.
            primary_key_cache.clear();
        }
    }

    std::vector<std::string> PrimaryKeyColumns(const std::string &object_name) const {
        std::lock_guard<std::mutex> lock(metadata_lock);
        if (!primary_keys_loaded) {
            LoadPrimaryKeysLocked();
        }
        const auto entry = primary_key_cache.find(object_name);
        if (entry == primary_key_cache.end()) {
            return {};
        }
        return entry->second;
    }

    // Looks one object up, which is a different question from enumerating the
    // schema: the name may simply not be an Oracle object. An empty result says
    // exactly that and is not an error — DuckDB asks its catalogs about names
    // that belong to none of them, including its own `duckdb_tables`, and a
    // catalog that throws for those breaks every such lookup. Enumeration is
    // ListObjects; this is the lookup half.
    //
    // USER_TAB_COLUMNS is stable across the supported Oracle versions and
    // provides the type metadata required by the current ATTACH surface. The
    // native zero-row SELECT path is independently live-verified, but it does
    // not yet provide the exact Oracle type mapping this catalog path needs.
    std::vector<OracleColumn> TryDescribe(const std::string &object_name) const {
        std::lock_guard<std::mutex> lock(metadata_lock);
        if (!metadata_loaded) {
            LoadSchemaColumnsLocked();
        }
        const auto entry = column_cache.find(object_name);
        if (entry != column_cache.end()) {
            return entry->second;
        }
        if (metadata_complete) {
            // The bulk load saw every column in the schema, so a name it does
            // not carry is not an object here.
            return {};
        }
        auto columns = DescribeOneLocked(object_name);
        column_cache.emplace(object_name, columns);
        return columns;
    }

    // Describes the table from the dictionary and leaves the Oracle statement
    // for init, which is the first point that knows which columns the plan
    // actually reads.
    unique_ptr<OracleQueryBindData> PrepareScan(const std::string &object_name) const {
        auto result = make_uniq<OracleQueryBindData>();
        result->deferred_scan = true;
        result->config = config;
        result->password = password;
        result->object_name = object_name;
        result->secret_name = secret_name;
        result->columns = TryDescribe(object_name);
        if (result->columns.empty()) {
            // The catalog entry exists, so the object did when it was created.
            throw IOException("Oracle ATTACH table '%s' no longer has column metadata", object_name);
        }
        for (const auto &column : result->columns) {
            result->types.push_back(MappedType(column));
        }
        return result;
    }

};

BindInfo OracleAttachedScanBindInfo(const optional_ptr<FunctionData> bind_data) {
    auto &bind = bind_data->CastNoConst<OracleQueryBindData>();
    if (!bind.table_entry) {
        throw InternalException("an attached Oracle scan has no table entry");
    }
    return BindInfo(*bind.table_entry);
}

class OracleAttachedTableEntry final : public TableCatalogEntry {
public:
    OracleAttachedTableEntry(Catalog &catalog, SchemaCatalogEntry &schema, unique_ptr<CreateTableInfo> info,
                             shared_ptr<OracleAttachedState> state_p, std::string object_name_p,
                             std::vector<OracleColumn> oracle_columns_p)
        : TableCatalogEntry(catalog, schema, *info), state(std::move(state_p)), object_name(std::move(object_name_p)),
          oracle_columns(std::move(oracle_columns_p)) {
    }

    static unique_ptr<OracleAttachedTableEntry> Create(Catalog &catalog, SchemaCatalogEntry &schema,
                                                        shared_ptr<OracleAttachedState> state,
                                                        const std::string &object_name) {
        const auto oracle_columns = state->TryDescribe(object_name);
        if (oracle_columns.empty()) {
            // Not an object in the attached schema. Returning nothing lets
            // DuckDB carry on resolving the name, which is what its own catalog
            // views depend on; claiming it and failing breaks them.
            return nullptr;
        }
        auto info = make_uniq<CreateTableInfo>(schema, Identifier(object_name));
        std::unordered_set<std::string> used_names;
        std::unordered_map<std::string, std::string> output_names;
        for (idx_t index = 0; index < oracle_columns.size(); index++) {
            auto output_name = OutputName(oracle_columns[index], index, used_names);
            output_names.emplace(oracle_columns[index].name, output_name);
            info->columns.AddColumn(ColumnDefinition(Identifier(output_name), MappedType(oracle_columns[index])));
            if (!oracle_columns[index].nullable) {
                // USER_TAB_COLUMNS already carries this, so it costs no query.
                info->constraints.push_back(make_uniq<NotNullConstraint>(LogicalIndex(index)));
            }
        }
        auto key_columns = state->PrimaryKeyColumns(object_name);
        duckdb::vector<std::string> key_names;
        for (const auto &key_column : key_columns) {
            const auto named = output_names.find(key_column);
            if (named == output_names.end()) {
                // A key column the describe did not return leaves the key
                // incomplete, and a partial key is a false constraint.
                key_names.clear();
                break;
            }
            key_names.push_back(named->second);
        }
        if (!key_names.empty()) {
            info->constraints.push_back(make_uniq<UniqueConstraint>(std::move(key_names), true));
        }
        info->on_conflict = OnCreateConflict::IGNORE_ON_CONFLICT;
        return make_uniq<OracleAttachedTableEntry>(catalog, schema, std::move(info), std::move(state), object_name,
                                                   oracle_columns);
    }

    TableFunction GetScanFunction(ClientContext &context, unique_ptr<FunctionData> &bind_data) override {
        auto scan_bind = state->PrepareScan(object_name);
        scan_bind->table_entry = this;
        scan_bind->catalog_name = static_cast<const std::string &>(catalog.GetAttached().GetName());
        bind_data = std::move(scan_bind);
        TableFunction function({}, OracleQueryFunction, nullptr, OracleQueryInit);
        function.name = "oracle_attached_scan";
        function.get_bind_info = OracleAttachedScanBindInfo;
        Value pushdown;
        function.filter_pushdown =
            context.TryGetCurrentSetting("oracle_filter_pushdown", pushdown) && BooleanValue::Get(pushdown);
        function.projection_pushdown = true;
        return function;
    }

    TableStorageInfo GetStorageInfo(ClientContext &) override {
        return {};
    }

    const std::vector<OracleColumn> &OracleColumns() const {
        return oracle_columns;
    }

    const std::string &ObjectName() const {
        return object_name;
    }

    void OnDrop() override {
        // The entry lives in a DuckDB catalog set that would forget it happily
        // while Oracle still has the table. DDL is outside this version.
        throw NotImplementedException("Oracle table \"%s\" cannot be dropped: this extension does not issue DDL",
                                      object_name);
    }

    // DuckDB reaches for local storage on paths that assume a table it owns —
    // DROP clears transaction-local insertions this way, before OnDrop runs.
    // The base class answers with an InternalException, which invalidates the
    // database; an Oracle table simply has no DuckDB-local storage, and saying
    // so leaves the connection usable.
    DataTable &GetStorage() override {
        throw NotImplementedException(
            "Oracle table \"%s\" has no DuckDB-local storage: this operation is not supported on an attached Oracle "
            "table",
            object_name);
    }

    unique_ptr<BaseStatistics> GetStatistics(ClientContext &, column_t) override {
        return nullptr;
    }

    virtual_column_map_t GetVirtualColumns() const override {
        // Oracle's ROWID, not DuckDB's synthetic one, and a string rather than
        // DuckDB's ROW_TYPE: the scan selects it through ROWIDTOCHAR so no
        // ROWID codec is needed, and UPDATE and DELETE address rows by it.
        virtual_column_map_t virtual_columns;
        virtual_columns.insert(
            make_pair(COLUMN_IDENTIFIER_ROW_ID, TableColumn(ORACLE_ROWID_COLUMN_NAME, LogicalType::VARCHAR)));
        return virtual_columns;
    }

    vector<column_t> GetRowIdColumns() const override {
        return {COLUMN_IDENTIFIER_ROW_ID};
    }

    OracleWriteTarget WriteTarget(const std::string &catalog_name) const {
        OracleWriteTarget target;
        target.catalog_name = catalog_name;
        target.object_name = object_name;
        target.config = state->config;
        target.password = state->password;
        return target;
    }

private:
    shared_ptr<OracleAttachedState> state;
    std::string object_name;
    std::vector<OracleColumn> oracle_columns;
};

class OracleAttachedTableGenerator final : public DefaultGenerator {
public:
    OracleAttachedTableGenerator(Catalog &catalog, SchemaCatalogEntry &schema, shared_ptr<OracleAttachedState> state_p)
        : DefaultGenerator(catalog), schema(schema), state(std::move(state_p)) {
    }

    vector<Identifier> GetDefaultEntries() override {
        vector<Identifier> result;
        for (auto &name : state->ListObjects()) {
            result.emplace_back(Identifier(name));
        }
        return result;
    }

    // GetDefaultEntries enumerates; this answers "is this one name mine?", and
        // a null answer means it is not.
    // GetDefaultEntries above enumerates the schema; this answers the different
    // question of whether one particular name is ours, and a null answer means
    // it is not.
    unique_ptr<CatalogEntry> CreateDefaultEntry(ClientContext &, const Identifier &entry_name) override {
        return OracleAttachedTableEntry::Create(catalog, schema, state, static_cast<const std::string &>(entry_name));
    }

private:
    SchemaCatalogEntry &schema;
    shared_ptr<OracleAttachedState> state;
};

class OracleAttachedCatalog final : public DuckCatalog {
public:
    OracleAttachedCatalog(AttachedDatabase &db, shared_ptr<OracleAttachedState> state_p)
        : DuckCatalog(db), state(std::move(state_p)) {
    }

    string GetCatalogType() override {
        return "oracle_scanner";
    }

    PhysicalOperator &PlanInsert(ClientContext &context, PhysicalPlanGenerator &planner, LogicalInsert &op,
                                 optional_ptr<PhysicalOperator> plan) override {
        auto &table = op.table.Cast<OracleAttachedTableEntry>();
        return PlanOracleInsert(context, planner, op, plan, table.OracleColumns(),
                                table.WriteTarget(static_cast<const std::string &>(GetAttached().GetName())));
    }

    PhysicalOperator &PlanDelete(ClientContext &context, PhysicalPlanGenerator &planner, LogicalDelete &op,
                                 PhysicalOperator &plan) override {
        auto &table = op.table.Cast<OracleAttachedTableEntry>();
        return PlanOracleDelete(context, planner, op, plan, table.WriteTarget(static_cast<const std::string &>(GetAttached().GetName())));
    }

    PhysicalOperator &PlanUpdate(ClientContext &context, PhysicalPlanGenerator &planner, LogicalUpdate &op,
                                 PhysicalOperator &plan) override {
        auto &table = op.table.Cast<OracleAttachedTableEntry>();
        return PlanOracleUpdate(context, planner, op, plan, table.OracleColumns(),
                                table.WriteTarget(static_cast<const std::string &>(GetAttached().GetName())));
    }

    ErrorData SupportsCreateTable(BoundCreateTableInfo &) override {
        return ErrorData(ExceptionType::NOT_IMPLEMENTED,
                         "Oracle ATTACH cannot create a table: this extension does not issue DDL");
    }

    optional_ptr<CatalogEntry> CreateSchema(CatalogTransaction transaction, CreateSchemaInfo &info) override {
        if (info.SchemaName() == Identifier(DEFAULT_SCHEMA)) {
            // DuckCatalog::Initialize creates `main` itself, and it may run
            // more than once; that schema is the attached Oracle schema, and it
            // is the only one there is.
            return DuckCatalog::CreateSchema(transaction, info);
        }
        throw NotImplementedException("Oracle ATTACH exposes one schema and cannot create another");
    }

    void DropSchema(ClientContext &, DropInfo &) override {
        throw NotImplementedException("Oracle ATTACH cannot drop a schema: this extension does not issue DDL");
    }

    void Initialize(bool) override {
        state->ConnectAndDiscoverSchema();
        DuckCatalog::Initialize(false);
        auto transaction = CatalogTransaction::GetSystemTransaction(GetAttached().GetDatabase());
        auto &schema = GetSchema(transaction, DEFAULT_SCHEMA).Cast<DuckSchemaEntry>();
        schema.GetCatalogSet(CatalogType::TABLE_ENTRY)
            .SetDefaultGenerator(make_uniq<OracleAttachedTableGenerator>(*this, schema, state));
    }

private:
    shared_ptr<OracleAttachedState> state;
};

unique_ptr<Catalog> OracleAttachedCatalogAttach(optional_ptr<StorageExtensionInfo>, ClientContext &context,
                                                 AttachedDatabase &db, const string &, AttachInfo &info,
                                                 AttachOptions &options) {
    if (info.path.empty()) {
        throw BinderException("Oracle ATTACH requires the Oracle secret name as its path");
    }
    for (const auto &option : info.options) {
        if (!StringUtil::CIEquals(option.first, "type")) {
            throw BinderException(
                "Oracle ATTACH does not accept option '%s' yet; use ATTACH 'secret_name' AS name (TYPE oracle_scanner)",
                option.first);
        }
    }
    std::string password;
    auto state = make_shared_ptr<OracleAttachedState>();
    state->config = ConnectionFromSecret(context, info.path, password);
    state->password = std::move(password);
    state->secret_name = info.path;
    // DuckDB's attached-database wrapper owns a local StorageManager even for
    // a custom catalog. Keep that storage in memory: the ATTACH path is a
    // secret name, never a local database file.
    info.path = ":memory:";
    // The attached database stays read-write so INSERT can bind against it.
    // Nothing DuckDB-local is written: the catalog refuses every DDL entry
    // point above, and the only statement that reaches Oracle is the INSERT.
    auto catalog = make_uniq<OracleAttachedCatalog>(db, std::move(state));
    catalog->Initialize(false);
    return catalog;
}

unique_ptr<TransactionManager> OracleAttachedCatalogTransactionManager(optional_ptr<StorageExtensionInfo>,
                                                                         AttachedDatabase &db, Catalog &) {
    return make_uniq<DuckTransactionManager>(db);
}

} // namespace

void OpenProjectedScan(ClientContext &context, OracleQueryBindData &bind, const std::vector<column_t> &selected,
                       OracleSessionHandle &session, std::unique_ptr<OracleCursor> &cursor,
                       std::vector<OracleColumn> &columns) {
    std::string select_list;
    for (const auto column_id : selected) {
        if (!select_list.empty()) {
            select_list += ", ";
        }
        if (column_id == COLUMN_IDENTIFIER_ROW_ID) {
            select_list += ORACLE_ROWID_EXPRESSION;
            continue;
        }
        select_list += KeywordHelper::WriteQuoted(bind.columns[column_id].name, '"');
    }
    auto sql = "SELECT " + select_list + " FROM " + KeywordHelper::WriteQuoted(bind.object_name, '"');
    // The translated predicates, when filter pushdown is enabled and every
    // filter could be proven. An empty clause means nothing was pushed.
    if (!bind.where_clause.empty()) {
        sql += " WHERE " + bind.where_clause;
    }
    try {
        session = AcquireOracleReadSession(context, bind.secret_name, bind.catalog_name, bind.config, bind.password);
        cursor = session->Query(sql, {});
    } catch (const std::exception &error) {
        session.Poison();
        throw IOException("Oracle ATTACH could not open table '%s': %s", bind.object_name, error.what());
    }
    columns = cursor->Columns();
    if (columns.size() != selected.size()) {
        throw IOException("Oracle ATTACH table '%s' described %llu columns for a %llu column select list",
                          bind.object_name, static_cast<uint64_t>(columns.size()),
                          static_cast<uint64_t>(selected.size()));
    }
    for (idx_t index = 0; index < columns.size(); index++) {
        if (selected[index] == COLUMN_IDENTIFIER_ROW_ID) {
            // Described by Oracle under the expression's own name; the dictionary
            // has no entry for a pseudo-column, so the synthetic one stands.
            columns[index] = OracleRowIdColumn();
            continue;
        }
        const auto &dictionary_column = bind.columns[selected[index]];
        if (columns[index].name != dictionary_column.name) {
            throw IOException("Oracle ATTACH table '%s' returned column '%s' where '%s' was selected",
                              bind.object_name, columns[index].name, dictionary_column.name);
        }
        // The describe supplies the wire representation and the character
        // set form; the dictionary supplies declared NUMBER precision and
        // scale and nullability, so scan values match the table schema. A
        // dictionary type of zero means the mapping did not name it, and
        // the describe's own type stands so the refusal can name it.
        if (dictionary_column.oracle_type != 0) {
            columns[index].oracle_type = dictionary_column.oracle_type;
        }
        columns[index].byte_width = dictionary_column.byte_width;
        columns[index].precision = dictionary_column.precision;
        columns[index].scale = dictionary_column.scale;
        columns[index].nullable = dictionary_column.nullable;
        (void)TypeFor(columns[index]);
    }
}

void RegisterOracleAttachedCatalog(ExtensionLoader &loader) {
    // Off by default. Once a filter is handed to a scan DuckDB removes it from
    // the plan, so the scan must apply it exactly; this translator refuses
    // anything it cannot prove, and refusing would turn working queries into
    // errors. Opting in is therefore the user's choice, which is also how
    // DuckDB's own Postgres extension ships its filter pushdown.
    DBConfig::GetConfig(loader.GetDatabaseInstance())
        .AddExtensionOption("oracle_filter_pushdown",
                            "Send WHERE predicates on an attached Oracle table to Oracle. Only filters whose Oracle "
                            "meaning is provably identical are translated; anything else raises.",
                            LogicalType::BOOLEAN, Value::BOOLEAN(false));
    auto extension = make_shared_ptr<StorageExtension>();
    extension->attach = OracleAttachedCatalogAttach;
    extension->create_transaction_manager = OracleAttachedCatalogTransactionManager;
    StorageExtension::Register(DBConfig::GetConfig(loader.GetDatabaseInstance()), "oracle_scanner", std::move(extension));
}

} // namespace duckdb

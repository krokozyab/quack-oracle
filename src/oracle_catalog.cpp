// The Oracle catalog behind `ATTACH ... (TYPE oracle_scanner)`: schema and
// object discovery, lazy table entries, and the storage extension that
// registers it. It shares the scan's bind data and the type conversions with
// the table functions through oracle_adapter.hpp.

#include "oracle_adapter.hpp"
#include "duckdb/execution/physical_plan_generator.hpp"
#include "oracle_io_deadline.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/parsed_data/alter_table_info.hpp"
#include "duckdb/parser/parsed_data/drop_info.hpp"
#include "duckdb/planner/parsed_data/bound_create_table_info.hpp"
#include "duckdb/planner/operator/logical_create_table.hpp"
#include "duckdb/common/types/decimal.hpp"
#include <atomic>
#include <cmath>
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/planner/operator/logical_merge_into.hpp"

#include "duckdb/transaction/meta_transaction.hpp"

#include "duckdb/catalog/catalog_entry/duck_schema_entry.hpp"
#include "duckdb/parser/parsed_data/attach_info.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/catalog/default/default_generator.hpp"
#include "duckdb/catalog/duck_catalog.hpp"
#include "duckdb/transaction/duck_transaction.hpp"
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

#include "oracle_scanner/io_deadline_binding.hpp"
#include "oracle_scanner/oracle_vector.hpp"
#include "oracle_scanner/session_factory.hpp"

#include <map>
#include <mutex>
#include <unordered_map>

namespace duckdb {

using oracle_scanner::OpenOracleSession;

namespace {

// Administrative route for DDL outside the supported attached-table subset.
// Changes made through that API require a reattach to refresh metadata.
constexpr const char *ORACLE_DDL_ROUTE =
    "Run the DDL with oracle_execute_admin('<secret>', '<statement>'), then DETACH and ATTACH again to see it";

// A session for dictionary reads, outside any DuckDB transaction. With the
// catalog's transaction pool it is leased from there, and given back only
// after an acknowledged ROLLBACK ends whatever the reads may have begun; any
// failure closes it. Without a pool it is a session of its own, as before.
class OracleMetadataLease {
public:
    OracleMetadataLease(const std::shared_ptr<oracle_scanner::OracleTransactionSessionPool> &pool_p,
                        const ConnectionConfig &config, const std::string &password)
        : pool(pool_p) {
        session = pool ? pool->Acquire(nullptr) : std::shared_ptr<OracleSession>(OpenOracleSession(config, password));
    }
    ~OracleMetadataLease() {
        if (!session) {
            return;
        }
        if (pool) {
            pool->Discard(std::move(session));
            return;
        }
        try {
            session->Close();
        } catch (...) {
        }
    }
    OracleMetadataLease(const OracleMetadataLease &) = delete;
    OracleMetadataLease &operator=(const OracleMetadataLease &) = delete;

    OracleSession *operator->() const {
        return session.get();
    }

    // Called once the reads succeeded and their cursors are closed.
    void Finish() {
        if (!pool) {
            auto finished = std::move(session);
            finished->Close();
            return;
        }
        if (!session->ReadyForReuse()) {
            // It will be closed anyway, and closing ends whatever it began.
            pool->Discard(std::move(session));
            return;
        }
        try {
            session->Rollback();
        } catch (...) {
            pool->Discard(std::move(session));
            return;
        }
        pool->Release(std::move(session));
    }

private:
    std::shared_ptr<oracle_scanner::OracleTransactionSessionPool> pool;
    std::shared_ptr<OracleSession> session;
};

// Owners have independent metadata caches, but one attachment shares its DDL
// epoch, DDL lock and transaction-session pool across every schema alias.
struct OracleAttachedEpoch {
    std::mutex ddl_lock;
    std::atomic<idx_t> version {0};
};

struct OracleAttachedState {
    ConnectionConfig config;
    std::string password;
    // Idle transaction sessions kept between this catalog's transactions; see
    // OracleTransactionSessionPool. Null when oracle_transaction_pool_size is 0.
    std::shared_ptr<oracle_scanner::OracleTransactionSessionPool> transaction_pool;

    // The name the ATTACH resolved, so scans of this catalog share one pool.
    std::string secret_name;
    std::string current_schema;
    // Empty preserves the default owner's unqualified SQL. Named aliases keep
    // their explicit owner, using USER_ metadata only for the connected user.
    std::string owner;
    bool named_schema = false;
    bool discover_all_schemas = true;
    shared_ptr<OracleAttachedEpoch> epoch = make_shared_ptr<OracleAttachedEpoch>();
    mutable idx_t metadata_version = 0;
    bool OwnDictionary() const { return owner.empty() || owner == current_schema; }
    std::string EffectiveOwner() const { return owner.empty() ? current_schema : owner; }

    static std::string Literal(const std::string &text) {
        std::string result = "'";
        for (const auto character : text) {
            result.push_back(character);
            if (character == '\'') {
                result.push_back('\'');
            }
        }
        return result + "'";
    }
    // `user_tables` or `all_tables`, whichever this catalog reads.
    std::string View(const char *name) const {
        return std::string(OwnDictionary() ? "user_" : "all_") + name;
    }
    // A condition on the owner column, with the word that joins it to what
    // comes before. Empty for the connected user's own schema.
    std::string OwnerCondition(const char *column, const char *joiner) const {
        return OwnDictionary() ? std::string() : std::string(" ") + joiner + " " + column + " = " + Literal(owner);
    }
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
    // The names of the schema's tables, as opposed to its views: a sample can be
    // taken of a table, and Oracle refuses one of most views.
    mutable bool tables_loaded = false;
    mutable std::unordered_set<std::string> table_names;
    // NUM_ROWS from the optimizer statistics, for the tables that have any.
    mutable bool row_estimates_loaded = false;
    mutable std::unordered_map<std::string, uint64_t> row_estimates;
    // NUM_DISTINCT per table and column, from the same statistics.
    mutable std::unordered_map<std::string, std::unordered_map<std::string, uint64_t>> distinct_estimates;
    // LOW_VALUE and HIGH_VALUE, as the dictionary stores them (the column's own
    // encoding), from the same statistics. Only ever used for estimates.
    mutable std::unordered_map<std::string,
                               std::unordered_map<std::string, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>>
        value_bounds;
    // Whether the session compares text by bytes (NLS_COMP = BINARY), read once at
    // ATTACH. False when it could not be read: equality on text then stays in DuckDB.
    bool nls_comp_binary = false;

    void RefreshMetadataLocked() const {
        const auto version = epoch->version.load();
        if (metadata_version == version) { return; }
        objects_loaded = metadata_loaded = metadata_complete = primary_keys_loaded = tables_loaded = row_estimates_loaded = false;
        object_names.clear(); column_cache.clear(); primary_key_cache.clear(); table_names.clear();
        row_estimates.clear(); distinct_estimates.clear(); value_bounds.clear();
        metadata_version = version;
    }
    void InvalidateMetadata() {
        ++epoch->version;
        std::lock_guard<std::mutex> guard(metadata_lock);
        RefreshMetadataLocked();
    }

    void ConnectAndDiscoverSchema() {
        OracleMetadataLease session(transaction_pool, config, password);
        auto cursor = TranslatingOracleErrors("Oracle ATTACH could not read the current schema",
                                              [&] { return session->Query("SELECT USER FROM DUAL", {}); });
        const auto batch = TranslatingOracleErrors("Oracle ATTACH could not read the current schema",
                                                   [&] { return cursor->Fetch(1); });
        if (batch.rows.empty() || batch.rows[0].empty() || !batch.rows[0][0]) {
            throw IOException("Oracle ATTACH could not determine the current schema");
        }
        current_schema.assign(batch.rows[0][0]->begin(), batch.rows[0][0]->end());
        cursor->Close();
        session.Finish();
        ReadNlsComp();
        if (current_schema.empty()) {
            throw IOException("Oracle ATTACH received an empty current schema");
        }
        if (!owner.empty()) {
            ResolveOwner();
        }
    }

    // Settles the SCHEMA option against ALL_USERS: the name as written if it is
    // a schema, else the one schema that matches ignoring case (names are
    // upper case unless they were created quoted). The connected user's own
    // schema needs no qualification and is read through the USER_ views.
    bool ResolveOwner(bool missing_ok = false) {
        const auto lookup = [&](const std::string &condition) {
            std::vector<std::string> found;
            OracleMetadataLease session(transaction_pool, config, password);
            auto cursor = TranslatingOracleErrors("Oracle ATTACH could not look up a schema", [&] {
                return session->Query("SELECT username FROM all_users WHERE " + condition, {});
            });
            for (;;) {
                const auto batch = TranslatingOracleErrors("Oracle ATTACH could not look up a schema",
                                                           [&] { return cursor->Fetch(8); });
                for (const auto &row : batch.rows) {
                    if (!row.empty() && row[0]) {
                        found.emplace_back(row[0]->begin(), row[0]->end());
                    }
                }
                if (batch.exhausted) {
                    break;
                }
            }
            cursor->Close();
            session.Finish();
            return found;
        };
        auto found = lookup("username = " + Literal(owner));
        if (found.empty()) {
            found = lookup("UPPER(username) = UPPER(" + Literal(owner) + ")");
        }
        if (found.empty() && missing_ok) { return false; }
        if (found.size() != 1) {
            throw BinderException(found.empty() ? "Oracle ATTACH: there is no schema \"%s\" that this user can see"
                                                : "Oracle ATTACH: schema \"%s\" matches several users by case; write it exactly",
                                  owner);
        }
        owner = found[0];
        if (owner == current_schema && !named_schema) { owner.clear(); }
        return true;
    }

    // The cap existed because each object then cost a dictionary round trip on
    // first use. Metadata is now read for the whole schema in one query, so the
    // bound is only here to keep an enormous schema from being materialised.
    std::vector<std::string> ListObjects() const {
        constexpr size_t maximum_objects = 1U << 16U;
        std::lock_guard<std::mutex> lock(metadata_lock);
        RefreshMetadataLocked();
        if (objects_loaded) {
            return object_names;
        }
        const auto append_names = [&](const std::string &sql) {
            OracleMetadataLease session(transaction_pool, config, password);
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
            session.Finish();
        };
        append_names("SELECT table_name FROM " + View("tables") + " WHERE ROWNUM <= " + std::to_string(maximum_objects) +
                     OwnerCondition("owner", "AND"));
        if (object_names.size() < maximum_objects) {
            append_names("SELECT view_name FROM " + View("views") + " WHERE ROWNUM <= " +
                         std::to_string(maximum_objects - object_names.size()) + OwnerCondition("owner", "AND"));
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
        uint8_t character_set_form = 0;
        bool xml = false;
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
        } else if (type == "NVARCHAR2") {
            // The dictionary names the national types apart; on the wire they
            // share the code of VARCHAR2 and CHAR and differ in the form.
            oracle_type = 1;
            character_set_form = 2;
        } else if (type == "NCHAR") {
            oracle_type = 96;
            character_set_form = 2;
        } else if (StringUtil::StartsWith(type, "INTERVAL YEAR")) {
            oracle_type = 182;
        } else if (StringUtil::StartsWith(type, "INTERVAL DAY")) {
            oracle_type = 183;
        } else if (type == "CLOB") {
            oracle_type = 112;
        } else if (type == "NCLOB") {
            oracle_type = 112;
            character_set_form = 2;
        } else if (type == "BLOB") {
            oracle_type = 113;
        } else if (type == "XMLTYPE") {
            // Read and written as its serialized text, so it is a CLOB on the
            // wire; the flag makes the SQL wrap the column.
            oracle_type = 112;
            xml = true;
        } else if (type == "BOOLEAN") {
            oracle_type = 252;
        } else if (type == "JSON") {
            oracle_type = 119;
        } else if (type == "VECTOR") {
            // Its dimensions and format are in a column only a 23ai dictionary
            // has; ApplyVectorShapesLocked reads them once a VECTOR is seen.
            oracle_type = 127;
        } else if (type == "ROWID") {
            oracle_type = 11;
        } else if (type == "UROWID") {
            oracle_type = 208;
        } else if (type == "LONG") {
            oracle_type = 8;
        } else if (type == "LONG RAW") {
            oracle_type = 24;
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
        OracleColumn column {name,
                             oracle_type,
                             static_cast<uint32_t>(byte_width),
                             number(row[offset + 3], 0),
                             number(row[offset + 4], 0),
                             std::string(row[offset + 5]->begin(), row[offset + 5]->end()) == "Y",
                             character_set_form};
        column.xml = xml;
        // A column that declares a collation of its own is settled afterwards, by
        // ApplyCollationsLocked; this is the default, NLS_COMP's.
        column.compared_as_bytes = nls_comp_binary;
        return column;
    }

    // VECTOR_INFO reads `VECTOR(3,FLOAT32,DENSE)`, `VECTOR(*,*,DENSE)`,
    // `VECTOR(*,INT8,SPARSE)`: the dimension count or `*`, the storage format
    // or `*`, and whether the column stores its vectors dense or sparse.
    static bool ParseVectorInfo(const std::string &info, OracleColumn &column) {
        const auto open = info.find('(');
        const auto close = info.rfind(')');
        if (open == std::string::npos || close == std::string::npos || close < open) {
            return false;
        }
        auto parts = StringUtil::Split(info.substr(open + 1, close - open - 1), ',');
        if (parts.size() != 3) {
            return false;
        }
        for (auto &part : parts) {
            StringUtil::Trim(part);
        }
        uint32_t dimensions = 0;
        if (parts[0] != "*") {
            try {
                dimensions = static_cast<uint32_t>(std::stoul(parts[0]));
            } catch (const std::exception &) {
                return false;
            }
        }
        uint8_t format = 0;
        if (parts[1] == "FLOAT32") {
            format = oracle_scanner::ORACLE_VECTOR_FLOAT32;
        } else if (parts[1] == "FLOAT64") {
            format = oracle_scanner::ORACLE_VECTOR_FLOAT64;
        } else if (parts[1] == "INT8") {
            format = oracle_scanner::ORACLE_VECTOR_INT8;
        } else if (parts[1] == "BINARY") {
            format = oracle_scanner::ORACLE_VECTOR_BINARY;
        } else if (parts[1] != "*") {
            return false;
        }
        if (parts[2] != "DENSE" && parts[2] != "SPARSE") {
            return false;
        }
        column.vector_dimensions = dimensions;
        column.vector_format = format;
        column.vector_flags = static_cast<uint8_t>((dimensions == 0 ? oracle_scanner::ORACLE_VECTOR_COLUMN_FLEXIBLE_DIMENSIONS : 0) |
                                                   (parts[2] == "SPARSE" ? oracle_scanner::ORACLE_VECTOR_COLUMN_SPARSE : 0));
        return true;
    }

    // NLS_COMP decides how a column without a collation of its own compares text.
    // Every session of this catalog signs in as the same user, so they all start
    // from what this one is given, logon triggers included.
    void ReadNlsComp() {
        try {
            OracleMetadataLease session(transaction_pool, config, password);
            auto cursor =
                session->Query("SELECT value FROM nls_session_parameters WHERE parameter = 'NLS_COMP'", {});
            const auto batch = cursor->Fetch(1);
            nls_comp_binary = !batch.rows.empty() && !batch.rows[0].empty() && batch.rows[0][0] &&
                              std::string(batch.rows[0][0]->begin(), batch.rows[0][0]->end()) == "BINARY";
            cursor->Close();
            session.Finish();
        } catch (const std::exception &) {
            nls_comp_binary = false;
        }
    }

    // Settles compared_as_bytes for the columns that declare a collation of their
    // own (Oracle 12.2 and later, under MAX_STRING_SIZE = EXTENDED, as on
    // Autonomous Database): BINARY compares by bytes whatever NLS_COMP is, and
    // anything else (BINARY_CI, a linguistic sort, USING_NLS_SORT) does not. A
    // server older than COLLATION has no column collations; any other failure
    // leaves every character column to DuckDB, which is slower but not wrong.
    void ApplyCollationsLocked(std::unordered_map<std::string, std::vector<OracleColumn>> &columns_by_object,
                               const std::string &only_object) const {
        std::string sql = "SELECT table_name, column_name, collation FROM " + View("tab_columns") +
                          " WHERE collation IS NOT NULL AND collation <> 'USING_NLS_COMP'" +
                          OwnerCondition("owner", "AND");
        if (!only_object.empty()) {
            sql += " AND table_name = " + Literal(only_object);
        }
        try {
            OracleMetadataLease session(transaction_pool, config, password);
            auto cursor = session->Query(sql, {});
            for (;;) {
                const auto batch = cursor->Fetch(STANDARD_VECTOR_SIZE);
                for (const auto &row : batch.rows) {
                    if (row.size() < 3 || !row[0] || !row[1] || !row[2]) {
                        continue;
                    }
                    const auto entry = columns_by_object.find(std::string(row[0]->begin(), row[0]->end()));
                    if (entry == columns_by_object.end()) {
                        continue;
                    }
                    const std::string column_name(row[1]->begin(), row[1]->end());
                    const std::string collation(row[2]->begin(), row[2]->end());
                    for (auto &column : entry->second) {
                        if (column.name == column_name) {
                            column.compared_as_bytes = collation == "BINARY";
                        }
                    }
                }
                if (batch.exhausted) {
                    break;
                }
            }
            cursor->Close();
            session.Finish();
        } catch (const std::exception &error) {
            if (std::string(error.what()).find("ORA-00904") != std::string::npos) {
                return; // no COLLATION column: a server before 12.2
            }
            for (auto &entry : columns_by_object) {
                for (auto &column : entry.second) {
                    column.compared_as_bytes = false;
                }
            }
        }
    }

    // Gives every VECTOR column in `columns` the shape the dictionary states,
    // so the type it is declared with here is the one a scan then produces.
    // VECTOR_INFO does not exist before 23ai, and a server that has VECTOR
    // columns has it; if the query is refused the shape stays unknown and the
    // column is a list of DOUBLE, which holds any dense vector but BINARY.
    void ApplyVectorShapesLocked(std::unordered_map<std::string, std::vector<OracleColumn>> &columns_by_object,
                                 const std::string &only_object) const {
        bool any = false;
        for (const auto &entry : columns_by_object) {
            for (const auto &column : entry.second) {
                any = any || column.oracle_type == 127;
            }
        }
        if (!any) {
            return;
        }
        std::string sql = "SELECT table_name, column_name, vector_info FROM " + View("tab_columns") +
                          " WHERE data_type = 'VECTOR'" + OwnerCondition("owner", "AND");
        if (!only_object.empty()) {
            std::string literal;
            for (const auto character : only_object) {
                literal.push_back(character);
                if (character == '\'') {
                    literal.push_back('\'');
                }
            }
            sql += " AND table_name = '" + literal + "'";
        }
        try {
            OracleMetadataLease session(transaction_pool, config, password);
            auto cursor = session->Query(sql, {});
            for (;;) {
                const auto batch = cursor->Fetch(STANDARD_VECTOR_SIZE);
                for (const auto &row : batch.rows) {
                    if (row.size() < 3 || !row[0] || !row[1] || !row[2]) {
                        continue;
                    }
                    const auto entry = columns_by_object.find(std::string(row[0]->begin(), row[0]->end()));
                    if (entry == columns_by_object.end()) {
                        continue;
                    }
                    const std::string column_name(row[1]->begin(), row[1]->end());
                    for (auto &column : entry->second) {
                        if (column.oracle_type == 127 && column.name == column_name) {
                            ParseVectorInfo(std::string(row[2]->begin(), row[2]->end()), column);
                        }
                    }
                }
                if (batch.exhausted) {
                    break;
                }
            }
            cursor->Close();
            session.Finish();
        } catch (const std::exception &) {
            // Shapes left unknown; the columns still read, as DOUBLE lists.
        }
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
        OracleMetadataLease session(transaction_pool, config, password);
        auto cursor = TranslatingOracleErrors("Oracle ATTACH could not read schema metadata", [&] {
            return session->Query("SELECT table_name, column_name, data_type, data_length, data_precision, "
                                  "data_scale, nullable FROM " + View("tab_columns") + OwnerCondition("owner", "WHERE") +
                                      " ORDER BY table_name, column_id",
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
        session.Finish();
        ApplyVectorShapesLocked(column_cache, std::string());
        ApplyCollationsLocked(column_cache, std::string());
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
        OracleMetadataLease session(transaction_pool, config, password);
        const auto metadata_sql = "SELECT column_name, data_type, data_length, data_precision, data_scale, nullable "
                                  "FROM " + View("tab_columns") + " WHERE table_name = '" + name_literal + "'" +
                                  OwnerCondition("owner", "AND") + " ORDER BY column_id";
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
        session.Finish();
        std::unordered_map<std::string, std::vector<OracleColumn>> by_object;
        by_object.emplace(object_name, std::move(columns));
        ApplyVectorShapesLocked(by_object, object_name);
        ApplyCollationsLocked(by_object, object_name);
        return std::move(by_object.begin()->second);
    }

    // Oracle enforces a primary key only while the constraint is enabled and
    // validated; a DISABLED or NOVALIDATE one can have rows that violate it.
    // Telling DuckDB about those would let it eliminate a DISTINCT or reshape a
    // join on a uniqueness that does not hold, so only the enforced ones count.
    void LoadPrimaryKeysLocked() const {
        primary_keys_loaded = true;
        try {
            OracleMetadataLease session(transaction_pool, config, password);
            auto cursor = TranslatingOracleErrors("Oracle ATTACH could not read primary keys", [&] {
                return session->Query("SELECT c.table_name, k.column_name FROM " + View("constraints") + " c JOIN " +
                                      View("cons_columns") + " k ON k.constraint_name = c.constraint_name AND "
                                      "k.table_name = c.table_name" +
                                      (OwnDictionary() ? std::string() : " AND k.owner = c.owner") +
                                      " WHERE c.constraint_type = 'P'" + OwnerCondition("c.owner", "AND") + " AND "
                                      "c.status = 'ENABLED' AND c.validated = 'VALIDATED' AND c.deferrable = 'NOT DEFERRABLE' ORDER BY c.table_name, "
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
            session.Finish();
        } catch (const std::exception &) {
            // A partial key list would name some columns of a composite key,
            // which is a different and false constraint.
            primary_key_cache.clear();
        }
    }

    bool IsTable(const std::string &object_name) const {
        std::lock_guard<std::mutex> lock(metadata_lock);
        RefreshMetadataLocked();
        if (!tables_loaded) {
            tables_loaded = true;
            try {
                OracleMetadataLease session(transaction_pool, config, password);
                auto cursor = TranslatingOracleErrors("Oracle ATTACH could not list tables", [&] {
                    return session->Query("SELECT table_name FROM " + View("tables") +
                                              (OwnDictionary() ? std::string() : " WHERE owner = " + Literal(owner)),
                                          {});
                });
                for (;;) {
                    const auto batch = TranslatingOracleErrors("Oracle ATTACH could not list tables",
                                                               [&] { return cursor->Fetch(STANDARD_VECTOR_SIZE); });
                    for (const auto &row : batch.rows) {
                        if (!row.empty() && row[0]) {
                            table_names.emplace(row[0]->begin(), row[0]->end());
                        }
                    }
                    if (batch.exhausted) {
                        break;
                    }
                }
                cursor->Close();
                session.Finish();
            } catch (const std::exception &) {
                table_names.clear();
            }
        }
        return table_names.count(object_name) > 0;
    }

    // What Oracle's own statistics say the table holds (USER_TABLES.NUM_ROWS),
    // read once for the whole schema. DuckDB plans joins from it: without an
    // estimate it believes every attached table has one row, builds its hash
    // table from the Oracle side, and cannot push a join's keys into the scan.
    // It is an estimate (a table without statistics has none, and a stale one
    // can be far off), so it only steers the plan and never a result. A failed
    // read leaves the tables without estimates, as before.
    std::optional<uint64_t> RowEstimate(const std::string &object_name) const {
        std::lock_guard<std::mutex> lock(metadata_lock);
        RefreshMetadataLocked();
        if (!row_estimates_loaded) {
            row_estimates_loaded = true;
            try {
                OracleMetadataLease session(transaction_pool, config, password);
                auto cursor = TranslatingOracleErrors("Oracle ATTACH could not read table statistics", [&] {
                    return session->Query("SELECT table_name, num_rows FROM " + View("tables") +
                                              " WHERE num_rows IS NOT NULL" + OwnerCondition("owner", "AND"),
                                          {});
                });
                for (;;) {
                    const auto batch = TranslatingOracleErrors("Oracle ATTACH could not read table statistics",
                                                               [&] { return cursor->Fetch(STANDARD_VECTOR_SIZE); });
                    for (const auto &row : batch.rows) {
                        if (row.size() < 2 || !row[0] || !row[1]) {
                            continue;
                        }
                        try {
                            const auto rows = std::stoull(oracle_scanner::DecodeOracleNumber(*row[1]));
                            row_estimates[std::string(row[0]->begin(), row[0]->end())] = rows;
                        } catch (const std::exception &) {
                            continue;
                        }
                    }
                    if (batch.exhausted) {
                        break;
                    }
                }
                cursor->Close();
                // How many different values each column holds, which is what the
                // optimizer needs to size a join or a GROUP BY. Only the count: a
                // statistic can be stale, and a stale minimum, maximum or null count
                // would let DuckDB skip rows, where a stale count only misjudges a plan.
                // The low and high values come too, but only for this extension's own
                // estimate of how many rows a filter keeps (EstimatedRowsAfterFilters);
                // DuckDB never sees them.
                auto distinct = TranslatingOracleErrors("Oracle ATTACH could not read column statistics", [&] {
                    return session->Query("SELECT table_name, column_name, num_distinct, low_value, high_value FROM " +
                                              View("tab_col_statistics") + " WHERE num_distinct IS NOT NULL" +
                                              OwnerCondition("owner", "AND"),
                                          {});
                });
                for (;;) {
                    const auto batch = TranslatingOracleErrors("Oracle ATTACH could not read column statistics",
                                                               [&] { return distinct->Fetch(STANDARD_VECTOR_SIZE); });
                    for (const auto &row : batch.rows) {
                        if (row.size() < 3 || !row[0] || !row[1] || !row[2]) {
                            continue;
                        }
                        try {
                            distinct_estimates[std::string(row[0]->begin(), row[0]->end())]
                                              [std::string(row[1]->begin(), row[1]->end())] =
                                std::stoull(oracle_scanner::DecodeOracleNumber(*row[2]));
                            if (row.size() >= 5 && row[3] && row[4]) {
                                value_bounds[std::string(row[0]->begin(), row[0]->end())]
                                            [std::string(row[1]->begin(), row[1]->end())] = {*row[3], *row[4]};
                            }
                        } catch (const std::exception &) {
                            continue;
                        }
                    }
                    if (batch.exhausted) {
                        break;
                    }
                }
                distinct->Close();
                session.Finish();
            } catch (const std::exception &) {
                row_estimates.clear();
                distinct_estimates.clear();
                value_bounds.clear();
            }
        }
        const auto found = row_estimates.find(object_name);
        if (found == row_estimates.end()) {
            return std::nullopt;
        }
        return found->second;
    }

    // The distinct-value count of each of the table's columns, in order, where the
    // statistics have one.
    std::vector<std::optional<uint64_t>> DistinctCounts(const std::string &object_name,
                                                        const std::vector<OracleColumn> &columns) const {
        (void)RowEstimate(object_name); // loads the statistics
        std::lock_guard<std::mutex> lock(metadata_lock);
        RefreshMetadataLocked();
        std::vector<std::optional<uint64_t>> result(columns.size());
        const auto table = distinct_estimates.find(object_name);
        if (table == distinct_estimates.end()) {
            return result;
        }
        for (size_t index = 0; index < columns.size(); index++) {
            const auto found = table->second.find(columns[index].name);
            if (found != table->second.end()) {
                result[index] = found->second;
            }
        }
        return result;
    }

    // LOW_VALUE and HIGH_VALUE of each NUMBER, DATE and TIMESTAMP column, in order,
    // as numbers or seconds since 1970, where the statistics have them.
    std::vector<std::optional<std::pair<double, double>>> ValueBounds(const std::string &object_name,
                                                                      const std::vector<OracleColumn> &columns) const {
        (void)RowEstimate(object_name); // loads the statistics
        std::lock_guard<std::mutex> lock(metadata_lock);
        RefreshMetadataLocked();
        std::vector<std::optional<std::pair<double, double>>> result(columns.size());
        const auto table = value_bounds.find(object_name);
        if (table == value_bounds.end()) {
            return result;
        }
        const auto point = [](const OracleColumn &column, const std::vector<uint8_t> &raw) -> std::optional<double> {
            if (column.oracle_type == 2) {
                return std::stod(oracle_scanner::DecodeOracleNumber(raw));
            }
            if (column.oracle_type == 12 || column.oracle_type == 180) {
                const auto value = column.oracle_type == 12 ? oracle_scanner::DecodeOracleDate(raw)
                                                            : oracle_scanner::DecodeOracleTimestamp(raw);
                const auto day = Date::FromDate(value.year, value.month, value.day);
                return static_cast<double>(day.days) * 86400.0 + value.hour * 3600.0 + value.minute * 60.0 +
                       value.second + value.nanosecond / 1e9;
            }
            return std::nullopt;
        };
        for (size_t index = 0; index < columns.size(); index++) {
            const auto found = table->second.find(columns[index].name);
            if (found == table->second.end()) {
                continue;
            }
            try {
                const auto low = point(columns[index], found->second.first);
                const auto high = point(columns[index], found->second.second);
                if (low && high && *high >= *low) {
                    result[index] = std::make_pair(*low, *high);
                }
            } catch (const std::exception &) {
                // An encoding this does not read leaves the column without bounds.
            }
        }
        return result;
    }

    std::vector<std::string> PrimaryKeyColumns(const std::string &object_name) const {
        std::lock_guard<std::mutex> lock(metadata_lock);
        RefreshMetadataLocked();
        if (!primary_keys_loaded) {
            LoadPrimaryKeysLocked();
        }
        const auto entry = primary_key_cache.find(object_name);
        if (entry == primary_key_cache.end()) {
            return {};
        }
        return entry->second;
    }

    std::vector<std::vector<std::string>> UniqueKeys(const std::string &object_name) const {
        std::lock_guard<std::mutex> lock(metadata_lock);
        RefreshMetadataLocked();
        std::vector<std::vector<std::string>> result;
        try {
            OracleMetadataLease session(transaction_pool, config, password);
            auto cursor = session->Query("SELECT c.constraint_name, k.column_name, c.constraint_type FROM " + View("constraints") +
                " c JOIN " + View("cons_columns") + " k ON k.constraint_name=c.constraint_name AND k.table_name=c.table_name" +
                (OwnDictionary() ? std::string() : " AND k.owner=c.owner") +
                " WHERE c.constraint_type='U' AND c.status='ENABLED' AND c.validated='VALIDATED'" +
                " AND c.deferrable='NOT DEFERRABLE' AND c.table_name=" + KeywordHelper::WriteQuotedAndEscaped(object_name, '\'') +
                OwnerCondition("c.owner", "AND") + " ORDER BY c.constraint_name,k.position", {});
            std::string previous;
            for (;;) {
                const auto batch = cursor->Fetch(STANDARD_VECTOR_SIZE);
                for (const auto &row : batch.rows) {
                    if (row.size() != 3 || !row[0] || !row[1] || !row[2] || std::string(row[2]->begin(), row[2]->end()) != "U") {
                        throw IOException("Oracle UNIQUE metadata is incomplete");
                    }
                    std::string name(row[0]->begin(), row[0]->end());
                    if (name != previous || result.empty()) { result.emplace_back(); previous = name; }
                    result.back().emplace_back(row[1]->begin(), row[1]->end());
                }
                if (batch.exhausted) { break; }
            }
            cursor->Close();
            session.Finish();
        } catch (const std::exception &) { result.clear(); }
        return result;
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
        RefreshMetadataLocked();
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

    // DuckDB looks a name up as the user typed it, and Oracle stores unquoted
    // names in upper case, so `o.items` has to find ITEMS. An exact match wins;
    // otherwise a match ignoring case is taken only when exactly one object has
    // it, because a schema can hold both "items" and ITEMS and then the name
    // does not say which was meant. Returns the name as Oracle stores it, or
    // empty when there is no such object.
    std::string ResolveObjectName(const std::string &requested) const {
        {
            std::lock_guard<std::mutex> lock(metadata_lock);
            RefreshMetadataLocked();
            if (!metadata_loaded) {
                LoadSchemaColumnsLocked();
            }
            if (column_cache.find(requested) != column_cache.end()) {
                return column_cache.at(requested).empty() ? std::string() : requested;
            }
            std::string found;
            size_t matches = 0;
            for (const auto &entry : column_cache) {
                if (!entry.second.empty() && StringUtil::CIEquals(entry.first, requested)) {
                    found = entry.first;
                    matches++;
                }
            }
            if (matches == 1) {
                return found;
            }
            if (matches > 1 || metadata_complete) {
                return std::string();
            }
        }
        // An incomplete dictionary cannot prove existence. Describe the exact
        // spelling first, then the spelling of an unquoted Oracle identifier.
        if (!TryDescribe(requested).empty()) {
            return requested;
        }
        auto upper = StringUtil::Upper(requested);
        if (upper != requested && !TryDescribe(upper).empty()) {
            return upper;
        }
        return std::string();
    }

    // Describes the table from the dictionary and leaves the Oracle statement
    // for init, which is the first point that knows which columns the plan
    // actually reads.
    unique_ptr<OracleQueryBindData> PrepareScan(const std::string &object_name,
                                                const std::vector<OracleColumn> &entry_columns) const {
        auto result = make_uniq<OracleQueryBindData>();
        result->deferred_scan = true;
        result->config = config;
        result->password = password;
        result->object_name = object_name;
        result->estimated_rows = RowEstimate(object_name);
        result->distinct_counts = DistinctCounts(object_name, entry_columns);
        result->value_bounds = ValueBounds(object_name, entry_columns);
        result->schema_name = owner;
        result->secret_name = secret_name;
        // The table entry's own columns: they carry the number mapping chosen when
        // the entry was made, which is the one its DuckDB types were built from.
        result->columns = entry_columns;
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

// DuckDB 2.0 reads the table a scan addresses from get_table_entry (see
// LogicalGet::GetTable), not from its BindInfo; UPDATE, DELETE and the rowid
// virtual column depend on it.
optional_ptr<TableCatalogEntry> OracleAttachedScanTableEntry(optional_ptr<const FunctionData> bind_data) {
    auto &bind = bind_data->Cast<OracleQueryBindData>();
    if (!bind.table_entry) {
        throw InternalException("an attached Oracle scan has no table entry");
    }
    return bind.table_entry;
}

// The estimate PrepareScan read from the dictionary, for the optimizer.
unique_ptr<NodeStatistics> OracleAttachedScanCardinality(ClientContext &, const FunctionData *bind_data) {
	if (!bind_data) {
		return nullptr;
	}
	const auto &bind = bind_data->Cast<OracleQueryBindData>();
	if (!bind.estimated_rows) {
		return nullptr;
	}
	return make_uniq<NodeStatistics>(static_cast<idx_t>(*bind.estimated_rows));
}

// What the optimizer is told about one column: how many different values it
// holds, and nothing else.
unique_ptr<BaseStatistics> OracleAttachedScanStatistics(ClientContext &, const FunctionData *bind_data,
                                                        column_t column_index) {
	if (!bind_data) {
		return nullptr;
	}
	const auto &bind = bind_data->Cast<OracleQueryBindData>();
	if (column_index >= bind.distinct_counts.size() || column_index >= bind.types.size() ||
	    !bind.distinct_counts[column_index]) {
		return nullptr;
	}
	auto statistics = BaseStatistics::CreateUnknown(bind.types[column_index]);
	auto distinct = static_cast<idx_t>(*bind.distinct_counts[column_index]);
	if (bind.estimated_rows) {
		distinct = MinValue<idx_t>(distinct, static_cast<idx_t>(*bind.estimated_rows));
	}
	statistics.SetDistinctCount(distinct);
	return statistics.ToUnique();
}

class OracleAttachedTableEntry final : public TableCatalogEntry {
public:
    OracleAttachedTableEntry(Catalog &catalog, SchemaCatalogEntry &schema, unique_ptr<CreateTableInfo> info,
                             shared_ptr<OracleAttachedState> state_p, std::string object_name_p,
                             std::vector<OracleColumn> oracle_columns_p)
        : TableCatalogEntry(catalog, schema, *info), columns(std::move(info->columns)), state(std::move(state_p)),
          object_name(std::move(object_name_p)), oracle_columns(std::move(oracle_columns_p)) {
    }

    // DuckDB 2.0 leaves the columns to the entry, as DuckTableEntry keeps its own.
    const ColumnList &GetColumns() const override {
        return columns;
    }

    static unique_ptr<OracleAttachedTableEntry> Create(ClientContext &context, Catalog &catalog,
                                                        SchemaCatalogEntry &schema,
                                                        shared_ptr<OracleAttachedState> state,
                                                        const std::string &requested_name) {
        const auto object_name = state->ResolveObjectName(requested_name);
        auto oracle_columns = object_name.empty() ? std::vector<OracleColumn>() : state->TryDescribe(object_name);
        ApplyUnconstrainedNumberSetting(context, oracle_columns);
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
            ColumnDefinition definition(Identifier(output_name), MappedType(oracle_columns[index]));
            definition.SetDefaultValue(make_uniq<FunctionExpression>(Identifier("__oracle_scanner_default"), vector<unique_ptr<ParsedExpression>>()));
            info->columns.AddColumn(std::move(definition));
            if (!oracle_columns[index].nullable) {
                // USER_TAB_COLUMNS already carries this, so it costs no query.
                info->constraints.push_back(make_uniq<NotNullConstraint>(LogicalIndex(index)));
            }
        }
        auto key_columns = state->PrimaryKeyColumns(object_name);
        duckdb::vector<Identifier> key_names;
        for (const auto &key_column : key_columns) {
            const auto named = output_names.find(key_column);
            if (named == output_names.end()) {
                // A key column the describe did not return leaves the key
                // incomplete, and a partial key is a false constraint.
                key_names.clear();
                break;
            }
            key_names.push_back(Identifier(named->second));
        }
        if (!key_names.empty()) {
            info->constraints.push_back(make_uniq<UniqueConstraint>(std::move(key_names), true));
        }
        for (const auto &key : state->UniqueKeys(object_name)) {
            duckdb::vector<Identifier> names;
            for (const auto &column : key) {
                const auto found = output_names.find(column);
                if (found == output_names.end()) { names.clear(); break; }
                names.emplace_back(found->second);
            }
            if (!names.empty()) { info->constraints.push_back(make_uniq<UniqueConstraint>(std::move(names), false)); }
        }
        info->on_conflict = OnCreateConflict::IGNORE_ON_CONFLICT;
        return make_uniq<OracleAttachedTableEntry>(catalog, schema, std::move(info), std::move(state), object_name,
                                                   oracle_columns);
    }

    TableFunction GetScanFunction(ClientContext &context, unique_ptr<FunctionData> &bind_data) override {
        auto scan_bind = state->PrepareScan(object_name, oracle_columns);
        scan_bind->table_entry = this;
        scan_bind->catalog_name = static_cast<const std::string &>(catalog.GetAttached().GetName());
        bind_data = std::move(scan_bind);
        TableFunction function({}, OracleQueryFunction, nullptr, OracleQueryInit);
        function.name = "oracle_attached_scan";
        function.get_table_entry = OracleAttachedScanTableEntry;
        Value pushdown;
        function.filter_pushdown =
            context.TryGetCurrentSetting("oracle_filter_pushdown", pushdown) && BooleanValue::Get(pushdown);
        function.projection_pushdown = true;
        function.pushdown_expression = OraclePushdownExpression;
        function.cardinality = OracleAttachedScanCardinality;
        // TABLESAMPLE SYSTEM becomes Oracle's SAMPLE BLOCK, so a sample of a big
        // table reads a fraction of its blocks instead of all of them.
        function.sampling_pushdown = state->IsTable(object_name);
        function.init_local = OracleQueryInitLocal;
        function.get_metrics = OracleQueryMetrics;
        function.get_partition_data = OracleQueryPartitionData;
        function.statistics = OracleAttachedScanStatistics;
        return function;
    }

    void BindUpdateConstraints(Binder &, LogicalGet &, LogicalProjection &, LogicalUpdate &update,
                               ClientContext &) override {
        // Oracle enforces its constraints and updates its own indexes. DuckDB's
        // delete/insert emulation adds unchanged columns to SET, which would
        // write lossy read mappings back and fire unrelated UPDATE OF triggers.
        update.update_is_del_and_insert = false;
    }

    TableStorageInfo GetStorageInfo(ClientContext &) override {
        TableStorageInfo result;
        for (const auto &constraint : GetConstraints()) {
            if (constraint->type != ConstraintType::UNIQUE) { continue; }
            const auto &unique = constraint->Cast<UniqueConstraint>();
            IndexInfo index;
            index.is_unique = true;
            index.is_primary = unique.IsPrimaryKey();
            index.is_foreign = false;
            for (const auto &logical : unique.GetLogicalIndexes(columns)) {
                index.column_set.insert(columns.GetColumn(logical).Physical().index);
            }
            result.index_info.push_back(std::move(index));
        }
        return result;
    }

    const std::vector<OracleColumn> &OracleColumns() const {
        return oracle_columns;
    }

    const std::string &ObjectName() const {
        return object_name;
    }

    void OnDrop() override {
        // The entry lives in a DuckDB catalog set that would forget it happily
        // while Oracle still has the table.
        throw NotImplementedException("Oracle table \"%s\" cannot be dropped through ATTACH. %s", object_name,
                                      ORACLE_DDL_ROUTE);
    }

    // ALTER TABLE reaches the entry itself, and the base class answers with an
    // InternalException, which invalidates the whole database.
    unique_ptr<CatalogEntry> AlterEntry(ClientContext &, AlterInfo &) override {
        throw NotImplementedException("Oracle table \"%s\" cannot be altered through ATTACH. %s", object_name,
                                      ORACLE_DDL_ROUTE);
    }
    unique_ptr<CatalogEntry> AlterEntry(CatalogTransaction, AlterInfo &) override {
        throw NotImplementedException("Oracle table \"%s\" cannot be altered through ATTACH. %s", object_name,
                                      ORACLE_DDL_ROUTE);
    }

    // DuckDB reaches for local storage on paths that assume a table it owns —
    // DROP clears transaction-local insertions this way, before OnDrop runs.
    // The base class answers with an InternalException, which invalidates the
    // database; an Oracle table simply has no DuckDB-local storage, and saying
    // so leaves the connection usable.
    DataTable &GetStorage() override {
        throw NotImplementedException("Oracle table \"%s\" has no DuckDB-local storage. For DROP or ALTER: %s",
                                      object_name, ORACLE_DDL_ROUTE);
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
        target.schema_name = state->owner;
        target.config = state->config;
        target.password = state->password;
        target.pool = state->transaction_pool;
        return target;
    }

private:
    ColumnList columns;
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
            result.emplace_back(name);
        }
        return result;
    }

    // GetDefaultEntries above enumerates the schema; this answers the different
    // question of whether one particular name is ours, and a null answer means
    // it is not.
    unique_ptr<CatalogEntry> CreateDefaultEntry(ClientContext &context, const Identifier &entry_name) override {
        return OracleAttachedTableEntry::Create(context, catalog, schema, state,
                                                static_cast<const std::string &>(entry_name));
    }

private:
    SchemaCatalogEntry &schema;
    shared_ptr<OracleAttachedState> state;
};

// DDL is immediate in Oracle. Keep it off the caller's DML session, and keep
// acknowledged CREATEs for compensating cleanup on transaction rollback.
std::string DdlQuote(const std::string &name) { return KeywordHelper::WriteQuotedAndEscaped(name, '"'); }

std::pair<std::string, OracleColumn> DdlType(const LogicalType &type) {
    OracleColumn column;
    std::string sql;
    int precision = 0;
    switch (type.id()) {
    case LogicalTypeId::BOOLEAN: precision = 1; break;
    case LogicalTypeId::TINYINT: precision = 3; break;
    case LogicalTypeId::SMALLINT: precision = 5; break;
    case LogicalTypeId::INTEGER: precision = 10; break;
    case LogicalTypeId::BIGINT: precision = 19; break;
    case LogicalTypeId::UTINYINT: precision = 3; break;
    case LogicalTypeId::USMALLINT: precision = 5; break;
    case LogicalTypeId::UINTEGER: precision = 10; break;
    case LogicalTypeId::UBIGINT: precision = 20; break;
    case LogicalTypeId::HUGEINT: precision = 38; break;
    case LogicalTypeId::DECIMAL:
        column.oracle_type = 2;
        column.precision = DecimalType::GetWidth(type);
        column.scale = DecimalType::GetScale(type);
        sql = "NUMBER(" + std::to_string(column.precision) + "," + std::to_string(column.scale) + ")";
        break;
    case LogicalTypeId::VARCHAR: column.oracle_type = 1; column.byte_width = 4000; sql = "VARCHAR2(4000 BYTE)"; break;
    case LogicalTypeId::BLOB: column.oracle_type = 113; sql = "BLOB"; break;
    case LogicalTypeId::FLOAT: column.oracle_type = 100; sql = "BINARY_FLOAT"; break;
    case LogicalTypeId::DOUBLE: column.oracle_type = 101; sql = "BINARY_DOUBLE"; break;
    case LogicalTypeId::DATE: column.oracle_type = 12; sql = "DATE"; break;
    case LogicalTypeId::TIMESTAMP_SEC: column.oracle_type = 180; column.scale = 0; sql = "TIMESTAMP(0)"; break;
    case LogicalTypeId::TIMESTAMP_MS: column.oracle_type = 180; column.scale = 3; sql = "TIMESTAMP(3)"; break;
    case LogicalTypeId::TIMESTAMP: column.oracle_type = 180; column.scale = 6; sql = "TIMESTAMP(6)"; break;
    case LogicalTypeId::TIMESTAMP_NS: column.oracle_type = 180; column.scale = 9; sql = "TIMESTAMP(9)"; break;
    case LogicalTypeId::TIMESTAMP_TZ: column.oracle_type = 231; column.scale = 6; sql = "TIMESTAMP(6) WITH LOCAL TIME ZONE"; break;
    default: throw NotImplementedException("Oracle CREATE/ADD COLUMN does not support DuckDB type %s", type.ToString());
    }
    if (precision) {
        column.oracle_type = 2; column.precision = precision; column.scale = 0;
        sql = "NUMBER(" + std::to_string(precision) + ",0)";
    }
    return {sql, column};
}

std::string DdlDefault(const ParsedExpression &expression) {
    if (expression.GetExpressionClass() != ExpressionClass::CONSTANT) {
        throw NotImplementedException("Oracle DDL supports literal defaults only; use oracle_execute_admin for expressions");
    }
    const auto value = expression.Cast<ConstantExpression>().GetLiteral().ToValue();
    if (value.IsNull()) { return "NULL"; }
    if (value.type().id() == LogicalTypeId::VARCHAR) {
        if (value.ToString().find('\0') != std::string::npos) { throw InvalidInputException("Oracle DDL default contains NUL"); }
        return KeywordHelper::WriteQuotedAndEscaped(value.ToString(), '\'');
    }
    if (value.type().id() == LogicalTypeId::BOOLEAN) { return value.GetValue<bool>() ? "1" : "0"; }
    if (value.type().IsNumeric()) {
        if ((value.type().id() == LogicalTypeId::DOUBLE || value.type().id() == LogicalTypeId::FLOAT) &&
            !std::isfinite(value.GetValue<double>())) { throw InvalidInputException("Oracle default must be finite"); }
        return value.ToString();
    }
    throw NotImplementedException("Oracle DDL default type %s is not supported", value.type().ToString());
}

std::string DdlColumn(const ColumnDefinition &column) {
    if (column.Generated()) { throw NotImplementedException("Oracle CREATE does not support generated columns"); }
    auto sql = DdlQuote(column.Name().GetIdentifierName()) + " " + DdlType(column.Type()).first;
    if (column.HasDefaultValue()) {
        const auto &expression = column.DefaultValue();
        if (expression.GetExpressionClass() == ExpressionClass::CONSTANT) {
            const auto value = expression.Cast<ConstantExpression>().GetLiteral().ToValue();
            const auto type = DdlType(column.Type()).second.oracle_type;
            if (!value.IsNull() && ((type == 1 && value.type().id() != LogicalTypeId::VARCHAR) ||
                ((type == 2 || type == 100 || type == 101) && !value.type().IsNumeric() && value.type().id() != LogicalTypeId::BOOLEAN) ||
                (type != 1 && type != 2 && type != 100 && type != 101))) {
                throw NotImplementedException("Oracle DDL default must match the column type without an implicit conversion");
            }
        }
        sql += " DEFAULT " + DdlDefault(expression);
    }
    return sql;
}

std::string CreateDdl(const CreateTableInfo &info, const std::string &owner) {
    if (info.temporary || info.on_conflict == OnCreateConflict::REPLACE_ON_CONFLICT ||
        !info.options.empty() || !info.partition_keys.empty() || !info.sort_keys.empty()) {
        throw NotImplementedException("Oracle CREATE does not support TEMPORARY, OR REPLACE, partitioning or table options");
    }
    std::string list;
    for (const auto &column : info.columns.Physical()) {
        list += (list.empty() ? "" : ", ") + DdlColumn(column);
        if (info.FindNotNullConstraint(column.Logical()).IsValid()) { list += " NOT NULL"; }
    }
    for (const auto &constraint : info.constraints) {
        if (constraint->type == ConstraintType::NOT_NULL) { continue; }
        if (constraint->type != ConstraintType::UNIQUE) { throw NotImplementedException("Oracle CREATE supports NOT NULL, PRIMARY KEY and UNIQUE constraints only"); }
        const auto &key = constraint->Cast<UniqueConstraint>();
        list += key.IsPrimaryKey() ? ", PRIMARY KEY (" : ", UNIQUE (";
        bool first = true;
        for (const auto index : key.GetLogicalIndexes(info.columns)) {
            list += (first ? "" : ", ") + DdlQuote(info.columns.GetColumn(index).Name().GetIdentifierName()); first = false;
        }
        list += ")";
    }
    if (list.empty()) { throw InvalidInputException("Oracle CREATE needs columns"); }
    return "CREATE TABLE " + OracleObjectReference(owner, info.GetTableName().GetIdentifierName()) + " (" + list + ")";
}

std::shared_ptr<oracle_scanner::OracleIoDeadline> DdlDeadline(optional_ptr<ClientContext> context, bool cleanup) {
    if (!cleanup) { return OracleIoDeadlineFor(*context); }
    // Executor cancellation is already set during error rollback. Compensation
    // uses a separate bounded budget and must not inherit that failed query.
    auto deadline = std::make_shared<oracle_scanner::OracleIoDeadline>();
    deadline->Set(std::chrono::steady_clock::now() + std::chrono::seconds(10));
    return deadline;
}

void RunAttachedDdl(optional_ptr<ClientContext> context, const shared_ptr<OracleAttachedState> &state, const std::string &sql, bool cleanup = false, const std::string &lock_table = std::string()) {
    std::lock_guard<std::mutex> guard(state->epoch->ddl_lock);
    auto config = state->config;
    config.io_deadline = DdlDeadline(context, cleanup);
    if (cleanup) { config.connect_cancelled = nullptr; }
    TranslatingOracleErrors("Oracle DDL failed", [&] {
        auto session = oracle_scanner::OpenOracleSession(config, state->password);
        session->ExecuteAdmin("ALTER SESSION SET DDL_LOCK_TIMEOUT=0");
        // Some ALTER paths wait on TX even with DDL_LOCK_TIMEOUT=0. Check
        // existing DML locks explicitly before Oracle's implicit DDL commit.
        if (!lock_table.empty()) {
            oracle_scanner::OracleCallRequest request;
            request.kind = oracle_scanner::OracleCallableKind::ANONYMOUS_BLOCK;
            request.block = "BEGIN EXECUTE IMMEDIATE " + OracleAttachedState::Literal(
                "LOCK TABLE " + lock_table + " IN EXCLUSIVE MODE NOWAIT") + "; END;";
            session->Call(request);
        }
        session->ExecuteAdmin(sql);
        session->Close();
    });
    state->InvalidateMetadata();
}

struct OracleDdlUndo final : ClientContextState {
    struct Created { shared_ptr<OracleAttachedState> state; std::string name; std::string object_id; };
    std::unordered_map<std::string, std::vector<Created>> created;
    std::unordered_map<std::string, std::function<void()>> rollback_writes;
    ~OracleDdlUndo() override;
};

std::string DdlObjectId(optional_ptr<ClientContext> context, const shared_ptr<OracleAttachedState> &state, const std::string &name, bool cleanup = false) {
    auto config = state->config; config.io_deadline = DdlDeadline(context, cleanup);
    if (cleanup) { config.connect_cancelled = nullptr; }
    auto session = oracle_scanner::OpenOracleSession(config, state->password);
    auto cursor = session->Query("SELECT TO_CHAR(object_id) FROM " + state->View("objects") +
        " WHERE object_type='TABLE' AND object_name=" + OracleAttachedState::Literal(name) + state->OwnerCondition("owner", "AND"), {});
    auto batch = cursor->Fetch(2);
    std::string id;
    if (batch.rows.size() == 1 && batch.rows[0].size() == 1 && batch.rows[0][0]) {
        id.assign(batch.rows[0][0]->begin(), batch.rows[0][0]->end());
    }
    cursor->Close(); session->Close();
    return id;
}

void CompensateOracleCreate(optional_ptr<ClientContext> context, const OracleDdlUndo::Created &entry) {
    if (entry.object_id.empty()) {
        throw IOException("Oracle CREATE rollback refused a table without a recorded identity");
    }
    std::lock_guard<std::mutex> guard(entry.state->epoch->ddl_lock);
    auto config = entry.state->config;
    config.io_deadline = DdlDeadline(context, true);
    config.connect_cancelled = nullptr;
    const auto reference = OracleObjectReference(entry.state->owner, entry.name);
    oracle_scanner::OracleCallRequest request;
    request.kind = oracle_scanner::OracleCallableKind::ANONYMOUS_BLOCK;
    request.block = "DECLARE rv_expected_id CONSTANT VARCHAR2(128) := " + OracleAttachedState::Literal(entry.object_id) +
        "; rv_actual_id VARCHAR2(128); BEGIN "
        "BEGIN EXECUTE IMMEDIATE " + OracleAttachedState::Literal("LOCK TABLE " + reference + " IN EXCLUSIVE MODE NOWAIT") +
        "; EXCEPTION WHEN OTHERS THEN IF SQLCODE=-942 THEN RETURN; ELSE RAISE; END IF; END; "
        "SELECT TO_CHAR(object_id) INTO rv_actual_id FROM " + entry.state->View("objects") +
        " WHERE object_type='TABLE' AND object_name=" + OracleAttachedState::Literal(entry.name) +
        entry.state->OwnerCondition("owner", "AND") +
        "; IF rv_actual_id <> rv_expected_id THEN "
        "RAISE_APPLICATION_ERROR(-20907, 'Oracle CREATE rollback refused: table identity changed'); END IF; "
        "EXECUTE IMMEDIATE " + OracleAttachedState::Literal("DROP TABLE " + reference) +
        "; EXCEPTION WHEN NO_DATA_FOUND THEN NULL; END;";
    TranslatingOracleErrors("Oracle CREATE rollback cleanup failed", [&] {
        auto session = oracle_scanner::OpenOracleSession(config, entry.state->password);
        session->ExecuteAdmin("ALTER SESSION SET DDL_LOCK_TIMEOUT=0");
        session->Call(request);
        session->Close();
    });
    entry.state->InvalidateMetadata();
}

void CompensateOracleCreates(optional_ptr<ClientContext> context, std::vector<OracleDdlUndo::Created> entries) {
    std::string errors;
    for (auto it = entries.rbegin(); it != entries.rend(); ++it) {
        try {
            CompensateOracleCreate(context, *it);
        } catch (const std::exception &error) {
            it->state->InvalidateMetadata();
            errors += std::string(errors.empty() ? "" : "; ") + error.what();
        }
    }
    if (!errors.empty()) { throw IOException("Oracle CREATE rollback cleanup failed: %s", errors); }
}

OracleDdlUndo::~OracleDdlUndo() {
    // ClientContext's weak pointer has expired during connection destruction.
    // Retain the write state independently and release its locks before DDL.
    for (auto &entry : created) {
        try {
            const auto rollback = rollback_writes.find(entry.first);
            if (rollback != rollback_writes.end()) { rollback->second(); }
            CompensateOracleCreates(nullptr, std::move(entry.second));
        } catch (...) {
            // Destructors cannot report failures; explicit ROLLBACK reports them.
        }
    }
}

void FinishOracleDdl(ClientContext &context, const std::string &catalog, bool commit) {
    auto undo = context.registered_state->Get<OracleDdlUndo>("oracle_scanner.ddl_undo");
    if (!undo) { return; }
    auto found = undo->created.find(catalog);
    if (found == undo->created.end()) { return; }
    auto entries = std::move(found->second); undo->created.erase(found);
    undo->rollback_writes.erase(catalog);
    if (!commit) { CompensateOracleCreates(context, std::move(entries)); }
}

class OracleSchemaEntry final : public DuckSchemaEntry {
public:
    OracleSchemaEntry(Catalog &catalog, CreateSchemaInfo &info, shared_ptr<OracleAttachedState> state)
        : DuckSchemaEntry(catalog, info), state(std::move(state)) {
        auto generator = make_uniq<OracleAttachedTableGenerator>(catalog, *this, this->state);
        defaults = generator.get();
        GetCatalogSet(CatalogType::TABLE_ENTRY).SetDefaultGenerator(std::move(generator));
    }
    shared_ptr<OracleAttachedState> State() const { return state; }
    static bool IsRelation(CatalogType type) { return type==CatalogType::TABLE_ENTRY || type==CatalogType::VIEW_ENTRY; }
    void Sync(ClientContext &context) {
        std::lock_guard<std::mutex> guard(cache_lock);
        const auto version = state->epoch->version.load();
        if (version == cached_version) { return; }
        auto &set = GetCatalogSet(CatalogType::TABLE_ENTRY);
        vector<Identifier> names;
        set.Scan([&](CatalogEntry &entry) { if (entry.type == CatalogType::TABLE_ENTRY) { names.push_back(entry.name); } });
        const auto system = CatalogTransaction::GetSystemTransaction(catalog.GetDatabase());
        has_materialized_entries |= !names.empty();
        for (const auto &name : names) { set.DropEntry(system, name, true); }
        if (has_materialized_entries) {
            // A tombstone prevents DuckDB's default generator from running.
            // Restore previously materialized names that Oracle has revived,
            // without eagerly constructing every table in the remote schema.
            std::unordered_set<std::string> scheduled;
            for (const auto &name : names) { scheduled.insert(name.GetIdentifierName()); }
            for (const auto &remote : state->ListObjects()) {
                const auto head = set.GetHeadEntry(Identifier(remote));
                if (head && head->deleted && scheduled.insert(remote).second) { names.emplace_back(remote); }
            }
        }
        for (const auto &name : names) {
            auto entry = OracleAttachedTableEntry::Create(context, catalog, *this, state, name.GetIdentifierName());
            if (entry) { set.CreateEntry(system, entry->name, std::move(entry), LogicalDependencyList()); }
        }
        defaults->created_all_entries = false;
        cached_version = version;
    }
    optional_ptr<CatalogEntry> LookupEntry(CatalogTransaction transaction, const EntryLookupInfo &lookup) override {
        if (transaction.context && IsRelation(lookup.GetCatalogType())) { Sync(*transaction.context); }
        return DuckSchemaEntry::LookupEntry(transaction, lookup);
    }
    CatalogSet::EntryLookup LookupEntryDetailed(CatalogTransaction transaction, const EntryLookupInfo &lookup) override {
        if (transaction.context && IsRelation(lookup.GetCatalogType())) { Sync(*transaction.context); }
        return DuckSchemaEntry::LookupEntryDetailed(transaction, lookup);
    }
    void Scan(ClientContext &context, CatalogType type, const std::function<void(CatalogEntry &)> &callback) override {
        if (IsRelation(type)) { Sync(context); }
        DuckSchemaEntry::Scan(context, type, callback);
    }
    void Scan(CatalogTransaction transaction, CatalogType type, const std::function<void(CatalogEntry &)> &callback) override {
        if (transaction.context && IsRelation(type)) { Sync(*transaction.context); }
        DuckSchemaEntry::Scan(transaction, type, callback);
    }
    optional_ptr<CatalogEntry> CreateTable(CatalogTransaction transaction, BoundCreateTableInfo &info) override {
        auto &context = transaction.GetContext();
        if (catalog.GetAttached().IsReadOnly()) { throw BinderException("Oracle DDL is not allowed on a read-only catalog"); }
        Sync(context);
        const auto &base = info.Base();
        const auto sql = CreateDdl(base, state->owner); // validate everything before side effects
        const auto name = base.GetTableName().GetIdentifierName();
        auto &set = GetCatalogSet(CatalogType::TABLE_ENTRY);
        if (!state->ResolveObjectName(name).empty()) {
            if (base.on_conflict == OnCreateConflict::IGNORE_ON_CONFLICT) { return nullptr; }
            throw CatalogException("Oracle table already exists: %s", name);
        }
        RunAttachedDdl(context, state, sql);
        auto undo = context.registered_state->GetOrCreate<OracleDdlUndo>("oracle_scanner.ddl_undo");
        const auto catalog_name = catalog.GetName().GetIdentifierName();
        undo->rollback_writes[catalog_name] = OracleRollbackForCleanup(context, catalog_name);
        auto &created = undo->created[catalog_name];
        created.push_back({state, name, std::string()});
        created.back().object_id = DdlObjectId(context, state, name);
        if (created.back().object_id.empty()) { throw IOException("Oracle CREATE succeeded but its object identity could not be read; reconcile the table manually"); }
        Sync(context);
        // Sync may already have restored a previously materialized name.
        auto head = set.GetHeadEntry(Identifier(name));
        if (head && !head->deleted) { return head; }
        auto entry = OracleAttachedTableEntry::Create(context, catalog, *this, state, name);
        if (!entry) { throw IOException("Oracle CREATE succeeded but its table could not be described"); }
        auto result = entry.get();
        const auto system = CatalogTransaction::GetSystemTransaction(catalog.GetDatabase());
        if (!set.CreateEntry(system, entry->name, std::move(entry), LogicalDependencyList())) {
            throw IOException("Oracle CREATE metadata cache could not be updated");
        }
        return result;
    }
    void DropEntry(ClientContext &context, DropInfo &info) override {
        if (catalog.GetAttached().IsReadOnly()) { throw BinderException("Oracle DDL is not allowed on a read-only catalog"); }
        if (info.type != CatalogType::TABLE_ENTRY || info.cascade) { throw NotImplementedException("Oracle DROP supports TABLE without CASCADE only"); }
        Sync(context);
        const auto requested = info.GetQualifiedName().Name().GetIdentifierName();
        const auto name = state->ResolveObjectName(requested);
        if (name.empty()) {
            if (info.if_not_found == OnEntryNotFound::RETURN_NULL) { return; }
            throw CatalogException("Oracle table not found: %s", requested);
        }
        RunAttachedDdl(context, state, "DROP TABLE " + OracleObjectReference(state->owner, name), false, OracleObjectReference(state->owner, name));
        auto undo = context.registered_state->Get<OracleDdlUndo>("oracle_scanner.ddl_undo");
        if (undo) {
            auto &created = undo->created[catalog.GetName().GetIdentifierName()];
            created.erase(std::remove_if(created.begin(), created.end(), [&](const OracleDdlUndo::Created &item) { return item.name == name && item.state->EffectiveOwner() == state->EffectiveOwner(); }), created.end());
        }
        Sync(context);
    }
    void Alter(CatalogTransaction transaction, AlterInfo &info) override {
        auto &context = transaction.GetContext(); Sync(context);
        if (catalog.GetAttached().IsReadOnly()) { throw BinderException("Oracle DDL is not allowed on a read-only catalog"); }
        if (info.type != AlterType::ALTER_TABLE) { throw NotImplementedException("Oracle ALTER supports table changes only"); }
        const auto name = state->ResolveObjectName(info.GetQualifiedName().Name().GetIdentifierName());
        if (name.empty()) { throw CatalogException("Oracle table not found"); }
        auto &alter = info.Cast<AlterTableInfo>();
        auto reference = OracleObjectReference(state->owner, name);
        std::string sql = "ALTER TABLE " + reference;
        std::string renamed;
        const auto columns = state->TryDescribe(name);
        const auto column_name = [&](const Identifier &requested) {
            for (const auto &column : columns) { if (column.name == requested.GetIdentifierName()) { return column.name; } }
            std::string found;
            for (const auto &column : columns) {
                if (StringUtil::CIEquals(column.name, requested.GetIdentifierName())) {
                    if (!found.empty()) { throw BinderException("Oracle column name is ambiguous"); }
                    found = column.name;
                }
            }
            if (found.empty()) { throw BinderException("Oracle column not found: %s", requested); }
            return found;
        };
        switch (alter.alter_table_type) {
        case AlterTableType::ADD_COLUMN: {
            const auto &add = alter.Cast<AddColumnInfo>();
            if (add.add_column_constraints.add_unique) { throw NotImplementedException("Oracle ADD COLUMN UNIQUE is not supported"); }
            bool exists = false;
            for (const auto &column : columns) { exists |= StringUtil::CIEquals(column.name, add.new_column.Name().GetIdentifierName()); }
            if (exists && add.if_column_not_exists) { return; }
            sql += " ADD (" + DdlColumn(add.new_column);
            if (add.add_column_constraints.add_not_null) { sql += " NOT NULL"; }
            sql += ")"; break;
        }
        case AlterTableType::REMOVE_COLUMN: {
            const auto &remove = alter.Cast<RemoveColumnInfo>();
            if (remove.cascade) { throw NotImplementedException("Oracle DROP COLUMN CASCADE is not supported"); }
            bool exists = false;
            for (const auto &column : columns) { exists |= StringUtil::CIEquals(column.name, remove.removed_column.GetIdentifierName()); }
            if (!exists && remove.if_column_exists) { return; }
            sql += " DROP COLUMN " + DdlQuote(column_name(remove.removed_column)); break;
        }
        case AlterTableType::RENAME_COLUMN: {
            const auto &rename = alter.Cast<RenameColumnInfo>();
            sql += " RENAME COLUMN " + DdlQuote(column_name(rename.old_name)) + " TO " + DdlQuote(rename.new_name.GetIdentifierName()); break;
        }
        case AlterTableType::RENAME_TABLE:
            renamed = alter.Cast<RenameTableInfo>().new_table_name.GetIdentifierName();
            sql += " RENAME TO " + DdlQuote(renamed); break;
        default: throw NotImplementedException("Oracle ALTER supports ADD/DROP/RENAME COLUMN and RENAME TO only");
        }
        RunAttachedDdl(context, state, sql, false, reference);
        if (!renamed.empty()) {
            auto undo = context.registered_state->Get<OracleDdlUndo>("oracle_scanner.ddl_undo");
            if (undo) {
                for (auto &item : undo->created[catalog.GetName().GetIdentifierName()]) { if (item.name == name && item.state->EffectiveOwner() == state->EffectiveOwner()) { item.name = renamed; } }
            }
        }
        Sync(context);
    }
private:
    shared_ptr<OracleAttachedState> state;
    std::mutex cache_lock;
    idx_t cached_version = 0;
    bool has_materialized_entries = false;
    DefaultGenerator *defaults = nullptr;
};

class OracleAttachedCatalog final : public DuckCatalog {
public:
    OracleAttachedCatalog(AttachedDatabase &db, shared_ptr<OracleAttachedState> state_p)
        : DuckCatalog(db), state(std::move(state_p)) {
    }

    string GetCatalogType() override {
        return "oracle_scanner";
    }

    OracleWriteTarget WriteTarget() {
        OracleWriteTarget target;
        target.catalog_name = static_cast<const std::string &>(GetAttached().GetName());
        target.config = state->config;
        target.password = state->password;
        target.pool = state->transaction_pool;
        return target;
    }

    PhysicalOperator &PlanInsert(ClientContext &context, PhysicalPlanGenerator &planner, LogicalInsert &op,
                                 optional_ptr<PhysicalOperator> plan) override {
        auto &table = op.table.Cast<OracleAttachedTableEntry>();
        return PlanOracleInsert(context, planner, op, plan, table.OracleColumns(),
                                table.WriteTarget(static_cast<const std::string &>(GetAttached().GetName())));
    }

    PhysicalOperator &PlanMergeInto(ClientContext &, PhysicalPlanGenerator &, LogicalMergeInto &, PhysicalOperator &) override {
        throw NotImplementedException("Oracle MERGE/upsert requires the Oracle optimizer rewrite; use oracle_execute with Oracle MERGE SQL");
    }

    PhysicalOperator &PlanDelete(ClientContext &context, PhysicalPlanGenerator &planner, LogicalDelete &op,
                                 PhysicalOperator &plan) override {
        auto &table = op.table.Cast<OracleAttachedTableEntry>();
        return PlanOracleDelete(context, planner, op, plan, table.OracleColumns(), table.WriteTarget(static_cast<const std::string &>(GetAttached().GetName())));
    }

    PhysicalOperator &PlanUpdate(ClientContext &context, PhysicalPlanGenerator &planner, LogicalUpdate &op,
                                 PhysicalOperator &plan) override {
        auto &table = op.table.Cast<OracleAttachedTableEntry>();
        return PlanOracleUpdate(context, planner, op, plan, table.OracleColumns(),
                                table.WriteTarget(static_cast<const std::string &>(GetAttached().GetName())));
    }

    PhysicalOperator &PlanCreateTableAs(ClientContext &context, PhysicalPlanGenerator &planner,
                                        LogicalCreateTable &op, PhysicalOperator &source) override {
        auto &schema = op.schema;
        planner.dependencies.AddDependency(schema);
        const auto table_state = schema.Cast<OracleSchemaEntry>().State();
        (void)CreateDdl(op.info->Base(), table_state->owner);
        std::vector<OracleColumn> columns;
        for (const auto &column : op.info->Base().columns.Physical()) {
            auto declared = DdlType(column.Type()).second;
            declared.name = column.Name().GetIdentifierName();
            columns.push_back(std::move(declared));
        }
        auto base = shared_ptr<CreateInfo>(op.info->base->Copy().release());
        auto target = WriteTarget();
        target.schema_name = table_state->owner;
        target.object_name = op.info->Base().GetTableName().GetIdentifierName();
        auto create = [&schema, base](ClientContext &caller) {
            BoundCreateTableInfo bound(schema, base->Copy());
            return static_cast<bool>(schema.CreateTable(CatalogTransaction(schema.catalog, caller), bound));
        };
        return PlanOracleCreateAs(context, planner, source, op.types, std::move(target), std::move(columns), std::move(create));
    }

    ErrorData SupportsCreateTable(BoundCreateTableInfo &info) override {
        try { (void)CreateDdl(info.Base(), info.schema.Cast<OracleSchemaEntry>().State()->owner); }
        catch (const std::exception &error) { return ErrorData(error); }
        return ErrorData();
    }
    optional_idx GetCatalogVersion(ClientContext &) override { return state->epoch->version.load(); }


    optional_ptr<CatalogEntry> CreateSchema(CatalogTransaction transaction, CreateSchemaInfo &info) override {
        if (info.internal && info.SchemaName() == Identifier(DEFAULT_SCHEMA)) {
            // DuckCatalog initializes the legacy default-owner alias itself.
            // Other Oracle owners are registered by lookup/discovery below.
            auto entry = make_uniq<OracleSchemaEntry>(*this, info, state);
            auto result = entry.get();
            if (!GetSchemaCatalogSet().CreateEntry(transaction, info.SchemaName(), std::move(entry), LogicalDependencyList())) { return nullptr; }
            return result;
        }
        throw NotImplementedException("Oracle ATTACH cannot create Oracle users/schemas; use an existing Oracle schema");
    }

    void AlterSchema(CatalogTransaction, SchemaCatalogEntry &, AlterSchemaInfo &) override {
        throw NotImplementedException("Oracle ATTACH cannot alter Oracle users/schemas");
    }

    void DropSchema(ClientContext &, DropInfo &) override {
        throw NotImplementedException("Oracle ATTACH cannot drop a schema. %s", ORACLE_DDL_ROUTE);
    }

    bool SupportsNestedSchemas() const override { return false; }

    optional_ptr<SchemaCatalogEntry> LookupSchema(CatalogTransaction transaction, const EntryLookupInfo &lookup,
                                                  OnEntryNotFound if_not_found) override {
        return LookupSchemaPath(transaction, lookup, if_not_found, [&](const EntryLookupInfo &root) -> optional_ptr<CatalogEntry> {
            if (root.GetEntryIdentifier() == Identifier(DEFAULT_SCHEMA)) {
                return GetSchemaCatalogSet().GetEntry(transaction, root.GetEntryIdentifier());
            }
            return NamedSchema(root.GetEntryName()).get();
        });
    }

    void ScanSchemas(ClientContext &context, std::function<void(SchemaCatalogEntry &)> callback) override {
        DiscoverSchemas();
        DuckCatalog::ScanSchemas(context, std::move(callback));
    }

    optional_ptr<SchemaCatalogEntry> NamedSchema(const std::string &requested, bool known_owner = false) {
        std::lock_guard<std::mutex> guard(schema_lock);
        const auto cached = schema_aliases.find(requested);
        if (cached != schema_aliases.end()) { return cached->second; }
        if (missing_schemas.count(requested)) { return nullptr; }
        if (schema_aliases.size() + missing_schemas.size() >= 4096) { throw BinderException("Oracle ATTACH exceeds the 4096 named-schema limit"); }
        auto scoped = make_shared_ptr<OracleAttachedState>();
        scoped->config = state->config; scoped->password = state->password;
        scoped->secret_name = state->secret_name; scoped->transaction_pool = state->transaction_pool;
        scoped->current_schema = state->current_schema; scoped->nls_comp_binary = state->nls_comp_binary;
        scoped->epoch = state->epoch; scoped->named_schema = true; scoped->owner = requested;
        if (!known_owner && requested != state->current_schema && requested != state->owner && !scoped->ResolveOwner(true)) {
            missing_schemas.insert(requested);
            return nullptr;
        }
        const auto system = CatalogTransaction::GetSystemTransaction(GetDatabase());
        auto existing = GetSchemaCatalogSet().GetEntry(system, Identifier(scoped->owner));
        if (existing) {
            auto &schema = existing->Cast<OracleSchemaEntry>();
            if (schema.State()->EffectiveOwner() != scoped->owner) {
                throw BinderException("Oracle schemas with case-colliding names cannot coexist in one ATTACH; use separate attachments with SCHEMA");
            }
            schema_aliases.emplace(requested,&schema); return &schema;
        }
        CreateSchemaInfo info;
        info.SetQualifiedName(QualifiedName({Identifier(scoped->owner)},Identifier()));
        auto entry = make_uniq<OracleSchemaEntry>(*this,info,scoped);
        auto result = entry.get();
        if (!GetSchemaCatalogSet().CreateEntry(system,info.SchemaName(),std::move(entry),LogicalDependencyList())) {
            throw CatalogException("Oracle schema could not be registered");
        }
        schema_aliases.emplace(requested,result);
        return result;
    }

    void DiscoverSchemas() {
        std::vector<std::string> owners;
        {
            std::lock_guard<std::mutex> guard(discovery_lock);
            if (schemas_discovered) { return; }
            OracleMetadataLease session(state->transaction_pool,state->config,state->password);
            auto cursor = TranslatingOracleErrors("Oracle ATTACH could not list accessible schemas",[&] {
                return session->Query("SELECT DISTINCT o.owner FROM all_objects o JOIN all_users u ON u.username=o.owner "
                    "WHERE u.oracle_maintained='N' AND o.object_type IN ('TABLE','VIEW') ORDER BY o.owner",{});
            });
            // Validate the dictionary shape before interpreting names.
            if (cursor->Columns().size()==1 && StringUtil::CIEquals(cursor->Columns()[0].name,"OWNER")) {
                for (;;) {
                    const auto batch = cursor->Fetch(128);
                    for (const auto &row : batch.rows) {
                        if (row.size()!=1 || !row[0]) { throw IOException("Oracle schema listing returned an invalid owner"); }
                        if (owners.size() >= 4096) { break; }
                        owners.emplace_back(row[0]->begin(),row[0]->end());
                    }
                    if (batch.exhausted || owners.size() >= 4096) { break; }
                }
            }
            cursor->Close(); session.Finish();
            // Materialization is outside CatalogSet scanning and its locks.
            std::unordered_map<std::string,size_t> counts;
            for (const auto &owner : owners) { ++counts[StringUtil::Lower(owner)]; }
            for (const auto &owner : owners) {
                if (owner == state->EffectiveOwner() || StringUtil::CIEquals(owner,DEFAULT_SCHEMA) ||
                    counts[StringUtil::Lower(owner)] != 1) { continue; }
                NamedSchema(owner,true);
            }
            schemas_discovered = true;
        }
    }

    void Initialize(bool) override {
        state->ConnectAndDiscoverSchema();
        DuckCatalog::Initialize(false);
        if (state->discover_all_schemas) {
            DiscoverSchemas();
        } else {
            schemas_discovered = true;
        }
    }

private:
    shared_ptr<OracleAttachedState> state;
    std::mutex schema_lock;
    std::mutex discovery_lock;
    bool schemas_discovered = false;
    std::unordered_map<std::string,OracleSchemaEntry *> schema_aliases;
    std::unordered_set<std::string> missing_schemas;
};

constexpr int64_t ORACLE_TRANSACTION_POOL_DEFAULT_SIZE = 2;
constexpr int64_t ORACLE_TRANSACTION_POOL_MAXIMUM_SIZE = 64;

// The attached catalog's pool of transaction sessions. Sessions are opened from
// the secret resolved at ATTACH, like every session of this catalog, with the
// ATTACH context's deadline source replaced by a binding each transaction
// points at its own caller.
std::shared_ptr<oracle_scanner::OracleTransactionSessionPool>
MakeOracleTransactionPool(ClientContext &context, const ConnectionConfig &config, const std::string &password) {
    Value setting;
    int64_t size = ORACLE_TRANSACTION_POOL_DEFAULT_SIZE;
    if (context.TryGetCurrentSetting("oracle_transaction_pool_size", setting) && !setting.IsNull()) {
        size = setting.GetValue<int64_t>();
    }
    if (size < 0 || size > ORACLE_TRANSACTION_POOL_MAXIMUM_SIZE) {
        throw BinderException("oracle_transaction_pool_size must be between 0 and %lld",
                              static_cast<int64_t>(ORACLE_TRANSACTION_POOL_MAXIMUM_SIZE));
    }
    if (size == 0) {
        return nullptr;
    }
    auto pooled = config;
    pooled.io_deadline = nullptr;
    return std::make_shared<oracle_scanner::OracleTransactionSessionPool>(
        static_cast<size_t>(size),
        [pooled, password](std::shared_ptr<oracle_scanner::OracleIoDeadlineBinding> binding) {
            auto opened = pooled;
            opened.io_deadline_binding = std::move(binding);
            return std::shared_ptr<OracleSession>(OpenOracleSession(opened, password));
        });
}

unique_ptr<Catalog> OracleAttachedCatalogAttach(optional_ptr<StorageExtensionInfo>, ClientContext &context,
                                                 AttachedDatabase &db, const string &, AttachInfo &info,
                                                 AttachOptions &options) {
    if (info.path.empty()) {
        throw BinderException("Oracle ATTACH requires the Oracle secret name as its path");
    }
    for (const auto &option : info.options) {
        // Generic DuckDB flags are already applied to the attached-database
        // wrapper; DuckLake forwards them when attaching its metadata catalog.
        if (!StringUtil::CIEquals(option.first, "type") && !StringUtil::CIEquals(option.first, "read_only") &&
            !StringUtil::CIEquals(option.first, "readonly") && !StringUtil::CIEquals(option.first, "read_write") &&
            !StringUtil::CIEquals(option.first, "hidden") && !StringUtil::CIEquals(option.first, "schema")) {
            throw BinderException(
                "Oracle ATTACH does not accept option '%s' yet; use ATTACH 'secret_name' AS name (TYPE oracle_scanner[, SCHEMA 'owner'])",
                option.first);
        }
    }
    std::string password;
    auto state = make_shared_ptr<OracleAttachedState>();
    state->config = ConnectionFromSecret(context, info.path, password);
    state->password = std::move(password);
    state->secret_name = info.path;
    for (const auto &option : info.options) {
        if (StringUtil::CIEquals(option.first, "schema")) {
            if (option.second.IsNull() || option.second.type().id() != LogicalTypeId::VARCHAR ||
                option.second.GetValue<std::string>().empty()) {
                throw BinderException("Oracle ATTACH option SCHEMA takes a schema name as a string");
            }
            state->owner = option.second.GetValue<std::string>();
            state->discover_all_schemas = false;
        }
    }
    // The local storage DuckDB gives every attached database refuses options it
    // does not know, so the one this catalog took is not passed on.
    for (auto entry = options.options.begin(); entry != options.options.end();) {
        entry = StringUtil::CIEquals(entry->first, "schema") ? options.options.erase(entry) : std::next(entry);
    }
    state->transaction_pool = MakeOracleTransactionPool(context, state->config, state->password);
    // DuckDB's attached-database wrapper owns a local StorageManager even for
    // a custom catalog. Keep that storage in memory: the ATTACH path is a
    // secret name, never a local database file.
    info.path = ":memory:";
    // AttachedDatabase records READ_ONLY before invoking this callback.
    // Its dummy DuckCatalog storage must be initialized read-write because
    // DuckDB cannot initialize :memory: read-only. The attached database's
    // IsReadOnly flag stays set and still guards every user write.
    options.access_mode = AccessMode::READ_WRITE;
    // The attached database is read-write by default so INSERT can bind.
    // Explicit READ_ONLY is enforced by DuckDB and transactional DML below.
    // Remote DDL uses separate sessions; transactional DML uses pinned sessions.
    auto catalog = make_uniq<OracleAttachedCatalog>(db, std::move(state));
    catalog->Initialize(false);
    return catalog;
}

class OracleAttachedTransactionManager final : public DuckTransactionManager {
public:
    explicit OracleAttachedTransactionManager(AttachedDatabase &db_p)
        : DuckTransactionManager(db_p), catalog_name(db_p.GetName()) {
    }

    ErrorData CommitTransaction(ClientContext &context, Transaction &transaction) override {
        bool commit_started = false;
        try {
            // Generated dictionary entries use system transactions. The raw
            // SQL/DML path must have no local changes before remote COMMIT.
            if (transaction.Cast<DuckTransaction>().ChangesMade()) {
                throw TransactionException("Oracle transactions cannot commit local catalog or storage changes");
            }
            CommitOracleTransaction(context, catalog_name, commit_started);
            FinishOracleDdl(context, catalog_name, true);
        } catch (const std::exception &error) {
            RollbackOracleTransaction(context, catalog_name);
            DuckTransactionManager::RollbackTransaction(transaction);
            // Only an attempted remote COMMIT can have an unknown outcome.
            try {
                FinishOracleDdl(context, catalog_name, commit_started);
            } catch (const std::exception &cleanup_error) {
                return ErrorData(IOException("%s; %s", error.what(), cleanup_error.what()));
            }
            return ErrorData(error);
        }
        return DuckTransactionManager::CommitTransaction(context, transaction);
    }

    void RollbackTransaction(Transaction &transaction) override {
        auto context = transaction.context.lock();
        if (context) {
            RollbackOracleTransaction(*context, catalog_name);
        }
        DuckTransactionManager::RollbackTransaction(transaction);
        if (context) { FinishOracleDdl(*context, catalog_name, false); }
    }

private:
    std::string catalog_name;
};

unique_ptr<TransactionManager> OracleAttachedCatalogTransactionManager(optional_ptr<StorageExtensionInfo>,
                                                                         AttachedDatabase &db, Catalog &) {
    return make_uniq<OracleAttachedTransactionManager>(db);
}

} // namespace

OracleWriteTarget ResolveOracleWriteTarget(ClientContext &context, const std::string &catalog_name) {
    auto &catalog = Catalog::GetCatalog(context, Identifier(catalog_name));
    if (catalog.GetCatalogType() != "oracle_scanner") {
        throw BinderException("Oracle transaction functions require an attached oracle_scanner catalog");
    }
    return catalog.Cast<OracleAttachedCatalog>().WriteTarget();
}

std::string OracleObjectReference(const std::string &schema_name, const std::string &object_name) {
    const auto object = KeywordHelper::WriteQuotedAndEscaped(object_name, '"');
    return schema_name.empty() ? object : KeywordHelper::WriteQuotedAndEscaped(schema_name, '"') + "." + object;
}

std::string OracleSelectExpression(const OracleColumn &column) {
	const auto quoted = KeywordHelper::WriteQuotedAndEscaped(column.name, '"');
	return column.xml ? "XMLSERIALIZE(CONTENT " + quoted + " AS CLOB NO INDENT) " + quoted : quoted;
}

std::string OracleBindExpression(const OracleColumn &column, size_t bind_position) {
	const auto placeholder = ":" + std::to_string(bind_position);
	// XMLTYPE(:n) raises ORA-19032 for a NULL, and answering the NULL first needs
	// the placeholder twice, which a statement that is not PL/SQL counts as two
	// binds. XMLPARSE gives NULL for NULL and takes the placeholder once.
	return column.xml ? "XMLPARSE(DOCUMENT " + placeholder + ")" : placeholder;
}

namespace {

std::string ProjectedSelectList(const OracleQueryBindData &bind, const std::vector<column_t> &selected) {
    std::string select_list;
    for (const auto column_id : selected) {
        if (!select_list.empty()) {
            select_list += ", ";
        }
        if (column_id == COLUMN_IDENTIFIER_ROW_ID) {
            select_list += ORACLE_ROWID_EXPRESSION;
            continue;
        }
        select_list += OracleSelectExpression(bind.columns[column_id]);
    }
    return select_list;
}

std::string TextLiteral(const std::string &text) {
    std::string result = "'";
    for (const auto character : text) {
        result += character == '\'' ? std::string("''") : std::string(1, character);
    }
    return result + "'";
}

// All rows of a small dictionary query, as text.
std::vector<std::vector<std::string>> TextRows(OracleSession &session, const std::string &sql) {
    std::vector<std::vector<std::string>> rows;
    auto cursor = session.Query(sql, {});
    const auto &columns = cursor->Columns();
    for (;;) {
        const auto batch = cursor->Fetch(STANDARD_VECTOR_SIZE);
        for (const auto &row : batch.rows) {
            std::vector<std::string> text;
            for (size_t index = 0; index < row.size(); index++) {
                if (!row[index]) {
                    text.emplace_back();
                } else if (columns[index].oracle_type == 2) {
                    text.push_back(oracle_scanner::DecodeOracleNumber(*row[index]));
                } else {
                    text.emplace_back(row[index]->begin(), row[index]->end());
                }
            }
            rows.push_back(std::move(text));
        }
        if (batch.exhausted) {
            break;
        }
    }
    cursor->Close();
    return rows;
}

} // namespace

namespace {

// The change number a query reads every attached table at, per catalog, taken
// when its first scan starts. It belongs to the statement: the next one takes
// its own.
struct OracleQuerySnapshotState final : ClientContextState {
    std::mutex lock;
    idx_t query = 0;
    std::map<std::string, std::string> scn_by_catalog;
    //! A change number a snapshot build pinned for one catalog on this context, kept across statements.
    std::string pinned_catalog;
    std::string pinned_scn;
};

} // namespace

void OraclePinSnapshot(ClientContext &context, const std::string &catalog_name, const std::string &scn) {
    auto state = context.registered_state->GetOrCreate<OracleQuerySnapshotState>("oracle_scanner.query_snapshot");
    std::lock_guard<std::mutex> guard(state->lock);
    state->pinned_catalog = catalog_name;
    state->pinned_scn = scn;
}

std::string OracleCurrentScn(ClientContext &context, const std::string &catalog_name) {
    auto target = ResolveOracleWriteTarget(context, catalog_name);
    auto session = AcquireOracleReadSession(context, std::string(), target.catalog_name, target.config, target.password);
    const auto rows = TextRows(session.Get(), "SELECT dbms_flashback.get_system_change_number FROM dual");
    if (rows.size() != 1 || rows[0].size() != 1 || rows[0][0].empty()) {
        throw IOException("Oracle returned no change number");
    }
    return rows[0][0];
}

std::string OracleQuerySnapshot(ClientContext &context, const OracleQueryBindData &bind) {
    Value setting;
    if (!bind.catalog_name.empty()) {
        auto pinned = context.registered_state->GetOrCreate<OracleQuerySnapshotState>("oracle_scanner.query_snapshot");
        std::lock_guard<std::mutex> guard(pinned->lock);
        if (!pinned->pinned_scn.empty() && pinned->pinned_catalog == bind.catalog_name) {
            return pinned->pinned_scn;
        }
    }
    if (!context.TryGetCurrentSetting("oracle_consistent_read", setting) || setting.IsNull() ||
        !BooleanValue::Get(setting) || bind.catalog_name.empty() || TryTransactionSession(context, bind.catalog_name)) {
        return std::string();
    }
    auto state = context.registered_state->GetOrCreate<OracleQuerySnapshotState>("oracle_scanner.query_snapshot");
    const auto query = MetaTransaction::Get(context).GetActiveQuery();
    std::lock_guard<std::mutex> guard(state->lock);
    if (state->query != query) {
        state->query = query;
        state->scn_by_catalog.clear();
    }
    const auto known = state->scn_by_catalog.find(bind.catalog_name);
    if (known != state->scn_by_catalog.end()) {
        return known->second;
    }
    // The setting asks for one snapshot; a database that will not give out a
    // change number cannot honor it, and saying so beats reading several moments.
    try {
        auto session = AcquireOracleReadSession(context, bind.secret_name, bind.catalog_name, bind.config, bind.password);
        const auto rows = TextRows(session.Get(), "SELECT dbms_flashback.get_system_change_number FROM dual");
        if (rows.size() != 1 || rows[0].size() != 1 || rows[0][0].empty()) {
            throw IOException("Oracle returned no change number");
        }
        state->scn_by_catalog[bind.catalog_name] = rows[0][0];
        return rows[0][0];
    } catch (const std::exception &error) {
        throw IOException("oracle_consistent_read could not take a change number: %s", error.what());
    }
}

std::string OracleSnapshotOfHeapTable(ClientContext &context, const OracleQueryBindData &bind) {
    if (TryTransactionSession(context, bind.catalog_name)) {
        return std::string();
    }
    try {
        auto session = AcquireOracleReadSession(context, bind.secret_name, bind.catalog_name, bind.config, bind.password);
        auto scn = OracleQuerySnapshot(context, bind);
        if (scn.empty()) {
            const auto scn_rows = TextRows(session.Get(), "SELECT dbms_flashback.get_system_change_number FROM dual");
            if (scn_rows.size() != 1 || scn_rows[0].size() != 1 || scn_rows[0][0].empty()) {
                return std::string();
            }
            scn = scn_rows[0][0];
        }
        const bool own = bind.schema_name.empty();
        const auto kind = TextRows(session.Get(), std::string("SELECT iot_type, temporary, cluster_name FROM ") +
                                                 (own ? "user_tables" : "all_tables") +
                                                 " WHERE table_name = " + TextLiteral(bind.object_name) +
                                                 (own ? std::string() : " AND owner = " + TextLiteral(bind.schema_name)));
        if (kind.size() != 1 || !kind[0][0].empty() || kind[0][1] != "N" || !kind[0][2].empty()) {
            return std::string();
        }
        return scn;
    } catch (const std::exception &) {
        return std::string();
    }
}

std::vector<std::string> PlanParallelAttachedScan(ClientContext &context, const OracleQueryBindData &bind,
                                                  const std::vector<column_t> &selected, idx_t sessions) {
    // Only a plain read of a table as it is now: a sample would be taken once per
    // chunk, and a transaction that has written already holds the one session that
    // can see its rows. A scan that feeds an UPDATE or DELETE has pinned that session
    // already, to lock the rows it names, so it never reaches here in parallel.
    if (sessions < 2 || !bind.sample_clause.empty() || !bind.order_clause.empty() ||
        TryTransactionSession(context, bind.catalog_name)) {
        return {};
    }
    try {
        auto session = oracle_scanner::OpenOracleSession(bind.config, bind.password);
        // One snapshot for every chunk, taken before any of them reads. Without
        // a change number the chunks would be several moments, so no change
        // number means one stream.
        std::string scn = OracleQuerySnapshot(context, bind);
        if (scn.empty()) {
            const auto scn_rows = TextRows(*session, "SELECT dbms_flashback.get_system_change_number FROM dual");
            if (scn_rows.size() != 1 || scn_rows[0].size() != 1 || scn_rows[0][0].empty()) {
                return {};
            }
            scn = scn_rows[0][0];
        }
        const bool own = bind.schema_name.empty();
        const auto name = TextLiteral(bind.object_name);
        const auto owner = TextLiteral(bind.schema_name);
        // A heap table only: an index-organized, clustered or temporary table
        // has no ROWID ranges to cut.
        const auto kind = TextRows(*session, std::string("SELECT iot_type, temporary, cluster_name FROM ") +
                                                 (own ? "user_tables" : "all_tables") + " WHERE table_name = " + name +
                                                 (own ? std::string() : " AND owner = " + owner));
        if (kind.size() != 1 || !kind[0][0].empty() || kind[0][1] != "N" || !kind[0][2].empty()) {
            return {};
        }
        // The extents of the table, in ROWID order, each with the first ROWID it
        // can hold. ROWIDs sort by object, file, block, row, so a run of
        // consecutive extents is one ROWID range, and ranges cut between extents
        // neither overlap nor leave a gap. This reads DBA_EXTENTS, which not every
        // user may; without it the table is read with one session, because the
        // alternatives (a sample of its blocks, which comes back in a few clumps
        // and cut a 2,000,000-row table 99 to 1; USER_EXTENTS, which does not say
        // where an extent starts) do not divide it evenly. The object number comes from
        // ALL_OBJECTS, which shows every table the user can read, so DBA_EXTENTS is the
        // one dictionary view that needs a grant.
        const auto reference = OracleObjectReference(bind.schema_name, bind.object_name);
        const auto extents = TextRows(
            *session,
            std::string("SELECT ROWIDTOCHAR(DBMS_ROWID.ROWID_CREATE(1, o.data_object_id, e.relative_fno, e.block_id, 0)), "
                        "e.blocks FROM dba_extents e JOIN all_objects o ON o.owner = e.owner AND o.object_name = "
                        "e.segment_name AND (o.subobject_name = e.partition_name OR (o.subobject_name IS NULL AND "
                        "e.partition_name IS NULL)) WHERE e.owner = ") +
                (own ? std::string("USER") : owner) + " AND e.segment_name = " + name +
                " AND e.segment_type LIKE 'TABLE%' AND o.object_type LIKE 'TABLE%' ORDER BY o.data_object_id, "
                "e.relative_fno, e.block_id");
        uint64_t total_blocks = 0;
        for (const auto &extent : extents) {
            total_blocks += std::stoull(extent[1]);
        }
        // A table this small is quicker read by one session than cut up.
        constexpr uint64_t MINIMUM_BLOCKS = 2048;
        if (extents.empty() || total_blocks < MINIMUM_BLOCKS) {
            return {};
        }
        // About four chunks to a session, so a thread that finishes early takes
        // another instead of waiting for the slowest.
        const uint64_t chunks = MinValue<uint64_t>(MinValue<uint64_t>(sessions * 4, 64), total_blocks / 256);
        const uint64_t target = (total_blocks + chunks - 1) / chunks;
        std::vector<std::string> cuts;
        uint64_t accumulated = 0;
        for (size_t index = 0; index + 1 < extents.size(); index++) {
            accumulated += std::stoull(extents[index][1]);
            if (accumulated >= target) {
                cuts.push_back(extents[index + 1][0]);
                accumulated = 0;
            }
        }
        if (cuts.empty()) {
            return {};
        }
        const auto as_of = reference + " AS OF SCN " + scn;
        // The snapshot must be readable, which needs FLASHBACK on the table.
        (void)TextRows(*session, "SELECT 1 FROM " + as_of + " WHERE 1 = 0");
        session->Close();

        const auto select_list = ProjectedSelectList(bind, selected);
        const auto where = bind.where_clause.empty() ? std::string() : " AND (" + bind.where_clause + ")";
        // Half-open ranges between consecutive cut points, open at both ends, so
        // every ROWID belongs to exactly one chunk.
        std::vector<std::string> statements;
        for (size_t index = 0; index <= cuts.size(); index++) {
            std::string range;
            if (index > 0) {
                range = "ROWID >= CHARTOROWID(" + TextLiteral(cuts[index - 1]) + ")";
            }
            if (index < cuts.size()) {
                range += (range.empty() ? "" : " AND ") + std::string("ROWID < CHARTOROWID(") + TextLiteral(cuts[index]) + ")";
            }
            statements.push_back("SELECT " + select_list + " FROM " + as_of + " WHERE " + range + where);
        }
        return statements.size() >= 2 ? statements : std::vector<std::string>();
    } catch (const std::exception &) {
        // Anything the dictionary or the privileges will not give is a reason to
        // read the table the ordinary way, not to fail a query that would work.
        return {};
    }
}

// The describe supplies the wire representation and the character set form;
// the dictionary supplies declared NUMBER precision and scale and nullability,
// so scan values match the table schema. A dictionary type of zero means the
// mapping did not name it, and the describe's own type stands so the refusal
// can name it.
void OverlayDictionaryColumn(OracleColumn &described, const OracleColumn &dictionary) {
        if (dictionary.oracle_type != 0) {
            described.oracle_type = dictionary.oracle_type;
        }
        described.byte_width = dictionary.byte_width;
        described.precision = dictionary.precision;
        described.scale = dictionary.scale;
        described.nullable = dictionary.nullable;
        described.unconstrained_number = dictionary.unconstrained_number;
        described.unconstrained_precision = dictionary.unconstrained_precision;
        described.unconstrained_scale = dictionary.unconstrained_scale;
        if (dictionary.oracle_type == 127) {
            described.vector_dimensions = dictionary.vector_dimensions;
            described.vector_format = dictionary.vector_format;
            described.vector_flags = dictionary.vector_flags;
        }
}

void OpenProjectedScan(ClientContext &context, OracleQueryBindData &bind, const std::vector<column_t> &selected,
                       OracleSessionHandle &session, std::unique_ptr<OracleCursor> &cursor,
                       std::vector<OracleColumn> &columns, bool schema_only, OracleScanOpening *opening) {
    const auto select_list = ProjectedSelectList(bind, selected);
    auto sql = "SELECT " + select_list + " FROM " + OracleObjectReference(bind.schema_name, bind.object_name);
    if (!schema_only) {
        // Oracle takes the sample clause before AS OF and refuses it after
        // (ORA-00933, 19c): `t SAMPLE (10) AS OF SCN n`.
        sql += bind.sample_clause;
    }
    if (!bind.flashback_scn.empty()) {
        sql += " AS OF SCN " + bind.flashback_scn;
    }
    if (schema_only) {
        // Only the describe is wanted: the shape of the columns, with no row read.
        sql += " WHERE 1 = 0";
    } else {
        // The translated predicates, when filter pushdown is enabled and every
        // filter could be proven. An empty clause means nothing was pushed.
        if (!bind.where_clause.empty()) {
            sql += " WHERE " + bind.where_clause;
        }
        sql += bind.order_clause;
        // Oracle refuses FOR UPDATE beside FETCH FIRST (ORA-02014) and a sample.
        if (bind.for_update && bind.order_clause.empty() && bind.sample_clause.empty()) {
            sql += " FOR UPDATE";
        }
    }
    try {
        session = AcquireOracleReadSession(context, bind.secret_name, bind.catalog_name, bind.config, bind.password);
        const auto before = session->IoStats();
        cursor = session->Query(sql, {});
        if (opening) {
            opening->sql = sql;
            opening->io = session->IoStats() - before;
        }
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
        OverlayDictionaryColumn(columns[index], dictionary_column);
        (void)TypeFor(columns[index]);
    }
}

void ApplyUnconstrainedNumberSetting(ClientContext &context, std::vector<OracleColumn> &columns) {
	Value setting;
	if (!context.TryGetCurrentSetting("oracle_unconstrained_number", setting) || setting.IsNull()) {
		return;
	}
	std::string text;
	for (const auto character : setting.ToString()) {
		if (character != ' ') {
			text.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
		}
	}
	uint8_t mode = OracleColumn::UNCONSTRAINED_TEXT;
	uint8_t precision = 0;
	uint8_t scale = 0;
	if (text == "varchar" || text == "text" || text.empty()) {
		return;
	} else if (text == "double") {
		mode = OracleColumn::UNCONSTRAINED_DOUBLE;
	} else if (text.rfind("decimal(", 0) == 0 && text.back() == ')') {
		const auto comma = text.find(',');
		try {
			const auto p = std::stoi(text.substr(8, comma == std::string::npos ? std::string::npos : comma - 8));
			const auto s = comma == std::string::npos ? 0 : std::stoi(text.substr(comma + 1, text.size() - comma - 2));
			if (p < 1 || p > 38 || s < 0 || s > p) {
				throw std::out_of_range("range");
			}
			precision = static_cast<uint8_t>(p);
			scale = static_cast<uint8_t>(s);
			mode = OracleColumn::UNCONSTRAINED_DECIMAL;
		} catch (const std::exception &) {
			throw BinderException("oracle_unconstrained_number: DECIMAL needs 1 <= precision <= 38 and 0 <= scale <= precision");
		}
	} else {
		throw BinderException("oracle_unconstrained_number must be 'varchar', 'double' or 'decimal(precision, scale)', "
		                      "not '%s'",
		                      setting.ToString());
	}
	for (auto &column : columns) {
		if (column.oracle_type == 2 && column.precision == 0) {
			column.unconstrained_number = mode;
			column.unconstrained_precision = precision;
			column.unconstrained_scale = scale;
		}
	}
}

void RegisterOracleAttachedCatalog(ExtensionLoader &loader) {
    ScalarFunction default_marker(Identifier("__oracle_scanner_default"), vector<LogicalType>(), LogicalType::SQLNULL,
        [](DataChunk &, ExpressionState &, Vector &result) {
            result.SetVectorType(VectorType::CONSTANT_VECTOR);
            ConstantVector::SetNull(result, true);
        }, nullptr, nullptr, nullptr, LogicalType(LogicalTypeId::INVALID), FunctionStability::VOLATILE);
    loader.RegisterFunction(default_marker);
    RegisterOracleOptimizer(loader.GetDatabaseInstance());
    // On by default. Once a filter is handed to a scan DuckDB removes it from
    // the plan, so the scan must apply it exactly: the filters this translator
    // can prove go to Oracle, and the scan applies the rest itself to the rows
    // Oracle returns.
    DBConfig::GetConfig(loader.GetDatabaseInstance())
        .AddExtensionOption("oracle_filter_pushdown",
                            "Send WHERE predicates on an attached Oracle table to Oracle. Only filters whose Oracle "
                            "meaning is provably identical are translated; the rest are applied by the scan to the "
                            "rows Oracle returns.",
                            LogicalType::BOOLEAN, Value::BOOLEAN(true));
    DBConfig::GetConfig(loader.GetDatabaseInstance())
        .AddExtensionOption("oracle_consistent_read",
                            "Read every attached table of one statement at one Oracle change number (AS OF SCN), "
                            "taken when its first scan starts, so a join or a union of scans sees one moment. Needs "
                            "flashback on the tables; a transaction that has written reads its own session instead.",
                            LogicalType::BOOLEAN, Value::BOOLEAN(false));
    DBConfig::GetConfig(loader.GetDatabaseInstance())
        .AddExtensionOption("oracle_deferred_columns",
                            "Read CLOB, BLOB, JSON, VECTOR and XMLTYPE columns only for the rows that pass a filter "
                            "DuckDB applies itself, by ROWID at the same change number as the rows.",
                            LogicalType::BOOLEAN, Value::BOOLEAN(true));
    DBConfig::GetConfig(loader.GetDatabaseInstance())
        .AddExtensionOption("oracle_parallel_scan",
                            "How many Oracle sessions one scan of an attached table may read through at the same SCN, "
                            "each taking ROWID ranges cut at extent boundaries. -1 (the default) chooses: as many as "
                            "DuckDB has threads, up to 8, for a table whose statistics say 500,000 rows or more, else one. "
                            "0 or 1 reads with one session. A table "
                            "under 2,048 blocks, a sample, a transaction that has written, and a database that will not "
                            "give out an SCN are read with one.",
                            LogicalType::BIGINT, Value::BIGINT(-1));
    DBConfig::GetConfig(loader.GetDatabaseInstance())
        .AddExtensionOption("oracle_unconstrained_number",
                            "What a NUMBER with no declared precision (plain NUMBER, SUM(x), count(*)) becomes: "
                            "'varchar' (the default, exact), 'double', or 'decimal(precision, scale)'. Read when a "
                            "query is bound or a table is first used; the lossy choices round what does not fit.",
                            LogicalType::VARCHAR, Value("varchar"));
    DBConfig::GetConfig(loader.GetDatabaseInstance())
        .AddExtensionOption("oracle_transaction_pool_size",
                            "How many idle Oracle sessions an attached catalog keeps between its transactions, so a "
                            "transaction need not connect and authenticate again. Read at ATTACH; 0 disables reuse.",
                            LogicalType::BIGINT, Value::BIGINT(ORACLE_TRANSACTION_POOL_DEFAULT_SIZE));
    auto extension = make_shared_ptr<StorageExtension>();
    extension->attach = OracleAttachedCatalogAttach;
    extension->create_transaction_manager = OracleAttachedCatalogTransactionManager;
    StorageExtension::Register(DBConfig::GetConfig(loader.GetDatabaseInstance()), "oracle_scanner", std::move(extension));
}

} // namespace duckdb

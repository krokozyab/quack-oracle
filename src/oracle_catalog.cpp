// The Oracle catalog behind `ATTACH ... (TYPE oracle_scanner)`: schema and
// object discovery, lazy table entries, and the storage extension that
// registers it. It shares the scan's bind data and the type conversions with
// the table functions through oracle_adapter.hpp.

#include "oracle_adapter.hpp"

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

// ATTACH keeps no shared TTC channel. Metadata discovery and every scan open
// their own native session, matching oracle_query's proven ownership model.
// This makes the initial catalog explicitly read-only and avoids pretending
// that a DuckDB transaction spans an Oracle session.
struct OracleAttachedState {
    ConnectionConfig config;
    std::string password;
    // Idle transaction sessions kept between this catalog's transactions; see
    // OracleTransactionSessionPool. Null when oracle_transaction_pool_size is 0.
    std::shared_ptr<oracle_scanner::OracleTransactionSessionPool> transaction_pool;

    ~OracleAttachedState() {
        if (transaction_pool) {
            transaction_pool->Close();
        }
    }
    // The name the ATTACH resolved, so scans of this catalog share one pool.
    std::string secret_name;
    std::string current_schema;
    // ATTACH ... (SCHEMA 'X'): the schema whose objects this catalog lists, when
    // it is not the connected user's. Empty reads the user's own through the
    // USER_ views; set, it reads the ALL_ views for this owner.
    std::string owner;

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
        return std::string(owner.empty() ? "user_" : "all_") + name;
    }
    // A condition on the owner column, with the word that joins it to what
    // comes before. Empty for the connected user's own schema.
    std::string OwnerCondition(const char *column, const char *joiner) const {
        return owner.empty() ? std::string() : std::string(" ") + joiner + " " + column + " = " + Literal(owner);
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
    void ResolveOwner() {
        const auto lookup = [&](const std::string &condition) {
            std::vector<std::string> found;
            OracleMetadataLease session(transaction_pool, config, password);
            auto cursor = TranslatingOracleErrors("Oracle ATTACH could not look up the SCHEMA option", [&] {
                return session->Query("SELECT username FROM all_users WHERE " + condition, {});
            });
            for (;;) {
                const auto batch = TranslatingOracleErrors("Oracle ATTACH could not look up the SCHEMA option",
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
        if (found.size() != 1) {
            throw BinderException(found.empty() ? "Oracle ATTACH: there is no schema \"%s\" that this user can see"
                                                : "Oracle ATTACH: schema \"%s\" matches several users by case; write it exactly",
                                  owner);
        }
        owner = found[0];
        if (owner == current_schema) {
            owner.clear();
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
                                      (owner.empty() ? std::string() : " AND k.owner = c.owner") +
                                      " WHERE c.constraint_type = 'P'" + OwnerCondition("c.owner", "AND") + " AND "
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
            session.Finish();
        } catch (const std::exception &) {
            // A partial key list would name some columns of a composite key,
            // which is a different and false constraint.
            primary_key_cache.clear();
        }
    }

    bool IsTable(const std::string &object_name) const {
        std::lock_guard<std::mutex> lock(metadata_lock);
        if (!tables_loaded) {
            tables_loaded = true;
            try {
                OracleMetadataLease session(transaction_pool, config, password);
                auto cursor = TranslatingOracleErrors("Oracle ATTACH could not list tables", [&] {
                    return session->Query("SELECT table_name FROM " + View("tables") +
                                              (owner.empty() ? std::string() : " WHERE owner = " + Literal(owner)),
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
                auto distinct = TranslatingOracleErrors("Oracle ATTACH could not read column statistics", [&] {
                    return session->Query("SELECT table_name, column_name, num_distinct FROM " +
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

    // DuckDB looks a name up as the user typed it, and Oracle stores unquoted
    // names in upper case, so `o.items` has to find ITEMS. An exact match wins;
    // otherwise a match ignoring case is taken only when exactly one object has
    // it, because a schema can hold both "items" and ITEMS and then the name
    // does not say which was meant. Returns the name as Oracle stores it, or
    // empty when there is no such object.
    std::string ResolveObjectName(const std::string &requested) const {
        {
            std::lock_guard<std::mutex> lock(metadata_lock);
            if (!metadata_loaded) {
                LoadSchemaColumnsLocked();
            }
            if (column_cache.find(requested) != column_cache.end()) {
                return requested;
            }
            std::string found;
            size_t matches = 0;
            for (const auto &entry : column_cache) {
                if (StringUtil::CIEquals(entry.first, requested)) {
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
        // The bulk load was truncated and does not carry the name: ask for the
        // spelling Oracle would have stored an unquoted one in.
        auto upper = StringUtil::Upper(requested);
        if (upper != requested && !TryDescribe(upper).empty()) {
            return upper;
        }
        return requested;
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
            info->columns.AddColumn(ColumnDefinition(Identifier(output_name), MappedType(oracle_columns[index])));
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
        function.statistics = OracleAttachedScanStatistics;
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
    // Nothing DuckDB-local is written: the catalog refuses every DDL entry
    // point above, and the only statement that reaches Oracle is the INSERT.
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
        try {
            // Generated dictionary entries use system transactions. The raw
            // SQL/DML path must have no local changes before remote COMMIT.
            if (transaction.Cast<DuckTransaction>().ChangesMade()) {
                throw TransactionException("Oracle transactions cannot commit local catalog or storage changes");
            }
            CommitOracleTransaction(context, catalog_name);
        } catch (const std::exception &error) {
            RollbackOracleTransaction(context, catalog_name);
            DuckTransactionManager::RollbackTransaction(transaction);
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
    // can see its rows. (A scan that feeds an UPDATE or DELETE is fine: it reads
    // on a session of its own already, and the rows it names are committed ones.)
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
        // where an extent starts) do not divide it evenly.
        const auto reference = OracleObjectReference(bind.schema_name, bind.object_name);
        const auto extents = TextRows(
            *session,
            std::string("SELECT ROWIDTOCHAR(DBMS_ROWID.ROWID_CREATE(1, o.data_object_id, e.relative_fno, e.block_id, 0)), "
                        "e.blocks FROM dba_extents e JOIN dba_objects o ON o.owner = e.owner AND o.object_name = "
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

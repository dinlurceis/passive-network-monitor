#include "db_manager.hpp"
#include <spdlog/spdlog.h>
#include <chrono>
#include <stdexcept>

namespace netmon {

// Constructor
DbManager::DbManager(const std::string& connection_str) {
    connection_ = std::make_unique<pqxx::connection>(connection_str);
}

// ─── ping ────────────────────────────────────────────────────────────────────
bool DbManager::ping() {
    try {
        pqxx::work txn(*connection_);
        txn.exec("SELECT 1");
        txn.commit();
        return true;
    } catch (const std::exception& e) {
        spdlog::error("DB ping failed: {}", e.what());
        return false;
    }
}

// ─── initialize_schema ───────────────────────────────────────────────────────
void DbManager::initialize_schema() {
    pqxx::work txn(*connection_);

    txn.exec(R"sql(
        CREATE TABLE IF NOT EXISTS assets (
            id          SERIAL PRIMARY KEY,
            mac         VARCHAR(17) UNIQUE NOT NULL,
            ip          VARCHAR(15),
            hostname    TEXT,
            vendor      TEXT,
            os_guess    TEXT,
            first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            is_active   BOOLEAN NOT NULL DEFAULT TRUE,
            metadata    JSONB NOT NULL DEFAULT '{}'
        );
    )sql");

    txn.exec(R"sql(
        CREATE TABLE IF NOT EXISTS events (
            id          SERIAL PRIMARY KEY,
            asset_id    INT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            event_type  VARCHAR(32) NOT NULL,
            old_value   TEXT,
            new_value   TEXT,
            detail      JSONB NOT NULL DEFAULT '{}',
            ts          TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    )sql");

    // Indexes
    txn.exec("CREATE INDEX IF NOT EXISTS idx_assets_mac      ON assets(mac);");
    txn.exec("CREATE INDEX IF NOT EXISTS idx_assets_ip       ON assets(ip);");
    txn.exec("CREATE INDEX IF NOT EXISTS idx_events_asset_id ON events(asset_id);");
    txn.exec("CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);");
    txn.exec("CREATE INDEX IF NOT EXISTS idx_events_type     ON events(event_type);");

    // View
    txn.exec(R"sql(
        CREATE OR REPLACE VIEW asset_summary AS
        SELECT
            a.id, a.mac, a.ip, a.hostname, a.vendor, a.os_guess,
            a.first_seen, a.last_seen, a.is_active,
            COUNT(e.id) AS event_count
        FROM assets a
        LEFT JOIN events e ON e.asset_id = a.id
        GROUP BY a.id;
    )sql");

    txn.commit();
    spdlog::debug("DB schema initialized");
}

// ─── row_to_asset ─────────────────────────────────────────────────────────────
Asset DbManager::row_to_asset(const pqxx::row& row) {
    Asset a{};
    a.id        = row["id"].as<int>();
    a.mac       = row["mac"].as<std::string>();
    a.ip        = row["ip"].is_null()       ? "" : row["ip"].as<std::string>();
    a.hostname  = row["hostname"].is_null() ? "" : row["hostname"].as<std::string>();
    a.vendor    = row["vendor"].is_null()   ? "" : row["vendor"].as<std::string>();
    a.os_guess  = row["os_guess"].is_null() ? "" : row["os_guess"].as<std::string>();
    a.is_active = row["is_active"].as<bool>();
    a.first_seen = Clock::now();
    a.last_seen  = Clock::now();
    return a;
}

// ─── find_asset_by_mac ────────────────────────────────────────────────────────
std::optional<Asset> DbManager::find_asset_by_mac(const std::string& mac) {
    pqxx::work txn(*connection_);
    auto result = txn.exec_params(
        "SELECT id, mac, ip, hostname, vendor, os_guess, is_active, first_seen, last_seen "
        "FROM assets WHERE mac = $1",
        mac);
    txn.commit();
    if (result.empty()) return std::nullopt;
    return row_to_asset(result[0]);
}

// ─── find_asset_by_ip ────────────────────────────────────────────────────────
std::optional<Asset> DbManager::find_asset_by_ip(const std::string& ip) {
    pqxx::work txn(*connection_);
    auto result = txn.exec_params(
        "SELECT id, mac, ip, hostname, vendor, os_guess, is_active, first_seen, last_seen "
        "FROM assets WHERE ip = $1",
        ip);
    txn.commit();
    if (result.empty()) return std::nullopt;
    return row_to_asset(result[0]);
}

// ─── insert_asset ─────────────────────────────────────────────────────────────
// Uses UPSERT (ON CONFLICT) to avoid duplicate MAC inserts.
Asset DbManager::insert_asset(const Asset& a) {
    pqxx::work txn(*connection_);

    // Build escaped strings. Use pqxx quoting for safety.
    // Pass empty strings as NULL using NULLIF in SQL.
    auto result = txn.exec_params(
        "INSERT INTO assets (mac, ip, hostname, vendor, os_guess) "
        "VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, '')) "
        "ON CONFLICT (mac) DO UPDATE "
        "  SET last_seen = NOW(), "
        "      ip       = COALESCE(EXCLUDED.ip, assets.ip), "
        "      hostname = COALESCE(EXCLUDED.hostname, assets.hostname) "
        "RETURNING id, mac, ip, hostname, vendor, os_guess, is_active, first_seen, last_seen",
        a.mac, a.ip, a.hostname, a.vendor, a.os_guess);

    txn.commit();
    if (result.empty()) throw std::runtime_error("insert_asset: no row returned");
    return row_to_asset(result[0]);
}

// ─── update_asset ────────────────────────────────────────────────────────────
void DbManager::update_asset(const Asset& a) {
    pqxx::work txn(*connection_);
    txn.exec_params(
        "UPDATE assets SET ip=NULLIF($2,''), hostname=NULLIF($3,''), "
        "vendor=NULLIF($4,''), os_guess=NULLIF($5,''), "
        "is_active=$6, last_seen=NOW() WHERE id=$1",
        a.id, a.ip, a.hostname, a.vendor, a.os_guess, a.is_active);
    txn.commit();
}

// ─── update_asset_last_seen ──────────────────────────────────────────────────
void DbManager::update_asset_last_seen(int id) {
    pqxx::work txn(*connection_);
    txn.exec_params("UPDATE assets SET last_seen=NOW() WHERE id=$1", id);
    txn.commit();
}

// ─── update_asset_ip ─────────────────────────────────────────────────────────
void DbManager::update_asset_ip(int id, const std::string& ip) {
    pqxx::work txn(*connection_);
    txn.exec_params("UPDATE assets SET ip=NULLIF($2,''), last_seen=NOW() WHERE id=$1", id, ip);
    txn.commit();
}

// ─── update_asset_hostname ───────────────────────────────────────────────────
void DbManager::update_asset_hostname(int id, const std::string& hostname) {
    pqxx::work txn(*connection_);
    txn.exec_params("UPDATE assets SET hostname=NULLIF($2,'') WHERE id=$1", id, hostname);
    txn.commit();
}

// ─── set_asset_inactive ──────────────────────────────────────────────────────
void DbManager::set_asset_inactive(int id) {
    pqxx::work txn(*connection_);
    txn.exec_params("UPDATE assets SET is_active=FALSE WHERE id=$1", id);
    txn.commit();
}

// ─── insert_event ────────────────────────────────────────────────────────────
void DbManager::insert_event(int asset_id,
                              const std::string& event_type,
                              const std::string& old_val,
                              const std::string& new_val,
                              const std::string& detail_json) {
    pqxx::work txn(*connection_);
    txn.exec_params(
        "INSERT INTO events (asset_id, event_type, old_value, new_value, detail) "
        "VALUES ($1, $2, NULLIF($3,''), NULLIF($4,''), $5::jsonb)",
        asset_id, event_type, old_val, new_val, detail_json);
    txn.commit();
}

// ─── get_all_assets ──────────────────────────────────────────────────────────
std::vector<Asset> DbManager::get_all_assets(bool active_only) {
    pqxx::work txn(*connection_);
    pqxx::result rows;
    if (active_only) {
        rows = txn.exec(
            "SELECT id, mac, ip, hostname, vendor, os_guess, is_active, first_seen, last_seen "
            "FROM assets WHERE is_active=TRUE ORDER BY last_seen DESC");
    } else {
        rows = txn.exec(
            "SELECT id, mac, ip, hostname, vendor, os_guess, is_active, first_seen, last_seen "
            "FROM assets ORDER BY last_seen DESC");
    }
    txn.commit();

    std::vector<Asset> assets;
    assets.reserve(rows.size());
    for (const auto& row : rows) {
        assets.push_back(row_to_asset(row));
    }
    return assets;
}

// ─── get_assets_not_seen_since ───────────────────────────────────────────────
std::vector<Asset> DbManager::get_assets_not_seen_since(int seconds_ago) {
    pqxx::work txn(*connection_);
    // Use make_interval() to avoid SQL injection on the integer parameter
    auto rows = txn.exec_params(
        "SELECT id, mac, ip, hostname, vendor, os_guess, is_active, first_seen, last_seen "
        "FROM assets WHERE is_active=TRUE "
        "AND last_seen < NOW() - make_interval(secs => $1)",
        seconds_ago);
    txn.commit();

    std::vector<Asset> assets;
    for (const auto& row : rows) {
        assets.push_back(row_to_asset(row));
    }
    return assets;
}

} // namespace netmon

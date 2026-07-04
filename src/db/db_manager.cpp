#include "db_manager.hpp"
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <format>
#include <algorithm>

namespace pnads {

// ── Constructor ───────────────────────────────────────────────────────────────
DbManager::DbManager(const std::string& conn_str) {
    conn_ = std::make_unique<pqxx::connection>(conn_str);
}

// ── ping ──────────────────────────────────────────────────────────────────────
bool DbManager::ping() {
    try {
        pqxx::work txn(*conn_);
        txn.exec("SELECT 1");
        txn.commit();
        return true;
    } catch (const std::exception& e) {
        spdlog::error("DB ping failed: {}", e.what());
        return false;
    }
}

// ── initialize_schema ─────────────────────────────────────────────────────────
void DbManager::initialize_schema() {
    pqxx::work txn(*conn_);

    txn.exec(R"sql(
        CREATE TABLE IF NOT EXISTS assets (
            id             SERIAL PRIMARY KEY,
            mac            VARCHAR(17) UNIQUE NOT NULL,
            ip             VARCHAR(45),
            hostname       TEXT,
            vendor         TEXT,
            os_guess       TEXT,
            os_confidence  REAL NOT NULL DEFAULT 0,
            discovered_via TEXT[] NOT NULL DEFAULT '{}',
            first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            is_active      BOOLEAN NOT NULL DEFAULT TRUE,
            is_trusted     BOOLEAN NOT NULL DEFAULT FALSE,
            metadata       JSONB NOT NULL DEFAULT '{}'
        );
    )sql");

    txn.exec(R"sql(
        CREATE TABLE IF NOT EXISTS events (
            id         SERIAL PRIMARY KEY,
            asset_id   INT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            event_type VARCHAR(32) NOT NULL,
            protocol   VARCHAR(16) NOT NULL DEFAULT 'unknown',
            old_value  TEXT,
            new_value  TEXT,
            detail     JSONB NOT NULL DEFAULT '{}',
            ts         TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    )sql");

    txn.exec(R"sql(
        CREATE TABLE IF NOT EXISTS watchlist (
            id         SERIAL PRIMARY KEY,
            mac        VARCHAR(17),
            ip         VARCHAR(45),
            label      TEXT NOT NULL,
            note       TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CHECK (mac IS NOT NULL OR ip IS NOT NULL)
        );
    )sql");

    txn.exec(R"sql(
        CREATE TABLE IF NOT EXISTS alerts (
            id           SERIAL PRIMARY KEY,
            asset_id     INT REFERENCES assets(id) ON DELETE CASCADE,
            rule_type    VARCHAR(32) NOT NULL,
            severity     VARCHAR(16) NOT NULL DEFAULT 'medium',
            message      TEXT NOT NULL,
            detail       JSONB NOT NULL DEFAULT '{}',
            acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
            ts           TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    )sql");

    // Indexes
    txn.exec("CREATE INDEX IF NOT EXISTS idx_assets_mac      ON assets(mac);");
    txn.exec("CREATE INDEX IF NOT EXISTS idx_assets_ip       ON assets(ip);");
    txn.exec("CREATE INDEX IF NOT EXISTS idx_events_asset_id ON events(asset_id);");
    txn.exec("CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);");
    txn.exec("CREATE INDEX IF NOT EXISTS idx_events_type     ON events(event_type);");
    txn.exec("CREATE INDEX IF NOT EXISTS idx_watchlist_mac   ON watchlist(mac);");
    txn.exec("CREATE INDEX IF NOT EXISTS idx_watchlist_ip    ON watchlist(ip);");
    txn.exec("CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(ts);");
    txn.exec("CREATE INDEX IF NOT EXISTS idx_alerts_type     ON alerts(rule_type);");

    txn.exec(R"sql(
        CREATE OR REPLACE VIEW asset_summary AS
        SELECT a.*, COUNT(e.id) AS event_count
        FROM assets a
        LEFT JOIN events e ON e.asset_id = a.id
        GROUP BY a.id;
    )sql");

    txn.commit();
    spdlog::debug("DB schema initialized");
}

// ── row_to_asset ──────────────────────────────────────────────────────────────
Asset DbManager::row_to_asset(const pqxx::row& row) {
    Asset a{};
    a.id           = row["id"].as<int>();
    a.mac          = row["mac"].as<std::string>();
    a.ip           = row["ip"].is_null()           ? "" : row["ip"].as<std::string>();
    a.hostname     = row["hostname"].is_null()      ? "" : row["hostname"].as<std::string>();
    a.vendor       = row["vendor"].is_null()        ? "" : row["vendor"].as<std::string>();
    a.os_guess     = row["os_guess"].is_null()      ? "" : row["os_guess"].as<std::string>();
    a.os_confidence= row.column_number("os_confidence") >= 0
                     ? row["os_confidence"].as<float>() : 0.0f;
    a.is_active    = row["is_active"].as<bool>();
    a.is_trusted   = row.column_number("is_trusted") >= 0
                     ? row["is_trusted"].as<bool>() : false;
    a.first_seen   = Clock::now();
    a.last_seen    = Clock::now();
    return a;
}

// ── find_asset_by_mac ─────────────────────────────────────────────────────────
std::optional<Asset> DbManager::find_asset_by_mac(const std::string& mac) {
    pqxx::work txn(*conn_);
    auto result = txn.exec_params(
        "SELECT id, mac, ip, hostname, vendor, os_guess, os_confidence, "
        "is_active, is_trusted FROM assets WHERE mac = $1", mac);
    txn.commit();
    if (result.empty()) return std::nullopt;
    return row_to_asset(result[0]);
}

// ── find_asset_by_ip ──────────────────────────────────────────────────────────
std::optional<Asset> DbManager::find_asset_by_ip(const std::string& ip) {
    pqxx::work txn(*conn_);
    auto result = txn.exec_params(
        "SELECT id, mac, ip, hostname, vendor, os_guess, os_confidence, "
        "is_active, is_trusted FROM assets WHERE ip = $1", ip);
    txn.commit();
    if (result.empty()) return std::nullopt;
    return row_to_asset(result[0]);
}

// ── insert_asset ──────────────────────────────────────────────────────────────
Asset DbManager::insert_asset(const Asset& a) {
    pqxx::work txn(*conn_);
    auto result = txn.exec_params(
        "INSERT INTO assets (mac, ip, hostname, vendor, os_guess) "
        "VALUES ($1, NULLIF($2,''), NULLIF($3,''), NULLIF($4,''), NULLIF($5,'')) "
        "ON CONFLICT (mac) DO UPDATE "
        "  SET last_seen = NOW(), "
        "      ip       = COALESCE(EXCLUDED.ip, assets.ip), "
        "      hostname = COALESCE(EXCLUDED.hostname, assets.hostname) "
        "RETURNING id, mac, ip, hostname, vendor, os_guess, os_confidence, is_active, is_trusted",
        a.mac, a.ip, a.hostname, a.vendor, a.os_guess);
    txn.commit();
    if (result.empty()) throw std::runtime_error("insert_asset: no row returned");
    return row_to_asset(result[0]);
}

// ── update_asset ──────────────────────────────────────────────────────────────
void DbManager::update_asset(const Asset& a) {
    pqxx::work txn(*conn_);
    txn.exec_params(
        "UPDATE assets SET ip=NULLIF($2,''), hostname=NULLIF($3,''), "
        "vendor=NULLIF($4,''), os_guess=NULLIF($5,''), os_confidence=$6, "
        "is_active=$7, is_trusted=$8, last_seen=NOW() WHERE id=$1",
        a.id, a.ip, a.hostname, a.vendor, a.os_guess, a.os_confidence,
        a.is_active, a.is_trusted);
    txn.commit();
}

// ── update_asset_last_seen ────────────────────────────────────────────────────
void DbManager::update_asset_last_seen(int id) {
    pqxx::work txn(*conn_);
    txn.exec_params("UPDATE assets SET last_seen=NOW() WHERE id=$1", id);
    txn.commit();
}

// ── update_asset_ip ───────────────────────────────────────────────────────────
void DbManager::update_asset_ip(int id, const std::string& ip) {
    pqxx::work txn(*conn_);
    txn.exec_params("UPDATE assets SET ip=NULLIF($2,''), last_seen=NOW() WHERE id=$1", id, ip);
    txn.commit();
}

// ── update_asset_hostname ─────────────────────────────────────────────────────
void DbManager::update_asset_hostname(int id, const std::string& hostname) {
    pqxx::work txn(*conn_);
    txn.exec_params("UPDATE assets SET hostname=NULLIF($2,'') WHERE id=$1", id, hostname);
    txn.commit();
}

// ── update_asset_vendor ───────────────────────────────────────────────────────
void DbManager::update_asset_vendor(int id, const std::string& vendor) {
    pqxx::work txn(*conn_);
    txn.exec_params("UPDATE assets SET vendor=NULLIF($2,'') WHERE id=$1", id, vendor);
    txn.commit();
}

// ── update_asset_os ───────────────────────────────────────────────────────────
void DbManager::update_asset_os(int id, const std::string& os_guess, float confidence) {
    pqxx::work txn(*conn_);
    txn.exec_params(
        "UPDATE assets SET os_guess=NULLIF($2,''), os_confidence=$3 WHERE id=$1",
        id, os_guess, confidence);
    txn.commit();
}

// ── update_asset_discovered_via ───────────────────────────────────────────────
void DbManager::update_asset_discovered_via(int id, const std::vector<std::string>& via) {
    if (via.empty()) return;
    // Build PostgreSQL array literal: ARRAY['arp','dhcp']
    std::string arr = "ARRAY[";
    for (size_t i = 0; i < via.size(); ++i) {
        if (i > 0) arr += ',';
        arr += '\'' + via[i] + '\'';
    }
    arr += ']';
    pqxx::work txn(*conn_);
    txn.exec_params(
        "UPDATE assets SET discovered_via = (SELECT array_agg(DISTINCT x) "
        "FROM unnest(discovered_via || " + arr + "::text[]) x) WHERE id=$1",
        id);
    txn.commit();
}

// ── update_asset_trusted ──────────────────────────────────────────────────────
void DbManager::update_asset_trusted(int id, bool trusted) {
    pqxx::work txn(*conn_);
    txn.exec_params("UPDATE assets SET is_trusted=$2 WHERE id=$1", id, trusted);
    txn.commit();
}

// ── set_asset_inactive ────────────────────────────────────────────────────────
void DbManager::set_asset_inactive(int id) {
    pqxx::work txn(*conn_);
    txn.exec_params("UPDATE assets SET is_active=FALSE WHERE id=$1", id);
    txn.commit();
}

// ── insert_event ──────────────────────────────────────────────────────────────
void DbManager::insert_event(int asset_id,
                              const std::string& event_type,
                              const std::string& protocol,
                              const std::string& old_val,
                              const std::string& new_val,
                              const std::string& detail_json) {
    pqxx::work txn(*conn_);
    txn.exec_params(
        "INSERT INTO events (asset_id, event_type, protocol, old_value, new_value, detail) "
        "VALUES ($1, $2, $3, NULLIF($4,''), NULLIF($5,''), $6::jsonb)",
        asset_id, event_type, protocol, old_val, new_val, detail_json);
    txn.commit();
}

// ── get_events_by_asset ───────────────────────────────────────────────────────
std::vector<pqxx::row> DbManager::get_events_by_asset(const std::string& mac, int limit) {
    pqxx::work txn(*conn_);
    auto result = txn.exec_params(
        "SELECT e.id, e.event_type, e.protocol, e.old_value, e.new_value, "
        "e.detail, e.ts FROM events e "
        "JOIN assets a ON a.id = e.asset_id "
        "WHERE a.mac = $1 ORDER BY e.ts DESC LIMIT $2",
        mac, limit);
    txn.commit();
    return std::vector<pqxx::row>(result.begin(), result.end());
}

// ── insert_alert ──────────────────────────────────────────────────────────────
void DbManager::insert_alert(int asset_id,
                              const std::string& rule_type,
                              const std::string& severity,
                              const std::string& message,
                              const std::string& detail_json) {
    pqxx::work txn(*conn_);
    txn.exec_params(
        "INSERT INTO alerts (asset_id, rule_type, severity, message, detail) "
        "VALUES ($1, $2, $3, $4, $5::jsonb)",
        asset_id, rule_type, severity, message, detail_json);
    txn.commit();
}

// ── get_alerts ────────────────────────────────────────────────────────────────
std::vector<AlertRecord> DbManager::get_alerts(bool unacked_only,
                                                const std::string& severity_filter) {
    pqxx::work txn(*conn_);
    std::string query =
        "SELECT id, asset_id, rule_type, severity, message, detail, acknowledged "
        "FROM alerts WHERE 1=1";
    if (unacked_only) query += " AND acknowledged=FALSE";
    if (!severity_filter.empty()) query += " AND severity='" + severity_filter + "'";
    query += " ORDER BY ts DESC LIMIT 200";

    auto result = txn.exec(query);
    txn.commit();

    std::vector<AlertRecord> alerts;
    for (const auto& row : result) {
        AlertRecord ar{};
        ar.id           = row["id"].as<int>();
        ar.asset_id     = row["asset_id"].is_null() ? 0 : row["asset_id"].as<int>();
        ar.rule_type    = row["rule_type"].as<std::string>();
        ar.severity     = row["severity"].as<std::string>();
        ar.message      = row["message"].as<std::string>();
        ar.detail_json  = row["detail"].as<std::string>();
        ar.acknowledged = row["acknowledged"].as<bool>();
        alerts.push_back(ar);
    }
    return alerts;
}

// ── ack_alert ─────────────────────────────────────────────────────────────────
void DbManager::ack_alert(int id) {
    pqxx::work txn(*conn_);
    txn.exec_params("UPDATE alerts SET acknowledged=TRUE WHERE id=$1", id);
    txn.commit();
}

// ── get_watchlist ─────────────────────────────────────────────────────────────
std::vector<WatchlistEntry> DbManager::get_watchlist() {
    pqxx::work txn(*conn_);
    auto result = txn.exec(
        "SELECT id, mac, ip, label, note FROM watchlist ORDER BY created_at DESC");
    txn.commit();

    std::vector<WatchlistEntry> list;
    for (const auto& row : result) {
        WatchlistEntry e{};
        e.id    = row["id"].as<int>();
        e.mac   = row["mac"].is_null() ? "" : row["mac"].as<std::string>();
        e.ip    = row["ip"].is_null()  ? "" : row["ip"].as<std::string>();
        e.label = row["label"].as<std::string>();
        e.note  = row["note"].is_null() ? "" : row["note"].as<std::string>();
        list.push_back(e);
    }
    return list;
}

// ── insert_watchlist ──────────────────────────────────────────────────────────
WatchlistEntry DbManager::insert_watchlist(const std::string& mac,
                                            const std::string& ip,
                                            const std::string& label,
                                            const std::string& note) {
    pqxx::work txn(*conn_);
    auto result = txn.exec_params(
        "INSERT INTO watchlist (mac, ip, label, note) "
        "VALUES (NULLIF($1,''), NULLIF($2,''), $3, NULLIF($4,'')) "
        "RETURNING id, mac, ip, label, note",
        mac, ip, label, note);
    txn.commit();
    if (result.empty()) throw std::runtime_error("insert_watchlist: no row returned");

    const auto& row = result[0];
    return {row["id"].as<int>(),
            row["mac"].is_null() ? "" : row["mac"].as<std::string>(),
            row["ip"].is_null()  ? "" : row["ip"].as<std::string>(),
            row["label"].as<std::string>(),
            row["note"].is_null() ? "" : row["note"].as<std::string>()};
}

// ── delete_watchlist ──────────────────────────────────────────────────────────
void DbManager::delete_watchlist(int id) {
    pqxx::work txn(*conn_);
    txn.exec_params("DELETE FROM watchlist WHERE id=$1", id);
    txn.commit();
}

// ── get_all_assets ────────────────────────────────────────────────────────────
std::vector<Asset> DbManager::get_all_assets(bool active_only) {
    pqxx::work txn(*conn_);
    std::string query =
        "SELECT id, mac, ip, hostname, vendor, os_guess, os_confidence, is_active, is_trusted "
        "FROM assets";
    if (active_only) query += " WHERE is_active=TRUE";
    query += " ORDER BY last_seen DESC";

    auto rows = txn.exec(query);
    txn.commit();

    std::vector<Asset> assets;
    assets.reserve(rows.size());
    for (const auto& row : rows) assets.push_back(row_to_asset(row));
    return assets;
}

// ── get_assets_not_seen_since ─────────────────────────────────────────────────
std::vector<Asset> DbManager::get_assets_not_seen_since(int seconds_ago) {
    pqxx::work txn(*conn_);
    auto rows = txn.exec_params(
        "SELECT id, mac, ip, hostname, vendor, os_guess, os_confidence, is_active, is_trusted "
        "FROM assets WHERE is_active=TRUE "
        "AND last_seen < NOW() - make_interval(secs => $1)",
        seconds_ago);
    txn.commit();

    std::vector<Asset> assets;
    for (const auto& row : rows) assets.push_back(row_to_asset(row));
    return assets;
}

// ── get_total_events ──────────────────────────────────────────────────────────
int DbManager::get_total_events() {
    pqxx::work txn(*conn_);
    auto result = txn.exec("SELECT COUNT(*) FROM events");
    txn.commit();
    return result.empty() ? 0 : result[0][0].as<int>();
}

// ── get_unacked_alerts_count ──────────────────────────────────────────────────
int DbManager::get_unacked_alerts_count() {
    pqxx::work txn(*conn_);
    auto result = txn.exec("SELECT COUNT(*) FROM alerts WHERE acknowledged=FALSE");
    txn.commit();
    return result.empty() ? 0 : result[0][0].as<int>();
}

// ── get_timeseries ────────────────────────────────────────────────────────────
std::vector<TimeseriesBucket> DbManager::get_timeseries(const std::string& interval,
                                                          int range_hours,
                                                          const std::string& group_by,
                                                          const std::string& asset_mac) {
    // interval: "hour" | "day"
    // group_by: "event_type" | "protocol"
    pqxx::work txn(*conn_);

    std::string trunc_expr = (interval == "hour") ? "hour" : "day";
    std::string group_col  = (group_by == "protocol") ? "protocol" : "event_type";

    std::string query =
        "SELECT date_trunc($1, e.ts) AS bucket, e." + group_col + " AS key, "
        "COUNT(*) AS cnt FROM events e ";

    if (!asset_mac.empty()) {
        query += "JOIN assets a ON a.id = e.asset_id ";
    }

    query += "WHERE e.ts > NOW() - make_interval(hours => $2) ";

    if (!asset_mac.empty()) {
        query += "AND a.mac = $3 ";
        query += "GROUP BY bucket, key ORDER BY bucket ASC";
    } else {
        query += "GROUP BY bucket, key ORDER BY bucket ASC";
    }

    pqxx::result result;
    if (!asset_mac.empty()) {
        result = txn.exec_params(query, trunc_expr, range_hours, asset_mac);
    } else {
        result = txn.exec_params(query, trunc_expr, range_hours);
    }
    txn.commit();

    std::vector<TimeseriesBucket> buckets;
    for (const auto& row : result) {
        TimeseriesBucket b{};
        b.bucket = row["bucket"].as<std::string>();
        b.key    = row["key"].is_null() ? "unknown" : row["key"].as<std::string>();
        b.count  = row["cnt"].as<int>();
        buckets.push_back(b);
    }
    return buckets;
}

} // namespace pnads

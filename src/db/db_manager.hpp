#pragma once
#include "tracker/asset.hpp"
#include <pqxx/pqxx>
#include <string>
#include <vector>
#include <optional>
#include <memory>

namespace pnads {

struct WatchlistEntry {
    int         id;
    std::string mac;
    std::string ip;
    std::string label;
    std::string note;
};

struct AlertRecord {
    int         id;
    int         asset_id;
    std::string rule_type;
    std::string severity;
    std::string message;
    std::string detail_json;
    bool        acknowledged;
};

// Simple timeseries bucket
struct TimeseriesBucket {
    std::string bucket;  // "2026-06-27" or "2026-06-27T14:00"
    std::string key;     // event_type or protocol
    int         count;
};

class DbManager {
public:
    explicit DbManager(const std::string& conn_str);
    ~DbManager() = default;

    // Khởi tạo schema (CREATE TABLE IF NOT EXISTS inline)
    void initialize_schema();

    // ── Asset CRUD ────────────────────────────────────────────────────────────
    std::optional<Asset> find_asset_by_mac(const std::string& mac);
    std::optional<Asset> find_asset_by_ip(const std::string& ip);
    Asset                insert_asset(const Asset& a);
    void                 update_asset(const Asset& a);
    void                 update_asset_last_seen(int id);
    void                 update_asset_ip(int id, const std::string& ip);
    void                 update_asset_hostname(int id, const std::string& hostname);
    void                 update_asset_vendor(int id, const std::string& vendor);
    void                 update_asset_os(int id, const std::string& os_guess, float confidence);
    void                 update_asset_discovered_via(int id, const std::vector<std::string>& via);
    void                 update_asset_trusted(int id, bool trusted);
    void                 set_asset_inactive(int id);

    // ── Events ────────────────────────────────────────────────────────────────
    void insert_event(int asset_id,
                      const std::string& event_type,
                      const std::string& protocol    = "unknown",
                      const std::string& old_val     = "",
                      const std::string& new_val     = "",
                      const std::string& detail_json = "{}");

    std::vector<pqxx::row> get_events_by_asset(const std::string& mac, int limit = 100);

    // ── Alerts ────────────────────────────────────────────────────────────────
    void                    insert_alert(int asset_id,
                                         const std::string& rule_type,
                                         const std::string& severity,
                                         const std::string& message,
                                         const std::string& detail_json = "{}");
    std::vector<AlertRecord> get_alerts(bool unacked_only = false,
                                         const std::string& severity_filter = "");
    void                    ack_alert(int id);

    // ── Watchlist ─────────────────────────────────────────────────────────────
    std::vector<WatchlistEntry> get_watchlist();
    WatchlistEntry              insert_watchlist(const std::string& mac,
                                                  const std::string& ip,
                                                  const std::string& label,
                                                  const std::string& note = "");
    void                        delete_watchlist(int id);

    // ── Queries ───────────────────────────────────────────────────────────────
    std::vector<Asset> get_all_assets(bool active_only = false);
    std::vector<Asset> get_assets_not_seen_since(int seconds_ago);

    // ── Stats ─────────────────────────────────────────────────────────────────
    int get_total_events();
    int get_unacked_alerts_count();
    std::vector<TimeseriesBucket> get_timeseries(const std::string& interval,
                                                   int range_hours,
                                                   const std::string& group_by,
                                                   const std::string& asset_mac = "");

    // ── Utility ───────────────────────────────────────────────────────────────
    bool ping();

private:
    std::unique_ptr<pqxx::connection> conn_;

    Asset row_to_asset(const pqxx::row& row);
};

} // namespace pnads

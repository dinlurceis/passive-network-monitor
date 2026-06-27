#pragma once
#include "../tracker/asset.hpp"
#include <pqxx/pqxx>
#include <string>
#include <vector>
#include <optional>
#include <memory>

namespace netmon {

class DbManager {
public:
    explicit DbManager(const std::string& conn_str);
    ~DbManager() = default;

    // Khởi tạo schema (CREATE TABLE IF NOT EXISTS inline)
    void initialize_schema();

    // Asset CRUD
    std::optional<Asset> find_asset_by_mac(const std::string& mac);
    std::optional<Asset> find_asset_by_ip(const std::string& ip);
    Asset                insert_asset(const Asset& a);
    void                 update_asset(const Asset& a);      // full update
    void                 update_asset_last_seen(int id);
    void                 update_asset_ip(int id, const std::string& ip);
    void                 update_asset_hostname(int id, const std::string& hostname);
    void                 set_asset_inactive(int id);

    // Event
    void insert_event(int asset_id,
                      const std::string& event_type,
                      const std::string& old_val = "",
                      const std::string& new_val = "",
                      const std::string& detail_json = "{}");

    // Queries
    std::vector<Asset> get_all_assets(bool active_only = false);
    std::vector<Asset> get_assets_not_seen_since(int seconds_ago);

    // Ping DB để check connectivity
    bool ping();

private:
    std::unique_ptr<pqxx::connection> conn_;

    // Helper: convert pqxx row → Asset struct
    Asset row_to_asset(const pqxx::row& row);
};

} // namespace netmon

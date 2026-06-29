#pragma once
#include "asset.hpp"
#include "../parsers/arp_parser.hpp"
#include "../parsers/dhcp_parser.hpp"
#include "../db/db_manager.hpp"
#include "../enrichment/oui_lookup.hpp"
#include "../enrichment/os_fingerprint.hpp"
#include <unordered_map>
#include <mutex>
#include <vector>
#include <optional>

namespace netmon {

class AssetTracker {
public:
    // Constructor nhận OuiLookup để tra cứu vendor tên nhà sản xuất từ MAC
    AssetTracker(DbManager& db, OuiLookup& oui);

    // Gọi từ packet callback
    void process_arp(const ArpFrame& frame);
    void process_dhcp(const DhcpInfo& info);

    // Đánh dấu asset không còn active nếu quá timeout
    void expire_assets(int timeout_sec);

    // Query in-memory cache
    std::optional<Asset> find_by_mac(const std::string& mac) const;
    std::vector<Asset>   all_assets() const;
    size_t               active_count() const;

private:
    DbManager& db_;
    OuiLookup& oui_;   // tham chiếu đến OUI database dùng chung (không sở hữu)
    std::unordered_map<std::string, Asset> cache_;  // MAC → Asset
    mutable std::mutex mutex_;

    // Upsert asset vào DB và cache. Trả về asset đã lưu.
    // Caller phải giữ mutex_ trước khi gọi.
    Asset upsert_asset(const std::string& mac, const std::string& ip = "");

    void log_event(const Asset& asset, const std::string& event_type,
                   const std::string& old_val = "",
                   const std::string& new_val = "");
};

} // namespace netmon

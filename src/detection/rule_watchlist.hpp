#pragma once
#include "detection/detection_engine.hpp"
#include "db/db_manager.hpp"
#include <chrono>

namespace pnads {

// Khớp MAC/IP asset với bảng watchlist trong DB.
// Cache watchlist 30 giây — tự động reload khi hết TTL.
// Chỉ chạy trên các event có nghĩa (new_asset, ip_change, arp_announce, dhcp_ack).
class RuleWatchlist : public IDetectionRule {
public:
    explicit RuleWatchlist(DbManager& db) : db_(db) {}

    std::vector<Alert> evaluate(const Asset& asset,
                                 const std::string& event_type,
                                 const std::string& protocol,
                                 const std::string& detail_json) override;

private:
    DbManager& db_;

    // Cache watchlist — reload mỗi cache_ttl_sec giây
    static constexpr int cache_ttl_sec = 30;
    std::vector<WatchlistEntry>          cache_;
    std::chrono::steady_clock::time_point cache_ts_{};

    void maybe_reload();
};

} // namespace pnads

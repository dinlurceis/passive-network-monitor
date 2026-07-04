#include "detection/rule_watchlist.hpp"
#include <format>

namespace pnads {

std::vector<Alert> RuleWatchlist::evaluate(const Asset& asset,
                                            const std::string& /*event_type*/,
                                            const std::string& /*protocol*/,
                                            const std::string& /*detail_json*/) {
    auto watchlist = db_.get_watchlist();
    std::vector<Alert> alerts;

    for (const auto& entry : watchlist) {
        bool mac_match = !entry.mac.empty() && entry.mac == asset.mac;
        bool ip_match  = !entry.ip.empty()  && entry.ip  == asset.ip;

        if (mac_match || ip_match) {
            std::string msg = std::format(
                "Watchlist match '{}': device MAC={} IP={} seen on network",
                entry.label, asset.mac, asset.ip);

            std::string detail = std::format(
                "{{\"watchlist_id\":{},\"label\":\"{}\",\"mac\":\"{}\",\"ip\":\"{}\"}}",
                entry.id, entry.label, asset.mac, asset.ip);

            alerts.push_back({asset.id, "watchlist_match", Severity::High, msg, detail});
        }
    }

    return alerts;
}

} // namespace pnads

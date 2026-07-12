#include "detection/rule_watchlist.hpp"
#include <format>

namespace pnads {

// Event types mà watchlist nên check — bỏ qua các event "noisy" tần suất cao
// (tls_sni, dns_query, http_useragent fire liên tục với mỗi packet)
static bool is_meaningful_event(const std::string& event_type) {
    return event_type == "new_asset"    ||
           event_type == "ip_change"    ||
           event_type == "arp_announce" ||
           event_type == "dhcp_ack"     ||
           event_type == "dhcp_request" ||
           event_type == "dhcpv6_reply" ||
           event_type == "mdns_announce"||
           event_type == "ssdp_notify";
}

void RuleWatchlist::maybe_reload() {
    auto now = std::chrono::steady_clock::now();
    auto age = std::chrono::duration_cast<std::chrono::seconds>(now - cache_ts_).count();
    if (cache_.empty() || age >= cache_ttl_sec) {
        cache_    = db_.get_watchlist();
        cache_ts_ = now;
    }
}

std::vector<Alert> RuleWatchlist::evaluate(const Asset& asset,
                                            const std::string& event_type,
                                            const std::string& /*protocol*/,
                                            const std::string& /*detail_json*/) {
    // Bỏ qua các event tần suất cao để tránh spam
    if (!is_meaningful_event(event_type)) return {};

    maybe_reload();
    if (cache_.empty()) return {};

    std::vector<Alert> alerts;
    for (const auto& entry : cache_) {
        bool mac_match = !entry.mac.empty() && entry.mac == asset.mac;
        bool ip_match  = !entry.ip.empty()  && entry.ip  == asset.ip;

        if (mac_match || ip_match) {
            std::string match_type = mac_match ? "mac" : "ip";
            std::string msg = std::format(
                "Watchlist hit '{}' ({}): device MAC={} IP={} via {}",
                entry.label, match_type, asset.mac, asset.ip, event_type);

            std::string detail = std::format(
                "{{\"watchlist_id\":{},\"label\":\"{}\",\"match_by\":\"{}\","
                "\"mac\":\"{}\",\"ip\":\"{}\",\"event\":\"{}\"}}",
                entry.id, entry.label, match_type,
                asset.mac, asset.ip, event_type);

            alerts.push_back({asset.id, "watchlist_match", Severity::High, msg, detail});
        }
    }

    return alerts;
}

} // namespace pnads

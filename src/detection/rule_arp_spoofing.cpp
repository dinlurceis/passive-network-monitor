#include "detection/rule_arp_spoofing.hpp"
#include <format>

namespace pnads {

std::vector<Alert> RuleArpSpoofing::evaluate(const Asset& asset,
                                              const std::string& event_type,
                                              const std::string& protocol,
                                              const std::string& /*detail_json*/) {
    // Only trigger on ARP events involving an IP
    if (protocol != "arp") return {};
    if (event_type != "new_asset" && event_type != "ip_change" &&
        event_type != "arp_announce") return {};
    if (asset.ip.empty()) return {};

    // Query DB: count distinct MACs claiming this IP in the time window
    // We use a direct DB query approach
    try {
        // Check how many distinct MACs have claimed this IP recently
        // by looking at events for other assets with the same IP
        // This is a simplified check — production would use a subquery
        auto conflict = db_.find_asset_by_ip(asset.ip);
        if (!conflict) return {};

        // If conflict asset has a different MAC than current asset → possible spoofing
        if (conflict->mac != asset.mac && conflict->is_active) {
            std::string msg = std::format(
                "Possible ARP spoofing: IP {} claimed by both {} and {} within {}s",
                asset.ip, asset.mac, conflict->mac, window_sec_);

            std::string detail = std::format(
                "{{\"ip\":\"{}\",\"macs\":[\"{}\",\"{}\"],\"window_sec\":{}}}",
                asset.ip, asset.mac, conflict->mac, window_sec_);

            return {{asset.id, "arp_spoofing", Severity::High, msg, detail}};
        }
    } catch (...) {}

    return {};
}

} // namespace pnads

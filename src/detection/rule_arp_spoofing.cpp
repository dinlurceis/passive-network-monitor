#include "detection/rule_arp_spoofing.hpp"
#include <format>
#include <algorithm>

namespace pnads {

// Xóa các entry đã quá cũ (ngoài window_sec) của một IP
void RuleArpSpoofing::prune(const std::string& ip) {
    auto it = window_.find(ip);
    if (it == window_.end()) return;

    auto cutoff = Clock::now() - std::chrono::seconds(window_sec_);
    auto& dq    = it->second;
    while (!dq.empty() && dq.front().ts < cutoff) {
        dq.pop_front();
    }
    if (dq.empty()) window_.erase(it);
}

std::vector<Alert> RuleArpSpoofing::evaluate(const Asset& asset,
                                              const std::string& event_type,
                                              const std::string& protocol,
                                              const std::string& /*detail_json*/) {
    // Chỉ xét các event ARP có IP
    if (protocol != "arp") return {};
    if (event_type != "new_asset" && event_type != "ip_change" &&
        event_type != "arp_announce") return {};
    if (asset.ip.empty() || asset.mac.empty()) return {};

    const std::string& ip  = asset.ip;
    const std::string& mac = asset.mac;

    // Dọn entry cũ trước đã
    prune(ip);

    auto& dq = window_[ip];
    auto  now = Clock::now();

    // Thêm event hiện tại vào window nếu MAC này chưa có sẵn,
    // tránh đếm trùng khi cùng một MAC claim nhiều lần
    bool already_tracked = false;
    for (const auto& e : dq) {
        if (e.mac == mac) { already_tracked = true; break; }
    }
    if (!already_tracked) {
        dq.push_back({now, mac});
    } else {
        // Chỉ cập nhật lại timestamp cho entry đó
        for (auto& e : dq) {
            if (e.mac == mac) { e.ts = now; break; }
        }
    }

    // Đếm số MAC phân biệt trong window
    std::unordered_set<std::string> distinct_macs;
    for (const auto& e : dq) distinct_macs.insert(e.mac);

    int count = static_cast<int>(distinct_macs.size());
    if (count < mac_threshold_) return {};

    // Dựng danh sách các MAC đang xung đột
    std::string macs_json;
    for (const auto& m : distinct_macs) {
        if (!macs_json.empty()) macs_json += ',';
        macs_json += '"' + m + '"';
    }

    std::string msg = std::format(
        "ARP spoofing suspected: IP {} claimed by {} distinct MACs within {}s",
        ip, count, window_sec_);

    std::string detail = std::format(
        "{{\"ip\":\"{}\",\"distinct_macs\":{},\"macs\":[{}],\"window_sec\":{}}}",
        ip, count, macs_json, window_sec_);

    return {{asset.id, "arp_spoofing", Severity::High, msg, detail}};
}

} // namespace pnads

#include "detection/rule_new_device.hpp"
#include <format>
#include <numeric>

namespace pnads {

// Format vector<string> thành "arp, dhcp, mdns"
static std::string join(const std::vector<std::string>& v, const std::string& sep = ", ") {
    if (v.empty()) return "";
    return std::accumulate(std::next(v.begin()), v.end(), v[0],
        [&](const std::string& a, const std::string& b) { return a + sep + b; });
}

std::vector<Alert> RuleNewDevice::evaluate(const Asset& asset,
                                            const std::string& event_type,
                                            const std::string& /*protocol*/,
                                            const std::string& /*detail_json*/) {
    if (event_type != "new_asset") return {};
    if (asset.is_trusted) return {};  // thiết bị đã tin cậy thì không cảnh báo

    // Xác định severity dựa trên thông tin có được:
    //   - Không có vendor → Unknown device → High (thiết bị lạ hoàn toàn)
    //   - Có vendor nhưng không biết OS → Medium
    //   - Có cả vendor + OS → Low (đủ thông tin để đánh giá)
    Severity sev = Severity::Medium;
    if (asset.vendor.empty()) {
        sev = Severity::High;    // MAC không có trong OUI DB — rất đáng ngờ
    } else if (!asset.os_guess.empty() && asset.os_guess != "Unknown") {
        sev = Severity::Low;     // Đã biết vendor + OS → ít rủi ro hơn
    }

    std::string via_str   = join(asset.discovered_via);
    std::string vendor_str = asset.vendor.empty() ? "Unknown (not in OUI DB)" : asset.vendor;
    std::string os_str    = (asset.os_guess.empty() || asset.os_guess == "Unknown")
                              ? "Unknown" : asset.os_guess;

    std::string msg = std::format(
        "New device: MAC={} IP={} vendor='{}' os='{}' via=[{}]",
        asset.mac, asset.ip, vendor_str, os_str, via_str);

    std::string detail = std::format(
        "{{\"mac\":\"{}\",\"ip\":\"{}\",\"hostname\":\"{}\","
        "\"vendor\":\"{}\",\"os\":\"{}\",\"os_confidence\":{:.2f},"
        "\"discovered_via\":[{}]}}",
        asset.mac,
        asset.ip,
        asset.hostname,
        asset.vendor,
        asset.os_guess,
        asset.os_confidence,
        [&]() {
            std::string s;
            for (const auto& v : asset.discovered_via) {
                if (!s.empty()) s += ',';
                s += '"' + v + '"';
            }
            return s;
        }());

    return {{asset.id, "new_device", sev, msg, detail}};
}

} // namespace pnads

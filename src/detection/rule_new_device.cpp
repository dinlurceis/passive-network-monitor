#include "detection/rule_new_device.hpp"
#include <format>

namespace pnads {

std::vector<Alert> RuleNewDevice::evaluate(const Asset& asset,
                                            const std::string& event_type,
                                            const std::string& /*protocol*/,
                                            const std::string& /*detail_json*/) {
    if (event_type != "new_asset") return {};
    if (asset.is_trusted)          return {};  // trusted devices don't alert

    std::string msg = std::format(
        "New device detected: MAC={} IP={} vendor='{}'",
        asset.mac, asset.ip, asset.vendor.empty() ? "Unknown" : asset.vendor);

    std::string detail = std::format(
        "{{\"mac\":\"{}\",\"ip\":\"{}\",\"vendor\":\"{}\",\"os\":\"{}\"}}",
        asset.mac, asset.ip, asset.vendor, asset.os_guess);

    return {{asset.id, "new_device", Severity::Medium, msg, detail}};
}

} // namespace pnads

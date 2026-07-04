#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace pnads {

// Tập hợp tín hiệu từ nhiều nguồn dùng để suy luận OS
struct FingerprintSignals {
    std::optional<uint8_t>     observed_ttl;        // từ IPv4 header
    std::vector<uint8_t>       dhcp_param_list;      // DHCP option 55
    std::optional<std::string> http_user_agent;
    std::optional<std::string> mdns_service_type;    // "_airplay._tcp" ...
    std::optional<std::string> ssdp_server_header;
};

// Kết quả suy luận OS
struct OsGuessResult {
    std::string              os_name;      // "Windows", "macOS", "Linux", "Android", "iOS", "IoT/Embedded", "Unknown"
    float                    confidence;   // 0.0 - 1.0
    std::vector<std::string> matched_rules; // để giải thích kết quả (audit/log)
};

// OsFingerprint — rule-based, nhiều tín hiệu, có trọng số
// Mỗi tín hiệu đóng góp "phiếu bầu" theo trọng số; OS có tổng điểm cao nhất thắng.
class OsFingerprint {
public:
    OsGuessResult guess(const FingerprintSignals& s) const;
};

} // namespace pnads

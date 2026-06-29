#include "oui_lookup.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <spdlog/spdlog.h>

namespace netmon {

// ─── Constructor ─────────────────────────────────────────────────────────────
OuiLookup::OuiLookup(const std::string& oui_file) {
    std::ifstream file(oui_file);
    if (!file.is_open()) {
        spdlog::warn("[OUI] Cannot open file: {}. Vendor lookup disabled.", oui_file);
        return;
    }

    // Mỗi dòng trong file có format: "AA:BB:CC","Vendor Name"
    // Ví dụ: "4C:32:75","Apple, Inc."
    std::string line;
    size_t count = 0;

    while (std::getline(file, line)) {
        if (line.empty()) continue;

        // Bỏ ký tự '\r' nếu file có line endings kiểu Windows (CRLF)
        if (!line.empty() && line.back() == '\r') line.pop_back();

        // Tìm dấu ',' phân tách 2 cột
        // Format: "AA:BB:CC","Vendor Name"
        //          ^^^^^^^^^  ^^^^^^^^^^^^
        //          oui_part   vendor_part
        size_t comma_pos = line.find(',');
        if (comma_pos == std::string::npos) continue;

        std::string oui_part    = line.substr(0, comma_pos);
        std::string vendor_part = line.substr(comma_pos + 1);

        // Bỏ dấu nháy kép ở hai đầu mỗi phần
        auto strip_quotes = [](std::string& s) {
            if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
                s = s.substr(1, s.size() - 2);
            }
        };
        strip_quotes(oui_part);
        strip_quotes(vendor_part);

        if (oui_part.size() < 8) continue;  // "AA:BB:CC" = 8 ký tự

        // Chuẩn hoá OUI key về chữ HOA để so sánh nhất quán
        // Vì MAC address có thể viết hoa hoặc thường
        std::transform(oui_part.begin(), oui_part.end(), oui_part.begin(), ::toupper);

        table_[oui_part] = vendor_part;
        ++count;
    }

    loaded_ = true;
    spdlog::info("[OUI] Database loaded: {} entries from {}", count, oui_file);
}

// ─── lookup ──────────────────────────────────────────────────────────────────
std::string OuiLookup::lookup(const std::string& mac) const {
    if (!loaded_ || mac.size() < 8) return "Unknown";

    // Tách 8 ký tự đầu: "AA:BB:CC" (3 byte OUI + 2 dấu ':')
    std::string prefix = mac.substr(0, 8);

    // Chuẩn hoá về chữ HOA
    std::transform(prefix.begin(), prefix.end(), prefix.begin(), ::toupper);

    auto it = table_.find(prefix);
    if (it != table_.end()) {
        return it->second;
    }
    return "Unknown";
}

} // namespace netmon

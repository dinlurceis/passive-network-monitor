#include "oui_lookup.hpp"
#include <fstream>
#include <algorithm>
#include <cctype>
#include <spdlog/spdlog.h>

namespace pnads {

OuiLookup::OuiLookup(const std::string& oui_file) {
    std::ifstream file(oui_file);
    if (!file.is_open()) {
        spdlog::warn("[OUI] Cannot open file: {}. Vendor lookup disabled.", oui_file);
        return;
    }

    std::string line;
    size_t count = 0;

    while (std::getline(file, line)) {
        if (line.empty()) continue;
        if (!line.empty() && line.back() == '\r') line.pop_back();

        size_t comma_pos = line.find(',');
        if (comma_pos == std::string::npos) continue;

        std::string oui_part    = line.substr(0, comma_pos);
        std::string vendor_part = line.substr(comma_pos + 1);

        auto strip_quotes = [](std::string& s) {
            if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
                s = s.substr(1, s.size() - 2);
            }
        };
        strip_quotes(oui_part);
        strip_quotes(vendor_part);

        if (oui_part.size() < 8) continue;  // "AA:BB:CC" = 8 chars

        std::transform(oui_part.begin(), oui_part.end(), oui_part.begin(), ::toupper);
        table_[oui_part] = vendor_part;
        ++count;
    }

    loaded_ = true;
    spdlog::info("[OUI] Database loaded: {} entries from {}", count, oui_file);
}

std::optional<std::string> OuiLookup::lookup(const std::string& mac) const {
    if (!loaded_ || mac.size() < 8) return std::nullopt;

    std::string prefix = mac.substr(0, 8);
    std::transform(prefix.begin(), prefix.end(), prefix.begin(), ::toupper);

    auto it = table_.find(prefix);
    if (it != table_.end()) return it->second;
    return std::nullopt;
}

} // namespace pnads

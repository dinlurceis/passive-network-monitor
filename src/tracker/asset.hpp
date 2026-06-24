#pragma once
#include <string>
#include <chrono>
#include <optional>

namespace netmon {

using Clock     = std::chrono::system_clock;
using TimePoint = std::chrono::time_point<Clock>;

struct Asset {
    int         id          = 0;        // DB id (0 = chưa lưu)
    std::string mac;
    std::string ip;
    std::string hostname;
    std::string vendor;
    std::string os_guess;
    TimePoint   first_seen;
    TimePoint   last_seen;
    bool        is_active   = true;

    // Feature vector cho ML (Phase 3 populate thêm)
    float       arp_rate    = 0.0f;     // ARP packets per minute
    int         ip_changes  = 0;        // số lần đổi IP
};

} // namespace netmon

#pragma once
#include <string>
#include <vector>
#include <chrono>

namespace pnads {

using Clock     = std::chrono::system_clock;
using TimePoint = std::chrono::time_point<Clock>;

struct Asset {
    int                      id = 0;          // DB id (0 = chưa lưu)
    std::string              mac;
    std::string              ip;
    std::string              hostname;
    std::string              vendor;
    std::string              os_guess;
    float                    os_confidence = 0.0f;
    std::vector<std::string> discovered_via;   // ["arp","dhcp","mdns","ssdp","dns","http"]
    TimePoint                first_seen;
    TimePoint                last_seen;
    bool                     is_active  = true;
    bool                     is_trusted = false;
};

} // namespace pnads

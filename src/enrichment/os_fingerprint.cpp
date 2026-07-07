#include "os_fingerprint.hpp"
#include <algorithm>
#include <numeric>
#include <unordered_map>
#include <string_view>

namespace pnads {

// Cơ sở dữ liệu chữ ký DHCP Option 55
struct DhcpSignature {
    std::vector<uint8_t> options;
    const char*          os_name;
    float                weight;  // trọng số cao → tín hiệu chắc chắn hơn
};

static const DhcpSignature kDhcpSigs[] = {
    // Windows
    // Windows 11 24H2 (2025): option 252=WPAD thêm vào, 44=NetBIOS NS vẫn còn
    { {1,15,3,6,44,46,47,31,33,121,249,43,252},     "Windows", 0.92f },
    { {1,15,3,6,44,46,47,31,33,121,249,43},         "Windows", 0.90f },
    { {1,15,3,6,44,46,47,31,33,121,249,43,252,12},  "Windows", 0.88f },
    { {1,3,6,15,31,33,43,44,46,47,119,121,249,252}, "Windows", 0.87f },
    // Windows Server / joined domain: thêm option 119 (domain search)
    { {1,3,6,15,44,46,47,119,121,249,252,43},       "Windows", 0.85f },
    // macOS
    // macOS Sequoia 15.x: option 95 (LDAP) ít thấy hơn, option 114 (CAPTIVE) thêm vào
    { {1,121,3,6,15,119,252,95,44,46},              "macOS",   0.90f },
    { {1,121,3,6,15,119,252,95,44,46,47},           "macOS",   0.87f },
    { {1,121,3,6,15,119,252,114},                   "macOS",   0.85f },
    // iOS / iPadOS
    // iOS 18.x: compact option list, option 114 (CAPTIVE portal) mới thêm
    { {1,121,3,6,15,119,252},                       "iOS",     0.82f },
    { {1,121,3,6,15,119,252,44,46},                 "iOS",     0.82f },
    { {1,121,3,6,15,119,252,114},                   "iOS",     0.85f },
    // Android
    // Android 15 (DHCP client: dhcpcd / android-dhcp-15)
    { {1,33,3,6,15,28,51,58,59},                    "Android", 0.83f },
    { {1,3,6,15,26,28,51,58,59},                    "Android", 0.82f },
    { {1,3,6,12,15,17,23,28,29,31,33,40,41,42,43},  "Android", 0.80f },
    // ChromeOS
    // ChromeOS M124+ (dhcpcd 10.x): subnet, router, dns, domain, classless-routes, broadcast
    { {1,3,6,15,121,28},                            "ChromeOS", 0.85f },
    { {1,3,6,15,121,28,119},                        "ChromeOS", 0.83f },
    // Linux
    // systemd-networkd (Ubuntu 24.04+)
    { {1,28,2,3,15,6,12,42},                        "Linux",   0.80f },
    // NetworkManager (RHEL 9 / Fedora 40+)
    { {1,2,3,4,5,6,7,11,12,13,15,16,17,18,43,54},   "Linux",   0.82f },
    // dhcpcd (bản cũ / Arch Linux)
    { {1,3,6,12,15,28,42},                          "Linux",   0.75f },
    // IoT / Embedded (RTOS, bare-metal lwIP)
    // Minimal option list — chỉ subnet + router + dns
    { {1,3,6},                                      "IoT/Embedded", 0.60f },
    { {1,3,6,12},                                   "IoT/Embedded", 0.65f },
    { {1,3,6,15,42},                                "IoT/Embedded", 0.62f },
};

static float dhcp_similarity(const std::vector<uint8_t>& observed,
                              const std::vector<uint8_t>& sig) {
    if (observed.empty() || sig.empty()) return 0.0f;
    size_t matches = 0;
    for (uint8_t opt : observed) {
        if (std::find(sig.begin(), sig.end(), opt) != sig.end()) ++matches;
    }
    size_t denom = std::max(observed.size(), sig.size());
    return static_cast<float>(matches) / static_cast<float>(denom);
}

// TTL heuristic
// TTL heuristic: Linux/macOS/iOS/Android đều dùng initial TTL=64 — không phân biệt được.
// Windows dùng 128, network gear dùng 255.
// ⚠️  Chỉ dùng để phân biệt Windows vs Unix-family, không phân biệt được các Unix OS với nhau.
static std::string guess_from_ttl(uint8_t ttl) {
    if      (ttl <= 64)  return "Unix-family";  // Linux, macOS, iOS, Android — không phân biệt được qua TTL
    else if (ttl <= 128) return "Windows";
    else                 return "Network";       // BSD / Cisco / router / thiết bị mạng
}

// HTTP User-Agent rules
static std::string guess_from_ua(const std::string& ua) {
    if (ua.find("Windows NT") != std::string::npos)  return "Windows";
    if (ua.find("Mac OS X")   != std::string::npos)  return "macOS";
    if (ua.find("iPhone OS")  != std::string::npos)  return "iOS";
    if (ua.find("iPad")       != std::string::npos)  return "iOS";
    if (ua.find("Android")    != std::string::npos)  return "Android";
    if (ua.find("CrOS")       != std::string::npos)  return "ChromeOS";
    if (ua.find("X11; Linux") != std::string::npos)  return "Linux";
    if (ua.find("Linux")      != std::string::npos)  return "Linux";
    return "";
}

// mDNS / SSDP IoT rules
static std::string guess_from_mdns_service(const std::string& svc) {
    if (svc.find("_airplay")          != std::string::npos) return "Apple/AirPlay";
    if (svc.find("_googlecast")        != std::string::npos) return "Chromecast";
    if (svc.find("_googlezone")        != std::string::npos) return "Chromecast";
    if (svc.find("_spotify-connect")   != std::string::npos) return "IoT/Embedded";
    if (svc.find("_printer")           != std::string::npos) return "IoT/Printer";
    if (svc.find("_ipp")               != std::string::npos) return "IoT/Printer";
    if (svc.find("_pdl-datastream")    != std::string::npos) return "IoT/Printer";
    if (svc.find("_daap")              != std::string::npos) return "Apple/iTunes";
    if (svc.find("_dacp")              != std::string::npos) return "Apple/iTunes";  // Remote control
    if (svc.find("_airdrop")           != std::string::npos) return "Apple/AirDrop";
    // HomeKit Accessory Protocol (HAP) — Apple smart home devices
    if (svc.find("_hap")               != std::string::npos) return "Apple/HomeKit";
    if (svc.find("_companion-link")    != std::string::npos) return "Apple/HomeKit";
    // Matter protocol (CSA, 2022+) — Apple/Google/Amazon/Samsung smart home
    if (svc.find("_matter")            != std::string::npos) return "IoT/Matter";
    if (svc.find("_matterc")           != std::string::npos) return "IoT/Matter";
    if (svc.find("_meshcop")           != std::string::npos) return "IoT/Thread";   // Router biên mạng Thread
    return "";
}

static std::string guess_from_ssdp(const std::string& server_hdr) {
    if (server_hdr.find("UPnP")        != std::string::npos &&
        server_hdr.find("Linux")       != std::string::npos) return "Linux";
    if (server_hdr.find("Windows")     != std::string::npos) return "Windows";
    if (server_hdr.find("TiVo")        != std::string::npos) return "IoT/Embedded";
    if (server_hdr.find("Roku")        != std::string::npos) return "IoT/Embedded";
    if (server_hdr.find("Samsung")     != std::string::npos) return "IoT/SmartTV";
    if (server_hdr.find("LG")          != std::string::npos) return "IoT/SmartTV";
    if (server_hdr.find("Sonos")       != std::string::npos) return "IoT/Embedded";
    return "";
}

// OsFingerprint::guess
OsGuessResult OsFingerprint::guess(const FingerprintSignals& s) const {
    // Accumulate votes: os_name → total weight
    std::unordered_map<std::string, float> votes;

    // Rule 1 — TTL heuristic (weight rất thấp = 0.15, quá mơ hồ với Unix-family)
    if (s.observed_ttl) {
        std::string os = guess_from_ttl(*s.observed_ttl);
        if (!os.empty()) {
            votes[os] += 0.15f;
        }
    }

    // Rule 2 — DHCP option 55 (weight HIGH = 1.0 × similarity × sig_weight)
    if (!s.dhcp_param_list.empty()) {
        float best_score = 0.0f;
        std::string best_os;
        for (const auto& sig : kDhcpSigs) {
            float sim = dhcp_similarity(s.dhcp_param_list, sig.options);
            float score = sim * sig.weight;
            if (score > best_score) {
                best_score = score;
                best_os    = sig.os_name;
            }
        }
        if (!best_os.empty() && best_score > 0.3f) {
            votes[best_os] += best_score;
        }
    }

    // Rule 3 — mDNS service type (weight MEDIUM = 0.8)
    if (s.mdns_service_type && !s.mdns_service_type->empty()) {
        std::string os = guess_from_mdns_service(*s.mdns_service_type);
        if (!os.empty()) {
            votes[os] += 0.8f;
        }
    }

    // Rule 4 — SSDP SERVER header (weight MEDIUM = 0.7)
    if (s.ssdp_server_header && !s.ssdp_server_header->empty()) {
        std::string os = guess_from_ssdp(*s.ssdp_server_header);
        if (!os.empty()) {
            votes[os] += 0.7f;
        }
    }

    if (votes.empty()) {
        return {"Unknown", 0.0f, {}};
    }

    // Find winner
    float total = 0.0f;
    std::string winner;
    float winner_score = 0.0f;
    for (const auto& [os, score] : votes) {
        total += score;
        if (score > winner_score) {
            winner_score = score;
            winner       = os;
        }
    }

    float confidence = (total > 0.0f) ? (winner_score / total) : 0.0f;

    // Xây dựng danh sách các rule khớp
    std::vector<std::string> rules;
    if (s.observed_ttl)             rules.push_back("ttl=" + std::to_string(*s.observed_ttl));
    if (!s.dhcp_param_list.empty()) rules.push_back("dhcp_option55");
    if (s.mdns_service_type)        rules.push_back("mdns=" + *s.mdns_service_type);
    if (s.ssdp_server_header)       rules.push_back("ssdp");

    return {winner, confidence, rules};
}

} // namespace pnads

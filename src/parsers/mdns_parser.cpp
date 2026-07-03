#include "mdns_parser.hpp"
#include <algorithm>

namespace pnads {

std::optional<MdnsRecord> parse_mdns(const uint8_t* data, size_t len,
                                      const std::string& src_ip) {
    auto msg = parse_dns_message(data, len);
    if (!msg) return std::nullopt;

    MdnsRecord rec{};
    rec.src_ip = src_ip;

    for (const auto& ans : msg->answers) {
        // A or AAAA record → hostname is the name portion without ".local"
        if ((ans.type == 1 || ans.type == 28) && !ans.name.empty()) {
            std::string name = ans.name;
            // Strip ".local" suffix
            constexpr std::string_view LOCAL = ".local";
            if (name.size() > LOCAL.size() &&
                name.compare(name.size() - LOCAL.size(), LOCAL.size(), LOCAL) == 0) {
                name = name.substr(0, name.size() - LOCAL.size());
            }
            if (rec.hostname.empty()) rec.hostname = name;
        }

        // PTR record → service type is the name, hostname is in rdata
        if (ans.type == 12) {
            if (ans.name.find("._tcp.local") != std::string::npos ||
                ans.name.find("._udp.local") != std::string::npos) {
                if (rec.service_type.empty()) rec.service_type = ans.name;
            }
            // Extract instance name from PTR rdata (e.g., "MyDevice._airplay._tcp.local")
            if (rec.hostname.empty() && !ans.rdata_str.empty()) {
                // First label before the first dot is often the device name
                auto dot = ans.rdata_str.find('.');
                if (dot != std::string::npos) {
                    rec.hostname = ans.rdata_str.substr(0, dot);
                }
            }
        }

        // TXT record → look for model hint keys
        if (ans.type == 16 && !ans.rdata_str.empty()) {
            // Search for "model=", "md=", "fn=" patterns
            for (const auto& prefix : {"model=", "md=", "fn="}) {
                auto p = ans.rdata_str.find(prefix);
                if (p != std::string::npos) {
                    size_t start = p + std::strlen(prefix);
                    size_t end   = ans.rdata_str.find(' ', start);
                    rec.model_hint = ans.rdata_str.substr(start,
                        end == std::string::npos ? std::string::npos : end - start);
                    break;
                }
            }
        }
    }

    // Return nullopt if we got no useful info
    if (rec.hostname.empty() && rec.service_type.empty()) return std::nullopt;

    return rec;
}

} // namespace pnads

#pragma once
#include "parsers/dns_message.hpp"
#include <optional>
#include <string>

namespace pnads {

constexpr uint16_t MDNS_PORT = 5353;

struct MdnsRecord {
    std::string src_ip;
    std::string hostname;      // rút từ answer type A/AAAA hoặc PTR "*.local"
    std::string service_type;  // "_airplay._tcp.local", "_googlecast._tcp.local" ...
    std::string model_hint;    // rút từ TXT record (model=, md=...)
    // SRV record (type 33) fields
    std::string  srv_target;   // target hostname từ SRV record
    uint16_t     srv_port = 0; // port từ SRV record (hữu ích để identify service type)
};

// Bọc parse_dns_message(): lọc ra các answer hữu ích để định danh thiết bị.
std::optional<MdnsRecord> parse_mdns(const uint8_t* data, size_t len,
                                      const std::string& src_ip);

} // namespace pnads

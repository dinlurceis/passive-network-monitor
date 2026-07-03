#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace pnads {

struct DnsRecord {
    std::string name;
    uint16_t    type;      // A=1, PTR=12, TXT=16, SRV=33, AAAA=28
    uint32_t    ttl;
    std::string rdata_str; // giá trị đã giải mã sang string
};

struct DnsMessage {
    uint16_t                  id;
    bool                      is_response;
    std::vector<std::string>  questions;  // tên được truy vấn
    std::vector<DnsRecord>    answers;
};

// Parse DNS message (dùng cho cả DNS port 53 và mDNS port 5353).
// Xử lý name compression (pointer 0xC0xx).
std::optional<DnsMessage> parse_dns_message(const uint8_t* data, size_t len);

} // namespace pnads

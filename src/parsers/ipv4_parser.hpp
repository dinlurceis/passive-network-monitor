#pragma once
#include <cstdint>
#include <cstddef>
#include <optional>
#include <array>
#include <string>

namespace pnads {

constexpr uint8_t IP_PROTO_UDP = 17;
constexpr uint8_t IP_PROTO_TCP = 6;

struct IPv4Header {
    std::array<uint8_t, 4> src_ip;
    std::array<uint8_t, 4> dst_ip;
    uint8_t                protocol;
    uint8_t                ttl;
    const uint8_t*         payload;
    size_t                 payload_len;
};

std::optional<IPv4Header> parse_ipv4(const uint8_t* data, size_t len);

std::string ip_to_string(const std::array<uint8_t, 4>& ip);

} // namespace pnads

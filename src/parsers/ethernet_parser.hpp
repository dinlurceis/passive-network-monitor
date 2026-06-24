#pragma once
#include <cstdint>
#include <cstddef>
#include <optional>
#include <array>
#include <string>

namespace netmon {

// EtherType constants
constexpr uint16_t ETHERTYPE_ARP  = 0x0806;
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
constexpr uint16_t ETHERTYPE_VLAN = 0x8100;

constexpr size_t ETH_HEADER_LEN   = 14;
constexpr size_t ETH_ADDR_LEN     = 6;

struct EthernetFrame {
    std::array<uint8_t, ETH_ADDR_LEN> dst_mac;
    std::array<uint8_t, ETH_ADDR_LEN> src_mac;
    uint16_t ethertype;
    const uint8_t* payload;     // pointer vào buffer gốc (không copy)
    size_t payload_len;
};

// Parse Ethernet II frame. Trả về nullopt nếu data quá ngắn.
// Xử lý VLAN tag (802.1Q) tự động.
std::optional<EthernetFrame> parse_ethernet(const uint8_t* data, size_t len);

// Chuyển 6-byte MAC array thành string "AA:BB:CC:DD:EE:FF"
std::string mac_to_string(const std::array<uint8_t, ETH_ADDR_LEN>& mac);

// Chuyển string "AA:BB:CC:DD:EE:FF" thành array (trả false nếu format sai)
bool string_to_mac(const std::string& s, std::array<uint8_t, ETH_ADDR_LEN>& out);

} // namespace netmon

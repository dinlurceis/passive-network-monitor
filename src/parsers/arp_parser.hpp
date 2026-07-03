#pragma once
#include <cstdint>
#include <string>
#include <optional>

namespace pnads {

// ARP opcodes
constexpr uint16_t ARP_REQUEST     = 1;
constexpr uint16_t ARP_REPLY       = 2;
constexpr uint16_t ARP_RARP_REQ    = 3;
constexpr uint16_t ARP_RARP_REPLY  = 4;

struct ArpFrame {
    uint16_t    opcode;
    std::string sender_mac;     // "AA:BB:CC:DD:EE:FF"
    std::string sender_ip;      // "192.168.1.1"
    std::string target_mac;
    std::string target_ip;

    // Derived helpers
    bool is_request()    const { return opcode == ARP_REQUEST; }
    bool is_reply()      const { return opcode == ARP_REPLY; }
    bool is_gratuitous() const { return is_reply() && sender_ip == target_ip; }
    bool is_probe()      const { return is_request() && sender_ip == "0.0.0.0"; }
};

// Parse ARP payload (sau Ethernet header).
// data trỏ vào phần payload của EthernetFrame.
std::optional<ArpFrame> parse_arp(const uint8_t* data, size_t len);

} // namespace pnads

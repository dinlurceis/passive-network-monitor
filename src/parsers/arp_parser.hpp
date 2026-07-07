#pragma once
#include <cstdint>
#include <string>
#include <optional>

namespace pnads {

// Các mã opcode của ARP
constexpr uint16_t ARP_REQUEST     = 1;
constexpr uint16_t ARP_REPLY       = 2;
constexpr uint16_t ARP_RARP_REQ    = 3; // reverse ARP - tìm IP từ MAC
constexpr uint16_t ARP_RARP_REPLY  = 4;

struct ArpFrame {
    uint16_t    opcode;
    std::string sender_mac;     // "AA:BB:CC:DD:EE:FF"
    std::string sender_ip;      // "192.168.1.1"
    std::string target_mac;
    std::string target_ip;

    bool is_request()    const { return opcode == ARP_REQUEST; }
    bool is_reply()      const { return opcode == ARP_REPLY; }
    // yêu cầu cập nhật bảng MAC của các thiết bị trong mạng LAN (dùng khi mới kết nối mạng/ đổi IP)
    bool is_gratuitous() const { return is_reply() && sender_ip == target_ip; }
    // thăm dò xem có thiết bị nào đang dùng IP mà mình định dùng k
    bool is_probe()      const { return is_request() && sender_ip == "0.0.0.0"; }
};

// Parse ARP payload (sau Ethernet header).
// data trỏ vào phần payload của EthernetFrame.
std::optional<ArpFrame> parse_arp(const uint8_t* data, size_t len);

} // namespace pnads

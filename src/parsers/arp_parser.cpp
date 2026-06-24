#include "arp_parser.hpp"
#include <format>
#include <cstring>

namespace netmon {

// ARP packet layout (28 bytes for IPv4 over Ethernet):
// Offset  Size  Field
//  0       2    htype  (hardware type: 1=Ethernet)
//  2       2    ptype  (protocol type: 0x0800=IPv4)
//  4       1    hlen   (hardware addr length: 6 for MAC)
//  5       1    plen   (protocol addr length: 4 for IPv4)
//  6       2    opcode (1=request, 2=reply)
//  8       6    sender_mac
// 14       4    sender_ip
// 18       6    target_mac
// 24       4    target_ip

constexpr size_t ARP_MIN_LEN = 28;

static std::string mac_bytes_to_string(const uint8_t* b) {
    return std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        b[0], b[1], b[2], b[3], b[4], b[5]);
}

static std::string ip_bytes_to_string(const uint8_t* b) {
    return std::format("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
}

std::optional<ArpFrame> parse_arp(const uint8_t* data, size_t len) {
    if (len < ARP_MIN_LEN) {
        return std::nullopt;
    }

    // Validate: htype=1 (Ethernet), ptype=0x0800 (IPv4), hlen=6, plen=4
    uint16_t htype = static_cast<uint16_t>((data[0] << 8) | data[1]);
    uint16_t ptype = static_cast<uint16_t>((data[2] << 8) | data[3]);
    uint8_t  hlen  = data[4];
    uint8_t  plen  = data[5];

    if (htype != 1 || ptype != 0x0800 || hlen != 6 || plen != 4) {
        return std::nullopt;
    }

    ArpFrame frame{};
    frame.opcode     = static_cast<uint16_t>((data[6] << 8) | data[7]);
    frame.sender_mac = mac_bytes_to_string(data + 8);
    frame.sender_ip  = ip_bytes_to_string(data + 14);
    frame.target_mac = mac_bytes_to_string(data + 18);
    frame.target_ip  = ip_bytes_to_string(data + 24);

    return frame;
}

} // namespace netmon

#include "arp_parser.hpp"
#include "util/binary_reader.hpp"
#include <format>

namespace pnads {

// Cấu trúc gói ARP (28 byte cho IPv4 trên Ethernet):
// htype(2) - loại phần cứng
// ptype(2) - loại giao thức
// hlen(1) - độ dài địa chỉ phần cứng
// plen(1) - độ dài địa chỉ giao thức
// opcode(2) - 1 là request, 2 là reply
// sender_mac(6) sender_ip(4) target_mac(6) target_ip(4)

static std::string mac_array_to_string(const std::array<uint8_t, 6>& m) {
    return std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        m[0], m[1], m[2], m[3], m[4], m[5]);
}

std::optional<ArpFrame> parse_arp(const uint8_t* data, size_t len) {
    BinaryReader r(data, len);

    auto htype = r.read_u16(); auto ptype = r.read_u16();
    auto hlen  = r.read_u8();  auto plen  = r.read_u8();
    auto opcode    = r.read_u16();
    auto sender_mac_array   = r.read_mac(); auto sender_ip = r.read_ipv4_str();
    auto target_mac_array   = r.read_mac(); auto target_ip = r.read_ipv4_str();

    if (!htype || !ptype || !hlen || !plen || !opcode ||
        !sender_mac_array   || !sender_ip   || !target_mac_array  || !target_ip) {
        return std::nullopt;
    }

    // Kiểm tra hợp lệ: Ethernet (1), IPv4 (0x0800), hlen=6, plen=4
    if (*htype != 1 || *ptype != 0x0800 || *hlen != 6 || *plen != 4) {
        return std::nullopt;
    }

    ArpFrame frame{};
    frame.opcode     = *opcode;
    frame.sender_mac = mac_array_to_string(*sender_mac_array);
    frame.sender_ip  = *sender_ip;
    frame.target_mac = mac_array_to_string(*target_mac_array);
    frame.target_ip  = *target_ip;

    return frame;
}

} // namespace pnads

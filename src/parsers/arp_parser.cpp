#include "arp_parser.hpp"
#include "util/binary_reader.hpp"
#include <format>

namespace pnads {

// ARP packet layout (28 bytes for IPv4 over Ethernet):
// htype(2) ptype(2) hlen(1) plen(1) opcode(2)
// sender_mac(6) sender_ip(4) target_mac(6) target_ip(4)

static std::string mac_array_to_string(const std::array<uint8_t, 6>& m) {
    return std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        m[0], m[1], m[2], m[3], m[4], m[5]);
}

std::optional<ArpFrame> parse_arp(const uint8_t* data, size_t len) {
    BinaryReader r(data, len);

    auto htype = r.read_u16(); auto ptype = r.read_u16();
    auto hlen  = r.read_u8();  auto plen  = r.read_u8();
    auto op    = r.read_u16();
    auto sha   = r.read_mac(); auto spa = r.read_ipv4_str();
    auto tha   = r.read_mac(); auto tpa = r.read_ipv4_str();

    if (!htype || !ptype || !hlen || !plen || !op ||
        !sha   || !spa   || !tha  || !tpa) {
        return std::nullopt;
    }

    // Validate: Ethernet (1), IPv4 (0x0800), hlen=6, plen=4
    if (*htype != 1 || *ptype != 0x0800 || *hlen != 6 || *plen != 4) {
        return std::nullopt;
    }

    ArpFrame frame{};
    frame.opcode     = *op;
    frame.sender_mac = mac_array_to_string(*sha);
    frame.sender_ip  = *spa;
    frame.target_mac = mac_array_to_string(*tha);
    frame.target_ip  = *tpa;

    return frame;
}

} // namespace pnads

#include "ethernet_parser.hpp"
#include <cstring>
#include <format>
#include <optional>

namespace netmon {

std::optional<EthernetFrame> parse_ethernet(const uint8_t* data, size_t len) {
    // Minimum: 6 (dst) + 6 (src) + 2 (ethertype) = 14 bytes
    if (len < ETH_HEADER_LEN) {
        return std::nullopt;
    }

    EthernetFrame frame{};

    // Destination MAC (bytes 0–5)
    std::memcpy(frame.dst_mac.data(), data, ETH_ADDR_LEN);
    // Source MAC (bytes 6–11)
    std::memcpy(frame.src_mac.data(), data + ETH_ADDR_LEN, ETH_ADDR_LEN);

    // EtherType (bytes 12–13), big-endian
    uint16_t ethertype = static_cast<uint16_t>((data[12] << 8) | data[13]);

    size_t payload_offset = ETH_HEADER_LEN;

    // Handle 802.1Q VLAN tag: ethertype == 0x8100, followed by 4-byte tag
    // After tag: real ethertype at offset 16
    if (ethertype == ETHERTYPE_VLAN) {
        // Need at least 4 more bytes for the VLAN tag
        if (len < ETH_HEADER_LEN + 4) {
            return std::nullopt;
        }
        // VLAN tag: 2 bytes TCI (ignored) + 2 bytes real ethertype
        ethertype = static_cast<uint16_t>((data[16] << 8) | data[17]);
        payload_offset = ETH_HEADER_LEN + 4;  // 18 bytes total
    }

    frame.ethertype   = ethertype;
    frame.payload     = data + payload_offset;
    frame.payload_len = (len > payload_offset) ? (len - payload_offset) : 0;

    return frame;
}

std::string mac_to_string(const std::array<uint8_t, ETH_ADDR_LEN>& mac) {
    return std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool string_to_mac(const std::string& s, std::array<uint8_t, ETH_ADDR_LEN>& out) {
    // Expect format "AA:BB:CC:DD:EE:FF" (17 chars)
    if (s.size() != 17) {
        return false;
    }
    for (int i = 0; i < 6; ++i) {
        const char* p = s.c_str() + i * 3;
        // Check separator
        if (i < 5 && s[i * 3 + 2] != ':') {
            return false;
        }
        char* endptr = nullptr;
        unsigned long val = std::strtoul(p, &endptr, 16);
        if (endptr != p + 2 || val > 0xFF) {
            return false;
        }
        out[i] = static_cast<uint8_t>(val);
    }
    return true;
}

} // namespace netmon

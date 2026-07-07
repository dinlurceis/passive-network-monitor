#include "ethernet_parser.hpp"
#include <cstring>
#include <format>
#include <optional>

namespace pnads {

std::optional<EthernetFrame> parse_ethernet(const uint8_t* data, size_t len) {
    // Tối thiểu: 6 (dst) + 6 (src) + 2 (ethertype) = 14 byte
    if (len < ETH_HEADER_LEN) {
        return std::nullopt;
    }

    EthernetFrame frame{};

    // MAC đích (byte 0-5)
    std::memcpy(frame.dst_mac.data(), data, ETH_ADDR_LEN);
    // MAC nguồn (byte 6-11)
    std::memcpy(frame.src_mac.data(), data + ETH_ADDR_LEN, ETH_ADDR_LEN);

    // EtherType (byte 12-13), big-endian
    uint16_t ethertype = static_cast<uint16_t>((data[12] << 8) | data[13]);

    size_t payload_offset = ETH_HEADER_LEN;

    // Xử lý VLAN tag 802.1Q: ethertype == 0x8100, theo sau là tag 4 byte
    // Sau tag: ethertype thật nằm ở offset 16
    if (ethertype == ETHERTYPE_VLAN) {
        // Cần thêm ít nhất 4 byte nữa cho VLAN tag
        if (len < ETH_HEADER_LEN + 4) {
            return std::nullopt;
        }
        // VLAN tag gồm 2 byte TCI (không quan tâm, bỏ qua byte 14 15) + 2 byte ethertype
        // chỉ quan tâm 2 byte ethertype
        ethertype = static_cast<uint16_t>((data[16] << 8) | data[17]);
        payload_offset = ETH_HEADER_LEN + 4;  // tổng cộng 18 byte
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
    // Định dạng mong đợi "AA:BB:CC:DD:EE:FF" (17 ký tự)
    if (s.size() != 17) {
        return false;
    }
    for (int i = 0; i < 6; ++i) {
        const char* p = s.c_str() + i * 3;
        // Check dấu ":" có đúng vị trí k
        if (i < 5 && s[i * 3 + 2] != ':') {
            return false;
        }
        char* endptr = nullptr;
        // strtoul chuyển đổi cụm ký tự thành số nguyên -> check có vượt quá 0xFF (1 byte) k
        unsigned long val = std::strtoul(p, &endptr, 16);
        if (endptr != p + 2 || val > 0xFF) {
            return false;
        }
        out[i] = static_cast<uint8_t>(val);
    }
    return true;
}

} // namespace pnads

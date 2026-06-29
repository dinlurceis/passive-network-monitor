#include "ipv4_parser.hpp"
#include <format>

namespace netmon {

// ─── parse_ipv4 ──────────────────────────────────────────────────────────────
//
// Cấu trúc IPv4 header (tối thiểu 20 byte):
//
//  Bit  0-3  : Version (phải là 4)
//  Bit  4-7  : IHL (Internet Header Length) — đơn vị là 32-bit word
//              → độ dài thực = IHL * 4 byte
//  Byte 9    : Protocol (17=UDP, 6=TCP, ...)
//  Byte 12-15: Source IP (4 byte)
//  Byte 16-19: Destination IP (4 byte)
//  Byte 20+  : Options (nếu IHL > 5) và payload
//
std::optional<IPv4Header> parse_ipv4(const uint8_t* data, size_t len) {
    // Tối thiểu phải có 20 byte (header cơ bản)
    if (!data || len < 20) return std::nullopt;

    // Byte đầu: version (4 bit cao) và IHL (4 bit thấp)
    uint8_t version = (data[0] >> 4) & 0x0F;
    if (version != 4) return std::nullopt;  // Không phải IPv4

    // IHL = số lượng 32-bit word trong header → nhân 4 ra byte
    uint8_t ihl = (data[0] & 0x0F) * 4;
    if (ihl < 20 || len < ihl) return std::nullopt;  // IHL không hợp lệ

    IPv4Header hdr;
    hdr.protocol = data[9];

    // Copy địa chỉ IP nguồn và đích
    hdr.src_ip = { data[12], data[13], data[14], data[15] };
    hdr.dst_ip = { data[16], data[17], data[18], data[19] };

    // Payload bắt đầu ngay sau IPv4 header
    hdr.payload     = data + ihl;
    hdr.payload_len = len - ihl;

    return hdr;
}

// ─── parse_udp ───────────────────────────────────────────────────────────────
//
// Cấu trúc UDP header (cố định 8 byte):
//
//  Byte 0-1: Source Port
//  Byte 2-3: Destination Port
//  Byte 4-5: Length (bao gồm cả 8 byte header)
//  Byte 6-7: Checksum
//  Byte 8+ : Payload
//
std::optional<UdpSegment> parse_udp(const uint8_t* data, size_t len) {
    if (!data || len < 8) return std::nullopt;

    UdpSegment seg;
    // Ghép 2 byte thành uint16_t: byte cao << 8 | byte thấp
    // (dữ liệu mạng luôn là big-endian)
    seg.src_port = static_cast<uint16_t>((data[0] << 8) | data[1]);
    seg.dst_port = static_cast<uint16_t>((data[2] << 8) | data[3]);

    // udp_len = tổng chiều dài UDP segment (header + data)
    uint16_t udp_len = static_cast<uint16_t>((data[4] << 8) | data[5]);

    // Validate: udp_len phải >= 8 (header) và không vượt quá len thực
    if (udp_len < 8 || static_cast<size_t>(udp_len) > len) return std::nullopt;

    seg.payload     = data + 8;                // skip 8-byte UDP header
    seg.payload_len = static_cast<size_t>(udp_len) - 8;

    return seg;
}

// ─── ip_to_string ────────────────────────────────────────────────────────────
std::string ip_to_string(const std::array<uint8_t, 4>& ip) {
    return std::format("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
}

} // namespace netmon

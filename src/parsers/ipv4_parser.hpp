#pragma once
#include <cstdint>
#include <cstddef>
#include <optional>
#include <array>
#include <string>

namespace netmon {

// Số hiệu giao thức ở tầng transport (nằm trong IP header)
constexpr uint8_t IP_PROTO_UDP = 17;
constexpr uint8_t IP_PROTO_TCP = 6;

// Kết quả parse tầng IPv4.
// payload trỏ thẳng vào buffer gốc (không copy) — không cần giải phóng.
struct IPv4Header {
    std::array<uint8_t, 4> src_ip;      // địa chỉ nguồn (4 byte)
    std::array<uint8_t, 4> dst_ip;      // địa chỉ đích
    uint8_t                protocol;    // giao thức bên trong (UDP=17, TCP=6, ...)
    const uint8_t*         payload;     // con trỏ đến phần dữ liệu sau IP header
    size_t                 payload_len;
};

// Kết quả parse tầng UDP.
struct UdpSegment {
    uint16_t       src_port;
    uint16_t       dst_port;
    const uint8_t* payload;     // con trỏ đến dữ liệu ứng dụng (sau UDP header)
    size_t         payload_len;
};

// Parse IPv4 header từ con trỏ data/len.
// Trả về nullopt nếu data quá ngắn hoặc không phải IPv4.
// Tự động tính toán độ dài header (IHL * 4) và loại bỏ phần padding.
std::optional<IPv4Header> parse_ipv4(const uint8_t* data, size_t len);

// Parse UDP header.
// Trả về nullopt nếu data quá ngắn (< 8 byte).
std::optional<UdpSegment> parse_udp(const uint8_t* data, size_t len);

// Tiện ích: chuyển mảng 4 byte IP → chuỗi "192.168.1.1"
std::string ip_to_string(const std::array<uint8_t, 4>& ip);

} // namespace netmon

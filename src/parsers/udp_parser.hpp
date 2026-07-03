#pragma once
#include <cstdint>
#include <cstddef>
#include <optional>

namespace pnads {

struct UdpSegment {
    uint16_t       src_port;
    uint16_t       dst_port;
    const uint8_t* payload;
    size_t         payload_len;
};

// Parse UDP header (8 bytes cố định).
std::optional<UdpSegment> parse_udp(const uint8_t* data, size_t len);

} // namespace pnads

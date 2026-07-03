#pragma once
#include <cstdint>
#include <cstddef>
#include <optional>

namespace pnads {

struct TcpSegment {
    uint16_t       src_port;
    uint16_t       dst_port;
    const uint8_t* payload;
    size_t         payload_len;
};

// Parse TCP header — chỉ cần port và payload pointer.
std::optional<TcpSegment> parse_tcp(const uint8_t* data, size_t len);

} // namespace pnads

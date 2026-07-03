#include "tcp_parser.hpp"
#include "util/binary_reader.hpp"

namespace pnads {

std::optional<TcpSegment> parse_tcp(const uint8_t* data, size_t len) {
    // TCP header minimum 20 bytes
    if (!data || len < 20) return std::nullopt;

    BinaryReader r(data, len);
    auto src_port = r.read_u16();
    auto dst_port = r.read_u16();
    if (!src_port || !dst_port) return std::nullopt;

    // seq(4) + ack(4)
    if (!r.skip(8)) return std::nullopt;

    // Data offset (upper 4 bits of byte 12)
    auto off_byte = r.read_u8();
    if (!off_byte) return std::nullopt;
    size_t header_len = ((*off_byte >> 4) & 0x0F) * 4;
    if (header_len < 20 || header_len > len) return std::nullopt;

    TcpSegment seg{};
    seg.src_port    = *src_port;
    seg.dst_port    = *dst_port;
    seg.payload     = data + header_len;
    seg.payload_len = len - header_len;

    return seg;
}

} // namespace pnads

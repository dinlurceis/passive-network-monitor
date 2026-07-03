#include "udp_parser.hpp"
#include "util/binary_reader.hpp"

namespace pnads {

std::optional<UdpSegment> parse_udp(const uint8_t* data, size_t len) {
    if (!data || len < 8) return std::nullopt;

    BinaryReader r(data, len);
    auto src_port = r.read_u16();
    auto dst_port = r.read_u16();
    auto udp_len  = r.read_u16();
    // skip checksum
    if (!r.skip(2)) return std::nullopt;

    if (!src_port || !dst_port || !udp_len) return std::nullopt;
    if (*udp_len < 8 || static_cast<size_t>(*udp_len) > len) return std::nullopt;

    UdpSegment seg{};
    seg.src_port    = *src_port;
    seg.dst_port    = *dst_port;
    seg.payload     = data + 8;
    seg.payload_len = static_cast<size_t>(*udp_len) - 8;

    return seg;
}

} // namespace pnads

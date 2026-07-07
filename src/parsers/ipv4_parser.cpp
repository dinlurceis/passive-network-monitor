#include "ipv4_parser.hpp"
#include "util/binary_reader.hpp"
#include <format>

namespace pnads {

std::optional<IPv4Header> parse_ipv4(const uint8_t* data, size_t len) {
    // độ dài gói tin IPv4 từ 20-60 byte
    if (!data || len < 20) return std::nullopt;

    // byte đầu tiên (data[0]) gồm 4 bit version và 4 bit ihl (internet header length)
    uint8_t version = (data[0] >> 4) & 0x0F;
    if (version != 4) return std::nullopt;

    uint8_t ihl = (data[0] & 0x0F) * 4;
    if (ihl < 20 || len < ihl) return std::nullopt;

    // total_length (bytes 2-3): reject truncated packets where buffer < total_length
    uint16_t total_length = static_cast<uint16_t>((data[2] << 8) | data[3]);
    if (total_length < ihl || len < total_length) return std::nullopt;

    IPv4Header hdr{};
    hdr.ttl      = data[8];
    hdr.protocol = data[9];
    hdr.src_ip   = { data[12], data[13], data[14], data[15] };
    hdr.dst_ip   = { data[16], data[17], data[18], data[19] };
    hdr.payload     = data + ihl;
    hdr.payload_len = total_length - ihl;

    return hdr;
}

std::string ip_to_string(const std::array<uint8_t, 4>& ip) {
    return std::format("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
}

} // namespace pnads

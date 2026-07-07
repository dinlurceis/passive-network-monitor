#include <gtest/gtest.h>
#include "parsers/udp_parser.hpp"

using namespace pnads;

TEST(UdpParser, ValidStandardPacket) {
    // 8 bytes UDP header + 4 bytes payload
    std::vector<uint8_t> pkt = {
        0x1f, 0x90, // src port: 8080
        0x00, 0x43, // dst port: 67
        0x00, 0x0c, // length: 12 (8 header + 4 payload)
        0x00, 0x00, // checksum: 0
        0xde, 0xad, 0xbe, 0xef // payload
    };

    auto udp = parse_udp(pkt.data(), pkt.size());
    ASSERT_TRUE(udp.has_value());
    EXPECT_EQ(udp->src_port, 8080);
    EXPECT_EQ(udp->dst_port, 67);
    EXPECT_EQ(udp->payload_len, 4);
    EXPECT_EQ(udp->payload[0], 0xde);
}

TEST(UdpParser, PacketTooShort) {
    // Under 8 bytes
    std::vector<uint8_t> pkt = {
        0x1f, 0x90, 
        0x00, 0x43, 
        0x00, 0x0c, 
        0x00 // missing checksum byte
    };

    auto udp = parse_udp(pkt.data(), pkt.size());
    EXPECT_FALSE(udp.has_value());
}

TEST(UdpParser, LengthFieldTooSmall) {
    // UDP Length field is < 8 bytes
    std::vector<uint8_t> pkt = {
        0x1f, 0x90, 
        0x00, 0x43, 
        0x00, 0x07, // Length = 7 (invalid, must be at least 8)
        0x00, 0x00,
        0xde, 0xad
    };

    auto udp = parse_udp(pkt.data(), pkt.size());
    EXPECT_FALSE(udp.has_value());
}

TEST(UdpParser, TruncatedPayload) {
    // Length indicates 12 bytes total, but we only pass 10 bytes to the parser
    std::vector<uint8_t> pkt = {
        0x1f, 0x90, 
        0x00, 0x43, 
        0x00, 0x0c, // Length = 12
        0x00, 0x00,
        0xde, 0xad  // Only 2 bytes payload (total 10 bytes)
    };

    auto udp = parse_udp(pkt.data(), pkt.size());
    EXPECT_FALSE(udp.has_value());
}

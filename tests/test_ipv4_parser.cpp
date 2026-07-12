#include <gtest/gtest.h>
#include "parsers/ipv4_parser.hpp"

using namespace pnads;

TEST(Ipv4Parser, ValidStandardPacket) {
    // 20 bytes IPv4 header
    std::vector<uint8_t> pkt = {
        0x45, 0x00, 0x00, 0x1c, // Version=4, IHL=5, TOS=0, Total Len=28
        0x00, 0x00, 0x40, 0x00, // ID=0, Flags/Frag=0x4000 (DF)
        0x40, 0x11, 0x00, 0x00, // TTL=64, Proto=17 (UDP), Checksum=0
        0xc0, 0xa8, 0x01, 0x01, // Src IP: 192.168.1.1
        0xc0, 0xa8, 0x01, 0x02, // Dst IP: 192.168.1.2
        // Payload (8 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    auto ipv4 = parse_ipv4(pkt.data(), pkt.size());
    ASSERT_TRUE(ipv4.has_value());
    EXPECT_EQ(ipv4->src_ip, (std::array<uint8_t, 4>{0xc0, 0xa8, 0x01, 0x01}));
    EXPECT_EQ(ipv4->dst_ip, (std::array<uint8_t, 4>{0xc0, 0xa8, 0x01, 0x02}));
    EXPECT_EQ(ipv4->protocol, 17); // IP_PROTO_UDP
    EXPECT_EQ(ipv4->ttl, 64);
    EXPECT_EQ(ipv4->payload_len, 8);
    EXPECT_EQ(ipv4->payload[0], 0x01);

    EXPECT_EQ(ip_to_string(ipv4->src_ip), "192.168.1.1");
}

TEST(Ipv4Parser, Ipv4WithOptions) {
    // 24 bytes IPv4 header (IHL=6)
    std::vector<uint8_t> pkt = {
        0x46, 0x00, 0x00, 0x1c, // Version=4, IHL=6, Total Len=28
        0x00, 0x00, 0x40, 0x00, 
        0x40, 0x11, 0x00, 0x00, 
        0x08, 0x08, 0x08, 0x08, // Src IP: 8.8.8.8
        0x08, 0x08, 0x04, 0x04, // Dst IP: 8.8.4.4
        0x00, 0x00, 0x00, 0x00, // Options (4 bytes)
        // Payload (4 bytes)
        0xff, 0xff, 0xff, 0xff
    };

    auto ipv4 = parse_ipv4(pkt.data(), pkt.size());
    ASSERT_TRUE(ipv4.has_value());
    EXPECT_EQ(ipv4->payload_len, 4);
    EXPECT_EQ(ipv4->payload[0], 0xff);
}

TEST(Ipv4Parser, InvalidVersion) {
    // IPv6 (version=6) should be rejected
    std::vector<uint8_t> pkt = {
        0x65, 0x00, 0x00, 0x1c, 
        0x00, 0x00, 0x40, 0x00, 
        0x40, 0x11, 0x00, 0x00, 
        0xc0, 0xa8, 0x01, 0x01, 
        0xc0, 0xa8, 0x01, 0x02
    };

    auto ipv4 = parse_ipv4(pkt.data(), pkt.size());
    EXPECT_FALSE(ipv4.has_value());
}

TEST(Ipv4Parser, InvalidIhl) {
    // IHL < 5 should be rejected
    std::vector<uint8_t> pkt = {
        0x44, 0x00, 0x00, 0x1c, 
        0x00, 0x00, 0x40, 0x00, 
        0x40, 0x11, 0x00, 0x00, 
        0xc0, 0xa8, 0x01, 0x01, 
        0xc0, 0xa8, 0x01, 0x02
    };

    auto ipv4 = parse_ipv4(pkt.data(), pkt.size());
    EXPECT_FALSE(ipv4.has_value());
}

TEST(Ipv4Parser, PacketTooShort) {
    // Under 20 bytes
    std::vector<uint8_t> pkt = {
        0x45, 0x00, 0x00, 0x1c, 
        0x00, 0x00, 0x40, 0x00, 
        0x40, 0x11, 0x00, 0x00, 
        0xc0, 0xa8, 0x01, 0x01
    };

    auto ipv4 = parse_ipv4(pkt.data(), pkt.size());
    EXPECT_FALSE(ipv4.has_value());
}

TEST(Ipv4Parser, TruncatedPayload) {
    // Header indicates Total Length = 28, but buffer only has 24 bytes
    std::vector<uint8_t> pkt = {
        0x45, 0x00, 0x00, 0x1c, // Total Len=28
        0x00, 0x00, 0x40, 0x00, 
        0x40, 0x11, 0x00, 0x00, 
        0xc0, 0xa8, 0x01, 0x01, 
        0xc0, 0xa8, 0x01, 0x02,
        0xff, 0xff, 0xff, 0xff // Only 24 bytes total
    };

    auto ipv4 = parse_ipv4(pkt.data(), pkt.size());
    EXPECT_FALSE(ipv4.has_value());
}

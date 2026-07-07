#include <gtest/gtest.h>
#include "parsers/ethernet_parser.hpp"

using namespace pnads;

TEST(EthernetParser, ValidStandardFrame) {
    // 14 bytes basic Ethernet II frame
    // dst: 01:02:03:04:05:06, src: 0a:0b:0c:0d:0e:0f, type: 0800 (IPv4)
    std::vector<uint8_t> pkt = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x08, 0x00,
        0xff, 0xff, 0xff // payload (3 bytes)
    };

    auto eth = parse_ethernet(pkt.data(), pkt.size());
    ASSERT_TRUE(eth.has_value());
    EXPECT_EQ(eth->ethertype, ETHERTYPE_IPV4);
    EXPECT_EQ(eth->payload_len, 3);
    EXPECT_EQ(eth->payload[0], 0xff);

    EXPECT_EQ(mac_to_string(eth->dst_mac), "01:02:03:04:05:06");
    EXPECT_EQ(mac_to_string(eth->src_mac), "0A:0B:0C:0D:0E:0F");
}

TEST(EthernetParser, VlanFrame) {
    // 18 bytes frame with 802.1Q VLAN tag
    // dst, src, 8100, vlan tag (2 bytes), type 0806 (ARP)
    std::vector<uint8_t> pkt = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x81, 0x00, 0x00, 0x0a, // 8100 + VLAN ID 10
        0x08, 0x06,             // ARP
        0x11, 0x22              // payload (2 bytes)
    };

    auto eth = parse_ethernet(pkt.data(), pkt.size());
    ASSERT_TRUE(eth.has_value());
    EXPECT_EQ(eth->ethertype, ETHERTYPE_ARP);
    EXPECT_EQ(eth->payload_len, 2);
    EXPECT_EQ(eth->payload[0], 0x11);
}

TEST(EthernetParser, FrameTooShort) {
    // Under 14 bytes
    std::vector<uint8_t> pkt = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x08 // missing 1 byte of ethertype
    };

    auto eth = parse_ethernet(pkt.data(), pkt.size());
    EXPECT_FALSE(eth.has_value());
}

TEST(EthernetParser, VlanFrameTooShort) {
    // Contains 8100 but not enough bytes for the rest
    std::vector<uint8_t> pkt = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x81, 0x00, 0x00, 0x0a, 
        0x08 // missing 1 byte of ethertype
    };

    auto eth = parse_ethernet(pkt.data(), pkt.size());
    EXPECT_FALSE(eth.has_value());
}

TEST(EthernetParser, StringToMac) {
    std::array<uint8_t, 6> mac;
    EXPECT_TRUE(string_to_mac("01:02:03:04:05:06", mac));
    EXPECT_EQ(mac[0], 0x01);
    EXPECT_EQ(mac[5], 0x06);

    EXPECT_TRUE(string_to_mac("AA:bb:cc:DD:ee:FF", mac));
    EXPECT_EQ(mac[0], 0xaa);
    EXPECT_EQ(mac[5], 0xff);

    // Invalid format
    EXPECT_FALSE(string_to_mac("01:02:03:04:05", mac));
    EXPECT_FALSE(string_to_mac("01-02-03-04-05-06", mac));
    EXPECT_FALSE(string_to_mac("01:02:03:04:05:0Z", mac));
    EXPECT_FALSE(string_to_mac("01:02:03:04:05:06:07", mac));
}

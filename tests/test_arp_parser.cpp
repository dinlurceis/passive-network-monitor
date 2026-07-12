#include <gtest/gtest.h>
#include "parsers/arp_parser.hpp"
#include <cstring>

// Raw ARP reply packet (28 bytes ARP payload, sau Ethernet header)
// sender: 192.168.1.1 / AA:BB:CC:DD:EE:FF
// target: 192.168.1.2 / 11:22:33:44:55:66
static const uint8_t ARP_REPLY_BYTES[] = {
    0x00,0x01,               // htype = Ethernet
    0x08,0x00,               // ptype = IPv4
    0x06,                    // hlen = 6
    0x04,                    // plen = 4
    0x00,0x02,               // opcode = reply
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,  // sender MAC
    0xC0,0xA8,0x01,0x01,     // sender IP = 192.168.1.1
    0x11,0x22,0x33,0x44,0x55,0x66,  // target MAC
    0xC0,0xA8,0x01,0x02      // target IP = 192.168.1.2
};

static const uint8_t ARP_REQUEST_BYTES[] = {
    0x00,0x01, 0x08,0x00, 0x06, 0x04,
    0x00,0x01,               // opcode = request
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
    0xC0,0xA8,0x01,0x01,
    0x00,0x00,0x00,0x00,0x00,0x00,
    0xC0,0xA8,0x01,0x02
};

static const uint8_t ARP_PROBE_BYTES[] = {
    0x00,0x01, 0x08,0x00, 0x06, 0x04,
    0x00,0x01,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
    0x00,0x00,0x00,0x00,     // sender IP = 0.0.0.0
    0x00,0x00,0x00,0x00,0x00,0x00,
    0xC0,0xA8,0x01,0x02
};

TEST(ArpParser, ParseReply) {
    auto r = pnads::parse_arp(ARP_REPLY_BYTES, sizeof(ARP_REPLY_BYTES));
    ASSERT_TRUE(r.has_value());
    EXPECT_TRUE(r->is_reply());
    EXPECT_FALSE(r->is_request());
    EXPECT_EQ(r->sender_mac, "AA:BB:CC:DD:EE:FF");
    EXPECT_EQ(r->sender_ip,  "192.168.1.1");
    EXPECT_EQ(r->target_ip,  "192.168.1.2");
}

TEST(ArpParser, ParseRequest) {
    auto r = pnads::parse_arp(ARP_REQUEST_BYTES, sizeof(ARP_REQUEST_BYTES));
    ASSERT_TRUE(r.has_value());
    EXPECT_TRUE(r->is_request());
    EXPECT_FALSE(r->is_gratuitous());
}

TEST(ArpParser, ParseProbe) {
    auto r = pnads::parse_arp(ARP_PROBE_BYTES, sizeof(ARP_PROBE_BYTES));
    ASSERT_TRUE(r.has_value());
    EXPECT_TRUE(r->is_probe());
    EXPECT_EQ(r->sender_ip, "0.0.0.0");
}

TEST(ArpParser, TooShort) {
    uint8_t buf[10] = {0};
    auto r = pnads::parse_arp(buf, sizeof(buf));
    EXPECT_FALSE(r.has_value());
}

TEST(ArpParser, TooShortExact27) {
    // 28 bytes needed, 27 should fail
    uint8_t buf[27];
    std::memcpy(buf, ARP_REPLY_BYTES, 27);
    auto r = pnads::parse_arp(buf, 27);
    EXPECT_FALSE(r.has_value());
}

TEST(ArpParser, Gratuitous) {
    // Gratuitous ARP: reply with sender_ip == target_ip
    uint8_t buf[28];
    std::memcpy(buf, ARP_REPLY_BYTES, 28);
    // Set target IP to 192.168.1.1 (same as sender)
    buf[24] = 0xC0; buf[25] = 0xA8; buf[26] = 0x01; buf[27] = 0x01;
    auto r = pnads::parse_arp(buf, 28);
    ASSERT_TRUE(r.has_value());
    EXPECT_TRUE(r->is_gratuitous());
    EXPECT_EQ(r->sender_ip, r->target_ip);
}

TEST(ArpParser, InvalidHtype) {
    // htype != 1 should return nullopt
    uint8_t buf[28];
    std::memcpy(buf, ARP_REPLY_BYTES, 28);
    buf[0] = 0x00; buf[1] = 0x02;  // htype = 2 (not Ethernet)
    auto r = pnads::parse_arp(buf, 28);
    EXPECT_FALSE(r.has_value());
}

TEST(ArpParser, MacFormat) {
    auto r = pnads::parse_arp(ARP_REPLY_BYTES, sizeof(ARP_REPLY_BYTES));
    ASSERT_TRUE(r.has_value());
    // MAC format: colon-separated uppercase hex
    EXPECT_EQ(r->sender_mac.size(), 17u);
    EXPECT_EQ(r->sender_mac[2], ':');
    EXPECT_EQ(r->sender_mac[5], ':');
}

TEST(ArpParser, TargetMacRequest) {
    // In request, target MAC should be all zeros
    auto r = pnads::parse_arp(ARP_REQUEST_BYTES, sizeof(ARP_REQUEST_BYTES));
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->target_mac, "00:00:00:00:00:00");
}

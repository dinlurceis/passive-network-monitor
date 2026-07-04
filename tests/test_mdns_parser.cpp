#include <gtest/gtest.h>
#include "parsers/mdns_parser.hpp"
#include <cstring>

// Minimal mDNS response with A record for "MyDevice.local" → 192.168.1.10
// DNS message format: header(12) + answer section
static const uint8_t MDNS_A_RECORD[] = {
    // Header
    0x00, 0x00,  // ID = 0
    0x84, 0x00,  // QR=1 (response), AA=1
    0x00, 0x00,  // QDCOUNT = 0
    0x00, 0x01,  // ANCOUNT = 1
    0x00, 0x00,  // NSCOUNT = 0
    0x00, 0x00,  // ARCOUNT = 0
    // Answer: name "MyDevice.local"
    0x08, 'M','y','D','e','v','i','c','e',  // label "MyDevice" (8 bytes)
    0x05, 'l','o','c','a','l',              // label "local" (5 bytes)
    0x00,                                    // end of name
    0x00, 0x01,  // TYPE = A
    0x00, 0x01,  // CLASS = IN
    0x00, 0x00, 0x00, 0x78,  // TTL = 120
    0x00, 0x04,  // RDLENGTH = 4
    0xC0, 0xA8, 0x01, 0x0A  // RDATA = 192.168.1.10
};

TEST(MdnsParser, ParseARecord) {
    auto rec = pnads::parse_mdns(MDNS_A_RECORD, sizeof(MDNS_A_RECORD), "192.168.1.10");
    ASSERT_TRUE(rec.has_value());
    EXPECT_EQ(rec->src_ip, "192.168.1.10");
    EXPECT_FALSE(rec->hostname.empty());
    // hostname should be "MyDevice" (stripped .local)
    EXPECT_EQ(rec->hostname, "MyDevice");
}

TEST(MdnsParser, NullptrReturnsNullopt) {
    auto rec = pnads::parse_mdns(nullptr, 0, "192.168.1.1");
    EXPECT_FALSE(rec.has_value());
}

TEST(MdnsParser, TooShortReturnsNullopt) {
    uint8_t buf[5] = {0};
    auto rec = pnads::parse_mdns(buf, sizeof(buf), "192.168.1.1");
    EXPECT_FALSE(rec.has_value());
}

TEST(MdnsParser, QueryNotResponse) {
    // QR=0 (query) → mDNS parser may return empty or nullopt
    uint8_t buf[12] = {0};
    // flags = 0x0000 → query, no answers
    auto rec = pnads::parse_mdns(buf, sizeof(buf), "192.168.1.1");
    // Query with no answers → nullopt (no useful info)
    EXPECT_FALSE(rec.has_value());
}

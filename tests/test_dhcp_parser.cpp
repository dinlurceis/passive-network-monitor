#include <gtest/gtest.h>
#include "parsers/dhcp_parser.hpp"
#include <cstring>
#include <vector>

// ─── Helper: build a minimal DHCP packet ─────────────────────────────────────
// Creates a complete DHCP packet with given options.
// options: vector of (code, value_bytes)
static std::vector<uint8_t> make_dhcp_packet(
    uint8_t op,
    const std::array<uint8_t, 6>& chaddr_mac,
    const std::array<uint8_t, 4>& yiaddr,
    const std::array<uint8_t, 4>& ciaddr,
    const std::vector<std::pair<uint8_t, std::vector<uint8_t>>>& options)
{
    std::vector<uint8_t> pkt(240, 0);  // fixed header (240 bytes) initialized to zero

    pkt[0] = op;     // op: 1=BOOTREQUEST, 2=BOOTREPLY
    pkt[1] = 1;      // htype: Ethernet
    pkt[2] = 6;      // hlen: 6 bytes MAC
    pkt[3] = 0;      // hops

    // ciaddr (offset 12)
    std::memcpy(pkt.data() + 12, ciaddr.data(), 4);
    // yiaddr (offset 16)
    std::memcpy(pkt.data() + 16, yiaddr.data(), 4);
    // chaddr (offset 28, 16 bytes, first 6 = MAC)
    std::memcpy(pkt.data() + 28, chaddr_mac.data(), 6);

    // Magic cookie at offset 236
    pkt[236] = 0x63; pkt[237] = 0x82; pkt[238] = 0x53; pkt[239] = 0x63;

    // Options (TLV)
    for (const auto& [code, val] : options) {
        pkt.push_back(code);
        pkt.push_back(static_cast<uint8_t>(val.size()));
        pkt.insert(pkt.end(), val.begin(), val.end());
    }
    // END option
    pkt.push_back(255);

    return pkt;
}

static const std::array<uint8_t, 6> TEST_MAC = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
static const std::array<uint8_t, 4> ZERO_IP  = {0, 0, 0, 0};
static const std::array<uint8_t, 4> TEST_IP  = {192, 168, 1, 100};

// ─── Tests ───────────────────────────────────────────────────────────────────

TEST(DhcpParser, TooShort) {
    uint8_t buf[100] = {0};
    // Không có magic cookie → nullopt
    auto r = pnads::parse_dhcp(buf, sizeof(buf));
    EXPECT_FALSE(r.has_value());
}

TEST(DhcpParser, EmptyPacket) {
    std::vector<uint8_t> empty;
    auto r = pnads::parse_dhcp(empty.data(), empty.size());
    EXPECT_FALSE(r.has_value());
}

TEST(DhcpParser, InvalidMagicCookie) {
    std::vector<uint8_t> pkt(250, 0);
    // Wrong magic cookie
    pkt[236] = 0x00; pkt[237] = 0x00; pkt[238] = 0x00; pkt[239] = 0x00;
    auto r = pnads::parse_dhcp(pkt.data(), pkt.size());
    EXPECT_FALSE(r.has_value());
}

TEST(DhcpParser, ParseDiscover) {
    // DHCP DISCOVER với:
    //   op=1, option 53=1 (DISCOVER), option 55=[1,3,6,15,12] (Linux-like)
    std::vector<uint8_t> opt53_val = {1};  // DISCOVER
    std::vector<uint8_t> opt55_val = {1, 3, 6, 15, 12};  // param request list

    auto pkt = make_dhcp_packet(1, TEST_MAC, ZERO_IP, ZERO_IP, {
        {53, opt53_val},
        {55, opt55_val}
    });

    auto r = pnads::parse_dhcp(pkt.data(), pkt.size());
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->msg_type, pnads::DhcpMsgType::DISCOVER);
    EXPECT_EQ(r->client_mac, "AA:BB:CC:DD:EE:FF");
    EXPECT_FALSE(r->param_request_list.empty());
    EXPECT_EQ(r->param_request_list.size(), 5u);
    EXPECT_EQ(r->param_request_list[0], 1);
    EXPECT_EQ(r->param_request_list[2], 6);
    EXPECT_FALSE(r->is_from_server);
}

TEST(DhcpParser, ParseAckWithHostname) {
    // DHCP ACK từ server với:
    //   op=2 (BOOTREPLY), option 53=5 (ACK), option 12="my-laptop", yiaddr=192.168.1.100
    std::vector<uint8_t> opt53_val = {5};  // ACK
    std::string hostname = "my-laptop";
    std::vector<uint8_t> opt12_val(hostname.begin(), hostname.end());

    auto pkt = make_dhcp_packet(2, TEST_MAC, TEST_IP, ZERO_IP, {
        {53, opt53_val},
        {12, opt12_val}
    });

    auto r = pnads::parse_dhcp(pkt.data(), pkt.size());
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->msg_type, pnads::DhcpMsgType::ACK);
    EXPECT_EQ(r->hostname, "my-laptop");
    EXPECT_EQ(r->your_ip, "192.168.1.100");
    EXPECT_TRUE(r->is_from_server);
    EXPECT_EQ(r->client_mac, "AA:BB:CC:DD:EE:FF");
}

TEST(DhcpParser, ParseRequest) {
    std::vector<uint8_t> opt53_val = {3};  // REQUEST
    std::vector<uint8_t> opt50_val = {192, 168, 1, 50};  // requested IP 192.168.1.50

    auto pkt = make_dhcp_packet(1, TEST_MAC, ZERO_IP, ZERO_IP, {
        {53, opt53_val},
        {50, opt50_val}
    });

    auto r = pnads::parse_dhcp(pkt.data(), pkt.size());
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->msg_type, pnads::DhcpMsgType::REQUEST);
    EXPECT_EQ(r->requested_ip, "192.168.1.50");
}

TEST(DhcpParser, ParseOffer) {
    std::vector<uint8_t> opt53_val = {2};  // OFFER
    std::array<uint8_t, 4> offered_ip = {10, 0, 0, 5};

    auto pkt = make_dhcp_packet(2, TEST_MAC, offered_ip, ZERO_IP, {
        {53, opt53_val}
    });

    auto r = pnads::parse_dhcp(pkt.data(), pkt.size());
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->msg_type, pnads::DhcpMsgType::OFFER);
    EXPECT_EQ(r->your_ip, "10.0.0.5");
    EXPECT_TRUE(r->is_from_server);
}

TEST(DhcpParser, MsgTypeString) {
    EXPECT_EQ(pnads::dhcp_msg_type_str(pnads::DhcpMsgType::DISCOVER), "dhcp_discover");
    EXPECT_EQ(pnads::dhcp_msg_type_str(pnads::DhcpMsgType::ACK),      "dhcp_ack");
    EXPECT_EQ(pnads::dhcp_msg_type_str(pnads::DhcpMsgType::REQUEST),  "dhcp_request");
    EXPECT_EQ(pnads::dhcp_msg_type_str(pnads::DhcpMsgType::OFFER),    "dhcp_offer");
}

TEST(DhcpParser, OptionsStored) {
    // Verify tất cả options được lưu vào options map
    std::vector<uint8_t> opt53_val = {1};
    std::vector<uint8_t> opt55_val = {1, 3, 6};

    auto pkt = make_dhcp_packet(1, TEST_MAC, ZERO_IP, ZERO_IP, {
        {53, opt53_val},
        {55, opt55_val}
    });

    auto r = pnads::parse_dhcp(pkt.data(), pkt.size());
    ASSERT_TRUE(r.has_value());
    EXPECT_TRUE(r->options.count(53) > 0);
    EXPECT_TRUE(r->options.count(55) > 0);
}

TEST(DhcpParser, NoMsgType) {
    // Packet without option 53 → msg_type should be UNKNOWN
    auto pkt = make_dhcp_packet(1, TEST_MAC, ZERO_IP, ZERO_IP, {});
    auto r = pnads::parse_dhcp(pkt.data(), pkt.size());
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->msg_type, pnads::DhcpMsgType::UNKNOWN);
}

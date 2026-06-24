#include <gtest/gtest.h>
#include "parsers/arp_parser.hpp"
#include "parsers/dhcp_parser.hpp"

// test_asset_tracker.cpp
//
// AssetTracker requires a live PostgreSQL connection (DbManager).
// These tests verify the parser → tracker data flow logic
// without actually hitting the DB by testing the parser outputs
// that would be fed into the tracker.
//
// For full integration tests, run with a live DB:
//   DB_HOST=localhost DB_USER=netmon DB_PASSWORD=secret DB_NAME=netmon
//   ./build/debug/tests/test_asset_tracker

// ─── Parser → Tracker data flow tests ───────────────────────────────────────

TEST(AssetTrackerDataFlow, ArpReplyProducesCorrectFields) {
    // Simulate: an ARP reply that would trigger "new_asset" in tracker
    static const uint8_t ARP_REPLY[] = {
        0x00,0x01, 0x08,0x00, 0x06, 0x04,
        0x00,0x02,  // opcode=reply
        0x11,0x22,0x33,0x44,0x55,0x66,  // sender MAC
        0x0A,0x00,0x00,0x01,             // sender IP 10.0.0.1
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0x0A,0x00,0x00,0x02
    };

    auto frame = netmon::parse_arp(ARP_REPLY, sizeof(ARP_REPLY));
    ASSERT_TRUE(frame.has_value());

    // Check fields that asset_tracker::process_arp() uses
    EXPECT_FALSE(frame->sender_mac.empty());
    EXPECT_NE(frame->sender_mac, "00:00:00:00:00:00");
    EXPECT_NE(frame->sender_mac, "FF:FF:FF:FF:FF:FF");
    EXPECT_FALSE(frame->is_probe());   // not a probe (sender_ip != 0.0.0.0)
    EXPECT_EQ(frame->sender_ip, "10.0.0.1");
}

TEST(AssetTrackerDataFlow, ArpProbeNotTriggerNewAsset) {
    // ARP probe: sender_ip == 0.0.0.0
    // tracker should NOT create new_asset, should log arp_probe
    static const uint8_t ARP_PROBE[] = {
        0x00,0x01, 0x08,0x00, 0x06, 0x04,
        0x00,0x01,
        0x11,0x22,0x33,0x44,0x55,0x66,
        0x00,0x00,0x00,0x00,             // sender IP = 0.0.0.0
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x0A,0x00,0x00,0x64
    };

    auto frame = netmon::parse_arp(ARP_PROBE, sizeof(ARP_PROBE));
    ASSERT_TRUE(frame.has_value());
    EXPECT_TRUE(frame->is_probe());
    EXPECT_EQ(frame->sender_ip, "0.0.0.0");
}

TEST(AssetTrackerDataFlow, GratuitousArpDetected) {
    // Gratuitous ARP: reply where sender_ip == target_ip
    static const uint8_t GARP[] = {
        0x00,0x01, 0x08,0x00, 0x06, 0x04,
        0x00,0x02,  // reply
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        0xC0,0xA8,0x01,0x01,  // sender IP 192.168.1.1
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xC0,0xA8,0x01,0x01   // target IP = same as sender
    };

    auto frame = netmon::parse_arp(GARP, sizeof(GARP));
    ASSERT_TRUE(frame.has_value());
    EXPECT_TRUE(frame->is_gratuitous());
    EXPECT_FALSE(frame->is_probe());
}

TEST(AssetTrackerDataFlow, DhcpAckProvidesHostnameAndIP) {
    // DHCP ACK payload — should provide hostname and your_ip for tracker
    // Build minimal DHCP ACK packet
    std::vector<uint8_t> pkt(240, 0);
    pkt[0] = 2;  // BOOTREPLY
    pkt[1] = 1;  // htype=Ethernet
    pkt[2] = 6;  // hlen
    // yiaddr = 192.168.1.200
    pkt[16] = 192; pkt[17] = 168; pkt[18] = 1; pkt[19] = 200;
    // chaddr = AA:BB:CC:11:22:33
    pkt[28] = 0xAA; pkt[29] = 0xBB; pkt[30] = 0xCC;
    pkt[31] = 0x11; pkt[32] = 0x22; pkt[33] = 0x33;
    // Magic cookie
    pkt[236] = 0x63; pkt[237] = 0x82; pkt[238] = 0x53; pkt[239] = 0x63;
    // Option 53: ACK (5)
    pkt.push_back(53); pkt.push_back(1); pkt.push_back(5);
    // Option 12: hostname = "server01"
    std::string hn = "server01";
    pkt.push_back(12); pkt.push_back(static_cast<uint8_t>(hn.size()));
    pkt.insert(pkt.end(), hn.begin(), hn.end());
    // END
    pkt.push_back(255);

    auto info = netmon::parse_dhcp(pkt.data(), pkt.size());
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->msg_type, netmon::DhcpMsgType::ACK);
    EXPECT_EQ(info->your_ip, "192.168.1.200");
    EXPECT_EQ(info->hostname, "server01");
    EXPECT_EQ(info->client_mac, "AA:BB:CC:11:22:33");
    EXPECT_TRUE(info->is_from_server);
}

TEST(AssetTrackerDataFlow, BroadcastMacFiltered) {
    // tracker ignores broadcast MACs
    // Simulate what tracker checks: mac == "FF:FF:FF:FF:FF:FF"
    static const uint8_t ARP_BCAST[] = {
        0x00,0x01, 0x08,0x00, 0x06, 0x04,
        0x00,0x01,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,   // broadcast sender MAC
        0xC0,0xA8,0x01,0x01,
        0x00,0x00,0x00,0x00,0x00,0x00,
        0xC0,0xA8,0x01,0x02
    };

    auto frame = netmon::parse_arp(ARP_BCAST, sizeof(ARP_BCAST));
    ASSERT_TRUE(frame.has_value());
    // Tracker would skip this
    EXPECT_EQ(frame->sender_mac, "FF:FF:FF:FF:FF:FF");
}

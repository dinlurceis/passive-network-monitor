#include <gtest/gtest.h>
#include "parsers/ssdp_parser.hpp"
#include <cstring>

static const char* SSDP_NOTIFY =
    "NOTIFY * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "NT: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
    "NTS: ssdp:alive\r\n"
    "SERVER: Linux/3.18 UPnP/1.0 MyTV/1.0\r\n"
    "USN: uuid:device-001\r\n"
    "\r\n";

static const char* SSDP_MSEARCH =
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "ST: ssdp:all\r\n"
    "\r\n";

TEST(SsdpParser, ParseNotify) {
    auto msg = pnads::parse_ssdp(
        reinterpret_cast<const uint8_t*>(SSDP_NOTIFY), std::strlen(SSDP_NOTIFY),
        "192.168.1.50");
    ASSERT_TRUE(msg.has_value());
    EXPECT_EQ(msg->method, "NOTIFY");
    EXPECT_EQ(msg->src_ip, "192.168.1.50");
    EXPECT_FALSE(msg->headers.empty());
    EXPECT_NE(msg->headers.find("server"), msg->headers.end());
    EXPECT_EQ(msg->headers.at("server"), "Linux/3.18 UPnP/1.0 MyTV/1.0");
}

TEST(SsdpParser, ParseMSearch) {
    auto msg = pnads::parse_ssdp(
        reinterpret_cast<const uint8_t*>(SSDP_MSEARCH), std::strlen(SSDP_MSEARCH),
        "192.168.1.20");
    ASSERT_TRUE(msg.has_value());
    EXPECT_EQ(msg->method, "M-SEARCH");
}

TEST(SsdpParser, HeadersAreLowercased) {
    auto msg = pnads::parse_ssdp(
        reinterpret_cast<const uint8_t*>(SSDP_NOTIFY), std::strlen(SSDP_NOTIFY),
        "192.168.1.1");
    ASSERT_TRUE(msg.has_value());
    // Keys should be lowercase
    EXPECT_NE(msg->headers.find("nt"), msg->headers.end());
    EXPECT_NE(msg->headers.find("nts"), msg->headers.end());
}

TEST(SsdpParser, EmptyReturnsNullopt) {
    auto msg = pnads::parse_ssdp(nullptr, 0, "192.168.1.1");
    EXPECT_FALSE(msg.has_value());
}

TEST(SsdpParser, InvalidMessageReturnsNullopt) {
    const char* garbage = "GARBAGE DATA\r\nFoo: Bar\r\n";
    auto msg = pnads::parse_ssdp(
        reinterpret_cast<const uint8_t*>(garbage), std::strlen(garbage), "1.2.3.4");
    EXPECT_FALSE(msg.has_value());
}

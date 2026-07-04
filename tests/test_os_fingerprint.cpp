#include <gtest/gtest.h>
#include "enrichment/os_fingerprint.hpp"

using namespace pnads;

TEST(OsFingerprint, WindowsFromUA) {
    FingerprintSignals sig;
    sig.http_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    OsFingerprint fp;
    auto result = fp.guess(sig);
    EXPECT_EQ(result.os_name, "Windows");
    EXPECT_GT(result.confidence, 0.5f);
    EXPECT_FALSE(result.matched_rules.empty());
}

TEST(OsFingerprint, MacOSFromDHCP) {
    // macOS DHCP option 55 signature: {1,121,3,6,15,119,252,95,44,46}
    FingerprintSignals sig;
    sig.dhcp_param_list = {1, 121, 3, 6, 15, 119, 252, 95, 44, 46};
    OsFingerprint fp;
    auto result = fp.guess(sig);
    EXPECT_EQ(result.os_name, "macOS");
    EXPECT_GT(result.confidence, 0.5f);
}

TEST(OsFingerprint, AndroidFromUA) {
    FingerprintSignals sig;
    sig.http_user_agent = "Mozilla/5.0 (Linux; Android 12; Pixel 6) Mobile Safari/537.36";
    OsFingerprint fp;
    auto result = fp.guess(sig);
    EXPECT_EQ(result.os_name, "Android");
}

TEST(OsFingerprint, IoTFromSsdp) {
    FingerprintSignals sig;
    sig.ssdp_server_header = "Roku/9.2 UPnP/1.0 Roku/9.2";
    OsFingerprint fp;
    auto result = fp.guess(sig);
    EXPECT_EQ(result.os_name, "IoT/Embedded");
}

TEST(OsFingerprint, ChromecastFromMdns) {
    FingerprintSignals sig;
    sig.mdns_service_type = "_googlecast._tcp.local";
    OsFingerprint fp;
    auto result = fp.guess(sig);
    EXPECT_EQ(result.os_name, "Chromecast");
}

TEST(OsFingerprint, UnknownWhenNoSignals) {
    FingerprintSignals sig;  // all empty
    OsFingerprint fp;
    auto result = fp.guess(sig);
    EXPECT_EQ(result.os_name, "Unknown");
    EXPECT_FLOAT_EQ(result.confidence, 0.0f);
}

TEST(OsFingerprint, ConfidenceRange) {
    FingerprintSignals sig;
    sig.http_user_agent = "Mozilla/5.0 (Windows NT 10.0)";
    sig.observed_ttl    = 128;
    OsFingerprint fp;
    auto result = fp.guess(sig);
    EXPECT_GE(result.confidence, 0.0f);
    EXPECT_LE(result.confidence, 1.0f);
}

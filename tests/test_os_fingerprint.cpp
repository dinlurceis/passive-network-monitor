#include <gtest/gtest.h>
#include "enrichment/os_fingerprint.hpp"

using namespace pnads;

TEST(OsFingerprint, WindowsFromDHCP) {
    FingerprintSignals sig;
    // Windows DHCP signature: {1,15,3,6,44,46,47,31,33,121,249,43,252}
    sig.dhcp_param_list = {1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 43, 252};
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

TEST(OsFingerprint, AndroidFromDHCP) {
    FingerprintSignals sig;
    // Android 15 signature: {1,33,3,6,15,28,51,58,59}
    sig.dhcp_param_list = {1, 33, 3, 6, 15, 28, 51, 58, 59};
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
    sig.ssdp_server_header = "Windows/10.0 UPnP/1.1";
    sig.observed_ttl    = 128;
    OsFingerprint fp;
    auto result = fp.guess(sig);
    EXPECT_GE(result.confidence, 0.0f);
    EXPECT_LE(result.confidence, 1.0f);
}

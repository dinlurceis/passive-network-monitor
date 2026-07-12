#include <gtest/gtest.h>
#include "detection/detection_engine.hpp"
#include "detection/rule_new_device.hpp"
#include "detection/alert.hpp"
#include "tracker/asset.hpp"

using namespace pnads;

// Helper to create a test asset
static Asset make_asset(int id, const std::string& mac, const std::string& ip,
                         bool trusted = false) {
    Asset a{};
    a.id         = id;
    a.mac        = mac;
    a.ip         = ip;
    a.vendor     = "Test Vendor";
    a.is_active  = true;
    a.is_trusted = trusted;
    return a;
}

// ── RuleNewDevice ─────────────────────────────────────────────────────────────

TEST(RuleNewDevice, FiresOnNewAsset) {
    RuleNewDevice rule;
    auto asset = make_asset(1, "AA:BB:CC:DD:EE:FF", "192.168.1.10");
    auto alerts = rule.evaluate(asset, "new_asset", "arp", "{}");
    ASSERT_EQ(alerts.size(), 1u);
    EXPECT_EQ(alerts[0].rule_type, "new_device");
    EXPECT_EQ(alerts[0].severity, Severity::Medium);
    EXPECT_EQ(alerts[0].asset_id, 1);
}

TEST(RuleNewDevice, DoesNotFireOnOtherEvents) {
    RuleNewDevice rule;
    auto asset = make_asset(1, "AA:BB:CC:DD:EE:FF", "192.168.1.10");
    auto a1 = rule.evaluate(asset, "ip_change",    "arp", "{}");
    auto a2 = rule.evaluate(asset, "dhcp_ack",     "dhcp", "{}");
    auto a3 = rule.evaluate(asset, "arp_announce", "arp", "{}");
    EXPECT_TRUE(a1.empty());
    EXPECT_TRUE(a2.empty());
    EXPECT_TRUE(a3.empty());
}

TEST(RuleNewDevice, DoesNotFireForTrustedDevice) {
    RuleNewDevice rule;
    auto asset = make_asset(1, "AA:BB:CC:DD:EE:FF", "192.168.1.10", /*trusted=*/true);
    auto alerts = rule.evaluate(asset, "new_asset", "arp", "{}");
    EXPECT_TRUE(alerts.empty());
}

// ── Alert struct ──────────────────────────────────────────────────────────────

TEST(Alert, SeverityStrings) {
    EXPECT_EQ(severity_str(Severity::Low),    "low");
    EXPECT_EQ(severity_str(Severity::Medium), "medium");
    EXPECT_EQ(severity_str(Severity::High),   "high");
}

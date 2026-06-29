#include <gtest/gtest.h>
#include "enrichment/oui_lookup.hpp"
#include "enrichment/os_fingerprint.hpp"
#include <fstream>
#include <filesystem>

// ─── OuiLookup Tests ─────────────────────────────────────────────────────────

// Test khi file không tồn tại — không crash, loaded() trả false
TEST(OuiLookup, FileNotFound) {
    netmon::OuiLookup oui("/nonexistent/path/oui.csv");
    EXPECT_FALSE(oui.loaded());
    EXPECT_EQ(oui.size(), 0u);
    // lookup vẫn chạy được, trả "Unknown"
    EXPECT_EQ(oui.lookup("AA:BB:CC:DD:EE:FF"), "Unknown");
}

// Test với file CSV giả lập tạo tạm
TEST(OuiLookup, BasicLookup) {
    // Tạo file CSV tạm thời để test
    const std::string tmp_path = "test_oui_temp.csv";
    {
        std::ofstream f(tmp_path);
        f << "\"4C:32:75\",\"Apple, Inc.\"\n";
        f << "\"00:50:56\",\"VMware, Inc.\"\n";
        f << "\"AA:BB:CC\",\"Test Vendor\"\n";
    }

    netmon::OuiLookup oui(tmp_path);
    EXPECT_TRUE(oui.loaded());
    EXPECT_EQ(oui.size(), 3u);

    // Tìm thấy đúng vendor
    EXPECT_EQ(oui.lookup("4C:32:75:AB:CD:EF"), "Apple, Inc.");
    EXPECT_EQ(oui.lookup("00:50:56:12:34:56"), "VMware, Inc.");
    EXPECT_EQ(oui.lookup("AA:BB:CC:DD:EE:FF"), "Test Vendor");

    // MAC không có trong database → "Unknown"
    EXPECT_EQ(oui.lookup("FF:EE:DD:CC:BB:AA"), "Unknown");

    // Dọn dẹp
    std::filesystem::remove(tmp_path);
}

// Test không phân biệt hoa/thường
TEST(OuiLookup, CaseInsensitive) {
    const std::string tmp_path = "test_oui_case.csv";
    {
        std::ofstream f(tmp_path);
        f << "\"4C:32:75\",\"Apple, Inc.\"\n";
    }

    netmon::OuiLookup oui(tmp_path);
    EXPECT_TRUE(oui.loaded());

    // Cả hoa lẫn thường đều phải tìm được
    EXPECT_EQ(oui.lookup("4c:32:75:ab:cd:ef"), "Apple, Inc.");
    EXPECT_EQ(oui.lookup("4C:32:75:AB:CD:EF"), "Apple, Inc.");
    EXPECT_EQ(oui.lookup("4C:32:75:00:00:00"), "Apple, Inc.");

    std::filesystem::remove(tmp_path);
}

// Test MAC quá ngắn
TEST(OuiLookup, ShortMac) {
    netmon::OuiLookup oui("/nonexistent.csv");
    // MAC dưới 8 ký tự → "Unknown" không crash
    EXPECT_EQ(oui.lookup("AA:BB"), "Unknown");
    EXPECT_EQ(oui.lookup(""), "Unknown");
}

// ─── OsFingerprint Tests ──────────────────────────────────────────────────────

// Danh sách option 55 rỗng → Unknown
TEST(OsFingerprint, EmptyOptions) {
    std::vector<uint8_t> empty;
    auto fp = netmon::fingerprint_from_dhcp_options(empty);
    EXPECT_EQ(fp.os_family, "Unknown");
    EXPECT_FLOAT_EQ(fp.confidence, 0.0f);
}

// Signature Windows 7/10: {1,15,3,6,44,46,47,31,33,121,249,43,252}
TEST(OsFingerprint, WindowsSignature) {
    std::vector<uint8_t> win_options = {1,15,3,6,44,46,47,31,33,121,249,43,252};
    auto fp = netmon::fingerprint_from_dhcp_options(win_options);
    EXPECT_EQ(fp.os_family, "Windows");
    EXPECT_GE(fp.confidence, 0.5f);
}

// Signature macOS: {1,121,3,6,15,119,252,95,44,46}
TEST(OsFingerprint, MacOsSignature) {
    std::vector<uint8_t> mac_options = {1,121,3,6,15,119,252,95,44,46};
    auto fp = netmon::fingerprint_from_dhcp_options(mac_options);
    EXPECT_EQ(fp.os_family, "macOS");
    EXPECT_GE(fp.confidence, 0.5f);
}

// Signature Android: {1,33,3,6,15,28,51,58,59}
TEST(OsFingerprint, AndroidSignature) {
    std::vector<uint8_t> android_options = {1,33,3,6,15,28,51,58,59};
    auto fp = netmon::fingerprint_from_dhcp_options(android_options);
    EXPECT_EQ(fp.os_family, "Android");
    EXPECT_GE(fp.confidence, 0.5f);
}

// Option list hoàn toàn ngẫu nhiên → Unknown (điểm quá thấp)
TEST(OsFingerprint, UnknownSignature) {
    std::vector<uint8_t> unknown = {200, 201, 202, 203};
    auto fp = netmon::fingerprint_from_dhcp_options(unknown);
    EXPECT_EQ(fp.os_family, "Unknown");
}

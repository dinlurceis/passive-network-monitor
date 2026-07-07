#include <gtest/gtest.h>
#include "enrichment/oui_lookup.hpp"

#include <fstream>
#include <filesystem>

// ─── OuiLookup Tests ─────────────────────────────────────────────────────────

// Test khi file không tồn tại — không crash, loaded() trả false
TEST(OuiLookup, FileNotFound) {
    pnads::OuiLookup oui("/nonexistent/path/oui.csv");
    EXPECT_FALSE(oui.loaded());
    EXPECT_EQ(oui.size(), 0u);
    // lookup vẫn chạy được, trả "Unknown"
    EXPECT_EQ(oui.lookup("AA:BB:CC:DD:EE:FF").value_or("Unknown"), "Unknown");
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

    pnads::OuiLookup oui(tmp_path);
    EXPECT_TRUE(oui.loaded());
    EXPECT_EQ(oui.size(), 3u);

    // Tìm thấy đúng vendor
    EXPECT_EQ(oui.lookup("4C:32:75:AB:CD:EF"), "Apple, Inc.");
    EXPECT_EQ(oui.lookup("00:50:56:12:34:56"), "VMware, Inc.");
    EXPECT_EQ(oui.lookup("AA:BB:CC:DD:EE:FF"), "Test Vendor");

    // MAC không có trong database → "Unknown"
    EXPECT_EQ(oui.lookup("FF:EE:DD:CC:BB:AA").value_or("Unknown"), "Unknown");

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

    pnads::OuiLookup oui(tmp_path);
    EXPECT_TRUE(oui.loaded());

    // Cả hoa lẫn thường đều phải tìm được
    EXPECT_EQ(oui.lookup("4c:32:75:ab:cd:ef"), "Apple, Inc.");
    EXPECT_EQ(oui.lookup("4C:32:75:AB:CD:EF"), "Apple, Inc.");
    EXPECT_EQ(oui.lookup("4C:32:75:00:00:00"), "Apple, Inc.");

    std::filesystem::remove(tmp_path);
}

// Test MAC quá ngắn
TEST(OuiLookup, ShortMac) {
    pnads::OuiLookup oui("/nonexistent.csv");
    // MAC dưới 8 ký tự → "Unknown" không crash
    EXPECT_EQ(oui.lookup("AA:BB").value_or("Unknown"), "Unknown");
    EXPECT_EQ(oui.lookup("").value_or("Unknown"), "Unknown");
}


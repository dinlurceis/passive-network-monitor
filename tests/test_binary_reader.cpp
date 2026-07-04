#include <gtest/gtest.h>
#include "util/binary_reader.hpp"
#include <cstring>

using namespace pnads;

TEST(BinaryReader, ReadU8) {
    uint8_t buf[] = {0x42};
    BinaryReader r(buf, 1);
    auto v = r.read_u8();
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, 0x42);
    EXPECT_FALSE(r.read_u8().has_value());  // exhausted
}

TEST(BinaryReader, ReadU16BigEndian) {
    uint8_t buf[] = {0x08, 0x06};
    BinaryReader r(buf, 2);
    auto v = r.read_u16();
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, 0x0806);
}

TEST(BinaryReader, ReadU32BigEndian) {
    uint8_t buf[] = {0x63, 0x82, 0x53, 0x63};
    BinaryReader r(buf, 4);
    auto v = r.read_u32();
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, 0x63825363u);
}

TEST(BinaryReader, ReadMac) {
    uint8_t buf[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    BinaryReader r(buf, 6);
    auto mac = r.read_mac();
    ASSERT_TRUE(mac.has_value());
    EXPECT_EQ((*mac)[0], 0xAA);
    EXPECT_EQ((*mac)[5], 0xFF);
}

TEST(BinaryReader, ReadIPv4Str) {
    uint8_t buf[] = {192, 168, 1, 1};
    BinaryReader r(buf, 4);
    auto ip = r.read_ipv4_str();
    ASSERT_TRUE(ip.has_value());
    EXPECT_EQ(*ip, "192.168.1.1");
}

TEST(BinaryReader, BoundsCheck) {
    uint8_t buf[] = {0x01, 0x02};
    BinaryReader r(buf, 2);
    EXPECT_TRUE(r.read_u8().has_value());
    EXPECT_TRUE(r.read_u8().has_value());
    EXPECT_FALSE(r.read_u8().has_value());   // out of bounds
    EXPECT_FALSE(r.read_u16().has_value());  // out of bounds
}

TEST(BinaryReader, Skip) {
    uint8_t buf[] = {0x01, 0x02, 0x03, 0x04};
    BinaryReader r(buf, 4);
    EXPECT_TRUE(r.skip(2));
    EXPECT_EQ(r.offset(), 2u);
    auto v = r.read_u16();
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, 0x0304);
}

TEST(BinaryReader, ReadFixedString) {
    uint8_t buf[] = {'H','e','l','l','o',0,0,0};
    BinaryReader r(buf, 8);
    auto s = r.read_fixed_string(8);
    ASSERT_TRUE(s.has_value());
    EXPECT_EQ(*s, "Hello");
}

TEST(BinaryReader, ReadLine) {
    const char* text = "NOTIFY * HTTP/1.1\r\nSERVER: Linux\r\n\r\n";
    BinaryReader r(reinterpret_cast<const uint8_t*>(text), std::strlen(text));
    auto line1 = r.read_line();
    ASSERT_TRUE(line1.has_value());
    EXPECT_EQ(*line1, "NOTIFY * HTTP/1.1");
    auto line2 = r.read_line();
    ASSERT_TRUE(line2.has_value());
    EXPECT_EQ(*line2, "SERVER: Linux");
}

TEST(BinaryReader, ReadBytes) {
    uint8_t buf[] = {1, 2, 3, 4, 5};
    BinaryReader r(buf, 5);
    auto sp = r.read_bytes(3);
    ASSERT_TRUE(sp.has_value());
    EXPECT_EQ(sp->size(), 3u);
    EXPECT_EQ((*sp)[0], 1);
    EXPECT_EQ((*sp)[2], 3);
}

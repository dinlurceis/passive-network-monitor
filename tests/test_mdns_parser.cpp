// test_mdns_parser.cpp
// All test packets use fully-inline (no DNS compression pointer) encoding to avoid
// off-by-one offset errors. Each byte layout is documented step by step.
#include <gtest/gtest.h>
#include "parsers/mdns_parser.hpp"
#include <cstring>

using namespace pnads;

// ---------------------------------------------------------------------------
// Helper: build a label-encoded DNS name into a vector (no compression).
// e.g. "MyDevice.local" → {8,'M','y','D','e','v','i','c','e', 5,'l','o','c','a','l', 0}
// ---------------------------------------------------------------------------
static std::vector<uint8_t> make_name(std::vector<std::string> labels) {
    std::vector<uint8_t> out;
    for (const auto& l : labels) {
        out.push_back(static_cast<uint8_t>(l.size()));
        for (char c : l) out.push_back(static_cast<uint8_t>(c));
    }
    out.push_back(0); // terminator
    return out;
}

// Helper: append bytes to a vector
static void append(std::vector<uint8_t>& v, std::initializer_list<uint8_t> bytes) {
    v.insert(v.end(), bytes);
}
static void append_u16(std::vector<uint8_t>& v, uint16_t val) {
    v.push_back(static_cast<uint8_t>(val >> 8));
    v.push_back(static_cast<uint8_t>(val & 0xFF));
}
static void append_u32(std::vector<uint8_t>& v, uint32_t val) {
    v.push_back(static_cast<uint8_t>(val >> 24));
    v.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    v.push_back(static_cast<uint8_t>((val >>  8) & 0xFF));
    v.push_back(static_cast<uint8_t>(val & 0xFF));
}

// Build a DNS header (12 bytes): id, flags, qdcnt, ancnt, 0, 0
static std::vector<uint8_t> make_dns_header(uint16_t id, uint16_t flags,
                                             uint16_t qdcnt, uint16_t ancnt) {
    std::vector<uint8_t> hdr;
    append_u16(hdr, id);
    append_u16(hdr, flags);
    append_u16(hdr, qdcnt);
    append_u16(hdr, ancnt);
    append_u16(hdr, 0); // nscount
    append_u16(hdr, 0); // arcount
    return hdr;
}

// Build a DNS RR: name bytes + type + class + ttl + rdlen + rdata
static void add_rr(std::vector<uint8_t>& pkt,
                   const std::vector<uint8_t>& name,
                   uint16_t type, uint32_t ttl,
                   const std::vector<uint8_t>& rdata) {
    pkt.insert(pkt.end(), name.begin(), name.end());
    append_u16(pkt, type);
    append_u16(pkt, 1 /*IN*/);
    append_u32(pkt, ttl);
    append_u16(pkt, static_cast<uint16_t>(rdata.size()));
    pkt.insert(pkt.end(), rdata.begin(), rdata.end());
}

// ---------------------------------------------------------------------------
// TEST 1: Parse A record → hostname set, src_ip passed through
// ---------------------------------------------------------------------------
TEST(MdnsParser, ParseARecord) {
    // "MyDevice.local" A record → 192.168.1.10
    // dns_message.cpp: type==1, rdlen==4 → rdata_str = "192.168.1.10"
    // mdns_parser.cpp: strips ".local" → hostname = "MyDevice"
    auto hdr  = make_dns_header(0, 0x8400, 0, 1); // QR=1, AA=1, 1 answer
    auto name = make_name({"MyDevice", "local"});
    std::vector<uint8_t> rdata = {192, 168, 1, 10};

    std::vector<uint8_t> pkt = hdr;
    add_rr(pkt, name, 1 /*A*/, 120, rdata);

    auto rec = parse_mdns(pkt.data(), pkt.size(), "192.168.1.10");
    ASSERT_TRUE(rec.has_value());
    EXPECT_EQ(rec->src_ip, "192.168.1.10");
    EXPECT_EQ(rec->hostname, "MyDevice");
}

// ---------------------------------------------------------------------------
// TEST 2: nullptr → nullopt
// ---------------------------------------------------------------------------
TEST(MdnsParser, NullptrReturnsNullopt) {
    auto rec = parse_mdns(nullptr, 0, "192.168.1.1");
    EXPECT_FALSE(rec.has_value());
}

// ---------------------------------------------------------------------------
// TEST 3: Buffer too short → nullopt
// ---------------------------------------------------------------------------
TEST(MdnsParser, TooShortReturnsNullopt) {
    uint8_t buf[5] = {0};
    auto rec = parse_mdns(buf, sizeof(buf), "192.168.1.1");
    EXPECT_FALSE(rec.has_value());
}

// ---------------------------------------------------------------------------
// TEST 4: Query (QR=0) with no answers → no useful info → nullopt
// ---------------------------------------------------------------------------
TEST(MdnsParser, QueryNotResponse) {
    uint8_t buf[12] = {0}; // flags=0 → QR=0 (query), ancnt=0
    auto rec = parse_mdns(buf, sizeof(buf), "192.168.1.1");
    EXPECT_FALSE(rec.has_value());
}

// ---------------------------------------------------------------------------
// TEST 5: PTR + TXT → hostname + service_type + model_hint
//
// We send TWO answers (no SRV to keep it simple):
//   Answer 1: PTR  _airplay._tcp.local → "AppleTV._airplay._tcp.local"
//   Answer 2: TXT  AppleTV._airplay._tcp.local → "model=AppleTV3,1"
//
// Expected parser behaviour (from mdns_parser.cpp):
//   PTR  → service_type = "_airplay._tcp.local"
//          hostname     = "AppleTV" (first label of rdata before first '.')
//   TXT  → model_hint  = "AppleTV3,1"
// ---------------------------------------------------------------------------
TEST(MdnsParser, ParsePtrAndTxt) {
    auto hdr = make_dns_header(0, 0x8400, 0, 2); // QR=1, AA=1, 2 answers

    // ---- Answer 1: PTR ----
    // Owner name: _airplay._tcp.local
    auto ptr_owner = make_name({"_airplay", "_tcp", "local"});
    // RDATA: a fully-encoded name "AppleTV._airplay._tcp.local"
    auto ptr_rdata = make_name({"AppleTV", "_airplay", "_tcp", "local"});

    // ---- Answer 2: TXT ----
    // Owner name: AppleTV._airplay._tcp.local
    auto txt_owner = make_name({"AppleTV", "_airplay", "_tcp", "local"});
    // RDATA: TXT record body = length-prefixed string "model=AppleTV3,1"
    std::string txt_str = "model=AppleTV3,1";
    std::vector<uint8_t> txt_rdata;
    txt_rdata.push_back(static_cast<uint8_t>(txt_str.size())); // length byte
    txt_rdata.insert(txt_rdata.end(), txt_str.begin(), txt_str.end());

    std::vector<uint8_t> pkt = hdr;
    add_rr(pkt, ptr_owner, 12 /*PTR*/, 120, ptr_rdata);
    add_rr(pkt, txt_owner, 16 /*TXT*/, 120, txt_rdata);

    auto rec = parse_mdns(pkt.data(), pkt.size(), "192.168.1.11");
    ASSERT_TRUE(rec.has_value());
    EXPECT_EQ(rec->src_ip, "192.168.1.11");
    // PTR owner name "_airplay._tcp.local" contains "._tcp.local" → service_type
    EXPECT_EQ(rec->service_type, "_airplay._tcp.local");
    // PTR rdata "AppleTV._airplay._tcp.local" → first label before '.'
    EXPECT_EQ(rec->hostname, "AppleTV");
    // TXT "model=AppleTV3,1" → model_hint
    EXPECT_EQ(rec->model_hint, "AppleTV3,1");
}

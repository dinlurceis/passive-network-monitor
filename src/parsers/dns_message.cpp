#include "dns_message.hpp"
#include "util/binary_reader.hpp"
#include <format>

namespace pnads {

// Parse DNS name with pointer compression (RFC 1035 section 4.1.4)
// base: con trỏ đầu thông điệp DNS (để giải mã pointer)
// base_len: tổng độ dài thông điệp DNS
// pos: vị trí hiện tại trong thông điệp (sẽ bị thay đổi)
static std::string parse_dns_name(const uint8_t* base, size_t base_len, size_t& pos) {
    std::string name;
    bool first = true;
    int max_jumps = 10;  // chống lặp vô hạn từ gói tin lỗi

    while (pos < base_len) {
        uint8_t len_byte = base[pos];

        if (len_byte == 0) {
            // End of name
            ++pos;
            break;
        } else if ((len_byte & 0xC0) == 0xC0) {
            // Pointer compression: next byte gives low 8 bits of offset
            if (pos + 1 >= base_len) break;
            size_t ptr = ((len_byte & 0x3F) << 8) | base[pos + 1];
            pos += 2;
            // Follow pointer (only follow, don't update pos further from here)
            if (ptr >= base_len || max_jumps-- <= 0) break;
            size_t ptr_pos = ptr;
            std::string rest = parse_dns_name(base, base_len, ptr_pos);
            if (!name.empty() && !rest.empty()) name += '.';
            name += rest;
            return name;
        } else {
            // Normal label
            ++pos;
            if (pos + len_byte > base_len) break;
            if (!first) name += '.';
            name += std::string(reinterpret_cast<const char*>(base + pos), len_byte);
            pos += len_byte;
            first = false;
        }
    }

    return name;
}

std::optional<DnsMessage> parse_dns_message(const uint8_t* data, size_t len) {
    // DNS header is 12 bytes
    if (len < 12) return std::nullopt;

    BinaryReader r(data, len);
    auto id    = r.read_u16();
    auto flags = r.read_u16();
    auto qdcnt = r.read_u16();
    auto ancnt = r.read_u16();
    // bỏ qua nscount + arcount
    if (!r.skip(4)) return std::nullopt;

    // Check only if reads failed — qdcnt=0 and ancnt=0 are valid DNS/mDNS values
    if (!id.has_value() || !flags.has_value() || !qdcnt.has_value() || !ancnt.has_value()) return std::nullopt;

    DnsMessage msg{};
    msg.id          = *id;
    msg.is_response = (*flags & 0x8000) != 0;

    size_t pos = r.offset();

    // Parse questions
    for (uint16_t i = 0; i < *qdcnt && pos < len; ++i) {
        std::string qname = parse_dns_name(data, len, pos);
        msg.questions.push_back(qname);
        pos += 4; // bỏ qua qtype(2) + qclass(2)
    }

    // Parse answers
    for (uint16_t i = 0; i < *ancnt && pos < len; ++i) {
        std::string rname = parse_dns_name(data, len, pos);
        if (pos + 10 > len) break;

        BinaryReader rr(data + pos, len - pos);
        auto rtype  = rr.read_u16();
        auto rclass = rr.read_u16();
        auto rttl   = rr.read_u32();
        auto rdlen  = rr.read_u16();
        pos += rr.offset();

        if (!rtype || !rttl || !rdlen) break;
        if (pos + *rdlen > len) break;

        DnsRecord rec{};
        rec.name = rname;
        rec.type = *rtype;
        rec.ttl  = *rttl;

        // Decode rdata
        if (*rtype == 1 && *rdlen == 4) {
            // A record
            BinaryReader ip_r(data + pos, 4);
            auto ip = ip_r.read_ipv4_str();
            if (ip) rec.rdata_str = *ip;
        } else if (*rtype == 28 && *rdlen == 16) {
            // AAAA record
            BinaryReader ip6_r(data + pos, 16);
            auto ip6 = ip6_r.read_ipv6_str();
            if (ip6) rec.rdata_str = *ip6;
        } else if (*rtype == 12 || *rtype == 5) {
            // PTR or CNAME — contains a domain name
            size_t rdata_pos = pos;
            rec.rdata_str = parse_dns_name(data, len, rdata_pos);
        } else if (*rtype == 16) {
            // TXT record — concatenate strings
            size_t txt_pos = pos;
            while (txt_pos < pos + *rdlen && txt_pos < len) {
                uint8_t txt_len = data[txt_pos++];
                if (txt_pos + txt_len > len) break;
                if (!rec.rdata_str.empty()) rec.rdata_str += ' ';
                rec.rdata_str += std::string(reinterpret_cast<const char*>(data + txt_pos), txt_len);
                txt_pos += txt_len;
            }
        } else if (*rtype == 33 && *rdlen >= 6) {
            // SRV record — priority(2) + weight(2) + port(2) + target
            size_t target_pos = pos + 6;
            rec.rdata_str = parse_dns_name(data, len, target_pos);
        }

        msg.answers.push_back(rec);
        pos += *rdlen;
    }

    return msg;
}

} // namespace pnads

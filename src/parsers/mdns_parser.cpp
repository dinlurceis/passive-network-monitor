#include "mdns_parser.hpp"
#include <algorithm>
#include <cstring>

namespace pnads {

std::optional<MdnsRecord> parse_mdns(const uint8_t* data, size_t len,
                                      const std::string& src_ip) {
    auto msg = parse_dns_message(data, len);
    if (!msg) return std::nullopt;

    MdnsRecord rec{};
    rec.src_ip = src_ip;

    for (const auto& ans : msg->answers) {
        // Record A/AAAA: hostname là phần name bỏ đi đuôi ".local"
        if ((ans.type == 1 || ans.type == 28) && !ans.name.empty()) {
            std::string name = ans.name;
            // Cắt bỏ đuôi ".local"
            constexpr std::string_view LOCAL = ".local";
            if (name.size() > LOCAL.size() &&
                name.compare(name.size() - LOCAL.size(), LOCAL.size(), LOCAL) == 0) {
                name = name.substr(0, name.size() - LOCAL.size());
            }
            if (rec.hostname.empty()) rec.hostname = name;
        }

        // Record PTR: name là service type, hostname nằm trong rdata
        if (ans.type == 12) {
            // Nhận diện các service type quen thuộc, kể cả giao thức IoT hiện đại
            const std::string& n = ans.name;
            if (n.find("._tcp.local") != std::string::npos ||
                n.find("._udp.local") != std::string::npos) {
                if (rec.service_type.empty()) rec.service_type = n;
            }
            // Lấy instance name từ rdata của PTR (vd: "MyDevice._airplay._tcp.local")
            if (rec.hostname.empty() && !ans.rdata_str.empty()) {
                auto dot = ans.rdata_str.find('.');
                if (dot != std::string::npos) {
                    rec.hostname = ans.rdata_str.substr(0, dot);
                }
            }
        }

        // Record SRV (type 33): priority(2) + weight(2) + port(2) + target
        // parse_dns_message hiện chỉ decode target vào rdata_str, chưa lấy port;
        // phần port sẽ bổ sung ở dns_message.cpp sau, ở đây dùng những gì đang có.
        if (ans.type == 33 && !ans.name.empty()) {
            if (rec.srv_target.empty() && !ans.rdata_str.empty()) {
                rec.srv_target = ans.rdata_str;
            }
            // Lấy service type từ owner name của SRV: "instance._svc._tcp.local"
            if (rec.service_type.empty()) {
                // Tìm cụm "._" đầu tiên để tách ra service type
                auto svc_start = ans.name.find("._");
                if (svc_start != std::string::npos) {
                    rec.service_type = ans.name.substr(svc_start + 1);
                }
            }
        }

        // Record TXT: tìm các key gợi ý model
        if (ans.type == 16 && !ans.rdata_str.empty()) {
            // Dò các mẫu "model=", "md=", "fn="
            for (const auto& prefix : {"model=", "md=", "fn="}) {
                auto p = ans.rdata_str.find(prefix);
                if (p != std::string::npos) {
                    size_t start = p + std::strlen(prefix);
                    size_t end   = ans.rdata_str.find(' ', start);
                    rec.model_hint = ans.rdata_str.substr(start,
                        end == std::string::npos ? std::string::npos : end - start);
                    break;
                }
            }
        }
    }

    // Không thu được thông tin gì hữu ích thì trả về nullopt
    if (rec.hostname.empty() && rec.service_type.empty()) return std::nullopt;

    return rec;
}

} // namespace pnads

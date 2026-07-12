#include "ssdp_parser.hpp"
#include "util/binary_reader.hpp"
#include <algorithm>

namespace pnads {

// Convert header name to lowercase for case-insensitive comparison
static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

std::optional<SsdpMessage> parse_ssdp(const uint8_t* data, size_t len,
                                       const std::string& src_ip) {
    if (!data || len == 0) return std::nullopt;

    BinaryReader r(data, len);

    // Đọc dòng đầu tiên - method hoặc response
    auto first_line = r.read_line();
    if (!first_line) return std::nullopt;

    SsdpMessage msg{};
    msg.src_ip = src_ip;

    const std::string& fl = *first_line;
    if (fl.rfind("NOTIFY", 0) == 0)        msg.method = "NOTIFY";
    else if (fl.rfind("M-SEARCH", 0) == 0) msg.method = "M-SEARCH";
    else if (fl.rfind("HTTP/", 0) == 0)    msg.method = "200 OK";
    else return std::nullopt;  // Not a recognized SSDP message

    // Đọc các headers cho đến dòng trống
    while (r.remaining() > 0) {
        auto line = r.read_line();
        if (!line || line->empty()) break;

        auto colon = line->find(':');
        if (colon == std::string::npos) continue;

        std::string key = to_lower(line->substr(0, colon));
        std::string val = line->substr(colon + 1);

        // Cắt bỏ khoảng trắng ở đầu
        val.erase(0, val.find_first_not_of(" \t"));
        // Cắt bỏ khoảng trắng ở cuối
        while (!val.empty() && (val.back() == ' ' || val.back() == '\t' || val.back() == '\r'))
            val.pop_back();

        msg.headers[key] = val;

        // Convenience: hoist LOCATION ra field riêng
        if (key == "location") msg.location = val;
    }

    if (msg.headers.empty()) return std::nullopt;

    return msg;
}

} // namespace pnads

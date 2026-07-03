#include "http_parser.hpp"
#include "util/binary_reader.hpp"
#include <algorithm>
#include <string_view>

namespace pnads {

std::optional<std::string> extract_user_agent(const uint8_t* tcp_payload, size_t len) {
    if (!tcp_payload || len == 0) return std::nullopt;

    BinaryReader r(tcp_payload, len);

    // Read first line — must be an HTTP request (GET, POST, HEAD, etc.)
    auto first_line = r.read_line();
    if (!first_line) return std::nullopt;

    // Only parse HTTP requests (not responses)
    bool is_request = (first_line->rfind("GET ",     0) == 0 ||
                       first_line->rfind("POST ",    0) == 0 ||
                       first_line->rfind("HEAD ",    0) == 0 ||
                       first_line->rfind("PUT ",     0) == 0 ||
                       first_line->rfind("DELETE ",  0) == 0 ||
                       first_line->rfind("OPTIONS ", 0) == 0);
    if (!is_request) return std::nullopt;

    // Scan headers for "User-Agent:"
    while (r.remaining() > 0) {
        auto line = r.read_line();
        if (!line || line->empty()) break;

        // Case-insensitive prefix match
        std::string lower_line = *line;
        std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(), ::tolower);

        if (lower_line.rfind("user-agent:", 0) == 0) {
            // Extract value after "user-agent:"
            std::string val = line->substr(11); // len("user-agent:") = 11
            // Strip leading whitespace
            val.erase(0, val.find_first_not_of(" \t"));
            // Strip trailing whitespace
            while (!val.empty() && (val.back() == ' ' || val.back() == '\t' || val.back() == '\r'))
                val.pop_back();
            if (!val.empty()) return val;
        }
    }

    return std::nullopt;
}

} // namespace pnads

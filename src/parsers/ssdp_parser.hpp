#pragma once
#include <string>
#include <map>
#include <optional>
#include <cstdint>

namespace pnads {

constexpr uint16_t SSDP_PORT = 1900;

struct SsdpMessage {
    std::string method;                         // "NOTIFY" | "M-SEARCH" | "200 OK"
    std::map<std::string, std::string> headers; // SERVER, USN, LOCATION, ST, NT...
    std::string src_ip;
    std::string location;  // Header LOCATION: http://IP:PORT/device.xml (UPnP device description URL)
    // Header SERVER thường có dạng "Linux/3.x UPnP/1.0 MyDevice/1.0"
    // → dùng cho vendor hint và os_fingerprint
};

// Parse SSDP UDP payload (text-based, giống HTTP).
// Dùng BinaryReader::read_line() để tách từng dòng header.
std::optional<SsdpMessage> parse_ssdp(const uint8_t* data, size_t len,
                                       const std::string& src_ip);

} // namespace pnads

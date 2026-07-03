#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <optional>

namespace pnads {

// DHCP message types (option 53)
enum class DhcpMsgType : uint8_t {
    DISCOVER = 1,
    OFFER    = 2,
    REQUEST  = 3,
    DECLINE  = 4,
    ACK      = 5,
    NAK      = 6,
    RELEASE  = 7,
    INFORM   = 8,
    UNKNOWN  = 0
};

std::string dhcp_msg_type_str(DhcpMsgType t);

struct DhcpInfo {
    DhcpMsgType                         msg_type = DhcpMsgType::UNKNOWN;
    std::string                         client_mac;       // từ chaddr field
    std::string                         client_ip;        // ciaddr (nếu có)
    std::string                         your_ip;          // yiaddr (IP server cấp)
    std::string                         server_ip;        // siaddr
    std::string                         hostname;         // option 12
    std::string                         requested_ip;     // option 50
    std::vector<uint8_t>                param_request_list; // option 55 (OS fingerprint)
    std::map<uint8_t, std::vector<uint8_t>> options;     // tất cả options raw
    bool                                is_from_server = false; // OFFER hoặc ACK
};

// Parse UDP payload của DHCP packet.
// data phải bắt đầu từ DHCP header (sau UDP header).
std::optional<DhcpInfo> parse_dhcp(const uint8_t* data, size_t len);

// DHCP nằm trên UDP port 67 (server) và 68 (client)
constexpr uint16_t DHCP_SERVER_PORT = 67;
constexpr uint16_t DHCP_CLIENT_PORT = 68;
constexpr uint32_t DHCP_MAGIC_COOKIE = 0x63825363;

} // namespace pnads

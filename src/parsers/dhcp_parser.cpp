#include "dhcp_parser.hpp"
#include "util/binary_reader.hpp"
#include <format>

namespace pnads {

// DHCP fixed header offsets (all before magic cookie at 236):
// op(1) htype(1) hlen(1) hops(1) xid(4) secs(2) flags(2)
// ciaddr(4) yiaddr(4) siaddr(4) giaddr(4) chaddr(16)
// sname(64) file(128) → total 236 bytes before magic cookie

constexpr size_t DHCP_MIN_LEN     = 240;  // up to and including magic cookie
constexpr size_t DHCP_OPTIONS_OFF = 240;

static std::string mac_bytes_to_str(const uint8_t* b) {
    return std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        b[0], b[1], b[2], b[3], b[4], b[5]);
}

std::string dhcp_msg_type_str(DhcpMsgType t) {
    switch (t) {
        case DhcpMsgType::DISCOVER: return "dhcp_discover";
        case DhcpMsgType::OFFER:    return "dhcp_offer";
        case DhcpMsgType::REQUEST:  return "dhcp_request";
        case DhcpMsgType::DECLINE:  return "dhcp_decline";
        case DhcpMsgType::ACK:      return "dhcp_ack";
        case DhcpMsgType::NAK:      return "dhcp_nak";
        case DhcpMsgType::RELEASE:  return "dhcp_release";
        case DhcpMsgType::INFORM:   return "dhcp_inform";
        default:                    return "dhcp_unknown";
    }
}

std::optional<DhcpInfo> parse_dhcp(const uint8_t* data, size_t len) {
    if (len < DHCP_MIN_LEN) return std::nullopt;

    // Validate magic cookie at offset 236
    BinaryReader mc(data + 236, 4);
    auto cookie = mc.read_u32();
    if (!cookie || *cookie != DHCP_MAGIC_COOKIE) return std::nullopt;

    DhcpInfo info{};

    // op field: 1=BOOTREQUEST, 2=BOOTREPLY
    info.is_from_server = (data[0] == 2);

    // htype=1 (Ethernet), hlen=6 (MAC)
    if (data[1] == 1 && data[2] == 6) {
        info.client_mac = mac_bytes_to_str(data + 28);
    }

    // ciaddr (client IP, offset 12)
    if (data[12] || data[13] || data[14] || data[15]) {
        BinaryReader r(data + 12, 4);
        auto s = r.read_ipv4_str();
        if (s) info.client_ip = *s;
    }
    // yiaddr (your IP, offset 16)
    if (data[16] || data[17] || data[18] || data[19]) {
        BinaryReader r(data + 16, 4);
        auto s = r.read_ipv4_str();
        if (s) info.your_ip = *s;
    }
    // siaddr (server IP, offset 20)
    if (data[20] || data[21] || data[22] || data[23]) {
        BinaryReader r(data + 20, 4);
        auto s = r.read_ipv4_str();
        if (s) info.server_ip = *s;
    }

    // Parse options (TLV after magic cookie)
    BinaryReader r(data + DHCP_OPTIONS_OFF, len - DHCP_OPTIONS_OFF);
    while (r.remaining() > 0) {
        auto code_opt = r.read_u8();
        if (!code_opt) break;
        uint8_t code = *code_opt;

        if (code == 255) break;  // END
        if (code == 0)  continue; // PAD

        auto len_opt = r.read_u8();
        if (!len_opt) break;
        uint8_t opt_len = *len_opt;

        auto bytes = r.read_bytes(opt_len);
        if (!bytes) break;

        std::vector<uint8_t> opt_val(bytes->begin(), bytes->end());
        info.options[code] = opt_val;

        switch (code) {
            case 53:  // DHCP Message Type
                if (!opt_val.empty()) {
                    uint8_t mt = opt_val[0];
                    if (mt >= 1 && mt <= 8)
                        info.msg_type = static_cast<DhcpMsgType>(mt);
                }
                break;

            case 12:  // Host Name
                info.hostname = std::string(opt_val.begin(), opt_val.end());
                break;

            case 50:  // Requested IP Address
                if (opt_val.size() == 4) {
                    BinaryReader ip_r(opt_val.data(), 4);
                    auto ip = ip_r.read_ipv4_str();
                    if (ip) info.requested_ip = *ip;
                }
                break;

            case 55:  // Parameter Request List
                info.param_request_list = opt_val;
                break;

            default:
                break;
        }
    }

    return info;
}

} // namespace pnads

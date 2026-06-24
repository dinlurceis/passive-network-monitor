#include "dhcp_parser.hpp"
#include <format>
#include <cstring>

namespace netmon {

// DHCP packet structure:
// Offset  Size  Field
//  0       1    op       (1=BOOTREQUEST, 2=BOOTREPLY)
//  1       1    htype    (1=Ethernet)
//  2       1    hlen     (6 for MAC)
//  3       1    hops
//  4       4    xid      (transaction ID)
//  8       2    secs
// 10       2    flags
// 12       4    ciaddr   (client IP address)
// 16       4    yiaddr   (your IP address — server gives to client)
// 20       4    siaddr   (server IP)
// 24       4    giaddr   (relay agent IP)
// 28      16    chaddr   (client hardware address, first 6 bytes = MAC)
// 44      64    sname    (server hostname)
//108     128    file     (boot filename)
//236       4    magic cookie (0x63825363)
//240      ..    options  (TLV format)

constexpr size_t DHCP_MIN_LEN     = 240;  // header up to magic cookie
constexpr size_t DHCP_OPTIONS_OFF = 240;

static std::string ip_bytes_to_string(const uint8_t* b) {
    return std::format("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
}

static std::string mac_bytes_to_string(const uint8_t* b) {
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
    // Need at least the fixed header + magic cookie
    if (len < DHCP_MIN_LEN) {
        return std::nullopt;
    }

    // Validate magic cookie at offset 236
    uint32_t cookie = (static_cast<uint32_t>(data[236]) << 24) |
                      (static_cast<uint32_t>(data[237]) << 16) |
                      (static_cast<uint32_t>(data[238]) << 8)  |
                       static_cast<uint32_t>(data[239]);
    if (cookie != DHCP_MAGIC_COOKIE) {
        return std::nullopt;
    }

    DhcpInfo info{};

    // op field: 1=BOOTREQUEST, 2=BOOTREPLY
    uint8_t op = data[0];
    info.is_from_server = (op == 2);

    // IP addresses
    // ciaddr (client IP — set if client has valid IP, else 0.0.0.0)
    if (data[12] || data[13] || data[14] || data[15]) {
        info.client_ip = ip_bytes_to_string(data + 12);
    }
    // yiaddr (your IP — server-assigned)
    if (data[16] || data[17] || data[18] || data[19]) {
        info.your_ip = ip_bytes_to_string(data + 16);
    }
    // siaddr (next server IP)
    if (data[20] || data[21] || data[22] || data[23]) {
        info.server_ip = ip_bytes_to_string(data + 20);
    }

    // chaddr: client hardware address (MAC = first 6 bytes of 16-byte field at offset 28)
    // htype=1, hlen=6 → first 6 bytes are MAC
    if (data[1] == 1 && data[2] == 6) {
        info.client_mac = mac_bytes_to_string(data + 28);
    }

    // Parse options (TLV after magic cookie at offset 240)
    size_t pos = DHCP_OPTIONS_OFF;
    while (pos < len) {
        uint8_t code = data[pos++];

        if (code == 255) {  // END option
            break;
        }
        if (code == 0) {    // PAD option (no length byte)
            continue;
        }

        // Need at least 1 more byte for length
        if (pos >= len) break;
        uint8_t opt_len = data[pos++];

        // Need opt_len more bytes
        if (pos + opt_len > len) break;

        // Store raw option
        std::vector<uint8_t> opt_val(data + pos, data + pos + opt_len);
        info.options[code] = opt_val;

        // Process known options
        switch (code) {
            case 53:  // DHCP Message Type
                if (opt_len >= 1) {
                    uint8_t mt = data[pos];
                    if (mt >= 1 && mt <= 8) {
                        info.msg_type = static_cast<DhcpMsgType>(mt);
                    }
                }
                break;

            case 12:  // Host Name
                info.hostname = std::string(reinterpret_cast<const char*>(data + pos), opt_len);
                break;

            case 50:  // Requested IP Address
                if (opt_len == 4) {
                    info.requested_ip = ip_bytes_to_string(data + pos);
                }
                break;

            case 55:  // Parameter Request List (OS fingerprint)
                info.param_request_list.assign(data + pos, data + pos + opt_len);
                break;

            default:
                break;
        }

        pos += opt_len;
    }

    return info;
}

} // namespace netmon

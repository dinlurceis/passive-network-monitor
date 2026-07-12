"""
generate_violation_pcap.py
──────────────────────────────────────────────────────────────────
Tạo file PCAP demo chứa CÁC VI PHẠM để trigger detection rules.

Detection rules được trigger:
  1. rule_new_device    → 3 thiết bị hoàn toàn mới (MAC chưa trong DB)
  2. rule_arp_spoofing  → IP 192.168.1.254 bị claim bởi 2 MAC khác nhau
  3. rule_watchlist_match → MAC DE:AD:BE:EF:00:01 xuất hiện (phải seed watchlist trước)

Cách dùng:
  1. Seed watchlist:  psql -U pnads -d pnads -f scripts/seed_watchlist.sql
  2. Tạo PCAP:        python scripts/generate_violation_pcap.py
  3. Upload qua UI:   mở dashboard → PCAP Upload → chọn samples/violation.pcap

Gói tin tuân thủ đúng pipeline C++ parser:
  Ethernet → IPv4 → UDP → [ARP|DHCP|mDNS|SSDP]
"""

import struct
import socket
import random
import os
import sys
import time

try:
    from scapy.utils import wrpcap
    from scapy.layers.l2 import Ether
except ImportError:
    print("Thiếu scapy: pip install scapy")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Constants — khớp với parser C++ (namespace pnads)
# ─────────────────────────────────────────────────────────────────────────────
ETHERTYPE_ARP  = 0x0806
ETHERTYPE_IPV4 = 0x0800
IP_PROTO_UDP   = 17
DHCP_MAGIC     = 0x63825363
DHCP_SRV_PORT  = 67
DHCP_CLI_PORT  = 68
MDNS_PORT      = 5353
SSDP_PORT      = 1900

MDNS_MULTICAST = "224.0.0.251"
SSDP_MULTICAST = "239.255.255.250"
MDNS_MAC       = bytes.fromhex("01005e0000fb")
SSDP_MAC       = bytes.fromhex("01005e7ffffa")
BCAST_MAC      = b"\xff\xff\xff\xff\xff\xff"
ZERO_MAC       = b"\x00\x00\x00\x00\x00\x00"

# ─────────────────────────────────────────────────────────────────────────────
# Violation actors
# ─────────────────────────────────────────────────────────────────────────────

# Rule 1: new_device — 3 thiết bị lạ chưa từng có trong DB
NEW_DEVICES = [
    {"mac": "BA:D0:CA:FE:00:01", "ip": "192.168.1.200",
     "hostname": "unknown-device-1", "opt55": bytes([1, 3, 6, 15])},
    {"mac": "BA:D0:CA:FE:00:02", "ip": "192.168.1.201",
     "hostname": "rogue-laptop",     "opt55": bytes([1, 15, 3, 6, 44, 46])},
    {"mac": "BA:D0:CA:FE:00:03", "ip": "192.168.1.202",
     "hostname": "hidden-pi",        "opt55": bytes([1, 28, 2, 3, 15, 6, 12])},
]

# Rule 2: arp_spoofing — 2 MAC claim cùng 1 IP trong <60s
SPOOF_IP       = "192.168.1.254"     # IP bị giả mạo (gateway mới)
SPOOF_LEGIT    = "AA:BB:CC:11:22:33" # MAC hợp lệ của IP này
SPOOF_ATTACKER = "DE:AD:BE:EF:CA:FE" # MAC kẻ tấn công ARP spoofing

# Rule 3: watchlist_match — MAC này phải có trong bảng watchlist trước khi replay
# Xem scripts/seed_watchlist.sql
WATCHLIST_MAC  = "DE:AD:BE:EF:00:01"
WATCHLIST_IP   = "192.168.1.250"

# Existing gateway (already known)
GATEWAY = {"mac": "00:11:22:33:44:55", "ip": "192.168.1.1"}

# ─────────────────────────────────────────────────────────────────────────────
# Layer builders (same as generate_full_coverage_pcap.py)
# ─────────────────────────────────────────────────────────────────────────────
def mac_bytes(mac_str: str) -> bytes:
    return bytes.fromhex(mac_str.replace(":", ""))

def ip_bytes(ip_str: str) -> bytes:
    return socket.inet_aton(ip_str)

def build_eth(src_mac: str, dst_mac_bytes: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst_mac_bytes + mac_bytes(src_mac) + struct.pack("!H", ethertype) + payload

def build_ipv4(src_ip: str, dst_ip: str, proto: int, payload: bytes, ttl: int = 64) -> bytes:
    ihl = 5
    vhl = (4 << 4) | ihl
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s",
        vhl, 0, total, random.randint(0, 0xFFFF),
        0x4000, ttl, proto, 0,
        ip_bytes(src_ip), ip_bytes(dst_ip),
    )
    return hdr + payload

def build_udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload

def build_arp_payload(op: int, sender_mac: str, sender_ip: str,
                      target_mac: bytes, target_ip: str) -> bytes:
    return struct.pack("!HHBBH",
        1, 0x0800, 6, 4, op
    ) + mac_bytes(sender_mac) + ip_bytes(sender_ip) + target_mac + ip_bytes(target_ip)

def make_arp_packet(op: int, sender_mac: str, sender_ip: str,
                    target_mac: bytes, target_ip: str,
                    dst_eth: bytes = None) -> bytes:
    if dst_eth is None:
        dst_eth = BCAST_MAC
    arp = build_arp_payload(op, sender_mac, sender_ip, target_mac, target_ip)
    return build_eth(sender_mac, dst_eth, ETHERTYPE_ARP, arp)

def build_dhcp_options(*option_list) -> bytes:
    result = b""
    for code, value in option_list:
        result += bytes([code, len(value)]) + value
    result += bytes([255])
    return result

def build_dhcp_payload(op: int, xid: int, client_mac: str,
                       ciaddr: str = "0.0.0.0",
                       yiaddr: str = "0.0.0.0",
                       siaddr: str = "0.0.0.0",
                       options: bytes = b"") -> bytes:
    mac_b  = bytes.fromhex(client_mac.replace(":", ""))
    chaddr = mac_b + b"\x00" * 10
    header = struct.pack("!BBBB I HH 4s4s4s4s",
        op, 1, 6, 0, xid, 0, 0,
        ip_bytes(ciaddr), ip_bytes(yiaddr), ip_bytes(siaddr), ip_bytes("0.0.0.0"),
    )
    return header + chaddr + b"\x00" * 64 + b"\x00" * 128 + struct.pack("!I", DHCP_MAGIC) + options

def encode_dns_name(name: str) -> bytes:
    result = b""
    for label in name.rstrip(".").split("."):
        enc = label.encode()
        result += bytes([len(enc)]) + enc
    result += b"\x00"
    return result

packets: list = []
pkt_counts: dict = {}

def add_frame(raw_bytes: bytes, proto: str = "other"):
    packets.append(Ether(raw_bytes))
    pkt_counts[proto] = pkt_counts.get(proto, 0) + 1


# ─────────────────────────────────────────────────────────────────────────────
# VIOLATION 1: rule_new_device
# Trigger: event_type == "new_asset" cho MAC chưa bao giờ trong DB
# Rule: RuleNewDevice.evaluate() chỉ kích hoạt khi event_type == "new_asset"
# ─────────────────────────────────────────────────────────────────────────────
def gen_violation_new_device():
    """
    3 thiết bị hoàn toàn mới:
    - ARP probe (is_probe=true) → asset_tracker: upsert mới + "new_asset"
    - ARP request/reply         → asset_tracker: upsert nếu chưa có
    - DHCP Discover + ACK       → asset_tracker: update hostname + ip

    Mỗi thiết bị → 1 event "new_asset" → 1 alert "new_device" severity=medium
    """
    print("  [VIOLATION-1] Generating new_device events (3 unknown MACs)...")
    gw_mac = GATEWAY["mac"]
    gw_ip  = GATEWAY["ip"]

    for dev in NEW_DEVICES:
        mac = dev["mac"]
        ip  = dev["ip"]
        xid = random.randint(1, 0xFFFFFFFF)
        hn  = dev["hostname"].encode()

        # ARP Probe → first appearance triggers "new_asset"
        add_frame(make_arp_packet(op=1, sender_mac=mac, sender_ip="0.0.0.0",
                                  target_mac=ZERO_MAC, target_ip=ip), "arp")

        # ARP Request to gateway
        add_frame(make_arp_packet(op=1, sender_mac=mac, sender_ip=ip,
                                  target_mac=ZERO_MAC, target_ip=gw_ip), "arp")

        # Gratuitous ARP (announce presence)
        add_frame(make_arp_packet(op=2, sender_mac=mac, sender_ip=ip,
                                  target_mac=BCAST_MAC, target_ip=ip), "arp")

        # DHCP Discover → process_dhcp() with hostname
        opts = build_dhcp_options(
            (53, bytes([1])),        # DISCOVER
            (12, hn),                # hostname
            (55, dev["opt55"]),      # PRL (OS fingerprint)
        )
        dhcp = build_dhcp_payload(op=1, xid=xid, client_mac=mac, options=opts)
        udp  = build_udp(DHCP_CLI_PORT, DHCP_SRV_PORT, dhcp)
        ipv4 = build_ipv4("0.0.0.0", "255.255.255.255", IP_PROTO_UDP, udp)
        eth  = build_eth(mac, BCAST_MAC, ETHERTYPE_IPV4, ipv4)
        add_frame(eth, "dhcp")

        # DHCP Request
        opts = build_dhcp_options(
            (53, bytes([3])),        # REQUEST
            (50, ip_bytes(ip)),      # Requested IP
            (12, hn),
            (55, dev["opt55"]),
        )
        dhcp = build_dhcp_payload(op=1, xid=xid, client_mac=mac, options=opts)
        udp  = build_udp(DHCP_CLI_PORT, DHCP_SRV_PORT, dhcp)
        ipv4 = build_ipv4("0.0.0.0", "255.255.255.255", IP_PROTO_UDP, udp)
        eth  = build_eth(mac, BCAST_MAC, ETHERTYPE_IPV4, ipv4)
        add_frame(eth, "dhcp")

        # DHCP ACK (server confirms IP)
        opts = build_dhcp_options(
            (53, bytes([5])),                    # ACK
            (1,  ip_bytes("255.255.255.0")),
            (3,  ip_bytes(gw_ip)),
            (51, struct.pack("!I", 86400)),
            (12, hn),
        )
        dhcp = build_dhcp_payload(op=2, xid=xid, client_mac=mac,
                                   yiaddr=ip, siaddr=gw_ip, options=opts)
        udp  = build_udp(DHCP_SRV_PORT, DHCP_CLI_PORT, dhcp)
        ipv4 = build_ipv4(gw_ip, "255.255.255.255", IP_PROTO_UDP, udp)
        eth  = build_eth(gw_mac, mac_bytes(mac), ETHERTYPE_IPV4, ipv4)
        add_frame(eth, "dhcp")


# ─────────────────────────────────────────────────────────────────────────────
# VIOLATION 2: rule_arp_spoofing
# Trigger: IP 192.168.1.254 được claim bởi >= ARP_SPOOF_MAC_THRESHOLD (2) MACs
#          trong cửa sổ ARP_SPOOF_WINDOW_SEC (60s)
# Rule: RuleArpSpoofing.evaluate() theo dõi window_[ip] deque of {ts, mac}
# ─────────────────────────────────────────────────────────────────────────────
def gen_violation_arp_spoofing():
    """
    ARP Spoofing attack simulation:
    - MAC hợp lệ (SPOOF_LEGIT)    claim SPOOF_IP bằng ARP reply (bình thường)
    - MAC kẻ tấn công (SPOOF_ATTACKER) cũng claim SPOOF_IP bằng gratuitous ARP

    Cả 2 gói tin cùng xuất hiện trong 1 PCAP → replay xảy ra trong cùng 1 giây
    → window_ thấy 2 MAC distinct cho cùng IP → sinh alert arp_spoofing severity=high
    """
    print(f"  [VIOLATION-2] Generating ARP spoofing on IP {SPOOF_IP}...")

    # Legitimate host announces itself first
    add_frame(make_arp_packet(
        op=2, sender_mac=SPOOF_LEGIT, sender_ip=SPOOF_IP,
        target_mac=BCAST_MAC, target_ip=SPOOF_IP
    ), "arp")

    # Attacker sends gratuitous ARP claiming same IP → conflict!
    add_frame(make_arp_packet(
        op=2, sender_mac=SPOOF_ATTACKER, sender_ip=SPOOF_IP,
        target_mac=BCAST_MAC, target_ip=SPOOF_IP
    ), "arp")

    # Attacker also responds to ARP requests for that IP
    add_frame(make_arp_packet(
        op=2, sender_mac=SPOOF_ATTACKER, sender_ip=SPOOF_IP,
        target_mac=mac_bytes(GATEWAY["mac"]), target_ip=GATEWAY["ip"],
        dst_eth=mac_bytes(GATEWAY["mac"])
    ), "arp")

    # Legitimate host repeats announcement (trying to reclaim IP)
    add_frame(make_arp_packet(
        op=2, sender_mac=SPOOF_LEGIT, sender_ip=SPOOF_IP,
        target_mac=BCAST_MAC, target_ip=SPOOF_IP
    ), "arp")

    # Additional ARP requests from other devices caught in the confusion
    add_frame(make_arp_packet(
        op=1, sender_mac=GATEWAY["mac"], sender_ip=GATEWAY["ip"],
        target_mac=ZERO_MAC, target_ip=SPOOF_IP
    ), "arp")


# ─────────────────────────────────────────────────────────────────────────────
# VIOLATION 3: rule_watchlist_match
# Trigger: asset MAC/IP khớp với entry trong bảng watchlist
# Prerequisite: phải chạy seed_watchlist.sql trước!
# Rule: RuleWatchlist.evaluate() query "SELECT FROM watchlist WHERE mac=:mac OR ip=:ip"
# ─────────────────────────────────────────────────────────────────────────────
def gen_violation_watchlist():
    """
    Thiết bị trong watchlist xuất hiện:
    - Gửi ARP announce (gratuitous) → asset_tracker: upsert + event
    - → RuleWatchlist: SELECT khớp → sinh alert watchlist_match severity=high
    - Gửi DHCP Discover (với hostname) để enrichment thêm thông tin
    - Gửi mDNS announcement
    """
    print(f"  [VIOLATION-3] Generating watchlist match (MAC={WATCHLIST_MAC})...")
    gw_mac = GATEWAY["mac"]
    gw_ip  = GATEWAY["ip"]
    mac    = WATCHLIST_MAC
    ip     = WATCHLIST_IP
    xid    = random.randint(1, 0xFFFFFFFF)

    # ARP probe → first thing on network
    add_frame(make_arp_packet(op=1, sender_mac=mac, sender_ip="0.0.0.0",
                              target_mac=ZERO_MAC, target_ip=ip), "arp")

    # Gratuitous ARP → asset_tracker: upsert, event "new_asset" hoặc "arp_announce"
    # → RuleWatchlist.evaluate() fired → alert "watchlist_match"
    add_frame(make_arp_packet(op=2, sender_mac=mac, sender_ip=ip,
                              target_mac=BCAST_MAC, target_ip=ip), "arp")

    # ARP Request to gateway
    add_frame(make_arp_packet(op=1, sender_mac=mac, sender_ip=ip,
                              target_mac=ZERO_MAC, target_ip=gw_ip), "arp")

    # DHCP Discover (mang hostname để enrichment có thêm tín hiệu)
    hostname = b"suspicious-device"
    opts = build_dhcp_options(
        (53, bytes([1])),                        # DISCOVER
        (12, hostname),                          # hostname
        (55, bytes([1, 15, 3, 6, 44, 46, 47])), # Windows-like PRL
    )
    dhcp = build_dhcp_payload(op=1, xid=xid, client_mac=mac, options=opts)
    udp  = build_udp(DHCP_CLI_PORT, DHCP_SRV_PORT, dhcp)
    ipv4 = build_ipv4("0.0.0.0", "255.255.255.255", IP_PROTO_UDP, udp)
    eth  = build_eth(mac, BCAST_MAC, ETHERTYPE_IPV4, ipv4)
    add_frame(eth, "dhcp")

    # DHCP ACK
    opts = build_dhcp_options(
        (53, bytes([5])),
        (1,  ip_bytes("255.255.255.0")),
        (3,  ip_bytes(gw_ip)),
        (51, struct.pack("!I", 86400)),
        (12, hostname),
    )
    dhcp = build_dhcp_payload(op=2, xid=xid, client_mac=mac,
                               yiaddr=ip, siaddr=gw_ip, options=opts)
    udp  = build_udp(DHCP_SRV_PORT, DHCP_CLI_PORT, dhcp)
    ipv4 = build_ipv4(gw_ip, "255.255.255.255", IP_PROTO_UDP, udp)
    eth  = build_eth(gw_mac, mac_bytes(mac), ETHERTYPE_IPV4, ipv4)
    add_frame(eth, "dhcp")

    # mDNS SSDP announce — thêm tín hiệu cho os_fingerprint
    ssdp_body = (
        "NOTIFY * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "CACHE-CONTROL: max-age=300\r\n"
        f"LOCATION: http://{ip}:8080/device.xml\r\n"
        "NT: urn:schemas-upnp-org:device:Basic:1\r\n"
        "NTS: ssdp:alive\r\n"
        "SERVER: Linux/4.19 UPnP/1.0 SuspiciousDevice/1.0\r\n"
        f"USN: uuid:suspicious-001::urn:schemas-upnp-org:device:Basic:1\r\n"
        "\r\n"
    ).encode()
    sport = random.randint(32768, 60000)
    udp   = build_udp(sport, SSDP_PORT, ssdp_body)
    ipv4  = build_ipv4(ip, SSDP_MULTICAST, IP_PROTO_UDP, udp, ttl=4)
    eth   = build_eth(mac, SSD_MAC_bytes(), ETHERTYPE_IPV4, ipv4)
    add_frame(eth, "ssdp")

def SSD_MAC_bytes():
    return bytes.fromhex("01005e7ffffa")


# ─────────────────────────────────────────────────────────────────────────────
# BONUS: Một số gói bình thường để context không trống
# ─────────────────────────────────────────────────────────────────────────────
def gen_normal_context():
    """Vài gói ARP bình thường để DB có context."""
    print("  [NORMAL] Adding context ARP packets...")
    normal_mac = "DC:21:48:AA:BB:01"
    normal_ip  = "192.168.1.10"

    # Gateway ARP request
    add_frame(make_arp_packet(op=1, sender_mac=GATEWAY["mac"],
                              sender_ip=GATEWAY["ip"],
                              target_mac=ZERO_MAC, target_ip=normal_ip), "arp")
    add_frame(make_arp_packet(op=2, sender_mac=normal_mac,
                              sender_ip=normal_ip,
                              target_mac=mac_bytes(GATEWAY["mac"]),
                              target_ip=GATEWAY["ip"],
                              dst_eth=mac_bytes(GATEWAY["mac"])), "arp")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    out_dir  = os.path.join(project_dir, "samples")
    out_file = os.path.join(out_dir, "violation.pcap")
    os.makedirs(out_dir, exist_ok=True)

    print("=== Violation PCAP Generator ===")
    print("Triggers: new_device | arp_spoofing | watchlist_match")
    print()
    print("IMPORTANT: Run seed_watchlist.sql BEFORE replaying this PCAP!")
    print(f"  psql -U pnads -d pnads -f scripts/seed_watchlist.sql")
    print()

    t_start = time.perf_counter()

    gen_normal_context()
    gen_violation_new_device()
    gen_violation_arp_spoofing()
    gen_violation_watchlist()

    t_gen = time.perf_counter() - t_start

    print(f"\nTotal packets : {len(packets):,}")
    print(f"Output        : {out_file}")
    print(f"Writing PCAP...")

    t_write = time.perf_counter()
    wrpcap(out_file, packets)
    t_write = time.perf_counter() - t_write

    fsize_kb = os.path.getsize(out_file) / 1024

    print(f"\n[Done]")
    print(f"  Packets   : {len(packets)}")
    print(f"  File size : {fsize_kb:.1f} KB")
    print(f"  Gen time  : {t_gen*1000:.0f}ms")
    print()
    print("  Breakdown:")
    for proto, cnt in sorted(pkt_counts.items(), key=lambda x: -x[1]):
        print(f"    {proto:<10} {cnt:>4} pkts")
    print()
    print("  Expected alerts after replay:")
    print("    [new_device]      3 alerts — MAC: BA:D0:CA:FE:00:0{1,2,3}")
    print(f"   [arp_spoofing]   1+ alerts — IP: {SPOOF_IP}")
    print(f"   [watchlist_match] 1+ alerts — MAC: {WATCHLIST_MAC}")
    print()
    print("  Upload via dashboard or API:")
    print("    curl -X POST http://localhost:8080/api/pcap/upload \\")
    print("         --data-binary @samples/violation.pcap \\")
    print("         -H 'Content-Type: application/octet-stream' \\")
    print("         -G -d 'filename=violation.pcap'")

if __name__ == "__main__":
    main()

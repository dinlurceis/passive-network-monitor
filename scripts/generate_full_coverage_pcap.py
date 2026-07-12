"""
generate_full_coverage_pcap.py
──────────────────────────────────────────────────────────────────
Tạo file PCAP test bao phủ tất cả parsers trong hệ thống.

Gói tin được build TỪ TẦNG THẤP NHẤT lên, giống hệt cách C++ parser bóc tách:
  Layer 2: Ethernet II  (ethernet_parser.hpp)
           └── EtherType 0x0806 → ARP payload          (arp_parser.hpp)
           └── EtherType 0x0800 → IPv4 header           (ipv4_parser.hpp)
                └── proto 17 (UDP)                       (udp_parser.hpp)
                     ├── dst/src port 67/68 → DHCP       (dhcp_parser.hpp)
                     ├── dst/src port 5353  → mDNS       (mdns_parser.hpp)
                     ├── dst/src port 1900  → SSDP       (ssdp_parser.hpp)
                     └── dst/src port 53    → DNS        (dns_message.hpp)

Không dùng Scapy layer cao (BOOTP, DHCP class) để tránh ambiguity.
Toàn bộ gói tin được build bằng struct.pack / bytes thô.

Yêu cầu: pip install scapy
Chạy:    python scripts/generate_full_coverage_pcap.py
Output:  samples/pcaplist/full_coverage.pcap
Target:  ~1,000,000 gói tin
"""

import struct
import socket
import random
import os
import sys
import time

try:
    from scapy.utils import wrpcap
    from scapy.packet import Raw
    from scapy.layers.l2 import Ether
except ImportError:
    print("Thiếu scapy: pip install scapy")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Constants — khớp với các header file C++ (namespace pnads)
# ─────────────────────────────────────────────────────────────────────────────
ETHERTYPE_ARP  = 0x0806   # ethernet_parser.hpp: ETHERTYPE_ARP
ETHERTYPE_IPV4 = 0x0800   # ethernet_parser.hpp: ETHERTYPE_IPV4
IP_PROTO_UDP   = 17       # ipv4_parser.hpp: IP_PROTO_UDP
DHCP_MAGIC     = 0x63825363  # dhcp_parser.hpp: DHCP_MAGIC_COOKIE
DHCP_SRV_PORT  = 67       # dhcp_parser.hpp: DHCP_SERVER_PORT
DHCP_CLI_PORT  = 68       # dhcp_parser.hpp: DHCP_CLIENT_PORT
MDNS_PORT      = 5353     # mdns_parser.hpp: MDNS_PORT
NUM_ROUNDS     = 50       # ssdp_parser.hpp: SSDP_PORT
SSDP_PORT      = 1900     # ssdp_parser.hpp: SSDP_PORT
DNS_PORT       = 53

MDNS_MULTICAST = "224.0.0.251"
SSDP_MULTICAST = "239.255.255.250"
# Multicast MAC: 01:00:5e:xx:xx:xx
MDNS_MAC       = bytes.fromhex("01005e0000fb")   # 224.0.0.251
SSDP_MAC       = bytes.fromhex("01005e7ffffa")   # 239.255.255.250
BCAST_MAC      = b"\xff\xff\xff\xff\xff\xff"
ZERO_MAC       = b"\x00\x00\x00\x00\x00\x00"

# ─────────────────────────────────────────────────────────────────────────────
# Device profiles — giống real network
# ─────────────────────────────────────────────────────────────────────────────
DEVICES = [
    {"name": "Windows11-PC",       "mac": "DC:21:48:AA:BB:01", "ip": "192.168.1.10",
     "hostname": "DESKTOP-WIN11",  "os": "Windows",
     "opt55": bytes([1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 43, 252])},
    {"name": "MacbookPro-M3",      "mac": "3C:22:FB:CC:DD:02", "ip": "192.168.1.11",
     "hostname": "MacBook-Pro-M3", "os": "macOS",
     "opt55": bytes([1, 121, 3, 6, 15, 119, 252, 95, 44, 46])},
    {"name": "iPhone16",           "mac": "A8:5C:2C:EE:FF:03", "ip": "192.168.1.12",
     "hostname": "iPhone-16",      "os": "iOS",
     "opt55": bytes([1, 121, 3, 6, 15, 119, 252])},
    {"name": "SamsungAndroid15",   "mac": "48:DB:50:11:22:04", "ip": "192.168.1.13",
     "hostname": "Samsung-S25",    "os": "Android",
     "opt55": bytes([1, 33, 3, 6, 15, 28, 51, 58, 59])},
    {"name": "UbuntuLinux",        "mac": "52:54:00:55:66:05", "ip": "192.168.1.14",
     "hostname": "ubuntu-server",  "os": "Linux",
     "opt55": bytes([1, 28, 2, 3, 15, 6, 12, 42])},
    {"name": "ChromeOS-Chromebook","mac": "F4:F5:E8:77:88:06", "ip": "192.168.1.15",
     "hostname": "chromebook-home","os": "ChromeOS",
     "opt55": bytes([1, 3, 6, 15, 121, 28])},
    {"name": "IoT-Camera",         "mac": "00:E0:4C:99:AA:07", "ip": "192.168.1.20",
     "hostname": "hikvision-cam",  "os": "IoT/Embedded",
     "opt55": bytes([1, 3, 6])},
    {"name": "SmartTV-Samsung",    "mac": "CC:32:E5:BB:CC:08", "ip": "192.168.1.21",
     "hostname": "Samsung-TV",     "os": "IoT/SmartTV",
     "opt55": bytes([1, 3, 6, 12, 15])},
]
GATEWAY = {"name": "Router", "mac": "00:11:22:33:44:55", "ip": "192.168.1.1"}

# ─────────────────────────────────────────────────────────────────────────────
# Packet accounting
# ─────────────────────────────────────────────────────────────────────────────
packets: list = []
pkt_counts: dict = {}


# ─────────────────────────────────────────────────────────────────────────────
# Layer builders — raw bytes, khớp chính xác với C++ parsers
# ─────────────────────────────────────────────────────────────────────────────

def mac_bytes(mac_str: str) -> bytes:
    return bytes.fromhex(mac_str.replace(":", ""))

def ip_bytes(ip_str: str) -> bytes:
    return socket.inet_aton(ip_str)

def build_eth(src_mac: str, dst_mac_bytes: bytes, ethertype: int, payload: bytes) -> bytes:
    """
    Ethernet II frame — ethernet_parser.cpp parse_ethernet():
      dst(6) + src(6) + ethertype(2) + payload
    Parser: dst_mac@[0..5], src_mac@[6..11], ethertype@[12..13]
    Handles VLAN 0x8100 automatically in C++ parser — no VLAN here for simplicity.
    """
    return dst_mac_bytes + mac_bytes(src_mac) + struct.pack("!H", ethertype) + payload

def build_ipv4(src_ip: str, dst_ip: str, proto: int, payload: bytes, ttl: int = 64) -> bytes:
    """
    IPv4 header — ipv4_parser.cpp parse_ipv4():
      version+ihl(1) + dscp(1) + total_len(2) + id(2) + flags+frag(2)
      + ttl(1) + proto(1) + checksum(2) + src(4) + dst(4)
    Parser reads: proto@[9], src@[12..15], dst@[16..19], ttl@[8]
    payload starts at ihl*4 (=20 for standard header, ihl=5)
    """
    ihl = 5
    vhl = (4 << 4) | ihl
    total = 20 + len(payload)
    pkt_id = random.randint(0, 0xFFFF)
    hdr = struct.pack("!BBHHHBBH4s4s",
        vhl, 0, total, pkt_id,
        0x4000,    # DF=1, no fragment
        ttl, proto,
        0,         # checksum=0 (parser does not verify)
        ip_bytes(src_ip),
        ip_bytes(dst_ip),
    )
    return hdr + payload

def build_udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    """
    UDP header — udp_parser.cpp parse_udp():
      src_port(2) + dst_port(2) + length(2) + checksum(2) + payload
    Parser reads: src_port@[0..1], dst_port@[2..3]
    payload starts at offset 8
    """
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


# ─────────────────────────────────────────────────────────────────────────────
# ARP payload builder — arp_parser.cpp parse_arp()
# ─────────────────────────────────────────────────────────────────────────────
def build_arp_payload(op: int, sender_mac: str, sender_ip: str,
                      target_mac: bytes, target_ip: str) -> bytes:
    """
    ARP packet — arp_parser.cpp:
      htype(2) + ptype(2) + hlen(1) + plen(1) + opcode(2)
      + sender_mac(6) + sender_ip(4) + target_mac(6) + target_ip(4)
    Parser reads: opcode@[6..7], sender_mac@[8..13], sender_ip@[14..17]
                  target_mac@[18..23], target_ip@[24..27]
    is_gratuitous(): is_reply() && sender_ip == target_ip
    is_probe():      is_request() && sender_ip == "0.0.0.0"
    """
    return struct.pack("!HHBBH",
        1,       # htype: Ethernet
        0x0800,  # ptype: IPv4
        6,       # hlen: MAC length
        4,       # plen: IPv4 length
        op       # opcode: 1=REQUEST, 2=REPLY
    ) + mac_bytes(sender_mac) + ip_bytes(sender_ip) + target_mac + ip_bytes(target_ip)

def make_arp_packet(op: int, sender_mac: str, sender_ip: str,
                    target_mac: bytes, target_ip: str,
                    dst_eth: bytes = None) -> bytes:
    if dst_eth is None:
        dst_eth = BCAST_MAC
    arp_payload = build_arp_payload(op, sender_mac, sender_ip, target_mac, target_ip)
    return build_eth(sender_mac, dst_eth, ETHERTYPE_ARP, arp_payload)

def add_frame(raw_bytes: bytes, proto: str = "other"):
    """Wrap raw bytes in Scapy Ether for wrpcap compatibility."""
    packets.append(Ether(raw_bytes))
    pkt_counts[proto] = pkt_counts.get(proto, 0) + 1


# ─────────────────────────────────────────────────────────────────────────────
# 1. ARP flows — arp_parser.cpp
# ─────────────────────────────────────────────────────────────────────────────
def gen_arp(shuffle: bool = False):
    """
    Generates all ARP variants:
    - Probe    (op=1, sender_ip=0.0.0.0)  → is_probe()=true
    - Request  (op=1, normal)             → is_request()=true
    - Reply    (op=2, normal)             → is_reply()=true
    - Gratuitous (op=2, sender_ip==target_ip) → is_gratuitous()=true
    - IP change (same MAC, different IP)
    """
    clients = DEVICES[:]
    if shuffle:
        random.shuffle(clients)

    # ARP Probe: sender_ip = 0.0.0.0 → is_probe() == true
    for dev in clients[:4]:
        add_frame(make_arp_packet(
            op=1, sender_mac=dev["mac"], sender_ip="0.0.0.0",
            target_mac=ZERO_MAC, target_ip=dev["ip"]
        ), "arp")

    # ARP Request + Reply pairs
    all_hosts = clients + [GATEWAY]
    for _ in range(55):
        src = random.choice(clients)
        dst = random.choice(all_hosts)
        if src is dst:
            continue
        # ARP Request — op=1
        add_frame(make_arp_packet(
            op=1, sender_mac=src["mac"], sender_ip=src["ip"],
            target_mac=ZERO_MAC, target_ip=dst["ip"]
        ), "arp")
        # ARP Reply — op=2
        if random.random() < 0.80:
            add_frame(make_arp_packet(
                op=2, sender_mac=dst["mac"], sender_ip=dst["ip"],
                target_mac=mac_bytes(src["mac"]), target_ip=src["ip"],
                dst_eth=mac_bytes(src["mac"])
            ), "arp")

    # Gratuitous ARP (ARP Announce) — op=2, sender_ip == target_ip
    for dev in clients:
        add_frame(make_arp_packet(
            op=2, sender_mac=dev["mac"], sender_ip=dev["ip"],
            target_mac=BCAST_MAC, target_ip=dev["ip"]
        ), "arp")

    # IP change: same MAC, new IP → asset_tracker logs "ip_change"
    old_dev = clients[0]
    # Dùng 1 IP phụ duy nhất ứng với từng MAC để không bị trùng (tránh tạo ARP Spoofing ảo)
    new_ip = old_dev["ip"].replace("192.168.1", "192.168.2")
    add_frame(make_arp_packet(
        op=2, sender_mac=old_dev["mac"], sender_ip=new_ip,
        target_mac=BCAST_MAC, target_ip=new_ip
    ), "arp")


# ─────────────────────────────────────────────────────────────────────────────
# 2. DHCP flows — dhcp_parser.cpp
#    Chuỗi: Discover → Offer → Request → ACK
#    Stack: Ethernet → IPv4 → UDP(67/68) → DHCP payload
# ─────────────────────────────────────────────────────────────────────────────
def build_dhcp_options(*option_list) -> bytes:
    """
    DHCP options TLV — dhcp_parser.cpp options parsing:
      byte0: option code
      byte1: length  (nếu code != 0 và code != 255)
      bytes 2..2+length-1: value
      code 255 = END, code 0 = PAD
    """
    result = b""
    for opt in option_list:
        code, value = opt[0], opt[1]
        result += bytes([code, len(value)]) + value
    result += bytes([255])  # END option
    return result

def build_dhcp_payload(op: int, xid: int, client_mac: str,
                       ciaddr: str = "0.0.0.0",
                       yiaddr: str = "0.0.0.0",
                       siaddr: str = "0.0.0.0",
                       options: bytes = b"") -> bytes:
    """
    DHCP packet body — dhcp_parser.cpp parse_dhcp():
    Exact offset layout (must match parser comments):
      [0]      op      (1=BOOTREQUEST, 2=BOOTREPLY)
      [1]      htype   (1=Ethernet)
      [2]      hlen    (6=MAC)
      [3]      hops    (0)
      [4..7]   xid
      [8..9]   secs
      [10..11] flags
      [12..15] ciaddr  → parser reads client_ip
      [16..19] yiaddr  → parser reads your_ip
      [20..23] siaddr  → parser reads server_ip
      [24..27] giaddr
      [28..43] chaddr  → parser reads client_mac from [28..33]
      [44..107] sname  (64 bytes)
      [108..235] file  (128 bytes)
      [236..239] magic cookie = 0x63825363
      [240+]  options (TLV)
    """
    mac_b  = bytes.fromhex(client_mac.replace(":", ""))
    chaddr = mac_b + b"\x00" * 10   # 16 bytes: MAC(6) + padding(10)

    header = struct.pack("!BBBB I HH 4s4s4s4s",
        op, 1, 6, 0,           # op, htype, hlen, hops
        xid,                   # transaction ID
        0, 0,                  # secs, flags
        ip_bytes(ciaddr),
        ip_bytes(yiaddr),
        ip_bytes(siaddr),
        ip_bytes("0.0.0.0"),   # giaddr
    )
    sname = b"\x00" * 64
    file_ = b"\x00" * 128
    magic = struct.pack("!I", DHCP_MAGIC)
    return header + chaddr + sname + file_ + magic + options

def gen_dhcp():
    """
    DHCP 4-way handshake per device:
    DISCOVER (client→broadcast, op=1, msg_type=1)
    OFFER    (server→client,    op=2, msg_type=2, yiaddr=client_ip)
    REQUEST  (client→broadcast, op=1, msg_type=3, opt50=requested_ip)
    ACK      (server→client,    op=2, msg_type=5, yiaddr=client_ip)
    
    asset_tracker.process_dhcp():
      DISCOVER → event "dhcp_discover", hostname from opt12
      REQUEST  → event "dhcp_request"
      ACK      → event "dhcp_ack", update asset.ip = your_ip
    """
    gw_mac = GATEWAY["mac"]
    gw_ip  = GATEWAY["ip"]

    for dev in DEVICES:
        xid       = random.randint(1, 0xFFFFFFFF)
        c_mac     = dev["mac"]
        c_ip      = dev["ip"]
        hostname_b = dev["hostname"].encode()

        # ── DISCOVER (client → broadcast) ──────────────────────────────────
        # dhcp_parser: msg_type=DISCOVER(1), reads hostname from opt12, opt55 PRL
        dhcp_opts = build_dhcp_options(
            (53, bytes([1])),          # Option 53: Message Type = DISCOVER
            (12, hostname_b),          # Option 12: Hostname
            (55, dev["opt55"]),        # Option 55: Parameter Request List
        )
        dhcp_pkt = build_dhcp_payload(op=1, xid=xid, client_mac=c_mac, options=dhcp_opts)
        udp  = build_udp(DHCP_CLI_PORT, DHCP_SRV_PORT, dhcp_pkt)
        ipv4 = build_ipv4("0.0.0.0", "255.255.255.255", IP_PROTO_UDP, udp)
        eth  = build_eth(c_mac, BCAST_MAC, ETHERTYPE_IPV4, ipv4)
        add_frame(eth, "dhcp")  # ← tagged "dhcp"

        # ── OFFER (server → client) ────────────────────────────────────────
        # dhcp_parser: msg_type=OFFER(2), is_from_server=true, yiaddr=c_ip
        dhcp_opts = build_dhcp_options(
            (53, bytes([2])),                    # Message Type: OFFER
            (1,  ip_bytes("255.255.255.0")),     # Subnet Mask
            (3,  ip_bytes(gw_ip)),               # Router
            (6,  ip_bytes(gw_ip)),               # DNS Server
            (51, struct.pack("!I", 86400)),      # Lease Time: 24h
            (54, ip_bytes(gw_ip)),               # Server Identifier
        )
        dhcp_pkt = build_dhcp_payload(
            op=2, xid=xid, client_mac=c_mac,
            yiaddr=c_ip, siaddr=gw_ip, options=dhcp_opts
        )
        udp  = build_udp(DHCP_SRV_PORT, DHCP_CLI_PORT, dhcp_pkt)
        ipv4 = build_ipv4(gw_ip, "255.255.255.255", IP_PROTO_UDP, udp)
        eth  = build_eth(gw_mac, mac_bytes(c_mac), ETHERTYPE_IPV4, ipv4)
        add_frame(eth, "dhcp")

        # ── REQUEST (client → broadcast) ───────────────────────────────────
        # dhcp_parser: msg_type=REQUEST(3), opt50=requested_ip
        dhcp_opts = build_dhcp_options(
            (53, bytes([3])),          # Message Type: REQUEST
            (50, ip_bytes(c_ip)),      # Option 50: Requested IP Address
            (12, hostname_b),          # Hostname
            (55, dev["opt55"]),        # PRL
            (54, ip_bytes(gw_ip)),     # Server Identifier
        )
        dhcp_pkt = build_dhcp_payload(op=1, xid=xid, client_mac=c_mac, options=dhcp_opts)
        udp  = build_udp(DHCP_CLI_PORT, DHCP_SRV_PORT, dhcp_pkt)
        ipv4 = build_ipv4("0.0.0.0", "255.255.255.255", IP_PROTO_UDP, udp)
        eth  = build_eth(c_mac, BCAST_MAC, ETHERTYPE_IPV4, ipv4)
        add_frame(eth, "dhcp")

        # ── ACK (server → client) ──────────────────────────────────────────
        # dhcp_parser: msg_type=ACK(5), yiaddr=c_ip → asset_tracker updates ip
        dhcp_opts = build_dhcp_options(
            (53, bytes([5])),                    # Message Type: ACK
            (1,  ip_bytes("255.255.255.0")),     # Subnet Mask
            (3,  ip_bytes(gw_ip)),               # Router
            (6,  ip_bytes(gw_ip)),               # DNS Server
            (51, struct.pack("!I", 86400)),      # Lease Time
            (54, ip_bytes(gw_ip)),               # Server Identifier
            (12, hostname_b),                    # Hostname confirmed
        )
        dhcp_pkt = build_dhcp_payload(
            op=2, xid=xid, client_mac=c_mac,
            yiaddr=c_ip, siaddr=gw_ip, options=dhcp_opts
        )
        udp  = build_udp(DHCP_SRV_PORT, DHCP_CLI_PORT, dhcp_pkt)
        ipv4 = build_ipv4(gw_ip, "255.255.255.255", IP_PROTO_UDP, udp)
        eth  = build_eth(gw_mac, mac_bytes(c_mac), ETHERTYPE_IPV4, ipv4)
        add_frame(eth, "dhcp")


# ─────────────────────────────────────────────────────────────────────────────
# 3. mDNS — mdns_parser.cpp
#    Stack: Ethernet → IPv4(dst=224.0.0.251) → UDP(5353) → DNS message
#    mdns_parser.cpp parse_mdns() wraps parse_dns_message()
# ─────────────────────────────────────────────────────────────────────────────
def encode_dns_name(name: str) -> bytes:
    """
    DNS name encoding (RFC 1035) — dns_message.cpp parse_dns_name():
    Each label prefixed by its length byte, terminated by 0x00.
    Compression pointers (0xC0xx) not generated here (not needed for queries).
    """
    result = b""
    for label in name.rstrip(".").split("."):
        enc = label.encode()
        result += bytes([len(enc)]) + enc
    result += b"\x00"
    return result

def build_dns_a_record(name: str, ip: str) -> bytes:
    """
    DNS A record — dns_message.cpp:
      name + type(2) + class(2) + ttl(4) + rdlength(2) + rdata(4)
    type=A(1), class=IN+cache-flush (0x8001 for mDNS)
    """
    name_enc = encode_dns_name(name)
    rdata    = ip_bytes(ip)
    return name_enc + struct.pack("!HHIH", 1, 0x8001, 4500, len(rdata)) + rdata

def build_dns_ptr_record(service: str, instance: str) -> bytes:
    """DNS PTR record: service → instance name."""
    service_enc  = encode_dns_name(service)
    instance_enc = encode_dns_name(instance)
    return service_enc + struct.pack("!HHIH", 12, 0x0001, 4500, len(instance_enc)) + instance_enc

def build_dns_txt_record(name: str, txt: bytes) -> bytes:
    """DNS TXT record: name → text data."""
    name_enc = encode_dns_name(name)
    return name_enc + struct.pack("!HHIH", 16, 0x8001, 4500, len(txt)) + txt

def build_dns_message(qr: int, questions: list = None, answers: list = None) -> bytes:
    """
    DNS message header — dns_message.cpp parse_dns_message():
      id(2) + flags(2) + qdcount(2) + ancount(2) + nscount(2) + arcount(2)
    qr=1 → response (mDNS announcements), AA bit set
    """
    flags   = (qr << 15) | (1 << 10)  # qr + AA bit
    qdcount = len(questions) if questions else 0
    ancount = len(answers)  if answers  else 0
    header  = struct.pack("!HHHHHH", 0, flags, qdcount, ancount, 0, 0)
    q_bytes = b"".join(questions) if questions else b""
    a_bytes = b"".join(answers)   if answers   else b""
    return header + q_bytes + a_bytes

def gen_mdns():
    """
    mDNS announcements — mdns_parser.cpp parse_mdns():
    Extracts: hostname (from A records ending in .local),
              service_type (from PTR records),
              model_hint (from TXT records: model=, md=, fn=)
    """
    mdns_services = [
        # (device, service_type, txt_bytes)
        (DEVICES[1], "_airplay._tcp",         b"\x14model=MacBookPro21,1\x0efn=MacBook-Pro"),
        (DEVICES[2], "_airdrop._tcp",         b"\x0cmodel=iPhone\x0cfn=iPhone-16"),
        (DEVICES[3], "_googlecast._tcp",      b"\x13md=Chromecast Ultra\x0efn=Living-Room"),
        (DEVICES[6], "_matter._tcp",          b"\x12model=DS-2CD2T47G2\x0cfn=Hikvision"),
        (DEVICES[4], "_ipp._tcp",             b"\x0fmodel=HP M479dw\x0afn=Printer"),
        (DEVICES[7], "_spotify-connect._tcp", b"\x0emodel=Smart-TV\x0dfn=Samsung-TV"),
    ]

    for dev, service, txt_b in mdns_services:
        local_name = f"{dev['hostname']}.local"
        instance   = f"{dev['hostname']}.{service}.local"

        # mDNS A record: hostname.local → IP
        # mdns_parser: type A + ends in ".local" → sets rec.hostname
        a_record = build_dns_a_record(local_name, dev["ip"])
        dns_msg  = build_dns_message(qr=1, answers=[a_record])
        udp  = build_udp(MDNS_PORT, MDNS_PORT, dns_msg)
        ipv4 = build_ipv4(dev["ip"], MDNS_MULTICAST, IP_PROTO_UDP, udp, ttl=255)
        eth  = build_eth(dev["mac"], MDNS_MAC, ETHERTYPE_IPV4, ipv4)
        add_frame(eth, "mdns")  # ← tagged "mdns"

        # mDNS PTR + TXT records
        # mdns_parser: PTR → sets rec.service_type, TXT → model_hint
        ptr_record = build_dns_ptr_record(f"{service}.local", instance)
        txt_record = build_dns_txt_record(instance, txt_b)
        dns_msg    = build_dns_message(qr=1, answers=[ptr_record, txt_record])
        udp  = build_udp(MDNS_PORT, MDNS_PORT, dns_msg)
        ipv4 = build_ipv4(dev["ip"], MDNS_MULTICAST, IP_PROTO_UDP, udp, ttl=255)
        eth  = build_eth(dev["mac"], MDNS_MAC, ETHERTYPE_IPV4, ipv4)
        add_frame(eth, "mdns")


# ─────────────────────────────────────────────────────────────────────────────
# 4. SSDP / UPnP — ssdp_parser.cpp
#    Stack: Ethernet → IPv4(dst=239.255.255.250) → UDP(1900) → HTTP-like text
#    ssdp_parser.cpp: BinaryReader::read_line() → parses headers key: value
# ─────────────────────────────────────────────────────────────────────────────
def gen_ssdp():
    """
    SSDP NOTIFY packets — ssdp_parser.cpp parse_ssdp():
    Reads first line for method ("NOTIFY" | "M-SEARCH"),
    then headers until empty line (\r\n\r\n).
    Parses: SERVER, LOCATION, NT, NTS, USN headers.
    """
    ssdp_entries = [
        (DEVICES[7], "Linux/5.15 UPnP/1.0 Samsung-SmartTV/T-HKMFDEUC-2102.2",
                     "urn:schemas-upnp-org:device:MediaRenderer:1",
                     "uuid:Samsung-SmartTV-2024::urn:schemas-upnp-org:device:MediaRenderer:1"),
        (GATEWAY,    "Asus/RT-AX88U UPnP/1.0 MiniUPnPd/2.3.7",
                     "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                     "uuid:ASUS-Router-2024::urn:schemas-upnp-org:device:InternetGatewayDevice:1"),
        (DEVICES[6], "Linux/3.10 UPnP/1.0 Hikvision-IPC/V5.7.6",
                     "urn:schemas-upnp-org:device:Basic:1",
                     "uuid:Hikvision-DS2CD-001::urn:schemas-upnp-org:device:Basic:1"),
        (DEVICES[0], "Microsoft-Windows/10.0 UPnP/1.0 Windows-Media-Player/12.0",
                     "urn:schemas-upnp-org:device:MediaServer:1",
                     "uuid:WMP-PC-001::urn:schemas-upnp-org:device:MediaServer:1"),
    ]

    for dev, server, nt, usn in ssdp_entries:
        location = f"http://{dev['ip']}:1900/device.xml"
        # ssdp_parser.cpp reads each \r\n-terminated line
        body = (
            f"NOTIFY * HTTP/1.1\r\n"
            f"HOST: 239.255.255.250:1900\r\n"
            f"CACHE-CONTROL: max-age=1800\r\n"
            f"LOCATION: {location}\r\n"
            f"NT: {nt}\r\n"
            f"NTS: ssdp:alive\r\n"
            f"SERVER: {server}\r\n"
            f"USN: {usn}\r\n"
            f"\r\n"
        ).encode()

        sport = random.randint(32768, 60000)
        udp  = build_udp(sport, SSDP_PORT, body)
        ipv4 = build_ipv4(dev["ip"], SSDP_MULTICAST, IP_PROTO_UDP, udp, ttl=4)
        eth  = build_eth(dev["mac"], SSDP_MAC, ETHERTYPE_IPV4, ipv4)
        add_frame(eth, "ssdp")  # ← tagged "ssdp"


# ─────────────────────────────────────────────────────────────────────────────
# 5. DNS — dns_message.cpp
#    Stack: Ethernet → IPv4 → UDP(53) → DNS query/response
#    dns_message.cpp parse_dns_message(): used for both DNS and mDNS
# ─────────────────────────────────────────────────────────────────────────────
def build_dns_query(txid: int, qname: str) -> bytes:
    """
    DNS query — dns_message.cpp:
      header: id(2) + flags(2,RD=1) + qdcount(1) + 0,0,0
      question: qname + qtype(A=1) + qclass(IN=1)
    """
    flags    = 0x0100  # QR=0 (query), RD=1 (recursion desired)
    header   = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    question = encode_dns_name(qname) + struct.pack("!HH", 1, 1)  # A, IN
    return header + question

def build_dns_response(txid: int, qname: str, answer_ip: str) -> bytes:
    """
    DNS response — dns_message.cpp:
      flags: QR=1, RD=1, RA=1
      + question section + A record answer
    """
    flags    = 0x8180  # QR=1, RD=1, RA=1
    a_answer = build_dns_a_record(qname, answer_ip)
    header   = struct.pack("!HHHHHH", txid, flags, 1, 1, 0, 0)
    question = encode_dns_name(qname) + struct.pack("!HH", 1, 1)
    return header + question + a_answer

def gen_dns():
    """
    Passive DNS query/response pairs — asset_tracker.process_dns():
    Captures DNS queries from each device to gateway.
    dns_message: is_response=false for queries, is_response=true for responses.
    """
    queries = [
        ("www.google.com",      DEVICES[0]),
        ("api.apple.com",       DEVICES[1]),
        ("icloud.com",          DEVICES[2]),
        ("play.google.com",     DEVICES[3]),
        ("github.com",          DEVICES[4]),
        ("accounts.google.com", DEVICES[5]),
        ("nvr.hikvision.local", DEVICES[6]),
        ("samsung.com",         DEVICES[7]),
        ("update.windows.com",  DEVICES[0]),
        ("push.apple.com",      DEVICES[2]),
    ]

    gw_mac = GATEWAY["mac"]
    gw_ip  = GATEWAY["ip"]

    for qname, dev in queries:
        txid    = random.randint(1, 0xFFFF)
        sport   = random.randint(32768, 60000)
        fake_ip = f"1.2.3.{random.randint(1, 254)}"

        # DNS Query: client → gateway port 53
        dns_q = build_dns_query(txid, qname)
        udp   = build_udp(sport, DNS_PORT, dns_q)
        ipv4  = build_ipv4(dev["ip"], gw_ip, IP_PROTO_UDP, udp)
        eth   = build_eth(dev["mac"], mac_bytes(gw_mac), ETHERTYPE_IPV4, ipv4)
        add_frame(eth, "dns")  # ← tagged "dns"

        # DNS Response: gateway → client
        dns_r = build_dns_response(txid, qname, fake_ip)
        udp   = build_udp(DNS_PORT, sport, dns_r)
        ipv4  = build_ipv4(gw_ip, dev["ip"], IP_PROTO_UDP, udp)
        eth   = build_eth(gw_mac, mac_bytes(dev["mac"]), ETHERTYPE_IPV4, ipv4)
        add_frame(eth, "dns")


# ─────────────────────────────────────────────────────────────────────────────
# Per-round count:
#   gen_arp:  4 probes + ~55*1.8 pairs + 8 gratuitous + 1 ip_change ≈ 112
#   gen_dhcp: 8 devices * 4 pkts = 32
#   gen_mdns: 6 services * 2 pkts = 12
#   gen_ssdp: 4 entries * 1 pkt  = 4
#   gen_dns:  10 queries * 2 pkts = 20
#   Total per round ≈ 180
#
# Target 1,000,000 → REPEAT = ceil(1_000_000 / 180) ≈ 5556 → use 5600
# ─────────────────────────────────────────────────────────────────────────────
REPEAT = 560   # → ~100,000 packets


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    out_dir  = os.path.join(project_dir, "samples", "pcaplist")
    out_file = os.path.join(out_dir, "full_coverage.pcap")
    os.makedirs(out_dir, exist_ok=True)

    print("=== Full Coverage PCAP Generator (raw layer-by-layer) ===")
    print(f"Pipeline: Ethernet -> IPv4 -> UDP -> [ARP|DHCP|mDNS|SSDP|DNS]")
    print(f"Repeat  : {REPEAT}x (target ~{REPEAT * 180:,} packets)\n")

    t_start = time.perf_counter()

    for i in range(REPEAT):
        if i % 500 == 0:
            pct = i * 100 // REPEAT
            elapsed = time.perf_counter() - t_start
            rate = len(packets) / elapsed if elapsed > 0 else 0
            print(f"  Generating... {pct:3d}% | {len(packets):>10,} packets | {rate:,.0f} pkt/s", end="\r")
        # Round starts with ARP to ensure initial asset discovery
        gen_arp(shuffle=(i % 10 == 0))  # shuffle every 10 rounds for variety
        gen_dhcp()
        gen_mdns()
        gen_ssdp()
        gen_dns()

    t_gen = time.perf_counter() - t_start
    print(f"\n  Generation done in {t_gen:.1f}s")

    print(f"\nTotal packets  : {len(packets):,}")
    print(f"Output         : {out_file}")
    print(f"Writing PCAP...")
    t_write = time.perf_counter()
    wrpcap(out_file, packets)
    t_write = time.perf_counter() - t_write

    fsize_mb = os.path.getsize(out_file) / 1024 / 1024

    print(f"\n[Done]")
    print(f"  Total packets : {len(packets):,}")
    print(f"  File size     : {fsize_mb:.1f} MB")
    print(f"  Gen time      : {t_gen:.1f}s")
    print(f"  Write time    : {t_write:.1f}s")
    print(f"  Gen rate      : {len(packets)/t_gen:,.0f} pkts/s")
    print()
    print("  Packet breakdown (per protocol):")
    for proto, cnt in sorted(pkt_counts.items(), key=lambda x: -x[1]):
        print(f"    {proto:<10} {cnt:>10,} pkts  ({cnt*100//len(packets):2d}%)")
    print()
    print("  Parser coverage:")
    print("    ethernet_parser -- Ethernet II (EtherType ARP=0x0806, IPv4=0x0800)")
    print("    arp_parser      -- Request(op=1), Reply(op=2), Probe(sender_ip=0.0.0.0), Gratuitous")
    print("    ipv4_parser     -- version=4, ihl=5, ttl, proto=17(UDP), src/dst IP")
    print("    udp_parser      -- port demux: 67/68->DHCP, 5353->mDNS, 1900->SSDP, 53->DNS")
    print("    dhcp_parser     -- DISCOVER/OFFER/REQUEST/ACK + opt12/50/53/55")
    print("    mdns_parser     -- A record (.local hostname), PTR (service_type), TXT (model_hint)")
    print("    ssdp_parser     -- NOTIFY: SERVER/LOCATION/NT/NTS/USN headers")
    print("    dns_message     -- Query(QR=0,RD=1) + Response(QR=1,RA=1, A record)")

if __name__ == "__main__":
    main()

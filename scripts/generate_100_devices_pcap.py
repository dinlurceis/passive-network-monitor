import sys
import socket
import csv
import random
import string
import re

try:
    from scapy.all import Ether, IP, UDP, BOOTP, DHCP, ARP, wrpcap
except ImportError:
    print("Vui lòng cài đặt scapy: pip install scapy")
    sys.exit(1)

def load_oui(file_path):
    vendors = []
    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                vendors.append((row[0], row[1]))
    return vendors

def generate_mac(prefix):
    # Prefix "AA:BB:CC" -> append 3 random bytes
    suffix = ":".join([f"{random.randint(0, 255):02x}" for _ in range(3)])
    return f"{prefix}:{suffix}".lower()

def clean_vendor_name(vendor):
    # Lấy từ đầu tiên hoặc tên chính của hãng, bỏ ký tự đặc biệt
    clean = re.sub(r'[^a-zA-Z0-9]', '', vendor.split()[0])
    return clean[:10] if clean else "Device"

def generate_devices(vendors, count=100):
    devices = []
    selected_vendors = random.sample(vendors, count)
    
    ip_base = "192.168.1."
    ip_pool = list(range(10, 250))
    random.shuffle(ip_pool)

    # Vài mẫu OS Option 55 signature
    apple_opt55 = b"\x01\x03\x06\x0f\x77\xfc" # Apple fake
    win_opt55   = b"\x01\x0f\x03\x06\x2c\x2e\x2f" # Windows fake
    linux_opt55 = b"\x01\x1c\x02\x03\x0f\x06\x77\x0c" # Linux fake

    for i, (prefix, vendor_name) in enumerate(selected_vendors):
        mac = generate_mac(prefix)
        ip = f"{ip_base}{ip_pool[i]}"
        
        # Đoán OS dựa trên tên hãng
        v_lower = vendor_name.lower()
        if "apple" in v_lower:
            opt55 = apple_opt55
            os_guess = "Apple"
        elif "microsoft" in v_lower or "cisco" in v_lower:
            opt55 = win_opt55
            os_guess = "Windows"
        else:
            opt55 = linux_opt55
            os_guess = "Linux/IoT"

        # Tạo hostname: Hãng + mã random
        rand_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        hostname = f"{clean_vendor_name(vendor_name)}-{rand_str}"
        
        devices.append({
            "mac": mac,
            "ip": ip,
            "hostname": hostname,
            "vendor": vendor_name,
            "os_guess": os_guess,
            "opt55": opt55
        })
    return devices

def generate_dhcp_flow(device, packets, server_mac, server_ip):
    mac_bytes = bytes.fromhex(device["mac"].replace(":", ""))
    ip_bytes = socket.inet_aton(device["ip"])
    
    # xid random cho mỗi transaction
    xid = random.randint(1, 0xFFFFFFFF)

    # 1. DHCP Discover
    discover = (
        Ether(src=device["mac"], dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=mac_bytes, xid=xid) /
        DHCP(options=[
            (53, b"\x01"), 
            (12, device["hostname"].encode("utf-8")), 
            (55, device["opt55"]), 
            "end"
        ])
    )
    packets.append(discover)

    # 2. DHCP Offer
    offer = (
        Ether(src=server_mac, dst=device["mac"]) /
        IP(src=server_ip, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, yiaddr=device["ip"], siaddr=server_ip, chaddr=mac_bytes, xid=xid) /
        DHCP(options=[(53, b"\x02"), "end"]) 
    )
    packets.append(offer)

    # 3. DHCP Request
    request = (
        Ether(src=device["mac"], dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=mac_bytes, xid=xid) /
        DHCP(options=[
            (53, b"\x03"), 
            (50, ip_bytes), 
            (12, device["hostname"].encode("utf-8")), 
            "end"
        ])
    )
    packets.append(request)

    # 4. DHCP ACK
    ack = (
        Ether(src=server_mac, dst=device["mac"]) /
        IP(src=server_ip, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, yiaddr=device["ip"], siaddr=server_ip, chaddr=mac_bytes, xid=xid) /
        DHCP(options=[(53, b"\x05"), "end"]) 
    )
    packets.append(ack)

    # 5. Gratuitous ARP
    garp = (
        Ether(src=device["mac"], dst="ff:ff:ff:ff:ff:ff") /
        ARP(op=2, psrc=device["ip"], hwsrc=device["mac"], pdst=device["ip"], hwdst="ff:ff:ff:ff:ff:ff")
    )
    packets.append(garp)

def main():
    print("Reading OUI database...")
    oui_list = load_oui("data/oui.csv")
    if not oui_list:
        print("Error: Could not read oui.csv")
        return

    print("Generating 100 random devices...")
    devices = generate_devices(oui_list, 100)
    
    server_mac = "00:11:22:33:44:55"
    server_ip = "192.168.1.1"
    packets = []

    # Giả lập mỗi thiết bị gia nhập mạng
    for dev in devices:
        generate_dhcp_flow(dev, packets, server_mac, server_ip)

    # Trộn thêm 200 gói tin ARP loạn xạ (thiết bị đang tìm nhau)
    for _ in range(200):
        src_dev = random.choice(devices)
        dst_dev = random.choice(devices + [{"mac": server_mac, "ip": server_ip}]) # Có thể tìm router
        if src_dev == dst_dev: continue

        # ARP Request
        arp_req = (
            Ether(src=src_dev["mac"], dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, psrc=src_dev["ip"], hwsrc=src_dev["mac"], pdst=dst_dev["ip"], hwdst="00:00:00:00:00:00")
        )
        packets.append(arp_req)
        
        # ARP Reply (chỉ 80% số lần là thành công để thực tế hơn)
        if random.random() < 0.8:
            arp_rep = (
                Ether(src=dst_dev["mac"], dst=src_dev["mac"]) /
                ARP(op=2, psrc=dst_dev["ip"], hwsrc=dst_dev["mac"], pdst=src_dev["ip"], hwdst=src_dev["mac"])
            )
            packets.append(arp_rep)

    output_file = "samples/realistic_100_devices.pcap"
    print(f"Writing {len(packets)} packets to {output_file}...")
    wrpcap(output_file, packets)
    print("Done!")

if __name__ == "__main__":
    main()

# Parsers Module

Module phân tích và giải mã các lớp giao thức mạng (Protocol Parsers).

Nhiệm vụ của module là nhận một luồng dữ liệu byte nhị phân (raw data) và chuyển đổi thành các kiểu dữ liệu struct C++ có ý nghĩa:
- **Ethernet Parser**: Xử lý layer 2 (Data Link), tách lấy MAC nguồn/đích và xác định loại giao thức payload (EtherType), có hỗ trợ VLAN 802.1Q.
- **ARP Parser**: Phân tách gói tin Address Resolution Protocol (Request / Reply / Gratuitous / Probe) để biết ánh xạ IP-MAC trong mạng cục bộ.
- **DHCP Parser**: Phân tách gói tin cấu hình host động (Layer 7 trên nền UDP), tập trung lấy metadata như hostname, IP requested, message type.
- **IPv4 Parser**: (Mở rộng) Xử lý các tiêu đề layer 3.

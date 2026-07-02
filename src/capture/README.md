# Capture Module

Module quản lý luồng dữ liệu đầu vào thông qua Packet Capture.

**Thành phần chính:**
- `pcap_reader`: Wrapper an toàn (C++ object) cho thư viện C `libpcap`.
- Hỗ trợ thiết lập bộ lọc BPF (Berkeley Packet Filter).
- Có thể hoạt động ở hai chế độ:
  1. Đọc gói tin offline từ file `.pcap` (phù hợp cho dev/Windows vì không cần cấu hình card mạng promiscuous).
  2. Bắt gói tin trực tiếp (live capture) từ network interface (thường dùng trên Linux/Docker).

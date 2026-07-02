# Enrichment Module

Module làm giàu dữ liệu (Data Enrichment), đóng vai trò phân tích metadata mở rộng từ các luồng gói tin đã parse.

**Tính năng:**
- **OUI Lookup**: Map 6 bytes đầu của địa chỉ MAC với cơ sở dữ liệu OUI của IEEE (`oui.csv`) để tự động gán nhãn Nhà sản xuất/Vendor phần cứng cho các thiết bị mạng.
- **OS Fingerprinting (Tương lai)**: Đọc OS Fingerprinting dựa vào các đặc trưng trong Option 55 (Parameter Request List) của DHCP, kết hợp với trường TTL (Time to Live) của IPv4.

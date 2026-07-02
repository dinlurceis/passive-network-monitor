# Tracker Module

Module logic cốt lõi chuyên biệt theo dõi tài sản mạng (Asset Tracker).

**Luồng hoạt động (Workflow):**
- Đóng vai trò là "cầu nối" phân tích nghiệp vụ. Chấp nhận các cấu trúc gói tin (ARP, DHCP) từ `parsers`.
- Sở hữu một bộ nhớ đệm nội bộ (in-memory cache) ánh xạ từ MAC tới Asset.
- Khớp thông tin mới nhận vào với bộ nhớ đệm:
  - Nếu MAC chưa từng xuất hiện → Sinh sự kiện `new_asset`.
  - Nếu MAC bị đổi IP gắn kèm → Sinh sự kiện `ip_change`.
- Gọi hàm tương ứng từ `DbManager` để ghi trạng thái Asset và sự kiện mạng mới xuống PostgreSQL.
- Xử lý việc làm mới thời gian `last_seen` và định kỳ "expire" đánh dấu ngưng kết nối cho những tài sản không còn phản hồi sau giới hạn timeout.

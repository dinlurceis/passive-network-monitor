# Config Module

Module quản lý cấu hình hệ thống của ứng dụng.

**Tính năng:**
- Đọc các cài đặt cốt lõi từ biến môi trường (Environment Variables) hoặc `.env`.
- Quản lý các cấu hình liên quan đến Database (Host, Port, User, Password), đường dẫn file PCAP đầu vào, đường dẫn file dữ liệu OUI, cũng như cấu hình log level.
- Cung cấp phương thức tĩnh `Config::from_env()` để khởi tạo struct `Config` duy nhất cho toàn ứng dụng.

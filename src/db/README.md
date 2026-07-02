# Database Module

Module thao tác và giao tiếp với cơ sở dữ liệu PostgreSQL.

**Thành phần chính:**
- `DbManager`: Sử dụng `libpqxx` (C++ PostgreSQL client library).
- Quản lý quá trình khởi tạo schema, tự động tạo các bảng (`assets`, `events`) nếu chưa tồn tại.
- Cung cấp các hàm API thao tác dữ liệu (CRUD) như thêm/cập nhật thông tin tài sản, ghi sự kiện mạng, cũng như đánh dấu tài sản không còn hoạt động (inactive).

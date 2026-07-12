# PNADS — Passive Network Asset Discovery System

**PNADS** (Hệ thống Khám phá Tài sản Mạng Thụ động) là một hệ thống giám sát mạng hiệu năng cao được phát triển bằng **C++20**. Hệ thống hoạt động hoàn toàn ở chế độ "thụ động" (passive), nghĩa là nó chỉ "lắng nghe" các luồng dữ liệu (traffic) chạy qua mạng mà không hề gửi đi bất kỳ gói tin quét (probe) nào, đảm bảo tàng hình 100% và không làm ảnh hưởng đến băng thông mạng.

PNADS hỗ trợ thu thập gói tin qua file PCAP, phân tích các giao thức đa dạng, nhận diện thông tin thiết bị (Vendor, OS), và sử dụng một Engine Phát hiện (Detection Engine) dựa trên luật (Rule-based) để phát hiện các bất thường như tấn công ARP Spoofing hay thiết bị lạ truy cập trái phép.

---

## 1. Tính năng nổi bật (Key Features)

- **Giám sát thụ động (100% Passive):** Hoạt động ẩn danh hoàn toàn, không can thiệp hay làm gián đoạn lưu lượng mạng.
- **Phân tích Đa giao thức (Multi-protocol Parsing):** Tự động bóc tách (parse) Ethernet, IPv4, UDP, TCP, ARP, DHCP, DNS, mDNS, SSDP.
- **Nhận diện Hệ điều hành (OS Fingerprinting):** Sử dụng hệ thống tính điểm theo trọng số kết hợp nhiều yếu tố như: DHCP Option 55 (Parameter Request List), Giá trị TTL, mDNS Service, SSDP User-Agent để dự đoán hệ điều hành.
- **Phát hiện Dấu hiệu Tấn công (Detection Engine):** 
  - Đánh giá sự kiện theo thời gian thực (Real-time).
  - Tích hợp các Rule mặc định: *Phát hiện Thiết bị mới (New Device)*, *Thiết bị trong danh sách đen (Watchlist)*, và *Cảnh báo giả mạo ARP (ARP Spoofing)*.
- **Kiến trúc Tối ưu (Lockless Tracker):** Tách biệt luồng bắt gói tin (Capture loop) chạy độc lập không cần khóa (mutex) nhằm tối đa hóa tốc độ, trong khi REST API được phục vụ trên các luồng riêng biệt truy vấn trực tiếp từ PostgreSQL.
- **Web Dashboard:** Giao diện với phong cách thiết kế hiện đại, biểu đồ thời gian thực sử dụng Chart.js và các animation mượt mà.
- **REST API:** Cung cấp các API Endpoint để truy xuất dữ liệu Assets, Events, Alerts và Thống kê chuỗi thời gian (Timeseries).

---

## 2. Tài liệu mô tả thiết kế hệ thống (System Design)

Hệ thống được thiết kế theo mô hình **Pipeline** với các thành phần chính sau:

1. **Capture Module (`PcapReader` / `PcapLive`):** 
   - Sử dụng BPF filter để lọc rác.
2. **Parsers:** 
   - Tự viết hoàn toàn cho các giao thức (Zero-copy parsing) để phân tách cấu trúc gói tin.
3. **Asset Tracker (`AssetTracker`):** 
   - Duy trì bộ nhớ đệm (Cache) In-memory của toàn bộ thiết bị trong mạng. Quản lý trạng thái `active`, thay đổi IP (`ip_change`).
4. **Enrichment Module:**
   - **OUI Lookup:** Tra cứu địa chỉ MAC để tìm nhà sản xuất thiết bị (Vendor) qua tệp dữ liệu chuẩn của IEEE.
   - **OS Fingerprint:** So khớp các dấu hiệu (Signatures) để dự đoán Hệ điều hành.
5. **Detection Engine:**
   - Hệ thống Rule-based Engine đánh giá mọi sự kiện (Event) do Tracker đẩy ra. Nếu vi phạm Rule, một `Alert` (Cảnh báo) sẽ được tạo ra.
6. **Database (`DbManager`):**
   - Sử dụng PostgreSQL và thư viện `pqxx`.
   - Cung cấp các thao tác ghi lô (Batch Insert) cho Events để giảm tải I/O.
7. **REST API Server:**
   - Xử lý các request từ Frontend Dashboard, truy vấn trực tiếp DB.

---

## 3. Cấu trúc Thư mục (Directory Structure)

```text
passive-network-monitor/
├── src/                 # Mã nguồn C++ chính
│   ├── api/             # HTTP REST API Server
│   ├── capture/         # Module bắt gói tin (libpcap wrapper)
│   ├── config/          # Xử lý biến môi trường (.env)
│   ├── db/              # Giao tiếp với PostgreSQL
│   ├── detection/       # Detection Engine và các Rule
│   ├── enrichment/      # OUI Database và OS Fingerprinting
│   ├── parsers/         # Bóc tách các giao thức mạng (ARP, DHCP, DNS...)
│   └── tracker/         # Quản lý vòng đời và cache thiết bị
├── web/                 # Dashboard Frontend (HTML, CSS, JS)
├── scripts/             # Shell script tiện ích (ví dụ: download_oui.sh)
├── samples/             # File pcap mẫu và cơ sở dữ liệu mẫu
├── CMakeLists.txt       # Cấu hình build C++
├── docker-compose.yml   # Cấu hình deploy bằng Docker
└── README.md            # Tài liệu dự án
```

---

## 4. Cấu hình Hệ thống (.env)

Hệ thống cho phép cấu hình linh hoạt thông qua file `.env` hoặc Biến môi trường. Các tham số bao gồm:

- `API_PORT`: Cổng chạy REST API (Mặc định: `8080`).
- `LOG_LEVEL`: Cấp độ log (`info`, `debug`, `warning`, `error`).
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`: Cấu hình kết nối PostgreSQL.
- `INTERFACE`: Giao diện mạng để lắng nghe (Live Capture) (Ví dụ: `eth0`, `wlan0`). *Để trống nếu chạy Offline*.
- `PCAP_FILE`: Đường dẫn tới file `.pcap` để phân tích (Offline Capture).
- `ARP_SPOOF_WINDOW_SEC`: Cửa sổ thời gian (giây) cho Rule ARP Spoofing.
- `ARP_SPOOF_MAC_THRESHOLD`: Ngưỡng số lượng địa chỉ MAC bất thường cho Rule ARP Spoofing.

---

## 5. Hướng dẫn Build / Deploy (Cài đặt & Triển khai)

### 5.1 Yêu cầu hệ thống (Prerequisites)
- Hệ điều hành: Ubuntu 24.04 (hoặc Linux tương đương).
- Yêu cầu môi trường Deploy: **Docker** & **Docker Compose**.
- Yêu cầu biên dịch cục bộ (Local Build): `cmake`, `g++`, `libpcap-dev`, `libpqxx-dev`, `libspdlog-dev`, `nlohmann-json3-dev`.

### 5.2 Deploy nhanh với Docker (Khuyến nghị)
Đây là cách đơn giản nhất để chạy ứng dụng mà không cần cài đặt các thư viện C++.

1. **Clone repository:**
   ```bash
   git clone <repo-url>
   cd passive-network-monitor
   ```

2. **Tải xuống cơ sở dữ liệu địa chỉ MAC (OUI):**
   *(Bước này bắt buộc để hệ thống nhận diện được Vendor của thiết bị)*
   ```bash
   chmod +x scripts/download_oui.sh
   ./scripts/download_oui.sh
   ```

3. **Tùy chỉnh cấu hình (Tùy chọn):**
   Bạn có thể chỉnh sửa `docker-compose.yml` để chuyển giữa việc đọc file PCAP mẫu (Offline) sang lắng nghe card mạng thực (Live Capture) bằng cách thiết lập `PCAP_FILE: ""` và cấu hình `INTERFACE: "eth0"`.

4. **Khởi động hệ thống:**
   ```bash
   docker compose build
   docker compose up -d db          # Chạy database trước
   docker compose up pnads          # Chạy backend và API
   ```

5. **Truy cập Dashboard:**
   Mở trình duyệt và truy cập: [http://localhost:8080](http://localhost:8080).

### 5.3 Biên dịch và phát triển cục bộ (Local Development)
Nếu bạn muốn đóng góp code hoặc tự build không dùng Docker:

```bash
# Tạo thư mục build với cấu hình Debug
cmake --preset debug
cmake --build build/debug

# Chạy hệ thống
./build/debug/pnads

# Chạy Unit Tests
cd build/debug && ctest --output-on-failure
```

---

## 6. Danh sách Sự kiện (Events) và Cảnh báo (Alerts)

PNADS theo dõi và phát sinh các sự kiện sau:
- `new_asset`: Phát hiện thiết bị mới truy cập mạng.
- `ip_change`: Một thiết bị (cùng MAC) đổi địa chỉ IP (dựa trên ARP hoặc DHCP).
- `dhcp_discover`, `dhcp_request`, `dhcp_ack`: Quá trình xin cấp IP.
- `dns_query`: Yêu cầu phân giải tên miền.
- `mdns_announce`, `ssdp_notify`: Các giao thức phát hiện dịch vụ nội bộ (IoT, Chromecast, Apple TV).
- `asset_gone`, `asset_returned`: Thiết bị offline quá thời gian hoặc online trở lại.

Các Rule Cảnh báo (Alerts) mặc định:
- **Watchlist Alert**: Cảnh báo tức thì nếu phát hiện thiết bị có MAC hoặc IP nằm trong danh sách đen (Watchlist).
- **ARP Spoofing Alert**: Cảnh báo khi một địa chỉ IP (thường là Gateway) được thông báo sở hữu bởi nhiều địa chỉ MAC liên tục trong khoảng thời gian ngắn (tấn công MITM).
- **New Device Alert**: Cảnh báo có thiết bị lạ xuất hiện trong mạng lưới.

---

## 7. Tài liệu API (REST API Reference)

Toàn bộ API luôn trả về định dạng JSON (`application/json`).
- `GET /health` : Kiểm tra trạng thái hệ thống, Uptime và Database.
- `GET /api/assets` : Lấy danh sách thiết bị (Hỗ trợ phân trang: `?page=1&page_size=20&active=true`).
- `GET /api/assets/:mac` : Chi tiết một thiết bị cụ thể theo MAC.
- `GET /api/assets/:mac/events` : Dòng thời gian sự kiện của thiết bị.
- `GET /api/events` : Lấy toàn bộ sự kiện trên mạng (Hỗ trợ filter `?type=` & `?protocol=`).
- `GET /api/alerts` : Lấy danh sách cảnh báo bảo mật.
- `POST /api/alerts/:id/ack` : Đánh dấu cảnh báo đã được xử lý (Acknowledge).
- `GET /api/stats/timeseries` : Lấy dữ liệu biểu đồ chuỗi thời gian (Ví dụ: `?interval=hour&range=24h`).
- `GET /api/watchlist` : Quản lý danh sách đen.
- `POST /api/watchlist` : Thêm đối tượng vào danh sách đen.

---

## 8. Đóng góp (Contributing)

PNADS là một dự án mở và hệ thống Detection Engine được thiết kế cực kỳ dễ mở rộng (Extensible). Bạn có thể tự viết thêm một Rule bảo mật mới bằng cách kế thừa class `DetectionRule` chỉ với vài chục dòng code.

Mọi ý tưởng đóng góp (Pull requests) đều rất được hoan nghênh! Vui lòng tạo Issue để thảo luận trước khi bắt tay vào những thay đổi lớn.
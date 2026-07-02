# passive-network-monitor

**Passive Network Monitor** là một hệ thống giám sát mạng thụ động (không can thiệp hoặc làm thay đổi lưu lượng mạng). Hệ thống được thiết kế để theo dõi, quản lý tài sản (assets) trong mạng nội bộ và phát hiện các hành vi bất thường.

## 🌟 Tính năng cốt lõi (Features)

- **Theo dõi tài sản (Asset Tracking)**: Đọc các gói tin từ file PCAP hoặc bắt trực tiếp (live capture) trên interface. Phân tích các giao thức như **ARP**, **DHCP** để tự động phát hiện thiết bị (IP/MAC), hệ điều hành và gán thông tin nhà sản xuất.
- **Enrichment**: Tự động tra cứu nhà sản xuất phần cứng (Vendor) thông qua cơ sở dữ liệu OUI của IEEE dựa vào địa chỉ MAC.
- **Lưu trữ chuẩn xác**: Sử dụng **PostgreSQL** làm cơ sở dữ liệu trung tâm, lưu vết vòng đời của từng tài sản và các sự kiện mạng (ví dụ: cấp phát IP mới, đổi IP).
- **Hỗ trợ đa môi trường**: Trên môi trường Windows (không sử dụng Npcap), hệ thống hỗ trợ đọc và phân tích từ các file offline `.pcap`. Trên môi trường Linux/Docker, hệ thống có thể chạy ở chế độ live capture.

## 📂 Cấu trúc thư mục (Directory Structure)

```text
passive-network-monitor/
├── CMakeLists.txt        # File cấu hình build chính
├── docker-compose.yml    # Cấu hình deploy Docker 
├── Dockerfile            # Định nghĩa image Docker
├── .env.example          # Mẫu biến môi trường
├── data/                 # Chứa dữ liệu enrich (như oui.csv)
├── docs/                 # Tài liệu thiết kế
├── models/               # Chứa model AI (cập nhật sau)
├── samples/              # Nơi chứa các file .pcap để test
├── scripts/              # Chứa các script tiện ích (init_db, download_oui...)
├── src/                  # Mã nguồn chính của dự án (C++)
│   ├── api/              # Module REST API (Phase 4)
│   ├── capture/          # Module đọc và xử lý gói tin (pcap_reader)
│   ├── config/           # Cấu hình hệ thống (load từ biến môi trường)
│   ├── db/               # Giao tiếp với PostgreSQL (DbManager)
│   ├── enrichment/       # Phân tích MAC/OS fingerprinting
│   ├── ml/               # Machine Learning & Phát hiện bất thường
│   ├── parsers/          # Trình phân tích giao thức (Ethernet, ARP, DHCP)
│   └── tracker/          # Module theo dõi tài sản và trạng thái
└── tests/                # Unit test (GoogleTest)
```

## Tech Stack

- **Language**: C++20
- **Build**: CMake 3.20+ / Ninja
- **Database**: PostgreSQL 16
- **Capture**: libpcap
- **Logging**: spdlog
- **JSON**: nlohmann_json
- **Testing**: GoogleTest
- **Container**: Docker + Docker Compose

## Prerequisites

### Ubuntu/Debian (WSL2 hoặc Docker)

```bash
sudo apt-get update && sudo apt-get install -y \
    cmake ninja-build g++ pkg-config \
    libpcap-dev \
    libpqxx-dev \
    libspdlog-dev \
    nlohmann-json3-dev \
    libgtest-dev \
    postgresql-client \
    curl
```

## Quick Start

### 1. Setup environment

```bash
cp .env.example .env
# Edit .env với DB credentials của bạn
```

### 2. Build (Phase 1)

```bash
cmake --preset debug
cmake --build build/debug -j$(nproc)
```

### 3. Init database

```bash
psql -h localhost -U netmon -d netmon -f scripts/init_db.sql
```

### 4. Download OUI Database (Phase 2)

Cơ sở dữ liệu MAC vendor (OUI) được yêu cầu cho chức năng Enrichment.

```bash
# Trên Linux / WSL / Git Bash:
bash scripts/download_oui.sh

# Trên Windows (Powershell/CMD):
python scripts/download_oui.py
```

### 5. Run với PCAP file

```bash
PCAP_FILE=samples/test.pcap \
DB_HOST=localhost DB_USER=netmon DB_PASSWORD=secret DB_NAME=netmon \
./build/debug/netmon
```

### 6. Run tests

```bash
cd build/debug && ctest --output-on-failure
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | localhost | PostgreSQL host |
| `DB_PORT` | 5432 | PostgreSQL port |
| `DB_NAME` | netmon | Database name |
| `DB_USER` | netmon | Database user |
| `DB_PASSWORD` | secret | Database password |
| `PCAP_FILE` | (empty) | Path to PCAP file (empty = live capture) |
| `INTERFACE` | eth0 | Network interface for live capture |
| `LOG_LEVEL` | info | Log level: debug/info/warning/error |
| `OUI_FILE` | data/oui.csv | MAC vendor database |
| `MODEL_PATH` | models/anomaly_model.onnx | ONNX anomaly detection model |
| `API_PORT` | 8080 | REST API port (Phase 4) |

## Project Phases

- **Phase 1** ✅: Core engine — PCAP reader, ARP/DHCP parser, PostgreSQL storage
- **Phase 2** ✅ : Enrichment — OUI vendor lookup, OS fingerprinting
- **Phase 3**: ML — Isolation Forest anomaly detection via ONNX Runtime
- **Phase 4** ✅ : Docker + REST API

## Verify Results

```bash
# Xem tất cả assets
psql -h localhost -U netmon -d netmon -c "SELECT * FROM asset_summary;"

# Xem events gần nhất
psql -h localhost -U netmon -d netmon -c "SELECT * FROM events ORDER BY ts DESC LIMIT 20;"
```
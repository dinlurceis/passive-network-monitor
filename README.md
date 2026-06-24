# passive-network-monitor

Passive network monitoring system — đọc PCAP file hoặc live interface, phát hiện asset (IP/MAC), parse ARP/DHCP metadata, lưu PostgreSQL, tích hợp ML.

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

### 4. Run với PCAP file

```bash
PCAP_FILE=samples/test.pcap \
DB_HOST=localhost DB_USER=netmon DB_PASSWORD=secret DB_NAME=netmon \
./build/debug/netmon
```

### 5. Run tests

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
- **Phase 2**: Enrichment — OUI vendor lookup, OS fingerprinting, CLI query interface
- **Phase 3**: ML — Isolation Forest anomaly detection via ONNX Runtime
- **Phase 4**: Docker + REST API

## Verify Results

```bash
# Xem tất cả assets
psql -h localhost -U netmon -d netmon -c "SELECT * FROM asset_summary;"

# Xem events gần nhất
psql -h localhost -U netmon -d netmon -c "SELECT * FROM events ORDER BY ts DESC LIMIT 20;"
```
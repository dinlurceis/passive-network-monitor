# PNADS — Passive Network Asset Discovery System

PNADS is a high-performance, passive network monitoring system written in C++20. It discovers and tracks network assets (devices) by passively analyzing network traffic (via PCAP files or live capture) without sending any active probes. 

It leverages multiple protocols (ARP, DHCP, DNS, mDNS, SSDP, HTTP) to discover devices, fingerprints their OS and vendor, and uses a rule-based detection engine to identify anomalous behavior (like ARP spoofing or unknown devices). 

It features a PostgreSQL backend for persistence and a beautiful, modern Web Dashboard served directly via an embedded REST API.

## Features

- **Passive Discovery**: 100% passive, no impact on network traffic.
- **Protocol Analysis**: Parses Ethernet, IPv4, UDP, TCP, ARP, DHCP, DNS, mDNS, SSDP, and HTTP (User-Agent extraction).
- **OS Fingerprinting**: Employs a multi-signal weighted voting system (DHCP Option 55, TTL, User-Agents, mDNS, SSDP) to confidently guess the operating system.
- **Detection Engine**: Real-time evaluation of events against rules (New Device, Watchlist Match, ARP Spoofing) to generate alerts.
- **REST API**: Built-in HTTP server (`cpp-httplib`) exposing assets, events, alerts, and timeseries statistics.
- **Premium Web Dashboard**: A responsive, glassmorphism-styled Single Page Application with interactive Chart.js visualizations.
- **Lockless Tracker**: Optimized single-threaded capture loop avoids mutex contention, while the REST API queries the database concurrently.

## Prerequisites

- Ubuntu 24.04 (or similar Linux environment)
- Docker & Docker Compose (Recommended for deployment)
- For local build:
  ```bash
  sudo apt-get update && sudo apt-get install -y \
      cmake ninja-build g++ pkg-config git \
      libpcap-dev libpqxx-dev libspdlog-dev nlohmann-json3-dev \
      libgtest-dev postgresql-client curl
  ```

## Setup & Running with Docker

1. **Clone the repository**:
   ```bash
   git clone <repo-url>
   cd passive-network-monitor
   ```

2. **Download OUI Database** (Required for Vendor MAC lookups):
   ```bash
   chmod +x scripts/download_oui.sh
   ./scripts/download_oui.sh
   ```

3. **Start the system via Docker Compose**:
   ```bash
   docker compose build
   docker compose up -d db
   docker compose up pnads
   ```
   *Note*: The default configuration reads from a sample PCAP file (`samples/test.pcap`). To run a live capture on a specific interface, edit the `docker-compose.yml` to set `PCAP_FILE: ""` and `INTERFACE: "eth0"`.

4. **Access the Dashboard**:
   Open [http://localhost:8080](http://localhost:8080) in your web browser.

## Architecture

See [docs/design.md](docs/design.md) for detailed architecture, component diagrams, and detection rule explanations.

## REST API Reference

- `GET /health` : API and DB health status.
- `GET /api/assets` : List of discovered assets.
- `GET /api/assets/:mac/events` : Timeline of events for a specific asset.
- `GET /api/alerts` : List of generated alerts.
- `GET /api/stats/timeseries` : Chart data (e.g., `?interval=day&range=7d&group_by=event_type`).
- `GET /api/watchlist` : View watchlist entries.
- `POST /api/watchlist` : Add a suspicious MAC/IP to the watchlist.

## Development & Testing

To build and test locally without Docker:

```bash
cmake --preset debug
cmake --build build/debug

# Run tests
cd build/debug
ctest --output-on-failure
```
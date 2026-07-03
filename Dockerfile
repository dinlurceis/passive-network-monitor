# syntax=docker/dockerfile:1
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies (Removed ONNX related dependencies since Phase 3 is skipped)
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build g++ pkg-config git ca-certificates \
    libpcap-dev \
    libpq-dev \
    libspdlog-dev \
    nlohmann-json3-dev \
    libgtest-dev \
    && rm -rf /var/lib/apt/lists/*

# Build libpqxx 7.9.2 from source with C++20
# Ubuntu 24.04's libpqxx-dev has an ABI mismatch (compiled with C++17 but
# headers use std::source_location from C++20), so we build from source.
RUN git clone --depth 1 --branch 7.9.2 https://github.com/jtv/libpqxx.git /tmp/libpqxx \
    && cmake -S /tmp/libpqxx -B /tmp/libpqxx/build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CXX_STANDARD=20 \
        -DSKIP_BUILD_TEST=ON \
        -DBUILD_SHARED_LIBS=ON \
    && cmake --build /tmp/libpqxx/build -j$(nproc) \
    && cmake --install /tmp/libpqxx/build \
    && ldconfig \
    && rm -rf /tmp/libpqxx

WORKDIR /build
COPY . .

RUN cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j$(nproc) && \
    ctest --test-dir build --output-on-failure

# ─── Runtime image ───────────────────────────────────────────────────
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 libpq5 libspdlog1.12 \
    ca-certificates postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy built binary and libpqxx from builder
COPY --from=builder /build/build/netmon     /usr/local/bin/netmon
COPY --from=builder /usr/local/lib/libpqxx* /usr/local/lib/
RUN ldconfig

WORKDIR /app
COPY scripts/   /app/scripts/
COPY data/      /app/data/
COPY frontend/  /app/frontend/

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/netmon"]
CMD ["--pcap", "/samples/test.pcap"]

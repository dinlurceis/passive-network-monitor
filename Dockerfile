# ---- build stage ----
FROM ubuntu:24.04 AS build
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    cmake ninja-build g++ pkg-config git \
    libpcap-dev libpq-dev libspdlog-dev nlohmann-json3-dev libgtest-dev

RUN git clone --depth 1 -b 7.8.1 https://github.com/jtv/libpqxx.git /tmp/libpqxx && \
    cd /tmp/libpqxx && \
    cmake -B build -DCMAKE_CXX_STANDARD=20 -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DSKIP_BUILD_TEST=ON && \
    cmake --build build --parallel 4 && \
    cmake --install build && \
    rm -rf /tmp/libpqxx

WORKDIR /src
COPY . .
RUN cmake --preset release && cmake --build build/release

# ---- runtime stage ----
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libpcap0.8 libpq5 libspdlog1.12 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /src/build/release/pnads /usr/local/bin/pnads
COPY data/   /app/data/
COPY web/    /app/web/
COPY scripts/ /app/scripts/

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pnads"]

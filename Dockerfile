# ---- build stage ----
FROM ubuntu:24.04 AS build
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    cmake ninja-build g++ pkg-config git \
    libpcap-dev libpqxx-dev libspdlog-dev nlohmann-json3-dev

WORKDIR /src
COPY . .
RUN cmake --preset release && cmake --build build/release

# ---- runtime stage ----
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libpcap0.8 libpqxx-7.9 libspdlog1.12 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /src/build/release/pnads /usr/local/bin/pnads
COPY data/   /app/data/
COPY web/    /app/web/
COPY scripts/ /app/scripts/

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pnads"]

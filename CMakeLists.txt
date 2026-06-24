cmake_minimum_required(VERSION 3.20)
project(passive-network-monitor VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
find_package(PostgreSQL REQUIRED)

# libpqxx (prefer CMake package, fallback to pkg-config)
find_package(libpqxx QUIET)
if(NOT libpqxx_FOUND)
    pkg_check_modules(PQXX REQUIRED libpqxx)
    message(STATUS "libpqxx found via pkg-config")
else()
    message(STATUS "libpqxx found via CMake config")
endif()

find_package(spdlog REQUIRED)
find_package(nlohmann_json REQUIRED)

# Source files (phase 1)
set(SOURCES
    src/main.cpp
    src/config/config.cpp
    src/capture/pcap_reader.cpp
    src/parsers/ethernet_parser.cpp
    src/parsers/arp_parser.cpp
    src/parsers/dhcp_parser.cpp
    src/tracker/asset_tracker.cpp
    src/db/db_manager.cpp
)

add_executable(netmon ${SOURCES})

target_include_directories(netmon PRIVATE
    src/
    ${PCAP_INCLUDE_DIRS}
    ${PostgreSQL_INCLUDE_DIRS}
)

target_link_libraries(netmon PRIVATE
    ${PCAP_LIBRARIES}
    $<IF:$<TARGET_EXISTS:libpqxx::pqxx>,libpqxx::pqxx,${PQXX_LIBRARIES}>
    PostgreSQL::PostgreSQL
    spdlog::spdlog
    nlohmann_json::nlohmann_json
)

# Tests
enable_testing()
add_subdirectory(tests)

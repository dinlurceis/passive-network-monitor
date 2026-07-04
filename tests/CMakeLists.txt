find_package(GTest REQUIRED)

set(COMMON_PARSER_SOURCES
    ${CMAKE_SOURCE_DIR}/src/util/binary_reader.cpp
    ${CMAKE_SOURCE_DIR}/src/parsers/ethernet_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/parsers/arp_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/parsers/dhcp_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/parsers/ipv4_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/parsers/udp_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/parsers/tcp_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/parsers/dns_message.cpp
    ${CMAKE_SOURCE_DIR}/src/parsers/mdns_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/parsers/ssdp_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/parsers/http_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/config/config.cpp
)

# ── Helper function ───────────────────────────────────────────────────────────
function(add_pnads_test name)
    add_executable(${name} ${name}.cpp ${COMMON_PARSER_SOURCES})
    target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(${name} PRIVATE GTest::gtest_main spdlog::spdlog)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# ── Parser / utility tests (no DB) ───────────────────────────────────────────
add_pnads_test(test_binary_reader)
add_pnads_test(test_arp_parser)
add_pnads_test(test_dhcp_parser)
add_pnads_test(test_mdns_parser)
add_pnads_test(test_ssdp_parser)
add_pnads_test(test_http_parser)

# ── Enrichment tests (no DB) ──────────────────────────────────────────────────
add_executable(test_oui_lookup
    test_oui_lookup.cpp
    ${CMAKE_SOURCE_DIR}/src/util/binary_reader.cpp
    ${CMAKE_SOURCE_DIR}/src/enrichment/oui_lookup.cpp
    ${CMAKE_SOURCE_DIR}/src/enrichment/os_fingerprint.cpp
)
target_include_directories(test_oui_lookup PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_oui_lookup PRIVATE GTest::gtest_main spdlog::spdlog)
add_test(NAME test_oui_lookup COMMAND test_oui_lookup)

# ── OS fingerprint test (no DB) ───────────────────────────────────────────────
add_executable(test_os_fingerprint
    test_os_fingerprint.cpp
    ${CMAKE_SOURCE_DIR}/src/util/binary_reader.cpp
    ${CMAKE_SOURCE_DIR}/src/enrichment/os_fingerprint.cpp
)
target_include_directories(test_os_fingerprint PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_os_fingerprint PRIVATE GTest::gtest_main spdlog::spdlog)
add_test(NAME test_os_fingerprint COMMAND test_os_fingerprint)

# ── Detection rules test (no DB) ──────────────────────────────────────────────
add_executable(test_detection_rules
    test_detection_rules.cpp
    ${CMAKE_SOURCE_DIR}/src/detection/rule_new_device.cpp
)
target_include_directories(test_detection_rules PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_detection_rules PRIVATE GTest::gtest_main spdlog::spdlog)
add_test(NAME test_detection_rules COMMAND test_detection_rules)

# ── Asset tracker test (requires PostgreSQL at runtime) ───────────────────────
find_package(libpqxx QUIET)
if(NOT libpqxx_FOUND)
    pkg_check_modules(PQXX QUIET libpqxx)
endif()

find_package(PostgreSQL QUIET)

if(libpqxx_FOUND OR PQXX_FOUND)
    add_executable(test_asset_tracker
        test_asset_tracker.cpp
        ${COMMON_PARSER_SOURCES}
        ${CMAKE_SOURCE_DIR}/src/tracker/asset_tracker.cpp
        ${CMAKE_SOURCE_DIR}/src/db/db_manager.cpp
        ${CMAKE_SOURCE_DIR}/src/enrichment/oui_lookup.cpp
        ${CMAKE_SOURCE_DIR}/src/enrichment/os_fingerprint.cpp
    )
    target_include_directories(test_asset_tracker PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${PostgreSQL_INCLUDE_DIRS}
    )
    target_link_libraries(test_asset_tracker PRIVATE
        GTest::gtest_main
        spdlog::spdlog
        $<IF:$<TARGET_EXISTS:libpqxx::pqxx>,libpqxx::pqxx,${PQXX_LIBRARIES}>
        PostgreSQL::PostgreSQL
    )
    add_test(NAME test_asset_tracker COMMAND test_asset_tracker)
endif()

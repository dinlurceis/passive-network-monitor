find_package(GTest REQUIRED)

# Helper function to create test executables
function(add_netmon_test name)
    add_executable(${name} ${name}.cpp
        ${CMAKE_SOURCE_DIR}/src/parsers/ethernet_parser.cpp
        ${CMAKE_SOURCE_DIR}/src/parsers/arp_parser.cpp
        ${CMAKE_SOURCE_DIR}/src/parsers/dhcp_parser.cpp
        ${CMAKE_SOURCE_DIR}/src/config/config.cpp
    )
    target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(${name} PRIVATE
        GTest::gtest_main
        spdlog::spdlog
    )
    add_test(NAME ${name} COMMAND ${name})
endfunction()

add_netmon_test(test_arp_parser)
add_netmon_test(test_dhcp_parser)

# test_asset_tracker requires PostgreSQL — skip if no DB connection configured
# It's compiled but may fail at runtime without DB
add_netmon_test(test_asset_tracker)

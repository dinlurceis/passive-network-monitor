#pragma once
#include <string>

namespace pnads {

struct Config {
    // Database
    std::string db_host     = "localhost";
    int         db_port     = 5432;
    std::string db_name     = "pnads";
    std::string db_user     = "pnads";
    std::string db_password = "secret";

    // Capture
    std::string pcap_file   = "";       // empty = live capture
    std::string interface   = "eth0";   // dùng khi pcap_file empty
    int         snaplen     = 65535;
    int         timeout_ms  = 1000;

    // App
    std::string log_level   = "info";
    std::string oui_file    = "data/oui.csv";
    int         api_port    = 8080;

    // Thresholds
    int   asset_timeout_sec       = 300;  // giây không thấy → is_active=false
    int   arp_spoof_window_sec    = 60;   // cửa sổ thời gian phát hiện ARP spoofing
    int   arp_spoof_mac_threshold = 2;    // số MAC khác nhau cho cùng IP → alert

    // Load từ environment variables (tự động load .env nếu có)
    static Config from_env();

    // Trả về connection string cho libpqxx
    std::string db_connection_string() const;
};

} // namespace pnads

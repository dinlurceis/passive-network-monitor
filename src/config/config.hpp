#pragma once
#include <string>

namespace netmon {

struct Config {
    // Database
    std::string db_host     = "localhost";
    int         db_port     = 5432;
    std::string db_name     = "netmon";
    std::string db_user     = "netmon";
    std::string db_password = "secret";

    // Capture
    std::string pcap_file   = "1.pcap";       // empty = live capture
    std::string interface   = "eth0";   // dùng khi pcap_file empty
    int         snaplen     = 65535;
    int         timeout_ms  = 1000;

    // App
    std::string log_level   = "info";
    std::string oui_file    = "data/oui.csv";
    std::string model_path  = "models/anomaly_model.onnx";
    int         api_port    = 8080;

    // Thresholds
    int         asset_timeout_sec = 300;  // giây không thấy → is_active=false

    // Load từ environment variables
    static Config from_env();

    // Trả về connection string cho libpqxx
    std::string db_connection_string() const;
};

} // namespace netmon

#include "config/config.hpp"
#include <cstdlib>
#include <format>
#include <fstream>
#include <sstream>

namespace netmon {

// Hàm đơn giản để đọc file .env và set environment variables
static void load_dotenv(const std::string& path = ".env") {
    std::ifstream file(path);
    if (!file.is_open()) return;

    std::string line;
    while (std::getline(file, line)) {
        // Bỏ qua dòng trống hoặc comment
        if (line.empty() || line[0] == '#') continue;

        auto pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string val = line.substr(pos + 1);
            
            // Xóa khoảng trắng và dấu ngoặc kép thừa
            key.erase(0, key.find_first_not_of(" \t\r\n"));
            key.erase(key.find_last_not_of(" \t\r\n") + 1);
            val.erase(0, val.find_first_not_of(" \t\r\n\"'"));
            val.erase(val.find_last_not_of(" \t\r\n\"'") + 1);

            // Chỉ set nếu biến chưa tồn tại trong môi trường
            if (std::getenv(key.c_str()) == nullptr) {
                setenv(key.c_str(), val.c_str(), 0);
            }
        }
    }
}

static std::string getenv_or(const char* name, const std::string& def) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : def;
}

Config Config::from_env() {
    load_dotenv(); // Tự động load file .env ở thư mục chạy

    Config c;
    c.db_host       = getenv_or("DB_HOST",     "localhost");
    c.db_port       = std::stoi(getenv_or("DB_PORT", "5432"));
    c.db_name       = getenv_or("DB_NAME",     "netmon");
    c.db_user       = getenv_or("DB_USER",     "netmon");
    c.db_password   = getenv_or("DB_PASSWORD", "secret");
    c.pcap_file     = getenv_or("PCAP_FILE",   "");
    c.interface     = getenv_or("INTERFACE",   "eth0");
    c.log_level     = getenv_or("LOG_LEVEL",   "info");
    c.oui_file      = getenv_or("OUI_FILE",    "data/oui.csv");
    c.model_path    = getenv_or("MODEL_PATH",  "models/anomaly_model.onnx");
    c.api_port      = std::stoi(getenv_or("API_PORT", "8080"));
    return c;
}

std::string Config::db_connection_string() const {
    return std::format(
        "host={} port={} dbname={} user={} password={}",
        db_host, db_port, db_name, db_user, db_password
    );
}

} // namespace netmon

#include "config/config.hpp"
#include <cstdlib>
#include <format>
#include <fstream>
#include <sstream>

namespace pnads {

// Load file .env và set environment variables (không ghi đè biến đã có)
static void load_dotenv(const std::string& path = ".env") {
    std::ifstream file(path);
    if (!file.is_open()) return;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        auto pos = line.find('=');
        if (pos == std::string::npos) continue;

        std::string key = line.substr(0, pos);
        std::string val = line.substr(pos + 1);

        // Cắt bỏ khoảng trắng và dấu nháy
        key.erase(0, key.find_first_not_of(" \t\r\n"));
        key.erase(key.find_last_not_of(" \t\r\n") + 1);
        val.erase(0, val.find_first_not_of(" \t\r\n\"'"));
        val.erase(val.find_last_not_of(" \t\r\n\"'") + 1);

        if (!key.empty() && std::getenv(key.c_str()) == nullptr) {
            setenv(key.c_str(), val.c_str(), 0);
        }
    }
}

static std::string getenv_or(const char* name, const std::string& def) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : def;
}

static int getenv_int(const char* name, int def) {
    const char* v = std::getenv(name);
    if (!v) return def;
    try { return std::stoi(v); } catch (...) { return def; }
}

Config Config::from_env() {
    load_dotenv();

    Config c;
    c.db_host                 = getenv_or("DB_HOST",     "localhost");
    c.db_port                 = getenv_int("DB_PORT",    5432);
    c.db_name                 = getenv_or("DB_NAME",     "pnads");
    c.db_user                 = getenv_or("DB_USER",     "pnads");
    c.db_password             = getenv_or("DB_PASSWORD", "secret");
    c.pcap_file     = getenv_or("PCAP_FILE",   "");
    c.interface     = getenv_or("INTERFACE",   "eth0");
    c.log_level     = getenv_or("LOG_LEVEL",   "info");
    c.oui_file                = getenv_or("OUI_FILE",    "data/oui.csv");
    c.api_port                = getenv_int("API_PORT",   8080);
    c.asset_timeout_sec       = getenv_int("ASSET_TIMEOUT_SEC",       300);
    c.arp_spoof_window_sec    = getenv_int("ARP_SPOOF_WINDOW_SEC",    60);
    c.arp_spoof_mac_threshold = getenv_int("ARP_SPOOF_MAC_THRESHOLD", 2);
    return c;
}

std::string Config::db_connection_string() const {
    return std::format(
        "host={} port={} dbname={} user={} password={}",
        db_host, db_port, db_name, db_user, db_password
    );
}

} // namespace pnads

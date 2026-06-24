#include "config.hpp"
#include <cstdlib>
#include <format>

namespace netmon {

static std::string getenv_or(const char* name, const std::string& def) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : def;
}

Config Config::from_env() {
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

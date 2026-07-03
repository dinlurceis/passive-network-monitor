#include "api/rest_server.hpp"
#include "api/httplib.h"
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <chrono>
#include <iomanip>
#include <sstream>

using json = nlohmann::json;

namespace netmon {

static std::string time_point_to_iso(const TimePoint& tp) {
    auto c_time = Clock::to_time_t(tp);
    std::tm tm = *std::gmtime(&c_time);
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

RestServer::RestServer(DbManager& db, AssetTracker& tracker, int port)
    : db_(db), tracker_(tracker), port_(port) {
    srv_ = std::make_unique<httplib::Server>();
    setup_routes();
}

RestServer::~RestServer() {
    stop();
}

void RestServer::start() {
    if (running_) return;
    running_ = true;
    
    thread_ = std::thread([this]() {
        spdlog::info("REST API Server starting on port {}", port_);
        srv_->listen("0.0.0.0", port_);
        spdlog::info("REST API Server stopped.");
    });
}

void RestServer::stop() {
    if (!running_) return;
    srv_->stop();
    if (thread_.joinable()) {
        thread_.join();
    }
    running_ = false;
}

void RestServer::setup_routes() {
    // Phục vụ giao diện tĩnh
    srv_->set_mount_point("/", "./frontend");

    // GET /health
    srv_->Get("/health", [this](const httplib::Request&, httplib::Response& res) {
        json response = {
            {"status", "ok"},
            {"db", db_.ping() ? "connected" : "disconnected"},
            {"assets", tracker_.active_count()},
            {"model_loaded", false} // Phase 3 ML model is skipped
        };
        res.set_content(response.dump(), "application/json");
    });

    // GET /api/assets
    srv_->Get("/api/assets", [this](const httplib::Request&, httplib::Response& res) {
        auto assets = db_.get_all_assets();
        json response = json::array();
        
        for (const auto& a : assets) {
            json item = {
                {"id", a.id},
                {"mac", a.mac},
                {"ip", a.ip},
                {"hostname", a.hostname},
                {"vendor", a.vendor},
                {"os_guess", a.os_guess},
                {"first_seen", time_point_to_iso(a.first_seen)},
                {"last_seen", time_point_to_iso(a.last_seen)},
                {"is_active", a.is_active}
            };
            response.push_back(item);
        }
        res.set_content(response.dump(), "application/json");
    });

    // GET /api/stats
    srv_->Get("/api/stats", [this](const httplib::Request&, httplib::Response& res) {
        auto assets = db_.get_all_assets();
        int active = 0;
        for (const auto& a : assets) {
            if (a.is_active) active++;
        }
        
        json response = {
            {"total_assets", assets.size()},
            {"active_assets", active},
            // The real uptime would be tracked via a start time variable, 
            // but for simplicity here we return 0.
            {"uptime_seconds", 0} 
        };
        res.set_content(response.dump(), "application/json");
    });
}

} // namespace netmon

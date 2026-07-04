#include "api/rest_server.hpp"
#include "api/httplib.h"
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <iomanip>
#include <sstream>

using json = nlohmann::json;

namespace pnads {

static std::string tp_to_iso(const TimePoint& tp) {
    auto c_time = Clock::to_time_t(tp);
    std::tm tm  = *std::gmtime(&c_time);
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

static json asset_to_json(const Asset& a) {
    json item;
    item["id"]            = a.id;
    item["mac"]           = a.mac;
    item["ip"]            = a.ip;
    item["hostname"]      = a.hostname;
    item["vendor"]        = a.vendor;
    item["os_guess"]      = a.os_guess;
    item["os_confidence"] = a.os_confidence;
    item["discovered_via"]= a.discovered_via;
    item["first_seen"]    = tp_to_iso(a.first_seen);
    item["last_seen"]     = tp_to_iso(a.last_seen);
    item["is_active"]     = a.is_active;
    item["is_trusted"]    = a.is_trusted;
    return item;
}

RestServer::RestServer(DbManager& db, int port)
    : db_(db), port_(port),
      start_time_(std::chrono::steady_clock::now()) {
    srv_ = std::make_unique<httplib::Server>();
    setup_routes();
}

RestServer::~RestServer() { stop(); }

void RestServer::start() {
    if (running_) return;
    running_ = true;
    thread_ = std::thread([this]() {
        spdlog::info("REST API listening on :{}", port_);
        srv_->listen("0.0.0.0", port_);
        spdlog::info("REST API stopped");
    });
}

void RestServer::stop() {
    if (!running_) return;
    srv_->stop();
    if (thread_.joinable()) thread_.join();
    running_ = false;
}

void RestServer::setup_routes() {
    // ── Static files (web dashboard) ──────────────────────────────────────────
    srv_->set_mount_point("/", "./web");

    // ── CORS headers (for dev) ────────────────────────────────────────────────
    srv_->set_pre_routing_handler([](const httplib::Request&, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // ── Health ────────────────────────────────────────────────────────────────
    srv_->Get("/health", [this](const httplib::Request&, httplib::Response& res) {
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start_time_).count();
        auto assets = db_.get_all_assets();
        int active  = 0;
        for (const auto& a : assets) if (a.is_active) ++active;
        json r = {{"status", "ok"},
                  {"db", db_.ping() ? "connected" : "disconnected"},
                  {"assets", active},
                  {"uptime_seconds", uptime}};
        res.set_content(r.dump(), "application/json");
    });

    // ── GET /api/assets ───────────────────────────────────────────────────────
    srv_->Get("/api/assets", [this](const httplib::Request& req, httplib::Response& res) {
        bool active_only = req.has_param("active") && req.get_param_value("active") == "true";
        auto assets = db_.get_all_assets(active_only);
        json arr = json::array();
        for (const auto& a : assets) arr.push_back(asset_to_json(a));
        res.set_content(arr.dump(), "application/json");
    });

    // ── GET /api/assets/:mac ──────────────────────────────────────────────────
    srv_->Get(R"(/api/assets/([^/]+))", [this](const httplib::Request& req, httplib::Response& res) {
        std::string mac = req.matches[1];
        auto asset = db_.find_asset_by_mac(mac);
        if (!asset) { res.status = 404; res.set_content("{\"error\":\"not found\"}", "application/json"); return; }
        res.set_content(asset_to_json(*asset).dump(), "application/json");
    });

    // ── GET /api/assets/:mac/events ───────────────────────────────────────────
    srv_->Get(R"(/api/assets/([^/]+)/events)", [this](const httplib::Request& req, httplib::Response& res) {
        std::string mac = req.matches[1];
        int limit = 100;
        if (req.has_param("limit")) {
            try { limit = std::stoi(req.get_param_value("limit")); } catch (...) {}
        }
        auto rows = db_.get_events_by_asset(mac, limit);
        json arr = json::array();
        for (const auto& row : rows) {
            json ev;
            ev["id"]         = row["id"].as<int>();
            ev["event_type"] = row["event_type"].as<std::string>();
            ev["protocol"]   = row["protocol"].as<std::string>();
            ev["old_value"]  = row["old_value"].is_null() ? "" : row["old_value"].as<std::string>();
            ev["new_value"]  = row["new_value"].is_null() ? "" : row["new_value"].as<std::string>();
            ev["ts"]         = row["ts"].as<std::string>();
            arr.push_back(ev);
        }
        res.set_content(arr.dump(), "application/json");
    });

    // ── GET /api/events ───────────────────────────────────────────────────────
    srv_->Get("/api/events", [this](const httplib::Request& req, httplib::Response& res) {
        // Simplified — just return recent events via stats
        json r = {{"message", "Use /api/assets/:mac/events for asset-specific events"}};
        res.set_content(r.dump(), "application/json");
    });

    // ── GET /api/alerts ───────────────────────────────────────────────────────
    srv_->Get("/api/alerts", [this](const httplib::Request& req, httplib::Response& res) {
        bool   unacked = req.has_param("ack") && req.get_param_value("ack") == "false";
        std::string sev = req.has_param("severity") ? req.get_param_value("severity") : "";
        auto alerts = db_.get_alerts(unacked, sev);
        json arr = json::array();
        for (const auto& a : alerts) {
            json item;
            item["id"]           = a.id;
            item["asset_id"]     = a.asset_id;
            item["rule_type"]    = a.rule_type;
            item["severity"]     = a.severity;
            item["message"]      = a.message;
            item["acknowledged"] = a.acknowledged;
            arr.push_back(item);
        }
        res.set_content(arr.dump(), "application/json");
    });

    // ── POST /api/alerts/:id/ack ──────────────────────────────────────────────
    srv_->Post(R"(/api/alerts/(\d+)/ack)", [this](const httplib::Request& req, httplib::Response& res) {
        int id = std::stoi(req.matches[1]);
        db_.ack_alert(id);
        res.set_content("{\"ok\":true}", "application/json");
    });

    // ── GET /api/watchlist ────────────────────────────────────────────────────
    srv_->Get("/api/watchlist", [this](const httplib::Request&, httplib::Response& res) {
        auto list = db_.get_watchlist();
        json arr = json::array();
        for (const auto& e : list) {
            arr.push_back({{"id",e.id},{"mac",e.mac},{"ip",e.ip},
                           {"label",e.label},{"note",e.note}});
        }
        res.set_content(arr.dump(), "application/json");
    });

    // ── POST /api/watchlist ───────────────────────────────────────────────────
    srv_->Post("/api/watchlist", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = json::parse(req.body);
            std::string mac   = body.value("mac",   "");
            std::string ip    = body.value("ip",    "");
            std::string label = body.value("label", "");
            std::string note  = body.value("note",  "");
            if (mac.empty() && ip.empty()) {
                res.status = 400;
                res.set_content("{\"error\":\"mac or ip required\"}", "application/json");
                return;
            }
            auto entry = db_.insert_watchlist(mac, ip, label, note);
            res.status = 201;
            res.set_content(json({{"id",entry.id},{"mac",entry.mac},{"ip",entry.ip},
                                   {"label",entry.label}}).dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(std::format("{{\"error\":\"{}\"}}", e.what()), "application/json");
        }
    });

    // ── DELETE /api/watchlist/:id ─────────────────────────────────────────────
    srv_->Delete(R"(/api/watchlist/(\d+))", [this](const httplib::Request& req, httplib::Response& res) {
        int id = std::stoi(req.matches[1]);
        db_.delete_watchlist(id);
        res.set_content("{\"ok\":true}", "application/json");
    });

    // ── GET /api/stats ────────────────────────────────────────────────────────
    srv_->Get("/api/stats", [this](const httplib::Request&, httplib::Response& res) {
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start_time_).count();
        auto assets  = db_.get_all_assets();
        int  active  = 0;
        for (const auto& a : assets) if (a.is_active) ++active;
        int total_ev = db_.get_total_events();
        int unacked  = db_.get_unacked_alerts_count();

        json r = {
            {"total_assets",          static_cast<int>(assets.size())},
            {"active_assets",         active},
            {"total_events",          total_ev},
            {"alerts_unacknowledged", unacked},
            {"uptime_seconds",        uptime}
        };
        res.set_content(r.dump(), "application/json");
    });

    // ── GET /api/stats/timeseries ─────────────────────────────────────────────
    srv_->Get("/api/stats/timeseries", [this](const httplib::Request& req, httplib::Response& res) {
        std::string interval   = req.has_param("interval")   ? req.get_param_value("interval")   : "hour";
        std::string range_str  = req.has_param("range")      ? req.get_param_value("range")      : "24h";
        std::string group_by   = req.has_param("group_by")   ? req.get_param_value("group_by")   : "event_type";
        std::string asset_mac  = req.has_param("asset_mac")  ? req.get_param_value("asset_mac")  : "";

        // Parse range (e.g. "24h" or "7d")
        int range_hours = 24;
        if (!range_str.empty()) {
            try {
                if (range_str.back() == 'h') range_hours = std::stoi(range_str.substr(0, range_str.size()-1));
                else if (range_str.back() == 'd') range_hours = std::stoi(range_str.substr(0, range_str.size()-1)) * 24;
            } catch (...) {}
        }

        auto buckets = db_.get_timeseries(interval, range_hours, group_by, asset_mac);

        // Build series: group by bucket, collect key→count pairs
        json series = json::array();
        std::string cur_bucket;
        json cur_obj;
        for (const auto& b : buckets) {
            if (b.bucket != cur_bucket) {
                if (!cur_bucket.empty()) series.push_back(cur_obj);
                cur_bucket = b.bucket;
                cur_obj = {{"bucket", b.bucket}};
            }
            cur_obj[b.key] = b.count;
        }
        if (!cur_bucket.empty()) series.push_back(cur_obj);

        json r = {{"interval", interval}, {"group_by", group_by}, {"series", series}};
        res.set_content(r.dump(), "application/json");
    });
}

} // namespace pnads

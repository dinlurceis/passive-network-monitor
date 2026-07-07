#include "api/rest_server.hpp"
#include "api/httplib.h"
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <fstream>

using json = nlohmann::json;

namespace pnads {

// Chuyển TimePoint sang chuỗi ISO8601 giờ Việt Nam (UTC+7)
static std::string tp_to_iso(const TimePoint& tp) {
    // Thêm 7 giờ để chuyển sang giờ Việt Nam
    auto vn_tp   = tp + std::chrono::hours(7);
    auto c_time  = Clock::to_time_t(vn_tp);
    std::tm tm   = *std::gmtime(&c_time);
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S+07:00");
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

RestServer::RestServer(const std::string& conn_str, int port, PcapQueueManager* queue_mgr)
    : conn_str_(conn_str),
      db_own_(std::make_unique<DbManager>(conn_str)),
      db_(*db_own_),
      port_(port), queue_mgr_(queue_mgr),
      start_time_(std::chrono::steady_clock::now()) {
    srv_ = std::make_unique<httplib::Server>();
    
    // Đảm bảo thư mục upload tồn tại
    std::filesystem::create_directories("/tmp/uploads");

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
    // Phục vụ các file tĩnh (giao diện web dashboard)
    srv_->set_mount_point("/", "./web");

    // Thêm CORS headers (dành cho môi trường dev)
    srv_->set_pre_routing_handler([](const httplib::Request&, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // Bắt lỗi toàn cục — luôn trả JSON, không để body rỗng
    srv_->set_exception_handler([](const httplib::Request&, httplib::Response& res, std::exception_ptr ep) {
        std::string msg = "Internal server error";
        try { if (ep) std::rethrow_exception(ep); }
        catch (const std::exception& e) { msg = e.what(); }
        catch (...) {}
        spdlog::error("[REST] Unhandled exception: {}", msg);
        res.status = 500;
        res.set_content("{\"error\":\"" + msg + "\"}", "application/json");
    });

    // Kiểm tra trạng thái (Health)
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

    // GET /api/assets
    // Hỗ trợ: ?active=true&page=1&page_size=20
    // Trả về: {data:[...], total, page, page_size, total_pages}
    srv_->Get("/api/assets", [this](const httplib::Request& req, httplib::Response& res) {
        bool active_only = req.has_param("active") && req.get_param_value("active") == "true";
        int  page      = 1;
        int  page_size = 20;
        try {
            if (req.has_param("page"))      page      = std::stoi(req.get_param_value("page"));
            if (req.has_param("page_size")) page_size = std::stoi(req.get_param_value("page_size"));
        } catch (...) {}

        auto pr = db_.get_all_assets_paged(active_only, page, page_size);
        json arr = json::array();
        for (const auto& a : pr.data) arr.push_back(asset_to_json(a));
        json r = {
            {"data",        arr},
            {"total",       pr.total},
            {"page",        pr.page},
            {"page_size",   pr.page_size},
            {"total_pages", pr.total_pages}
        };
        res.set_content(r.dump(), "application/json");
    });

    // GET /api/assets/:mac
    srv_->Get(R"(/api/assets/([^/]+))", [this](const httplib::Request& req, httplib::Response& res) {
        std::string mac = req.matches[1];
        auto asset = db_.find_asset_by_mac(mac);
        if (!asset) { res.status = 404; res.set_content("{\"error\":\"not found\"}", "application/json"); return; }
        res.set_content(asset_to_json(*asset).dump(), "application/json");
    });

    // GET /api/assets/:mac/events
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

    // GET /api/events
    // Hỗ trợ: ?type=&protocol=&page=1&page_size=20
    srv_->Get("/api/events", [this](const httplib::Request& req, httplib::Response& res) {
        std::string type_f  = req.has_param("type")     ? req.get_param_value("type")     : "";
        std::string proto_f = req.has_param("protocol") ? req.get_param_value("protocol") : "";
        int page      = 1;
        int page_size = 20;
        try {
            if (req.has_param("page"))      page      = std::stoi(req.get_param_value("page"));
            if (req.has_param("page_size")) page_size = std::stoi(req.get_param_value("page_size"));
        } catch (...) {}

        auto pr = db_.get_events_paged(type_f, proto_f, page, page_size);
        json arr = json::array();
        for (const auto& er : pr.data) {
            json ev;
            ev["id"]         = er.id;
            ev["asset_id"]   = er.asset_id;
            ev["mac"]        = er.mac;
            ev["event_type"] = er.event_type;
            ev["protocol"]   = er.protocol;
            ev["old_value"]  = er.old_value;
            ev["new_value"]  = er.new_value;
            ev["ts"]         = er.ts;
            arr.push_back(ev);
        }
        json r = {
            {"data",        arr},
            {"total",       pr.total},
            {"page",        pr.page},
            {"page_size",   pr.page_size},
            {"total_pages", pr.total_pages}
        };
        res.set_content(r.dump(), "application/json");
    });


    // GET /api/alerts
    // Hỗ trợ: ?ack=false&severity=high&page=1&page_size=20
    srv_->Get("/api/alerts", [this](const httplib::Request& req, httplib::Response& res) {
        bool        unacked = req.has_param("ack") && req.get_param_value("ack") == "false";
        std::string sev     = req.has_param("severity") ? req.get_param_value("severity") : "";
        int page      = 1;
        int page_size = 20;
        try {
            if (req.has_param("page"))      page      = std::stoi(req.get_param_value("page"));
            if (req.has_param("page_size")) page_size = std::stoi(req.get_param_value("page_size"));
        } catch (...) {}

        auto pr = db_.get_alerts_paged(unacked, sev, page, page_size);
        json arr = json::array();
        for (const auto& a : pr.data) {
            json item;
            item["id"]           = a.id;
            item["asset_id"]     = a.asset_id;
            item["rule_type"]    = a.rule_type;
            item["severity"]     = a.severity;
            item["message"]      = a.message;
            item["acknowledged"] = a.acknowledged;
            item["ts"]           = a.ts;
            arr.push_back(item);
        }
        json r = {
            {"data",        arr},
            {"total",       pr.total},
            {"page",        pr.page},
            {"page_size",   pr.page_size},
            {"total_pages", pr.total_pages}
        };
        res.set_content(r.dump(), "application/json");
    });


    // POST /api/alerts/:id/ack
    srv_->Post(R"(/api/alerts/(\d+)/ack)", [this](const httplib::Request& req, httplib::Response& res) {
        int id = std::stoi(req.matches[1]);
        db_.ack_alert(id);
        res.set_content("{\"ok\":true}", "application/json");
    });

    // GET /api/watchlist
    srv_->Get("/api/watchlist", [this](const httplib::Request&, httplib::Response& res) {
        auto list = db_.get_watchlist();
        json arr = json::array();
        for (const auto& e : list) {
            arr.push_back({{"id",e.id},{"mac",e.mac},{"ip",e.ip},
                           {"label",e.label},{"note",e.note}});
        }
        res.set_content(arr.dump(), "application/json");
    });

    // POST /api/watchlist
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

    // DELETE /api/watchlist/:id
    srv_->Delete(R"(/api/watchlist/(\d+))", [this](const httplib::Request& req, httplib::Response& res) {
        int id = std::stoi(req.matches[1]);
        db_.delete_watchlist(id);
        res.set_content("{\"ok\":true}", "application/json");
    });

    // GET /api/stats
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

    // GET /api/stats/timeseries
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

    // GET /api/pcap/queue
    srv_->Get("/api/pcap/queue", [this](const httplib::Request&, httplib::Response& res) {
        if (!queue_mgr_) {
            res.status = 501;
            res.set_content("{\"error\":\"PCAP Queue not enabled\"}", "application/json");
            return;
        }
        std::lock_guard<std::mutex> lock(queue_mgr_->mutex);
        json queue_arr = json::array();
        for (const auto& q : queue_mgr_->queue) queue_arr.push_back(q);
        json r = {
            {"current", queue_mgr_->current_pcap},
            {"queue",   queue_arr},
            {"mode",    queue_mgr_->current_pcap.empty() ? "idle" :
                        (queue_arr.empty() ? "stable_loop" : "priority")}
        };
        res.set_content(r.dump(), "application/json");
    });

    // GET /api/pcap/status
    // Alias endpoint for frontend status display
    srv_->Get("/api/pcap/status", [this](const httplib::Request&, httplib::Response& res) {
        if (!queue_mgr_) {
            json r = {{"mode", "unknown"}, {"current", ""}, {"queue_size", 0}};
            res.set_content(r.dump(), "application/json");
            return;
        }
        std::lock_guard<std::mutex> lock(queue_mgr_->mutex);
        std::string mode = "idle";
        if (!queue_mgr_->current_pcap.empty()) {
            mode = queue_mgr_->queue.empty() ? "stable_loop" : "priority";
        }
        // Chỉ trả về tên file, không lấy đường dẫn
        std::string cur = queue_mgr_->current_pcap;
        if (!cur.empty()) {
            auto pos = cur.find_last_of("/\\");
            if (pos != std::string::npos) cur = cur.substr(pos + 1);
        }
        json r = {
            {"mode",       mode},
            {"current",    cur},
            {"queue_size", static_cast<int>(queue_mgr_->queue.size())}
        };
        res.set_content(r.dump(), "application/json");
    });


    // POST /api/pcap/upload
    srv_->Post("/api/pcap/upload", [this](const httplib::Request& req, httplib::Response& res) {
        if (!queue_mgr_) {
            res.status = 501;
            res.set_content("{\"error\":\"PCAP Queue not enabled\"}", "application/json");
            return;
        }

        std::string filename = "uploaded.pcap";
        if (req.has_param("filename")) {
            filename = req.get_param_value("filename");
        }
        
        // Thêm timestamp để tránh trùng tên
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::string dest_path = std::format("/tmp/uploads/{}_{}", ms, filename);

        std::ofstream ofs(dest_path, std::ios::binary);
        if (!ofs) {
            res.status = 500;
            res.set_content("{\"error\":\"Cannot save file\"}", "application/json");
            return;
        }
        ofs.write(req.body.data(), req.body.size());
        ofs.close();

        queue_mgr_->push(dest_path);
        
        json r = {{"status", "ok"}, {"file", filename}};
        res.set_content(r.dump(), "application/json");
    });
}

} // namespace pnads

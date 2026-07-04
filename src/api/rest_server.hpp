#pragma once
#include "db/db_manager.hpp"
#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <chrono>

namespace httplib { class Server; }

namespace pnads {

class RestServer {
public:
    // REST API đọc trực tiếp từ DB — không cần tham chiếu AssetTracker
    RestServer(DbManager& db, int port);
    ~RestServer();

    void start();  // non-blocking, starts in background thread
    void stop();

private:
    DbManager&            db_;
    int                   port_;
    std::atomic<bool>     running_{false};
    std::thread           thread_;
    std::unique_ptr<httplib::Server> srv_;
    std::chrono::steady_clock::time_point start_time_;

    void setup_routes();
};

} // namespace pnads

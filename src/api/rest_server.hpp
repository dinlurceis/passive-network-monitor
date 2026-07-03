#pragma once
#include "db/db_manager.hpp"
#include "tracker/asset_tracker.hpp"
#include <string>
#include <thread>
#include <atomic>
#include <memory>

// Forward declare httplib::Server to avoid including httplib.h in the header
namespace httplib {
    class Server;
}

namespace netmon {

class RestServer {
public:
    RestServer(DbManager& db, AssetTracker& tracker, int port);
    ~RestServer();

    void start();  // non-blocking, starts in background thread
    void stop();

private:
    DbManager&        db_;
    AssetTracker&     tracker_;
    int               port_;
    std::atomic<bool> running_{false};
    std::thread       thread_;
    std::unique_ptr<httplib::Server> srv_;

    void setup_routes();
};

} // namespace netmon

#pragma once
#include "db/db_manager.hpp"
#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <chrono>
#include <deque>
#include <mutex>
#include <condition_variable>

namespace httplib { class Server; }

namespace pnads {

struct PcapQueueManager {
    std::deque<std::string> queue;
    std::mutex mutex;
    std::condition_variable cv;
    std::string current_pcap = "";

    void push(const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex);
        queue.push_back(path);
        cv.notify_one();
    }
};

class RestServer {
public:
    // Nhận conn_str để tạo DB connection riêng — tránh race với tracker thread
    explicit RestServer(const std::string& conn_str, int port, PcapQueueManager* queue_mgr = nullptr);
    ~RestServer();

    void start();  // không chặn, chạy ngầm trong thread
    void stop();

private:
    std::string           conn_str_;    // giữ lại để tạo DbManager riêng
    std::unique_ptr<DbManager> db_own_; // sở hữu kết nối riêng, độc lập với tracker
    DbManager&            db_;          // reference to db_own_
    int                   port_;
    PcapQueueManager*     queue_mgr_;
    std::atomic<bool>     running_{false};
    std::thread           thread_;
    std::unique_ptr<httplib::Server> srv_;
    std::chrono::steady_clock::time_point start_time_;

    void setup_routes();
};

} // namespace pnads

#pragma once
#include "detection/detection_engine.hpp"
#include "db/db_manager.hpp"
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <chrono>
#include <string>

namespace pnads {

// Phát hiện ARP spoofing: đếm số MAC khác nhau cùng claim một IP trong cửa sổ window_sec.
// State giữ trong memory, không query DB mỗi event cho đỡ nặng.
// Bắn alert khi số MAC phân biệt >= mac_threshold trong window.
class RuleArpSpoofing : public IDetectionRule {
public:
    RuleArpSpoofing(DbManager& db, int window_sec, int mac_threshold)
        : db_(db), window_sec_(window_sec), mac_threshold_(mac_threshold) {}

    std::vector<Alert> evaluate(const Asset& asset,
                                 const std::string& event_type,
                                 const std::string& protocol,
                                 const std::string& detail_json) override;

private:
    DbManager& db_;
    int        window_sec_;
    int        mac_threshold_;

    // Cửa sổ trượt cho mỗi IP: deque các cặp {timestamp, mac}
    using Clock    = std::chrono::steady_clock;
    using TP       = std::chrono::time_point<Clock>;
    struct Entry   { TP ts; std::string mac; };
    std::unordered_map<std::string, std::deque<Entry>> window_;  // IP -> danh sách event

    // Bỏ các entry cũ hơn window_sec khỏi deque của một IP
    void prune(const std::string& ip);
};

} // namespace pnads

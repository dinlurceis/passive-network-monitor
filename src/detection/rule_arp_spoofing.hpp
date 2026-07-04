#pragma once
#include "detection/detection_engine.hpp"
#include "db/db_manager.hpp"

namespace pnads {

// Phát hiện xung đột IP↔MAC: nếu 1 IP được claim bởi >= threshold MAC khác nhau
// trong cửa sổ thời gian window_sec → nghi vấn ARP spoofing.
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
};

} // namespace pnads

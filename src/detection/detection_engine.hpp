#pragma once
#include "detection/alert.hpp"
#include "tracker/asset.hpp"
#include "db/db_manager.hpp"
#include <vector>
#include <memory>

namespace pnads {

// Interface chung cho mỗi rule — dễ thêm rule mới mà không sửa engine.
class IDetectionRule {
public:
    virtual ~IDetectionRule() = default;
    virtual std::vector<Alert> evaluate(const Asset& asset,
                                         const std::string& event_type,
                                         const std::string& protocol,
                                         const std::string& detail_json) = 0;
};

class DetectionEngine {
public:
    explicit DetectionEngine(DbManager& db);

    void add_rule(std::unique_ptr<IDetectionRule> rule);

    // Gọi từ AssetTracker::EventCallback ngay sau khi event được ghi vào DB.
    // Chạy tuần tự trong CÙNG thread capture — không cần mutex/queue.
    void on_event(const Asset& asset,
                  const std::string& event_type,
                  const std::string& protocol,
                  const std::string& detail_json);

private:
    DbManager& db_;
    std::vector<std::unique_ptr<IDetectionRule>> rules_;
};

} // namespace pnads

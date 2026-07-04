#pragma once
#include "detection/detection_engine.hpp"

namespace pnads {

// Cảnh báo khi asset chưa từng thấy (event_type == "new_asset").
// Chỉ kích hoạt đúng 1 lần trong vòng đời asset.
class RuleNewDevice : public IDetectionRule {
public:
    std::vector<Alert> evaluate(const Asset& asset,
                                 const std::string& event_type,
                                 const std::string& protocol,
                                 const std::string& detail_json) override;
};

} // namespace pnads

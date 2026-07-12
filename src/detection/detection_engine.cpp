#include "detection/detection_engine.hpp"
#include <spdlog/spdlog.h>

namespace pnads {

DetectionEngine::DetectionEngine(DbManager& db) : db_(db) {}

void DetectionEngine::add_rule(std::unique_ptr<IDetectionRule> rule) {
    rules_.push_back(std::move(rule));
}

void DetectionEngine::on_event(const Asset& asset,
                                const std::string& event_type,
                                const std::string& protocol,
                                const std::string& detail_json) {
    for (auto& rule : rules_) {
        try {
            auto alerts = rule->evaluate(asset, event_type, protocol, detail_json);
            for (const auto& alert : alerts) {
                db_.insert_alert(alert.asset_id, alert.rule_type,
                                 severity_str(alert.severity),
                                 alert.message, alert.detail_json);
                spdlog::warn("[ALERT][{}][{}] asset_id={} msg={}",
                             alert.rule_type, severity_str(alert.severity),
                             alert.asset_id, alert.message);
            }
        } catch (const std::exception& e) {
            spdlog::error("[DetectionEngine] rule failed: {}", e.what());
        }
    }
}

} // namespace pnads

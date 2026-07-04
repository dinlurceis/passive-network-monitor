#pragma once
#include "detection/detection_engine.hpp"
#include "db/db_manager.hpp"

namespace pnads {

// Khớp MAC/IP asset với bảng watchlist trong DB.
// Query DB mỗi lần event — không cache để luôn nhận watchlist mới nhất.
class RuleWatchlist : public IDetectionRule {
public:
    explicit RuleWatchlist(DbManager& db) : db_(db) {}

    std::vector<Alert> evaluate(const Asset& asset,
                                 const std::string& event_type,
                                 const std::string& protocol,
                                 const std::string& detail_json) override;

private:
    DbManager& db_;
};

} // namespace pnads

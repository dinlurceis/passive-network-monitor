#pragma once
#include <string>

namespace pnads {

enum class Severity { Low, Medium, High };

struct Alert {
    int         asset_id;
    std::string rule_type;
    Severity    severity;
    std::string message;
    std::string detail_json = "{}";
};

inline std::string severity_str(Severity s) {
    switch (s) {
        case Severity::Low:    return "low";
        case Severity::High:   return "high";
        default:               return "medium";
    }
}

} // namespace pnads

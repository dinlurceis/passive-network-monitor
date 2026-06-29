#include "os_fingerprint.hpp"
#include <algorithm>
#include <numeric>

namespace netmon {

// ─── Signature database ───────────────────────────────────────────────────────
//
// Mỗi entry trong database là:
//   - signature: danh sách option code theo thứ tự đặc trưng của từng OS
//   - os_family: tên hệ điều hành
//   - detail: phiên bản / biến thể
//
// Nguồn tham khảo: Wireshark, fingerbank.org, nghiên cứu DHCP fingerprinting.
// Lưu ý: đây là heuristic — không đảm bảo 100% chính xác.
//
struct Signature {
    std::vector<uint8_t> options; // thứ tự option codes trong Option 55
    const char*          os_family;
    const char*          detail;
    float                base_confidence;
};

// clang-format off
static const Signature kSignatures[] = {
    // Windows
    { {1,15,3,6,44,46,47,31,33,121,249,43},         "Windows", "Windows XP",    0.85f },
    { {1,15,3,6,44,46,47,31,33,121,249,43,252},      "Windows", "Windows 7/10",  0.90f },
    { {1,15,3,6,44,46,47,31,33,121,249,43,252,12},   "Windows", "Windows 10/11", 0.88f },
    { {1,3,6,15,31,33,43,44,46,47,119,121,249,252},  "Windows", "Windows 10",    0.87f },

    // Linux
    { {1,28,2,3,15,6,12,40,41,42},                   "Linux",   "Linux (generic)", 0.80f },
    { {1,2,3,4,5,6,7,11,12,13,15,16,17,18,43,54},    "Linux",   "Linux (dhclient)",0.82f },
    { {1,3,6,12,15,28,42},                            "Linux",   "Linux (udhcpc)",  0.78f },

    // macOS
    { {1,121,3,6,15,119,252,95,44,46},               "macOS",   "macOS (modern)", 0.88f },
    { {1,121,3,6,15,119,252,95,44,46,47},             "macOS",   "macOS 10.x",    0.86f },
    { {1,3,6,15,119,252},                             "macOS",   "macOS (minimal)",0.75f },

    // iOS / iPadOS
    { {1,121,3,6,15,119,252},                         "iOS",     "iOS/iPadOS",    0.82f },
    { {1,121,3,6,15,119,252,44,46},                   "iOS",     "iOS (older)",   0.78f },

    // Android
    { {1,33,3,6,15,28,51,58,59},                      "Android", "Android",       0.83f },
    { {1,3,6,12,15,17,23,28,29,31,33,40,41,42,43},    "Android", "Android (AOSP)",0.80f },
};
// clang-format on

// ─── Hàm tính điểm giống nhau giữa 2 danh sách option ───────────────────────
//
// Thuật toán: đếm số option xuất hiện ở cả 2 danh sách (intersection).
// Chia cho max(len1, len2) để chuẩn hoá về [0, 1].
//
// Đây là cách đơn giản nhất, không tính đến thứ tự.
// (Cách nâng cao hơn là Longest Common Subsequence hoặc Jaccard Index)
//
static float similarity_score(const std::vector<uint8_t>& observed,
                               const std::vector<uint8_t>& signature) {
    if (observed.empty() || signature.empty()) return 0.0f;

    size_t matches = 0;
    for (uint8_t opt : observed) {
        if (std::find(signature.begin(), signature.end(), opt) != signature.end()) {
            ++matches;
        }
    }

    // Mẫu số: lấy cái lớn hơn để phạt khi signature quá khác observed
    size_t denom = std::max(observed.size(), signature.size());
    return static_cast<float>(matches) / static_cast<float>(denom);
}

// ─── fingerprint_from_dhcp_options ───────────────────────────────────────────
OsFingerprint fingerprint_from_dhcp_options(
    const std::vector<uint8_t>& param_request_list)
{
    if (param_request_list.empty()) {
        return {"Unknown", "", 0.0f};
    }

    float       best_score  = 0.0f;
    const char* best_family = "Unknown";
    const char* best_detail = "";
    float       best_conf   = 0.0f;

    for (const auto& sig : kSignatures) {
        // Tính điểm tương đồng với signature này
        float sim = similarity_score(param_request_list, sig.options);

        // Điểm cuối cùng = điểm tương đồng × base_confidence của signature
        float final_score = sim * sig.base_confidence;

        if (final_score > best_score) {
            best_score  = final_score;
            best_family = sig.os_family;
            best_detail = sig.detail;
            best_conf   = sim;     // confidence = tỷ lệ trùng khớp
        }
    }

    // Nếu điểm tốt nhất quá thấp, coi như không xác định được
    if (best_score < 0.35f) {
        return {"Unknown", "", best_score};
    }

    return {best_family, best_detail, best_conf};
}

} // namespace netmon

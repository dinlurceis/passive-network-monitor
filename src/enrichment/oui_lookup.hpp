#pragma once
#include <string>
#include <unordered_map>

namespace netmon {

// OuiLookup — tra cứu tên nhà sản xuất (vendor) từ địa chỉ MAC.
//
// Nguyên lý hoạt động:
//   Địa chỉ MAC có 6 byte, ví dụ: "4C:32:75:AB:CD:EF"
//   3 byte đầu (OUI — Organizationally Unique Identifier) được IEEE
//   cấp phát cho từng nhà sản xuất. Ví dụ: "4C:32:75" → "Apple, Inc."
//
//   Class này load một file CSV chứa ánh xạ OUI → vendor name,
//   sau đó cho phép tra cứu nhanh qua unordered_map (O(1) average).
//
class OuiLookup {
public:
    // Đọc file CSV. Format mỗi dòng: "AA:BB:CC","Vendor Name"
    // Nếu file không tồn tại, loaded() sẽ trả false — không throw.
    explicit OuiLookup(const std::string& oui_file);

    // Tra cứu vendor từ địa chỉ MAC đầy đủ.
    // Input:  "4C:32:75:AB:CD:EF" (bất kỳ độ dài nào, tối thiểu 8 ký tự)
    // Output: tên vendor hoặc "Unknown" nếu không tìm thấy.
    std::string lookup(const std::string& mac) const;

    size_t size()   const { return table_.size(); }
    bool   loaded() const { return loaded_; }

private:
    // Key: "AA:BB:CC" (uppercase, 3 byte đầu của MAC)
    // Value: tên vendor
    std::unordered_map<std::string, std::string> table_;
    bool loaded_ = false;
};

} // namespace netmon

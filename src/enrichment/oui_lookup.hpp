#pragma once
#include <string>
#include <unordered_map>
#include <optional>

namespace pnads {

// OuiLookup — tra cứu tên nhà sản xuất (vendor) từ địa chỉ MAC.
// 3 byte đầu (OUI) → vendor name.
class OuiLookup {
public:
    // Đọc file CSV. Format mỗi dòng: "AA:BB:CC","Vendor Name"
    // Nếu file không tồn tại, loaded() trả false — không throw.
    explicit OuiLookup(const std::string& oui_file);

    // Tra cứu vendor từ địa chỉ MAC đầy đủ.
    // Input:  "4C:32:75:AB:CD:EF" (tối thiểu 8 ký tự)
    // Output: std::optional<std::string> — nullopt nếu không tìm thấy
    std::optional<std::string> lookup(const std::string& mac) const;

    size_t size()   const { return table_.size(); }
    bool   loaded() const { return loaded_; }

private:
    std::unordered_map<std::string, std::string> table_; // "AA:BB:CC" → vendor
    bool loaded_ = false;
};

} // namespace pnads

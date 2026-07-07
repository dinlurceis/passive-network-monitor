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

    // Kiểm tra MAC có phải là "Locally Administered" (random) không.
    // Bit 1 của byte đầu tiên (LSB của octet 0) = 1 → locally administered
    // → nhiều khả năng là MAC được randomize bởi OS (iOS 14+, Android 10+, Win 10+)
    // Input: "AA:BB:CC:DD:EE:FF"
    static bool is_randomized_mac(const std::string& mac);

    // Kiểm tra MAC có phải multicast/broadcast không.
    // Bit 0 của byte đầu tiên = 1 → multicast (FF:FF:FF:FF:FF:FF là trường hợp đặc biệt)
    static bool is_multicast_mac(const std::string& mac);

private:
    std::unordered_map<std::string, std::string> table_; // "AA:BB:CC" → vendor
    bool loaded_ = false;
};

} // namespace pnads

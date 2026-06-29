#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace netmon {

// OsFingerprint — kết quả đoán hệ điều hành từ DHCP traffic.
//
// Kỹ thuật này gọi là "passive OS fingerprinting":
//   - Hệ thống chỉ QUAN SÁT gói tin DHCP mà thiết bị gửi đi.
//   - Không chủ động gửi thêm gói tin nào để dò hỏi.
//
// DHCP Option 55 (Parameter Request List):
//   Khi một thiết bị xin địa chỉ IP (DHCP Discover/Request), nó sẽ kèm
//   theo danh sách các tùy chọn mà nó muốn nhận từ server (ví dụ: subnet mask,
//   default gateway, DNS server, ...).
//   Danh sách này (option 55) rất đặc trưng cho từng hệ điều hành và
//   phiên bản khác nhau, giống như "dấu vân tay" (fingerprint).
//
struct OsFingerprint {
    std::string os_family;   // "Windows", "Linux", "macOS", "iOS", "Android", "Unknown"
    std::string detail;      // phiên bản nếu có thể xác định được
    float       confidence;  // độ tin cậy từ 0.0 đến 1.0
};

// Đoán OS dựa trên nội dung của DHCP Option 55.
// Input: param_request_list lấy từ DhcpInfo.param_request_list
// Output: OsFingerprint với os_family, detail, confidence
OsFingerprint fingerprint_from_dhcp_options(
    const std::vector<uint8_t>& param_request_list);

} // namespace netmon

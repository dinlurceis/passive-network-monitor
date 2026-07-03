#pragma once
#include <string>
#include <optional>

namespace pnads {

// Chỉ cần bắt request line + header "User-Agent:" từ payload TCP port 80.
// Không cần reassembly TCP đầy đủ — đa số User-Agent nằm trọn trong segment đầu.
std::optional<std::string> extract_user_agent(const uint8_t* tcp_payload, size_t len);

} // namespace pnads

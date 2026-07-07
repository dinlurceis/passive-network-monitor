#pragma once
#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <optional>
#include <span>

namespace pnads {

// Đọc tuần tự một buffer byte theo network byte order.
// Mọi hàm read_* tự tăng con trỏ nội bộ và trả std::nullopt nếu vượt biên,
// nhờ vậy parser gọi tuần tự các hàm này mà không cần tự tính offset.
class BinaryReader {
public:
    BinaryReader(const uint8_t* data, size_t len) : data_(data), len_(len), pos_(0) {}

    bool   has(size_t n)    const { return pos_ + n <= len_; }
    size_t remaining()      const { return len_ - pos_; }
    size_t offset()         const { return pos_; }

    std::optional<uint8_t>  read_u8();
    std::optional<uint16_t> read_u16();   // big-endian (lưu byte lớn ở đầu, byte nhỏ ở sau)
    std::optional<uint32_t> read_u32();   // big-endian (lưu byte lớn ở đầu, byte nhỏ ở sau)
    std::optional<std::array<uint8_t, 6>> read_mac();
    std::optional<std::string> read_ipv4_str();   // "192.168.1.1"
    std::optional<std::string> read_ipv6_str();
    std::optional<std::string> read_fixed_string(size_t len); // đọc len byte, strip \0
    std::optional<std::span<const uint8_t>> read_bytes(size_t n);
    bool skip(size_t n);

    // Đọc một dòng text kết thúc bởi "\r\n" (dùng cho SSDP/HTTP header)
    std::optional<std::string> read_line();

    // Peek không tăng con trỏ — cần cho DNS name-pointer compression
    const uint8_t* raw()       const { return data_; }
    size_t         total_len() const { return len_; }

private:
    const uint8_t* data_;
    size_t         len_;
    size_t         pos_;
};

} // namespace pnads

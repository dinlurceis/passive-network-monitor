#include "util/binary_reader.hpp"
#include <format>
#include <algorithm>

namespace pnads {

std::optional<uint8_t> BinaryReader::read_u8() {
    if (!has(1)) return std::nullopt;
    return data_[pos_++];
}

std::optional<uint16_t> BinaryReader::read_u16() {
    if (!has(2)) return std::nullopt;
    uint16_t v = static_cast<uint16_t>((data_[pos_] << 8) | data_[pos_ + 1]);
    pos_ += 2;
    return v;
}

std::optional<uint32_t> BinaryReader::read_u32() {
    if (!has(4)) return std::nullopt;
    uint32_t v = (static_cast<uint32_t>(data_[pos_])     << 24) |
                 (static_cast<uint32_t>(data_[pos_ + 1]) << 16) |
                 (static_cast<uint32_t>(data_[pos_ + 2]) <<  8) |
                  static_cast<uint32_t>(data_[pos_ + 3]);
    pos_ += 4;
    return v;
}

std::optional<std::array<uint8_t, 6>> BinaryReader::read_mac() {
    if (!has(6)) return std::nullopt;
    std::array<uint8_t, 6> mac;
    for (int i = 0; i < 6; ++i) mac[i] = data_[pos_++];
    return mac;
}

std::optional<std::string> BinaryReader::read_ipv4_str() {
    if (!has(4)) return std::nullopt;
    std::string s = std::format("{}.{}.{}.{}",
        data_[pos_], data_[pos_+1], data_[pos_+2], data_[pos_+3]);
    pos_ += 4;
    return s;
}

std::optional<std::string> BinaryReader::read_ipv6_str() {
    if (!has(16)) return std::nullopt;
    // Format as compressed IPv6
    std::string s;
    for (int i = 0; i < 16; i += 2) {
        if (i > 0) s += ':';
        s += std::format("{:x}", (static_cast<uint16_t>(data_[pos_+i]) << 8) |
                                   data_[pos_+i+1]);
    }
    pos_ += 16;
    return s;
}

std::optional<std::string> BinaryReader::read_fixed_string(size_t len) {
    if (!has(len)) return std::nullopt;
    // Cắt bỏ các byte null ở cuối
    size_t end = len;
    while (end > 0 && data_[pos_ + end - 1] == 0) --end;
    std::string s(reinterpret_cast<const char*>(data_ + pos_), end);
    pos_ += len;
    return s;
}

std::optional<std::span<const uint8_t>> BinaryReader::read_bytes(size_t n) {
    if (!has(n)) return std::nullopt;
    std::span<const uint8_t> sp(data_ + pos_, n);
    pos_ += n;
    return sp;
}

bool BinaryReader::skip(size_t n) {
    if (!has(n)) return false;
    pos_ += n;
    return true;
}

std::optional<std::string> BinaryReader::read_line() {
    // Tìm "\r\n" từ vị trí hiện tại
    for (size_t i = pos_; i + 1 < len_; ++i) {
        if (data_[i] == '\r' && data_[i + 1] == '\n') {
            std::string line(reinterpret_cast<const char*>(data_ + pos_), i - pos_);
            pos_ = i + 2;
            return line;
        }
    }
    // K tìm thấy \r\n found —> tìm \n
    for (size_t i = pos_; i < len_; ++i) {
        if (data_[i] == '\n') {
            std::string line(reinterpret_cast<const char*>(data_ + pos_), i - pos_);
            pos_ = i + 1;
            return line;
        }
    }
    return std::nullopt;
}

} // namespace pnads

#pragma once
#include <string>
#include <functional>
#include <cstdint>
#include <cstddef>
#include <atomic>

// Forward declare để không phải include pcap.h ở header
struct pcap;
typedef struct pcap pcap_t;

namespace pnads {

struct RawPacket {
    const uint8_t* data;
    size_t         len;
    long           ts_sec;
    int            ts_usec;
};

using PacketCallback = std::function<void(const RawPacket&)>;

class PcapReader {
public:
    // file_or_iface: đường dẫn .pcap file hoặc tên interface ("eth0")
    // live: true = live capture (cần root/CAP_NET_RAW), false = đọc file
    explicit PcapReader(const std::string& file_or_iface, bool live = false);
    ~PcapReader();

    // Thiết lập BPF filter (ví dụ: "arp or (udp port 67)")
    // Gọi trước start(). Trả về false nếu filter không hợp lệ.
    bool set_filter(const std::string& filter_expr);

    // Bắt đầu vòng lặp capture. Blocking.
    // Gọi stop() từ thread khác để dừng.
    void start(PacketCallback cb);

    // Dừng vòng lặp (thread-safe)
    void stop();

    bool is_live() const { return live_; }

private:
    pcap_t*             handle_ = nullptr;
    bool                live_;
    std::atomic<bool>   running_{false};

    // Không cho copy
    PcapReader(const PcapReader&)            = delete;
    PcapReader& operator=(const PcapReader&) = delete;
};

} // namespace pnads

#include "pcap_reader.hpp"
#include <pcap.h>
#include <stdexcept>
#include <format>

namespace netmon {

// Static dispatch callback for pcap_loop
static void pcap_dispatch_cb(uint8_t* user,
                              const struct pcap_pkthdr* header,
                              const uint8_t* packet) {
    auto* ctx = reinterpret_cast<std::pair<PacketCallback*, std::atomic<bool>*>*>(user);
    PacketCallback* cb = ctx->first;

    RawPacket pkt{};
    pkt.data    = packet;
    pkt.len     = header->caplen;
    pkt.ts_sec  = static_cast<long>(header->ts.tv_sec);
    pkt.ts_usec = static_cast<int>(header->ts.tv_usec);

    (*cb)(pkt);
}

PcapReader::PcapReader(const std::string& file_or_iface, bool live)
    : live_(live)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {};

    if (!live) {
        handle_ = pcap_open_offline(file_or_iface.c_str(), errbuf);
    } else {
        // snaplen=65535, promiscuous=1, timeout_ms=1000
        handle_ = pcap_open_live(file_or_iface.c_str(), 65535, 1, 1000, errbuf);
    }

    if (!handle_) {
        throw std::runtime_error(
            std::format("PcapReader: cannot open '{}': {}", file_or_iface, errbuf));
    }
}

PcapReader::~PcapReader() {
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

bool PcapReader::set_filter(const std::string& filter_expr) {
    struct bpf_program bpf{};
    if (pcap_compile(handle_, &bpf, filter_expr.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
        return false;
    }
    bool ok = (pcap_setfilter(handle_, &bpf) == 0);
    pcap_freecode(&bpf);
    return ok;
}

void PcapReader::start(PacketCallback cb) {
    running_ = true;

    // Context: pair of (callback ptr, running flag ptr)
    // We use pcap_loop with a static dispatch function
    auto ctx = std::make_pair(&cb, &running_);

    // pcap_loop returns:
    //  0  = count packets processed
    // -1  = error
    // -2  = pcap_breakloop() called
    pcap_loop(handle_, 0,
        [](uint8_t* user, const struct pcap_pkthdr* hdr, const uint8_t* pkt) {
            auto* c = reinterpret_cast<std::pair<PacketCallback*, std::atomic<bool>*>*>(user);
            RawPacket raw{};
            raw.data    = pkt;
            raw.len     = hdr->caplen;
            raw.ts_sec  = static_cast<long>(hdr->ts.tv_sec);
            raw.ts_usec = static_cast<int>(hdr->ts.tv_usec);
            (*c->first)(raw);
        },
        reinterpret_cast<uint8_t*>(&ctx));

    running_ = false;
}

void PcapReader::stop() {
    running_ = false;
    if (handle_) {
        pcap_breakloop(handle_);
    }
}

} // namespace netmon

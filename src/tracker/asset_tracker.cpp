#include "asset_tracker.hpp"
#include <spdlog/spdlog.h>
#include <format>
#include <chrono>

namespace netmon {

// Constructor — nhận cả DbManager lẫn OuiLookup qua tham chiếu
AssetTracker::AssetTracker(DbManager& db, OuiLookup& oui)
    : db_(db), oui_(oui) {}

// upsert_asset
// Caller MUST hold mutex_ before calling this.
Asset AssetTracker::upsert_asset(const std::string& mac, const std::string& ip) {
    // Check DB first
    auto existing = db_.find_asset_by_mac(mac);
    if (!existing) {
        // New asset — insert
        Asset a{};
        a.mac       = mac;
        a.ip        = ip;
        a.first_seen = Clock::now();
        a.last_seen  = Clock::now();
        a.is_active  = true;
        Asset saved = db_.insert_asset(a);
        cache_[mac] = saved;
        return saved;
    } else {
        // Existing asset — update last_seen
        db_.update_asset_last_seen(existing->id);
        existing->last_seen = Clock::now();
        // If IP changed, update it
        if (!ip.empty() && ip != existing->ip) {
            db_.update_asset_ip(existing->id, ip);
            existing->ip = ip;
        }
        cache_[mac] = *existing;
        return *existing;
    }
}

// log_event
void AssetTracker::log_event(const Asset& asset, const std::string& event_type,
                              const std::string& old_val, const std::string& new_val) {
    db_.insert_event(asset.id, event_type, old_val, new_val);
    spdlog::info("[{}] MAC={} IP={} old='{}' new='{}'",
                 event_type, asset.mac, asset.ip, old_val, new_val);
}

// process_arp
void AssetTracker::process_arp(const ArpFrame& frame) {
    try {
        const std::string& mac = frame.sender_mac;
        const std::string& ip  = frame.sender_ip;

        // Bỏ qua MAC không hợp lệ (null hoặc broadcast)
        if (mac == "00:00:00:00:00:00" || mac == "FF:FF:FF:FF:FF:FF") {
            return;
        }

        // ARP probe: sender_ip == 0.0.0.0 — thiết bị đang kiểm tra xem IP có ai dùng chưa
        if (frame.is_probe()) {
            std::lock_guard<std::mutex> lock(mutex_);
            Asset asset = upsert_asset(mac, "");
            log_event(asset, "arp_probe", "", frame.target_ip);
            return;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find(mac);

        if (it == cache_.end()) {
            // Thiết bị mới — lưu vào DB và gựi OUI lookup
            Asset asset = upsert_asset(mac, ip);

            // Tra cứu vendor ngay khi thấy thiết bị lần đầu
            std::string vendor = oui_.lookup(mac);
            if (vendor != "Unknown" && vendor != asset.vendor) {
                db_.update_asset_vendor(asset.id, vendor);
                cache_[mac].vendor = vendor;
                asset.vendor = vendor;
                spdlog::debug("[OUI] MAC={} vendor={}", mac, vendor);
            }

            log_event(asset, "new_asset", "", ip);
        } else {
            Asset& cached = it->second;

            // Cập nhật vendor nếu chưa có (ví dụ: asset được thấy lần đầu qua DHCP)
            if (cached.vendor.empty()) {
                std::string vendor = oui_.lookup(mac);
                if (vendor != "Unknown") {
                    db_.update_asset_vendor(cached.id, vendor);
                    cached.vendor = vendor;
                    spdlog::debug("[OUI] MAC={} vendor={} (late lookup)", mac, vendor);
                }
            }

            if (cached.ip != ip && !ip.empty()) {
                // IP thay đổi — cập nhật và ghi event
                std::string old_ip = cached.ip;
                db_.update_asset_ip(cached.id, ip);
                db_.update_asset_last_seen(cached.id);
                cached.ip       = ip;
                cached.last_seen = Clock::now();
                cached.ip_changes++;
                log_event(cached, "ip_change", old_ip, ip);
            } else {
                // Cùng IP — chỉ cập nhật last_seen
                db_.update_asset_last_seen(cached.id);
                cached.last_seen = Clock::now();
            }
        }

        // Gratuitous ARP: thiết bị thông báo IP của mình cho cả mạng
        if (frame.is_gratuitous()) {
            auto it2 = cache_.find(mac);
            if (it2 != cache_.end()) {
                log_event(it2->second, "arp_announce", ip, ip);
            }
        }
    } catch (const std::exception& e) {
        spdlog::error("process_arp failed: {}", e.what());
    }
}

// process_dhcp
void AssetTracker::process_dhcp(const DhcpInfo& info) {
    try {
        const std::string& mac = info.client_mac;
        if (mac.empty()) return;

        std::lock_guard<std::mutex> lock(mutex_);
        Asset asset = upsert_asset(mac, "");

        // Tra cứu vendor nếu chưa có (một số thiết bị chỉ xuất hiện qua DHCP)
        if (cache_[mac].vendor.empty()) {
            std::string vendor = oui_.lookup(mac);
            if (vendor != "Unknown") {
                db_.update_asset_vendor(asset.id, vendor);
                cache_[mac].vendor = vendor;
                asset.vendor = vendor;
            }
        }

        // Cập nhật hostname nếu có trong DHCP Option 12
        if (!info.hostname.empty() && info.hostname != asset.hostname) {
            db_.update_asset_hostname(asset.id, info.hostname);
            cache_[mac].hostname = info.hostname;
            asset.hostname = info.hostname;
        }

        // OS fingerprinting từ DHCP Option 55 (Parameter Request List)
        // Chỉ chạy khi có dữ liệu và chưa biết OS
        if (!info.param_request_list.empty() && cache_[mac].os_guess.empty()) {
            auto fp = fingerprint_from_dhcp_options(info.param_request_list);
            if (fp.os_family != "Unknown" && fp.confidence >= 0.5f) {
                // Lưu cả family và detail: ví dụ "Windows (Windows 10/11)"
                std::string os_str = fp.detail.empty()
                    ? fp.os_family
                    : std::format("{} ({})", fp.os_family, fp.detail);
                db_.update_asset_os_guess(asset.id, os_str);
                cache_[mac].os_guess = os_str;
                asset.os_guess = os_str;
                spdlog::info("[OS] MAC={} os_guess='{}' confidence={:.2f}",
                             mac, os_str, fp.confidence);
            }
        }

        // Ghi event theo loại DHCP message
        switch (info.msg_type) {
            case DhcpMsgType::DISCOVER:
                log_event(asset, "dhcp_discover");
                break;

            case DhcpMsgType::REQUEST: {
                std::string detail = info.requested_ip.empty() ? "{}" :
                    std::format("{{\"requested_ip\":\"{}\"}}", info.requested_ip);
                db_.insert_event(asset.id, "dhcp_request", "", info.requested_ip, detail);
                spdlog::info("[dhcp_request] MAC={} requested={}", mac, info.requested_ip);
                break;
            }

            case DhcpMsgType::ACK: {
                if (!info.your_ip.empty()) {
                    std::string old_ip = asset.ip;
                    db_.update_asset_ip(asset.id, info.your_ip);
                    cache_[mac].ip = info.your_ip;
                    std::string detail = std::format("{{\"your_ip\":\"{}\"}}", info.your_ip);
                    db_.insert_event(asset.id, "dhcp_ack", old_ip, info.your_ip, detail);
                    spdlog::info("[dhcp_ack] MAC={} your_ip={}", mac, info.your_ip);
                }
                break;
            }

            default:
                // Các loại DHCP khác (OFFER, NAK, ...) không cần theo dõi ở Phase 2
                break;
        }
    } catch (const std::exception& e) {
        spdlog::error("process_dhcp failed: {}", e.what());
    }
}

// expire_assets
void AssetTracker::expire_assets(int timeout_sec) {
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        auto stale = db_.get_assets_not_seen_since(timeout_sec);
        for (const auto& a : stale) {
            db_.set_asset_inactive(a.id);
            db_.insert_event(a.id, "asset_gone");
            cache_.erase(a.mac);
            spdlog::warn("[asset_gone] MAC={} IP={}", a.mac, a.ip);
        }
    } catch (const std::exception& e) {
        spdlog::error("expire_assets failed: {}", e.what());
    }
}

// find_by_mac
std::optional<Asset> AssetTracker::find_by_mac(const std::string& mac) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(mac);
    if (it == cache_.end()) return std::nullopt;
    return it->second;
}

// all_assets
std::vector<Asset> AssetTracker::all_assets() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Asset> result;
    result.reserve(cache_.size());
    for (const auto& [mac, asset] : cache_) {
        result.push_back(asset);
    }
    return result;
}

// active_count
size_t AssetTracker::active_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [mac, asset] : cache_) {
        if (asset.is_active) ++count;
    }
    return count;
}

} // namespace netmon

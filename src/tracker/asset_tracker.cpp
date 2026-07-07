#include "tracker/asset_tracker.hpp"
#include <spdlog/spdlog.h>
#include <format>
#include <algorithm>
#include <cctype>
#include <unordered_set>

namespace {
// Bỏ ký tự điều khiển ASCII (0x00–0x1F, 0x7F) và backslash/nháy kép
// để chuỗi an toàn khi nhúng vào JSON literal dựng thủ công.
std::string sanitize_for_json(std::string s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (c == '"')  { out += "\\\""; }
        else if (c == '\\') { out += "\\\\"; }
        else if (c < 0x20 || c == 0x7F) { /* skip control chars */ }
        else { out += static_cast<char>(c); }
    }
    return out;
}
} // namespace ẩn danh

namespace pnads {

AssetTracker::AssetTracker(DbManager& db, OuiLookup& oui, OsFingerprint& fp)
    : db_(db), oui_(oui), fp_(fp) {
    pending_events_.reserve(1024);
}

// upsert_asset
Asset& AssetTracker::upsert_asset(const std::string& mac, const std::string& ip,
                                   const std::string& source_protocol) {
    if (!ip.empty()) ip_to_mac_[ip] = mac;
    auto now = Clock::now();
    auto it = cache_.find(mac);
    if (it == cache_.end()) {
        auto existing = db_.find_asset_by_mac(mac);
        if (!existing) {
            Asset a{};
            a.mac        = mac;
            a.ip         = ip;
            a.first_seen = now;
            a.last_seen  = now;
            a.is_active  = true;
            Asset saved = db_.insert_asset(a);
            saved.discovered_via = {source_protocol};
            db_.update_asset_discovered_via(saved.id, saved.discovered_via);
            cache_[mac] = saved;
            last_db_update_[saved.id] = now;
        } else {
            existing->last_seen = now;
            auto last_it = last_db_update_.find(existing->id);
            if (last_it == last_db_update_.end() || std::chrono::duration_cast<std::chrono::seconds>(now - last_it->second).count() > 10) {
                db_.update_asset_last_seen(existing->id);
                last_db_update_[existing->id] = now;
            }
            auto& via = existing->discovered_via;
            if (std::find(via.begin(), via.end(), source_protocol) == via.end()) {
                via.push_back(source_protocol);
                db_.update_asset_discovered_via(existing->id, via);
            }
            cache_[mac] = *existing;
        }
    } else {
        Asset& cached = it->second;
        cached.last_seen = now;
        auto last_it = last_db_update_.find(cached.id);
        if (last_it == last_db_update_.end() || std::chrono::duration_cast<std::chrono::seconds>(now - last_it->second).count() > 10) {
            db_.update_asset_last_seen(cached.id);
            last_db_update_[cached.id] = now;
        }
        if (!ip.empty() && ip != cached.ip) {
            db_.update_asset_ip(cached.id, ip);
            cached.ip = ip;
        }
        auto& via = cached.discovered_via;
        if (std::find(via.begin(), via.end(), source_protocol) == via.end()) {
            via.push_back(source_protocol);
            db_.update_asset_discovered_via(cached.id, via);
        }
    }
    return cache_[mac];
}

void AssetTracker::flush_events() {
    if (pending_events_.empty()) return;
    db_.insert_events_batch(pending_events_);
    pending_events_.clear();
}

// Các event này có tần suất cao nhưng ít giá trị phân biệt → debounce 60s
static constexpr int EVENT_DEBOUNCE_SEC = 60;
static const std::unordered_set<std::string> DEBOUNCED_EVENT_TYPES = {
    "dns_query", "mdns_announce", "ssdp_notify",
    "arp_announce", "dhcp_discover", "dhcp_request"
};

void AssetTracker::log_event(const Asset& a, const std::string& type,
                              const std::string& protocol,
                              const std::string& old_v, const std::string& new_v,
                              const std::string& detail_json) {
    // Debounce: bỏ qua event lặp lại quá nhanh cho các loại không phải state-change
    if (DEBOUNCED_EVENT_TYPES.count(type)) {
        auto key = std::to_string(a.id) + ':' + type;
        auto now = Clock::now();
        auto it = event_debounce_.find(key);
        if (it != event_debounce_.end()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
            if (elapsed < EVENT_DEBOUNCE_SEC) return; // skip
        }
        event_debounce_[key] = now;
    }

    pending_events_.push_back({a.id, type, protocol, old_v, new_v, detail_json});
    if (pending_events_.size() >= 500) flush_events();

    spdlog::debug("[{}][{}] MAC={} IP={} old='{}' new='{}'",
                  type, protocol, a.mac, a.ip, old_v, new_v);

    if (on_event_) {
        on_event_(a, type, protocol, detail_json);
    }
}

void AssetTracker::refresh_enrichment(Asset& a, const FingerprintSignals& signals) {
    // Tra cứu nhà cung cấp qua OUI
    if (a.vendor.empty()) {
        auto vendor = oui_.lookup(a.mac);
        if (vendor) {
            db_.update_asset_vendor(a.id, *vendor);
            a.vendor = *vendor;
            spdlog::debug("[OUI] MAC={} vendor={}", a.mac, *vendor);
        } else {
            // OUI lookup failed — check if MAC is randomized (Locally Administered Address)
            // iOS 14+, Android 10+, Windows 10+ sinh MAC ngẫu nhiên khi dò/kết nối Wi-Fi.
            // LAA bit: bit 1 of first byte = 1 → not a real globally assigned OUI.
            if (OuiLookup::is_randomized_mac(a.mac)) {
                // Đánh dấu rõ trong vendor field để UI/report biết
                const std::string hint = "[Randomized MAC — vendor unknown]";
                if (a.vendor != hint) {
                    db_.update_asset_vendor(a.id, hint);
                    a.vendor = hint;
                    spdlog::info("[OUI] MAC={} is locally administered (randomized)", a.mac);
                }
            }
        }
    }

    // OS fingerprinting — chỉ cập nhật khi kết quả mới có confidence cao hơn
    auto result = fp_.guess(signals);
    if (result.os_name != "Unknown" && result.confidence > a.os_confidence) {
        db_.update_asset_os(a.id, result.os_name, result.confidence);
        a.os_guess     = result.os_name;
        a.os_confidence= result.confidence;
        spdlog::info("[OS] MAC={} os='{}' confidence={:.2f} rules=[{}]",
                     a.mac, result.os_name, result.confidence,
                     [&]{ std::string s; for (auto& r : result.matched_rules) s += r + " "; return s; }());
    }
}

void AssetTracker::process_arp(const ArpFrame& frame) {
    try {
        const std::string& mac = frame.sender_mac;
        const std::string& ip  = frame.sender_ip;

        // Bỏ qua các địa chỉ MAC không hợp lệ
        if (mac == "00:00:00:00:00:00" || mac == "FF:FF:FF:FF:FF:FF") return;

        bool is_new = (cache_.find(mac) == cache_.end());
        Asset& asset = upsert_asset(mac, frame.is_probe() ? "" : ip, "arp");

        if (frame.is_probe()) {
            log_event(asset, "arp_probe", "arp", "", frame.target_ip);
            return;
        }

        if (is_new) {
            FingerprintSignals sig{};
            refresh_enrichment(asset, sig);
            log_event(asset, "new_asset", "arp", "", ip);
        } else {
            // Kiểm tra nếu IP thay đổi
            if (!ip.empty() && asset.ip != ip) {
                std::string old_ip = asset.ip;
                asset.ip = ip;
                log_event(asset, "ip_change", "arp", old_ip, ip);
            }
        }

        if (frame.is_gratuitous()) {
            log_event(asset, "arp_announce", "arp", ip, ip);
        }
    } catch (const std::exception& e) {
        spdlog::error("process_arp failed: {}", e.what());
    }
}

void AssetTracker::process_dhcp(const DhcpInfo& info) {
    try {
        const std::string& mac = info.client_mac;
        if (mac.empty()) return;

        bool is_new = (cache_.find(mac) == cache_.end());
        Asset& asset = upsert_asset(mac, "", "dhcp");

        // Update hostname
        if (!info.hostname.empty() && info.hostname != asset.hostname) {
            db_.update_asset_hostname(asset.id, info.hostname);
            asset.hostname = info.hostname;
        }

        // OS fingerprinting lấy từ DHCP option 55
        FingerprintSignals sig{};
        sig.dhcp_param_list = info.param_request_list;
        refresh_enrichment(asset, sig);

        if (is_new) {
            log_event(asset, "new_asset", "dhcp");
        }

        // Log DHCP message type
        switch (info.msg_type) {
            case DhcpMsgType::DISCOVER:
                log_event(asset, "dhcp_discover", "dhcp");
                break;
            case DhcpMsgType::REQUEST: {
                std::string detail = info.requested_ip.empty() ? "{}" :
                    std::format("{{\"requested_ip\":\"{}\"}}", info.requested_ip);
                log_event(asset, "dhcp_request", "dhcp", "", info.requested_ip, detail);
                break;
            }
            case DhcpMsgType::ACK: {
                if (!info.your_ip.empty()) {
                    std::string old_ip = asset.ip;
                    db_.update_asset_ip(asset.id, info.your_ip);
                    asset.ip = info.your_ip;
                    std::string detail = std::format("{{\"your_ip\":\"{}\"}}", info.your_ip);
                    log_event(asset, "dhcp_ack", "dhcp", old_ip, info.your_ip, detail);
                }
                break;
            }
            default: break;
        }
    } catch (const std::exception& e) {
        spdlog::error("process_dhcp failed: {}", e.what());
    }
}

void AssetTracker::process_mdns(const MdnsRecord& rec) {
    try {
        if (rec.src_ip.empty()) return;

        std::string mac;
        auto ip_it = ip_to_mac_.find(rec.src_ip);
        if (ip_it != ip_to_mac_.end()) {
            if (ip_it->second.empty()) return;
            mac = ip_it->second;
        } else {
            auto existing = db_.find_asset_by_ip(rec.src_ip);
            if (!existing) {
                ip_to_mac_[rec.src_ip] = ""; // cache miss
                return;
            }
            mac = existing->mac;
            ip_to_mac_[rec.src_ip] = mac;
        }

        Asset& asset = cache_[mac];
        if (asset.id == 0) {
            auto existing = db_.find_asset_by_mac(mac);
            if (existing) asset = *existing;
            else return;
        }

        auto now = Clock::now();
        asset.last_seen = now;
        auto last_it = last_db_update_.find(asset.id);
        if (last_it == last_db_update_.end() || std::chrono::duration_cast<std::chrono::seconds>(now - last_it->second).count() > 10) {
            db_.update_asset_last_seen(asset.id);
            last_db_update_[asset.id] = now;
        }

        // Cập nhật hostname nếu có
        if (!rec.hostname.empty() && rec.hostname != asset.hostname) {
            db_.update_asset_hostname(asset.id, rec.hostname);
            asset.hostname = rec.hostname;
        }

        FingerprintSignals sig{};
        if (!rec.service_type.empty()) sig.mdns_service_type = rec.service_type;
        refresh_enrichment(asset, sig);

        std::string detail = std::format("{{\"hostname\":\"{}\",\"service\":\"{}\",\"model\":\"{}\"}}",
            sanitize_for_json(rec.hostname),
            sanitize_for_json(rec.service_type),
            sanitize_for_json(rec.model_hint));
        log_event(asset, "mdns_announce", "mdns", "", rec.hostname, detail);
    } catch (const std::exception& e) {
        spdlog::error("process_mdns failed: {}", e.what());
    }
}

void AssetTracker::process_ssdp(const SsdpMessage& msg, const std::string& mac_hint) {
    try {
        if (msg.src_ip.empty()) return;

        std::string mac;
        auto ip_it = ip_to_mac_.find(msg.src_ip);
        if (ip_it != ip_to_mac_.end()) {
            if (ip_it->second.empty()) return;
            mac = ip_it->second;
        } else {
            auto existing = db_.find_asset_by_ip(msg.src_ip);
            if (!existing) {
                ip_to_mac_[msg.src_ip] = "";
                return;
            }
            mac = existing->mac;
            ip_to_mac_[msg.src_ip] = mac;
        }

        Asset& asset = cache_[mac];
        if (asset.id == 0) {
            auto existing = db_.find_asset_by_mac(mac);
            if (existing) asset = *existing;
            else return;
        }

        auto now = Clock::now();
        asset.last_seen = now;
        auto last_it = last_db_update_.find(asset.id);
        if (last_it == last_db_update_.end() || std::chrono::duration_cast<std::chrono::seconds>(now - last_it->second).count() > 10) {
            db_.update_asset_last_seen(asset.id);
            last_db_update_[asset.id] = now;
        }

        FingerprintSignals sig{};
        auto server_it = msg.headers.find("server");
        if (server_it != msg.headers.end()) {
            sig.ssdp_server_header = server_it->second;
        }
        refresh_enrichment(asset, sig);

        auto nt_it  = msg.headers.find("nt");
        auto usn_it = msg.headers.find("usn");
        std::string detail = std::format("{{\"method\":\"{}\",\"nt\":\"{}\",\"usn\":\"{}\"}}",
            sanitize_for_json(msg.method),
            nt_it  != msg.headers.end() ? sanitize_for_json(nt_it->second)  : "",
            usn_it != msg.headers.end() ? sanitize_for_json(usn_it->second) : "");
        log_event(asset, "ssdp_notify", "ssdp", "", "", detail);
    } catch (const std::exception& e) {
        spdlog::error("process_ssdp failed: {}", e.what());
    }
}

void AssetTracker::process_dns(const DnsMessage& msg, const std::string& src_ip) {
    try {
        if (msg.is_response || msg.questions.empty()) return;
        if (src_ip.empty()) return;

        std::string mac;
        auto ip_it = ip_to_mac_.find(src_ip);
        if (ip_it != ip_to_mac_.end()) {
            if (ip_it->second.empty()) return;
            mac = ip_it->second;
        } else {
            auto existing = db_.find_asset_by_ip(src_ip);
            if (!existing) {
                ip_to_mac_[src_ip] = "";
                return;
            }
            mac = existing->mac;
            ip_to_mac_[src_ip] = mac;
        }

        Asset& asset = cache_[mac];
        if (asset.id == 0) {
            auto existing = db_.find_asset_by_mac(mac);
            if (existing) asset = *existing;
            else return;
        }

        auto now = Clock::now();
        asset.last_seen = now;
        auto last_it = last_db_update_.find(asset.id);
        if (last_it == last_db_update_.end() || std::chrono::duration_cast<std::chrono::seconds>(now - last_it->second).count() > 10) {
            db_.update_asset_last_seen(asset.id);
            last_db_update_[asset.id] = now;
        }

        std::string detail = std::format("{{\"query\":\"{}\"}}", sanitize_for_json(msg.questions[0]));
        log_event(asset, "dns_query", "dns", "", msg.questions[0], detail);
    } catch (const std::exception& e) {
        spdlog::error("process_dns failed: {}", e.what());
    }
}


void AssetTracker::expire_assets(int timeout_sec) {
    try {
        auto stale = db_.get_assets_not_seen_since(timeout_sec);
        for (const auto& a : stale) {
            db_.set_asset_inactive(a.id);
            db_.insert_event(a.id, "asset_gone", "system");
            cache_.erase(a.mac);
            spdlog::warn("[asset_gone] MAC={} IP={}", a.mac, a.ip);
        }
    } catch (const std::exception& e) {
        spdlog::error("expire_assets failed: {}", e.what());
    }
}


} // namespace pnads

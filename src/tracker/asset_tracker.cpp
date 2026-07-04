#include "tracker/asset_tracker.hpp"
#include <spdlog/spdlog.h>
#include <format>
#include <algorithm>

namespace pnads {

AssetTracker::AssetTracker(DbManager& db, OuiLookup& oui, OsFingerprint& fp)
    : db_(db), oui_(oui), fp_(fp) {}

// ── upsert_asset ──────────────────────────────────────────────────────────────
Asset& AssetTracker::upsert_asset(const std::string& mac, const std::string& ip,
                                   const std::string& source_protocol) {
    auto it = cache_.find(mac);
    if (it == cache_.end()) {
        // New to cache — check DB first
        auto existing = db_.find_asset_by_mac(mac);
        if (!existing) {
            // Brand new asset
            Asset a{};
            a.mac        = mac;
            a.ip         = ip;
            a.first_seen = Clock::now();
            a.last_seen  = Clock::now();
            a.is_active  = true;
            Asset saved = db_.insert_asset(a);
            saved.discovered_via = {source_protocol};
            db_.update_asset_discovered_via(saved.id, saved.discovered_via);
            cache_[mac] = saved;
        } else {
            // Known to DB but not in cache — load and update last_seen
            db_.update_asset_last_seen(existing->id);
            existing->last_seen = Clock::now();
            // Add source protocol to discovered_via
            auto& via = existing->discovered_via;
            if (std::find(via.begin(), via.end(), source_protocol) == via.end()) {
                via.push_back(source_protocol);
                db_.update_asset_discovered_via(existing->id, via);
            }
            cache_[mac] = *existing;
        }
    } else {
        // Already in cache
        Asset& cached = it->second;
        db_.update_asset_last_seen(cached.id);
        cached.last_seen = Clock::now();
        // Update IP if provided and changed
        if (!ip.empty() && ip != cached.ip) {
            db_.update_asset_ip(cached.id, ip);
            cached.ip = ip;
        }
        // Track source protocol
        auto& via = cached.discovered_via;
        if (std::find(via.begin(), via.end(), source_protocol) == via.end()) {
            via.push_back(source_protocol);
            db_.update_asset_discovered_via(cached.id, via);
        }
    }

    return cache_[mac];
}

// ── log_event ─────────────────────────────────────────────────────────────────
void AssetTracker::log_event(const Asset& a, const std::string& type,
                              const std::string& protocol,
                              const std::string& old_v, const std::string& new_v,
                              const std::string& detail_json) {
    db_.insert_event(a.id, type, protocol, old_v, new_v, detail_json);
    spdlog::info("[{}][{}] MAC={} IP={} old='{}' new='{}'",
                 type, protocol, a.mac, a.ip, old_v, new_v);

    // Notify detection engine (runs synchronously in same thread)
    if (on_event_) {
        on_event_(a, type, protocol, detail_json);
    }
}

// ── refresh_enrichment ────────────────────────────────────────────────────────
void AssetTracker::refresh_enrichment(Asset& a, const FingerprintSignals& signals) {
    // OUI vendor lookup
    if (a.vendor.empty()) {
        auto vendor = oui_.lookup(a.mac);
        if (vendor) {
            db_.update_asset_vendor(a.id, *vendor);
            a.vendor = *vendor;
            spdlog::debug("[OUI] MAC={} vendor={}", a.mac, *vendor);
        }
    }

    // OS fingerprinting — only update if new result is more confident
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

// ── process_arp ───────────────────────────────────────────────────────────────
void AssetTracker::process_arp(const ArpFrame& frame) {
    try {
        const std::string& mac = frame.sender_mac;
        const std::string& ip  = frame.sender_ip;

        // Skip invalid MACs
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
            // Check IP change
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

// ── process_dhcp ──────────────────────────────────────────────────────────────
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

        // OS fingerprinting from DHCP option 55
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

// ── process_mdns ──────────────────────────────────────────────────────────────
void AssetTracker::process_mdns(const MdnsRecord& rec) {
    try {
        if (rec.src_ip.empty()) return;

        // Find asset by IP — we may not have MAC from mDNS
        auto existing = db_.find_asset_by_ip(rec.src_ip);
        if (!existing) return;  // No known asset for this IP

        Asset& asset = cache_[existing->mac];
        if (asset.id == 0) {
            asset = *existing;
        }

        db_.update_asset_last_seen(asset.id);
        asset.last_seen = Clock::now();

        // Update hostname if we got one
        if (!rec.hostname.empty() && rec.hostname != asset.hostname) {
            db_.update_asset_hostname(asset.id, rec.hostname);
            asset.hostname = rec.hostname;
        }

        FingerprintSignals sig{};
        if (!rec.service_type.empty()) sig.mdns_service_type = rec.service_type;
        refresh_enrichment(asset, sig);

        std::string detail = std::format("{{\"hostname\":\"{}\",\"service\":\"{}\",\"model\":\"{}\"}}",
            rec.hostname, rec.service_type, rec.model_hint);
        log_event(asset, "mdns_announce", "mdns", "", rec.hostname, detail);
    } catch (const std::exception& e) {
        spdlog::error("process_mdns failed: {}", e.what());
    }
}

// ── process_ssdp ──────────────────────────────────────────────────────────────
void AssetTracker::process_ssdp(const SsdpMessage& msg, const std::string& mac_hint) {
    try {
        if (msg.src_ip.empty()) return;

        auto existing = db_.find_asset_by_ip(msg.src_ip);
        if (!existing) return;

        Asset& asset = cache_[existing->mac];
        if (asset.id == 0) asset = *existing;

        db_.update_asset_last_seen(asset.id);
        asset.last_seen = Clock::now();

        FingerprintSignals sig{};
        auto server_it = msg.headers.find("server");
        if (server_it != msg.headers.end()) {
            sig.ssdp_server_header = server_it->second;
        }
        refresh_enrichment(asset, sig);

        auto nt_it  = msg.headers.find("nt");
        auto usn_it = msg.headers.find("usn");
        std::string detail = std::format("{{\"method\":\"{}\",\"nt\":\"{}\",\"usn\":\"{}\"}}",
            msg.method,
            nt_it  != msg.headers.end() ? nt_it->second  : "",
            usn_it != msg.headers.end() ? usn_it->second : "");
        log_event(asset, "ssdp_notify", "ssdp", "", "", detail);
    } catch (const std::exception& e) {
        spdlog::error("process_ssdp failed: {}", e.what());
    }
}

// ── process_dns ───────────────────────────────────────────────────────────────
void AssetTracker::process_dns(const DnsMessage& msg, const std::string& src_ip) {
    try {
        if (msg.is_response || msg.questions.empty()) return;
        if (src_ip.empty()) return;

        auto existing = db_.find_asset_by_ip(src_ip);
        if (!existing) return;

        Asset& asset = cache_[existing->mac];
        if (asset.id == 0) asset = *existing;

        db_.update_asset_last_seen(asset.id);
        asset.last_seen = Clock::now();

        std::string detail = std::format("{{\"query\":\"{}\"}}", msg.questions[0]);
        log_event(asset, "dns_query", "dns", "", msg.questions[0], detail);
    } catch (const std::exception& e) {
        spdlog::error("process_dns failed: {}", e.what());
    }
}

// ── process_http_ua ───────────────────────────────────────────────────────────
void AssetTracker::process_http_ua(const std::string& src_ip,
                                    const std::string& user_agent) {
    try {
        if (src_ip.empty() || user_agent.empty()) return;

        auto existing = db_.find_asset_by_ip(src_ip);
        if (!existing) return;

        Asset& asset = cache_[existing->mac];
        if (asset.id == 0) asset = *existing;

        db_.update_asset_last_seen(asset.id);
        asset.last_seen = Clock::now();

        FingerprintSignals sig{};
        sig.http_user_agent = user_agent;
        refresh_enrichment(asset, sig);

        std::string detail = std::format("{{\"user_agent\":\"{}\"}}", user_agent);
        log_event(asset, "http_useragent", "http", "", "", detail);
    } catch (const std::exception& e) {
        spdlog::error("process_http_ua failed: {}", e.what());
    }
}

// ── expire_assets ─────────────────────────────────────────────────────────────
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

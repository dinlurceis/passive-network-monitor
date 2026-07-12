#pragma once
#include "tracker/asset.hpp"
#include "parsers/arp_parser.hpp"
#include "parsers/dhcp_parser.hpp"
#include "parsers/mdns_parser.hpp"
#include "parsers/ssdp_parser.hpp"
#include "parsers/dns_message.hpp"
#include "db/db_manager.hpp"
#include "enrichment/oui_lookup.hpp"
#include "enrichment/os_fingerprint.hpp"
#include <unordered_map>
#include <functional>

namespace pnads {

// Callback khi có event mới ghi vào DB — dùng để detection engine (Phase 3)
// xử lý ngay trong cùng thread, không cần polling/queue.
using EventCallback = std::function<void(const Asset&, const std::string& event_type,
                                          const std::string& protocol,
                                          const std::string& detail_json)>;

// AssetTracker — chỉ được gọi từ capture thread duy nhất.
// Không có mutex: REST API đọc trực tiếp từ PostgreSQL qua DbManager.
class AssetTracker {
public:
    AssetTracker(DbManager& db, OuiLookup& oui, OsFingerprint& fp);

    // Protocol handlers — gọi từ packet callback
    void process_arp(const ArpFrame& frame);
    void process_dhcp(const DhcpInfo& info);
    void process_mdns(const MdnsRecord& rec);
    void process_ssdp(const SsdpMessage& msg, const std::string& mac_hint = "");
    void process_dns(const DnsMessage& msg, const std::string& src_ip);

    // Đánh dấu asset không còn active nếu quá timeout
    void expire_assets(int timeout_sec);

    // Detection engine callback — gọi sau mỗi event
    void set_event_callback(EventCallback cb) { on_event_ = std::move(cb); }

    // Xả các event đang chờ vào DB
    void flush_events();

private:
    DbManager&     db_;
    OuiLookup&     oui_;
    OsFingerprint& fp_;
    EventCallback  on_event_;

    // cache chỉ đọc/ghi bởi capture thread — an toàn không cần mutex
    std::unordered_map<std::string, Asset> cache_;  // MAC → Asset
    std::unordered_map<std::string, std::string> ip_to_mac_; // IP → MAC
    std::unordered_map<int, TimePoint> last_db_update_; // id → last update
    std::vector<DbManager::EventBuffer> pending_events_; // Queue for batch insert
    // key = "asset_id:event_type", value = last log time
    // Tránh log lặp lại các event không có thay đổi (dns_query, mdns_announce, ssdp_notify)
    std::unordered_map<std::string, TimePoint> event_debounce_;

    // Upsert asset và trả về reference vào cache (không bao giờ null sau call)
    Asset& upsert_asset(const std::string& mac, const std::string& ip,
                         const std::string& source_protocol);

    void log_event(const Asset& a, const std::string& type,
                   const std::string& protocol,
                   const std::string& old_v = "", const std::string& new_v = "",
                   const std::string& detail_json = "{}");

    // Chạy OUI + OsFingerprint sau khi có tín hiệu mới
    void refresh_enrichment(Asset& a, const FingerprintSignals& signals);
};

} // namespace pnads

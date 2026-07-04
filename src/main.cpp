// main.cpp — PNADS entry point
// Kết nối tất cả components: capture → parse → tracker → detection → DB → REST API

#include "config/config.hpp"
#include "capture/pcap_reader.hpp"
#include "parsers/ethernet_parser.hpp"
#include "parsers/arp_parser.hpp"
#include "parsers/dhcp_parser.hpp"
#include "parsers/ipv4_parser.hpp"
#include "parsers/udp_parser.hpp"
#include "parsers/tcp_parser.hpp"
#include "parsers/mdns_parser.hpp"
#include "parsers/ssdp_parser.hpp"
#include "parsers/dns_message.hpp"
#include "parsers/http_parser.hpp"
#include "tracker/asset_tracker.hpp"
#include "db/db_manager.hpp"
#include "enrichment/oui_lookup.hpp"
#include "enrichment/os_fingerprint.hpp"
#include "detection/detection_engine.hpp"
#include "detection/rule_new_device.hpp"
#include "detection/rule_watchlist.hpp"
#include "detection/rule_arp_spoofing.hpp"
#include "api/rest_server.hpp"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <csignal>
#include <atomic>
#include <memory>
#include <thread>
#include <chrono>

// Global để signal handler có thể dừng reader và API
static std::unique_ptr<pnads::PcapReader> g_reader;
static std::unique_ptr<pnads::RestServer> g_api_server;
static std::atomic<bool>                  g_running{true};

void signal_handler(int sig) {
    spdlog::info("Signal {} received, stopping...", sig);
    g_running = false;
    if (g_reader)     g_reader->stop();
    if (g_api_server) g_api_server->stop();
}

int main() {
    // Setup signal handlers
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Load config từ .env + environment variables
    auto cfg = pnads::Config::from_env();

    // Setup logging
    auto logger = spdlog::stdout_color_mt("pnads");
    spdlog::set_default_logger(logger);
    if      (cfg.log_level == "debug")   spdlog::set_level(spdlog::level::debug);
    else if (cfg.log_level == "warning") spdlog::set_level(spdlog::level::warn);
    else if (cfg.log_level == "error")   spdlog::set_level(spdlog::level::err);
    else                                 spdlog::set_level(spdlog::level::info);

    spdlog::info("PNADS v0.2.0 starting");

    // Xác định nguồn capture
    bool live = cfg.pcap_file.empty();
    std::string source = live ? cfg.interface : cfg.pcap_file;
    if (source.empty()) {
        spdlog::critical("No capture source. Set PCAP_FILE or INTERFACE env var.");
        return 1;
    }

    try {
        // ── Database ──────────────────────────────────────────────────────────
        pnads::DbManager db(cfg.db_connection_string());
        if (!db.ping()) {
            spdlog::critical("Cannot connect to PostgreSQL: {}", cfg.db_connection_string());
            return 1;
        }
        db.initialize_schema();
        spdlog::info("Database connected and schema ready");

        // ── Enrichment ────────────────────────────────────────────────────────
        pnads::OuiLookup    oui(cfg.oui_file);
        pnads::OsFingerprint fp;
        if (!oui.loaded()) {
            spdlog::warn("OUI database not loaded. Run scripts/download_oui.sh first.");
        }

        // ── Asset Tracker ─────────────────────────────────────────────────────
        pnads::AssetTracker tracker(db, oui, fp);

        // ── Detection Engine ──────────────────────────────────────────────────
        pnads::DetectionEngine engine(db);
        engine.add_rule(std::make_unique<pnads::RuleNewDevice>());
        engine.add_rule(std::make_unique<pnads::RuleWatchlist>(db));
        engine.add_rule(std::make_unique<pnads::RuleArpSpoofing>(
            db, cfg.arp_spoof_window_sec, cfg.arp_spoof_mac_threshold));

        // Wire detection engine to tracker via EventCallback
        tracker.set_event_callback(
            [&engine](const pnads::Asset& asset,
                      const std::string& event_type,
                      const std::string& protocol,
                      const std::string& detail_json) {
                engine.on_event(asset, event_type, protocol, detail_json);
            });

        // ── REST API ──────────────────────────────────────────────────────────
        g_api_server = std::make_unique<pnads::RestServer>(db, cfg.api_port);
        g_api_server->start();

        // ── PCAP Reader ───────────────────────────────────────────────────────
        g_reader = std::make_unique<pnads::PcapReader>(source, live);

        // Extended BPF filter: ARP + DHCP + mDNS + SSDP + DNS + HTTP
        std::string bpf_filter =
            "arp or "
            "(udp and (port 67 or port 68 or port 5353 or port 1900 or port 53)) or "
            "tcp port 80";

        if (!g_reader->set_filter(bpf_filter)) {
            spdlog::warn("Extended BPF filter failed, falling back to ARP+DHCP only");
            g_reader->set_filter("arp or (udp and (port 67 or port 68))");
        }

        spdlog::info("Capturing from '{}' ({}) | API on :{}",
                     source, live ? "live" : "pcap file", cfg.api_port);

        // ── Packet callback ───────────────────────────────────────────────────
        auto callback = [&](const pnads::RawPacket& pkt) {
            auto eth = pnads::parse_ethernet(pkt.data, pkt.len);
            if (!eth) return;

            if (eth->ethertype == pnads::ETHERTYPE_ARP) {
                auto arp = pnads::parse_arp(eth->payload, eth->payload_len);
                if (arp) {
                    spdlog::debug("ARP {}: {} → {}", arp->is_request() ? "REQ" : "REP",
                                  arp->sender_ip, arp->target_ip);
                    tracker.process_arp(*arp);
                }
            }
            else if (eth->ethertype == pnads::ETHERTYPE_IPV4) {
                auto ipv4 = pnads::parse_ipv4(eth->payload, eth->payload_len);
                if (!ipv4) return;

                std::string src_ip = pnads::ip_to_string(ipv4->src_ip);

                if (ipv4->protocol == pnads::IP_PROTO_UDP) {
                    auto udp = pnads::parse_udp(ipv4->payload, ipv4->payload_len);
                    if (!udp) return;

                    uint16_t sp = udp->src_port, dp = udp->dst_port;

                    // DHCP
                    if (sp == pnads::DHCP_SERVER_PORT || sp == pnads::DHCP_CLIENT_PORT ||
                        dp == pnads::DHCP_SERVER_PORT || dp == pnads::DHCP_CLIENT_PORT) {
                        auto dhcp = pnads::parse_dhcp(udp->payload, udp->payload_len);
                        if (dhcp) {
                            spdlog::debug("DHCP {}: MAC={}", pnads::dhcp_msg_type_str(dhcp->msg_type), dhcp->client_mac);
                            tracker.process_dhcp(*dhcp);
                        }
                    }
                    // mDNS
                    else if (sp == pnads::MDNS_PORT || dp == pnads::MDNS_PORT) {
                        auto mdns = pnads::parse_mdns(udp->payload, udp->payload_len, src_ip);
                        if (mdns) {
                            spdlog::debug("mDNS: {} svc={}", mdns->hostname, mdns->service_type);
                            tracker.process_mdns(*mdns);
                        }
                    }
                    // SSDP
                    else if (sp == pnads::SSDP_PORT || dp == pnads::SSDP_PORT) {
                        auto ssdp = pnads::parse_ssdp(udp->payload, udp->payload_len, src_ip);
                        if (ssdp) {
                            spdlog::debug("SSDP: {} {}", ssdp->method, src_ip);
                            tracker.process_ssdp(*ssdp);
                        }
                    }
                    // DNS (passive)
                    else if (sp == 53 || dp == 53) {
                        auto dns = pnads::parse_dns_message(udp->payload, udp->payload_len);
                        if (dns && !dns->is_response) {
                            tracker.process_dns(*dns, src_ip);
                        }
                    }
                }
                else if (ipv4->protocol == pnads::IP_PROTO_TCP) {
                    auto tcp = pnads::parse_tcp(ipv4->payload, ipv4->payload_len);
                    if (!tcp) return;

                    // HTTP User-Agent sniffing (port 80 requests)
                    if (tcp->dst_port == 80 && tcp->payload_len > 0) {
                        auto ua = pnads::extract_user_agent(tcp->payload, tcp->payload_len);
                        if (ua) {
                            spdlog::debug("HTTP UA: {} → {}", src_ip, *ua);
                            tracker.process_http_ua(src_ip, *ua);
                        }
                    }
                }
            }
        };

        // ── Main capture loop (blocking) ──────────────────────────────────────
        g_reader->start(callback);

        spdlog::info("Capture finished");

        // Keep alive after offline PCAP read (API still serves)
        if (!live) {
            spdlog::info("Offline capture complete. API still running at :{} — press Ctrl+C to exit.",
                          cfg.api_port);
            while (g_running) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }

    } catch (const std::exception& e) {
        spdlog::critical("Fatal error: {}", e.what());
        return 1;
    }

    return 0;
}

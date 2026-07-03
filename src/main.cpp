// main.cpp — kết nối tất cả các component

#include "config/config.hpp"
#include "capture/pcap_reader.hpp"
#include "parsers/ethernet_parser.hpp"
#include "parsers/arp_parser.hpp"
#include "parsers/dhcp_parser.hpp"
#include "parsers/ipv4_parser.hpp"        // Phase 2: parse IPv4/UDP chuẩn hóa
#include "tracker/asset_tracker.hpp"
#include "db/db_manager.hpp"
#include "enrichment/oui_lookup.hpp"      // Phase 2: tra cứu vendor từ MAC
#include "api/rest_server.hpp"            // Phase 4: REST API Server
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <csignal>
#include <atomic>
#include <memory>
#include <thread>
#include <chrono>

// Global để signal handler có thể dừng reader
static std::unique_ptr<netmon::PcapReader> g_reader;
static std::unique_ptr<netmon::RestServer> g_api_server;
static std::atomic<bool> g_running{true};

void signal_handler(int sig) {
    spdlog::info("Signal {} received, stopping...", sig);
    g_running = false;
    if (g_reader) g_reader->stop();
    if (g_api_server) g_api_server->stop();
}

int main(int argc, char* argv[]) {
    // Setup signal handler
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Load config
    auto cfg = netmon::Config::from_env();

    // Parse CLI arguments — override env vars if provided
    for (int i = 1; i < argc - 1; ++i) {
        std::string arg(argv[i]);
        if (arg == "--pcap") {
            cfg.pcap_file = argv[i + 1];
        } else if (arg == "--iface") {
            cfg.interface = argv[i + 1];
            cfg.pcap_file = "";  // live mode
        } else if (arg == "--log-level") {
            cfg.log_level = argv[i + 1];
        }
    }

    // Setup logging
    auto logger = spdlog::stdout_color_mt("netmon");
    spdlog::set_default_logger(logger);
    if      (cfg.log_level == "debug")   spdlog::set_level(spdlog::level::debug);
    else if (cfg.log_level == "warning") spdlog::set_level(spdlog::level::warn);
    else if (cfg.log_level == "error")   spdlog::set_level(spdlog::level::err);
    else                                 spdlog::set_level(spdlog::level::info);

    spdlog::info("passive-network-monitor v0.1.0 starting");

    // Validate input source
    bool live = cfg.pcap_file.empty();
    std::string source = live ? cfg.interface : cfg.pcap_file;

    if (source.empty()) {
        spdlog::critical("No capture source specified. Use PCAP_FILE env or --pcap <file>");
        return 1;
    }

    // Init DB
    try {
        netmon::DbManager db(cfg.db_connection_string());
        if (!db.ping()) {
            spdlog::critical("Cannot connect to PostgreSQL: {}", cfg.db_connection_string());
            return 1;
        }
        db.initialize_schema();
        spdlog::info("Database connected and schema ready");

        // Init OUI lookup — đọc file CSV một lần khi khởi động
        netmon::OuiLookup oui(cfg.oui_file);
        if (!oui.loaded()) {
            spdlog::warn("OUI database not loaded. Run scripts/download_oui.sh to enable vendor lookup.");
        }

        // Init tracker (truyền oui để enrich vendor info)
        netmon::AssetTracker tracker(db, oui);

        // Init REST API Server
        g_api_server = std::make_unique<netmon::RestServer>(db, tracker, cfg.api_port);
        g_api_server->start();

        // Init PCAP reader
        g_reader = std::make_unique<netmon::PcapReader>(source, live);

        // Set BPF filter to capture only ARP and DHCP traffic
        if (!g_reader->set_filter("arp or (udp and (port 67 or port 68))")) {
            spdlog::warn("BPF filter failed, capturing all traffic");
        }

        spdlog::info("Reading from '{}' ({})", source, live ? "live" : "pcap file");

        // Packet callback
        auto callback = [&](const netmon::RawPacket& pkt) {
            auto eth = netmon::parse_ethernet(pkt.data, pkt.len);
            if (!eth) return;

            if (eth->ethertype == netmon::ETHERTYPE_ARP) {
                auto arp = netmon::parse_arp(eth->payload, eth->payload_len);
                if (arp) {
                    spdlog::debug("ARP {}: {} ({}) → {} ({})",
                        arp->is_request() ? "REQ" : "REP",
                        arp->sender_ip, arp->sender_mac,
                        arp->target_ip, arp->target_mac);
                    tracker.process_arp(*arp);
                }
            }
            else if (eth->ethertype == netmon::ETHERTYPE_IPV4) {
                // Phase 2: dùng parse_ipv4() và parse_udp() thay cho code inline
                auto ipv4 = netmon::parse_ipv4(eth->payload, eth->payload_len);
                if (!ipv4 || ipv4->protocol != netmon::IP_PROTO_UDP) return;

                auto udp = netmon::parse_udp(ipv4->payload, ipv4->payload_len);
                if (!udp) return;

                // DHCP dùng port 67 (server) và 68 (client)
                bool is_dhcp = (udp->src_port == netmon::DHCP_SERVER_PORT ||
                                udp->src_port == netmon::DHCP_CLIENT_PORT ||
                                udp->dst_port == netmon::DHCP_SERVER_PORT ||
                                udp->dst_port == netmon::DHCP_CLIENT_PORT);
                if (!is_dhcp) return;

                auto dhcp = netmon::parse_dhcp(udp->payload, udp->payload_len);
                if (dhcp) {
                    spdlog::debug("DHCP {}: MAC={} hostname={} your_ip={}",
                        netmon::dhcp_msg_type_str(dhcp->msg_type),
                        dhcp->client_mac, dhcp->hostname, dhcp->your_ip);
                    tracker.process_dhcp(*dhcp);
                }
            }
        };

        // Start capture loop (blocking)
        g_reader->start(callback);

        // After loop ends
        spdlog::info("Capture finished. Active assets: {}", tracker.active_count());

        // Log summary
        auto assets = tracker.all_assets();
        spdlog::info("Total unique assets seen: {}", assets.size());
        
        // Giữ chương trình sống để phục vụ Web UI sau khi đọc xong file PCAP
        if (!live) {
            spdlog::info("Offline capture complete. Web UI is still running at port {}. Press Ctrl+C to exit.", cfg.api_port);
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

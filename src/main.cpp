// main.cpp — kết nối tất cả các component

#include "config/config.hpp"
#include "capture/pcap_reader.hpp"
#include "parsers/ethernet_parser.hpp"
#include "parsers/arp_parser.hpp"
#include "parsers/dhcp_parser.hpp"
#include "tracker/asset_tracker.hpp"
#include "db/db_manager.hpp"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <csignal>
#include <atomic>
#include <memory>

// Global để signal handler có thể dừng reader
static std::unique_ptr<netmon::PcapReader> g_reader;
static std::atomic<bool> g_running{true};

void signal_handler(int sig) {
    spdlog::info("Signal {} received, stopping...", sig);
    g_running = false;
    if (g_reader) g_reader->stop();
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

        // Init tracker
        netmon::AssetTracker tracker(db);

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
                // Phase 1 minimal: parse IPv4 + UDP manually to reach DHCP payload
                // IPv4 header: minimum 20 bytes
                const uint8_t* ip_data = eth->payload;
                size_t         ip_len  = eth->payload_len;

                if (ip_len < 20) return;

                uint8_t ihl      = (ip_data[0] & 0x0F) * 4;  // IP header length
                uint8_t protocol = ip_data[9];

                // Only process UDP (protocol 17)
                if (protocol != 17 || ip_len < static_cast<size_t>(ihl) + 8) return;

                const uint8_t* udp_data = ip_data + ihl;
                uint16_t src_port = static_cast<uint16_t>((udp_data[0] << 8) | udp_data[1]);
                uint16_t dst_port = static_cast<uint16_t>((udp_data[2] << 8) | udp_data[3]);
                uint16_t udp_len  = static_cast<uint16_t>((udp_data[4] << 8) | udp_data[5]);

                // DHCP: src or dst is port 67 or 68
                bool is_dhcp = (src_port == netmon::DHCP_SERVER_PORT ||
                                src_port == netmon::DHCP_CLIENT_PORT ||
                                dst_port == netmon::DHCP_SERVER_PORT ||
                                dst_port == netmon::DHCP_CLIENT_PORT);

                if (!is_dhcp) return;

                // UDP payload starts at offset 8
                if (udp_len < 8) return;
                const uint8_t* dhcp_data = udp_data + 8;
                size_t         dhcp_len  = static_cast<size_t>(udp_len) - 8;

                auto dhcp = netmon::parse_dhcp(dhcp_data, dhcp_len);
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
        for (const auto& a : assets) {
            spdlog::info("  MAC={} IP={} hostname='{}'", a.mac, a.ip, a.hostname);
        }

    } catch (const std::exception& e) {
        spdlog::critical("Fatal error: {}", e.what());
        return 1;
    }

    return 0;
}

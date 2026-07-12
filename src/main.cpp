// main.cpp — PNADS entry point
// Kết nối tất cả components: capture → parse → tracker → detection → DB → REST
// API

#include "api/rest_server.hpp"
#include "capture/pcap_reader.hpp"
#include "config/config.hpp"
#include "db/db_manager.hpp"
#include "detection/detection_engine.hpp"
#include "detection/rule_arp_spoofing.hpp"
#include "detection/rule_new_device.hpp"
#include "detection/rule_watchlist.hpp"
#include "enrichment/os_fingerprint.hpp"
#include "enrichment/oui_lookup.hpp"
#include "parsers/arp_parser.hpp"
#include "parsers/dhcp_parser.hpp"
#include "parsers/dns_message.hpp"
#include "parsers/ethernet_parser.hpp"
#include "parsers/ipv4_parser.hpp"
#include "parsers/mdns_parser.hpp"
#include "parsers/ssdp_parser.hpp"
#include "parsers/udp_parser.hpp"
#include "tracker/asset_tracker.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <memory>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <thread>
#include <vector>


// Global để signal handler có thể dừng reader và API
static std::unique_ptr<pnads::PcapReader> g_reader;
static std::unique_ptr<pnads::RestServer> g_api_server;
static std::atomic<bool> g_running{true};

void signal_handler(int sig) {
  spdlog::info("Signal {} received, stopping...", sig);
  g_running = false;
  if (g_reader)
    g_reader->stop();
  if (g_api_server)
    g_api_server->stop();
}

int main() {
  // Cấu hình xử lý tín hiệu (Ctrl+C)
  std::signal(SIGINT, signal_handler);
  std::signal(SIGTERM, signal_handler);

  // Load config từ .env + environment variables
  auto cfg = pnads::Config::from_env();

  // Cấu hình logging
  auto logger = spdlog::stdout_color_mt("pnads");
  spdlog::set_default_logger(logger);
  if (cfg.log_level == "debug")
    spdlog::set_level(spdlog::level::debug);
  else if (cfg.log_level == "warning")
    spdlog::set_level(spdlog::level::warn);
  else if (cfg.log_level == "error")
    spdlog::set_level(spdlog::level::err);
  else
    spdlog::set_level(spdlog::level::info);

  spdlog::info("PNADS v0.2.0 starting");

  // Xác định nguồn capture
  bool live = cfg.pcap_file.empty();
  std::string source = live ? cfg.interface : cfg.pcap_file;
  if (source.empty()) {
    spdlog::critical("No capture source. Set PCAP_FILE or INTERFACE env var.");
    return 1;
  }

  try {
    // Cơ sở dữ liệu
    pnads::DbManager db(cfg.db_connection_string());
    if (!db.ping()) {
      spdlog::critical("Cannot connect to PostgreSQL: {}",
                       cfg.db_connection_string());
      return 1;
    }
    db.initialize_schema();
    spdlog::info("Database connected and schema ready");

    // Thu thập thêm thông tin (Enrichment)
    pnads::OuiLookup oui(cfg.oui_file);
    pnads::OsFingerprint fp;
    if (!oui.loaded()) {
      spdlog::warn(
          "OUI database not loaded. Run scripts/download_oui.sh first.");
    }

    // Bộ theo dõi thiết bị (Asset Tracker)
    pnads::AssetTracker tracker(db, oui, fp);

    // Engine phát hiện bất thường
    pnads::DetectionEngine engine(db);
    engine.add_rule(std::make_unique<pnads::RuleNewDevice>());
    engine.add_rule(std::make_unique<pnads::RuleWatchlist>(db));
    engine.add_rule(std::make_unique<pnads::RuleArpSpoofing>(
        db, cfg.arp_spoof_window_sec, cfg.arp_spoof_mac_threshold));

    // Kết nối engine phát hiện với tracker qua EventCallback
    tracker.set_event_callback(
        [&engine](const pnads::Asset &asset, const std::string &event_type,
                  const std::string &protocol, const std::string &detail_json) {
          engine.on_event(asset, event_type, protocol, detail_json);
        });

    // Quản lý hàng đợi PCAP
    pnads::PcapQueueManager pcap_queue;

    // REST API Server
    g_api_server = std::make_unique<pnads::RestServer>(
        cfg.db_connection_string(), cfg.api_port, &pcap_queue);
    g_api_server->start();

    spdlog::info("API on :{}", cfg.api_port);

    // Hàm callback xử lý từng gói tin
    std::atomic<uint64_t> packet_count{0};
    std::atomic<uint64_t> pkt_arp{0}, pkt_dhcp{0}, pkt_mdns{0}, pkt_ssdp{0},
        pkt_dns{0};
    auto callback = [&](const pnads::RawPacket &pkt) {
      packet_count++;
      if (packet_count % 500000 == 0) {
        spdlog::info("Processed {} packets...", packet_count);
      }

      auto eth = pnads::parse_ethernet(pkt.data, pkt.len);
      if (!eth)
        return;

      if (eth->ethertype == pnads::ETHERTYPE_ARP) {
        auto arp = pnads::parse_arp(eth->payload, eth->payload_len);
        if (arp) {
          pkt_arp++;
          spdlog::debug("ARP op={} {}->{}", arp->opcode, arp->sender_ip,
                        arp->target_ip);
          tracker.process_arp(*arp);
        }
      } else if (eth->ethertype == pnads::ETHERTYPE_IPV4) {
        auto ipv4 = pnads::parse_ipv4(eth->payload, eth->payload_len);
        if (!ipv4)
          return;

        std::string src_ip = pnads::ip_to_string(ipv4->src_ip);

        if (ipv4->protocol == pnads::IP_PROTO_UDP) {
          auto udp = pnads::parse_udp(ipv4->payload, ipv4->payload_len);
          if (!udp)
            return;

          uint16_t sp = udp->src_port, dp = udp->dst_port;

          // DHCP (v4)
          if (sp == pnads::DHCP_SERVER_PORT || sp == pnads::DHCP_CLIENT_PORT ||
              dp == pnads::DHCP_SERVER_PORT || dp == pnads::DHCP_CLIENT_PORT) {
            auto dhcp = pnads::parse_dhcp(udp->payload, udp->payload_len);
            if (dhcp) {
              pkt_dhcp++;
              spdlog::debug("DHCP {}: MAC={}",
                            pnads::dhcp_msg_type_str(dhcp->msg_type),
                            dhcp->client_mac);
              tracker.process_dhcp(*dhcp);
            }
          }

          // mDNS
          else if (sp == pnads::MDNS_PORT || dp == pnads::MDNS_PORT) {
            auto mdns =
                pnads::parse_mdns(udp->payload, udp->payload_len, src_ip);
            if (mdns) {
              pkt_mdns++;
              spdlog::debug("mDNS: {} svc={}", mdns->hostname,
                            mdns->service_type);
              tracker.process_mdns(*mdns);
            }
          }
          // SSDP
          else if (sp == pnads::SSDP_PORT || dp == pnads::SSDP_PORT) {
            auto ssdp =
                pnads::parse_ssdp(udp->payload, udp->payload_len, src_ip);
            if (ssdp) {
              pkt_ssdp++;
              spdlog::debug("SSDP: {} {}", ssdp->method, src_ip);
              tracker.process_ssdp(*ssdp);
            }
          }
          // DNS (passive)
          else if (sp == 53 || dp == 53) {
            auto dns = pnads::parse_dns_message(udp->payload, udp->payload_len);
            if (dns) {
              pkt_dns++;
              tracker.process_dns(*dns, src_ip);
            }
          }
        }
      }
    };

    // Vòng lặp capture chính (chặn luồng)
    if (live) {
      spdlog::info("Starting live capture on interface {}", source);
      g_reader = std::make_unique<pnads::PcapReader>(source, true);
      std::string bpf_filter = "arp or (udp and (port 67 or port 68 or port "
                               "5353 or port 1900 or port 53))";
      if (!g_reader->set_filter(bpf_filter))
        g_reader->set_filter("arp or (udp and (port 67 or port 68))");
      g_reader->start(callback);
      tracker.flush_events(); // xả event còn trong buffer trước khi thoát
      spdlog::info("Live capture finished");
    } else {
      // Xác định stable PCAP (loop liên tục)
      // Ưu tiên: PCAP_FILE env var, rồi file đầu tiên trong /samples/pcaplist/
      std::string stable_pcap = cfg.pcap_file;

      if (stable_pcap.empty()) {
        // Tìm file đầu tiên (alphabet) trong /samples/pcaplist
        std::string pcaplist_dir = "/samples/pcaplist";
        if (std::filesystem::exists(pcaplist_dir)) {
          std::vector<std::string> found;
          for (const auto &entry :
               std::filesystem::directory_iterator(pcaplist_dir)) {
            if (!entry.is_regular_file())
              continue;
            std::string ext = entry.path().extension().string();
            if (ext == ".pcap" || ext == ".pcapng")
              found.push_back(entry.path().string());
          }
          std::sort(found.begin(), found.end());
          if (!found.empty())
            stable_pcap = found.front();
        }
      }

      if (stable_pcap.empty()) {
        spdlog::warn("No stable PCAP found. Set PCAP_FILE or place .pcap in "
                     "/samples/pcaplist/");
        spdlog::info("Idle mode: API listening on :{} — waiting for uploads",
                     cfg.api_port);
        // Chỉ chờ upload
        while (g_running) {
          std::string next_file;
          {
            std::unique_lock<std::mutex> lock(pcap_queue.mutex);
            pcap_queue.cv.wait_for(lock, std::chrono::seconds(2), [&] {
              return !pcap_queue.queue.empty() || !g_running;
            });
            if (!g_running)
              break;
            if (!pcap_queue.queue.empty()) {
              next_file = pcap_queue.queue.front();
              pcap_queue.queue.pop_front();
              pcap_queue.current_pcap = next_file;
            }
          }
          if (!next_file.empty()) {
            try {
              spdlog::info("[UPLOAD] Processing: {}", next_file);
              g_reader = std::make_unique<pnads::PcapReader>(next_file, false);
              g_reader->set_filter("arp or (udp and (port 67 or port 68 or "
                                   "port 5353 or port 1900 or port 53))");
              g_reader->start(callback);
              tracker.flush_events();
              spdlog::info("[UPLOAD] Done: {}", next_file);
            } catch (const std::exception &e) {
              spdlog::error("[UPLOAD] Failed {}: {}", next_file, e.what());
            }
            {
              std::lock_guard<std::mutex> lock(pcap_queue.mutex);
              pcap_queue.current_pcap = "";
            }
          }
        }
      } else {
        spdlog::info("Stable PCAP (loop): {}", stable_pcap);
        spdlog::info(
            "API listening on :{} — upload a PCAP to interrupt the loop",
            cfg.api_port);

        uint64_t loop_count = 0;

        // BPF filter dùng chung
        const std::string bpf_filter = "arp or (udp and (port 67 or port 68 or "
                                       "port 5353 or port 1900 or port 53))";

        while (g_running) {
          // Ưu tiên: kiểm tra priority queue (file upload)
          std::string priority_file;
          {
            std::unique_lock<std::mutex> lock(pcap_queue.mutex);
            if (!pcap_queue.queue.empty()) {
              priority_file = pcap_queue.queue.front();
              pcap_queue.queue.pop_front();
              pcap_queue.current_pcap = priority_file;
            }
          }

          if (!priority_file.empty()) {
            // Xử lý file upload (priority)
            spdlog::info(
                "[PRIORITY] Pausing stable loop — processing upload: {}",
                priority_file.substr(priority_file.find_last_of("/\\") + 1));
            uint64_t pkts_before = packet_count.load();
            auto t0 = std::chrono::steady_clock::now();
            try {
              g_reader =
                  std::make_unique<pnads::PcapReader>(priority_file, false);
              if (!g_reader->set_filter(bpf_filter))
                g_reader->set_filter("arp or (udp and (port 67 or port 68))");
              g_reader->start(callback);
              tracker.flush_events();
              double elapsed = std::chrono::duration<double>(
                                   std::chrono::steady_clock::now() - t0)
                                   .count();
              uint64_t processed = packet_count.load() - pkts_before;
              double pps = (elapsed > 0) ? processed / elapsed : 0;
              spdlog::info(
                  "[PRIORITY] Done: {} | {:.2f}s | {} pkts | {:.0f} pkt/s",
                  priority_file.substr(priority_file.find_last_of("/\\") + 1),
                  elapsed, processed, pps);
              spdlog::info("[PRIORITY] Resuming stable loop...");
            } catch (const std::exception &e) {
              spdlog::error("[PRIORITY] Failed {}: {}", priority_file,
                            e.what());
            }
            {
              std::lock_guard<std::mutex> lock(pcap_queue.mutex);
              pcap_queue.current_pcap = "";
            }
            pkt_arp = pkt_dhcp = pkt_mdns = pkt_ssdp = pkt_dns = 0;
            continue; // Kiểm tra lại queue trước khi loop stable
          }

          // Chạy 1 lần stable PCAP
          ++loop_count;
          {
            std::lock_guard<std::mutex> lock(pcap_queue.mutex);
            pcap_queue.current_pcap = stable_pcap;
          }
          if (loop_count % 10 == 1) {
            spdlog::info(
                "[STABLE] Loop #{} — {}", loop_count,
                stable_pcap.substr(stable_pcap.find_last_of("/\\") + 1));
          }

          uint64_t pkts_before = packet_count.load();
          auto t0 = std::chrono::steady_clock::now();
          try {
            g_reader = std::make_unique<pnads::PcapReader>(stable_pcap, false);
            if (!g_reader->set_filter(bpf_filter))
              g_reader->set_filter("arp or (udp and (port 67 or port 68))");
            g_reader->start(callback);
            tracker.flush_events();
          } catch (const std::exception &e) {
            tracker.flush_events(); // xả nốt kể cả khi lỗi
            spdlog::error("[STABLE] Failed to read {}: {}", stable_pcap,
                          e.what());
            std::this_thread::sleep_for(std::chrono::seconds(2));
          }

          // Tính tốc độ cho mỗi lần loop luôn để dễ quan sát
          double elapsed = std::chrono::duration<double>(
                               std::chrono::steady_clock::now() - t0)
                               .count();
          uint64_t processed = packet_count.load() - pkts_before;
          double pps = (elapsed > 0) ? processed / elapsed : 0;
          spdlog::info(
              "[STABLE] Loop #{} done | {:.2f}s | {} pkts | {:.0f} pkt/s",
              loop_count, elapsed, processed, pps);
          pkt_arp = pkt_dhcp = pkt_mdns = pkt_ssdp = pkt_dns = 0;

          {
            std::lock_guard<std::mutex> lock(pcap_queue.mutex);
            pcap_queue.current_pcap = "";
          }
          // Không sleep — loop ngay lập tức để liên tục
        }
      }
    }
  } catch (const std::exception &e) {
    spdlog::critical("Fatal error: {}", e.what());
    return 1;
  }

  return 0;
}

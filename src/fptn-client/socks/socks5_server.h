/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "fptn-client/socks/tunnel_resolver.h"

namespace fptn::socks {

// SOCKS5 entry point for coexistence with a transparent proxy in front of the
// client. CONNECT only: QUIC and other UDP do not traverse it, so they either
// stay outside the tunnel or the application has to fall back to TCP.
class Socks5Server {
 public:
  struct Config {
    std::string listen_address = "127.0.0.1";
    std::uint16_t listen_port = 1080;
    std::string tun_interface_name;
    std::string tun_address_ipv4;
    std::string tun_address_ipv6;
    std::string dns_server_ipv4;
    int connect_timeout_ms = 10000;
  };

  explicit Socks5Server(Config config);
  ~Socks5Server();

  Socks5Server(const Socks5Server&) = delete;
  Socks5Server& operator=(const Socks5Server&) = delete;

  bool Start();
  void Stop();
  bool IsRunning() const noexcept { return running_.load(); }

 private:
  boost::asio::awaitable<void> AcceptLoop();
  boost::asio::awaitable<void> HandleSession(
      boost::asio::ip::tcp::socket client);
  boost::asio::awaitable<void> Relay(boost::asio::ip::tcp::socket& from,
      boost::asio::ip::tcp::socket& to);

  Config config_;
  boost::asio::io_context ioc_;
  std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
  std::unique_ptr<TunnelResolver> resolver_;
  std::thread thread_;
  std::atomic<bool> running_{false};
  std::atomic<std::uint64_t> session_counter_{0};
};

using Socks5ServerPtr = std::unique_ptr<Socks5Server>;

}  // namespace fptn::socks

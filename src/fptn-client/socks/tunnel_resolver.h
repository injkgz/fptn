/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address.hpp>

namespace fptn::socks {

class TunnelResolver {
 public:
  struct Config {
    std::string dns_server_ipv4;
    std::string bind_address_ipv4;
    int timeout_ms = 4000;
  };

  explicit TunnelResolver(Config config);

  // An empty result means the name could not be resolved.
  // A is tried first, AAAA on failure.
  boost::asio::awaitable<std::vector<boost::asio::ip::address>> Resolve(
      std::string host);

 private:
  boost::asio::awaitable<std::vector<boost::asio::ip::address>> Query(
      const std::string& host, std::uint16_t qtype);

  Config config_;
};

}  // namespace fptn::socks

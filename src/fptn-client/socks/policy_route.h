/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <string>

namespace fptn::socks {

class PolicyRoute {
 public:
  struct Config {
    std::string tun_interface_name;
    std::string tun_address_ipv4;
    std::string tun_address_ipv6;
    std::uint32_t table_id = 100;
    std::uint32_t rule_priority = 10000;
  };

  explicit PolicyRoute(Config config);
  ~PolicyRoute();

  PolicyRoute(const PolicyRoute&) = delete;
  PolicyRoute& operator=(const PolicyRoute&) = delete;

  // Idempotent: removes leftovers from a previous run before adding.
  bool Apply();
  void Clean();

 private:
  Config config_;
  bool applied_ = false;
};

}  // namespace fptn::socks

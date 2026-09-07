/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-client/socks/policy_route.h"

#include <string>
#include <utility>

#include <fmt/format.h>      // NOLINT(build/include_order)
#include <spdlog/spdlog.h>   // NOLINT(build/include_order)

#include "common/system/command.h"

namespace fptn::socks {

namespace {

// Commands whose failure is expected (deleting something that is absent).
void RunQuiet(const std::string& command) {
  fptn::common::system::command::run(command);
}
bool RunChecked(const std::string& command) {
  if (!fptn::common::system::command::run(command)) {
    SPDLOG_ERROR("Command failed: {}", command);
    return false;
  }
  return true;
}

}  // namespace

PolicyRoute::PolicyRoute(Config config) : config_(std::move(config)) {}

PolicyRoute::~PolicyRoute() { Clean(); }

bool PolicyRoute::Apply() {
  if (config_.tun_interface_name.empty()) {
    SPDLOG_ERROR("PolicyRoute: TUN interface name is empty");
    return false;
  }

  // Clean leftovers from a previous run (e.g. after the process crashed).
  Clean();

  const auto table = std::to_string(config_.table_id);

  if (!RunChecked(fmt::format("ip route replace default dev {} table {}",
          config_.tun_interface_name, table))) {
    return false;
  }

  if (!config_.tun_address_ipv4.empty()) {
    if (!RunChecked(fmt::format("ip rule add from {} lookup {} priority {}",
            config_.tun_address_ipv4, table, config_.rule_priority))) {
      Clean();
      return false;
    }
  }

  // IPv6 is optional: many ISPs do not provide it and that must not be fatal.
  if (!config_.tun_address_ipv6.empty()) {
    RunQuiet(fmt::format("ip -6 route replace default dev {} table {}",
        config_.tun_interface_name, table));
    RunQuiet(fmt::format("ip -6 rule add from {} lookup {} priority {}",
        config_.tun_address_ipv6, table, config_.rule_priority));
  }

  applied_ = true;
  SPDLOG_INFO(
      "Policy routing applied: from {} lookup {} (default dev {}), "
      "main table untouched",
      config_.tun_address_ipv4, table, config_.tun_interface_name);
  return true;
}

void PolicyRoute::Clean() {
  const auto table = std::to_string(config_.table_id);

  if (!config_.tun_address_ipv4.empty()) {
    RunQuiet(fmt::format("ip rule del from {} lookup {} priority {}",
        config_.tun_address_ipv4, table, config_.rule_priority));
  }
  if (!config_.tun_address_ipv6.empty()) {
    RunQuiet(fmt::format("ip -6 rule del from {} lookup {} priority {}",
        config_.tun_address_ipv6, table, config_.rule_priority));
  }
  RunQuiet(fmt::format("ip route flush table {}", table));
  RunQuiet(fmt::format("ip -6 route flush table {}", table));

  if (applied_) {
    SPDLOG_INFO("Policy routing removed (table {})", table);
    applied_ = false;
  }
}

}  // namespace fptn::socks

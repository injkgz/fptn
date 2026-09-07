/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/socket_options.h"

#include <atomic>

#if defined(__linux__)
#include <sys/socket.h>  // NOLINT(build/include_order)

#include <cerrno>
#include <cstring>
#endif

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace {
std::atomic<std::uint32_t> g_routing_mark{0};
}  // namespace

namespace fptn::protocol::https {

void SetRoutingMark(std::uint32_t mark) noexcept {
  g_routing_mark.store(mark, std::memory_order_relaxed);
  if (mark != 0) {
    SPDLOG_INFO("Routing mark (SO_MARK) enabled: 0x{:08x}", mark);
  }
}

std::uint32_t GetRoutingMark() noexcept {
  return g_routing_mark.load(std::memory_order_relaxed);
}

bool ApplyRoutingMark(int fd) noexcept {
  const std::uint32_t mark = GetRoutingMark();
  if (mark == 0 || fd < 0) {
    return true;
  }
#if defined(__linux__)
  const int value = static_cast<int>(mark);
  if (::setsockopt(fd, SOL_SOCKET, SO_MARK, &value, sizeof(value)) != 0) {
    // Not fatal: without CAP_NET_ADMIN the kernel refuses, the client keeps
    // running unmarked - only mark-based exclusion rules stop working.
    SPDLOG_WARN("Failed to set SO_MARK=0x{:08x} on fd={}: {}", mark, fd,
        std::strerror(errno));
    return false;
  }
  SPDLOG_DEBUG("SO_MARK=0x{:08x} applied to fd={}", mark, fd);
  return true;
#else
  (void)fd;
  return true;
#endif
}

}  // namespace fptn::protocol::https

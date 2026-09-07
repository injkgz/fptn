/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>

namespace fptn::protocol::https {

// Routing mark (SO_MARK) applied to every outgoing client socket.
//
// Needed on routers where client traffic is captured by a transparent proxy
// (ZeroBlock/tproxy) or processed by a DPI-bypass tool (zapret2). The client's
// own connections to the FPTN server get marked so that nftables rules can
// exclude them and avoid a tunnel-inside-tunnel loop.
//
// A value of 0 disables marking. Disabled by default.
void SetRoutingMark(std::uint32_t mark) noexcept;

std::uint32_t GetRoutingMark() noexcept;

// Sets SO_MARK on an already opened socket. Call it BEFORE connect(), otherwise
// the SYN goes out unmarked. Returns false only on a real setsockopt error;
// when no mark is set or the platform is not Linux this is a no-op returning true.
bool ApplyRoutingMark(int fd) noexcept;

}  // namespace fptn::protocol::https

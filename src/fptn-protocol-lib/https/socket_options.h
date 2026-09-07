/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>

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

// Connects to the first resolved endpoint with the mark already set, which the
// stock connect helpers cannot do: they open the socket themselves, so the SYN
// is on its way before there is a descriptor to mark. Only for the marked path;
// with no mark configured callers keep their normal connect.
boost::asio::ip::tcp::endpoint ConnectMarked(boost::asio::ip::tcp::socket& socket,
    const boost::asio::ip::tcp::resolver::results_type& results,
    boost::system::error_code& ec);

}  // namespace fptn::protocol::https

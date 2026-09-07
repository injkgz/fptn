/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-client/socks/tunnel_resolver.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/socket_options.h"

namespace fptn::socks {

namespace {

constexpr std::uint16_t kTypeA = 1;
constexpr std::uint16_t kTypeAAAA = 28;
constexpr std::size_t kHeaderSize = 12;
constexpr std::size_t kMaxResponseSize = 1500;

void PutU16(std::vector<std::uint8_t>& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value >> 8));
  out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

std::uint16_t GetU16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

// Encodes "example.com" into a sequence of DNS labels.
bool EncodeName(const std::string& host, std::vector<std::uint8_t>& out) {
  std::size_t start = 0;
  while (start <= host.size()) {
    const std::size_t dot = host.find('.', start);
    const std::size_t end = (dot == std::string::npos) ? host.size() : dot;
    const std::size_t len = end - start;
    if (len == 0) {
      // An empty label is only valid as the trailing dot at the end of a name.
      if (end != host.size()) {
        return false;
      }
      break;
    }
    if (len > 63) {
      return false;
    }
    out.push_back(static_cast<std::uint8_t>(len));
    out.insert(out.end(), host.begin() + static_cast<long>(start),
        host.begin() + static_cast<long>(end));
    if (dot == std::string::npos) {
      break;
    }
    start = end + 1;
  }
  out.push_back(0);
  return true;
}

// Skips a name in the response: either a label chain or a compression pointer.
bool SkipName(const std::uint8_t* data, std::size_t size, std::size_t& offset) {
  while (offset < size) {
    const std::uint8_t len = data[offset];
    if ((len & 0xC0) == 0xC0) {
      offset += 2;  // a pointer is exactly two bytes
      return offset <= size;
    }
    offset += 1;
    if (len == 0) {
      return true;
    }
    offset += len;
  }
  return false;
}

}  // namespace

TunnelResolver::TunnelResolver(Config config) : config_(std::move(config)) {}

boost::asio::awaitable<std::vector<boost::asio::ip::address>>
TunnelResolver::Resolve(std::string host) {
  if (!host.empty() && host.back() == '.') {
    host.pop_back();
  }

  auto result = co_await Query(host, kTypeA);
  if (result.empty()) {
    result = co_await Query(host, kTypeAAAA);
  }
  co_return result;
}

boost::asio::awaitable<std::vector<boost::asio::ip::address>>
TunnelResolver::Query(const std::string& host, std::uint16_t qtype) {
  using boost::asio::experimental::awaitable_operators::operator||;

  std::vector<boost::asio::ip::address> addresses;

  static thread_local std::mt19937 rng{std::random_device{}()};
  const auto query_id = static_cast<std::uint16_t>(
      std::uniform_int_distribution<int>(1, 0xFFFF)(rng));

  std::vector<std::uint8_t> request;
  request.reserve(64);
  PutU16(request, query_id);
  PutU16(request, 0x0100);  // RD - recursion desired
  PutU16(request, 1);       // QDCOUNT
  PutU16(request, 0);       // ANCOUNT
  PutU16(request, 0);       // NSCOUNT
  PutU16(request, 0);       // ARCOUNT
  if (!EncodeName(host, request)) {
    SPDLOG_WARN("TunnelResolver: bad hostname '{}'", host);
    co_return addresses;
  }
  PutU16(request, qtype);
  PutU16(request, 1);  // IN

  boost::system::error_code ec;
  auto executor = co_await boost::asio::this_coro::executor;
  boost::asio::ip::udp::socket socket(executor);

  socket.open(boost::asio::ip::udp::v4(), ec);
  if (ec) {
    SPDLOG_ERROR("TunnelResolver: socket open failed: {}", ec.message());
    co_return addresses;
  }
  fptn::protocol::https::ApplyRoutingMark(socket.native_handle());

  if (!config_.bind_address_ipv4.empty()) {
    const auto bind_addr =
        boost::asio::ip::make_address(config_.bind_address_ipv4, ec);
    if (!ec) {
      socket.bind(boost::asio::ip::udp::endpoint(bind_addr, 0), ec);
      if (ec) {
        SPDLOG_ERROR("TunnelResolver: bind to {} failed: {}",
            config_.bind_address_ipv4, ec.message());
        co_return addresses;
      }
    }
  }

  const auto dns_addr =
      boost::asio::ip::make_address(config_.dns_server_ipv4, ec);
  if (ec) {
    SPDLOG_ERROR("TunnelResolver: bad DNS server address '{}'",
        config_.dns_server_ipv4);
    co_return addresses;
  }
  const boost::asio::ip::udp::endpoint dns_endpoint(dns_addr, 53);

  co_await socket.async_send_to(boost::asio::buffer(request), dns_endpoint,
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec) {
    SPDLOG_WARN("TunnelResolver: send failed: {}", ec.message());
    co_return addresses;
  }

  std::array<std::uint8_t, kMaxResponseSize> response{};
  boost::asio::ip::udp::endpoint from;
  boost::asio::steady_timer timer(executor);
  timer.expires_after(std::chrono::milliseconds(config_.timeout_ms));

  std::size_t received = 0;
  boost::system::error_code recv_ec;
  const auto outcome = co_await (
      socket.async_receive_from(boost::asio::buffer(response), from,
          boost::asio::redirect_error(boost::asio::use_awaitable, recv_ec)) ||
      timer.async_wait(
          boost::asio::redirect_error(boost::asio::use_awaitable, ec)));

  if (outcome.index() == 1) {
    SPDLOG_WARN("TunnelResolver: timeout resolving '{}' via {}", host,
        config_.dns_server_ipv4);
    socket.close(ec);
    co_return addresses;
  }
  received = std::get<0>(outcome);
  if (recv_ec || received < kHeaderSize) {
    SPDLOG_WARN("TunnelResolver: receive failed for '{}': {}", host,
        recv_ec.message());
    co_return addresses;
  }

  const std::uint8_t* data = response.data();
  if (GetU16(data) != query_id) {
    SPDLOG_WARN("TunnelResolver: response id mismatch for '{}'", host);
    co_return addresses;
  }
  const std::uint16_t qdcount = GetU16(data + 4);
  const std::uint16_t ancount = GetU16(data + 6);

  std::size_t offset = kHeaderSize;
  for (std::uint16_t i = 0; i < qdcount; ++i) {
    if (!SkipName(data, received, offset)) {
      co_return addresses;
    }
    offset += 4;  // QTYPE + QCLASS
  }

  for (std::uint16_t i = 0; i < ancount && offset + 10 <= received; ++i) {
    if (!SkipName(data, received, offset)) {
      break;
    }
    if (offset + 10 > received) {
      break;
    }
    const std::uint16_t rtype = GetU16(data + offset);
    const std::uint16_t rdlength = GetU16(data + offset + 8);
    offset += 10;
    if (offset + rdlength > received) {
      break;
    }
    if (rtype == kTypeA && rdlength == 4) {
      boost::asio::ip::address_v4::bytes_type bytes{};
      std::memcpy(bytes.data(), data + offset, bytes.size());
      addresses.emplace_back(boost::asio::ip::address_v4(bytes));
    } else if (rtype == kTypeAAAA && rdlength == 16) {
      boost::asio::ip::address_v6::bytes_type bytes{};
      std::memcpy(bytes.data(), data + offset, bytes.size());
      addresses.emplace_back(boost::asio::ip::address_v6(bytes));
    }
    offset += rdlength;
  }

  SPDLOG_DEBUG("TunnelResolver: '{}' -> {} address(es)", host, addresses.size());
  co_return addresses;
}

}  // namespace fptn::socks

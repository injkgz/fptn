/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-client/socks/socks5_server.h"

#include "fptn-client/socks/udp_associate.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/socket_options.h"

namespace fptn::socks {

namespace {

constexpr std::uint8_t kVersion = 0x05;
constexpr std::uint8_t kAuthNone = 0x00;
constexpr std::uint8_t kAuthUnacceptable = 0xFF;

constexpr std::uint8_t kCmdConnect = 0x01;
constexpr std::uint8_t kCmdUdpAssociate = 0x03;

constexpr std::uint8_t kAtypIPv4 = 0x01;
constexpr std::uint8_t kAtypDomain = 0x03;
constexpr std::uint8_t kAtypIPv6 = 0x04;

constexpr std::uint8_t kRepSuccess = 0x00;
constexpr std::uint8_t kRepGeneralFailure = 0x01;
constexpr std::uint8_t kRepNetworkUnreachable = 0x03;
constexpr std::uint8_t kRepHostUnreachable = 0x04;
constexpr std::uint8_t kRepConnectionRefused = 0x05;
constexpr std::uint8_t kRepTtlExpired = 0x06;
constexpr std::uint8_t kRepCommandNotSupported = 0x07;
constexpr std::uint8_t kRepAddressNotSupported = 0x08;

constexpr std::size_t kRelayBufferSize = 32 * 1024;

std::uint8_t ErrorToReply(const boost::system::error_code& ec) {
  if (ec == boost::asio::error::connection_refused) {
    return kRepConnectionRefused;
  }
  if (ec == boost::asio::error::network_unreachable) {
    return kRepNetworkUnreachable;
  }
  if (ec == boost::asio::error::host_unreachable ||
      ec == boost::asio::error::host_not_found) {
    return kRepHostUnreachable;
  }
  if (ec == boost::asio::error::timed_out) {
    return kRepTtlExpired;
  }
  return kRepGeneralFailure;
}

// Reply to the client. We have nothing meaningful to report in BND.ADDR/BND.PORT,
// so we send zeroes - every practical implementation does that and clients accept it.
boost::asio::awaitable<void> SendReply(
    boost::asio::ip::tcp::socket& client, std::uint8_t reply) {
  const std::array<std::uint8_t, 10> response{
      kVersion, reply, 0x00, kAtypIPv4, 0, 0, 0, 0, 0, 0};
  boost::system::error_code ec;
  co_await boost::asio::async_write(client, boost::asio::buffer(response),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
}

// Reply carrying a real BND.ADDR/BND.PORT, which UDP ASSOCIATE needs: it tells
// the client where to send its datagrams.
boost::asio::awaitable<void> SendReplyWithEndpoint(
    boost::asio::ip::tcp::socket& client,
    std::uint8_t reply,
    const boost::asio::ip::udp::endpoint& endpoint) {
  std::vector<std::uint8_t> response{kVersion, reply, 0x00};
  if (endpoint.address().is_v4()) {
    const auto bytes = endpoint.address().to_v4().to_bytes();
    response.push_back(kAtypIPv4);
    response.insert(response.end(), bytes.begin(), bytes.end());
  } else {
    const auto bytes = endpoint.address().to_v6().to_bytes();
    response.push_back(kAtypIPv6);
    response.insert(response.end(), bytes.begin(), bytes.end());
  }
  response.push_back(static_cast<std::uint8_t>(endpoint.port() >> 8));
  response.push_back(static_cast<std::uint8_t>(endpoint.port() & 0xFF));

  boost::system::error_code ec;
  co_await boost::asio::async_write(client, boost::asio::buffer(response),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
}

}  // namespace

Socks5Server::Socks5Server(Config config) : config_(std::move(config)) {
  resolver_ = std::make_unique<TunnelResolver>(TunnelResolver::Config{
      .dns_server_ipv4 = config_.dns_server_ipv4,
      .bind_address_ipv4 = config_.tun_address_ipv4,
  });
}

Socks5Server::~Socks5Server() { Stop(); }

bool Socks5Server::Start() {
  if (running_.load()) {
    return true;
  }

  boost::system::error_code ec;
  const auto address =
      boost::asio::ip::make_address(config_.listen_address, ec);
  if (ec) {
    SPDLOG_ERROR("SOCKS5: bad listen address '{}': {}", config_.listen_address,
        ec.message());
    return false;
  }

  const boost::asio::ip::tcp::endpoint endpoint(address, config_.listen_port);
  acceptor_ = std::make_unique<boost::asio::ip::tcp::acceptor>(ioc_);
  acceptor_->open(endpoint.protocol(), ec);
  if (ec) {
    SPDLOG_ERROR("SOCKS5: acceptor open failed: {}", ec.message());
    return false;
  }
  acceptor_->set_option(boost::asio::socket_base::reuse_address(true), ec);
  acceptor_->bind(endpoint, ec);
  if (ec) {
    SPDLOG_ERROR("SOCKS5: bind to {}:{} failed: {}", config_.listen_address,
        config_.listen_port, ec.message());
    return false;
  }
  acceptor_->listen(boost::asio::socket_base::max_listen_connections, ec);
  if (ec) {
    SPDLOG_ERROR("SOCKS5: listen failed: {}", ec.message());
    return false;
  }

  running_.store(true);
  boost::asio::co_spawn(
      ioc_, [this]() -> boost::asio::awaitable<void> { co_await AcceptLoop(); },
      boost::asio::detached);

  thread_ = std::thread([this]() {
    try {
      ioc_.run();
    } catch (const std::exception& ex) {
      SPDLOG_ERROR("SOCKS5: io_context stopped with exception: {}", ex.what());
    }
  });

  SPDLOG_INFO("SOCKS5 proxy listening on {}:{} (via {} / {})",
      config_.listen_address, config_.listen_port, config_.tun_interface_name,
      config_.tun_address_ipv4);
  return true;
}

void Socks5Server::Stop() {
  if (!running_.exchange(false)) {
    return;
  }
  boost::system::error_code ec;
  if (acceptor_) {
    acceptor_->close(ec);
  }
  ioc_.stop();
  if (thread_.joinable()) {
    thread_.join();
  }
  SPDLOG_INFO("SOCKS5 proxy stopped");
}

boost::asio::awaitable<void> Socks5Server::AcceptLoop() {
  while (running_.load()) {
    boost::system::error_code ec;
    auto client = co_await acceptor_->async_accept(
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      if (running_.load()) {
        SPDLOG_WARN("SOCKS5: accept failed: {}", ec.message());
      }
      continue;
    }
    boost::asio::co_spawn(
        ioc_,
        [this, sock = std::move(client)]() mutable
        -> boost::asio::awaitable<void> {
          co_await HandleSession(std::move(sock));
        },
        boost::asio::detached);
  }
}

boost::asio::awaitable<void> Socks5Server::HandleSession(
    boost::asio::ip::tcp::socket client) {
  using boost::asio::experimental::awaitable_operators::operator&&;
  using boost::asio::experimental::awaitable_operators::operator||;

  const auto session_id = ++session_counter_;
  boost::system::error_code ec;
  auto executor = co_await boost::asio::this_coro::executor;

  // --- greeting: VER | NMETHODS | METHODS... ---
  std::array<std::uint8_t, 2> greeting{};
  co_await boost::asio::async_read(client, boost::asio::buffer(greeting),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec || greeting[0] != kVersion) {
    SPDLOG_DEBUG("SOCKS5[{}]: bad greeting", session_id);
    co_return;
  }
  std::vector<std::uint8_t> methods(greeting[1]);
  if (greeting[1] > 0) {
    co_await boost::asio::async_read(client, boost::asio::buffer(methods),
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      co_return;
    }
  }
  const bool no_auth_supported =
      std::find(methods.begin(), methods.end(), kAuthNone) != methods.end();
  const std::array<std::uint8_t, 2> method_reply{
      kVersion, no_auth_supported ? kAuthNone : kAuthUnacceptable};
  co_await boost::asio::async_write(client, boost::asio::buffer(method_reply),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec || !no_auth_supported) {
    co_return;
  }

  // --- request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT ---
  std::array<std::uint8_t, 4> header{};
  co_await boost::asio::async_read(client, boost::asio::buffer(header),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec || header[0] != kVersion) {
    co_return;
  }
  const std::uint8_t command = header[1];
  if (command != kCmdConnect && command != kCmdUdpAssociate) {
    SPDLOG_WARN("SOCKS5[{}]: unsupported command {}", session_id, command);
    co_await SendReply(client, kRepCommandNotSupported);
    co_return;
  }

  std::string target_host;
  boost::asio::ip::address target_address;
  bool have_address = false;

  switch (header[3]) {
    case kAtypIPv4: {
      boost::asio::ip::address_v4::bytes_type bytes{};
      co_await boost::asio::async_read(client, boost::asio::buffer(bytes),
          boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec) {
        co_return;
      }
      target_address = boost::asio::ip::address_v4(bytes);
      have_address = true;
      break;
    }
    case kAtypIPv6: {
      boost::asio::ip::address_v6::bytes_type bytes{};
      co_await boost::asio::async_read(client, boost::asio::buffer(bytes),
          boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec) {
        co_return;
      }
      target_address = boost::asio::ip::address_v6(bytes);
      have_address = true;
      break;
    }
    case kAtypDomain: {
      std::uint8_t length = 0;
      co_await boost::asio::async_read(client,
          boost::asio::buffer(&length, 1),
          boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec || length == 0) {
        co_return;
      }
      std::vector<char> name(length);
      co_await boost::asio::async_read(client, boost::asio::buffer(name),
          boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec) {
        co_return;
      }
      target_host.assign(name.begin(), name.end());
      break;
    }
    default:
      co_await SendReply(client, kRepAddressNotSupported);
      co_return;
  }

  std::array<std::uint8_t, 2> port_bytes{};
  co_await boost::asio::async_read(client, boost::asio::buffer(port_bytes),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec) {
    co_return;
  }
  const auto target_port =
      static_cast<std::uint16_t>((port_bytes[0] << 8) | port_bytes[1]);

  if (command == kCmdUdpAssociate) {
    co_await HandleUdpAssociate(client, session_id);
    co_return;
  }

  // Resolve the name through the tunnel, otherwise the local dnsmasq hands us a FakeIP.
  if (!have_address) {
    const auto resolved = co_await resolver_->Resolve(target_host);
    if (resolved.empty()) {
      SPDLOG_WARN("SOCKS5[{}]: cannot resolve '{}'", session_id, target_host);
      co_await SendReply(client, kRepHostUnreachable);
      co_return;
    }
    target_address = resolved.front();
  }

  // --- outgoing connection through the tunnel ---
  const boost::asio::ip::tcp::endpoint target(target_address, target_port);
  boost::asio::ip::tcp::socket remote(executor);

  remote.open(target.protocol(), ec);
  if (ec) {
    co_await SendReply(client, kRepGeneralFailure);
    co_return;
  }
  fptn::protocol::https::ApplyRoutingMark(remote.native_handle());

  // Bind to the tunnel address: the policy rule then steers packets into the TUN.
  const std::string& bind_ip = target_address.is_v4()
                                   ? config_.tun_address_ipv4
                                   : config_.tun_address_ipv6;
  if (!bind_ip.empty()) {
    const auto bind_addr = boost::asio::ip::make_address(bind_ip, ec);
    if (!ec) {
      remote.bind(boost::asio::ip::tcp::endpoint(bind_addr, 0), ec);
      if (ec) {
        SPDLOG_WARN("SOCKS5[{}]: bind to {} failed: {}", session_id, bind_ip,
            ec.message());
        co_await SendReply(client, kRepGeneralFailure);
        co_return;
      }
    }
  }

  boost::asio::steady_timer connect_timer(executor);
  connect_timer.expires_after(
      std::chrono::milliseconds(config_.connect_timeout_ms));
  boost::system::error_code connect_ec;
  boost::system::error_code timer_ec;
  const auto outcome = co_await (
      remote.async_connect(target,
          boost::asio::redirect_error(boost::asio::use_awaitable,
              connect_ec)) ||
      connect_timer.async_wait(
          boost::asio::redirect_error(boost::asio::use_awaitable, timer_ec)));

  if (outcome.index() == 1) {
    SPDLOG_WARN("SOCKS5[{}]: connect to {}:{} timed out", session_id,
        target_address.to_string(), target_port);
    remote.close(ec);
    co_await SendReply(client, kRepTtlExpired);
    co_return;
  }
  connect_timer.cancel();
  if (connect_ec) {
    SPDLOG_WARN("SOCKS5[{}]: connect to {}:{} failed: {}", session_id,
        target_address.to_string(), target_port, connect_ec.message());
    co_await SendReply(client, ErrorToReply(connect_ec));
    co_return;
  }

  remote.set_option(boost::asio::ip::tcp::no_delay(true), ec);
  client.set_option(boost::asio::ip::tcp::no_delay(true), ec);

  co_await SendReply(client, kRepSuccess);
  SPDLOG_DEBUG("SOCKS5[{}]: {} -> {}:{}", session_id,
      target_host.empty() ? "ip" : target_host, target_address.to_string(),
      target_port);

  // --- relay data in both directions ---
  co_await (Relay(client, remote) && Relay(remote, client));

  client.close(ec);
  remote.close(ec);
}

boost::asio::awaitable<void> Socks5Server::Relay(
    boost::asio::ip::tcp::socket& from, boost::asio::ip::tcp::socket& to) {
  std::vector<std::uint8_t> buffer(kRelayBufferSize);
  boost::system::error_code ec;

  for (;;) {
    const std::size_t bytes = co_await from.async_read_some(
        boost::asio::buffer(buffer),
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec || bytes == 0) {
      break;
    }
    co_await boost::asio::async_write(to,
        boost::asio::buffer(buffer.data(), bytes),
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      break;
    }
  }

  // Half-close the peer socket, otherwise the opposite coroutine hangs forever.
  boost::system::error_code shutdown_ec;
  to.shutdown(boost::asio::ip::tcp::socket::shutdown_send, shutdown_ec);
}

// The association is owned by this coroutine, so it dies with the control
// connection exactly as RFC 1928 requires. Both directions are awaited
// together: whichever ends first tears the other down.
boost::asio::awaitable<void> Socks5Server::HandleUdpAssociate(
    boost::asio::ip::tcp::socket& client, std::uint64_t session_id) {
  using boost::asio::experimental::awaitable_operators::operator||;

  auto executor = co_await boost::asio::this_coro::executor;
  UdpAssociate associate(executor,
      UdpAssociate::Config{
          .listen_address = config_.listen_address,
          .tun_address_ipv4 = config_.tun_address_ipv4,
          .tun_address_ipv6 = config_.tun_address_ipv6,
      },
      resolver_.get(), session_id);

  boost::system::error_code ec;
  if (!associate.Open(ec)) {
    SPDLOG_WARN("SOCKS5[{}]: UDP associate failed: {}", session_id,
        ec.message());
    co_await SendReply(client, kRepGeneralFailure);
    co_return;
  }

  co_await SendReplyWithEndpoint(
      client, kRepSuccess, associate.BoundEndpoint());
  SPDLOG_DEBUG("SOCKS5[{}]: UDP associate on {}:{}", session_id,
      associate.BoundEndpoint().address().to_string(),
      associate.BoundEndpoint().port());

  // Reading the control connection is how its close is noticed; a compliant
  // client sends nothing on it, so any byte just keeps the wait alive.
  co_await (associate.Run() || WaitForClose(client));
  associate.Close();
}

boost::asio::awaitable<void> Socks5Server::WaitForClose(
    boost::asio::ip::tcp::socket& client) {
  std::array<std::uint8_t, 64> scratch{};
  boost::system::error_code ec;
  for (;;) {
    co_await client.async_read_some(boost::asio::buffer(scratch),
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      co_return;
    }
  }
}

}  // namespace fptn::socks

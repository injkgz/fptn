/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include "fptn-client/socks/tunnel_resolver.h"

namespace fptn::socks {

// UDP ASSOCIATE (RFC 1928 section 4, datagram format in section 7), the half of
// SOCKS5 that carries QUIC and plain UDP.
//
// Same approach as the TCP side: no user-space UDP stack. Datagrams arriving on
// the relay socket are unwrapped and sent from a kernel socket bound to the TUN
// address, so the policy rule steers them into the tunnel; replies are wrapped
// back into the SOCKS5 header and returned to the client.
//
// One association per control connection, as the RFC requires: the association
// lives exactly as long as the TCP connection that requested it, and the caller
// destroys this object when that connection ends.
//
// Fragmentation (FRAG != 0) is rejected. No mainstream implementation emits it,
// and reassembly would mean holding partial datagrams with no way to know when
// the rest is coming.
class UdpAssociate {
 public:
  struct Config {
    // Address the relay socket binds to; the client is told where to send.
    std::string listen_address;
    std::string tun_address_ipv4;
    std::string tun_address_ipv6;
    // How long an idle target socket is kept before it is closed.
    std::chrono::seconds session_timeout{60};
  };

  UdpAssociate(boost::asio::any_io_executor executor,
      Config config,
      TunnelResolver* resolver,
      std::uint64_t session_id);
  ~UdpAssociate();

  UdpAssociate(const UdpAssociate&) = delete;
  UdpAssociate& operator=(const UdpAssociate&) = delete;

  // Opens the relay socket. On success the endpoint to report to the client in
  // BND.ADDR/BND.PORT is available through BoundEndpoint().
  bool Open(boost::system::error_code& ec);

  const boost::asio::ip::udp::endpoint& BoundEndpoint() const noexcept {
    return bound_;
  }

  // Relays until the object is closed. Returns when the relay socket fails,
  // which is how the caller learns the association ended.
  boost::asio::awaitable<void> Run();

  void Close();

 private:
  // One target the client talks to. Each gets its own socket bound to the TUN
  // address so the kernel keeps the source port stable, which is what NAT on
  // the far side expects.
  struct Session {
    boost::asio::ip::udp::socket socket;
    boost::asio::ip::udp::endpoint client;
    std::chrono::steady_clock::time_point last_used;
    bool receiving = false;
  };

  using Key = std::pair<boost::asio::ip::udp::endpoint,
      boost::asio::ip::udp::endpoint>;

  boost::asio::awaitable<void> HandleDatagram(
      const boost::asio::ip::udp::endpoint& from,
      const std::uint8_t* data,
      std::size_t size);

  // Pumps replies from one target socket back to the client until it errors or
  // the association closes.
  boost::asio::awaitable<void> ReceiveLoop(Key key);

  Session* FindOrCreate(const Key& key,
      const boost::asio::ip::udp::endpoint& client,
      boost::system::error_code& ec);

  void SweepIdle();

  boost::asio::any_io_executor executor_;
  Config config_;
  TunnelResolver* resolver_;
  std::uint64_t session_id_;

  boost::asio::ip::udp::socket relay_;
  boost::asio::ip::udp::endpoint bound_;
  // Set from the first datagram: the RFC lets the client announce the address
  // it will send from, but in practice everyone sends zeroes and we learn it.
  boost::asio::ip::udp::endpoint client_;
  std::map<Key, std::unique_ptr<Session>> sessions_;
  bool closed_ = false;
};

}  // namespace fptn::socks

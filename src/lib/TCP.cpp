#include <cassert>

#include <arpa/inet.h>

#include "TCP.h"

#include "utils.h"
#include "log.h"

TCP::TCP(L3 &l3_)
    : dispatcher(l3_.l2.netBase.dispatcher), timer(l3_.l2.netBase.timer),
      l3(l3_) {}

int TCP::setup() {
  for (uint16_t p = DYN_PORTS_BEGIN; p; p++)
    freePorts.insert(p);
  l3.addOnRecv(
      [this](auto &&...args) -> int {
        handleRecv(args...);
        return 0;
      },
      PROTOCOL_ID);
  return 0;
}

bool TCP::hasUse(Sock sock) {
  if (sock.addr == L3::Addr{0})
    return portUserCount.count(sock.port);
  else {
    return sockUserCount.count(sock) &&
           sockUserCount.count({L3::Addr{0}, sock.port});
  }
}

void TCP::addUse(Sock sock) {
  if (sock.port) {
    if (!portUserCount.count(sock.port)) {
      if (sock.port >= DYN_PORTS_BEGIN)
        freePorts.erase(sock.port);
      portUserCount[sock.port] = 1;
    } else {
      portUserCount[sock.port]++;
    }
    if (!sockUserCount.count(sock))
      sockUserCount[sock] = 1;
    else
      sockUserCount[sock]++;
  }
}

void TCP::releaseUse(Sock sock) {
  if (sock.port) {
    if (--portUserCount[sock.port] == 0) {
      portUserCount.erase(sock.port);
      if (sock.port >= DYN_PORTS_BEGIN)
        freePorts.insert(sock.port);
    }
    if (--sockUserCount[sock] == 0)
      sockUserCount.erase(sock);
  }
}

TCP::Desc *TCP::create() {
  return new Desc(*this);
}

TCP::Listener *TCP::listen(Desc *desc) {
  if (desc->local.port == 0) {
    if (freePorts.empty()) {
      LOG_INFO("No port avalibale");
      return nullptr;
    }
    desc->local.port = *freePorts.begin();
    addUse(desc->local);
  }

  auto *listener = new Listener(*desc);
  delete desc;

#ifdef NETSTACK_DEBUG
  assert(!listeners.count(listener->local));
#endif
  listeners[listener->local] = listener;

  return listener;
}

uint16_t TCP::calcChecksum(const void *seg, size_t segLen, L3::Addr src,
                           L3::Addr dst) {
  const TCP::Header &header = *(const Header *)seg;
  size_t dataOff = ((header.offAndRsrv >> 4)) * 4UL;
  PseudoL3Header pseudo{.src = src,
                        .dst = dst,
                        .ptcl = PROTOCOL_ID,
                        .tcpLen = htons(segLen)};
  uint16_t sum = csum16(&pseudo, sizeof(pseudo));
  return csum16(seg, segLen, ~sum);
}

int TCP::reset(const Header &inHeader, L3::Addr inSrc, L3::Addr inDst) {
  uint32_t seqNum = (inHeader.ctrl & CTL_ACK) ? inHeader.ackNum : 0;
  Header header{.srcPort = inHeader.dstPort,
                .dstPort = inHeader.srcPort,
                .seqNum = seqNum,
                .ackNum = htonl(ntohl(inHeader.seqNum) + 1),
                .offAndRsrv = (sizeof(Header) / 4) << 4,
                .ctrl = CTL_RST | CTL_ACK,
                .window = 0,
                .checksum = 0,
                .urgPtr = 0};
  header.checksum = calcChecksum(&header, sizeof(Header), inDst, inSrc);
#ifdef NETSTACK_DEBUG
  assert(calcChecksum(&header, sizeof(Header), inDst, inSrc) == 0);
#endif
  return l3.send(&header, sizeof(Header), inDst, inSrc, PROTOCOL_ID,
                 {.autoRetry = true});
}

void TCP::handleRecv(const void *seg, size_t segLen, const L3::RecvInfo &info) {
  if (segLen < sizeof(Header)) {
    LOG_INFO("Truncated TCP Header: %lu/%lu", segLen, sizeof(Header));
    return;
  }
  const Header &header = *(const Header *)seg;
  size_t dataOff = (header.offAndRsrv >> 4) * 4UL;
  if (segLen < dataOff) {
    LOG_INFO("Truncated TCP Header: %lu/%lu:%lu", segLen, sizeof(Header),
             dataOff);
    return;
  }
  if (calcChecksum(seg, segLen, info.header->src, info.header->dst) != 0) {
    LOG_INFO("TCP checksum error");
    return;
  }

  const void *data = (const char *)seg + dataOff;
  size_t dataLen = segLen - dataOff;
  RecvInfo newInfo{.l3 = info, .header = &header};

  Sock local{.addr = info.header->dst, .port = header.dstPort};
  Sock remote{.addr = info.header->src, .port = header.srcPort};
  auto itConn = connections.find({local, remote});
  if (itConn != connections.end()) {
    itConn->second->handleRecv(data, dataLen, newInfo);
  } else {
    auto itListen = listeners.find(local);
    if (itListen == listeners.end())
      itListen = listeners.find(Sock{.addr{0}, .port = local.port});
    if (itListen != listeners.end())
      itListen->second->handleRecv(data, dataLen, newInfo);
    else
      reset(header, info.header->src, info.header->dst);
  }
}

TCP::Desc::Desc(TCP &tcp_) : tcp(tcp_), local{0, 0} {}
TCP::Desc::~Desc() {}

int TCP::Desc::bind(Sock sock) {
  if (tcp.hasUse(sock)) {
    LOG_ERR("Address already in use: " IP_ADDR_FMT_STRING ":%hu",
            IP_ADDR_FMT_ARGS(sock.addr), sock.port);
    return -1;
  }
  tcp.releaseUse(local);
  local = sock;
  tcp.addUse(sock);
  return 0;
}

TCP::Listener::Listener(Desc &desc) : Desc(desc) {}

void TCP::Listener::close() {
  tcp.listeners.erase(local);
  delete this;
}

void TCP::Listener::handleRecv(const void *data, size_t dataLen,
                               const RecvInfo &info) {
  if (~info.header->ctrl & CTL_SYN) {
    tcp.reset(*info.header, info.l3.header->src, info.l3.header->dst);
    return;
  }
}

void TCP::Connection::handleRecv(const void *data, size_t dataLen,
                               const RecvInfo &info) {
  if (info.header->ctrl & CTL_SYN) {
    tcp.reset(*info.header, info.l3.header->src, info.l3.header->dst);
    return;
  }
}

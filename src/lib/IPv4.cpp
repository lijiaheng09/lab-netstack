#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <netinet/ether.h>

#include "log.h"
#include "utils.h"

#include "IPv4.h"

constexpr int IPv4::PROTOCOL_ID = ETHERTYPE_IP;

IPv4::IPv4(LinkLayer &linkLayer_)
    : linkLayer(linkLayer_), routing(nullptr), linkLayerHandler(*this) {}

void IPv4::addAddr(LinkLayer::Device *device, const Addr &addr) {
  addrs.push_back({device, addr});
}

IPv4::LinkLayer::Device *IPv4::findDeviceByAddr(const Addr &addr) {
  for (auto &&a : addrs)
    if (a.addr == addr)
      return a.dev;
  return nullptr;
}

void IPv4::setRouting(Routing *routing_) {
  routing = routing_;
}

int IPv4::sendPacketWithHeader(void *buf, int len) {
  Header &header = *(Header *)buf;
  if (len < sizeof(Header)) {
    ERRLOG("Truncated IPv4 header: %d/%d\n", len, (int)sizeof(Header));
    return -1;
  }
  int hdrLen = (header.versionAndIHL & 0x0f) * 4;
  int packetLen = ntohs(header.totalLength);
  if (len != packetLen || packetLen < hdrLen) {
    ERRLOG("Invalid IPv4 packet length: %d/%d:%d\n", len, hdrLen, packetLen);
    return -1;
  }

  header.headerChecksum = 0;
  header.headerChecksum = calcInternetChecksum16((const void *)&header, hdrLen);
#ifdef NETSTACK_DEBUG
  assert(calcInternetChecksum16((const void *)&header, hdrLen) == 0);
#endif

  if (!routing) {
    ERRLOG("No IPv4 routing table.\n");
    return -1;
  }
  auto hop = routing->match(header.dst);
  if (!hop.device) {
    ERRLOG("No IPv4 routing for " IPV4_ADDR_FMT_STRING "\n",
           IPV4_ADDR_FMT_ARGS(header.dst));
    return -1;
  }
  return hop.device->sendFrame(buf, len, hop.dstMAC, PROTOCOL_ID);
}

int IPv4::sendPacket(const void *buf, int len, const Addr &src, const Addr &dst,
                     int protocol) {
  int packetLen = sizeof(Header) + len;

  if ((packetLen >> 16) != 0) {
    ERRLOG("Invalid IPv4 packet length: %d\n", packetLen);
    return -1;
  }
  if ((protocol >> 8) != 0) {
    ERRLOG("Invalid IPv4 protocol field: %X\n", protocol);
    return -1;
  }

  void *packet = malloc(packetLen);
  if (!packet) {
    ERRLOG("malloc error: %s\n", strerror(errno));
    return -1;
  }

  Header &header = *(Header *)packet;
  header = Header{
    versionAndIHL : 4 << 4 | 5,
    typeOfService : 0,
    totalLength : htons(packetLen),
    identification : 0,
    flagsAndFragmentOffset : htons(0b010 << 13 | 0),
    timeToLive : 64,
    protocol : (uint8_t)protocol,
    headerChecksum : 0,
    src : src,
    dst : dst
  };
  int rc = sendPacketWithHeader(packet, packetLen);
  free(packet);
  return rc;
}

IPv4::RecvCallback::RecvCallback(bool promiscuous_, int protocol_)
    : promiscuous(promiscuous_), protocol(protocol_) {}

void IPv4::addRecvCallback(RecvCallback *callback) {
  callbacks.push_back(callback);
}

int IPv4::handlePacket(const void *buf, int len) {
  const Header &header = *(const Header *)buf;
  if (len < sizeof(Header)) {
    ERRLOG("Truncated IPv4 header: %d/%d\n", len, (int)sizeof(Header));
    return -1;
  }
  int hdrLen = (header.versionAndIHL & 0x0f) * 4;
  int packetLen = ntohs(header.totalLength);
  if (len < packetLen || packetLen < hdrLen) {
    ERRLOG("Truncated IPv4 packet: %d/%d:%d\n", len, hdrLen, packetLen);
    return -1;
  }
  if (calcInternetChecksum16((const void *)&header, hdrLen) != 0) {
    ERRLOG("IPv4 Checksum error\n");
    return -1;
  }

  LinkLayer::Device *endDevice = findDeviceByAddr(header.dst);
  int protocol = header.protocol;
  int rc = 0;
  for (auto *c : callbacks)
    if (c->promiscuous || endDevice) {
      if (c->protocol == -1 || c->protocol == header.protocol) {
        if (c->handle(buf, packetLen))
          rc = -1;
      }
    }
  return rc;
}

int IPv4::setup() {
  linkLayer.addRecvCallback(&linkLayerHandler);
  return 0;
}

IPv4::LinkLayerHandler::LinkLayerHandler(IPv4 &ipv4Layer_)
    : LinkLayer::RecvCallback(PROTOCOL_ID), ipv4Layer(ipv4Layer_) {}

int IPv4::LinkLayerHandler::handle(const void *buf, int len,
                                   LinkLayer::Device *device) {
  return ipv4Layer.handlePacket(
      (const void *)((const unsigned char *)buf + sizeof(LinkLayer::Header)), len);
}

#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <netinet/ether.h>
#include <arpa/inet.h>

#include "log.h"
#include "utils.h"

#include "IP.h"
#include "ICMP.h"

constexpr int IP::PROTOCOL_ID = ETHERTYPE_IP;
constexpr IP::Addr IP::Addr::BROADCAST{255, 255, 255, 255};

IP::IP(LinkLayer &linkLayer_)
    : linkLayer(linkLayer_), routing(nullptr), linkLayerHandler(*this),
      icmp(*(new ICMP(*this))) {}

IP::~IP() {
  delete &icmp;
}

void IP::addAddr(const DevAddr &entry) {
  addrs.push_back(entry);
}

const Vector<IP::DevAddr> &IP::getAddrs() {
  return addrs;
}

int IP::getAnyAddr(LinkLayer::Device *device, Addr &addr) {
  if (addrs.empty())
    return -1;
  for (auto &&e : addrs)
    if (e.device == device) {
      addr = e.addr;
      return 1;
    }
  addr = addrs.front().addr;
  return 0;
}

IP::LinkLayer::Device *IP::findDeviceByAddr(const Addr &addr) {
  for (auto &&a : addrs)
    if (a.addr == addr)
      return a.device;
  return nullptr;
}

void IP::setRouting(Routing *routing) {
  this->routing = routing;
}

int IP::sendPacketWithHeader(void *packet, int packetLen) {
  Header &header = *(Header *)packet;
  if (packetLen < sizeof(Header)) {
    ERRLOG("Truncated IP header: %d/%d\n", packetLen, (int)sizeof(Header));
    return -1;
  }
  int hdrLen = (header.versionAndIHL & 0x0f) * 4;
  if (ntohs(header.totalLength) != packetLen || packetLen < hdrLen) {
    ERRLOG("Invalid IP packet length: %d/%d:%d\n", packetLen, hdrLen,
           ntohs(header.totalLength));
    return -1;
  }

  header.headerChecksum = 0;
  header.headerChecksum = calcInternetChecksum16(&header, hdrLen);
#ifdef NETSTACK_DEBUG
  assert(calcInternetChecksum16(&header, hdrLen) == 0);
#endif

  int rc = 0;
  bool isBroadcast = false;
  for (auto &&e : addrs)
    if (header.dst == Addr::BROADCAST || header.dst == (e.addr | ~e.mask)) {
      isBroadcast = true;
      if (e.device->sendFrame(packet, packetLen, LinkLayer::Addr::BROADCAST,
                              PROTOCOL_ID) != 0) {
        rc = -1;
      }
    }
  if (isBroadcast)
    return rc;

  if (!routing) {
    ERRLOG("No IP routing policy.\n");
    return -1;
  }
  auto hop = routing->match(header.dst);
  if (!hop.device) {
    ERRLOG("No IP routing for " IP_ADDR_FMT_STRING "\n",
           IP_ADDR_FMT_ARGS(header.dst));
    return -1;
  }
  return hop.device->sendFrame(packet, packetLen, hop.dstMAC, PROTOCOL_ID);
}

int IP::sendPacket(const void *data, int dataLen, const Addr &src,
                   const Addr &dst, int protocol) {
  int packetLen = sizeof(Header) + dataLen;

  if (dataLen < 0 || (packetLen >> 16) != 0) {
    ERRLOG("Invalid IP data length: %d\n", dataLen);
    return -1;
  }
  if ((protocol >> 8) != 0) {
    ERRLOG("Invalid IP protocol field: %X\n", protocol);
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
  memcpy(&header + 1, data, dataLen);
  int rc = sendPacketWithHeader(packet, packetLen);
  free(packet);
  return rc;
}

IP::RecvCallback::RecvCallback(bool promiscuous_, int protocol_)
    : promiscuous(promiscuous_), protocol(protocol_) {}

void IP::addRecvCallback(RecvCallback *callback) {
  callbacks.push_back(callback);
}

int IP::setup() {
  linkLayer.addRecvCallback(&linkLayerHandler);
  return icmp.setup();
}

IP::LinkLayerHandler::LinkLayerHandler(IP &ip_)
    : LinkLayer::RecvCallback(PROTOCOL_ID), ip(ip_) {}

int IP::LinkLayerHandler::handle(const void *packet, int packetCapLen,
                                 const Info &info) {
  if (packetCapLen < sizeof(Header)) {
    ERRLOG("Truncated IP header: %d/%d\n", packetCapLen, (int)sizeof(Header));
    return -1;
  }
  const Header &header = *(const Header *)packet;
  int hdrLen = (header.versionAndIHL & 0x0f) * 4;
  int packetLen = ntohs(header.totalLength);
  if (packetCapLen < packetLen || packetLen < hdrLen) {
    ERRLOG("Truncated IP packet: %d/%d:%d\n", packetCapLen, hdrLen, packetLen);
    return -1;
  }
  if (calcInternetChecksum16(&header, hdrLen) != 0) {
    ERRLOG("IP Checksum error\n");
    return -1;
  }

  IP::RecvCallback::Info newInfo(info);

  LinkLayer::Device *endDevice = nullptr;
  bool isBroadcast = false;

  if (header.dst == Addr::BROADCAST) {
    endDevice = info.linkDevice;
    isBroadcast = true;
  } else {
    for (auto &&e : ip.addrs)
      if (header.dst == (e.addr | ~e.mask)) {
        endDevice = e.device;
        isBroadcast = true;
        break;
      }
  }

  if (!isBroadcast)
    endDevice = ip.findDeviceByAddr(header.dst);
  newInfo.netHeader = &header;
  newInfo.isBroadcast = isBroadcast;
  newInfo.endDevice = endDevice;

  const void *data = (const unsigned char *)packet + hdrLen;
  int dataLen = packetLen - hdrLen;

  int protocol = header.protocol;
  int rc = 0;
  for (auto *c : ip.callbacks)
    if (c->promiscuous || endDevice) {
      if (c->protocol == -1 || c->protocol == protocol) {
        if (c->handle(data, dataLen, newInfo) != 0)
          rc = -1;
      }
    }
  return rc;
}

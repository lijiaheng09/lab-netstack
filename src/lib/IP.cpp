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
#include "ARP.h"

constexpr IP::Addr IP::BROADCAST;

IP::IP(L2 &l2_)
    : l2(l2_), routing(nullptr), icmp(*(new ICMP(*this))),
      arp(*(new ARP(l2, *this))) {}

IP::~IP() {
  delete &icmp;
  delete &arp;
}

void IP::addAddr(DevAddr entry) {
  addrs.push_back(entry);
}

const Vector<IP::DevAddr> &IP::getAddrs() {
  return addrs;
}

int IP::getAnyAddr(L2::Device *device, Addr &res) {
  if (addrs.empty())
    return -1;
  for (auto &&e : addrs)
    if (e.device == device) {
      res = e.addr;
      return 0;
    }
  res = addrs.front().addr;
  return 1;
}

int IP::getSrcAddr(Addr dst, Addr &res) {
  if (addrs.empty())
    return -1;
  Routing::HopInfo hop;
  int rc = routing->query(dst, hop);
  if (rc != 0)
    return rc;
  return getAnyAddr(hop.device, res);
}

IP::L2::Device *IP::findDeviceByAddr(Addr addr) {
  for (auto &&a : addrs)
    if (a.addr == addr)
      return a.device;
  return nullptr;
}

void IP::setRouting(Routing *routing) {
  this->routing = routing;
}

IP::Routing *IP::getRouting() {
  return routing;
}

int IP::sendWithHeader(void *packet, size_t packetLen, SendOptions options) {
  int rc = 0;
  do {
    Header &header = *(Header *)packet;
    if (packetLen < sizeof(Header)) {
      LOG_ERR("Truncated IP header: %lu/%lu", packetLen, sizeof(Header));
      rc = -1;
      break;
    }
    size_t hdrLen = (header.versionAndIHL & 0x0f) * 4;
    if (ntohs(header.totalLength) != packetLen || packetLen < hdrLen) {
      LOG_ERR("Invalid IP packet length: %lu/%lu:%hu", packetLen, hdrLen,
              ntohs(header.totalLength));
      rc = -1;
      break;
    }

    header.headerChecksum = 0;
    header.headerChecksum = csum16(&header, hdrLen);
#ifdef NETSTACK_DEBUG
    assert(csum16(&header, hdrLen) == 0);
#endif

    bool isBroadcast = false;
    for (auto &&e : addrs)
      if (!options.device || e.device == options.device) {
        if (header.dst == BROADCAST || header.dst == (e.addr | ~e.mask)) {
          isBroadcast = true;
          int rc1 =
              l2.send(packet, packetLen, L2::BROADCAST, PROTOCOL_ID, e.device);
          if (rc1 != 0)
            rc = rc1;
        }
      }
    if (isBroadcast)
      break;

    if (!routing) {
      LOG_ERR("No IP routing policy");
      rc = -1;
      break;
    }
    Routing::HopInfo hop;
    L2::Addr dstMAC;
    if (options.device && options.dstMAC != L2::Addr{0}) {
      hop.device = options.device;
      dstMAC = options.dstMAC;
    } else {
      rc = routing->query(header.dst, hop);
      if (rc != 0) {
        LOG_ERR("IP routing error for " IP_ADDR_FMT_STRING,
                IP_ADDR_FMT_ARGS(header.dst));
        break;
      }
      Addr hopAddr = hop.gateway == Addr{0} ? header.dst : hop.gateway;
      rc = arp.query(hopAddr, dstMAC);
      if (rc == E_WAIT_FOR_TRYAGAIN) {
        LOG_ERR("ARP query for " IP_ADDR_FMT_STRING ": wait to try again",
                IP_ADDR_FMT_ARGS(hopAddr));

        if (options.autoRetry) {
          void *packetCopy;
          if (options.freeBuf)
            packetCopy = packet;
          else {
            packetCopy = malloc(packetLen);
            if (!packetCopy) {
              LOG_ERR_POSIX("malloc");
              break;
            }
            memcpy(packetCopy, packet, packetLen);
          }
          options.autoRetry = false;
          options.freeBuf = false;
          arp.addWait(
              hopAddr,
              [this, packetCopy, packetLen, options](bool succ) {
                if (succ)
                  sendWithHeader(packetCopy, packetLen, options);
                free(packetCopy);
              },
              options.retryTimeout);
          return rc;
        }
      }
      if (rc != 0)
        break;
    }
    rc = l2.send(packet, packetLen, dstMAC, PROTOCOL_ID, hop.device);

  } while (0);

  if (options.freeBuf)
    free(const_cast<void *>(packet));
  return rc;
}

int IP::send(const void *data, size_t dataLen, Addr src, Addr dst,
             uint8_t protocol, SendOptions options) {
  int rc;
  do {
    if (dataLen > UINT16_MAX - sizeof(Header)) {
      LOG_ERR("IP data length too large: %lu", dataLen);
      rc = -1;
      break;
    }
    uint16_t packetLen = sizeof(Header) + dataLen;
#ifdef NETSTACK_DEBUG
    assert(options.timeToLive > 0);
#endif

    void *packet = malloc(packetLen);
    if (!packet) {
      LOG_ERR_POSIX("malloc");
      rc = -1;
      break;
    }

    Header &header = *(Header *)packet;
    header = Header{.versionAndIHL = 4 << 4 | 5,
                    .typeOfService = 0,
                    .totalLength = htons(packetLen),
                    .identification = 0,
                    .flagsAndFragmentOffset = htons(0b010 << 13 | 0),
                    .timeToLive = options.timeToLive,
                    .protocol = protocol,
                    .headerChecksum = 0,
                    .src = src,
                    .dst = dst};
    memcpy(&header + 1, data, dataLen);

    if (options.freeBuf)
      free(const_cast<void *>(data));
    options.freeBuf = true;
    return sendWithHeader(packet, packetLen, options);

  } while (0);

  if (options.freeBuf)
    free(const_cast<void *>(data));
  return rc;
}

int IP::addWait(Addr dst, WaitHandler handler, Timer::Duration timeout) {
  if (!routing) {
    LOG_ERR("No IP routing policy.");
    return -1;
  }
  Routing::HopInfo hop;
  int rc = routing->query(dst, hop);
  if (rc != 0) {
    LOG_ERR("No IP routing for " IP_ADDR_FMT_STRING "\n",
            IP_ADDR_FMT_ARGS(dst));
    return rc;
  }
  Addr hopAddr = hop.gateway == Addr{0} ? dst : hop.gateway;
  arp.addWait(hopAddr, handler, timeout);
  return 0;
}

void IP::addOnRecv(RecvHandler handler, uint8_t protocol, bool promiscuous) {
  if (promiscuous)
    onRecvPromiscuous.push_back(handler);
  else
    onRecv.insert({protocol, handler});
}

void IP::handleRecv(const void *packet, size_t packetCapLen,
                    const L2::RecvInfo &info) {
  if (packetCapLen < sizeof(Header)) {
    LOG_INFO("Truncated IP header: %lu/%lu", packetCapLen, sizeof(Header));
    return;
  }
  const Header &header = *(const Header *)packet;
  size_t hdrLen = (header.versionAndIHL & 0x0f) * 4;
  size_t packetLen = ntohs(header.totalLength);
  if (packetCapLen < packetLen || packetLen < hdrLen) {
    LOG_INFO("Truncated IP packet: %lu/%lu:%lu", packetCapLen, hdrLen,
             packetLen);
    return;
  }
  if (csum16(&header, hdrLen) != 0) {
    LOG_INFO("IP checksum error");
    return;
  }

  L2::Device *endDevice = nullptr;
  bool isBroadcast = false;
  if (header.dst == BROADCAST) {
    endDevice = info.device;
    isBroadcast = true;
  } else {
    for (auto &&e : addrs)
      if (header.dst == (e.addr | ~e.mask)) {
        endDevice = e.device;
        isBroadcast = true;
        break;
      }
  }
  if (!isBroadcast)
    endDevice = findDeviceByAddr(header.dst);
  IP::RecvInfo newInfo{.l2 = info,
                       .header = &header,
                       .isBroadcast = isBroadcast,
                       .endDevice = endDevice};
  const void *data = (const char *)packet + hdrLen;
  size_t dataLen = packetLen - hdrLen;

  for (auto it = onRecvPromiscuous.begin(); it != onRecvPromiscuous.end();) {
    if ((*it)(data, dataLen, newInfo) == 1)
      it = onRecvPromiscuous.erase(it);
    else
      it++;
  }

  if (endDevice) {
    auto r = onRecv.equal_range(header.protocol);
    for (auto it = r.first; it != r.second;) {
      if (it->second(data, dataLen, newInfo) == 1)
        it = onRecv.erase(it);
      else
        it++;
    }
  }
}

int IP::setup() {
  l2.addOnRecv(
      [this](auto &&...args) -> int {
        handleRecv(args...);
        return 0;
      },
      PROTOCOL_ID);
  int rc = 0;
  if ((rc = icmp.setup()) != 0 || (rc = arp.setup()) != 0)
    return rc;
  return 0;
}

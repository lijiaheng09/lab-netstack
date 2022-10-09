#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cerrno>

#include <arpa/inet.h>

#include "utils.h"
#include "log.h"

#include "UDP.h"

constexpr int UDP::PROTOCOL_ID = 17;

UDP::UDP(NetworkLayer &network_) : network(network_), networkHandler(*this) {}

int UDP::sendSegment(const void *data, int dataLen,
                     const NetworkLayer::Addr &srcAddr, int srcPort,
                     const NetworkLayer::Addr &dstAddr, int dstPort) {
  int segLen = sizeof(Header) + dataLen;
  int bufLen = sizeof(PseudoNetworkHeader) + segLen;

  if (dataLen < 0 || (segLen >> 16) != 0) {
    ERRLOG("Invalid UDP data length: %d\n", dataLen);
    return -1;
  }
  if ((srcPort >> 16) != 0 || (dstPort >> 16) != 0) {
    ERRLOG("Invalid UDP port: %d - %d\n", srcPort, dstPort);
    return -1;
  }

  void *buf = malloc(bufLen);
  if (!buf) {
    ERRLOG("malloc error: %s\n", strerror(errno));
    return -1;
  }
  auto &pseudoHeader = *(PseudoNetworkHeader *)buf;
  pseudoHeader = PseudoNetworkHeader{
    srcAddr : srcAddr,
    dstAddr : dstAddr,
    zero : 0,
    protocol : PROTOCOL_ID,
    udpLength : htons(segLen)
  };
  void *seg = &pseudoHeader + 1;
  auto &header = *(Header *)seg;
  header = Header{
    srcPort : htons(srcPort),
    dstPort : htons(dstPort),
    length : htons(segLen),
    checksum : 0
  };
  memcpy(&header + 1, data, dataLen);
  header.checksum = calcInternetChecksum16(buf, bufLen);
#ifdef NETSTACK_DEBUG
  assert(calcInternetChecksum16(buf, bufLen) == 0);
#endif

  int rc = network.sendPacket(seg, segLen, srcAddr, dstAddr, PROTOCOL_ID);
  free(buf);
  return rc;
}

UDP::RecvCallback::RecvCallback(int port_) : port(port_) {}

void UDP::addRecvCallback(RecvCallback *callback) {
  callbacks.push_back(callback);
}

int UDP::removeRecvCallback(RecvCallback *callback) {
  for (auto it = callbacks.begin(); it != callbacks.end(); it++)
    if (*it == callback) {
      callbacks.erase(it);
      return 0;
    }
  return 1;
}

int UDP::setup() {
  network.addRecvCallback(&networkHandler);
  return 0;
}

static uint16_t calcUdpChecksum(const UDP::PseudoNetworkHeader &pseudoHeader,
                                const void *data, int len) {
  const uint8_t *d0 = (const uint8_t *)&pseudoHeader;
  const uint8_t *d1 = (const uint8_t *)data;
  uint32_t sum = 0;
  for (int i = 0; i + 1 < sizeof(UDP::PseudoNetworkHeader); i += 2) {
    uint16_t x = ((uint16_t)d0[i] << 8 | d0[i + 1]);
    sum += x;
    sum = (sum + (sum >> 16)) & 0xFFFF;
  }
  for (int i = 0; i + 1 < len; i += 2) {
    uint16_t x = ((uint16_t)d1[i] << 8 | d1[i + 1]);
    sum += x;
    sum = (sum + (sum >> 16)) & 0xFFFF;
  }
  if (len % 2 != 0) {
    sum += (uint16_t)d1[len - 1] << 8;
    sum = (sum + (sum >> 16)) & 0xFFFF;
  }
  return htons(~sum);
}

UDP::NetworkLayerHandler::NetworkLayerHandler(UDP &udp_)
    : udp(udp_), NetworkLayer::RecvCallback(false, PROTOCOL_ID) {}

int UDP::NetworkLayerHandler::handle(const void *buf, int len,
                                     const Info &info) {
  const auto &netHeader = *(const NetworkLayer::Header *)buf;

  int segLen;
  const void *seg = NetworkLayer::stripHeader(buf, segLen);
  if (segLen < sizeof(Header)) {
    ERRLOG("Truncated UDP header: %d/%d\n", segLen, (int)sizeof(Header));
    return -1;
  }
  const Header &header = *(const Header *)seg;
  if (segLen != ntohs(header.length)) {
    ERRLOG("Invalid UDP packet length: %d/%d\n", segLen, header.length);
    return -1;
  }
  PseudoNetworkHeader pseudoHeader{
    srcAddr : netHeader.src,
    dstAddr : netHeader.dst,
    zero : 0,
    protocol : netHeader.protocol,
    udpLength : header.length
  };
  if (header.checksum != 0 && calcUdpChecksum(pseudoHeader, seg, segLen) != 0) {
    ERRLOG("UDP Checksum error\n");
    return -1;
  }

  UDP::RecvCallback::Info newInfo(info);
  newInfo.netHeader = &netHeader;

  int port = ntohs(header.dstPort);
  int rc = 0;
  for (auto *c : udp.callbacks)
    if (c->port == -1 || c->port == port) {
      if (c->handle(seg, segLen, newInfo) != 0)
        rc = -1;
    }
  return rc;
}

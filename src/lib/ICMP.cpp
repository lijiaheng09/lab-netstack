#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cerrno>

#include <arpa/inet.h>

#include "log.h"

#include "ICMP.h"

constexpr int ICMP::PROTOCOL_ID = 1;

ICMP::ICMP(IP &ip_) : ip(ip_), ipHandler(*this) {}

int ICMP::sendTimeExceeded(const void *orig, int origLen,
                           const IP::RecvCallback::Info &info) {
  const IP::Header &origHeader = *(const IP::Header *)orig;

  int origHdrLen = (origHeader.versionAndIHL & 0x0F) * 4;
  int backLen = origLen;
  if (backLen > origHdrLen + 8)
    backLen = origHdrLen + 8;
  int msgLen = sizeof(Header) + backLen;

  IP::Addr src;
  int rc = ip.getAnyAddr(info.linkDevice, src);
  if (rc < 0) {
    ERRLOG("No IP address on the host.\n");
    return rc;
  }

  void *msg = malloc(msgLen);
  if (!msg) {
    ERRLOG("malloc error: %s\n", strerror(errno));
    return -1;
  }

  Header &header = *(Header *)msg;
  header = Header{type : 11, code : 0, checksum : 0, 0};
  memcpy(&header + 1, orig, backLen);
  header.checksum = calcInternetChecksum16(msg, msgLen);
#ifdef NETSTACK_DEBUG
  assert(calcInternetChecksum16(msg, msgLen) == 0);
#endif

  rc = ip.sendPacket(msg, msgLen, src, origHeader.src, PROTOCOL_ID);
  free(msg);
  return rc;
}

int ICMP::sendEchoOrReply(const IP::Addr &src, const IP::Addr &dst, int type,
                          int identifier, int seqNumber, const void *data,
                          int dataLen, int timeToLive) {
  if (dataLen < 0) {
    ERRLOG("Invalid ICMP data length: %d\n", dataLen);
    return -1;
  }
  if ((identifier >> 16) != 0 || (seqNumber >> 16) != 0) {
    ERRLOG("Invalid ICMP identifier %d, sequence number %d\n", identifier, seqNumber);
    return -1;
  }
  int msgLen = sizeof(Header) + dataLen;
  void *msg = malloc(msgLen);
  if (!msg) {
    ERRLOG("malloc error: %s\n", strerror(errno));
    return -1;
  }

  Header &header = *(Header *)msg;
  header = Header{
    type : (uint8_t)type,
    code : 0,
    checksum : 0,
    identifier : ntohs(identifier),
    seqNumber : ntohs(seqNumber)
  };
  memcpy(&header + 1, data, dataLen);
  header.checksum = calcInternetChecksum16(msg, msgLen);
#ifdef NETSTACK_DEBUG
  assert(calcInternetChecksum16(msg, msgLen) == 0);
#endif

  int rc = ip.sendPacket(msg, msgLen, src, dst, PROTOCOL_ID, timeToLive);
  free(msg);
  return rc;
}

ICMP::RecvCallback::RecvCallback(int type_) : type(type_) {}

void ICMP::addRecvCallback(RecvCallback *callback) {
  callbacks.push_back(callback);
}

int ICMP::removeRecvCallback(RecvCallback *callback) {
  for (auto it = callbacks.begin(); it != callbacks.end(); it++)
    if (*it == callback) {
      callbacks.erase(it);
      return 0;
    }
  return 1;
}

int ICMP::setup() {
  ip.addRecvCallback(&ipHandler);
  return 0;
}

ICMP::IPHandler::IPHandler(ICMP &icmp_)
    : icmp(icmp_), IP::RecvCallback(false, PROTOCOL_ID) {}

int ICMP::IPHandler::handle(const void *msg, int msgLen, const Info &info) {
  if (msgLen < sizeof(Header)) {
    ERRLOG("Truncated ICMP message: %d/%d\n", msgLen, (int)sizeof(Header));
    return 1;
  }
  const Header &header = *(const Header *)msg;

  int rc = 0;

  // Replying echo messages
  if (header.type == 8) {
    do {
      void *reply = malloc(msgLen);
      if (!reply) {
        ERRLOG("malloc error: %s\n", strerror(errno));
        rc = -1;
        break;
      }
      memcpy(reply, msg, msgLen);

      Header &replyHeader = *(Header *)reply;
      replyHeader.type = 0;
      replyHeader.checksum = 0;
      replyHeader.checksum = calcInternetChecksum16(reply, msgLen);
#ifdef NETSTACK_DEBUG
      assert(calcInternetChecksum16(reply, msgLen) == 0);
#endif

      rc = icmp.ip.sendPacket(reply, msgLen, info.netHeader->dst,
                              info.netHeader->src, PROTOCOL_ID);
      free(reply);
    } while (0);
  }

  ICMP::RecvCallback::Info newInfo(info);
  newInfo.icmpHeader = &header;

  const void *data = &header + 1;
  int dataLen = msgLen - sizeof(header);
  for (auto *c : icmp.callbacks)
    if (c->type == -1 || c->type == header.type) {
      if (c->handle(data, dataLen, newInfo) != 0)
        rc = -1;
    }

  return rc;
}

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cerrno>

#include <arpa/inet.h>

#include "log.h"

#include "ICMP.h"

constexpr int ICMP::PROTOCOL_ID = 1;

ICMP::ICMP(IP &ip_) : ip(ip_) {}

int ICMP::sendTimeExceeded(const void *orig, int origLen,
                           const IP::RecvInfo &info) {
  const IP::Header &origHeader = *(const IP::Header *)orig;

  int origHdrLen = (origHeader.versionAndIHL & 0x0F) * 4;
  int backLen = origLen;
  if (backLen > origHdrLen + 8)
    backLen = origHdrLen + 8;
  int msgLen = sizeof(Header) + backLen;

  IP::Addr src;
  int rc = ip.getAnyAddr(info.l2.device, src);
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
  header.checksum = csum16(msg, msgLen);
#ifdef NETSTACK_DEBUG
  assert(csum16(msg, msgLen) == 0);
#endif

  rc = ip.send(msg, msgLen, src, origHeader.src, PROTOCOL_ID,
                     {.device = info.l2.device, .dstMAC = info.l2.header->src});
  free(msg);
  return rc;
}

int ICMP::sendEchoOrReply(const IP::Addr &src, const IP::Addr &dst, int type,
                          int identifier, int seqNumber, const void *data,
                          int dataLen, IP::SendOptions options) {
  if (dataLen < 0) {
    ERRLOG("Invalid ICMP data length: %d\n", dataLen);
    return -1;
  }
  if ((identifier >> 16) != 0 || (seqNumber >> 16) != 0) {
    ERRLOG("Invalid ICMP identifier %d, sequence number %d\n", identifier,
           seqNumber);
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
  header.checksum = csum16(msg, msgLen);
#ifdef NETSTACK_DEBUG
  assert(csum16(msg, msgLen) == 0);
#endif

  int rc = ip.send(msg, msgLen, src, dst, PROTOCOL_ID, options);
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
  ip.addOnRecv(
      [this](auto &&...args) -> int {
        handleRecv(args...);
        return 0;
      },
      PROTOCOL_ID);
  return 0;
}

void ICMP::handleRecv(const void *msg, size_t msgLen,
                      const IP::RecvInfo &info) {
  if (msgLen < sizeof(Header)) {
    LOG_INFO("Truncated ICMP message: %lu/%lu", msgLen, sizeof(Header));
    return;
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
      replyHeader.checksum = csum16(reply, msgLen);
#ifdef NETSTACK_DEBUG
      assert(csum16(reply, msgLen) == 0);
#endif

      rc = ip.send(
          reply, msgLen, info.header->dst, info.header->src, PROTOCOL_ID,
          {.device = info.l2.device, .dstMAC = info.l2.header->src});
      free(reply);
    } while (0);
  }

  ICMP::RecvCallback::Info newInfo(info);
  newInfo.icmpHeader = &header;

  const void *data = &header + 1;
  int dataLen = msgLen - sizeof(header);
  for (auto *c : callbacks)
    if (c->type == -1 || c->type == header.type) {
      c->handle(data, dataLen, newInfo);
    }
}

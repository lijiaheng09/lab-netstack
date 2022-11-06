#include <arpa/inet.h>

#include "TCP.h"

#include "utils.h"
#include "log.h"

TCP::TCP(L3 &l3_)
    : dispatcher(l3_.l2.netBase.dispatcher), timer(l3_.l2.netBase.timer),
      l3(l3_) {}

int TCP::setup() {
  l3.addOnRecv(
      [this](auto &&...args) -> int {
        handleRecv(args...);
        return 0;
      },
      PROTOCOL_ID);
  return 0;
}

uint16_t TCP::calcChecksum(const void *seg, size_t segLen, L3::Addr src,
                           L3::Addr dst) {
  const TCP::Header &header = *(const Header *)seg;
  size_t dataOff = ((header.offAndRsrv >> 4)) * 8UL;
  PseudoL3Header pseudo{.src = src,
                        .dst = dst,
                        .ptcl = PROTOCOL_ID,
                        .tcpLen = htons(sizeof(Header) + (segLen - dataOff))};
  uint16_t sum = csum16(&pseudo, sizeof(pseudo));
  return csum16(seg, segLen, ~sum);
}

void TCP::handleRecv(const void *seg, size_t segLen, const L3::RecvInfo &info) {
  if (segLen < sizeof(Header)) {
    LOG_INFO("Truncated TCP Header: %lu/%lu", segLen, sizeof(Header));
    return;
  }
  const Header &header = *(const Header *)seg;
  size_t dataOff = ((header.offAndRsrv >> 4)) * 8UL;
  if (segLen < dataOff) {
    LOG_INFO("Truncated TCP Header: %lu/%lu:%lu", segLen, sizeof(Header),
             dataOff);
    return;
  }
  if (calcChecksum(seg, segLen, info.header->src, info.header->dst) != 0) {
    LOG_INFO("TCP checksum error");
  }
}

#include <cstdlib>
#include <cstring>
#include <atomic>

#include <pcap/pcap.h>

#include "packetio.h"

#include "internal/device.h"

using namespace netstack_internal;

int sendFrame(const void *buf, int len, int ethtype, const void *destmac,
              int id) {
  int frameLen = ETHER_HDR_LEN + len;
  if (len < 0 || frameLen + ETHER_CRC_LEN > ETHER_MAX_LEN)
    return -1;

  if ((ethtype >> 16) != 0)
    return -1;

  mutexDevices.lock_shared();
  if (id >= nDevices)
    return -1; // invalid device id
  pcap_t *handle = devices[id].handle;
  ether_addr srcAddr = devices[id].ethAddr;
  mutexDevices.unlock_shared();

  u_char *frame = (u_char *)malloc(frameLen);
  if (!frame)
    return -1;

  uint16_t ethtypeNet = htons((uint16_t)ethtype);

  memcpy(frame, destmac, ETHER_ADDR_LEN);
  memcpy(frame + ETHER_ADDR_LEN, &srcAddr, ETHER_ADDR_LEN);
  memcpy(frame + ETHER_ADDR_LEN * 2, &ethtypeNet, ETHER_TYPE_LEN);
  memcpy(frame + ETHER_HDR_LEN, buf, len);

  int ret = pcap_sendpacket(handle, frame, frameLen);
  free(frame);
  if (ret != 0)
    return -1;

  return 0;
}

static std::atomic<frameReceiveCallback> atomicCurCallback;

namespace netstack_internal {

struct DeviceRecvActionArgs {
  pcap_t *handle;
  int id;
};

void devicePcapLoopHandler(u_char *user, const pcap_pkthdr *h, const u_char *bytes) {
  DeviceRecvActionArgs args = *(DeviceRecvActionArgs *)user;
  auto *curCallback = atomicCurCallback.load();
  if (curCallback) {
    if (curCallback(bytes, h->caplen, args.id))
      pcap_breakloop(args.handle);
  }
}

void deviceRecvAction(pcap_t *handle, int id) {
  DeviceRecvActionArgs args { handle, id };
  pcap_pkthdr hdr;
  pcap_loop(handle, -1, devicePcapLoopHandler, (u_char *)&args);
}

} // namespace netstack_internal

int setFrameReceiveCallback(frameReceiveCallback callback) {
  atomicCurCallback.store(callback);
  return 0;
}

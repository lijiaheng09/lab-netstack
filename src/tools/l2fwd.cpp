#include <cstdio>
#include <cstring>

#include <netinet/ether.h>
#include <linux/if_packet.h>

#include <pcap/pcap.h>

#include "netstack.h"

#include "internal/device.h"

using namespace std;

static const int MAX_DEVICES = 128;
static int nDevices = 0;
static int ID[MAX_DEVICES];
static ether_addr dstAddrs[MAX_DEVICES];

int recvHandler(const void *buf, int len, int id) {
  uint16_t *ethtypeNetp = (uint16_t *)((char *)buf + ETHER_ADDR_LEN * 2);
  int ethtype = ntohs(*ethtypeNetp);
  for (int i = 0; i < nDevices; i++)
    if (ID[i] != id)
      sendFrame((char *)buf + ETHER_HDR_LEN, len - ETHER_HDR_LEN, ethtype, &dstAddrs[i], ID[i]);
  return 0;
}

int main(int argc, char **argv) {
  netstackInit();

  nDevices = 0;
  for (int i = 1; i + 1 < argc && nDevices < MAX_DEVICES; i += 2) {
    int id = addDevice(argv[i]);
    if (id < 0) {
      fprintf(stderr, "error: addDevice(%s) returns %d\n", argv[i], id);
      continue;
    }
    printf("added device %d: %s\n", id, argv[i]);
    ID[nDevices] = id;
    ether_aton_r(argv[i + 1], &dstAddrs[nDevices]);
    nDevices++;
  }
  
  printf("Start forwarding...\n");
  setFrameReceiveCallback(recvHandler);
  getchar();

  return 0;
}

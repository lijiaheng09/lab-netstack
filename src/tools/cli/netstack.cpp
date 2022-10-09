#include "netstack.h"

NetBase netBase;
Ethernet ethernet(netBase);
IPv4 ipv4(ethernet);
LpmRouting routing;

IPv4Forward ipv4Forward(ipv4);

int initNetStack() {
  int rc;

  if ((rc = netBase.setup()) != 0 ||
      (rc = ethernet.setup()) != 0 ||
      (rc = ipv4.setup()) != 0) {
    return 1;
  }

  ipv4.setRouting(&routing);

  return 0;
}

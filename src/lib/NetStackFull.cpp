#include "NetStackFull.h"

#include "log.h"

NetStackFull::NetStackFull() : udp(ip), ipForward(nullptr), rip(nullptr) {
  if (udp.setup() != 0) {
    LOG_ERR("Netstack initialize failed");
    abort();
  }
}

int NetStackFull::enableForward() {
  if (ipForward) {
    LOG_ERR("IP Forwarding already enabled.");
    return -1;
  }
  ipForward = new IPForward(ip);
  return ipForward->setup();
}

int NetStackFull::configRIP(Timer::Duration updateCycle,
                            Timer::Duration expireCycle,
                            Timer::Duration cleanCycle) {
  if (rip) {
    LOG_ERR("RIP Routing already enabled.");
    return -1;
  }
  rip = new RIP(udp, ip, netBase, updateCycle, expireCycle, cleanCycle);
  int rc = rip->setup();
  if (rc != 0)
    return rc;
  routing = rip;
  ip.setRouting(rip);
  return 0;
}

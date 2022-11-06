#ifndef NETSTACK_NETSTACK_FULL_H
#define NETSTACK_NETSTACK_FULL_H

#include "UDP.h"
#include "RIP.h"
#include "IPForward.h"
#include "TCP.h"

#include "NetStackSimple.h"

class NetStackFull : public NetStackSimple {
public:
  UDP udp;
  TCP tcp;

  IPForward *ipForward;
  RIP *rip;

  NetStackFull();

  /**
   * @brief Need to be called before start looping, or in the thread of looping.
   *
   * @return 0 on success, -1 on error.
   */
  int enableForward();

  /**
   * @brief Configure the RIP routing.
   * Need to be called before start looping, or in the thread of looping.
   *
   * @param updateCycle
   * @param expireCycle
   * @param cleanCycle
   * @return 0 on success, negative on error.
   */
  int configRIP(Timer::Duration updateCycle = 30s, Timer::Duration expireCycle = 180s,
                Timer::Duration cleanCycle = 120s);
};

#endif

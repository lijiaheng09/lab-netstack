#ifndef NETSTACK_IP_FORWARD_H
#define NETSTACK_IP_FORWARD_H

#include "IP.h"

/**
 * @brief The IP forwarding service, built on `IP` network service.
 */
class IPForward {
public:
  IP &ip;

  IPForward(IP &ip_);
  IPForward(const IPForward &) = delete;

  /**
   * @brief Setup the IP forwarding service.
   *
   * @return 0 on success, negative on error.
   */
  int setup();

private:
  bool isUp;

  void handleRecv(const void *data, size_t dataLen, const IP::RecvInfo &info);
};

#endif

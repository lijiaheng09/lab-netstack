#ifndef NETSTACK_IPV4_FORWARD_H
#define NETSTACK_IPV4_FORWARD_H

#include "IPv4.h"

/**
 * @brief The IPv4 forwarding service, built on `IPv4` network service.
 */
class IPv4Forward {
public:
  IPv4 &ipv4;

  IPv4Forward(IPv4 &ipv4_);
  IPv4Forward(const IPv4Forward &) = delete;

  /**
   * @brief Setup the IPv4 forwarding service.
   * 
   * @return 0 on success, negative on error.
   */
  int setup();

private:
  class IPv4Handler : public IPv4::RecvCallback {
    IPv4Forward &ipv4Forward;
  public:
    IPv4Handler(IPv4Forward &ipv4Forward_);
    int handle(const void *buf, int len);
  } ipv4Handler;
};

#endif

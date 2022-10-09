#ifndef NETSTACK_ICMP_H
#define NETSTACK_ICMP_H

#include "IP.h"

class ICMP {
public:
  static const int PROTOCOL_ID;

  struct Header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t info;
  };

  IP &ip;

  ICMP(IP &ip_);
  ICMP(const ICMP &) = delete;

  /**
   * @brief Send Time Exceeded Message back for an IP packet.
   * 
   * @param orig Pointer to the original packet.
   * @param origLen Length of the original packet.
   * @param IP The IP layer service object.
   * 
   * @return 0 on success, negative on error.
   */
   int sendTimeExceeded(const void *orig, int origLen);
};

#endif

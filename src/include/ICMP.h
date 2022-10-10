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
   * @param info Other information of the received packet.
   *
   * @return 0 on success, negative on error.
   */
  int sendTimeExceeded(const void *orig, int origLen,
                       const IP::RecvCallback::Info &info);

  /**
   * @brief Send Echo or Reply Message.
   *
   * @param data Pointer to the data.
   * @param dataLen Length of the data.
   * @param 8 for echo message; 0 for echo reply message.
   * @param identifier Identifier field for matching.
   * @param seqNumber Sequence number.
   * @return 0 on success, negative on error.
   */
  int sendEchoOrReply(const void *data, int dataLen, int type, int identifier,
                      int seqNumber);

  int setup();

private:
  class IPHandler : public IP::RecvCallback {
    ICMP &icmp;

  public:
    IPHandler(ICMP &icmp_);

    int handle(const void *buf, int len, const Info &info) override;
  } ipHandler;
};

#endif

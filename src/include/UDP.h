#ifndef NETSTACK_UDP_H
#define NETSTACK_UDP_H

#include "IP.h"

/**
 * @brief The UDP datagram service built above `IP` network layer.
 * Can handle receiving UDP datagrams, or send them to the network layer.
 */
class UDP {
public:
  using L3 = IP;
  static const int PROTOCOL_ID;

  struct Header {
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t length;
    uint16_t checksum;
  } __attribute__((packed));

  struct PseudoL3Header {
    L3::Addr srcAddr;
    L3::Addr dstAddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t udpLength;
  } __attribute__((packed));

  L3 &l3;

  UDP(L3 &l3_);
  UDP(const UDP &) = delete;

  struct SendOptions {
    bool autoRetry;
    std::function<void()> waitingCallback;
  };

  /**
   * @brief Send an UDP segment.
   *
   * @param data Pointer to the payload data.
   * @param dataLen Length of the payload data.
   * @param srcAddr IP address of the source.
   * @param srcPort Source port.
   * @param dstAddr IP address of the destination.
   * @param dstPort Destination port.
   * @param options Other options
   * @return 0 on success, negative on error.
   * Including: E_WAIT_FOR_TRYAGAIN.
   */
  int sendSegment(const void *data, int dataLen,
                  const L3::Addr &srcAddr, int srcPort,
                  const L3::Addr &dstAddr, int dstPort,
                  SendOptions = {});

  class RecvCallback {
  public:
    int port; // The matching port, -1 for any.

    /**
     * @brief Construct a new RecvCallback object
     *
     * @param port_ // The matching port, -1 for any.
     */
    RecvCallback(int port_);

    struct Info {
      L3::RecvInfo l3;
      L3::L2::RecvInfo &l2 = l3.l2;
      const Header *udpHeader;
    };

    /**
     * @brief Handle a received UDP segment (guaranteed valid).
     *
     * @param data Pointer to the payload.
     * @param dataLen Length of the payload.
     * @param info Other information of the received packet.
     * @return 0 on success, negative on error.
     */
    virtual int handle(const void *data, int dataLen, const Info &info) = 0;
  };

  /**
   * @brief Register a callback on receiving UDP segments.
   *
   * @param callback Pointer to a `RecvCallback` object (which need to be
   * persistent).
   */
  void addRecvCallback(RecvCallback *callback);

  /**
   * @brief Remove a registered receiving callback.
   *
   * @param callback Pointer to the `RecvCallback` object.
   * @return 0 on success, 1 if no such callback.
   */
  int removeRecvCallback(RecvCallback *callback);

  /**
   * @brief Setup the UDP transport service.
   *
   * @return 0 on success, negative on error.
   */
  int setup();

private:
  Vector<RecvCallback *> callbacks;

  void handleRecv(const void *seg, size_t segLen,
                  const L3::RecvInfo &info);
};

#endif

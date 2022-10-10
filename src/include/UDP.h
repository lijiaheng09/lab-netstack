#ifndef NETSTACK_UDP_H
#define NETSTACK_UDP_H

#include "IP.h"

/**
 * @brief The UDP datagram service built above `IP` network layer.
 * Can handle receiving UDP datagrams, or send them to the network layer.
 */
class UDP {
public:
  using NetworkLayer = IP;
  static const int PROTOCOL_ID;

  struct Header {
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t length;
    uint16_t checksum;
  };

  struct PseudoNetworkHeader {
    NetworkLayer::Addr srcAddr;
    NetworkLayer::Addr dstAddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t udpLength;
  };

  NetworkLayer &network;

  UDP(NetworkLayer &network_);
  UDP(const UDP &) = delete;

  /**
   * @brief Send an UDP segment.
   *
   * @param data Pointer to the payload data.
   * @param dataLen Length of the payload data.
   * @param srcAddr IP address of the source.
   * @param srcPort Source port.
   * @param dstAddr IP address of the destination.
   * @param dstPort Destination port.
   * @return 0 on success, negative on error.
   */
  int sendSegment(const void *data, int dataLen,
                  const NetworkLayer::Addr &srcAddr, int srcPort,
                  const NetworkLayer::Addr &dstAddr, int dstPort);

  class RecvCallback {
  public:
    int port; // The matching port, -1 for any.

    /**
     * @brief Construct a new RecvCallback object
     *
     * @param port_ // The matching port, -1 for any.
     */
    RecvCallback(int port_);

    struct Info : NetworkLayer::RecvCallback::Info {
      const Header *udpHeader;

      Info(const NetworkLayer::RecvCallback::Info &info_)
          : NetworkLayer::RecvCallback::Info(info_) {}
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

  class NetworkLayerHandler : public NetworkLayer::RecvCallback {
    UDP &udp;

  public:
    NetworkLayerHandler(UDP &udp_);

    int handle(const void *seg, int segLen, const Info &info) override;
  } networkHandler;
};

#endif

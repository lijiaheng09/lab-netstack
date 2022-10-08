#ifndef NETSTACK_IPV4_H
#define NETSTACK_IPV4_H

#include <cinttypes>

#include <netinet/ip.h>

#include "Ethernet.h"

#define IPV4_ADDR_FMT_STRING "%hhu.%hhu.%hhu.%hhu"
#define IPV4_ADDR_FMT_ARGS(a) a.data[0], a.data[1], a.data[2], a.data[3]
#define IPV4_ADDR_FMT_NUM 4

class IPv4 {
public:
  using LinkLayer = Ethernet;
  static const int PROTOCOL_ID;

  struct Addr {
    unsigned char data[4];

    friend bool operator==(const Addr &a, const Addr &b) {
      return *(uint32_t *)a.data == *(uint32_t *)b.data;
    }

    friend Addr operator&(const Addr &a, const Addr &b) {
      Addr res;
      *(uint32_t *)res.data = *(uint32_t *)a.data & *(uint32_t *)b.data;
      return res;
    }
  };

  struct Header {
    uint8_t versionAndIHL; // version:4 | IHL:4
    uint8_t typeOfService;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flagsAndFragmentOffset; // flags:3 | fragmentOffset:13
    uint8_t timeToLive;
    uint8_t protocol;
    uint16_t headerChecksum;
    Addr src;
    Addr dst;
  };

  LinkLayer &linkLayer;

  IPv4(LinkLayer &linkLayer_);
  IPv4(const IPv4 &) = delete;

  /**
   * @brief Assign an IPv4 address to a device.
   *
   * @param device Pointer to the `LinkLayer::Device` object describing the
   * device.
   * @param addr The assigned address.
   */
  void addAddr(LinkLayer::Device *device, const Addr &addr);

  /**
   * @brief Find the device by assigned IPv4 address.
   *
   * @param addr The assigned address.
   * @return Pointer to the `LinkLayer::Device` object describing the
   * corresponding device, `nullptr` if not found.
   */
  LinkLayer::Device *findDeviceByAddr(const Addr &addr);

  class Routing {
  public:
    using NetworkLayer = IPv4;
    using LinkLayer = NetworkLayer::LinkLayer;
    using Addr = NetworkLayer::Addr;

    struct HopInfo {
      LinkLayer::Device *device; // The port to the next hop.
      LinkLayer::Addr dstMAC;    // The destination MAC address of the next hop.
    };

    /**
     * @brief Match for the next hop port for an IPv4 packet.
     *
     * @param addr The destination IPv4 address of the packet.
     * @return A `Routing::HopInfo` structure, including the port and
     * destination MAC address for the next hop.
     * If no valid routing is found, set device to `nullptr`.
     */
    virtual HopInfo match(const Addr &addr) = 0;
  };

  /**
   * @brief Set the routing table.
   *
   * @param routing_ Pointer to the `IPv4::Routing` object.
   */
  void setRouting(Routing *routing_);

  /**
   * @brief Send an IPv4 packet (leaving the checksum for recalculation).
   *
   * @param buf Pointer to the packet (with checksum may be modified).
   * @param len Length of the packet.
   *
   * @return 0 on success, negative on error.
   */
  int sendPacketWithHeader(void *buf, int len);

  /**
   * @brief Send an IPv4 packet.
   *
   * @param buf Pointer to the payload.
   * @param len Length of the payload.
   * @param src IPv4 address of the source host.
   * @param dst IPv4 address of the destination host.
   * @param protocol The `protocol` field of the packet.
   *
   * @return 0 on success, negative on error.
   */
  int sendPacket(const void *buf, int len, const Addr &src, const Addr &dst,
                 int protocol);

  class RecvCallback {
  public:
    bool promiscuous; // If matches destination IP of other hosts.
    int protocol;     // The matching IPv4 `protocol` field, -1 for any.

    /**
     * @brief Construct a new RecvCallback object
     *
     * @param promiscuous_ If matches destination IP of other hosts.
     * @param protocol_ The matching IPv4 `protocol` field, -1 for any.
     */
    RecvCallback(bool promiscuous_, int protocol_);

    /**
     * @brief Handle a received IPv4 packet (guaranteed valid).
     *
     * @param buf Pointer to the packet.
     * @param len Length of the packet.
     * @return 0 on success, negative on error.
     */
    virtual int handle(const void *buf, int len) = 0;
  };

  void addRecvCallback(RecvCallback *callback);

  int handlePacket(const void *buf, int len);

  /**
   * @brief Setup the IPv4 Layer.
   *
   * @return 0 on success, negative on error.
   */
  int setup();

private:
  class DevAddr {
  public:
    LinkLayer::Device *dev;
    Addr addr;
  };
  Vector<DevAddr> addrs;
  Routing *routing;

  Vector<RecvCallback *> callbacks;

  class LinkLayerHandler : public LinkLayer::RecvCallback {
    IPv4 &ipv4Layer;

  public:
    LinkLayerHandler(IPv4 &ipv4Layer_);

    int handle(const void *buf, int len, LinkLayer::Device *device) override;
  } linkLayerHandler;
};

#endif

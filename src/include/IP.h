#ifndef NETSTACK_IP_H
#define NETSTACK_IP_H

#include <cinttypes>

#include "Ethernet.h"

#define IP_ADDR_FMT_STRING "%hhu.%hhu.%hhu.%hhu"
#define IP_ADDR_FMT_ARGS(a) a.data[0], a.data[1], a.data[2], a.data[3]
#define IP_ADDR_FMT_NUM 4

/**
 * @brief The IP network service built above `Ethernet` (may be substituted by
 * other link layers).
 * Can handle receiving IP packets, or send them to the link layer.
 * Need to set routing policy by setting the `Routing` object.
 * May build services based on IP `protocol` field above it.
 */
class IP {
public:
  using LinkLayer = Ethernet;   // may be substituted by other link layers
  static const int PROTOCOL_ID; // The corresponding etherType

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

  IP(LinkLayer &linkLayer_);
  IP(const IP &) = delete;

  /**
   * @brief Assign an IP address to a device.
   *
   * @param device The link layer device to be set.
   * @param addr The assigned IP address.
   */
  void addAddr(LinkLayer::Device *device, const Addr &addr);

  /**
   * @brief Find the device by its assigned IP address.
   *
   * @param addr The assigned IP address.
   * @return The link layer device found, `nullptr` if not found.
   */
  LinkLayer::Device *findDeviceByAddr(const Addr &addr);

  /**
   * @brief Implementation of the IP routing policy.
   */
  class Routing {
  public:
    using NetworkLayer = IP;
    using LinkLayer = NetworkLayer::LinkLayer;
    using Addr = NetworkLayer::Addr;

    struct HopInfo {
      LinkLayer::Device *device; // The port to the next hop.
      LinkLayer::Addr dstMAC;    // The destination MAC address of the next hop.
    };

    /**
     * @brief Match for the next hop port for an IP packet.
     *
     * @param addr The destination IP address of the packet.
     * @return The port and destination MAC address for the next hop.
     * If no valid routing is found, set `device` to `nullptr`.
     */
    virtual HopInfo match(const Addr &addr) = 0;
  };

  /**
   * @brief Set the routing policy.
   *
   * @param routing Pointer to the `IP::Routing` object.
   */
  void setRouting(Routing *routing);

  /**
   * @brief Send a complete IP packet (leaving the checksum for
   * recalculation).
   *
   * @param buf Pointer to the packet (with checksum may be modified).
   * @param len Length of the packet.
   *
   * @return 0 on success, negative on error.
   */
  int sendPacketWithHeader(void *buf, int len);

  /**
   * @brief Send an IP packet.
   *
   * @param buf Pointer to the payload.
   * @param len Length of the payload.
   * @param src IP address of the source host.
   * @param dst IP address of the destination host.
   * @param protocol The `protocol` field of the packet.
   *
   * @return 0 on success, negative on error.
   */
  int sendPacket(const void *buf, int len, const Addr &src, const Addr &dst,
                 int protocol);

  class RecvCallback {
  public:
    bool promiscuous; // If matches destination IP of other hosts.
    int protocol;     // The matching IP `protocol` field, -1 for any.

    /**
     * @brief Construct a new RecvCallback object
     *
     * @param promiscuous_ If matches destination IP of other hosts.
     * @param protocol_ The matching IP `protocol` field, -1 for any.
     */
    RecvCallback(bool promiscuous_, int protocol_);

    /**
     * @brief Handle a received IP packet (guaranteed valid).
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
   * @brief Setup the IP network service.
   *
   * @return 0 on success, negative on error.
   */
  int setup();

private:
  class DevAddr {
  public:
    LinkLayer::Device *device;
    Addr addr;
  };
  Vector<DevAddr> addrs;
  Routing *routing;

  Vector<RecvCallback *> callbacks;

  class LinkLayerHandler : public LinkLayer::RecvCallback {
    IP &ip;

  public:
    LinkLayerHandler(IP &ip_);

    int handle(const void *buf, int len, LinkLayer::Device *device) override;
  } linkLayerHandler;
};

#endif

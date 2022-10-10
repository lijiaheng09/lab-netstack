#ifndef NETSTACK_IP_H
#define NETSTACK_IP_H

#include <cinttypes>

#include "Ethernet.h"

#define IP_ADDR_FMT_STRING "%hhu.%hhu.%hhu.%hhu"
#define IP_ADDR_FMT_ARGS(a) a.data[0], a.data[1], a.data[2], a.data[3]
#define IP_ADDR_FMT_NUM 4

class ICMP;

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
    union {
      unsigned char data[4];
      uint32_t num;
    };

    Addr operator~() const {
      return {num : ~num};
    }
    friend bool operator==(const Addr &a, const Addr &b) {
      return a.num == b.num;
    }
    friend Addr operator&(const Addr &a, const Addr &b) {
      return {num : a.num & b.num};
    }
    friend Addr operator|(const Addr &a, const Addr &b) {
      return {num : a.num | b.num};
    }

    static const Addr BROADCAST;
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

  ICMP &icmp;

  IP(LinkLayer &linkLayer_);
  IP(const IP &) = delete;
  ~IP();

  class DevAddr {
  public:
    LinkLayer::Device *device; // The corresponding link layer device.
    Addr addr;                 // The IP address
    Addr mask;                 // The subnet mask
  };

  /**
   * @brief Assign an IP address to a device.
   *
   * @param entry The address entry to be added.
   */
  void addAddr(const DevAddr &entry);

  /**
   * @brief Get all assigned IP addresses.
   * 
   * @return The IP address table.
   */
  const Vector<DevAddr> &getAddrs();

  /**
   * @brief Get any IP address of a device. If there is no such address, get any
   * of the host.
   *
   * @param device The preferred link layer device.
   * @param addr Storage of the result.
   *
   * @return 0 on success, 1 if got address of other device, -1 if no address
   * at all.
   */
  int getAnyAddr(LinkLayer::Device *device, Addr &addr);

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

    struct Info : LinkLayer::RecvCallback::Info {
      const LinkLayer::Header *linkHeader;
      LinkLayer::Device *linkDevice;

      bool isBroadcast;
      LinkLayer::Device *endDevice;

      Info(const LinkLayer::RecvCallback::Info &info_)
          : LinkLayer::RecvCallback::Info(info_) {}
    };

    /**
     * @brief Handle a received IP packet (guaranteed valid).
     *
     * @param buf Pointer to the packet.
     * @param len Length of the packet.
     * @param info Other information of the received packet.
     * @return 0 on success, negative on error.
     */
    virtual int handle(const void *buf, int len, const Info &info) = 0;
  };

  /**
   * @brief Register a callback on receiving IP packets.
   *
   * @param callback Pointer to a `RecvCallback` object (which need to be
   * persistent).
   */
  void addRecvCallback(RecvCallback *callback);

  /**
   * @brief Setup the IP network service.
   *
   * @return 0 on success, negative on error.
   */
  int setup();

  /**
   * @brief Strip the IP header of a valid IP packet.
   *
   * @param buf Pointer to the packet.
   * @param len Will be filled with length of the payload.
   * @return Pointer to the payload.
   */
  static const void *stripHeader(const void *packet, int &len);

private:
  Vector<DevAddr> addrs;
  Routing *routing;

  Vector<RecvCallback *> callbacks;

  class LinkLayerHandler : public LinkLayer::RecvCallback {
    IP &ip;

  public:
    LinkLayerHandler(IP &ip_);

    int handle(const void *buf, int len, LinkLayer::Device *device,
               const Info &info) override;
  } linkLayerHandler;
};

#endif

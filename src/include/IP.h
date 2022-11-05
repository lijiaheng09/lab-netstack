#ifndef NETSTACK_IP_H
#define NETSTACK_IP_H

#include <cinttypes>
#include <functional>

#include "Errors.h"
#include "Ethernet.h"

#define IP_ADDR_FMT_STRING "%hhu.%hhu.%hhu.%hhu"
#define IP_ADDR_FMT_ARGS(a) a.data[0], a.data[1], a.data[2], a.data[3]
#define IP_ADDR_FMT_NUM 4

class ICMP;
class ARP;

/**
 * @brief The IP network service built above `Ethernet` (may be substituted by
 * other link layers).
 * Can handle receiving IP packets, or send them to the link layer.
 * Need to set routing policy by setting the `Routing` object.
 * May build services based on IP `protocol` field above it.
 */
class IP {
public:
  using L2 = Ethernet; // may be substituted by other link layers

  static constexpr uint16_t PROTOCOL_ID = 0x0800; // The corresponding etherType

  struct Addr {
    union {
      unsigned char data[4];
      uint32_t num;
    };

    Addr operator~() const {
      return {.num = ~num};
    }
    friend bool operator==(Addr a, Addr b) {
      return a.num == b.num;
    }
    friend bool operator!=(Addr a, Addr b) {
      return a.num != b.num;
    }
    friend Addr operator&(Addr a, Addr b) {
      return {.num = a.num & b.num};
    }
    friend Addr operator|(Addr a, Addr b) {
      return {.num = a.num | b.num};
    }
  } __attribute__((packed));

  static constexpr Addr BROADCAST{255, 255, 255, 255};

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
  } __attribute__((packed));

  L2 &l2;
  ICMP &icmp;
  ARP &arp;

  IP(L2 &l2_);
  IP(const IP &) = delete;
  ~IP();

  struct DevAddr {
    L2::Device *device; // The corresponding link layer device.
    Addr addr;          // The IP address
    Addr mask;          // The subnet mask
  };

  /**
   * @brief Assign an IP address to a device.
   *
   * @param entry The address entry to be added.
   */
  void addAddr(DevAddr entry);

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
  int getAnyAddr(L2::Device *device, Addr &addr);

  int getSrcAddr(Addr dst, Addr &res);

  /**
   * @brief Find the device by its assigned IP address.
   *
   * @param addr The assigned IP address.
   * @return The link layer device found, `nullptr` if not found.
   */
  L2::Device *findDeviceByAddr(Addr addr);

  /**
   * @brief Implementation of the IP routing policy.
   */
  class Routing {
  public:
    using L3 = IP;
    using L2 = L3::L2;
    using Addr = L3::Addr;

    struct HopInfo {
      Addr gateway;       // The IP address of the next hop.
      L2::Device *device; // The port to the next hop.
    };

    /**
     * @brief Query for the next hop to the destination.
     *
     * @param dst The destination IP address.
     * @param res To be filled with the gateway and device for the next hop.
     * @return 0 on success, negative on error.
     */
    virtual int query(const Addr &dst, HopInfo &res) = 0;
  };

  /**
   * @brief Set the routing policy.
   *
   * @param routing Pointer to the `IP::Routing` object.
   */
  void setRouting(Routing *routing);

  /**
   * @brief Get the routing policy.
   *
   * @return routing Pointer to the `IP::Routing` object.
   */
  Routing *getRouting();

  struct SendOptions {
    int timeToLive;
    bool autoRetry;
    std::function<void()> waitingCallback;
  };

  /**
   * @brief Send a complete IP packet (leaving the checksum for
   * recalculation).
   *
   * @param buf Pointer to the packet (with checksum may be modified).
   * @param len Length of the packet.
   * @param options Other options.
   *        WARNING: autoRetry will automatically free the packet.
   *
   * @return 0 on success, negative on error.
   * Including: E_WAIT_FOR_TRYAGAIN.
   */
  int sendPacketWithHeader(void *packet, int packetLen,
                           SendOptions options = {});

  /**
   * @brief Send an IP packet.
   *
   * @param data Pointer to the payload.
   * @param dataLen Length of the payload.
   * @param src IP address of the source host.
   * @param dst IP address of the destination host.
   * @param protocol The `protocol` field of the packet.
   * @param timeToLive The `time to live` field of the packet.
   *
   * @return 0 on success, negative on error.
   * Including: E_WAIT_FOR_TRYAGAIN.
   */
  int sendPacket(const void *data, int dataLen, const Addr &src,
                 const Addr &dst, int protocol, SendOptions options = {});

  struct RecvInfo {
    L2::RecvInfo l2;       // The L2 `RecvInfo`
    const Header *header;  // The IP Header
    bool isBroadcast;      // Is the destination a broadcast IP
    L2::Device *endDevice; // The device corresponding to the destination IP
  };

  /**
   * @brief Handle a receiving IP packet.
   *
   * @param data Pointer to the payload.
   * @param dataLen Length of the payload.
   * @param info Other information.
   *
   * @return 0 on normal, 1 to remove the handler.
   */
  using RecvHandler = std::function<int(const void *data, size_t dataLen,
                                        const RecvInfo &info)>;

  /**
   * @brief Add a handler for receiving packets.
   *
   * @param handler The handler.
   * @param protocol The matched `protocol` field.
   * @param promiscuous If matches destination IP of other hosts, ignoring
   * `protocol`.
   */
  void addOnRecv(RecvHandler handler, uint8_t protocol,
                 bool promiscuous = false);

  /**
   * @brief Setup the IP network service.
   *
   * @return 0 on success, negative on error.
   */
  int setup();

private:
  Vector<DevAddr> addrs;
  Routing *routing;
  List<RecvHandler> onRecvPromiscuous;
  HashMultiMap<uint8_t, RecvHandler> onRecv;

  void handleRecv(const void *packet, size_t packetCapLen,
                  const L2::RecvInfo &info);
};

#endif

#ifndef NETSTACK_TCP_H
#define NETSTACK_TCP_H

#include "IP.h"

class TCP {
public:
  using L3 = IP;

  static constexpr uint8_t PROTOCOL_ID = 6;

  enum CtrlBits : uint8_t {
    CTL_URG = 0x20,
    CTL_ACK = 0x10,
    CTL_PSH = 0x08,
    CTL_RST = 0x04,
    CTL_SYN = 0x02,
    CTL_FIN = 0x01,
  };

  struct Header {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t offAndRsrv; // dataOff : 4 | reserved : 4
    uint8_t ctrl;       // reserved : 2 | ctrl bits : 6
    uint16_t window;
    uint16_t checksum;
    uint16_t urgPtr;
  } __attribute__((packed));

  enum OptionKind : uint8_t {
    OPT_END = 0,
    OPT_NOP = 1,
    OPT_MSS = 2,
  };

  struct PseudoL3Header {
    TCP::L3::Addr src;
    TCP::L3::Addr dst;
    uint8_t zero;
    uint8_t ptcl;
    uint16_t tcpLen;
  } __attribute__((packed));

  static uint16_t calcChecksum(const void *seg, size_t segLen, L3::Addr src,
                               L3::Addr dst);

  TaskDispatcher &dispatcher;
  Timer &timer;
  L3 &l3;

  TCP(L3 &l3_);

  int setup();

  struct Sock {
    L3::Addr addr;
    uint16_t port;

    friend bool operator==(Sock a, Sock b) {
      return a.addr == b.addr && a.port == b.port;
    }
  };

  class Desc {
    TCP &tcp;
    Sock local;

    Desc(TCP &tcp_);
    virtual ~Desc();

    friend class TCP;

  public:
    virtual int bind(Sock sock);
  };

  struct RecvInfo {
    L3::RecvInfo l3;
    const Header *header;
  };

  class Connection;

  class Listener : public Desc {
    Listener(Desc &desc);
    Listener(const Listener &) = delete;

    friend class TCP;

  public:
    Connection *awaitAccept();

    void close();

  private:
    void handleRecv(const void *data, size_t dataLen, const RecvInfo &info);

    using WaitHandler = std::function<void()>;

    Queue<Connection *> pendingConnctions;
    Queue<WaitHandler> pendingAccepts;
  };

  static constexpr size_t WND_SIZE = 256 << 10;

  class Connection : public Desc {
    enum class ST {
      LISTEN,
      SYN_SENT,
      SYN_RECEIVED,
      ESTABLISHED,
      FIN_WAIT_1,
      FIN_WAIT_2,
      CLOSE_WAIT,
      CLOSING,
      LAST_ACK,
      TIME_WAIT,
      CLOSED
    } state;

    Sock remote;

    Connection(Desc &end);
    Connection(const Connection &) = delete;
    ~Connection();

    friend class TCP;

  public:
    ssize_t send(const void *data, size_t dataLen);

    ssize_t recv(void *data, size_t maxLen);

    void close();

  private:
    void handleRecv(const void *seg, size_t segLen, const RecvInfo &info);

    using WaitHandler = std::function<void()>;

    void *sendBuf, *recvBuf;
    Queue<WaitHandler> pendingSends, pendingRecvs;

    uint32_t sndUnAck;  // send unacknowledged
    uint32_t sndNxt;    // send next
    uint32_t sndWnd;    // send window
    uint32_t sndUrgPtr; // send urgent pointer
    // segment sequence number used for last window update
    uint32_t sndWndUpdSeq;
    // segment acknowledgment number used for last window update
    uint32_t sndWndUpdAck;
    uint32_t initSndSeq; // initial send sequence number

    uint32_t rcvNxt;     // receive next
    uint32_t rcvWnd;     // receive window
    uint32_t rcvUrgPtr;  // receive urgent pointer
    uint32_t initRcvSeq; // initial receive sequence number
  };

  /**
   * @brief Create a TCP descriptor.
   *
   * @return The created descriptor.
   */
  Desc *create();

  /**
   * @brief Create a TCP listener by descriptor.
   * The descriptor will be destroyed.
   *
   * @param desc The descriptor.
   * @return The created listener.
   */
  Listener *listen(Desc *desc);

  static constexpr uint16_t DYN_PORTS_BEGIN = 49152;

private:
  HashSet<uint16_t> freePorts;
  HashMap<uint16_t, int> portUserCount;
  HashMap<Sock, int> sockUserCount;

  bool hasUse(Sock sock);
  void addUse(Sock sock);
  void releaseUse(Sock sock);

  HashMap<Sock, Listener *> listeners;
  HashMap<std::pair<Sock, Sock>, Connection *> connections;

  int reset(const Header &inHeader, L3::Addr inSrc, L3::Addr inDst);

  void handleRecv(const void *seg, size_t segLen, const L3::RecvInfo &info);
};

#endif

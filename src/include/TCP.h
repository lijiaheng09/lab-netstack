#ifndef NETSTACK_TCP_H
#define NETSTACK_TCP_H

#include <random>

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

  static uint16_t checksum(const void *seg, size_t tcpLen, L3::Addr src,
                           L3::Addr dst);

  static uint32_t genInitSeqNum();

  TaskDispatcher &dispatcher;
  Timer &timer;
  L3 &l3;
  std::mt19937 rnd;

  TCP(L3 &l3_);
  ~TCP();

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

    Desc(TCP &tcp_);
    virtual ~Desc();

    friend class TCP;

  public:
    Sock local;
    virtual int bind(Sock sock);
    virtual int awaitClose();
  };

  struct RecvInfo {
    L3::RecvInfo l3;
    const Header *header;
    const uint8_t *options;
  };

  class Connection;

  class Listener : public Desc {
    bool isClosed;

    Listener(const Desc &desc);
    Listener(const Listener &) = delete;
    ~Listener();

    friend class TCP;

  public:
    int bind(Sock sock) override;

    Connection *awaitAccept();

    int awaitClose() override;

  private:
    void handleRecv(const void *data, size_t dataLen, const RecvInfo &info);

    using WaitHandler = std::function<void()>;

    // established connections pending for `accept`.
    Queue<Connection *> pdRecv;
    Queue<WaitHandler> pdAccept;
  };

  static constexpr uint32_t MSS = 1024;
  static constexpr uint32_t BUF_SIZE = 128 << 10;
  static constexpr Timer::Duration RETRANS_TIMEOUT = 500ms;
  static constexpr Timer::Duration MSL = 60s;

  class Connection : public Desc {
  public:
    Sock foreign;

  private:
    enum class St {
      CLOSED,
      LISTEN,
      SYN_SENT,
      SYN_RECEIVED,
      ESTABLISHED,
      FIN_WAIT_1,
      FIN_WAIT_2,
      CLOSE_WAIT,
      CLOSING,
      LAST_ACK,
      TIME_WAIT
    } state;

    uint32_t mss;
    bool isReset;

    Connection(const Desc &desc, Sock foreign_);
    Connection(const Connection &) = delete;
    ~Connection();

    friend class TCP;

  public:
    int bind(Sock sock) override;

    ssize_t send(const void *data, size_t dataLen);

    ssize_t asyncSend(const void *data, size_t dataLen);

    ssize_t asyncSendAll(const void *data, size_t dataLen);

    ssize_t recv(void *data, size_t maxLen);

    ssize_t awaitRecv(void *data, size_t maxLen);

    int awaitClose() override;

  private:
    void notifyAll();

    void removeSegments();

    void advanceUnAck(uint32_t ack);

    void checkSend();

    int sendSeg(const void *data, uint32_t dataLen, uint8_t ctrl, uint32_t seqNum);

    int sendSeg(const void *data, uint32_t dataLen, uint8_t ctrl);

    void addSendSeg(const void *data, uint32_t dataLen, uint8_t ctrl);

    void connect();

    int establish();

    void deliverData(const void *data, uint32_t dataLen, uint32_t segSeq);

    void parseOptions(const uint8_t *begin, const uint8_t *end);

    void handleRecvListen(Listener *listener, const void *data, size_t dataLen,
                          const RecvInfo &info);

    void handleRecv(const void *data, size_t dataLen, const RecvInfo &info);

    using WaitHandler = std::function<void()>;

    struct SegInfo {
      uint32_t begin, end;

      friend bool operator<(SegInfo a, SegInfo b) {
        return a.begin != b.begin ? a.begin < b.begin : a.end < b.end;
      }
    };

    struct SndSegInfo : public SegInfo {
      void *data;
      uint32_t dataLen;
      uint8_t ctrl;
      // TODO: timer
      mutable Timer::Task *retrans;
    };

    uint32_t hRcv, tRcv, uRcv;
    char rcvBuf[BUF_SIZE];
    Queue<WaitHandler> pdSnd, pdRcv, onEstab, onClose;
    OrdSet<SegInfo> rcvInfo;
    OrdSet<SndSegInfo> sndInfo;

    Timer::Task *timeWait;

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
   * @return The created listener, `nullptr` on error.
   */
  Listener *listen(Desc *desc);

  /**
   * @brief Make a TCP connection from descriptor.
   *
   * @param desc The local descriptor.
   * @return The created connection, `nullptr` on error.
   */
  Connection *connect(Desc *desc, Sock dst);

  static constexpr uint16_t DYN_PORTS_BEGIN = 49152;
  static constexpr uint16_t DYN_PORTS_END = 65535;

private:
  HashMap<Sock, Listener *> listeners;

  // (local, foreign) -> connection
  HashMap<std::pair<Sock, Sock>, Connection *> connections;

  static bool seqLt(uint32_t a, uint32_t b);
  static bool seqLe(uint32_t a, uint32_t b);

  int sendSeg(const void *data, size_t dataLen, const Header &header,
              L3::Addr src, L3::Addr dst);

  void handleRecvClosed(const void *data, size_t dataLen, const RecvInfo &info);

  void handleRecv(const void *seg, size_t tcpLen, const L3::RecvInfo &info);

  void removeConnection(Connection *conn);
};

#endif

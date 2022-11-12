#include <cassert>

#include <mutex>

#include <arpa/inet.h>

#include "TCP.h"

#include "utils.h"
#include "log.h"

TCP::TCP(L3 &l3_)
    : dispatcher(l3_.l2.netBase.dispatcher), timer(l3_.l2.netBase.timer),
      l3(l3_), rnd(Timer::Clock::now().time_since_epoch().count()) {}

uint16_t TCP::checksum(const void *seg, size_t tcpLen, L3::Addr src,
                       L3::Addr dst) {
  const TCP::Header &header = *(const Header *)seg;
  size_t dataOff = ((header.offAndRsrv >> 4)) * 4UL;
  PseudoL3Header pseudo{
      .src = src, .dst = dst, .ptcl = PROTOCOL_ID, .tcpLen = htons(tcpLen)};
  uint16_t sum = csum16(&pseudo, sizeof(pseudo));
  return csum16(seg, tcpLen, ~sum);
}

uint32_t TCP::genInitSeqNum() {
  return std::chrono::duration_cast<std::chrono::microseconds>(
             Timer::Clock::now().time_since_epoch())
             .count() /
         4;
}

bool TCP::seqLe(uint32_t a, uint32_t b) {
  return (int32_t)(b - a) >= 0;
}

bool TCP::seqLt(uint32_t a, uint32_t b) {
  return (int32_t)(b - a) > 0;
}

int TCP::setup() {
  l3.addOnRecv(
      [this](auto &&...args) -> int {
        handleRecv(args...);
        return 0;
      },
      PROTOCOL_ID);
  return 0;
}

TCP::Desc::Desc(TCP &tcp_) : tcp(tcp_), local{} {}
TCP::Desc::~Desc() {}

int TCP::Desc::bind(Sock sock) {
  if (tcp.listeners.count(sock)) {
    LOG_ERR("Socket address already in use");
    return -1;
  }
  local = sock;
  return 0;
}

void TCP::Desc::close() {
  delete this;
}

TCP::Desc *TCP::create() {
  return new Desc(*this);
}

TCP::Listener *TCP::listen(Desc *desc) {
  if (desc->local.port == 0) {
    // TODO: allocate a port.
    Sock local = desc->local;
    do {
      local.port =
          DYN_PORTS_BEGIN + rnd() % (DYN_PORTS_END - DYN_PORTS_BEGIN + 1);
    } while (listeners.count(local) || listeners.count({{0}, local.port}));
    desc->local = local;
  }

  Listener *listener = new Listener(*desc);
  delete desc;
  listeners[listener->local] = listener;
  return listener;
}

TCP::Connection *TCP::connect(Desc *desc, Sock dst) {
  Sock local = desc->local;
  if (local.addr == L3::Addr{0}) {
    if (l3.getSrcAddr(dst.addr, local.addr) != 0) {
      LOG_ERR("Unable to get source address");
      return nullptr;
    }
  }
  if (local.port == 0) {
    // TODO: allocate a port.
    uint16_t p;
    do {
      local.port =
          DYN_PORTS_BEGIN + rnd() % (DYN_PORTS_END - DYN_PORTS_BEGIN + 1);
    } while (listeners.count(local) || listeners.count({{0}, p}) ||
             connections.count({local, dst}));
  }
  if (connections.count({local, dst})) {
    LOG_ERR("Socket address already in use");
    return nullptr;
  }
  desc->local = local;

  Connection *connection = new Connection(*desc, dst);
  delete desc;
  connection->connect();
  connections[{connection->local, connection->foreign}] = connection;
  return connection;
}

int TCP::sendSeg(const void *data, size_t dataLen, const Header &header,
                 L3::Addr src, L3::Addr dst) {
  assert(dataLen <= SIZE_MAX - sizeof(Header));

  size_t tcpLen = dataLen + sizeof(Header);
  void *seg = malloc(tcpLen);
  if (!seg) {
    LOG_ERR_POSIX("malloc");
    return -1;
  }

  Header &sendHeader = *(Header *)seg;
  sendHeader = header;
  if (sendHeader.offAndRsrv == 0)
    sendHeader.offAndRsrv = (sizeof(Header) / 4) << 4;
  sendHeader.checksum = 0;

  if (dataLen)
    memcpy(&sendHeader + 1, data, dataLen);

  sendHeader.checksum = checksum(seg, tcpLen, src, dst);
  NS_ASSERT(checksum(seg, tcpLen, src, dst) == 0);

  int rc = l3.send(seg, tcpLen, src, dst, PROTOCOL_ID,
                   {.timeToLive = 60, .autoRetry = true});
  free(seg);
  return rc;
}

void TCP::handleRecv(const void *seg, size_t tcpLen, const L3::RecvInfo &info) {
  if (tcpLen < sizeof(Header)) {
    LOG_INFO("Truncated TCP Header: %lu/%lu", tcpLen, sizeof(Header));
    return;
  }
  const Header &header = *(const Header *)seg;
  size_t dataOff = (header.offAndRsrv >> 4) * 4UL;
  if (tcpLen < dataOff) {
    LOG_INFO("Truncated TCP Header: %lu/%lu:%lu", tcpLen, sizeof(Header),
             dataOff);
    return;
  }
  if (checksum(seg, tcpLen, info.header->src, info.header->dst) != 0) {
    LOG_INFO("TCP checksum error");
    return;
  }

  const void *data = (const char *)seg + dataOff;
  size_t dataLen = tcpLen - dataOff;
  RecvInfo newInfo{.l3 = info, .header = &header};

  Sock local{.addr = info.header->dst, .port = ntohs(header.dstPort)};
  Sock foreign{.addr = info.header->src, .port = ntohs(header.srcPort)};

  auto itConn = connections.find({local, foreign});
  if (itConn != connections.end()) {
    itConn->second->handleRecv(data, dataLen, newInfo);

  } else {
    auto itListen = listeners.find(local);
    if (itListen == listeners.end())
      itListen = listeners.find(Sock{.addr{0}, .port = local.port});

    if (itListen != listeners.end())
      itListen->second->handleRecv(data, dataLen, newInfo);
    else
      handleRecvClosed(data, dataLen, newInfo);
  }
}

void TCP::handleRecvClosed(const void *data, size_t dataLen,
                           const RecvInfo &info) {
  const Header &h = *info.header;
  if (h.ctrl & CTL_RST)
    return;

  size_t segLen = dataLen;
  if (h.ctrl & CTL_SYN)
    segLen++;
  if (h.ctrl & CTL_FIN)
    segLen++;

  if (~h.ctrl & CTL_ACK) {
    sendSeg(nullptr, 0,
            {.srcPort = h.dstPort,
             .dstPort = h.srcPort,
             .seqNum = 0,
             .ackNum = htonl(ntohl(h.seqNum) + segLen),
             .ctrl = CTL_RST | CTL_ACK},
            info.l3.header->dst, info.l3.header->src);
  } else {
    sendSeg(nullptr, 0,
            {.srcPort = h.dstPort,
             .dstPort = h.srcPort,
             .seqNum = h.ackNum,
             .ctrl = CTL_RST},
            info.l3.header->dst, info.l3.header->src);
  }
}

TCP::Listener::Listener(const Desc &desc) : Desc(desc) {}

TCP::Connection *TCP::Listener::awaitAccept() {
  TCP::Connection *res = nullptr;
  std::mutex finish;
  finish.lock();
  tcp.dispatcher.beginInvoke([this, &res, &finish]() {
    auto get = [this, &res, &finish]() {
      NS_ASSERT(!pdEstab.empty());
      res = pdEstab.front();
      pdEstab.pop();
      finish.unlock();
    };
    if (!pdEstab.empty())
      get();
    else
      pdAccept.push(get);
  });
  finish.lock();
  return res;
}

void TCP::Listener::handleRecv(const void *data, size_t dataLen,
                               const RecvInfo &info) {
  const Header &h = *info.header;

  if (h.ctrl & CTL_RST)
    return;

  if (h.ctrl & CTL_ACK) {
    tcp.sendSeg(nullptr, 0,
                {.srcPort = h.dstPort,
                 .dstPort = h.srcPort,
                 .seqNum = h.ackNum,
                 .ctrl = CTL_RST},
                info.l3.header->dst, info.l3.header->src);
    return;
  }

  if (h.ctrl & CTL_SYN) {
    Connection *connection =
        new Connection(*this, {info.l3.header->src, ntohs(h.srcPort)});
    connection->local = {info.l3.header->dst, ntohs(h.dstPort)};
    connection->handleRecvListen(this, data, dataLen, info);
    tcp.connections[{connection->local, connection->foreign}] = connection;
  }

  return;
}

void TCP::Listener::newEstab(Connection *conn) {
  pdEstab.push(conn);
  while (!pdEstab.empty() && !pdAccept.empty()) {
    auto h = pdAccept.front();
    pdAccept.pop();
    h();
  }
}

void TCP::Listener::close() {
  return;
}

TCP::Connection::Connection(const Desc &desc, Sock foreign_)
    : Desc(desc), foreign(foreign_), listener(nullptr), rcvBuf(nullptr) {}

TCP::Connection::~Connection() {
  free(rcvBuf);
  for (auto &&e : sndInfo)
    free(e.data);
}

ssize_t TCP::Connection::recv(void *data, size_t maxLen) {
  if (!uRcv || !maxLen)
    return 0;

  size_t dataLen = uRcv;
  if (maxLen < dataLen)
    dataLen = maxLen;
  uRcv -= dataLen;
  if (hRcv + dataLen <= BUF_SIZE) {
    memcpy(data, (char *)rcvBuf + hRcv, dataLen);
  } else {
    size_t n0 = BUF_SIZE - hRcv;
    memcpy(data, (char *)rcvBuf + hRcv, n0);
    memcpy((char *)data + n0, rcvBuf, dataLen - n0);
  }
  hRcv = (hRcv + dataLen) % BUF_SIZE;
  rcvWnd = BUF_SIZE - uRcv;
  return dataLen;
}

ssize_t TCP::Connection::awaitRecv(void *data, size_t maxLen) {
  if (!maxLen)
    return 0;
  ssize_t rc;
  std::mutex finish;
  finish.lock();
  tcp.dispatcher.beginInvoke([this, &rc, &finish, data, maxLen]() {
    auto get = [this, &rc, &finish, data, maxLen]() {
      NS_ASSERT(uRcv);
      rc = recv(data, maxLen);
      finish.unlock();
    };
    if (uRcv)
      get();
    else
      pdRcv.push(get);
  });
  finish.lock();
  return rc;
}

ssize_t TCP::Connection::send(const void *data, size_t dataLen) {
  if (sndNxt - sndUnAck >= sndWnd)
    return 0;
  size_t maxLen = std::min(MSS, sndWnd - (sndNxt - sndUnAck));
  if (dataLen > maxLen)
    dataLen = maxLen;
  int rc = addSendSeg(data, dataLen, CTL_ACK);
  if (rc < 0)
    return rc;
  return dataLen;
}

ssize_t TCP::Connection::asyncSend(const void *data, size_t dataLen) {
  ssize_t rc;
  std::mutex finish;
  finish.lock();
  tcp.dispatcher.beginInvoke([this, &rc, &finish, data, dataLen]() {
    auto put = [this, &rc, &finish, data, dataLen]() {
      assert(sndNxt - sndUnAck < sndWnd);
      rc = send(data, dataLen);
      finish.unlock();
    };
    if (sndNxt - sndUnAck < sndWnd)
      put();
    else
      pdSnd.push(put);
  });
  finish.lock();
  return rc;
}

ssize_t TCP::Connection::asyncSendAll(const void *data, size_t dataLen) {
  size_t sent = 0;
  while (sent < dataLen) {
    ssize_t rc = asyncSend((const char *)data + sent, dataLen - sent);
    if (rc < 0)
      return rc;
    sent += rc;
  }
  return sent;
}

int TCP::Connection::sendSeg(const void *data, uint32_t dataLen, uint8_t ctrl) {
  return tcp.sendSeg(data, dataLen,
                     {.srcPort = htons(local.port),
                      .dstPort = htons(foreign.port),
                      .seqNum = htonl(sndNxt),
                      .ackNum = (ctrl & CTL_ACK) ? htonl(rcvNxt) : 0,
                      .ctrl = ctrl,
                      .window = htons(std::min(rcvWnd, (uint32_t)UINT16_MAX))},
                     local.addr, foreign.addr);
}

int TCP::Connection::addSendSeg(const void *data, uint32_t dataLen,
                                uint8_t ctrl) {
  uint32_t segLen = dataLen;
  if (ctrl & CTL_SYN)
    segLen++;
  if (ctrl & CTL_FIN)
    segLen++;

  void *dataCopy = nullptr;
  if (dataLen) {
    dataCopy = malloc(dataLen);
    if (!dataCopy) {
      LOG_ERR_POSIX("malloc");
      return -1;
    }
    memcpy(dataCopy, data, dataLen);
  }

  int rc = sendSeg(data, dataLen, ctrl);
  sndInfo.insert({sndNxt, sndNxt + segLen, dataCopy, dataLen, ctrl});
  sndNxt += segLen;
  return rc;
}

void TCP::Connection::connect() {
  initSndSeq = genInitSeqNum();
  sndUnAck = initSndSeq;
  sndNxt = initSndSeq;
  addSendSeg(nullptr, 0, CTL_SYN);
  state = St::SYN_SENT;
}

int TCP::Connection::establish() {
  state = St::ESTABLISHED;
  if (!(rcvBuf = malloc(BUF_SIZE))) {
    LOG_ERR_POSIX("malloc");
    return -1;
  }
  hRcv = tRcv = uRcv = 0;
  rcvWnd = BUF_SIZE;
  LOG_INFO("Connection established");
  if (listener)
    listener->newEstab(this);
  return 0;
}

void TCP::Connection::advanceUnAck(uint32_t ack) {
  uint32_t ackNum = ack - sndUnAck;
  sndUnAck = ack;
  while (!sndInfo.empty() && seqLe(sndInfo.begin()->end, sndUnAck)) {
    // TODO: remove timer
    auto p = sndInfo.begin();
    free(p->data);
    sndInfo.erase(p);
  }
}

void TCP::Connection::deliverData(const void *data, uint32_t dataLen,
                                  uint32_t segSeq) {
  // rcvNxt --- tRcv
  uint32_t maxLen = rcvWnd - (segSeq - rcvNxt);
  if (dataLen > maxLen)
    dataLen = maxLen;
  size_t p = (tRcv + (segSeq - rcvNxt)) % BUF_SIZE;

  if (p + dataLen <= BUF_SIZE) {
    memcpy((char *)rcvBuf + p, data, dataLen);
  } else {
    size_t n0 = BUF_SIZE - p;
    memcpy((char *)rcvBuf + p, data, n0);
    memcpy(rcvBuf, (const char *)data + n0, dataLen - n0);
  }

  rcvInfo.insert({segSeq, segSeq + dataLen});
  if (segSeq == rcvNxt) {
    uint32_t prvRcvNxt = rcvNxt;
    while (!rcvInfo.empty() && seqLe(rcvInfo.begin()->begin, rcvNxt)) {
      if (seqLt(rcvNxt, rcvInfo.begin()->end))
        rcvNxt = rcvInfo.begin()->end;
      rcvInfo.erase(rcvInfo.begin());
    }
    tRcv = (tRcv + (rcvNxt - prvRcvNxt)) % BUF_SIZE;
    uRcv += rcvNxt - prvRcvNxt;
  }

  while (uRcv && !pdRcv.empty()) {
    auto h = pdRcv.front();
    pdRcv.pop();
    h();
  }
}

void TCP::Connection::handleRecvListen(Listener *listener_, const void *data,
                                       size_t dataLen, const RecvInfo &info) {
  const Header &h = *info.header;
  listener = listener_;

  initRcvSeq = ntohl(h.seqNum);
  rcvNxt = initRcvSeq + 1;

  initSndSeq = genInitSeqNum();
  sndUnAck = initSndSeq;
  sndNxt = initSndSeq;
  addSendSeg(nullptr, 0, CTL_SYN | CTL_ACK);
  state = St::SYN_RECEIVED;
}

void TCP::Connection::handleRecv(const void *data, size_t dataLen,
                                 const RecvInfo &info) {
  const Header &h = *info.header;
  switch (state) {
  case St::CLOSED: {
    tcp.handleRecvClosed(data, dataLen, info);
    break;
  }

  case St::SYN_SENT: {
    bool ackAcceptable = false;

    if (h.ctrl & CTL_ACK) {
      uint32_t segAck = ntohl(h.ackNum);
      if (!seqLt(initSndSeq, segAck) || !seqLe(segAck, sndNxt)) {
        if (!h.ctrl & CTL_RST) {
          tcp.sendSeg(nullptr, 0,
                      {.srcPort = htons(local.port),
                       .dstPort = htons(foreign.port),
                       .seqNum = h.ackNum,
                       .ctrl = CTL_RST},
                      local.addr, foreign.addr);
        }
        return;
      }
      if (seqLe(sndUnAck, segAck) && seqLe(segAck, sndNxt))
        ackAcceptable = true;
    }

    if (h.ctrl & CTL_RST) {
      if (ackAcceptable) {
        // TODO: connection reset.
        LOG_INFO("Conenction reset");
        state = St::CLOSED;
        return;
      } else {
        return;
      }
    }

    if (h.ctrl & CTL_SYN) {
      initRcvSeq = ntohl(h.seqNum);
      rcvNxt = initRcvSeq + 1;
      if (h.ctrl & CTL_ACK) {
        advanceUnAck(ntohl(h.ackNum));
        sndWnd = ntohs(h.window);
        sndWndUpdSeq = ntohl(h.seqNum);
        sndWndUpdAck = ntohl(h.ackNum);
      }
      if (seqLt(initSndSeq, sndUnAck)) {
        if (establish() != 0) {
          // TODO: handle error
          abort();
        }
        sendSeg(nullptr, 0, CTL_ACK);

        // TODO: URG & text
      } else {
        state = St::SYN_RECEIVED;

        // TODO: resend SYN-ACK ??
        sendSeg(nullptr, 0, CTL_ACK);
      }
    }

    break;
  }

  case St::SYN_RECEIVED:
  case St::ESTABLISHED:
  case St::FIN_WAIT_1:
  case St::FIN_WAIT_2:
  case St::CLOSE_WAIT:
  case St::CLOSING:
  case St::LAST_ACK:
  case St::TIME_WAIT: {
    uint32_t segLen = dataLen;
    if (h.ctrl & CTL_SYN)
      segLen++;
    if (h.ctrl & CTL_FIN)
      segLen++;
    uint32_t segSeq = ntohl(h.seqNum);

    // first check sequence number
    bool seqAcceptable = false;
    if (segLen == 0) {
      if (rcvWnd == 0)
        seqAcceptable = segSeq == rcvNxt;
      else
        seqAcceptable = seqLe(rcvNxt, segSeq) && seqLt(segSeq, rcvNxt + rcvWnd);
    } else {
      if (rcvWnd == 0)
        seqAcceptable = false;
      else
        seqAcceptable =
            (seqLe(rcvNxt, segSeq) && seqLt(segSeq, rcvNxt + rcvWnd)) ||
            (seqLe(rcvNxt, segSeq + segLen - 1) &&
             seqLt(segSeq + segLen - 1, rcvNxt + rcvWnd));
    }
    if (!seqAcceptable) {
      if (~h.ctrl & CTL_RST)
        sendSeg(nullptr, 0, CTL_ACK);
      return;
    }
    // TODO: tailor the segment?

    // second check the RST bit
    switch (state) {
    case St::SYN_RECEIVED: {
      if (h.ctrl & CTL_RST) {
        if (listener) {
          // TODO: delete this
        } else {
          // TODO: signal user
          LOG_INFO("Connection refused");
          state = St::CLOSED;
          return;
        }
        // TODO: remove segments
      }
      break;
    }

    case St::ESTABLISHED:
    case St::FIN_WAIT_1:
    case St::FIN_WAIT_2:
    case St::CLOSE_WAIT: {
      if (h.ctrl & CTL_RST) {
        // TODO: signal user
        LOG_INFO("Connection reset");
        state = St::CLOSED;
        return;
      }
      break;
    }

    case St::CLOSING:
    case St::LAST_ACK:
    case St::TIME_WAIT: {
      if (h.ctrl & CTL_RST) {
        // TODO: reset
        LOG_INFO("Connection reset");
        state = St::CLOSED;
        return;
      }
      break;
    }
    }

    // third check security and precedence

    // fourth, check the SYN bit
    if (h.ctrl & CTL_SYN) {
      sendSeg(nullptr, 0, CTL_RST);
      // TODO: Connection reset
      LOG_INFO("Connection reset");
      state = St::CLOSED;
      return;
    }

    // fifth check the ACK field
    if (~h.ctrl & CTL_ACK)
      return;
    uint32_t segAck = htonl(h.ackNum);
    switch (state) {
    case St::SYN_RECEIVED: {
      if (seqLe(sndUnAck, segAck) && seqLe(segAck, sndNxt)) {
        sndWnd = ntohs(h.window);
        sndWndUpdSeq = segSeq;
        sndWndUpdAck = segAck;
        if (establish() != 0) {
          // TODO: handle error
          abort();
        }
      } else {
        tcp.sendSeg(nullptr, 0,
                    {.srcPort = htons(local.port),
                     .dstPort = htons(foreign.port),
                     .seqNum = h.ackNum,
                     .ctrl = CTL_RST},
                    local.addr, foreign.addr);
        return;
      }
      // continue process ESTABLISHED
    }

    case St::ESTABLISHED: {
      if (seqLt(sndUnAck, segAck) && seqLe(segAck, sndNxt)) {
        advanceUnAck(segAck);
        if (seqLt(sndWndUpdSeq, segSeq) ||
            (sndWndUpdSeq == segSeq && seqLe(sndWndUpdAck, segAck))) {
          sndWnd = ntohs(h.window);
          sndWndUpdSeq = segSeq;
          sndWndUpdAck = segAck;
          while (sndNxt - sndUnAck < sndWnd && !pdSnd.empty()) {
            auto h = pdSnd.front();
            pdSnd.pop();
            h();
          }
        }
      } else if (seqLt(sndNxt, segAck)) {
        sendSeg(nullptr, 0, CTL_ACK);
        return;
      }
      break;
    }

    default: {
      LOG_ERR("Unimplemented...");
      break;
    }
    }

    // (TODO) sixth, check the URG bit

    // seventh, process the segment text
    switch (state) {
    case St::ESTABLISHED:
    case St::FIN_WAIT_1:
    case St::FIN_WAIT_2: {
      deliverData(data, dataLen, segSeq);
      sendSeg(nullptr, 0, CTL_ACK);
      break;
    }

    default: {
      return;
    }
    }

    // eighth, check the FIN bit

    break;
  }

  default: {
    LOG_ERR("Unimplemented...");
    break;
  }
  }
}

void TCP::Connection::close() {
  // TODO;
}

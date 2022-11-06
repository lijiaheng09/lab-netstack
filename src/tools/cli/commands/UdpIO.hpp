#include "common.h"
#include "commands.h"

#include <atomic>
#include <mutex>

class CmdNcUdpListen : public Command {
  class Handler {
    std::atomic<bool> &listen;
    IP::Addr &remote;
    int &remotePort;

  public:
    int listenPort;

    Handler(std::atomic<bool> &listen_, IP::Addr &remote_, int &remotePort_,
            int port_)
        : listen(listen_), remote(remote_),
          remotePort(remotePort_), listenPort(port_) {}

    int handle(const void *data, int dataLen, const UDP::RecvInfo &info) {
      if (listen.load()) {
        remote = info.l3.header->src;
        remotePort = ntohs(info.udpHeader->srcPort);
        listen.store(false);
        printf("[*] Recv from " IP_ADDR_FMT_STRING ":%d\n",
               IP_ADDR_FMT_ARGS(remote), remotePort);
      }
      printf("%.*s", dataLen, (const char *)data);
      return 0;
    }
  };

public:
  CmdNcUdpListen() : Command("nc-u-listen") {}

  int main(int argc, char **argv) override {
    IP::Addr src, remote;
    int port, remotePort;
    if (argc != 2 || sscanf(argv[1], "%d", &port) != 1) {
      fprintf(stderr, "Usage: %s <port>\n", argv[0]);
      return 1;
    }

    if (ns.ip.getAnyAddr(nullptr, src) < 0) {
      fprintf(stderr, "No IP address on the host\n");
      return 1;
    }

    std::atomic<bool> listen;
    listen.store(true);

    std::atomic<bool> close;
    std::mutex closed;
    close.store(false);
    closed.lock();

    Handler *handler = new Handler(listen, remote, remotePort, port);
    INVOKE({
      ns.udp.addOnRecv([this, handler, &close, &closed](auto &&...args) -> int {
        if (close) {
          closed.unlock();
          return 1;
        }
        handler->handle(args...);
        return 0;
      }, handler->listenPort);
    })

    static constexpr int MAXLINE = 1024;
    char line[MAXLINE];
    while (fgets(line, MAXLINE, stdin)) {
      int dataLen = strlen(line);
      if (!listen.load()) {
        std::mutex sending;
        INVOKE({
          auto retryCallback = [&] { sending.unlock(); };
          int rc = ns.udp.sendSegment(
              line, dataLen, src, port, remote, remotePort,
              {autoRetry : true, waitingCallback : retryCallback});
          if (rc == E_WAIT_FOR_TRYAGAIN)
            sending.lock();
        })
        sending.lock();
      }
      if (strcmp(line, ":quit\n") == 0) {
        break;
      }
    }

    close.store(true);
    closed.lock();
    delete handler;
    return 0;
  }
};

class CmdNcUdp : public Command {
  class Handler {
  public:
    int listenPort;
    Handler(int port_) : listenPort(port_) {}

    int handle(const void *data, int dataLen, const UDP::RecvInfo &info) {
      printf("%.*s", dataLen, (const char *)data);
      return 0;
    }
  };

public:
  CmdNcUdp() : Command("nc-u") {}

  int main(int argc, char **argv) override {
    IP::Addr src, remote;
    int port, remotePort;
    if (argc != 3 ||
        sscanf(argv[1], IP_ADDR_FMT_STRING, IP_ADDR_FMT_ARGS(&remote)) !=
            IP_ADDR_FMT_NUM ||
        sscanf(argv[2], "%d", &remotePort) != 1) {
      fprintf(stderr, "Usage: %s <host> <port>\n", argv[0]);
      return 1;
    }

    if (ns.ip.getSrcAddr(remote, src) < 0) {
      fprintf(stderr, "No IP address on the host\n");
      return 1;
    }

    // Need to assign a port.
    port = 10000 + random() % 50000;

    std::atomic<bool> close;
    std::mutex closed;
    close.store(false);
    closed.lock();

    Handler *handler = new Handler(port);
    INVOKE({
      ns.udp.addOnRecv([this, handler, &close, &closed](auto &&...args) -> int {
        if (close) {
          closed.unlock();
          return 1;
        }
        handler->handle(args...);
        return 0;
      }, handler->listenPort);
    })

    static constexpr int MAXLINE = 1024;
    char line[MAXLINE];
    while (fgets(line, MAXLINE, stdin)) {
      int dataLen = strlen(line);
      std::mutex sending;
      INVOKE({
        auto retryCallback = [&] { sending.unlock(); };
        int rc = ns.udp.sendSegment(
            line, dataLen, src, port, remote, remotePort,
            {autoRetry : true, waitingCallback : retryCallback});
        if (rc == E_WAIT_FOR_TRYAGAIN)
          sending.lock();
      })
      sending.lock();
      if (strcmp(line, ":quit\n") == 0) {
        break;
      }
    }

    close.store(true);
    closed.lock();
    delete handler;
    return 0;
  };
};

#include "netstack.h"
#include "commands.h"

#include <atomic>
#include <mutex>

class CmdNcUdpListen : public Command {
  class Handler : public UDP::RecvCallback {
    std::atomic<bool> &listen;
    IP::Addr &remote;
    int &remotePort;

  public:
    Handler(std::atomic<bool> &listen_, IP::Addr &remote_, int &remotePort_,
            int port_)
        : listen(listen_), remote(remote_),
          remotePort(remotePort_), UDP::RecvCallback(port_) {}

    int handle(const void *data, int dataLen, const Info &info) override {
      if (listen.load()) {
        remote = info.netHeader->src;
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

    if (ip.getAnyAddr(nullptr, src) < 0) {
      fprintf(stderr, "No IP address on the host\n");
      return 1;
    }

    std::atomic<bool> listen;
    listen.store(true);

    Handler *handler = new Handler(listen, remote, remotePort, port);
    udp.addRecvCallback(handler);

    static constexpr int MAXLINE = 1024;
    char line[MAXLINE];
    while (fgets(line, MAXLINE, stdin)) {
      int dataLen = strlen(line);
      if (!listen.load()) {
        std::mutex sending;
        INVOKE({
          auto retryCallback = [&] { sending.unlock(); };
          int rc = udp.sendSegment(
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

    INVOKE({ udp.removeRecvCallback(handler); })
    delete handler;
    return 0;
  }
};

class CmdNcUdp : public Command {
  class Handler : public UDP::RecvCallback {
  public:
    Handler(int port_) : UDP::RecvCallback(port_) {}

    int handle(const void *data, int dataLen, const Info &info) override {
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

    if (ip.getSrcAddr(remote, src) < 0) {
      fprintf(stderr, "No IP address on the host\n");
      return 1;
    }

    // Need to assign a port.
    port = 10000 + random() % 50000;

    Handler *handler = new Handler(port);
    udp.addRecvCallback(handler);

    static constexpr int MAXLINE = 1024;
    char line[MAXLINE];
    while (fgets(line, MAXLINE, stdin)) {
      int dataLen = strlen(line);
      std::mutex sending;
      INVOKE({
        auto retryCallback = [&] { sending.unlock(); };
        int rc = udp.sendSegment(
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

    INVOKE({ udp.removeRecvCallback(handler); })
    delete handler;
    return 0;
  };
};

#include "common.h"
#include "commands.h"
#include "ICMP.h"

#include <mutex>
#include <atomic>
#include <random>

class CmdPing : public Command {
  static constexpr int TIMES = 4;

public:
  CmdPing() : Command("ping") {}

  class ICMPHandler : public ICMP::RecvCallback {
  public:
    std::timed_mutex &finish;
    int identifier;
    const char *data;
    // handle ICMP Echo Reply
    ICMPHandler(std::timed_mutex &finish_, int identifier_)
        : ICMP::RecvCallback(0), finish(finish_), identifier(identifier_) {}

    int handle(const void *data, int dataLen, const Info &info) {
      if (ntohs(info.icmpHeader->identifier) == identifier) {
        int seq = ntohs(info.icmpHeader->seqNumber);
        printf("%d bytes from " IP_ADDR_FMT_STRING ": icmp_seq=%d ttl=%d\n",
               dataLen + (int)sizeof(ICMP::Header),
               IP_ADDR_FMT_ARGS(info.header->src), seq,
               info.header->timeToLive);
        if (seq == TIMES)
          finish.unlock();
      }
      return 0;
    }
  };

  int main(int argc, char **argv) override {
    IP::Addr host;
    if (argc != 2 || sscanf(argv[1], IP_ADDR_FMT_STRING,
                            IP_ADDR_FMT_ARGS(&host)) != IP_ADDR_FMT_NUM) {
      fprintf(stderr, "Usage: %s <host>\n", argv[0]);
      return 1;
    }

    using namespace std::chrono_literals;

    IP::Addr src;
    int rc;
    INVOKE({ rc = ns.ip.getSrcAddr(host, src); });
    if (rc < 0) {
      fprintf(stderr, "No IP address on the host.\n");
      return rc;
    }

    int identifier = random() % 0xFFFF;
    const char data[] = "Lab-NetStack Ping Test\n";
    std::timed_mutex finish;
    finish.lock();
    auto *handler = new ICMPHandler(finish, identifier);

    INVOKE({ ns.ip.icmp.addRecvCallback(handler); })

    for (int i = 1; i <= TIMES; i++) {
      printf("Send %d\n", i);
      INVOKE({
        rc = ns.ip.icmp.sendEchoOrReply(src, host, 8, identifier, i, data,
                                        sizeof(data), {.autoRetry = true});
      })
      if (rc != 0 && rc != E_WAIT_FOR_TRYAGAIN) {
        goto END;
      }
      if (i < TIMES)
        std::this_thread::sleep_for(1s);
    }
    if (!finish.try_lock_for(1s)) {
      fprintf(stderr, "Time out.\n");
      rc = 1;
    }
  END:
    INVOKE({ ns.ip.icmp.removeRecvCallback(handler); })
    delete handler;

    return 0;
  }
};

class CmdTraceRoute : public Command {
public:
  CmdTraceRoute() : Command("traceroute") {}

  class ICMPHandler : public ICMP::RecvCallback {
  public:
    std::timed_mutex &idle;
    std::atomic<bool> &finish;
    int identifier;
    // handle ICMP Time Exceeded & Echo Reply
    ICMPHandler(std::timed_mutex &idle_, std::atomic<bool> &finish_,
                int identifier_)
        : ICMP::RecvCallback(-1), idle(idle_), finish(finish_),
          identifier(identifier_) {}

    int handle(const void *data, int dataLen, const Info &info) {
      if (info.icmpHeader->type == 0) {
        // Echo Reply
        if (ntohs(info.icmpHeader->identifier) == identifier) {
          int seq = ntohs(info.icmpHeader->seqNumber);
          printf(IP_ADDR_FMT_STRING "\n", IP_ADDR_FMT_ARGS(info.header->src));
          fflush(stdout);
          finish.store(true);
          idle.unlock();
        }

      } else if (info.icmpHeader->type == 11 && info.icmpHeader->code == 0) {
        // Time Exceeded
        if (dataLen < sizeof(ICMP::Header))
          return 0;
        const auto &echoHeader = (const ICMP::Header *)data;
        if (echoHeader->type != 8 ||
            ntohs(echoHeader->identifier) != identifier) {
          int seq = ntohs(echoHeader->seqNumber);
          printf(IP_ADDR_FMT_STRING "\n", IP_ADDR_FMT_ARGS(info.header->src));
          fflush(stdout);
          idle.unlock();
        }
      }
      return 0;
    }
  };

  int main(int argc, char **argv) override {
    IP::Addr host;
    if (argc != 2 || sscanf(argv[1], IP_ADDR_FMT_STRING,
                            IP_ADDR_FMT_ARGS(&host)) != IP_ADDR_FMT_NUM) {
      fprintf(stderr, "Usage: %s <host>\n", argv[0]);
      return 1;
    }

    using namespace std::chrono_literals;

    IP::Addr src;
    int rc;
    INVOKE({ rc = ns.ip.getSrcAddr(host, src); });
    if (rc < 0) {
      fprintf(stderr, "No IP address on the host.\n");
      return rc;
    }

    static std::random_device rndDev;
    int identifier = rndDev() % 0xFFFF;
    const char data[] = "Lab-NetStack TraceRoute Test\n";
    std::timed_mutex idle;
    std::atomic<bool> finish;
    finish.store(false);
    auto *handler = new ICMPHandler(idle, finish, identifier);

    INVOKE({ ns.ip.icmp.addRecvCallback(handler); })

    constexpr int MAXHOP = 16;
    int err = 3;
    for (int i = 1; i <= MAXHOP; i++) {
      printf("%d ", i);
      fflush(stdout);
      idle.lock();
      INVOKE({
        rc = ns.ip.icmp.sendEchoOrReply(src, host, 8, identifier, i, data,
                                        sizeof(data),
                                        {.timeToLive = (uint8_t)i, .autoRetry = true});
      })

      if (rc != 0 && rc != E_WAIT_FOR_TRYAGAIN)
        break;
      if (!idle.try_lock_for(i * 2s)) {
        printf("*\n");
        fflush(stdout);
        if (--err <= 0)
          break;
      } else if (finish.load()) {
        break;
      }
      idle.unlock();
    }

    INVOKE({ ns.ip.icmp.removeRecvCallback(handler); })
    delete handler;

    return rc;
  }
};

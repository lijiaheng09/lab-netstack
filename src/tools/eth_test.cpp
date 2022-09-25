#include <cstdio>
#include <cstring>
#include <thread>
#include <mutex>
#include <random>

#include <arpa/inet.h>
#include <netinet/ether.h>

#include "netstack.h"

static constexpr int LEN = 128;

struct LongNum {
  u_char v[LEN];
  LongNum() : v{} { }

  LongNum &operator ^=(const LongNum &a) {
    for (int i = 0; i < LEN; i++)
      v[i] ^= a.v[i];
    return *this;
  }

  uint64_t checksum() const {
    uint64_t r = 0;
    for (int i = 0; i < LEN; i++)
      r ^= (uint64_t)v[i] << ((i % 8) * 8);
    return r;
  }
};

LongNum randLongNum(std::mt19937 &rnd) {
  LongNum ret;
  for (int i = 0; i < LEN; i++)
    ret.v[i] = rnd() & 255;
  return ret;
}


const int MAX_DEVS = 128;
int n;
ether_addr dstAddr[MAX_DEVS];
std::thread *sendThreads[MAX_DEVS];

int recvNum[MAX_DEVS];
LongNum sentData[MAX_DEVS], recvData[MAX_DEVS];
std::timed_mutex ready[MAX_DEVS];
std::timed_mutex receiving[MAX_DEVS];

constexpr int ETH_TYPE_EXP1 = 0x88B5;
constexpr int ETH_TYPE_EXP2 = 0x88B6;
constexpr int TIMES = 10000;
constexpr int LOG_TIMES = 1000;

int recvHandler(const void *buf, int len, int id) {
  ether_addr *srcAddrp = (ether_addr *)((char *)buf + ETHER_ADDR_LEN);
  uint16_t *ethtypeNetp = (uint16_t *)((char *)buf + ETHER_ADDR_LEN * 2);
  uint16_t ethtype = ntohs(*ethtypeNetp);
  if (memcmp(srcAddrp, &dstAddr[id], sizeof(ether_addr)) != 0)
    return 0;

  if (ethtype == ETH_TYPE_EXP2) {
    fprintf(stderr, "Remote device %d connected\n", id);
    ready[id].unlock();

  } else if (ethtype == ETH_TYPE_EXP1) {
    if (len < ETHER_HDR_LEN + LEN) {
      fprintf(stderr, "invalid frame of length %d from device %d\n", len, id);
      return 1;
    }
    LongNum x = *(LongNum *)((char *)buf + ETHER_HDR_LEN);
    recvData[id] ^= x;
    if (++recvNum[id] % LOG_TIMES == 0) {
      fprintf(stderr, "device %d recv %d/%d\n", id, recvNum[id], TIMES);
    }
    if (recvNum[id] == TIMES)
      receiving[id].unlock();
  }
  return 0;
}

void sendThreadAction(int i, int seed) {
  using namespace std::chrono_literals;

  static constexpr int HELLO_LEN = 46;
  static const char HELLO_DATA[HELLO_LEN] = "Eth Test";
  static constexpr auto HELLO_TIMEOUT = 1000ms;

  while (!ready[i].try_lock_for(HELLO_TIMEOUT)) {
    sendFrame(HELLO_DATA, HELLO_LEN, ETH_TYPE_EXP2, &dstAddr[i], i);
    fprintf(stderr, "device %d sending HELLO\n", i);
  }
  sendFrame(HELLO_DATA, HELLO_LEN, ETH_TYPE_EXP2, &dstAddr[i], i);
  fprintf(stderr, "device %d sending HELLO\n", i);

  static constexpr auto SENDING_CYCLE = 0.5ms;

  std::mt19937 rnd(seed);
  for (int t = 0; t < TIMES; t++) {
    LongNum x = randLongNum(rnd);
    if (sendFrame(x.v, LEN, ETH_TYPE_EXP1, &dstAddr[i], i) != 0) {
      fprintf(stderr, "Sending error %d:%d\n", i, t);
    } else {
      sentData[i] ^= x;
    }
    if (t % LOG_TIMES == 0) {
      fprintf(stderr, "device %d sent %d/%d\n", i, t, TIMES);
    }
    std::this_thread::sleep_for(SENDING_CYCLE);
  }
}

int main(int argc, char **argv) {
  if (argc == 1 || (argc - 1) % 2 != 0) {
    fprintf(stderr, "usage: %s <device> <dstAddr> [<device> <dstAddr>]...\n", argv[0]);
    return 1;
  }

  for (int i = 1; i < argc; i += 2) {
    int id = addDevice(argv[i]);
    if (id != n) {
      fprintf(stderr, "addDevice %s error\n", argv[i]);
      return 1;
    }
    if (!ether_aton_r(argv[i + 1], &dstAddr[n])) {
      fprintf(stderr, "invalid dstAddr: %s\n", argv[i + 1]);
      return 1;
    }
    n++;
  }

  fprintf(stderr, "Start\n");
  
  for (int i = 0; i < n; i++) {
    ready[i].lock();
    receiving[i].lock();
  }

  setFrameReceiveCallback(recvHandler);

  std::random_device rndDev;
  for (int i = 0; i < n; i++)
    sendThreads[i] = new std::thread(sendThreadAction, i, rndDev());
  
  for (int i = 0; i < n; i++) {
    sendThreads[i]->join();
    delete sendThreads[i];
    fprintf(stderr, "device %d send finish\n", i);
  }

  for (int i = 0; i < n; i++) {
    using namespace std::chrono_literals;
    while (!receiving[i].try_lock_for(1s)) {
      // dangerous, but for diagnostics only
      fprintf(stderr, "device %d recv %d/%d\n", i, recvNum[i], TIMES);
    }
  }
  
  for (int i = 0; i < n; i++) {
    printf("device %d: %s, sent %016lX, recv %016lX\n",
      i, argv[2 * i + 1], sentData[i].checksum(), recvData[i].checksum());
  }

  return 0;
}

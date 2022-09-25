#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

#include <netinet/ether.h>
#include <linux/if_packet.h>

#include <pcap/pcap.h>

#include "netstack.h"

namespace commands {

int findAllDevs(int argc, char **argv) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devices;
  if (pcap_findalldevs(&devices, errbuf) != 0)
    fprintf(stderr, "error\n");
  for (auto *p = devices; p; p = p->next) {
    printf("device %s: %s\n", p->name, p->description);
    for (auto *a = p->addresses; a; a = a->next) {
      if (a->addr->sa_family == AF_PACKET) {
        struct sockaddr_ll *s = (struct sockaddr_ll*)a->addr;
        if (s->sll_hatype == ARPHRD_ETHER) {
          printf("    ether ");
          for (int i = 0; i < s->sll_halen; i++)
            printf("%02X%c", s->sll_addr[i], i + 1 < s->sll_halen ? ':' : '\n');
        }
      }
    }
  }
  pcap_freealldevs(devices);
  return 0;
}

int addDevice(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: addDevice <device>\n");
    return 1;
  }
  int id = ::addDevice(argv[1]);
  if (id == -1) {
    fprintf(stderr, "error\n");
    return 1;
  }
  printf("device added: %d\n", id);
  return 0;
}

int findDevice(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: findDevice <device>\n");
    return 1;
  }
  int id = ::findDevice(argv[1]);
  if (id == -1) {
    printf("device not found\n");
    return 1;
  }
  printf("device found: %d\n", id);
  return 0;
}

int sendFrame(int argc, char **argv) {
  int id, ethtype, padding = 0;
  ether_addr destmac;
  if (argc < 5 ||
      sscanf(argv[1], "%d", &id) != 1 ||
      !ether_aton_r(argv[2], &destmac) ||
      sscanf(argv[3], "0x%x", &ethtype) != 1 ||
      (argc == 6 && sscanf(argv[5], "%d", &padding) != 1) ||
      argc > 6) {
    fprintf(stderr, "usage: sendFrame <id> <destmac> <ethtype-hex> <data> [padding]\n");
    return 1;
  }

  int rLen = strlen(argv[4]);
  int len = rLen + padding;
  char *data = (char *)malloc(len);
  if (!data) {
    fprintf(stderr, "error\n");
    return 1;
  }
  memcpy(data, argv[4], rLen);
  memset(data + rLen, 0, padding);

  int ret = ::sendFrame(data, len, ethtype, &destmac, id);
  free(data);
  
  if (ret != 0) {
    fprintf(stderr, "error\n");
    return 1;
  }
  return 0;
}

int captureRecvCallback(const void *buf, int len, int id) {
  ether_addr *dst = (ether_addr *)buf;
  ether_addr *src = dst + 1;
  uint16_t *ethtypeNetp = (uint16_t *)((char *)buf + ETHER_ADDR_LEN * 2);
  int ethtype = ntohs(*ethtypeNetp);
  printf("Recv length %d from device %d\n", len, id);
  char dstStr[30], srcStr[30];
  ether_ntoa_r(dst, dstStr);
  ether_ntoa_r(src, srcStr);
  printf("    dst %s, src %s, ethtype %02x\n", dstStr, srcStr, ethtype);
  return 0;
}

int setCapture(int argc, char **argv) {
  int ret = ::setFrameReceiveCallback(captureRecvCallback);
  if (ret != 0) {
    fprintf(stderr, "error\n");
    return 1;
  }
  return 0;
}

} // namespace commands

typedef int (*CommandHandler)(int argc, char **argv);

struct Command {
  const char *name;
  CommandHandler handler;
};

Command commandList[] = {
  {"findAllDevs", commands::findAllDevs},
  {"addDevice", commands::addDevice},
  {"findDevice", commands::findDevice},
  {"sendFrame", commands::sendFrame},
  {"setCapture", commands::setCapture}
};

int parseLine(char *line, int &argc, char **argv) {
  char *p = line;
  argc = 1;
  argv[0] = p;
  while ((p = strchr(p, ' '))) {
    *p++ = '\0';
    argv[argc++] = p;
  }
  if (!(p = strchr(argv[argc - 1], '\n')))
    return 1;
  *p = '\0';
  return 0;
}

int main(int argc, char **argv) {
  constexpr int MAX_LINE = 1000;
  char line[MAX_LINE];
  char *iargv[MAX_LINE];

  if (netstackInit() != 0) {
    fprintf(stderr, "initialization error\n");
    return 1;
  }

  bool fileFromArg = false;
  FILE *fp = nullptr;
  if (argc >= 2) {
    fp = fopen(argv[1], "r");
    if (!fp) {
      fprintf(stderr, "error open file\n");
    } else {
      fileFromArg = true;
    }
  }

  while (true) {
    printf("> ");
    fflush(stdout);

    bool fromFile = false;
    if (fp) {
      if (!fgets(line, MAX_LINE, fp)) {
        fclose(fp);
        fp = nullptr;
        if (fileFromArg) {
          printf("exit\n");
          return 0;
        }
      } else {
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(1000ms);
        for (char *p = line; *p && *p != '\n'; p++) {
          putchar(*p);
          fflush(stdout);
        std::this_thread::sleep_for(10ms);
        }
        std::this_thread::sleep_for(1000ms);
        putchar('\n');
        fflush(stdout);
        fromFile = true;
      }
    }

    if (!fromFile) {
      if (!fgets(line, MAX_LINE, stdin)) {
        printf("exit\n");
        return 0;
      }
    }

    if (line[0] == '\n')
      continue;
    if (line[strlen(line) - 1] != '\n') {
      fprintf(stderr, "too long line\n");
      return 1;
    }
    if (line[0] == '!') {
      system(line + 1);
      continue;
    }
    int iargc;
    if (parseLine(line, iargc, iargv))
      return 1;
    
    if (strcmp(iargv[0], "source") == 0) {
      if (iargc != 2) {
        fprintf(stderr, "usage: source <file>\n");
        continue;
      }
      fp = fopen(iargv[1], "r");
      if (!fp) {
        fprintf(stderr, "error open file\n");
        continue;
      }
      continue;
    }

    CommandHandler handler = nullptr;
    for (auto &&c : commandList)
      if (strcmp(c.name, iargv[0]) == 0)
        handler = c.handler;
    if (handler == nullptr)
      fprintf(stderr, "command not found\n");
    else
      handler(iargc, iargv);
  }
  return 0;
}

#include <cstdio>
#include <cstdlib>
#include <cstring>

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
      sscanf(argv[3], "%d", &ethtype) != 1 ||
      (argc == 6 && sscanf(argv[5], "%d", &padding) != 1) ||
      argc > 6) {
    fprintf(stderr, "usage: sendFrame <id> <destmac> <ethtype> <data> [padding]\n");
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

} // namespace commands

typedef int (*command_handler)(int argc, char **argv);

struct command_t {
  const char *name;
  command_handler handler;
};

command_t commandList[] = {
  {"findAllDevs", commands::findAllDevs},
  {"addDevice", commands::addDevice},
  {"findDevice", commands::findDevice},
  {"sendFrame", commands::sendFrame}
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

int main() {
  constexpr int MAX_LINE = 1000;
  char line[MAX_LINE];
  char *argv[MAX_LINE];

  if (netstackInit() != 0) {
    fprintf(stderr, "initialization error\n");
    return 1;
  }

  while (true) {
    printf("> ");
    fflush(stdout);
    if (!fgets(line, MAX_LINE, stdin)) {
      printf("exit\n");
      return 0;
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
    int argc;
    if (parseLine(line, argc, argv))
      return 1;
    command_handler handler = nullptr;
    for (auto &&c : commandList)
      if (strcmp(c.name, argv[0]) == 0)
        handler = c.handler;
    if (handler == nullptr)
      fprintf(stderr, "command not found\n");
    else
      handler(argc, argv);
  }
  return 0;
}

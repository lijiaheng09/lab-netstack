#include <cstdio>
#include <cstring>

#include <pcap/pcap.h>

#include "netstack.h"

namespace commands {

int findAllDevs(int argc, char **argv) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devices;
  if (pcap_findalldevs(&devices, errbuf) != 0)
    fprintf(stderr, "error\n");
  for (auto *p = devices; p; p = p->next)
    printf("device %s: %s\n", p->name, p->description);
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

} // namespace commands

typedef int (*command_handler)(int argc, char **argv);

struct command_t {
  const char *name;
  command_handler handler;
};

command_t commandList[] = {
  {"findAllDevs", commands::findAllDevs},
  {"addDevice", commands::addDevice},
  {"findDevice", commands::findDevice}
};

int parseLine(char *line, int &argc, char **argv) {
  char *p = line;
  argc = 1;
  argv[0] = p;
  while ((p = strchr(p, ' '))) {
    *p++ = '\0';
    argv[argc++] = p;
  }
  if (!(p = strchr(argv[argc - 1], '\n'))) {
    fprintf(stderr, "too long line\n");
    return 1;
  }
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

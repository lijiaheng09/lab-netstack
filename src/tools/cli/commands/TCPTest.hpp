#include "common.h"
#include "commands.h"

#include <cassert>
#include <thread>

class CmdTcpTest : public Command {
public:
  CmdTcpTest() : Command("tcp-test") {}

  int main(int argc, char **argv) override {
    if (argc < 2) {
      fprintf(stderr, "Usage: %s <command> ...", argv[0]);
      return 1;
    }

    if (strcmp(argv[1], "connect") == 0) {
      IP::Addr host;
      uint16_t port;
      if (argc != 4 ||
          sscanf(argv[2], IP_ADDR_FMT_STRING, IP_ADDR_FMT_ARGS(&host)) !=
              IP_ADDR_FMT_NUM ||
          sscanf(argv[3], "%hu", &port) != 1) {
        fprintf(stderr, "Usage: %s %s [host] [port]\n", argv[0], argv[1]);
        return 1;
      }
      TCP::Desc *desc, *connection;
      ns.invoke([&]() {
        desc = ns.tcp.create();
        if (!desc) {
          fprintf(stderr, "Unable to create descriptor\n");
          return;
        }
        connection = ns.tcp.connect(desc, {host, port});
        if (!connection) {
          fprintf(stderr, "Unable to create connection\n");
          return;
        }
        // connection->close();
      });
      puts("Done.");
    }

    return 0;
  }
};

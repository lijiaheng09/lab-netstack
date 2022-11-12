#include "common.h"
#include "commands.h"

#include <cassert>
#include <thread>

class CmdTcpTest : public Command {
public:
  CmdTcpTest() : Command("tcp-test") {}

  void echo(TCP::Connection *connection) {
    static constexpr int BUF_SIZE = 128;
    char buf[BUF_SIZE], buf2[BUF_SIZE * 2];
    while (ssize_t len = connection->awaitRecv(buf, BUF_SIZE)) {
      assert(len > 0);
      fwrite(buf, 1, len, stdout);
      fflush(stdout);

      const char *msg = " !!!Echo back: ";
      memcpy(buf2, msg, strlen(msg));
      memcpy(buf2 + strlen(msg), buf, len);
      connection->asyncSendAll(buf2, strlen(msg) + len);
    }
    connection->awaitClose();
  }

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
        fprintf(stderr, "Usage: %s %s <host> <port>\n", argv[0], argv[1]);
        return 1;
      }
      TCP::Desc *desc;
      TCP::Connection *connection;
      ns.invoke([&]() {
        desc = ns.tcp.create();
        if (!desc) {
          fprintf(stderr, "create error\n");
          return;
        }
        connection = ns.tcp.connect(desc, {host, port});
        if (!connection) {
          fprintf(stderr, "connect error\n");
          return;
        }
        // connection->close();
      });
      if (connection) {
        puts("Connected.");
        echo(connection);
      }
    } else if (strcmp(argv[1], "listen") == 0) {
      uint16_t port;
      if (argc != 3 || sscanf(argv[2], "%hu", &port) != 1) {
        fprintf(stderr, "Usage: %s %s <port>\n", argv[0], argv[1]);
        return 1;
      }
      int rc = 0;
      TCP::Desc *desc;
      TCP::Listener *listener;
      TCP::Connection *connection;
      ns.invoke([&]() {
        desc = ns.tcp.create();
        if (!desc) {
          fprintf(stderr, "create error\n");
          rc = -1;
          return;
        }
        if (desc->bind({{0}, port}) != 0) {
          fprintf(stderr, "bind error\n");
          rc = -1;
          return;
        }
        listener = ns.tcp.listen(desc);
        if (!listener) {
          fprintf(stderr, "listen error\n");
          rc = -1;
          return;
        }
        rc = 0;
      });

      if (rc != 0)
        return 1;
      connection = listener->awaitAccept();
      if (!connection) {
        fprintf(stderr, "accept error\n");
      } else {
        puts("Accepted");
        echo(connection);
      }
      listener->awaitClose();
    } else {
      fprintf(stderr, "Unknown command: %s\n", argv[1]);
    }

    return 0;
  }
};

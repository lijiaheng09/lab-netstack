#include <cerrno>
#include <cstring>
#include <cstdlib>

#include <vector>
#include <thread>

#include <readline/readline.h>
#include <readline/history.h>

#include "nsInstance.h"
#include "commands.h"

NetStackFull ns;

static std::vector<char *> splitLine(char *line) {
  std::vector<char *> args;

  char *p = line;
  while (1) {
    while (isspace(*p))
      p++;
    if (!*p)
      break;
    args.push_back(p);

    while (*p && !isspace(*p))
      p++;
    if (!*p)
      break;
    *p++ = '\0';
  }

  return args;
}

char *completionEntryCmds(const char *text, int state) {
  static std::vector<Command *>::iterator cur;
  static int textLen;
  if (state == 0) {
    cur = allCommands.begin();
    textLen = strlen(text);
  }

  while (cur != allCommands.end()) {
    auto c = cur++;
    if (strncmp((*c)->name, text, textLen) == 0)
      return strdup((*c)->name);
  }
  return nullptr;
}

char **complete(const char *text, int start, int end) {
  char **matches = nullptr;
  if (start == 0)
    matches = rl_completion_matches(text, completionEntryCmds);
  return matches;
}

int executeCommand(std::vector<char *> &args) {
  int rc;
  if (args.empty()) {
    return 0;
  }

  bool found = false;
  for (auto &&c : allCommands)
    if (strcmp(c->name, args[0]) == 0) {
      found = true;
      rc = c->main((int)args.size(), args.data());
    }

  if (!found) {
    fprintf(stderr, "%s: command not found\n", args[0]);
    rc = 127;
  }

  return rc;
}

int main(int argc, char **argv) {
  ns.start();
  if (argc > 2 && argv[1][0] == '-' && argv[1][1] == 'c') {
    std::vector<char *> args(argv + 2, argv + argc);
    int rc = executeCommand(args);
    if (rc == 0 && argv[1][2] == 'w') {
      ns.wait();
      return rc;
    }
    if (argv[1][2] != 'i') {
      ns.stop();
      return rc;
    }
  }

  FILE *fp = nullptr;
  bool interactive = true;
  bool doWait = false;
  if (argc > 2 && argv[1][0] == '-' && argv[1][1] == 'f') {
    fp = fopen(argv[2], "r");
    if (!fp) {
      fprintf(stderr, "open file %s error: %s\n", argv[2], strerror(errno));
      ns.stop();
      return 1;
    }
    if (argv[1][2] != 'i')
      interactive = false;
    if (argv[1][2] == 'w')
      doWait = true;
  }

  rl_attempted_completion_function = complete;

  while (true) {
    char *line = nullptr;
    if (fp) {
      static constexpr int MAX_LINE = 1000;
      static char lineBuf[MAX_LINE];
      if (!fgets(lineBuf, MAX_LINE, fp)) {
        fclose(fp);
        fp = nullptr;
        if (!interactive) {
          break;
        }
      } else {
        if (interactive) {
          using namespace std::chrono_literals;
          printf("> ");
          fflush(stdout);
          std::this_thread::sleep_for(1s);
          fputs(lineBuf, stdout);
          fflush(stdout);
        }
        line = lineBuf;
      }
    }

    if (!line)
      line = readline("> ");
    if (!line) {
      putchar('\n');
      break;
    }
    add_history(line);

    int rc;

    if (line[0] == '!') {
      rc = system(line + 1);

    } else {
      auto args = splitLine(line);
      rc = executeCommand(args);
    }
  }
  if (doWait)
    ns.wait();
  return 0;
}

#include <cstdlib>

#include <vector>

#include <readline/readline.h>
#include <readline/history.h>

#include "netstack.h"
#include "commands.h"

static std::vector<char *> splitLine(char *line) {
  std::vector<char *> args;

  char *p = line;
  while (1) {
    while (isspace(*p))
      p++;
    if (!*p)
      break;
    args.push_back(p);

    p = strchr(p, ' ');
    if (!p)
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

int main(int argc, char **argv) {
  if (int rc = initNetStack()) {
    fprintf(stderr, "NetStack init error.\n");
    return rc;
  }

  rl_attempted_completion_function = complete;

  while (true) {
    char *line = readline("> ");
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
      if (args.empty()) {
        continue;
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
    }
  }
  return 0;
}

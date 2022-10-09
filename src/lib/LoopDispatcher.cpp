#include "LoopDispatcher.h"

int LoopDispatcher::handle() {
  int rc = 0;

  mutexTasks.lock();
  while (!tasks.empty()) {
    Task &t = tasks.front();
    rc = t.f->handle();
    if (t.finished)
      t.finished->unlock();
    tasks.pop();
    if (rc != 0)
      break;
  }
  mutexTasks.unlock();
  return rc;
}

void LoopDispatcher::invoke(LoopCallback *f) {
  auto *finish = new std::mutex();
  finish->lock();
  mutexTasks.lock();
  tasks.push({f, finish});
  mutexTasks.unlock();
  finish->lock();
  delete finish;
}

void LoopDispatcher::beginInvoke(LoopCallback *f) {
  mutexTasks.lock();
  tasks.push({f, nullptr});
  mutexTasks.unlock();
}

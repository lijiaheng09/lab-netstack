#include "Timer.h"

Timer::~Timer() {
  while (!tasks.empty()) {
    delete tasks.top();
    tasks.pop();
  }
}

void Timer::handle() {
  auto curTime = Clock::now();
  while (!tasks.empty() && curTime >= tasks.top()->expireTime) {
    auto *p = tasks.top();
    tasks.pop();
    if (!removed.empty() && removed.top() == p)
      removed.pop();
    else
      p->handler();
    delete p;
  }
}

Timer::Task *Timer::add(Handler handler, Duration duration) {
  auto *task =
      new Task{.expireTime = Clock::now() + duration, .handler = handler};
  tasks.push(task);
  return task;
}

void Timer::remove(Task *task) {
  removed.push(task);
}

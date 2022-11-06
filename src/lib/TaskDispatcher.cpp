#include "TaskDispatcher.h"

void TaskDispatcher::handle() {
  int rc = 0;

  std::queue<Task> curTasks;
  mutexTasks.lock();
  curTasks.swap(tasks);
  mutexTasks.unlock();

  while (!curTasks.empty()) {
    curTasks.front()();
    curTasks.pop();
  }
}

void TaskDispatcher::invoke(Task task) {
  std::mutex finish;
  mutexTasks.lock();
  finish.lock();
  tasks.push([task, &finish]() {
    task();
    finish.unlock();
  });
  mutexTasks.unlock();
  finish.lock();
}

void TaskDispatcher::beginInvoke(Task task) {
  mutexTasks.lock();
  tasks.push(task);
  mutexTasks.unlock();
}

#ifndef NETSTACK_TASK_DISPATCHER_H
#define NETSTACK_TASK_DISPATCHER_H

#include <functional>
#include <mutex>

#include "utils.h"

/**
 * @brief Dispatcher of tasks (from other thread).
 */
class TaskDispatcher {
public:
  using Task = std::function<void()>;

  /**
   * @brief Handle the queued tasks.
   */
  void handle();

  /**
   * @brief Invoke a task (from other thread) and wait for return.
   *
   * @param task The task to be invoked.
   */
  void invoke(Task task);

  /**
   * @brief Begin to invoke a task (from other thread) and continue.
   *
   * @param task The task to be invoked.
   */
  void beginInvoke(Task task);

private:
  std::mutex mutexTasks;
  std::queue<Task> tasks;
};

#endif

#ifndef NETSTACK_TASK_DISPATCHER_H
#define NETSTACK_TASK_DISPATCHER_H

#include <mutex>
#include <queue>

/**
 * @brief Callback in the main loop.
 */
class LoopCallback {
public:
  /**
   * @brief Handle the callback.
   *
   * @return 0 on normal, negative on error, positive to break the loop.
   */
  virtual int handle() = 0;

  /**
   * @brief Wrap a copy-constructible callable object into an `LoopCallback`
   * object.
   *
   * @tparam TFunc Type of the copy-constructible callable object.
   * @param f The callee object.
   * @return The wrapped `LoopCallback` object.
   */
  template <typename TFunc> static auto wrap(TFunc f) {
    class Wrap : public LoopCallback {
    public:
      TFunc f;
      Wrap(TFunc f_) : f(f_) {}
      int handle() override {
        return f();
      }
    };

    return Wrap(f);
  }
};

/**
 * @brief Dispatcher of actions (from other thread).
 */
class LoopDispatcher : public LoopCallback {
  struct Task {
    LoopCallback *f;
    std::mutex *finished;
  };

  std::mutex mutexTasks;
  std::queue<Task> tasks;

public:
  int handle() override;

  /**
   * @brief Invoke an callback (from other thread) in the loop and wait for
   * return.
   *
   * @param f Pointer to the callback to be invoked.
   */
  void invoke(LoopCallback *f);

  /**
   * @brief Begin to invoke an callback (from other thread) in the loop and
   * continue.
   *
   * @param f Pointer the callback to be invoked (which need to be persistent
   * before the callback returns).
   */
  void beginInvoke(LoopCallback *f);
};

#endif

#ifndef NETSTACK_TIMER_H
#define NETSTACK_TIMER_H

#include <chrono>
#include <queue>
#include <functional>

using namespace std::literals::chrono_literals;

class Timer {
public:
  using Clock = std::chrono::system_clock;
  using Duration = Clock::duration;
  using TimePoint = Clock::time_point;

  using Handler = std::function<void()>;

  struct Task {
    const TimePoint expireTime;
    const Handler handler;
  };

  ~Timer();

  /**
   * @brief Handle currently expired events.
   */
  void handle();

  /**
   * @brief Add a timer.
   *
   * @param handler The expiration handler.
   * @param duration The time to expire from now.
   * @return The added task handler.
   */
  Task *add(Handler handler, Duration duration);

  /**
   * @brief Remove a timer (must be valid now).
   *
   * @param task The task handler returned by `add`.
   */
  void remove(Task *task);

private:
  class Cmp {
  public:
    bool operator()(Task *a, Task *b) const {
      return a->expireTime != b->expireTime ? a->expireTime > b->expireTime
                                            : a > b;
    }
  };

  using PriorityQueue = std::priority_queue<Task *, std::vector<Task *>, Cmp>;
  PriorityQueue tasks, removed;
};

#endif

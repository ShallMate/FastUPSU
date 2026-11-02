#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <future>
#include <thread>
#include <utility>
#include <vector>

namespace upsu {

int intraop_default_num_threads();
int get_num_threads();
void set_num_threads(int count);
void pin_benchmark_thread(int rank, bool offline = false);
bool experiment_phase_threads_enabled();
void set_experiment_phase(bool offline, const char* stage);

template <typename Fn>
void parallel_for(int64_t begin, int64_t end, int64_t grain, Fn&& fn) {
  if (end <= begin) return;
  const int threads = std::max(1, get_num_threads());
  const int64_t count = end - begin;
  const int64_t chunk = std::max<int64_t>(grain, (count + threads - 1) / threads);
  if (threads == 1 || count <= chunk) {
    fn(begin, end);
    return;
  }
  std::vector<std::future<void>> work;
  for (int64_t first = begin; first < end; first += chunk) {
    const int64_t last = std::min(end, first + chunk);
    work.emplace_back(std::async(std::launch::async, [&, first, last] {
      fn(first, last);
    }));
  }
  for (auto& task : work) task.get();
}

template <typename Fn>
void parallel_for(int64_t begin, int64_t end, Fn&& fn) {
  parallel_for(begin, end, 1, std::forward<Fn>(fn));
}

template <typename T, typename Fn, typename Reduce>
T parallel_reduce(int64_t begin, int64_t end, int64_t grain, Fn&& fn,
                  Reduce&& reduce) {
  if (end <= begin) return T{};
  const int threads = std::max(1, get_num_threads());
  const int64_t count = end - begin;
  const int64_t chunk = std::max<int64_t>(grain, (count + threads - 1) / threads);
  if (threads == 1 || count <= chunk) return fn(begin, end);
  std::vector<std::future<T>> work;
  for (int64_t first = begin; first < end; first += chunk) {
    const int64_t last = std::min(end, first + chunk);
    work.emplace_back(std::async(std::launch::async, [&, first, last] {
      return fn(first, last);
    }));
  }
  T result = work.front().get();
  for (size_t i = 1; i < work.size(); ++i) result = reduce(result, work[i].get());
  return result;
}

}  // namespace upsu

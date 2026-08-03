#include "upsu/parallel.h"

#include <stdexcept>

namespace upsu {
namespace {
std::atomic<int> g_thread_count{
    static_cast<int>(std::max(1u, std::thread::hardware_concurrency()))};
}

int intraop_default_num_threads() { return g_thread_count.load(); }
int get_num_threads() { return g_thread_count.load(); }
void set_num_threads(int count) {
  if (count <= 0) throw std::invalid_argument("thread count must be positive");
  g_thread_count.store(count);
}
}  // namespace upsu

#include "upsu/parallel.h"

#include <stdexcept>
#include <cstdlib>
#include <cerrno>
#include <dirent.h>
#include <sched.h>
#include <sstream>
#include <cstring>
#include <iostream>
#include <unistd.h>

namespace upsu {
namespace {
std::atomic<int> g_thread_count{
    static_cast<int>(std::max(1u, std::thread::hardware_concurrency()))};

void WriteResourceRecord(const std::string& record) {
  // A single short write keeps the attestation intact even when unrelated
  // tracing code writes to stderr without sharing a logging mutex.
  if (record.size() >= 4096) throw std::runtime_error("resource record too long");
  ssize_t written;
  do {
    written = write(STDERR_FILENO, record.data(), record.size());
  } while (written < 0 && errno == EINTR);
  if (written != static_cast<ssize_t>(record.size()))
    throw std::runtime_error("cannot write complete resource attestation");
}
}

int intraop_default_num_threads() { return g_thread_count.load(); }
int get_num_threads() { return g_thread_count.load(); }
void pin_benchmark_thread(int rank, bool offline) {
  const char* value=std::getenv(rank==0 ? "PSU_BENCH_CPU0" : "PSU_BENCH_CPU1");
  if(!value) return;
  const int cpu=std::stoi(value);
  if(cpu<0 || cpu>=CPU_SETSIZE) throw std::invalid_argument("invalid benchmark CPU");
  cpu_set_t cpus;
  CPU_ZERO(&cpus);
  const int count = experiment_phase_threads_enabled() && offline ? 8 : 1;
  if (cpu + count > CPU_SETSIZE) throw std::invalid_argument("invalid benchmark CPU range");
  for (int i = 0; i < count; ++i) CPU_SET(cpu+i,&cpus);
  if(sched_setaffinity(0,sizeof(cpus),&cpus)!=0)
    throw std::runtime_error("cannot pin benchmark worker");
  if (experiment_phase_threads_enabled()) {
    cpu_set_t actual;
    CPU_ZERO(&actual);
    if (sched_getaffinity(0,sizeof(actual),&actual)!=0 || !CPU_EQUAL(&actual,&cpus))
      throw std::runtime_error("benchmark worker affinity mismatch");
    if (get_num_threads() != count) throw std::runtime_error("benchmark phase thread count mismatch");
    std::ostringstream record;
    record << "[primitive_resource_phase] " << (offline ? "offline" : "online")
              << " rank=" << rank << " threads=" << count << " first_cpu=" << cpu
              << " affinity_verified=yes\n";
    WriteResourceRecord(record.str());
  }
}
void set_num_threads(int count) {
  if (count <= 0) throw std::invalid_argument("thread count must be positive");
  const char* affinity = std::getenv(count == 1 ? "PSU_ONLINE_CPU" : "PSU_OFFLINE_CPUS");
  if (affinity && *affinity) {
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    std::istringstream input(affinity);
    std::string entry;
    while (std::getline(input, entry, ',')) {
      const int cpu = std::stoi(entry);
      if (cpu < 0 || cpu >= CPU_SETSIZE) throw std::invalid_argument("invalid CPU");
      CPU_SET(cpu, &cpus);
    }
    DIR* tasks = opendir("/proc/self/task");
    if (!tasks) throw std::runtime_error("cannot inspect process threads");
    while (auto* task = readdir(tasks)) {
      if (task->d_name[0] == '.') continue;
      if (sched_setaffinity(std::stoi(task->d_name), sizeof(cpus), &cpus) != 0 && errno != ESRCH) {
        closedir(tasks);
        throw std::runtime_error("cannot apply experiment CPU affinity");
      }
    }
    closedir(tasks);
  }
  g_thread_count.store(count);
}

bool experiment_phase_threads_enabled() {
  const char* enabled = std::getenv("PSU_PHASE_THREADS_V1");
  return enabled && std::strcmp(enabled, "1") == 0;
}

void set_experiment_phase(bool offline, const char* stage) {
  if (!experiment_phase_threads_enabled()) return;
  const char* count_value = std::getenv(offline ? "PSU_OFFLINE_THREADS" : "PSU_ONLINE_THREADS");
  if (!count_value) throw std::runtime_error("missing experiment phase thread count");
  const int count = std::stoi(count_value);
  if (count != (offline ? 8 : 1)) throw std::runtime_error("invalid experiment phase thread count");
  set_num_threads(count);
  cpu_set_t expected;
  CPU_ZERO(&expected);
  const char* cpus = std::getenv(offline ? "PSU_OFFLINE_CPUS" : "PSU_ONLINE_CPU");
  if (!cpus) throw std::runtime_error("missing experiment phase CPUs");
  std::istringstream input(cpus);
  std::string entry;
  while (std::getline(input, entry, ',')) {
    const int cpu = std::stoi(entry);
    if (cpu < 0 || cpu >= CPU_SETSIZE) throw std::runtime_error("invalid experiment phase CPU");
    CPU_SET(cpu, &expected);
  }
  if (CPU_COUNT(&expected) != count) throw std::runtime_error("experiment phase CPU count mismatch");
  DIR* tasks = opendir("/proc/self/task");
  if (!tasks) throw std::runtime_error("cannot verify process affinity");
  while (auto* task = readdir(tasks)) {
    if (task->d_name[0] == '.') continue;
    cpu_set_t actual;
    CPU_ZERO(&actual);
    if (sched_getaffinity(std::stoi(task->d_name), sizeof(actual), &actual) != 0) {
      if (errno == ESRCH) continue;
      closedir(tasks);
      throw std::runtime_error("cannot read process affinity");
    }
    if (!CPU_EQUAL(&expected, &actual)) {
      closedir(tasks);
      throw std::runtime_error("experiment phase task affinity mismatch");
    }
  }
  closedir(tasks);
  std::ostringstream record;
  record << "[resource_phase] " << (offline ? "offline" : "online")
            << " threads=" << count << " cpus=" << cpus << " stage=" << stage
            << " all_tasks_verified=yes\n";
  WriteResourceRecord(record.str());
}
}  // namespace upsu

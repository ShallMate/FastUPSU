#pragma once

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

namespace psu::debug {

inline bool Enabled() {
  static const bool enabled = [] {
    const char* env = std::getenv("PSU_DEBUG");
    if (env == nullptr) {
      return false;
    }
    const std::string value(env);
    return value == "1" || value == "true" || value == "TRUE" ||
           value == "on" || value == "ON";
  }();
  return enabled;
}

inline uint64_t ElapsedMs() {
  static const auto start = std::chrono::steady_clock::now();
  const auto now = std::chrono::steady_clock::now();
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(now - start)
          .count());
}

inline void Log(const std::string& message) {
  if (!Enabled()) {
    return;
  }
  static std::mutex mu;
  std::lock_guard<std::mutex> lock(mu);
  std::cerr << "[psu][debug][t+" << ElapsedMs() << "ms] " << message
            << std::endl;
}

inline void LogKv(const std::string& scope, const std::string& message) {
  if (!Enabled()) {
    return;
  }
  std::ostringstream oss;
  oss << scope;
  if (!message.empty()) {
    oss << " " << message;
  }
  Log(oss.str());
}

}

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fmt/format.h>

namespace upsu {

using uint128_t = unsigned __int128;

inline uint128_t MakeUint128(uint64_t high, uint64_t low) {
  return (static_cast<uint128_t>(high) << 64) | low;
}

inline uint64_t Uint128High64(uint128_t value) {
  return static_cast<uint64_t>(value >> 64);
}

inline uint64_t Uint128Low64(uint128_t value) {
  return static_cast<uint64_t>(value);
}

inline std::pair<uint64_t, uint64_t> DecomposeUInt128(uint128_t value) {
  return {Uint128High64(value), Uint128Low64(value)};
}

using ByteView = std::span<const std::byte>;

inline ByteView Bytes(const void* data, size_t size) {
  return {static_cast<const std::byte*>(data), size};
}

inline ByteView Bytes(std::string_view value) {
  return Bytes(value.data(), value.size());
}

uint64_t SecureRandU64();
void FillRand(void* data, size_t size);
std::vector<uint8_t> RandBits(size_t bit_count);

template <typename T>
std::vector<T> RandVec(size_t count, bool /*secure*/ = true) {
  std::vector<T> result(count);
  if (!result.empty()) {
    FillRand(result.data(), result.size() * sizeof(T));
  }
  return result;
}

uint128_t Hash128(ByteView input);

class Hash256 {
 public:
  Hash256();
  ~Hash256();
  Hash256(const Hash256&) = delete;
  Hash256& operator=(const Hash256&) = delete;

  void Update(ByteView input);
  void Update(std::string_view input) { Update(Bytes(input)); }
  std::array<uint8_t, 32> Final();

 private:
  struct Impl;
  Impl* impl_;
};

}  // namespace upsu

using uint128_t = upsu::uint128_t;

#define UPSU_ENFORCE(condition, ...)                                      \
  do {                                                                    \
    if (!(condition)) {                                                   \
      throw std::runtime_error(fmt::format(__VA_ARGS__));                 \
    }                                                                     \
  } while (false)

#define UPSU_THROW(...) throw std::runtime_error(fmt::format(__VA_ARGS__))

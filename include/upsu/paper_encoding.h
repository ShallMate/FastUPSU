#pragma once

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>
#include "upsu/common.h"
#include "upsu/input_encoding.h"

namespace psu::paper {

// Hash the full encoding. Rejection gives an ordered sample without replacement.
inline std::array<size_t, 3> CandidateBins(uint128_t encoding, size_t m) {
  UPSU_ENFORCE(m >= 3, "three-choice hashing requires at least three bins");
  std::array<size_t, 3> bins{};
  std::array<unsigned char, 32> input{};
  std::memcpy(input.data(), "UPSU-bins-v3", 12);
  for (size_t i = 0; i < 16; ++i) input[12 + i] = static_cast<unsigned char>(encoding >> (8 * i));
  const uint64_t threshold = -static_cast<uint64_t>(m) % m;
  size_t count = 0;
  for (uint32_t counter = 0; count != bins.size(); ++counter) {
    for (size_t i = 0; i < 4; ++i) input[28 + i] = static_cast<unsigned char>(counter >> (8 * i));
    const auto digest = psu::encoding::Blake3Digest(upsu::Bytes(input.data(), input.size()));
    for (size_t offset = 0; offset < digest.size() && count != bins.size(); offset += 8) {
      uint64_t word = 0;
      for (size_t i = 0; i < 8; ++i) word |= uint64_t{digest[offset + i]} << (8 * i);
      if (word < threshold) continue;
      const size_t bin = word % m;
      if (std::find(bins.begin(), bins.begin() + count, bin) == bins.begin() + count) bins[count++] = bin;
    }
  }
  return bins;
}

inline void RequireDistinctEncodings(const std::vector<uint128_t>& encodings) {
  auto sorted = encodings;
  std::sort(sorted.begin(), sorted.end());
  UPSU_ENFORCE(std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end(),
               "local 128-bit input encoding collision");
}

// A buffered cryptographic sampler for receiver padding and dummy coordinates.
class FieldSampler {
 public:
  uint64_t operator()(uint64_t modulus) {
    const uint64_t threshold = -modulus % modulus;
    for (;;) {
      if (offset_ == words_.size()) {
        upsu::FillRand(words_.data(), sizeof(words_));
        offset_ = 0;
      }
      const uint64_t word = words_[offset_++];
      if (word >= threshold) return word % modulus;
    }
  }
 private:
  std::array<uint64_t, 256> words_{};
  size_t offset_ = words_.size();
};

}  // namespace psu::paper

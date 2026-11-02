#pragma once

#include <cstdlib>
#include <cstring>
#include <immintrin.h>
#include "seal/util/uintarithsmallmod.h"

namespace psu::paper {

inline bool Avx512Available() {
  static const bool available = __builtin_cpu_supports("avx512f") &&
      __builtin_cpu_supports("avx512dq") && __builtin_cpu_supports("avx512ifma");
  return available;
}

inline bool Avx512Enabled() {
  const char* enabled = std::getenv("PSU_USE_AVX512");
  return enabled && std::strcmp(enabled, "1") == 0 && Avx512Available();
}

__attribute__((target("avx512f,avx512dq,avx512ifma")))
inline __m512i MulHigh64(__m512i a, __m512i b) {
  const auto zero = _mm512_setzero_si512();
  const auto ah = _mm512_srli_epi64(a, 52);
  const auto bh = _mm512_srli_epi64(b, 52);
  auto low = _mm512_madd52hi_epu64(zero, a, b);
  low = _mm512_madd52lo_epu64(low, a, bh);
  low = _mm512_madd52lo_epu64(low, ah, b);
  auto high = _mm512_madd52hi_epu64(zero, a, bh);
  high = _mm512_madd52hi_epu64(high, ah, b);
  high = _mm512_madd52lo_epu64(high, ah, bh);
  return _mm512_add_epi64(_mm512_srli_epi64(low, 12), _mm512_slli_epi64(high, 40));
}

__attribute__((target("avx512f,avx512dq,avx512ifma")))
inline void AccumulateShoupAvx512(const uint64_t* a, const uint64_t* b,
                                  const uint32_t* correction, uint64_t* result,
                                  size_t n, const seal::Modulus& modulus, bool first) {
  const auto q = _mm512_set1_epi64(modulus.value());
  const unsigned shift = 64 - modulus.bit_count();
  const auto shift_count = _mm_cvtsi32_si128(shift);
  size_t i = 0;
  for (; i + 8 <= n; i += 8) {
    const auto x = _mm512_loadu_si512(a + i);
    const auto y = _mm512_loadu_si512(b + i);
    const auto delta = _mm512_cvtepu32_epi64(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(correction + i)));
    const auto quotient = _mm512_add_epi64(_mm512_sll_epi64(y, shift_count), delta);
    const auto high = MulHigh64(x, quotient);
    auto product = _mm512_sub_epi64(_mm512_mullo_epi64(x, y), _mm512_mullo_epi64(high, q));
    if (!first) product = _mm512_add_epi64(product, _mm512_loadu_si512(result + i));
    _mm512_storeu_si512(result + i, product);
  }
  for (; i < n; ++i) {
    const seal::util::MultiplyUIntModOperand y{b[i], (b[i] << shift) + correction[i]};
    const uint64_t product = seal::util::multiply_uint_mod_lazy(a[i], y, modulus);
    result[i] = first ? product : result[i] + product;
  }
}

__attribute__((target("avx512f")))
inline size_t Mul65537Avx512(uint32_t* power, const uint32_t* base, size_t n) {
  const auto zero = _mm512_setzero_si512();
  const auto mask = _mm512_set1_epi64(65535);
  const auto q = _mm512_set1_epi64(65537);
  size_t i = 0;
  for (; i + 16 <= n; i += 16) {
    const auto a = _mm512_loadu_si512(power + i);
    const auto b = _mm512_loadu_si512(base + i);
    const auto even = _mm512_mul_epu32(a, b);
    const auto odd = _mm512_mul_epu32(_mm512_srli_epi64(a, 32), _mm512_srli_epi64(b, 32));
    auto e = _mm512_sub_epi64(_mm512_and_si512(even, mask), _mm512_srli_epi64(even, 16));
    auto o = _mm512_sub_epi64(_mm512_and_si512(odd, mask), _mm512_srli_epi64(odd, 16));
    e = _mm512_mask_add_epi64(e, _mm512_cmp_epi64_mask(e, zero, _MM_CMPINT_LT), e, q);
    o = _mm512_mask_add_epi64(o, _mm512_cmp_epi64_mask(o, zero, _MM_CMPINT_LT), o, q);
    _mm512_storeu_si512(power + i, _mm512_or_si512(e, _mm512_slli_epi64(o, 32)));
  }
  return i;
}

}  // namespace psu::paper

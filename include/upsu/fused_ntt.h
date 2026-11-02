#pragma once

#include <array>
#include <span>
#include <vector>
#include "seal/seal.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/uintarithsmallmod.h"
#include "upsu/common.h"
#include "upsu/simd_modular.h"

namespace psu::paper {

struct NttProduct {
  const seal::Ciphertext* ciphertext;
  const seal::Plaintext* plaintext;
  const std::vector<uint32_t>* quotients = nullptr;
};

inline std::vector<uint32_t> NttQuotients(const seal::Plaintext& plain,
                                         const seal::SEALContext& context) {
  const auto data = context.get_context_data(plain.parms_id());
  UPSU_ENFORCE(data && plain.is_ntt_form(), "precomputed multiplier needs NTT plaintext");
  const auto& moduli = data->parms().coeff_modulus();
  const size_t n = data->parms().poly_modulus_degree();
  // For primes close to 2^b, store the exact correction to operand << (64-b).
  for (const auto& modulus : moduli) {
    const unsigned bits = modulus.bit_count();
    if (bits <= 32 || bits >= 64) return {};
    const uint64_t gap = (uint64_t{1} << bits) - modulus.value();
    if (gap > (uint64_t{UINT32_MAX} >> (64 - bits))) return {};
  }
  std::vector<uint32_t> result(n * moduli.size());
  for (size_t limb = 0; limb < moduli.size(); ++limb) {
    for (size_t j = 0; j < n; ++j) {
      seal::util::MultiplyUIntModOperand operand;
      operand.set(plain[limb * n + j], moduli[limb]);
      const uint64_t base = operand.operand << (64 - moduli[limb].bit_count());
      const uint64_t correction = operand.quotient - base;
      UPSU_ENFORCE(correction <= UINT32_MAX, "multiplier correction overflow");
      result[limb * n + j] = static_cast<uint32_t>(correction);
    }
  }
  return result;
}

// Exact NTT dot product using SEAL's accelerated limb kernels and one reusable
// scratch limb, avoiding a complete temporary ciphertext for every term.
inline bool FusedNttDot(std::span<const NttProduct> terms,
                        const seal::SEALContext& context,
                        seal::Ciphertext& result) {
  if (terms.empty()) return false;
  const auto& prototype = *terms.front().ciphertext;
  const auto data = context.get_context_data(prototype.parms_id());
  UPSU_ENFORCE(data && prototype.is_ntt_form(), "NTT accumulation needs a valid NTT ciphertext");
  const auto& moduli = data->parms().coeff_modulus();
  const size_t n = prototype.poly_modulus_degree();
  const size_t components = prototype.size();
  for (const auto& term : terms) {
    UPSU_ENFORCE(term.ciphertext->parms_id() == prototype.parms_id() &&
        term.ciphertext->is_ntt_form() && term.ciphertext->size() == components &&
        term.plaintext->is_ntt_form() && term.plaintext->parms_id() == prototype.parms_id() &&
        term.plaintext->coeff_count() == n * moduli.size(), "incompatible NTT dot-product input");
  }
  bool precomputed = terms.size() >= 16 && moduli.front().bit_count() > 52;
  for (const auto& term : terms)
    precomputed &= term.quotients && term.quotients->size() == n * moduli.size();
  for (const auto& modulus : moduli)
    precomputed &= terms.size() <= UINT64_MAX / (2 * modulus.value());
  if (precomputed) {
    const bool use_avx512 = Avx512Enabled();
    result = prototype;
    for (size_t t = 0; t < terms.size(); ++t) {
      const auto& term = terms[t];
      for (size_t component = 0; component < components; ++component) {
        for (size_t limb = 0; limb < moduli.size(); ++limb) {
          const auto* a = term.ciphertext->data(component) + limb * n;
          const auto* b = term.plaintext->data() + limb * n;
          const auto* quotient = term.quotients->data() + limb * n;
          auto* destination = result.data(component) + limb * n;
          if (use_avx512) {
            AccumulateShoupAvx512(a, b, quotient, destination, n, moduli[limb], t == 0);
            continue;
          }
          for (size_t j = 0; j < n; ++j) {
            const seal::util::MultiplyUIntModOperand operand{
                b[j], (b[j] << (64 - moduli[limb].bit_count())) + quotient[j]};
            const uint64_t product = seal::util::multiply_uint_mod_lazy(a[j], operand, moduli[limb]);
            destination[j] = t ? destination[j] + product : product;
          }
        }
      }
    }
    for (size_t component = 0; component < components; ++component)
      for (size_t limb = 0; limb < moduli.size(); ++limb) {
        auto* destination = result.data(component) + limb * n;
        for (size_t j = 0; j < n; ++j)
          destination[j] = seal::util::barrett_reduce_64(destination[j], moduli[limb]);
      }
    return true;
  }
  result = prototype;
  std::vector<uint64_t> scratch(n);
  for (size_t t = 0; t < terms.size(); ++t) {
    const auto& term = terms[t];
    for (size_t component = 0; component < components; ++component) {
      for (size_t limb = 0; limb < moduli.size(); ++limb) {
        const auto* a = term.ciphertext->data(component) + limb * n;
        const auto* b = term.plaintext->data() + limb * n;
        auto* destination = result.data(component) + limb * n;
        if (t == 0) {
          seal::util::dyadic_product_coeffmod(a, b, n, moduli[limb], destination);
        } else {
          seal::util::dyadic_product_coeffmod(a, b, n, moduli[limb], scratch.data());
          seal::util::add_poly_coeffmod(destination, scratch.data(), n, moduli[limb], destination);
        }
      }
    }
  }
  return true;
}

}  // namespace psu::paper

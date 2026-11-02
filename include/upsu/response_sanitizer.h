#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <seal/seal.h>

namespace psu {

// One-time preprocessing token for a single packed BFV response.
struct ResponseMaskToken {
  // The sender's PEQT input under the protocol's existing sign convention.
  std::vector<std::uint64_t> additive_mask;

  // Standard Enc(mask) with an independently sampled smudging polynomial
  // already added to c0.
  seal::Ciphertext masked_ciphertext;

  bool consumed = false;

  ResponseMaskToken() = default;
  ResponseMaskToken(ResponseMaskToken&&) noexcept = default;
  ResponseMaskToken& operator=(ResponseMaskToken&&) noexcept = default;
  ResponseMaskToken(const ResponseMaskToken&) = delete;
  ResponseMaskToken& operator=(const ResponseMaskToken&) = delete;
};

// Samples unbiased field elements with the standalone cryptographic RNG.
std::vector<std::uint64_t> SampleResponseMask(std::size_t count,
                                              std::uint64_t modulus);

// Adds one centered-uniform signed integer per polynomial coefficient to c0.
// Each signed sample is reduced consistently into every RNS limb.
void AddSmudgingNoiseToC0(const seal::SEALContext& context,
                          seal::Ciphertext& ciphertext, std::size_t flood_bits);

ResponseMaskToken PrepareResponseMask(
    const seal::SEALContext& context, const seal::Encryptor& encryptor,
    const seal::Evaluator& evaluator, seal::BatchEncoder& encoder,
    seal::parms_id_type sanitize_parms_id, std::size_t flood_bits,
    std::span<const std::uint64_t> mask_slots,
    seal::MemoryPoolHandle pool = seal::MemoryManager::GetPool());

seal::parms_id_type SelectResponseParmsId(const seal::SEALContext& context,
                                          seal::parms_id_type sanitize_parms_id,
                                          std::size_t mod_switch_steps);

// Consumes token, computes Eval + Enc(mask) + (F, 0), and applies the fixed
// final modulus switch.
void ApplyResponseMask(
    seal::Ciphertext& evaluated, ResponseMaskToken&& token,
    seal::parms_id_type response_parms_id, const seal::SEALContext& context,
    const seal::Evaluator& evaluator,
    seal::MemoryPoolHandle pool = seal::MemoryManager::GetPool());

}  // namespace psu

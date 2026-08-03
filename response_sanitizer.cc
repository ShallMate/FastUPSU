#include "response_sanitizer.h"

#include "upsu/common.h"

#include <limits>
#include <stdexcept>

#include "seal/util/uintarithsmallmod.h"

namespace psu {

namespace {

using uint128_t = unsigned __int128;

std::uint64_t LowBitsMask(std::size_t bit_count) {
  const std::size_t remainder = bit_count % 64;
  return remainder == 0 ? std::numeric_limits<std::uint64_t>::max()
                        : (std::uint64_t{1} << remainder) - 1;
}

bool IsAllOnes(const std::uint64_t* words, std::size_t word_count,
               std::size_t bit_count) {
  for (std::size_t idx = 0; idx + 1 < word_count; ++idx) {
    if (words[idx] != std::numeric_limits<std::uint64_t>::max()) {
      return false;
    }
  }
  return words[word_count - 1] == LowBitsMask(bit_count);
}

std::uint64_t ReduceLowBits(const std::uint64_t* words, std::size_t bit_count,
                            std::uint64_t modulus) {
  const std::size_t word_count = (bit_count + 63) / 64;
  std::uint64_t residue = 0;
  for (std::size_t idx = word_count; idx-- > 0;) {
    std::uint64_t word = words[idx];
    if (idx + 1 == word_count) {
      word &= LowBitsMask(bit_count);
    }
    residue = static_cast<std::uint64_t>(
        ((static_cast<uint128_t>(residue) << 64) | word) % modulus);
  }
  return residue;
}

std::uint64_t FloodBoundResidue(std::size_t flood_bits, std::uint64_t modulus) {
  const std::size_t word_count = (flood_bits + 63) / 64;
  std::uint64_t residue = 0;
  for (std::size_t idx = word_count; idx-- > 0;) {
    std::uint64_t word = std::numeric_limits<std::uint64_t>::max();
    if (idx + 1 == word_count) {
      word = LowBitsMask(flood_bits);
    }
    residue = static_cast<std::uint64_t>(
        ((static_cast<uint128_t>(residue) << 64) | word) % modulus);
  }
  return residue;
}

void RefillCenteredSample(std::uint64_t* words, std::size_t word_count,
                          std::size_t sample_bits) {
  do {
    upsu::FillRand(words, word_count * sizeof(std::uint64_t));
    words[word_count - 1] &= LowBitsMask(sample_bits);
  } while (IsAllOnes(words, word_count, sample_bits));
}

}  // namespace

std::vector<std::uint64_t> SampleResponseMask(std::size_t count,
                                              std::uint64_t modulus) {
  if (modulus < 2) {
    throw std::invalid_argument("response-mask modulus must exceed one");
  }

  std::vector<std::uint64_t> mask(count);
  const std::uint64_t limit =
      std::numeric_limits<std::uint64_t>::max() -
      (std::numeric_limits<std::uint64_t>::max() % modulus);
  if (!mask.empty()) {
    upsu::FillRand(mask.data(), mask.size() * sizeof(std::uint64_t));
  }
  for (auto& value : mask) {
    while (value >= limit) {
      value = upsu::SecureRandU64();
    }
    value %= modulus;
  }
  return mask;
}

void AddSmudgingNoiseToC0(const seal::SEALContext& context,
                          seal::Ciphertext& ciphertext,
                          std::size_t flood_bits) {
  if (ciphertext.is_ntt_form()) {
    throw std::invalid_argument(
        "smudging requires a coefficient-form BFV ciphertext");
  }
  if (ciphertext.size() < 2) {
    throw std::invalid_argument("smudging requires a non-empty ciphertext");
  }

  const auto context_data = context.get_context_data(ciphertext.parms_id());
  if (!context_data) {
    throw std::invalid_argument("ciphertext has an invalid parms_id");
  }
  const auto& parms = context_data->parms();
  if (parms.scheme() != seal::scheme_type::bfv) {
    throw std::invalid_argument("smudging requires BFV parameters");
  }

  const int coeff_modulus_bits = context_data->total_coeff_modulus_bit_count();
  if (coeff_modulus_bits < 3 || flood_bits == 0 ||
      flood_bits > static_cast<std::size_t>(coeff_modulus_bits - 2)) {
    throw std::invalid_argument(
        "flood_bits must keep the public smudging bound below Q/2");
  }

  const auto& coeff_modulus = parms.coeff_modulus();
  const std::size_t coeff_count = parms.poly_modulus_degree();
  const std::size_t rns_limb_count = coeff_modulus.size();
  if (ciphertext.poly_modulus_degree() != coeff_count ||
      ciphertext.coeff_modulus_size() != rns_limb_count) {
    throw std::invalid_argument(
        "ciphertext shape does not match its BFV context data");
  }

  // B = 2^flood_bits - 1. Sampling x uniformly from [0, 2B] and
  // returning x-B gives the exact centered-uniform distribution [-B, B].
  const std::size_t sample_bits = flood_bits + 1;
  const std::size_t sample_word_count = (sample_bits + 63) / 64;
  if (coeff_count >
      std::numeric_limits<std::size_t>::max() / sample_word_count) {
    throw std::length_error("smudging sample buffer is too large");
  }
  std::vector<std::uint64_t> samples(coeff_count * sample_word_count);
  upsu::FillRand(samples.data(), samples.size() * sizeof(std::uint64_t));

  std::vector<std::uint64_t> bound_residues(rns_limb_count);
  for (std::size_t limb_idx = 0; limb_idx < rns_limb_count; ++limb_idx) {
    bound_residues[limb_idx] =
        FloodBoundResidue(flood_bits, coeff_modulus[limb_idx].value());
  }

  std::uint64_t* c0 = ciphertext.data(0);
  for (std::size_t coeff_idx = 0; coeff_idx < coeff_count; ++coeff_idx) {
    std::uint64_t* sample = samples.data() + coeff_idx * sample_word_count;
    sample[sample_word_count - 1] &= LowBitsMask(sample_bits);
    if (IsAllOnes(sample, sample_word_count, sample_bits)) {
      RefillCenteredSample(sample, sample_word_count, sample_bits);
    }

    const bool positive =
        ((sample[flood_bits / 64] >> (flood_bits % 64)) & 1U) != 0;
    for (std::size_t limb_idx = 0; limb_idx < rns_limb_count; ++limb_idx) {
      const auto& modulus = coeff_modulus[limb_idx];
      const std::uint64_t modulus_value = modulus.value();
      const std::uint64_t low_residue =
          ReduceLowBits(sample, flood_bits, modulus_value);

      std::uint64_t signed_residue;
      if (positive) {
        signed_residue = low_residue + 1;
        if (signed_residue == modulus_value) {
          signed_residue = 0;
        }
      } else {
        const std::uint64_t bound_residue = bound_residues[limb_idx];
        signed_residue = low_residue >= bound_residue
                             ? low_residue - bound_residue
                             : modulus_value - (bound_residue - low_residue);
      }

      std::uint64_t& destination = c0[limb_idx * coeff_count + coeff_idx];
      destination =
          seal::util::add_uint_mod(destination, signed_residue, modulus);
    }
  }
}

ResponseMaskToken PrepareResponseMask(
    const seal::SEALContext& context, const seal::Encryptor& encryptor,
    const seal::Evaluator& evaluator, seal::BatchEncoder& encoder,
    seal::parms_id_type sanitize_parms_id, std::size_t flood_bits,
    std::span<const std::uint64_t> mask_slots, seal::MemoryPoolHandle pool) {
  const auto context_data = context.get_context_data(sanitize_parms_id);
  if (!context_data) {
    throw std::invalid_argument("invalid response sanitization parms_id");
  }
  if (context_data->parms().scheme() != seal::scheme_type::bfv) {
    throw std::invalid_argument("response sanitization requires BFV");
  }
  if (mask_slots.size() > encoder.slot_count()) {
    throw std::invalid_argument("response mask exceeds BFV slot count");
  }
  if (!pool) {
    throw std::invalid_argument("response-mask memory pool is uninitialized");
  }

  ResponseMaskToken token;
  token.additive_mask.assign(mask_slots.begin(), mask_slots.end());

  std::vector<std::uint64_t> padded_slots(encoder.slot_count(), 0);
  const std::uint64_t plain_modulus =
      context_data->parms().plain_modulus().value();
  for (std::size_t idx = 0; idx < mask_slots.size(); ++idx) {
    if (mask_slots[idx] >= plain_modulus) {
      throw std::invalid_argument(
          "response mask element is outside the plaintext field");
    }
    padded_slots[idx] = mask_slots[idx];
  }

  seal::Plaintext mask_plaintext;
  encoder.encode(padded_slots, mask_plaintext);
  encryptor.encrypt_zero(sanitize_parms_id, token.masked_ciphertext, pool);
  evaluator.add_plain_inplace(token.masked_ciphertext, mask_plaintext, pool);
  AddSmudgingNoiseToC0(context, token.masked_ciphertext, flood_bits);
  return token;
}

seal::parms_id_type SelectResponseParmsId(const seal::SEALContext& context,
                                          seal::parms_id_type sanitize_parms_id,
                                          std::size_t mod_switch_steps) {
  auto context_data = context.get_context_data(sanitize_parms_id);
  if (!context_data) {
    throw std::invalid_argument("invalid response sanitization parms_id");
  }
  for (std::size_t step = 0;
       step < mod_switch_steps && context_data->next_context_data(); ++step) {
    context_data = context_data->next_context_data();
  }
  return context_data->parms_id();
}

void ApplyResponseMask(seal::Ciphertext& evaluated, ResponseMaskToken&& token,
                       seal::parms_id_type response_parms_id,
                       const seal::SEALContext& context,
                       const seal::Evaluator& evaluator,
                       seal::MemoryPoolHandle pool) {
  if (token.consumed || token.masked_ciphertext.size() == 0) {
    throw std::invalid_argument("response mask token was already consumed");
  }
  if (evaluated.parms_id() != token.masked_ciphertext.parms_id()) {
    throw std::invalid_argument(
        "evaluated ciphertext and response mask use different levels");
  }
  if (evaluated.is_ntt_form() != token.masked_ciphertext.is_ntt_form()) {
    throw std::invalid_argument(
        "evaluated ciphertext and response mask use different forms");
  }
  const auto current_data = context.get_context_data(evaluated.parms_id());
  const auto response_data = context.get_context_data(response_parms_id);
  if (!current_data || !response_data ||
      current_data->chain_index() < response_data->chain_index()) {
    throw std::invalid_argument("invalid final response modulus level");
  }
  if (!pool) {
    throw std::invalid_argument(
        "response-sanitization memory pool is uninitialized");
  }

  evaluator.add_inplace(evaluated, token.masked_ciphertext);
  if (evaluated.parms_id() != response_parms_id) {
    evaluator.mod_switch_to_inplace(evaluated, response_parms_id, pool);
  }

  token.masked_ciphertext.release();
  token.additive_mask.clear();
  token.consumed = true;
}

}  // namespace psu

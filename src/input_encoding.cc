#include "upsu/input_encoding.h"
#include "upsu/parallel.h"
#include <blake3.h>

namespace psu::encoding {
Salt FreshSalt() {
  Salt salt{};
  upsu::FillRand(salt.data(), salt.size());
  return salt;
}

std::array<uint8_t, 32> Blake3Digest(upsu::ByteView input) {
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, input.data(), input.size());
  std::array<uint8_t, 32> out{};
  blake3_hasher_finalize(&hasher, out.data(), out.size());
  return out;
}

uint128_t Hash(const Salt& salt, std::string_view item) {
  // Fixed domain, 16-byte salt, LE64 byte length, then the raw item bytes.
  constexpr char domain[] = "FastUPSU/input-encoding/20261102";
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, domain, sizeof(domain) - 1);
  blake3_hasher_update(&hasher, salt.data(), salt.size());
  std::array<uint8_t, 8> length{};
  for (size_t i = 0; i < length.size(); ++i) length[i] = static_cast<uint8_t>(uint64_t{item.size()} >> (8 * i));
  blake3_hasher_update(&hasher, length.data(), length.size());
  blake3_hasher_update(&hasher, item.data(), item.size());
  std::array<uint8_t, 16> out{};
  blake3_hasher_finalize(&hasher, out.data(), out.size());
  uint128_t value = 0;
  for (size_t i = 0; i < out.size(); ++i) value |= uint128_t{out[i]} << (8 * i);
  return value;
}

std::vector<uint128_t> Encode(const Salt& salt,
                             const std::vector<std::string>& items) {
  std::vector<uint128_t> encodings(items.size());
  upsu::parallel_for(0, static_cast<int64_t>(items.size()), [&](int64_t first, int64_t last) {
    for (int64_t i = first; i < last; ++i) encodings[i] = Hash(salt, items[i]);
  });
  return encodings;
}
}  // namespace psu::encoding

#include "upsu/common.h"

#include <memory>
#include <algorithm>
#include <climits>
#include <cstring>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace upsu {

void FillRand(void* data, size_t size) {
  if (size == 0) return;
  UPSU_ENFORCE(size <= static_cast<size_t>(INT_MAX),
               "random request is too large: {}", size);
  UPSU_ENFORCE(RAND_bytes(static_cast<unsigned char*>(data),
                          static_cast<int>(size)) == 1,
               "OpenSSL RAND_bytes failed");
}

uint64_t SecureRandU64() {
  uint64_t value = 0;
  FillRand(&value, sizeof(value));
  return value;
}

std::vector<uint8_t> RandBits(size_t bit_count) {
  std::vector<uint8_t> bits(bit_count);
  size_t offset = 0;
  while (offset < bit_count) {
    uint64_t word = SecureRandU64();
    const size_t take = std::min<size_t>(64, bit_count - offset);
    for (size_t i = 0; i < take; ++i) bits[offset + i] = (word >> i) & 1U;
    offset += take;
  }
  return bits;
}

uint128_t Hash128(ByteView input) {
  std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
  unsigned int digest_size = 0;
  UPSU_ENFORCE(EVP_Digest(input.data(), input.size(), digest.data(),
                          &digest_size, EVP_sha256(), nullptr) == 1,
               "SHA-256 failed");
  UPSU_ENFORCE(digest_size >= 16, "unexpected SHA-256 digest size");
  uint128_t result = 0;
  std::memcpy(&result, digest.data(), sizeof(result));
  return result;
}

struct Hash256::Impl {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
};

Hash256::Hash256() : impl_(new Impl) {
  UPSU_ENFORCE(impl_->ctx != nullptr, "failed to allocate SHA-256 context");
  UPSU_ENFORCE(EVP_DigestInit_ex(impl_->ctx, EVP_sha256(), nullptr) == 1,
               "failed to initialize SHA-256");
}

Hash256::~Hash256() {
  if (impl_) {
    EVP_MD_CTX_free(impl_->ctx);
    delete impl_;
  }
}

void Hash256::Update(ByteView input) {
  UPSU_ENFORCE(EVP_DigestUpdate(impl_->ctx, input.data(), input.size()) == 1,
               "SHA-256 update failed");
}

std::array<uint8_t, 32> Hash256::Final() {
  std::array<uint8_t, 32> result{};
  unsigned int size = 0;
  UPSU_ENFORCE(EVP_DigestFinal_ex(impl_->ctx, result.data(), &size) == 1,
               "SHA-256 finalization failed");
  UPSU_ENFORCE(size == result.size(), "unexpected SHA-256 digest size");
  return result;
}

}  // namespace upsu

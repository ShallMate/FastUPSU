#include "dh_oprf.h"

#include <algorithm>
#include <cstring>
#include <numeric>
#include <random>

#include <openssl/sha.h>
#include <sodium.h>

#include "upsu/parallel.h"

namespace psu {
namespace {
constexpr char kItemCountTag[] = "PSU:oprf_n";
constexpr char kMaskedPointsTag[] = "PSU:oprf_masked";
constexpr char kReturnedPointsTag[] = "PSU:oprf_returned";

void EnsureSodium() {
  static const int initialized = sodium_init();
  UPSU_ENFORCE(initialized >= 0, "libsodium initialization failed");
}
}  // namespace

DhOprf::DhOprf() {
  EnsureSodium();
  crypto_core_ristretto255_scalar_random(secret_key_.data());
}

DhOprf::Point DhOprf::HashAndMask(const std::string& item) const {
  std::array<uint8_t, crypto_core_ristretto255_HASHBYTES> uniform{};
  SHA512(reinterpret_cast<const unsigned char*>(item.data()), item.size(),
         uniform.data());
  Point point{};
  Point result{};
  UPSU_ENFORCE(crypto_core_ristretto255_from_hash(point.data(), uniform.data()) == 0,
               "Ristretto hash-to-group failed");
  UPSU_ENFORCE(crypto_scalarmult_ristretto255(result.data(), secret_key_.data(),
                                              point.data()) == 0,
               "Ristretto scalar multiplication failed");
  return result;
}

DhOprf::Point DhOprf::Mask(const Point& point) const {
  Point result{};
  UPSU_ENFORCE(crypto_scalarmult_ristretto255(result.data(), secret_key_.data(),
                                              point.data()) == 0,
               "Ristretto scalar multiplication failed");
  return result;
}

DhOprf::Point DhOprf::Unmask(const Point& point) const {
  std::array<uint8_t, 32> inverse{};
  crypto_core_ristretto255_scalar_invert(inverse.data(), secret_key_.data());
  Point result{};
  UPSU_ENFORCE(crypto_scalarmult_ristretto255(result.data(), inverse.data(),
                                              point.data()) == 0,
               "Ristretto inverse scalar multiplication failed");
  sodium_memzero(inverse.data(), inverse.size());
  return result;
}

uint128_t DhOprf::PointToHash(const Point& point) const {
  return upsu::Hash128(upsu::Bytes(point.data(), point.size()));
}

DhOprf::Point DhOprf::DeserializePoint(upsu::ByteView bytes) const {
  UPSU_ENFORCE(bytes.size() == GetPointSize(), "invalid Ristretto point size");
  Point point{};
  std::memcpy(point.data(), bytes.data(), point.size());
  UPSU_ENFORCE(crypto_core_ristretto255_is_valid_point(point.data()) == 1,
               "invalid Ristretto point encoding");
  return point;
}

void DhOprf::DeserializeSecretKey(std::string_view bytes) {
  EnsureSodium();
  UPSU_ENFORCE(bytes.size() == secret_key_.size(), "invalid OPRF secret-key size");
  std::memcpy(secret_key_.data(), bytes.data(), secret_key_.size());
  std::array<uint8_t, 32> zero{};
  UPSU_ENFORCE(sodium_memcmp(secret_key_.data(), zero.data(), zero.size()) != 0,
               "OPRF secret key must be nonzero");
}

std::vector<uint128_t> ComputeSenderOprf(
    const DhOprf& sender_oprf, const std::vector<std::string>& sender_items) {
  std::vector<uint128_t> result(sender_items.size());
  upsu::parallel_for(0, sender_items.size(), [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i)
      result[i] = sender_oprf.PointToHash(sender_oprf.HashAndMask(sender_items[i]));
  });
  return result;
}

void RunDhOprfSenderOnline(const std::shared_ptr<upsu::net::Context>& ctx,
                           const DhOprf& sender_oprf, bool shuffle_outputs) {
  auto count_buffer = ctx->Recv(ctx->PrevRank(), kItemCountTag);
  UPSU_ENFORCE(count_buffer.size() == sizeof(size_t), "invalid OPRF item count");
  size_t count = 0;
  std::memcpy(&count, count_buffer.data(), sizeof(count));
  auto input = ctx->Recv(ctx->PrevRank(), kMaskedPointsTag);
  UPSU_ENFORCE(input.size() == count * DhOprf::GetPointSize(),
               "invalid OPRF point payload size");

  std::vector<DhOprf::Point> output(count);
  upsu::parallel_for(0, count, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      auto point = sender_oprf.DeserializePoint(
          upsu::Bytes(input.data() + i * DhOprf::GetPointSize(),
                      DhOprf::GetPointSize()));
      output[i] = sender_oprf.Mask(point);
    }
  });
  if (shuffle_outputs) {
    std::mt19937_64 generator(upsu::SecureRandU64());
    std::shuffle(output.begin(), output.end(), generator);
  }
  std::vector<uint8_t> serialized(count * DhOprf::GetPointSize());
  for (size_t i = 0; i < count; ++i)
    std::memcpy(serialized.data() + i * DhOprf::GetPointSize(), output[i].data(),
                DhOprf::GetPointSize());
  ctx->SendAsync(ctx->NextRank(), upsu::Bytes(serialized.data(), serialized.size()),
                 kReturnedPointsTag);
}

std::vector<uint128_t> RunDhOprfReceiver(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::vector<std::string>& receiver_items) {
  DhOprf receiver_oprf;
  const size_t count = receiver_items.size();
  std::vector<uint8_t> serialized(count * DhOprf::GetPointSize());
  upsu::parallel_for(0, count, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      auto point = receiver_oprf.HashAndMask(receiver_items[i]);
      std::memcpy(serialized.data() + i * DhOprf::GetPointSize(), point.data(),
                  DhOprf::GetPointSize());
    }
  });
  ctx->Send(ctx->NextRank(), upsu::Bytes(&count, sizeof(count)), kItemCountTag);
  ctx->SendAsync(ctx->NextRank(), upsu::Bytes(serialized.data(), serialized.size()),
                 kMaskedPointsTag);
  auto returned = ctx->Recv(ctx->PrevRank(), kReturnedPointsTag);
  UPSU_ENFORCE(returned.size() == serialized.size(), "invalid returned OPRF payload");
  std::vector<uint128_t> result(count);
  upsu::parallel_for(0, count, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      auto point = receiver_oprf.DeserializePoint(
          upsu::Bytes(returned.data() + i * DhOprf::GetPointSize(),
                      DhOprf::GetPointSize()));
      result[i] = receiver_oprf.PointToHash(receiver_oprf.Unmask(point));
    }
  });
  return result;
}

}  // namespace psu

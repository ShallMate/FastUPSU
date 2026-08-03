#pragma once

#include <array>
#include <memory>
#include <string>
#include <vector>

#include "upsu/common.h"
#include "upsu/net/context.h"

namespace psu {

class DhOprf {
 public:
  using Point = std::array<uint8_t, 32>;

  DhOprf();
  Point HashAndMask(const std::string& item) const;
  Point Mask(const Point& point) const;
  Point Unmask(const Point& point) const;
  uint128_t PointToHash(const Point& point) const;
  static constexpr size_t GetPointSize() { return 32; }

  std::vector<uint8_t> SerializePoint(const Point& point) const {
    return {point.begin(), point.end()};
  }
  Point DeserializePoint(upsu::ByteView bytes) const;
  std::vector<uint8_t> SerializeSecretKey() const {
    return {secret_key_.begin(), secret_key_.end()};
  }
  void DeserializeSecretKey(std::string_view bytes);

 private:
  std::array<uint8_t, 32> secret_key_{};
};

std::vector<uint128_t> ComputeSenderOprf(
    const DhOprf& sender_oprf, const std::vector<std::string>& sender_items);
void RunDhOprfSenderOnline(const std::shared_ptr<upsu::net::Context>& ctx,
                           const DhOprf& sender_oprf,
                           bool shuffle_outputs = false);
std::vector<uint128_t> RunDhOprfReceiver(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::vector<std::string>& receiver_items);

}  // namespace psu

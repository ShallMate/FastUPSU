#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace upsu {

class PowersDag {
 public:
  struct PowersNode {
    uint32_t power = 0;
    uint32_t depth = 0;
    std::pair<uint32_t, uint32_t> parents{0, 0};
    bool is_source() const { return parents.first == 0 && parents.second == 0; }
  };

  bool configure(std::set<uint32_t> source_powers,
                 std::set<uint32_t> target_powers);
  bool is_configured() const { return configured_; }
  std::set<uint32_t> target_powers() const;
  uint32_t depth() const;
  uint32_t source_count() const;
  std::vector<PowersNode> source_nodes() const;
  std::string to_dot() const;

  template <typename Fn>
  void apply(Fn&& fn) const {
    if (!configured_) throw std::logic_error("PowersDag is not configured");
    for (uint32_t power : target_powers_) fn(nodes_.at(power));
  }

 private:
  std::map<uint32_t, PowersNode> nodes_;
  std::set<uint32_t> target_powers_;
  uint32_t depth_ = 0;
  uint32_t source_count_ = 0;
  bool configured_ = false;
};

std::vector<uint64_t> NewtonInterpolate(const std::vector<uint64_t>& points,
                                        const std::vector<uint64_t>& values,
                                        uint64_t modulus);

}  // namespace upsu

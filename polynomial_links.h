
#pragma once

#include "upsu/common.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>


namespace psu {


inline uint64_t EvalPoly(const std::vector<uint64_t>& coeffs, uint64_t x,
                         uint64_t prime) {
  if (coeffs.empty()) return 0;
  uint64_t result = 0;
  for (size_t i = coeffs.size(); i-- > 0;) {
    __uint128_t tmp = (__uint128_t)result * x + coeffs[i];
    result = (uint64_t)(tmp % prime);
  }
  return result;
}

std::vector<uint64_t> BuildStandardPoly(const std::vector<uint64_t>& roots,
                                        uint64_t prime);

std::vector<uint64_t> InterpolatePoly(const std::vector<uint64_t>& points,
                                      const std::vector<uint64_t>& values,
                                      uint64_t prime);

std::vector<uint64_t> SliceItem(uint128_t item, size_t ks, size_t sigma2_bits);

uint128_t UnsliceItem(const std::vector<uint64_t>& slices, size_t sigma2_bits);

struct PolyLinkSubBin {
  std::vector<std::vector<uint64_t>> poly_coeffs;
  size_t ks;
};

PolyLinkSubBin BuildPolyLinkSubBin(const std::vector<uint128_t>& items, size_t ks,
                         size_t sigma2_bits, uint64_t prime,
                         bool drop_first_poly = false);

bool PolyLinkCheck(const std::vector<uint64_t>& y_slices, const PolyLinkSubBin& sub_bin,
              uint64_t prime, bool drop_first_poly = false);

size_t EstimatePolyLinkStorageBytes(const PolyLinkSubBin& sub_bin);

}

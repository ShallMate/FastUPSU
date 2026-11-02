#pragma once

#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <NTL/lzz_p.h>
#include <NTL/lzz_pX.h>
#include "polynomial_links.h"

namespace psu::small_field {

inline bool Enabled() {
  const char* value = std::getenv("PSU_SMALL_FIELD_POLYS");
  return value && std::strcmp(value, "1") == 0;
}

using Field = NTL::zz_p;
using Polynomial = NTL::zz_pX;

inline const NTL::zz_pContext& ModulusContext(size_t count) {
  const char* native_fft = std::getenv("PSU_NATIVE_FIELD_FFT");
  if (count >= 512 && native_fft && std::strcmp(native_fft, "1") == 0) {
    // 65537 supports length-65536 transforms. The checked <=2048-point
    // product/remainder trees need far smaller transforms, without auxiliary CRT primes.
    static thread_local const NTL::zz_pContext fft(NTL::INIT_USER_FFT, 65537);
    return fft;
  }
  static thread_local const NTL::zz_pContext standard(65537);
  return standard;
}

struct ProductNode {
  size_t begin = 0;
  size_t end = 0;
  size_t left = 0;
  size_t right = 0;
  Polynomial polynomial;
  bool leaf() const { return end == begin + 1; }
};

inline size_t BuildTree(const std::vector<Field>& points, size_t begin,
                        size_t end, std::vector<ProductNode>& nodes) {
  const size_t index = nodes.size();
  nodes.emplace_back();
  nodes[index].begin = begin;
  nodes[index].end = end;
  if (end == begin + 1) {
    NTL::SetCoeff(nodes[index].polynomial, 0, -points[begin]);
    NTL::SetCoeff(nodes[index].polynomial, 1, Field(1));
  } else {
    const size_t middle = begin + (end - begin) / 2;
    const size_t left = BuildTree(points, begin, middle, nodes);
    const size_t right = BuildTree(points, middle, end, nodes);
    nodes[index].left = left;
    nodes[index].right = right;
    nodes[index].polynomial = nodes[left].polynomial * nodes[right].polynomial;
  }
  return index;
}

inline void EvaluateTree(const std::vector<ProductNode>& nodes, size_t index,
                         const Polynomial& polynomial, std::vector<Field>& values) {
  const auto& node = nodes[index];
  if (node.leaf()) {
    values[node.begin] = NTL::coeff(polynomial, 0);
    return;
  }
  Polynomial left, right;
  NTL::rem(left, polynomial, nodes[node.left].polynomial);
  NTL::rem(right, polynomial, nodes[node.right].polynomial);
  EvaluateTree(nodes, node.left, left, values);
  EvaluateTree(nodes, node.right, right, values);
}

inline std::vector<uint64_t> Coefficients(const Polynomial& polynomial) {
  const long degree = NTL::deg(polynomial);
  if (degree < 0) return {0};
  std::vector<uint64_t> result(static_cast<size_t>(degree) + 1);
  for (long i = 0; i <= degree; ++i)
    result[static_cast<size_t>(i)] = static_cast<uint64_t>(NTL::rep(NTL::coeff(polynomial, i)));
  return result;
}

// The same product-tree / remainder-tree interpolation over F_65537 as the
// arbitrary-precision path. A thread-local context avoids rebuilding the modulus
// data for every sub-bin. No modulus, anchors, coefficients or padding change.
inline PolyLinkSubBin Build(const std::vector<uint128_t>& items, size_t ks,
                            size_t slice_bits, bool drop_first_poly) {
  constexpr uint64_t prime = 65537;
  NTL::zz_pPush scope(ModulusContext(items.size()));
  PolyLinkSubBin result;
  result.ks = ks;
  result.poly_coeffs.resize(ks);
  const size_t count = items.size();
  if (count == 0) {
    result.poly_coeffs[0] = {1};
    for (size_t i = 1; i < ks; ++i) result.poly_coeffs[i] = {0};
    return result;
  }
  std::vector<std::vector<Field>> slices(ks, std::vector<Field>(count));
  for (size_t j = 0; j < count; ++j) {
    const auto row = SliceItem(items[j], ks, slice_bits);
    for (size_t i = 0; i < ks; ++i)
      slices[i][j] = NTL::conv<Field>(static_cast<long>(row[i] % prime));
  }
  std::vector<ProductNode> nodes;
  nodes.reserve(2 * count - 1);
  BuildTree(slices[0], 0, count, nodes);
  if (!drop_first_poly) result.poly_coeffs[0] = Coefficients(nodes[0].polynomial);
  Polynomial derivative;
  NTL::diff(derivative, nodes[0].polynomial);
  std::vector<Field> denominators(count), prefixes(count);
  EvaluateTree(nodes, 0, derivative, denominators);

  // Montgomery's batch-inversion trick: one inversion and O(count) field
  // multiplications, retaining the original duplicate-anchor rejection.
  Field product(1);
  for (size_t j = 0; j < count; ++j) {
    if (NTL::IsZero(denominators[j]))
      throw std::invalid_argument("duplicate first slice detected in fast PolyLinks interpolation");
    prefixes[j] = product;
    product *= denominators[j];
  }
  Field inverse_product = NTL::inv(product);
  for (size_t j = count; j-- > 0;) {
    const Field inverse = inverse_product * prefixes[j];
    inverse_product *= denominators[j];
    for (size_t i = 1; i < ks; ++i) slices[i][j] *= inverse;
  }
  for (size_t i = 1; i < ks; ++i) {
    std::vector<Polynomial> partial(nodes.size());
    // Children follow their parent in the flat tree, so reverse order is bottom-up.
    for (size_t index = nodes.size(); index-- > 0;) {
      const auto& node = nodes[index];
      if (node.leaf()) {
        NTL::SetCoeff(partial[index], 0, slices[i][node.begin]);
      } else {
        partial[index] = partial[node.left] * nodes[node.right].polynomial +
                         partial[node.right] * nodes[node.left].polynomial;
      }
    }
    result.poly_coeffs[i] = Coefficients(partial[0]);
  }
  return result;
}

}  // namespace psu::small_field

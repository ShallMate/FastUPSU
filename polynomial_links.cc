
#include "polynomial_links.h"
#include "small_field_polynomials.h"

#include <cassert>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>

namespace psu {

namespace {

struct ProductTreeNode {
  size_t begin = 0;
  size_t end = 0;
  NTL::ZZ_pX poly;
  std::unique_ptr<ProductTreeNode> left;
  std::unique_ptr<ProductTreeNode> right;

  bool IsLeaf() const { return end == begin + 1; }
};

NTL::ZZ ToNtlPrime(uint64_t prime) {
  return NTL::conv<NTL::ZZ>(prime);
}

std::vector<NTL::ZZ_p> ToZpValues(const std::vector<uint64_t>& values) {
  std::vector<NTL::ZZ_p> out(values.size());
  for (size_t i = 0; i < values.size(); ++i) {
    out[i] = NTL::conv<NTL::ZZ_p>(NTL::conv<NTL::ZZ>(values[i]));
  }
  return out;
}

std::vector<uint64_t> ToCoeffVector(const NTL::ZZ_pX& poly) {
  const long degree = NTL::deg(poly);
  if (degree < 0) {
    return {0};
  }
  std::vector<uint64_t> coeffs(static_cast<size_t>(degree) + 1, 0);
  for (long i = 0; i <= degree; ++i) {
    coeffs[static_cast<size_t>(i)] =
        static_cast<uint64_t>(NTL::conv<unsigned long>(NTL::rep(NTL::coeff(poly, i))));
  }
  return coeffs;
}

std::unique_ptr<ProductTreeNode> BuildProductTree(
    const std::vector<NTL::ZZ_p>& points, size_t begin, size_t end) {
  auto node = std::make_unique<ProductTreeNode>();
  node->begin = begin;
  node->end = end;
  if (end == begin + 1) {
    NTL::SetCoeff(node->poly, 0, -points[begin]);
    NTL::SetCoeff(node->poly, 1, NTL::ZZ_p(1));
    return node;
  }

  const size_t mid = begin + (end - begin) / 2;
  node->left = BuildProductTree(points, begin, mid);
  node->right = BuildProductTree(points, mid, end);
  node->poly = node->left->poly * node->right->poly;
  return node;
}

void EvaluateOnTree(const ProductTreeNode& node, const NTL::ZZ_pX& poly,
                    std::vector<NTL::ZZ_p>* values) {
  if (node.IsLeaf()) {
    (*values)[node.begin] =
        (NTL::deg(poly) >= 0) ? NTL::coeff(poly, 0) : NTL::ZZ_p(0);
    return;
  }

  NTL::ZZ_pX left_rem;
  NTL::ZZ_pX right_rem;
  rem(left_rem, poly, node.left->poly);
  rem(right_rem, poly, node.right->poly);
  EvaluateOnTree(*node.left, left_rem, values);
  EvaluateOnTree(*node.right, right_rem, values);
}

NTL::ZZ_pX BuildInterpolantFromScaledValues(
    const ProductTreeNode& node, const std::vector<NTL::ZZ_p>& scaled_values) {
  if (node.IsLeaf()) {
    NTL::ZZ_pX constant;
    NTL::SetCoeff(constant, 0, scaled_values[node.begin]);
    return constant;
  }

  NTL::ZZ_pX left_poly =
      BuildInterpolantFromScaledValues(*node.left, scaled_values);
  NTL::ZZ_pX right_poly =
      BuildInterpolantFromScaledValues(*node.right, scaled_values);
  return left_poly * node.right->poly + right_poly * node.left->poly;
}

std::vector<NTL::ZZ_pX> BuildInterpolantsFromScaledValues(
    const ProductTreeNode& node,
    const std::vector<std::vector<NTL::ZZ_p>>& scaled_values_list) {
  if (scaled_values_list.empty()) {
    return {};
  }
  if (node.IsLeaf()) {
    std::vector<NTL::ZZ_pX> constants(scaled_values_list.size());
    for (size_t i = 0; i < scaled_values_list.size(); ++i) {
      NTL::SetCoeff(constants[i], 0, scaled_values_list[i][node.begin]);
    }
    return constants;
  }

  auto left_polys =
      BuildInterpolantsFromScaledValues(*node.left, scaled_values_list);
  auto right_polys =
      BuildInterpolantsFromScaledValues(*node.right, scaled_values_list);

  std::vector<NTL::ZZ_pX> polys(scaled_values_list.size());
  for (size_t i = 0; i < scaled_values_list.size(); ++i) {
    polys[i] =
        left_polys[i] * node.right->poly + right_polys[i] * node.left->poly;
  }
  return polys;
}

std::vector<uint64_t> BuildFastStandardPoly(const std::vector<uint64_t>& roots,
                                            uint64_t prime) {
  if (roots.empty()) {
    return {1};
  }
  NTL::ZZ_p::init(ToNtlPrime(prime));
  auto points = ToZpValues(roots);
  auto tree = BuildProductTree(points, 0, points.size());
  return ToCoeffVector(tree->poly);
}

std::vector<uint64_t> BuildFastInterpolationPoly(
    const std::vector<uint64_t>& points_u64,
    const std::vector<uint64_t>& values_u64, uint64_t prime) {
  if (points_u64.size() != values_u64.size()) {
    throw std::invalid_argument("points and values must have same size");
  }
  if (points_u64.empty()) {
    return {};
  }

  NTL::ZZ_p::init(ToNtlPrime(prime));
  auto points = ToZpValues(points_u64);
  auto values = ToZpValues(values_u64);
  auto tree = BuildProductTree(points, 0, points.size());

  NTL::ZZ_pX derivative;
  diff(derivative, tree->poly);
  std::vector<NTL::ZZ_p> derivative_values(points.size());
  EvaluateOnTree(*tree, derivative, &derivative_values);

  std::vector<NTL::ZZ_p> scaled_values(points.size());
  for (size_t i = 0; i < points.size(); ++i) {
    if (IsZero(derivative_values[i])) {
      throw std::invalid_argument(
          "duplicate interpolation point detected in fast interpolation");
    }
    scaled_values[i] = values[i] / derivative_values[i];
  }

  return ToCoeffVector(BuildInterpolantFromScaledValues(*tree, scaled_values));
}

}


std::vector<uint64_t> BuildStandardPoly(const std::vector<uint64_t>& roots,
                                        uint64_t prime) {
  return BuildFastStandardPoly(roots, prime);
}


std::vector<uint64_t> InterpolatePoly(const std::vector<uint64_t>& points,
                                      const std::vector<uint64_t>& values,
                                      uint64_t prime) {
  return BuildFastInterpolationPoly(points, values, prime);
}


std::vector<uint64_t> SliceItem(uint128_t item, size_t ks, size_t sigma2_bits) {
  if (sigma2_bits == 0 || sigma2_bits > 64) {
    throw std::invalid_argument("sigma2_bits must be in [1, 64]");
  }
  if (ks == 0 || ks * sigma2_bits > 128) {
    throw std::invalid_argument("slicing exceeds 128-bit item width");
  }
  std::vector<uint64_t> slices(ks);
  const uint128_t mask = (sigma2_bits == 64)
                             ? static_cast<uint128_t>(UINT64_MAX)
                             : ((static_cast<uint128_t>(1) << sigma2_bits) - 1);
  for (size_t i = 0; i < ks; ++i) {
    slices[i] =
        static_cast<uint64_t>((item >> (i * sigma2_bits)) & mask);
  }
  return slices;
}

uint128_t UnsliceItem(const std::vector<uint64_t>& slices, size_t sigma2_bits) {
  if (sigma2_bits == 0 || sigma2_bits > 64) {
    throw std::invalid_argument("sigma2_bits must be in [1, 64]");
  }
  if (slices.empty() || slices.size() * sigma2_bits > 128) {
    throw std::invalid_argument("unslicing exceeds 128-bit item width");
  }
  uint128_t result = 0;
  for (size_t i = 0; i < slices.size(); ++i) {
    result |= (static_cast<uint128_t>(slices[i]) << (i * sigma2_bits));
  }
  return result;
}


PolyLinkSubBin BuildPolyLinkSubBin(const std::vector<uint128_t>& items, size_t ks,
                         size_t sigma2_bits, uint64_t prime,
                         bool drop_first_poly) {
  if (prime == 65537 && ks > 0 && items.size() <= 2048 && small_field::Enabled()) {
    return small_field::Build(items, ks, sigma2_bits, drop_first_poly);
  }
  PolyLinkSubBin sub_bin;
  sub_bin.ks = ks;
  size_t b = items.size();

  if (b == 0) {
    sub_bin.poly_coeffs.resize(ks);
    sub_bin.poly_coeffs[0] = {1};
    for (size_t i = 1; i < ks; ++i) {
      sub_bin.poly_coeffs[i] = {0};
    }
    return sub_bin;
  }

  std::vector<std::vector<uint64_t>> slices(b, std::vector<uint64_t>(ks));
  for (size_t j = 0; j < b; ++j) {
    slices[j] = SliceItem(items[j], ks, sigma2_bits);
    for (size_t i = 0; i < ks; ++i) {
      slices[j][i] = slices[j][i] % prime;
    }
  }

  std::vector<uint64_t> first_slices(b);
  for (size_t j = 0; j < b; ++j) {
    first_slices[j] = slices[j][0];
  }

  sub_bin.poly_coeffs.resize(ks);

  NTL::ZZ_p::init(ToNtlPrime(prime));
  auto points = ToZpValues(first_slices);
  auto tree = BuildProductTree(points, 0, points.size());
  if (!drop_first_poly) {
    sub_bin.poly_coeffs[0] = ToCoeffVector(tree->poly);
  }

  NTL::ZZ_pX derivative;
  diff(derivative, tree->poly);
  std::vector<NTL::ZZ_p> derivative_values(points.size());
  EvaluateOnTree(*tree, derivative, &derivative_values);

  std::vector<std::vector<NTL::ZZ_p>> scaled_values_list(
      ks > 1 ? (ks - 1) : 0, std::vector<NTL::ZZ_p>(points.size()));
  for (size_t j = 0; j < b; ++j) {
    if (IsZero(derivative_values[j])) {
      throw std::invalid_argument(
          "duplicate first slice detected in fast PolyLinks interpolation");
    }
    const auto inv_derivative = inv(derivative_values[j]);
    for (size_t i = 1; i < ks; ++i) {
      const auto value =
          NTL::conv<NTL::ZZ_p>(NTL::conv<NTL::ZZ>(slices[j][i]));
      scaled_values_list[i - 1][j] = value * inv_derivative;
    }
  }
  auto interpolants =
      BuildInterpolantsFromScaledValues(*tree, scaled_values_list);
  for (size_t i = 1; i < ks; ++i) {
    sub_bin.poly_coeffs[i] = ToCoeffVector(interpolants[i - 1]);
  }

  return sub_bin;
}


bool PolyLinkCheck(const std::vector<uint64_t>& y_slices, const PolyLinkSubBin& sub_bin,
              uint64_t prime, bool drop_first_poly) {
  if (sub_bin.poly_coeffs.empty()) return false;
  size_t ks = sub_bin.ks;

  uint64_t y1 = y_slices[0] % prime;

  if (!drop_first_poly) {
    uint64_t p1_val = EvalPoly(sub_bin.poly_coeffs[0], y1, prime);
    if (p1_val != 0) return false;
  }

  for (size_t i = 1; i < ks; ++i) {
    if (i < sub_bin.poly_coeffs.size()) {
      uint64_t pi_val = EvalPoly(sub_bin.poly_coeffs[i], y1, prime);
      uint64_t expected = y_slices[i] % prime;
      if (pi_val != expected) return false;
    }
  }
  return true;
}

size_t EstimatePolyLinkStorageBytes(const PolyLinkSubBin& sub_bin) {
  size_t bytes = 0;
  for (const auto& coeffs : sub_bin.poly_coeffs) {
    bytes += coeffs.size() * sizeof(uint64_t);
  }
  return bytes;
}

}

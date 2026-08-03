#include "upsu/powers_dag.h"

#include <algorithm>
#include <sstream>
#include <stdexcept>

#include "seal/modulus.h"
#include "seal/util/uintarithsmallmod.h"

namespace upsu {

bool PowersDag::configure(std::set<uint32_t> sources,
                          std::set<uint32_t> targets) {
  nodes_.clear();
  target_powers_.clear();
  depth_ = source_count_ = 0;
  configured_ = false;
  if (sources.count(0) || !sources.count(1) || targets.count(0) ||
      !targets.count(1) ||
      !std::includes(targets.begin(), targets.end(), sources.begin(), sources.end()))
    return false;
  for (uint32_t source : sources) nodes_[source] = {source, 0, {0, 0}};
  for (uint32_t power : targets) {
    if (sources.count(power)) continue;
    uint32_t best_depth = power - 1;
    std::pair<uint32_t, uint32_t> best{power - 1, 1};
    for (uint32_t left : targets) {
      if (left >= power) break;
      const uint32_t right = power - left;
      if (!targets.count(right) || !nodes_.count(left) || !nodes_.count(right)) continue;
      const uint32_t candidate = std::max(nodes_.at(left).depth,
                                          nodes_.at(right).depth) + 1;
      if (candidate < best_depth) {
        best_depth = candidate;
        best = {left, right};
      }
    }
    if (!nodes_.count(best.first) || !nodes_.count(best.second)) return false;
    nodes_[power] = {power, best_depth, best};
    depth_ = std::max(depth_, best_depth);
  }
  target_powers_ = std::move(targets);
  source_count_ = sources.size();
  configured_ = true;
  return true;
}

std::set<uint32_t> PowersDag::target_powers() const {
  if (!configured_) throw std::logic_error("PowersDag is not configured");
  return target_powers_;
}
uint32_t PowersDag::depth() const {
  if (!configured_) throw std::logic_error("PowersDag is not configured");
  return depth_;
}
uint32_t PowersDag::source_count() const {
  if (!configured_) throw std::logic_error("PowersDag is not configured");
  return source_count_;
}
std::vector<PowersDag::PowersNode> PowersDag::source_nodes() const {
  if (!configured_) throw std::logic_error("PowersDag is not configured");
  std::vector<PowersNode> result;
  for (const auto& [_, node] : nodes_) if (node.is_source()) result.push_back(node);
  return result;
}
std::string PowersDag::to_dot() const {
  if (!configured_) throw std::logic_error("PowersDag is not configured");
  std::ostringstream out;
  out << "digraph powers {\n";
  for (const auto& [power, node] : nodes_) {
    out << "\t" << power << ";\n";
    if (node.parents.first) out << "\t" << power << " -> " << node.parents.first << ";\n";
    if (node.parents.second) out << "\t" << power << " -> " << node.parents.second << ";\n";
  }
  return out.str() + "}\n";
}

namespace {
void MultiplyMonomial(std::vector<uint64_t>& polynomial, uint64_t root,
                      const seal::Modulus& modulus) {
  using namespace seal::util;
  polynomial.push_back(0);
  MultiplyUIntModOperand negative;
  negative.set(negate_uint_mod(root, modulus), modulus);
  for (size_t i = polynomial.size() - 1; i > 0; --i)
    polynomial[i] = multiply_add_uint_mod(polynomial[i], negative,
                                           polynomial[i - 1], modulus);
  polynomial[0] = multiply_uint_mod(polynomial[0], negative, modulus);
}
}  // namespace

std::vector<uint64_t> NewtonInterpolate(const std::vector<uint64_t>& points,
                                        const std::vector<uint64_t>& values,
                                        uint64_t modulus_value) {
  using namespace seal::util;
  if (points.size() != values.size())
    throw std::invalid_argument("interpolation point/value size mismatch");
  seal::Modulus modulus(modulus_value);
  if (!modulus.is_prime()) throw std::invalid_argument("modulus must be prime");
  const size_t size = points.size();
  if (std::all_of(values.begin(), values.end(), [](uint64_t v) { return v == 0; }))
    return std::vector<uint64_t>(std::max<size_t>(size, 1));
  std::vector<std::vector<uint64_t>> differences(size);
  for (size_t i = 0; i < size; ++i) differences[i].push_back(values[i]);
  for (size_t column = 1; column < size; ++column) {
    for (size_t row = 0; row < size - column; ++row) {
      const uint64_t numerator = sub_uint_mod(differences[row + 1][column - 1],
                                               differences[row][column - 1], modulus);
      const uint64_t denominator = sub_uint_mod(points[row + column], points[row], modulus);
      if (!denominator) throw std::logic_error("repeated interpolation point");
      const uint64_t inverse = exponentiate_uint_mod(denominator, modulus.value() - 2, modulus);
      differences[row].push_back(multiply_uint_mod(numerator, inverse, modulus));
    }
  }
  std::vector<uint64_t> result{0};
  for (size_t i = size - 1; i > 0; --i) {
    result[0] = add_uint_mod(result[0], differences[0][i], modulus);
    MultiplyMonomial(result, points[i - 1], modulus);
  }
  result[0] = add_uint_mod(result[0], differences[0][0], modulus);
  return result;
}

}  // namespace upsu

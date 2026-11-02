#pragma once

#include <limits>
#include <set>
#include <tuple>
#include <vector>
#include "upsu/common.h"
#include "upsu/powers_dag.h"

namespace psu::paper {

inline std::set<uint32_t> SourcePowers(const std::set<uint32_t>& targets,
                                     size_t max_depth,
                                     const std::vector<uint32_t>& preferred) {
  if (targets.empty() || max_depth == 0) return targets;
  std::set<uint32_t> sources{1};
  for (auto power : preferred) if (targets.count(power)) sources.insert(power);
  upsu::PowersDag dag;
  auto fits = [&] { return dag.configure(sources, targets) && dag.depth() <= max_depth; };
  if (fits()) return sources;
  // The paper's B=811 window explicitly includes 180 in addition to 225.
  if (targets.count(180)) sources.insert(180);
  if (fits()) return sources;
  while (sources.size() < targets.size()) {
    uint32_t best = 0;
    auto score = std::tuple<uint32_t, uint64_t, uint32_t>{UINT32_MAX, UINT64_MAX, UINT32_MAX};
    for (auto power : targets) {
      if (sources.count(power)) continue;
      auto trial = sources;
      trial.insert(power);
      upsu::PowersDag candidate;
      if (!candidate.configure(trial, targets)) continue;
      uint64_t depth_sum = 0;
      candidate.apply([&](const auto& node) { depth_sum += node.depth; });
      const auto candidate_score = std::tuple{candidate.depth(), depth_sum, power};
      if (candidate_score < score) { score = candidate_score; best = power; }
    }
    UPSU_ENFORCE(best != 0, "cannot derive source powers within the public depth bound");
    sources.insert(best);
    if (fits()) return sources;
  }
  UPSU_ENFORCE(fits(), "source-power depth exceeds the public limit");
  return sources;
}

}  // namespace psu::paper

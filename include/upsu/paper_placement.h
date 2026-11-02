#pragma once

#include <array>
#include <limits>
#include <vector>
#include "upsu/common.h"

namespace psu::paper {

// Deterministic augmenting paths depend only on candidate indices and input order.
inline std::vector<size_t> PlaceCuckoo(
    const std::vector<std::array<size_t, 3>>& candidates, size_t m) {
  const size_t empty = std::numeric_limits<size_t>::max();
  std::vector<size_t> items(m, empty), seen(m, 0), parent(m), queue;
  queue.reserve(m);
  for (size_t item = 0; item < candidates.size(); ++item) {
    bool inserted = false;
    for (size_t bin : candidates[item]) {
      if (items[bin] == empty) {
        items[bin] = item;
        inserted = true;
        break;
      }
    }
    if (inserted) continue;
    queue.clear();
    const size_t epoch = item + 1;
    for (size_t bin : candidates[item]) {
      seen[bin] = epoch;
      parent[bin] = m;
      queue.push_back(bin);
    }
    for (size_t head = 0; head < queue.size() && !inserted; ++head) {
      const size_t bin = queue[head];
      for (size_t next : candidates[items[bin]]) {
        if (seen[next] == epoch) continue;
        seen[next] = epoch;
        parent[next] = bin;
        if (items[next] != empty) {
          queue.push_back(next);
          continue;
        }
        size_t target = next;
        while (parent[target] != m) {
          const size_t source = parent[target];
          items[target] = items[source];
          target = source;
        }
        items[target] = item;
        inserted = true;
        break;
      }
    }
    UPSU_ENFORCE(inserted, "deterministic cuckoo insertion failed at input {}", item);
  }
  return items;
}

}  // namespace psu::paper

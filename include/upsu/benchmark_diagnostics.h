#pragma once
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>
#include "upsu/common.h"

namespace upsu::diagnostics {
// Synthetic benchmark diagnostics only. Never enabled for timed measurements.
template <typename T>
void Write(const char* name, const std::vector<T>& values) {
  const char* directory=std::getenv("PSU_DIAGNOSTIC_DIR");
  if(!directory || !*directory) return;
  UPSU_ENFORCE(std::getenv("PSU_RANDOM_INPUT_SEED"),"diagnostics require synthetic inputs");
  std::ofstream out(std::string(directory)+"/"+name,std::ios::binary);
  out.write(reinterpret_cast<const char*>(values.data()),values.size()*sizeof(T));
  UPSU_ENFORCE(out.good(),"cannot save benchmark diagnostics");
}
}

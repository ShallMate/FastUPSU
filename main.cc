#include "upsu/common.h"
#include "upsu/net/context.h"
#include "upsu/parallel.h"

#include <chrono>
#include <algorithm>
#include <cstddef>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#include "upsu/powers_dag.h"
#include "ote.h"
#include "poly_links.h"
#include "protocol.h"
#include "seal/modulus.h"

using namespace psu;


std::vector<std::string> CreateRangeItems(size_t begin, size_t size) {
  std::vector<std::string> items;
  items.reserve(size);
  for (size_t i = 0; i < size; ++i) {
    items.push_back(std::to_string(begin + i));
  }
  return items;
}

size_t GetEnvSize(const char* name, size_t fallback) {
  if (const char* value = std::getenv(name)) {
    return static_cast<size_t>(std::strtoull(value, nullptr, 10));
  }
  return fallback;
}

std::string GetEnvString(const char* name, const std::string& fallback = "") {
  if (const char* value = std::getenv(name)) {
    return value;
  }
  return fallback;
}

double GetEnvDouble(const char* name, double fallback) {
  if (const char* value = std::getenv(name)) {
    return std::strtod(value, nullptr);
  }
  return fallback;
}

std::optional<std::string> GetEnvOptional(const char* name) {
  if (const char* value = std::getenv(name)) {
    return std::string(value);
  }
  return std::nullopt;
}

bool EnvFlagEnabled(const char* name) {
  const char* value = std::getenv(name);
  if (!value || !*value) {
    return false;
  }
  std::string lowered(value);
  std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::tolower);
  return lowered != "0" && lowered != "false" && lowered != "no" &&
         lowered != "off";
}

size_t NextPowerOfTwo(size_t value) {
  size_t out = 1;
  while (out < value) {
    out <<= 1;
  }
  return out;
}

void SetEnvIfUnset(const char* name, const std::string& value) {
  if (std::getenv(name) == nullptr) {
    setenv(name, value.c_str(), 0);
  }
}

void SetOrUnsetEnv(const char* name, const std::optional<std::string>& value) {
  if (value.has_value()) {
    setenv(name, value->c_str(), 1);
  } else {
    unsetenv(name);
  }
}

std::string LoadSettingsJsonText() {
  const char* explicit_path = std::getenv("PSU_SETTINGS_FILE");
  const std::string path =
      (explicit_path && *explicit_path) ? explicit_path
                                        : "settings.json";
  std::ifstream input(path);
  if (!input.good()) {
    return "";
  }

  std::stringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

std::optional<std::string> ExtractJsonString(const std::string& json,
                                             const char* key) {
  const std::regex pattern(std::string("\"") + key + "\"\\s*:\\s*\"([^\"]*)\"");
  std::smatch match;
  if (std::regex_search(json, match, pattern) && match.size() >= 2) {
    return match[1].str();
  }
  return std::nullopt;
}

std::optional<std::string> ExtractJsonScalar(const std::string& json,
                                             const char* key) {
  const std::regex pattern(
      std::string("\"") + key + "\"\\s*:\\s*([-]?[A-Za-z0-9_\\.]+)");
  std::smatch match;
  if (std::regex_search(json, match, pattern) && match.size() >= 2) {
    return match[1].str();
  }
  return std::nullopt;
}

std::optional<std::string> ExtractJsonArray(const std::string& json,
                                            const char* key) {
  const std::regex pattern(std::string("\"") + key + "\"\\s*:\\s*\\[([^\\]]*)\\]");
  std::smatch match;
  if (std::regex_search(json, match, pattern) && match.size() >= 2) {
    return match[1].str();
  }
  return std::nullopt;
}

std::vector<std::string> ParseJsonStringArray(const std::string& array_body) {
  std::vector<std::string> result;
  const std::regex pattern("\"([^\"]*)\"");
  auto begin =
      std::sregex_iterator(array_body.begin(), array_body.end(), pattern);
  auto end = std::sregex_iterator();
  for (auto it = begin; it != end; ++it) {
    result.push_back((*it)[1].str());
  }
  return result;
}

std::string ReplaceAllCopy(std::string text, const std::string& from,
                           const std::string& to) {
  if (from.empty()) {
    return text;
  }
  size_t pos = 0;
  while ((pos = text.find(from, pos)) != std::string::npos) {
    text.replace(pos, from.size(), to);
    pos += to.size();
  }
  return text;
}

std::string SanitizePathComponent(std::string value) {
  if (value.empty()) {
    return value;
  }
  for (char& ch : value) {
    const bool keep =
        (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
        (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-';
    if (!keep) {
      ch = '_';
    }
  }
  return value;
}

void ExpandTemplateEnv(const char* name, const std::string& profile) {
  const char* raw = std::getenv(name);
  if (!raw || !*raw) {
    return;
  }
  std::string value(raw);
  std::string cache_tag =
      GetEnvString("PSU_CACHE_TAG",
                   GetEnvString("PSU_FHE_CANDIDATE"));
  cache_tag = SanitizePathComponent(cache_tag);
  value = ReplaceAllCopy(value, "{profile}",
                         profile.empty() ? "default" : profile);
  value = ReplaceAllCopy(value, "{candidate}",
                         cache_tag.empty() ? "default" : cache_tag);
  value = ReplaceAllCopy(value, "{cache_tag}",
                         cache_tag.empty() ? "default" : cache_tag);
  value = ReplaceAllCopy(value, "{candidate_suffix}",
                         cache_tag.empty() ? "" : ("/" + cache_tag));
  value = ReplaceAllCopy(
      value, "{nx}",
      GetEnvString("PSU_MEDIUM_NX", "0"));
  value = ReplaceAllCopy(
      value, "{ny}",
      GetEnvString("PSU_MEDIUM_NY", "0"));
  value = ReplaceAllCopy(
      value, "{cap}",
      GetEnvString("PSU_MEDIUM_CAP", "0"));
  setenv(name, value.c_str(), 1);
}

void ApplySettingsBlock(const std::string& json, const std::string& key_prefix,
                        bool overwrite_existing = false) {
  auto prefixed = [&](const char* key) {
    return key_prefix + key;
  };
  auto set_value = [&](const char* env_name, const std::string& value) {
    if (overwrite_existing) {
      setenv(env_name, value.c_str(), 1);
    } else {
      SetEnvIfUnset(env_name, value);
    }
  };

  auto apply_string = [&](const std::string& json_key, const char* env_name) {
    if (auto value = ExtractJsonString(json, json_key.c_str())) {
      set_value(env_name, *value);
    }
  };
  auto apply_scalar = [&](const std::string& json_key, const char* env_name) {
    if (auto value = ExtractJsonScalar(json, json_key.c_str())) {
      set_value(env_name, *value);
    }
  };
  auto apply_array = [&](const std::string& json_key, const char* env_name) {
    if (auto value = ExtractJsonArray(json, json_key.c_str())) {
      set_value(env_name, *value);
    }
  };
  auto apply_flag = [&](const std::string& json_key, const char* env_name) {
    if (auto value = ExtractJsonScalar(json, json_key.c_str())) {
      std::string lowered = *value;
      std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                     ::tolower);
      if (lowered == "true") {
        set_value(env_name, "1");
      } else if (lowered == "false") {
        set_value(env_name, "0");
      }
    }
  };

  apply_string(prefixed("bench_filter"), "PSU_BENCH_FILTER");
  apply_string(prefixed("mode"), "PSU_MODE");
  apply_string(prefixed("parties"), "PSU_PARTIES");
  apply_string(prefixed("prepared_cache_file"), "PSU_PREPARED_CACHE_FILE");
  apply_string(prefixed("intermediate_cache_file"),
               "PSU_INTERMEDIATE_CACHE_FILE");
  apply_scalar(prefixed("threads"), "PSU_THREADS");
  apply_scalar(prefixed("offline_threads"), "PSU_OFFLINE_THREADS");
  apply_scalar(prefixed("online_threads"), "PSU_ONLINE_THREADS");
  apply_flag(prefixed("trace"), "PSU_TRACE");
  apply_flag(prefixed("synthetic_online"), "PSU_SYNTHETIC_ONLINE");
  apply_scalar(prefixed("medium_nx"), "PSU_MEDIUM_NX");
  apply_scalar(prefixed("medium_ny"), "PSU_MEDIUM_NY");
  apply_scalar(prefixed("medium_cap"), "PSU_MEDIUM_CAP");
  apply_scalar(prefixed("ks"), "PSU_KS");
  apply_scalar(prefixed("hash_func_count"), "PSU_HASH_FUNC_COUNT");
  apply_scalar(prefixed("simple_hash_bins"), "PSU_SIMPLE_HASH_BINS");
  apply_scalar(prefixed("alpha"), "PSU_ALPHA");
  apply_scalar(prefixed("max_items_per_bin"),
               "PSU_MAX_ITEMS_PER_BIN");
  apply_flag(prefixed("permutation_hashing"),
             "PSU_PERMUTATION_HASHING");
  apply_flag(prefixed("dh_oprf"), "PSU_USE_DH_OPRF");
  apply_flag(prefixed("circuit_peqt"), "PSU_CIRCUIT_PEQT");
  apply_flag(prefixed("drop_first_poly"), "PSU_DROP_FIRST_POLY");
  apply_scalar(prefixed("query_depth"), "PSU_QUERY_DEPTH");
  apply_scalar(prefixed("ps_low_degree"), "PSU_PS_LOW_DEGREE");
  apply_scalar(prefixed("ntt_plain_eval"), "PSU_NTT_PLAIN_EVAL");
  apply_string(prefixed("ote_backend"), "PSU_OTE_BACKEND");
  apply_string(prefixed("ote_address"), "PSU_OTE_ADDRESS");
  apply_scalar(prefixed("ote_threads"), "PSU_OTE_THREADS");
  apply_scalar(prefixed("ote_auto_iknp_max"), "PSU_OTE_AUTO_IKNP_MAX");
  apply_scalar(prefixed("ote_auto_softspoken_max"),
               "PSU_OTE_AUTO_SOFTSPOKEN_MAX");
  apply_array(prefixed("query_powers"), "PSU_QUERY_POWERS");
  apply_scalar(prefixed("mod_switch_steps"), "PSU_MOD_SWITCH_STEPS");
  apply_scalar(prefixed("response_flood_bits"),
               "PSU_RESPONSE_FLOOD_BITS");
  apply_scalar(prefixed("poly_modulus_degree"),
               "PSU_POLY_MODULUS_DEGREE");
  apply_array(prefixed("coeff_modulus_bits"),
              "PSU_COEFF_MODULUS_BITS");
  apply_scalar(prefixed("plain_modulus"), "PSU_PLAIN_MODULUS");
  apply_scalar(prefixed("cuckoo_scale"), "PSU_CUCKOO_SCALE");
}

std::vector<std::string> LoadConfiguredProfiles() {
  const std::string json = LoadSettingsJsonText();
  if (json.empty()) {
    return {};
  }
  if (auto value = ExtractJsonArray(json, "profiles")) {
    return ParseJsonStringArray(*value);
  }
  if (auto value = ExtractJsonString(json, "default_profile")) {
    return {*value};
  }
  return {};
}

std::vector<std::string> LoadConfiguredCandidateNames(
    const std::string& profile) {
  const std::string json = LoadSettingsJsonText();
  if (json.empty()) {
    return {};
  }
  if (!profile.empty()) {
    const std::string profile_key =
        "profile_" + profile + "_fhe_candidate_names";
    if (auto value = ExtractJsonArray(json, profile_key.c_str())) {
      return ParseJsonStringArray(*value);
    }
  }
  if (auto value = ExtractJsonArray(json, "fhe_candidate_names")) {
    return ParseJsonStringArray(*value);
  }
  return {};
}

void ApplyFheCandidateBlock(const std::string& candidate_name) {
  const std::string json = LoadSettingsJsonText();
  if (json.empty() || candidate_name.empty()) {
    return;
  }
  setenv("PSU_FHE_CANDIDATE", candidate_name.c_str(), 1);
  ApplySettingsBlock(json, "candidate_" + candidate_name + "_", true);
  const std::string profile = GetEnvString("PSU_PROFILE");
  ExpandTemplateEnv("PSU_PREPARED_CACHE_FILE", profile);
  ExpandTemplateEnv("PSU_INTERMEDIATE_CACHE_FILE", profile);
}

void ApplySettingsJson() {
  const std::string json = LoadSettingsJsonText();
  if (json.empty()) {
    return;
  }

  ApplySettingsBlock(json, "");
  std::string profile = GetEnvString("PSU_PROFILE");
  if (profile.empty()) {
    if (auto value = ExtractJsonString(json, "default_profile")) {
      setenv("PSU_PROFILE", value->c_str(), 0);
      profile = *value;
    }
  }
  if (!profile.empty()) {
    ApplySettingsBlock(json, "profile_" + profile + "_", true);
  }
  const std::string candidate = GetEnvString("PSU_FHE_CANDIDATE");
  if (!candidate.empty()) {
    ApplyFheCandidateBlock(candidate);
  }
  ExpandTemplateEnv("PSU_PREPARED_CACHE_FILE", profile);
  ExpandTemplateEnv("PSU_INTERMEDIATE_CACHE_FILE", profile);
}

std::vector<int> ParseIntListEnv(const char* name) {
  std::vector<int> result;
  const char* value = std::getenv(name);
  if (!value || !*value) {
    return result;
  }

  std::stringstream ss(value);
  std::string token;
  while (std::getline(ss, token, ',')) {
    if (token.empty()) {
      continue;
    }
    result.push_back(std::stoi(token));
  }
  return result;
}

std::vector<uint32_t> ParseQueryPowersEnv(const char* name) {
  std::vector<uint32_t> result;
  const char* value = std::getenv(name);
  if (!value || !*value) {
    return result;
  }

  std::stringstream ss(value);
  std::string token;
  while (std::getline(ss, token, ',')) {
    if (token.empty()) {
      continue;
    }
    result.push_back(static_cast<uint32_t>(std::stoul(token)));
  }
  return result;
}

bool ShouldRunBenchmark(const std::string& name) {
  const char* filter = std::getenv("PSU_BENCH_FILTER");
  if (!filter || !*filter) {
    return true;
  }
  if (*filter == '=') {
    return name == (filter + 1);
  }
  return name.find(filter) != std::string::npos;
}

std::vector<std::string> SplitCsv(const std::string& csv) {
  std::vector<std::string> result;
  std::stringstream ss(csv);
  std::string token;
  while (std::getline(ss, token, ',')) {
    if (!token.empty()) {
      result.push_back(token);
    }
  }
  return result;
}

std::string ProtocolOutputName() {
  return "PSU";
}

std::string ResultCountLabel() {
  return "Output count";
}

bool ShouldPreviewOutputItems() {
  if (EnvFlagEnabled("PSU_PRINT_RECOVERED_ITEMS")) {
    return true;
  }
  return false;
}

void PrintOutputItems(const std::vector<std::string>& items) {
  if (items.empty()) {
    std::cout << "  Output preview:      (empty)" << std::endl;
    return;
  }

  const size_t preview_count = std::min<size_t>(items.size(), 32);
  std::ostringstream oss;
  for (size_t i = 0; i < preview_count; ++i) {
    if (i) {
      oss << ", ";
    }
    oss << items[i];
  }
  if (preview_count < items.size()) {
    oss << " ... (" << (items.size() - preview_count) << " more)";
  }
  std::cout << "  Output preview:      " << oss.str() << std::endl;
}

size_t TrueIntersectionSize(const std::vector<std::string>& x,
                             const std::vector<std::string>& y) {
  std::unordered_set<std::string> sx(x.begin(), x.end());
  size_t count = 0;
  for (const auto& yi : y) {
    if (sx.count(yi)) ++count;
  }
  return count;
}

size_t TrueUnionSize(const std::vector<std::string>& x,
                     const std::vector<std::string>& y) {
  std::unordered_set<std::string> s(x.begin(), x.end());
  s.insert(y.begin(), y.end());
  return s.size();
}

std::vector<uint8_t> SampleRandomBits(size_t n) {
  std::vector<uint8_t> out(n, 0);
  for (size_t i = 0; i < n; ++i) {
    out[i] = static_cast<uint8_t>(upsu::SecureRandU64() & 1U);
  }
  return out;
}


static void PrintStats(const std::string& name,
                       const std::shared_ptr<upsu::net::Context>& ctx0,
                       const std::shared_ptr<upsu::net::Context>& ctx1,
                       double elapsed_s, size_t cardinality,
                       size_t true_cardinality,
                       double receiver_offline_s = -1.0,
                       double end_to_end_s = -1.0,
                       bool timing_only = false,
                       size_t fhe_key_comm_bytes = 0,
                       double setup_time_s = -1.0,
                       double online_wall_time_s = -1.0,
                       double perm_setup_time_s = -1.0,
                       double peqt_setup_time_s = -1.0,
                       double perm_apply_time_s = -1.0,
                       double peqt_time_s = -1.0,
                       size_t perm_setup_comm_bytes = 0,
                       size_t peqt_setup_comm_bytes = 0,
                       size_t perm_apply_comm_bytes = 0,
                       size_t peqt_comm_bytes = 0,
                       size_t peqt_local_comm_bytes = 0,
                       size_t ote_comm_bytes = 0) {
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024.0 * 1024.0);
  };
  auto s0 = ctx0->GetStats();
  auto s1 = ctx1->GetStats();
  const size_t total_link_comm_bytes =
      s0->sent_bytes.load() + s0->recv_bytes.load();
  const size_t setup_comm_bytes =
      fhe_key_comm_bytes + perm_setup_comm_bytes + peqt_setup_comm_bytes;
  const size_t total_comm_bytes =
      total_link_comm_bytes + peqt_setup_comm_bytes + peqt_local_comm_bytes +
      ote_comm_bytes + perm_setup_comm_bytes + perm_apply_comm_bytes;
  const size_t online_link_comm_bytes =
      (total_link_comm_bytes >= fhe_key_comm_bytes)
          ? (total_link_comm_bytes - fhe_key_comm_bytes)
          : 0;
  const size_t online_comm_bytes =
      online_link_comm_bytes + peqt_local_comm_bytes + ote_comm_bytes +
      perm_apply_comm_bytes;
  const size_t fhe_query_response_comm_bytes =
      (online_comm_bytes >= peqt_comm_bytes + ote_comm_bytes + perm_apply_comm_bytes)
          ? (online_comm_bytes - peqt_comm_bytes - ote_comm_bytes -
             perm_apply_comm_bytes)
          : 0;
  const double total_comm_mb = bytesToMB(total_comm_bytes);
  const double online_comm_mb = bytesToMB(online_comm_bytes);
  const double setup_comm_mb = bytesToMB(setup_comm_bytes);
  const double fhe_key_comm_mb = bytesToMB(fhe_key_comm_bytes);
  const double fhe_query_response_comm_mb =
      bytesToMB(fhe_query_response_comm_bytes);
  const double setup_prep_time_s = receiver_offline_s >= 0.0 ? receiver_offline_s : 0.0;
  const double setup_total_time_s =
      (setup_prep_time_s > 0.0 ? setup_prep_time_s : 0.0) +
      (setup_time_s > 0.0 ? setup_time_s : 0.0);

  std::cout << "==============================" << std::endl;
  std::cout << "[" << name << "]" << std::endl;
  if (receiver_offline_s >= 0.0) {
    if (setup_prep_time_s > 0.0) {
      std::cout << "  Setup prep time:   " << setup_prep_time_s << " s"
                << std::endl;
    }
    if (setup_total_time_s > 0.0) {
      std::cout << "  Setup time:        " << setup_total_time_s << " s"
                << std::endl;
    } else if (setup_time_s > 0.0) {
      std::cout << "  Setup time:        " << setup_time_s << " s"
                << std::endl;
    }
    if (setup_time_s > 0.0) {
      std::cout << "  Setup online time: " << setup_time_s << " s"
                << std::endl;
    }
    if (perm_setup_time_s > 0.0) {
      std::cout << "  Perm setup time:   " << perm_setup_time_s << " s"
                << std::endl;
    }
    if (peqt_setup_time_s > 0.0) {
      std::cout << "  PEQT setup time:   " << peqt_setup_time_s << " s"
                << std::endl;
    }
    if (peqt_time_s > 0.0) {
      std::cout << "  PEQT time:         " << peqt_time_s << " s"
                << std::endl;
    }
    if (perm_apply_time_s > 0.0) {
      std::cout << "  Perm online time:  " << perm_apply_time_s << " s"
                << std::endl;
    }
    std::cout << "  Online time:       " << elapsed_s << " s" << std::endl;
    if (online_wall_time_s >= 0.0) {
      std::cout << "  Online wall:       " << online_wall_time_s << " s"
                << std::endl;
    }
    if (end_to_end_s >= 0.0) {
      std::cout << "  End-to-end:        " << end_to_end_s << " s"
                << std::endl;
    }
  } else {
    if (setup_total_time_s > 0.0) {
      std::cout << "  Setup time:        " << setup_total_time_s << " s"
                << std::endl;
    } else if (setup_time_s > 0.0) {
      std::cout << "  Setup time:        " << setup_time_s << " s"
                << std::endl;
    }
    if (perm_setup_time_s > 0.0) {
      std::cout << "  Perm setup time:   " << perm_setup_time_s << " s"
                << std::endl;
    }
    if (peqt_setup_time_s > 0.0) {
      std::cout << "  PEQT setup time:   " << peqt_setup_time_s << " s"
                << std::endl;
    }
    if (peqt_time_s > 0.0) {
      std::cout << "  PEQT time:         " << peqt_time_s << " s"
                << std::endl;
    }
    if (perm_apply_time_s > 0.0) {
      std::cout << "  Perm online time:  " << perm_apply_time_s << " s"
                << std::endl;
    }
    std::cout << "  Time:              " << elapsed_s << " s" << std::endl;
    if (online_wall_time_s >= 0.0) {
      std::cout << "  Online wall:       " << online_wall_time_s << " s"
                << std::endl;
    }
  }
  std::cout << "  " << ResultCountLabel()
            << ":";
  const std::string label = ResultCountLabel();
  const int pad = std::max(1, 18 - static_cast<int>(label.size()));
  std::cout << std::string(static_cast<size_t>(pad), ' ') << cardinality
            << " (true: " << true_cardinality << ")";
  if (timing_only) {
    std::cout << " [TIMING MODE]";
  } else {
    std::cout
        << (cardinality == true_cardinality ? " [CORRECT]" : " [WRONG!]");
  }
  std::cout << std::endl;
  std::cout << "  Receiver sent:     " << bytesToMB(s0->sent_bytes.load())
            << " MB" << std::endl;
  std::cout << "  Receiver recv:     " << bytesToMB(s0->recv_bytes.load())
            << " MB" << std::endl;
  std::cout << "  Sender sent:       " << bytesToMB(s1->sent_bytes.load())
            << " MB" << std::endl;
  std::cout << "  Sender recv:       " << bytesToMB(s1->recv_bytes.load())
            << " MB" << std::endl;
  if (setup_comm_bytes > 0) {
    std::cout << "  Setup comm:        " << setup_comm_mb << " MB"
              << std::endl;
    if (fhe_key_comm_bytes > 0) {
      std::cout << "  FHE key comm:      " << fhe_key_comm_mb << " MB"
                << " (pk + relin)" << std::endl;
    }
    if (perm_setup_comm_bytes > 0) {
      std::cout << "  Perm setup comm:   "
                << bytesToMB(perm_setup_comm_bytes) << " MB" << std::endl;
    }
    if (peqt_setup_comm_bytes > 0) {
      std::cout << "  PEQT setup comm:   "
                << bytesToMB(peqt_setup_comm_bytes) << " MB" << std::endl;
    }
    if (peqt_comm_bytes > 0) {
      std::cout << "  PEQT comm:         " << bytesToMB(peqt_comm_bytes)
                << " MB" << std::endl;
      if (ote_comm_bytes > 0) {
        std::cout << "  OTE comm:          " << bytesToMB(ote_comm_bytes)
                  << " MB" << std::endl;
      }
      if (perm_apply_comm_bytes > 0) {
        std::cout << "  Perm online comm:  "
                  << bytesToMB(perm_apply_comm_bytes) << " MB" << std::endl;
      }
      std::cout << "  FHE q/r comm:      " << fhe_query_response_comm_mb
                << " MB" << std::endl;
    }
    std::cout << "  Online comm:       " << online_comm_mb << " MB"
              << " (excl. pk/relin)" << std::endl;
  }
  std::cout << "  Total comm (S↔R):  " << total_comm_mb << " MB" << std::endl;
}

static void PrintSinglePartyStats(
    const std::string& name, const std::string& role,
    const std::shared_ptr<upsu::net::Context>& ctx, double elapsed_s,
    std::optional<size_t> cardinality, std::optional<size_t> true_cardinality,
    double receiver_offline_s = -1.0, double end_to_end_s = -1.0,
    bool timing_only = false, size_t fhe_key_comm_bytes = 0,
    double setup_time_s = -1.0,
    double online_wall_time_s = -1.0, double peqt_time_s = -1.0,
    double perm_setup_time_s = -1.0, double peqt_setup_time_s = -1.0,
    double perm_apply_time_s = -1.0, size_t perm_setup_comm_bytes = 0,
    size_t peqt_setup_comm_bytes = 0, size_t perm_apply_comm_bytes = 0,
    size_t peqt_comm_bytes = 0, size_t peqt_local_comm_bytes = 0,
    size_t ote_comm_bytes = 0) {
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024.0 * 1024.0);
  };
  auto stats = ctx->GetStats();
  const size_t total_link_comm_bytes =
      stats->sent_bytes.load() + stats->recv_bytes.load();
  const size_t setup_comm_bytes =
      fhe_key_comm_bytes + perm_setup_comm_bytes + peqt_setup_comm_bytes;
  const size_t total_comm_bytes =
      total_link_comm_bytes + peqt_setup_comm_bytes + peqt_local_comm_bytes +
      ote_comm_bytes + perm_setup_comm_bytes + perm_apply_comm_bytes;
  const size_t online_link_comm_bytes =
      (total_link_comm_bytes >= fhe_key_comm_bytes)
          ? (total_link_comm_bytes - fhe_key_comm_bytes)
          : 0;
  const size_t online_comm_bytes =
      online_link_comm_bytes + peqt_local_comm_bytes + ote_comm_bytes +
      perm_apply_comm_bytes;
  const size_t fhe_query_response_comm_bytes =
      (online_comm_bytes >= peqt_comm_bytes + ote_comm_bytes +
                                perm_apply_comm_bytes)
          ? (online_comm_bytes - peqt_comm_bytes - ote_comm_bytes -
             perm_apply_comm_bytes)
          : 0;
  const double setup_prep_time_s = receiver_offline_s >= 0.0 ? receiver_offline_s : 0.0;
  const double setup_total_time_s =
      (setup_prep_time_s > 0.0 ? setup_prep_time_s : 0.0) +
      (setup_time_s > 0.0 ? setup_time_s : 0.0);

  std::cout << "==============================" << std::endl;
  std::cout << "[" << name << "]" << std::endl;
  std::cout << "  Role:              " << role << std::endl;
  if (receiver_offline_s >= 0.0) {
    if (setup_prep_time_s > 0.0) {
      std::cout << "  Setup prep time:   " << setup_prep_time_s << " s"
                << std::endl;
    }
    if (setup_total_time_s > 0.0) {
      std::cout << "  Setup time:        " << setup_total_time_s << " s"
                << std::endl;
    } else if (setup_time_s > 0.0) {
      std::cout << "  Setup time:        " << setup_time_s << " s"
                << std::endl;
    }
    if (setup_time_s > 0.0) {
      std::cout << "  Setup online time: " << setup_time_s << " s"
                << std::endl;
    }
    if (perm_setup_time_s > 0.0) {
      std::cout << "  Perm setup time:   " << perm_setup_time_s << " s"
                << std::endl;
    }
    if (peqt_setup_time_s > 0.0) {
      std::cout << "  PEQT setup time:   " << peqt_setup_time_s << " s"
                << std::endl;
    }
    if (peqt_time_s > 0.0) {
      std::cout << "  PEQT time:         " << peqt_time_s << " s"
                << std::endl;
    }
    if (perm_apply_time_s > 0.0) {
      std::cout << "  Perm online time:  " << perm_apply_time_s << " s"
                << std::endl;
    }
    std::cout << "  Online time:       " << elapsed_s << " s" << std::endl;
    if (online_wall_time_s >= 0.0) {
      std::cout << "  Online wall:       " << online_wall_time_s << " s"
                << std::endl;
    }
    if (end_to_end_s >= 0.0) {
      std::cout << "  End-to-end:        " << end_to_end_s << " s"
                << std::endl;
    }
  } else {
    if (setup_total_time_s > 0.0) {
      std::cout << "  Setup time:        " << setup_total_time_s << " s"
                << std::endl;
    } else if (setup_time_s > 0.0) {
      std::cout << "  Setup time:        " << setup_time_s << " s"
                << std::endl;
    }
    if (perm_setup_time_s > 0.0) {
      std::cout << "  Perm setup time:   " << perm_setup_time_s << " s"
                << std::endl;
    }
    if (peqt_setup_time_s > 0.0) {
      std::cout << "  PEQT setup time:   " << peqt_setup_time_s << " s"
                << std::endl;
    }
    if (peqt_time_s > 0.0) {
      std::cout << "  PEQT time:         " << peqt_time_s << " s"
                << std::endl;
    }
    if (perm_apply_time_s > 0.0) {
      std::cout << "  Perm online time:  " << perm_apply_time_s << " s"
                << std::endl;
    }
    std::cout << "  Online time:       " << elapsed_s << " s" << std::endl;
    if (online_wall_time_s >= 0.0) {
      std::cout << "  Online wall:       " << online_wall_time_s << " s"
                << std::endl;
    }
  }
  if (cardinality.has_value()) {
    const std::string label = ResultCountLabel();
    const int pad = std::max(1, 18 - static_cast<int>(label.size()));
    std::cout << "  " << label << ":" << std::string(static_cast<size_t>(pad), ' ')
              << *cardinality;
    if (true_cardinality.has_value()) {
      std::cout << " (true: " << *true_cardinality << ")";
      if (timing_only) {
        std::cout << " [TIMING MODE]";
      } else {
        std::cout << (*cardinality == *true_cardinality ? " [CORRECT]"
                                                        : " [WRONG!]");
      }
    }
    std::cout << std::endl;
  }
  std::cout << "  Sent:              " << bytesToMB(stats->sent_bytes.load())
            << " MB" << std::endl;
  std::cout << "  Recv:              " << bytesToMB(stats->recv_bytes.load())
            << " MB" << std::endl;
  if (setup_comm_bytes > 0) {
    std::cout << "  Setup comm:        " << bytesToMB(setup_comm_bytes)
              << " MB" << std::endl;
    if (fhe_key_comm_bytes > 0) {
      std::cout << "  FHE key comm:      " << bytesToMB(fhe_key_comm_bytes)
                << " MB" << " (pk + relin)" << std::endl;
    }
    if (perm_setup_comm_bytes > 0) {
      std::cout << "  Perm setup comm:   "
                << bytesToMB(perm_setup_comm_bytes) << " MB" << std::endl;
    }
    if (peqt_setup_comm_bytes > 0) {
      std::cout << "  PEQT setup comm:   "
                << bytesToMB(peqt_setup_comm_bytes) << " MB" << std::endl;
    }
    if (peqt_comm_bytes > 0) {
      std::cout << "  PEQT comm:         " << bytesToMB(peqt_comm_bytes)
                << " MB" << std::endl;
      if (ote_comm_bytes > 0) {
        std::cout << "  OTE comm:          " << bytesToMB(ote_comm_bytes)
                  << " MB" << std::endl;
      }
      if (perm_apply_comm_bytes > 0) {
        std::cout << "  Perm online comm:  "
                  << bytesToMB(perm_apply_comm_bytes) << " MB" << std::endl;
      }
      std::cout << "  FHE q/r comm:      "
                << bytesToMB(fhe_query_response_comm_bytes) << " MB"
                << std::endl;
    }
    std::cout << "  Online comm:       " << bytesToMB(online_comm_bytes)
              << " MB" << " (excl. pk/relin)" << std::endl;
  }
  std::cout << "  Total comm (S↔R):  " << bytesToMB(total_comm_bytes) << " MB"
            << std::endl;
}


void TestPolyLinks() {
  std::cout << "\n=== Testing Polynomial Links ===" << std::endl;
  uint64_t prime = 65537;
  size_t ks = 4;
  size_t sigma2 = 10;

  std::vector<uint128_t> items = {1234, 5678, 9012, 3456, 7890};
  PolyLinkSubBin sub_bin = BuildPolyLinkSubBin(items, ks, sigma2, prime);

  size_t pass = 0;
  for (auto item : items) {
    auto slices = SliceItem(item, ks, sigma2);
    for (auto& s : slices) s %= prime;
    bool matched = PolyLinkCheck(slices, sub_bin, prime);
    if (matched) ++pass;
  }
  std::cout << "  " << pass << "/" << items.size() << " items match (expect all)" << std::endl;

  uint128_t non_item = 99999;
  auto non_slices = SliceItem(non_item, ks, sigma2);
  for (auto& s : non_slices) s %= prime;
  bool non_match = PolyLinkCheck(non_slices, sub_bin, prime);
  std::cout << "  Non-member matches: " << (non_match ? "FAIL" : "PASS") << std::endl;
}

void ConfigureReferenceParams(ProtocolParams* params, size_t nx, size_t ny) {
  params->ks = 4;
  params->hash_func_count =
      GetEnvSize("PSU_HASH_FUNC_COUNT", params->hash_func_count);
  params->use_permutation_hashing =
      EnvFlagEnabled("PSU_PERMUTATION_HASHING");
  if (std::getenv("PSU_USE_DH_OPRF") != nullptr) {
    params->use_dh_oprf = EnvFlagEnabled("PSU_USE_DH_OPRF");
  }
  params->use_circuit_peqt = EnvFlagEnabled("PSU_CIRCUIT_PEQT");
  params->drop_first_poly = EnvFlagEnabled("PSU_DROP_FIRST_POLY");
  params->poly_modulus_degree =
      GetEnvSize("PSU_POLY_MODULUS_DEGREE", params->poly_modulus_degree);
  auto coeff_modulus_bits = ParseIntListEnv("PSU_COEFF_MODULUS_BITS");
  if (!coeff_modulus_bits.empty()) {
    params->coeff_modulus_bits = coeff_modulus_bits;
  }
  params->cuckoo_scale =
      GetEnvDouble("PSU_CUCKOO_SCALE", params->cuckoo_scale);
  params->simple_hash_bins =
      GetEnvSize("PSU_SIMPLE_HASH_BINS", 0);
  const size_t min_simple_hash_bins =
      std::max<size_t>(64, static_cast<size_t>(std::ceil(
                               ny * params->cuckoo_scale)));
  if (params->simple_hash_bins == 0) {
    params->simple_hash_bins = min_simple_hash_bins;
  } else if (params->simple_hash_bins < min_simple_hash_bins) {
    std::cout << "[warn] simple_hash_bins=" << params->simple_hash_bins
              << " is below ceil(cuckoo_scale * |Y|)="
              << min_simple_hash_bins
              << "; clamping to preserve cuckoo insertion reliability"
              << std::endl;
    params->simple_hash_bins = min_simple_hash_bins;
  }
  params->alpha = GetEnvSize("PSU_ALPHA", params->alpha);
  params->max_items_per_bin =
      GetEnvSize("PSU_MAX_ITEMS_PER_BIN", params->max_items_per_bin);
  params->sigma1_bits = ComputePolyLinkHashBits(nx, ny, params->lambda);
  const size_t finalize_ks = params->ks;
  params->sigma2_bits =
      (params->EffectiveItemBitCount() + finalize_ks - 1) / finalize_ks;
  params->plain_modulus =
      ChoosePlainModulus(params->poly_modulus_degree, params->sigma2_bits);
  params->plain_modulus =
      static_cast<uint64_t>(GetEnvSize("PSU_PLAIN_MODULUS",
                                       params->plain_modulus));
  params->ps_low_degree = GetEnvSize("PSU_PS_LOW_DEGREE", 0);
  params->query_powers = ParseQueryPowersEnv("PSU_QUERY_POWERS");
  params->response_mod_switch_steps =
      GetEnvSize("PSU_MOD_SWITCH_STEPS", 2);
  params->response_flood_bits =
      GetEnvSize("PSU_RESPONSE_FLOOD_BITS", params->response_flood_bits);
}

struct SweepMetrics {
  bool success = false;
  bool correct = false;
  size_t sender_result = 0;
  size_t sender_truth = 0;
  size_t receiver_result = 0;
  size_t receiver_truth = 0;
  size_t total_comm_bytes = 0;
  size_t online_comm_bytes = 0;
  size_t fhe_key_comm_bytes = 0;
  size_t peqt_comm_bytes = 0;
  size_t ote_bytes = 0;
  double sender_offline_s = 0.0;
  double setup_time_s = 0.0;
  double online_s = 0.0;
  double peqt_time_s = 0.0;
  std::string error;
};

SweepMetrics RunLocalPsuOnce(size_t nx, size_t ny, size_t cap,
                              const ProtocolParams& params) {
  SweepMetrics metrics;
  auto x = CreateRangeItems(0, nx);
  auto y = CreateRangeItems(nx - cap, ny);

  auto lctxs = upsu::net::Context::SetupWorld(2);
  lctxs[0]->SetRecvTimeout(600000);
  lctxs[1]->SetRecvTimeout(600000);

  constexpr char kOteReceiverShareTag[] = "UPSI:ote_receiver_share";
  const size_t fhe_key_comm_bytes = EstimateFheKeyCommBytes(params);

  struct SenderRun {
    OnlineStats online_stats;
    size_t union_cardinality = 0;
    size_t true_union = 0;
    size_t ote_bytes = 0;
    ote::Backend ote_backend = ote::Backend::kIknp;
    double sender_offline_s = 0.0;
    double online_s = 0.0;
  };
  struct ReceiverRun {
    OnlineStats online_stats;
    size_t intersection_cardinality = 0;
    size_t true_intersection = 0;
    size_t ote_bytes = 0;
    ote::Backend ote_backend = ote::Backend::kIknp;
    double online_s = 0.0;
  };

  std::future<SenderRun> sender_fut = std::async(std::launch::async, [&]() {
    SenderRun run;
    auto sender_offline_start = std::chrono::high_resolution_clock::now();
    auto prepared = PrepareSender(x, params);
    MaterializeSenderOnlineCache(prepared, params);
    auto sender_offline_end = std::chrono::high_resolution_clock::now();
    run.sender_offline_s =
        std::chrono::duration<double>(sender_offline_end - sender_offline_start)
            .count();

    auto online_start = std::chrono::high_resolution_clock::now();
    SendPrepared(lctxs[0], prepared, params, &run.online_stats);
    auto receiver_share_buf =
        lctxs[0]->Recv(lctxs[0]->NextRank(), kOteReceiverShareTag);
    UPSU_ENFORCE(static_cast<size_t>(receiver_share_buf.size()) == ny,
                 "receiver OTE-share size mismatch: got {}, expect {}",
                 receiver_share_buf.size(), ny);
    std::vector<uint8_t> receiver_share(ny, 0);
    if (ny > 0) {
      std::memcpy(receiver_share.data(), receiver_share_buf.data(), ny);
    }
    auto ote_result = ote::RunEqValueReceiverRole(lctxs[0], receiver_share);
    auto online_end = std::chrono::high_resolution_clock::now();
    run.online_s =
        std::chrono::duration<double>(online_end - online_start).count();
    run.ote_bytes = ote_result.bytes;
    run.ote_backend = ote_result.backend;
    const size_t recovered_y_unique = static_cast<size_t>(std::count_if(
        ote_result.values.begin(), ote_result.values.end(),
        [](uint64_t value) { return value != 0; }));
    const size_t true_intersection = std::min(std::min(cap, ny), nx);
    run.union_cardinality = nx + recovered_y_unique;
    run.true_union = nx + ny - true_intersection;
    return run;
  });

  std::future<ReceiverRun> receiver_fut = std::async(std::launch::async, [&]() {
    ReceiverRun run;
    auto online_start = std::chrono::high_resolution_clock::now();
    auto membership_bits = RecvMembershipBits(lctxs[1], y, params,
                                              &run.online_stats);
    std::vector<uint8_t> receiver_share =
        SampleRandomBits(membership_bits.size());
    std::vector<uint8_t> sender_share(membership_bits.size(), 0);
    for (size_t i = 0; i < membership_bits.size(); ++i) {
      sender_share[i] = static_cast<uint8_t>((membership_bits[i] & 1U) ^
                                             (receiver_share[i] & 1U));
    }
    if (!receiver_share.empty()) {
      lctxs[1]->SendAsync(
          lctxs[1]->PrevRank(),
          upsu::Bytes(receiver_share.data(), receiver_share.size()),
          kOteReceiverShareTag);
    } else {
      static const char kEmpty = 0;
      lctxs[1]->SendAsync(lctxs[1]->PrevRank(), upsu::Bytes(&kEmpty, 0),
                          kOteReceiverShareTag);
    }
    auto y_values = EncodeItemsForFinalOte(y);
    auto ote_result =
        ote::RunEqValueSenderRole(lctxs[1], y_values, sender_share);
    auto online_end = std::chrono::high_resolution_clock::now();
    run.online_s =
        std::chrono::duration<double>(online_end - online_start).count();
    run.ote_bytes = ote_result.bytes;
    run.ote_backend = ote_result.backend;
    run.intersection_cardinality = static_cast<size_t>(std::count_if(
        membership_bits.begin(), membership_bits.end(),
        [](uint8_t bit) { return (bit & 1U) != 0U; }));
    run.true_intersection = std::min(std::min(cap, ny), nx);
    return run;
  });

  auto sender_run = sender_fut.get();
  auto receiver_run = receiver_fut.get();
  auto sender_stats = lctxs[0]->GetStats();
  const size_t sender_peqt_local_comm_bytes =
      sender_run.online_stats.peqt_local_sent_bytes +
      sender_run.online_stats.peqt_local_recv_bytes;
  const size_t receiver_peqt_local_comm_bytes =
      receiver_run.online_stats.peqt_local_sent_bytes +
      receiver_run.online_stats.peqt_local_recv_bytes;
  const size_t sender_peqt_setup_local_comm_bytes =
      sender_run.online_stats.peqt_setup_local_sent_bytes +
      sender_run.online_stats.peqt_setup_local_recv_bytes;
  const size_t receiver_peqt_setup_local_comm_bytes =
      receiver_run.online_stats.peqt_setup_local_sent_bytes +
      receiver_run.online_stats.peqt_setup_local_recv_bytes;
  const size_t peqt_setup_local_comm_bytes =
      std::max(sender_peqt_setup_local_comm_bytes,
               receiver_peqt_setup_local_comm_bytes);
  const size_t peqt_local_comm_bytes =
      std::max(sender_peqt_local_comm_bytes, receiver_peqt_local_comm_bytes);
  const size_t sender_peqt_comm_bytes =
      sender_peqt_local_comm_bytes + sender_run.online_stats.peqt_link_sent_bytes +
      sender_run.online_stats.peqt_link_recv_bytes;
  const size_t receiver_peqt_comm_bytes =
      receiver_peqt_local_comm_bytes +
      receiver_run.online_stats.peqt_link_sent_bytes +
      receiver_run.online_stats.peqt_link_recv_bytes;
  const size_t peqt_comm_bytes =
      std::max(sender_peqt_comm_bytes, receiver_peqt_comm_bytes);
  const size_t total_link_comm_bytes =
      sender_stats->sent_bytes.load() + sender_stats->recv_bytes.load();
  const size_t perm_setup_comm_bytes =
      std::max(sender_run.online_stats.perm_setup_bytes,
               receiver_run.online_stats.perm_setup_bytes);
  const size_t perm_apply_comm_bytes =
      std::max(sender_run.online_stats.perm_apply_bytes,
               receiver_run.online_stats.perm_apply_bytes);
  const size_t online_link_comm_bytes =
      (total_link_comm_bytes >= fhe_key_comm_bytes)
          ? (total_link_comm_bytes - fhe_key_comm_bytes)
          : 0;
  const size_t counted_ote_comm_bytes = std::max(
      sender_run.ote_backend == ote::Backend::kSilent ? size_t{0}
                                                      : sender_run.ote_bytes,
      receiver_run.ote_backend == ote::Backend::kSilent ? size_t{0}
                                                        : receiver_run.ote_bytes);
  const size_t online_comm_bytes =
      online_link_comm_bytes + peqt_local_comm_bytes + counted_ote_comm_bytes +
      perm_apply_comm_bytes;
  const size_t total_comm_bytes =
      total_link_comm_bytes + peqt_setup_local_comm_bytes +
      peqt_local_comm_bytes + counted_ote_comm_bytes +
      perm_setup_comm_bytes + perm_apply_comm_bytes;

  metrics.success = true;
  metrics.correct = sender_run.union_cardinality == sender_run.true_union &&
                    receiver_run.intersection_cardinality ==
                        receiver_run.true_intersection;
  metrics.sender_result = sender_run.union_cardinality;
  metrics.sender_truth = sender_run.true_union;
  metrics.receiver_result = receiver_run.intersection_cardinality;
  metrics.receiver_truth = receiver_run.true_intersection;
  metrics.total_comm_bytes = total_comm_bytes;
  metrics.online_comm_bytes = online_comm_bytes;
  metrics.fhe_key_comm_bytes = fhe_key_comm_bytes;
  metrics.peqt_comm_bytes = peqt_comm_bytes;
  metrics.ote_bytes = counted_ote_comm_bytes;
  metrics.sender_offline_s = sender_run.sender_offline_s;
  metrics.setup_time_s =
      std::max(sender_run.online_stats.setup_time_s,
               receiver_run.online_stats.setup_time_s);
  metrics.online_s =
      std::max(0.0, std::max(sender_run.online_s, receiver_run.online_s) -
                           metrics.setup_time_s);
  metrics.peqt_time_s =
      std::max(sender_run.online_stats.peqt_time_s,
               receiver_run.online_stats.peqt_time_s) +
      std::max(sender_run.online_stats.peqt_setup_time_s,
               receiver_run.online_stats.peqt_setup_time_s);
  return metrics;
}


void RunBenchmark(const std::string& protocol_name, size_t nx, size_t ny,
                  size_t intersection_size) {
  std::cout << "\n>>> Benchmark: " << protocol_name << std::endl;
  std::cout << "    |X|=" << nx << ", |Y|=" << ny
            << ", |X∩Y|=" << intersection_size << std::endl;

  auto x = CreateRangeItems(0, nx);
  auto y = CreateRangeItems(nx - intersection_size, ny);

  size_t true_card = TrueIntersectionSize(x, y);

  auto lctxs = upsu::net::Context::SetupWorld(2);
  lctxs[0]->SetRecvTimeout(600000);
  lctxs[1]->SetRecvTimeout(600000);

  ProtocolParams params;
  ConfigureReferenceParams(&params, nx, ny);
  params.reveal_match_items = true;
  if (const char* depth_env = std::getenv("PSU_QUERY_DEPTH")) {
    params.query_powers_max_depth = static_cast<size_t>(std::strtoull(depth_env, nullptr, 10));
  }
  const bool timing_only = EnvFlagEnabled("PSU_SYNTHETIC_ONLINE");
  const size_t fhe_key_comm_bytes = EstimateFheKeyCommBytes(params);

  std::shared_ptr<PreparedSender> prepared;
  auto sender_offline_start = std::chrono::high_resolution_clock::now();
  prepared = PrepareSender(x, params);
  MaterializeSenderOnlineCache(prepared, params);
  auto sender_offline_end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> sender_offline_elapsed =
      sender_offline_end - sender_offline_start;
  std::vector<std::string>().swap(x);

  auto online_start = std::chrono::high_resolution_clock::now();

  size_t result = 0;
  std::vector<std::string> intersection;
  OnlineStats sender_online_stats;
  OnlineStats receiver_online_stats;
  std::future<void> sender_fut =
      std::async(std::launch::async, [&] {
        SendPrepared(lctxs[0], prepared, params, &sender_online_stats);
      });
  std::future<std::vector<std::string>> recv_fut =
      std::async(std::launch::async, [&]() {
        return RecvItems(lctxs[1], y, params, &receiver_online_stats);
      });
  sender_fut.get();
  intersection = recv_fut.get();
  result = intersection.size();

  auto online_end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> online_elapsed = online_end - online_start;
  const double online_wall_s = online_elapsed.count();
  const double setup_time_s =
      std::max(sender_online_stats.setup_time_s, receiver_online_stats.setup_time_s);
  const double perm_setup_time_s = std::max(
      sender_online_stats.perm_setup_time_s,
      receiver_online_stats.perm_setup_time_s);
  const double peqt_setup_time_s = std::max(
      sender_online_stats.peqt_setup_time_s,
      receiver_online_stats.peqt_setup_time_s);
  const double online_time_s = std::max(0.0, online_wall_s - setup_time_s);
  const double perm_apply_time_s = std::max(
      sender_online_stats.perm_apply_time_s,
      receiver_online_stats.perm_apply_time_s);
  const double peqt_time_s =
      std::max(sender_online_stats.peqt_time_s, receiver_online_stats.peqt_time_s);
  const size_t perm_setup_comm_bytes =
      std::max(sender_online_stats.perm_setup_bytes,
               receiver_online_stats.perm_setup_bytes);
  const size_t perm_apply_comm_bytes =
      std::max(sender_online_stats.perm_apply_bytes,
               receiver_online_stats.perm_apply_bytes);
  const size_t sender_peqt_local_comm_bytes =
      sender_online_stats.peqt_local_sent_bytes +
      sender_online_stats.peqt_local_recv_bytes;
  const size_t receiver_peqt_local_comm_bytes =
      receiver_online_stats.peqt_local_sent_bytes +
      receiver_online_stats.peqt_local_recv_bytes;
  const size_t sender_peqt_setup_local_comm_bytes =
      sender_online_stats.peqt_setup_local_sent_bytes +
      sender_online_stats.peqt_setup_local_recv_bytes;
  const size_t receiver_peqt_setup_local_comm_bytes =
      receiver_online_stats.peqt_setup_local_sent_bytes +
      receiver_online_stats.peqt_setup_local_recv_bytes;
  const size_t peqt_setup_local_comm_bytes =
      std::max(sender_peqt_setup_local_comm_bytes,
               receiver_peqt_setup_local_comm_bytes);
  const size_t peqt_local_comm_bytes =
      std::max(sender_peqt_local_comm_bytes, receiver_peqt_local_comm_bytes);
  const size_t sender_peqt_comm_bytes =
      sender_peqt_local_comm_bytes + sender_online_stats.peqt_link_sent_bytes +
      sender_online_stats.peqt_link_recv_bytes;
  const size_t receiver_peqt_comm_bytes =
      receiver_peqt_local_comm_bytes + receiver_online_stats.peqt_link_sent_bytes +
      receiver_online_stats.peqt_link_recv_bytes;
  const size_t peqt_comm_bytes =
      std::max(sender_peqt_comm_bytes, receiver_peqt_comm_bytes);

  PrintStats(protocol_name, lctxs[0], lctxs[1], online_time_s, result,
             true_card, sender_offline_elapsed.count(),
             sender_offline_elapsed.count() + online_wall_s,
             timing_only, fhe_key_comm_bytes, setup_time_s, online_wall_s,
             perm_setup_time_s, peqt_setup_time_s, perm_apply_time_s,
             peqt_time_s, perm_setup_comm_bytes, peqt_setup_local_comm_bytes,
             perm_apply_comm_bytes, peqt_comm_bytes, peqt_local_comm_bytes);
  if (ShouldPreviewOutputItems()) {
    PrintOutputItems(intersection);
  }
}

int RunOlmtBench() {
  const size_t nx = GetEnvSize("PSU_MEDIUM_NX", size_t{1} << 16);
  const size_t ny = GetEnvSize("PSU_MEDIUM_NY", 512);
  const size_t cap = GetEnvSize("PSU_MEDIUM_CAP", 64);
  const size_t recv_timeout_ms =
      GetEnvSize("PSU_LINK_RECV_TIMEOUT_MS", size_t{600000});

  std::cout << "\n=== OSLMS Benchmark ===" << std::endl;
  std::cout << "|X|=" << nx << ", |Y|=" << ny
            << ", |X∩Y|=" << cap << std::endl;

  auto x = CreateRangeItems(0, nx);
  auto y = CreateRangeItems(nx - cap, ny);

  auto lctxs = upsu::net::Context::SetupWorld(2);
  lctxs[0]->SetRecvTimeout(recv_timeout_ms);
  lctxs[1]->SetRecvTimeout(recv_timeout_ms);

  ProtocolParams params;
  ConfigureReferenceParams(&params, nx, ny);
  params.use_dh_oprf = false;
  params.reveal_match_items = true;
  if (const char* depth_env = std::getenv("PSU_QUERY_DEPTH")) {
    params.query_powers_max_depth =
        static_cast<size_t>(std::strtoull(depth_env, nullptr, 10));
  }
  const size_t fhe_key_comm_bytes = EstimateFheKeyCommBytes(params);

  auto sender_offline_start = std::chrono::high_resolution_clock::now();
  auto prepared = PrepareSender(x, params);
  MaterializeSenderOnlineCache(prepared, params);
  auto sender_offline_end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> sender_offline_elapsed =
      sender_offline_end - sender_offline_start;

  OnlineStats sender_online_stats;
  OnlineStats receiver_online_stats;
  std::vector<uint8_t> sender_choice_share;
  OlmtReceiverOutput receiver_output;

  auto online_start = std::chrono::high_resolution_clock::now();
  std::future<void> sender_fut = std::async(std::launch::async, [&] {
    sender_choice_share =
        RunOlmtSender(lctxs[0], prepared, params, &sender_online_stats);
  });
  std::future<void> receiver_fut = std::async(std::launch::async, [&] {
    receiver_output = RunOlmtReceiver(lctxs[1], y, params,
                                      &receiver_online_stats);
  });
  sender_fut.get();
  receiver_fut.get();
  auto online_end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> online_elapsed = online_end - online_start;
  const double online_wall_s = online_elapsed.count();

  UPSU_ENFORCE(sender_choice_share.size() == receiver_output.choice_share.size(),
               "OSLMS share size mismatch: got {} and {}",
               sender_choice_share.size(), receiver_output.choice_share.size());
  UPSU_ENFORCE(sender_choice_share.size() == receiver_output.aligned_values.size(),
               "OSLMS value size mismatch: got {} shares and {} values",
               sender_choice_share.size(), receiver_output.aligned_values.size());

  std::vector<uint64_t> recovered_values;
  recovered_values.reserve(receiver_output.aligned_values.size());
  for (size_t i = 0; i < sender_choice_share.size(); ++i) {
    const uint8_t match =
        static_cast<uint8_t>((sender_choice_share[i] ^
                              receiver_output.choice_share[i]) &
                             1U);
    const uint64_t value = receiver_output.aligned_values[i];
    if (match == 0 && value != 0) {
      recovered_values.push_back(value);
    }
  }
  std::sort(recovered_values.begin(), recovered_values.end());
  recovered_values.erase(
      std::unique(recovered_values.begin(), recovered_values.end()),
      recovered_values.end());

  auto expected_values = EncodeItemsForFinalOte(y);
  std::vector<uint64_t> expected_non_members;
  expected_non_members.reserve(expected_values.size());
  for (size_t i = 0; i < y.size(); ++i) {
    if (static_cast<size_t>(std::strtoull(y[i].c_str(), nullptr, 10)) >= nx) {
      expected_non_members.push_back(expected_values[i]);
    }
  }
  std::sort(expected_non_members.begin(), expected_non_members.end());

  const bool correct = (recovered_values == expected_non_members);
  const double setup_time_s =
      std::max(sender_online_stats.setup_time_s,
               receiver_online_stats.setup_time_s);
  const double perm_setup_time_s =
      std::max(sender_online_stats.perm_setup_time_s,
               receiver_online_stats.perm_setup_time_s);
  const double peqt_setup_time_s =
      std::max(sender_online_stats.peqt_setup_time_s,
               receiver_online_stats.peqt_setup_time_s);
  const double perm_apply_time_s =
      std::max(sender_online_stats.perm_apply_time_s,
               receiver_online_stats.perm_apply_time_s);
  const double peqt_time_s =
      std::max(sender_online_stats.peqt_time_s,
               receiver_online_stats.peqt_time_s);
  const double online_time_s = std::max(0.0, online_wall_s - setup_time_s);

  const size_t perm_setup_comm_bytes =
      std::max(sender_online_stats.perm_setup_bytes,
               receiver_online_stats.perm_setup_bytes);
  const size_t perm_apply_comm_bytes =
      std::max(sender_online_stats.perm_apply_bytes,
               receiver_online_stats.perm_apply_bytes);
  const size_t sender_peqt_setup_local_comm_bytes =
      sender_online_stats.peqt_setup_local_sent_bytes +
      sender_online_stats.peqt_setup_local_recv_bytes;
  const size_t receiver_peqt_setup_local_comm_bytes =
      receiver_online_stats.peqt_setup_local_sent_bytes +
      receiver_online_stats.peqt_setup_local_recv_bytes;
  const size_t peqt_setup_local_comm_bytes =
      std::max(sender_peqt_setup_local_comm_bytes,
               receiver_peqt_setup_local_comm_bytes);
  const size_t sender_peqt_local_comm_bytes =
      sender_online_stats.peqt_local_sent_bytes +
      sender_online_stats.peqt_local_recv_bytes;
  const size_t receiver_peqt_local_comm_bytes =
      receiver_online_stats.peqt_local_sent_bytes +
      receiver_online_stats.peqt_local_recv_bytes;
  const size_t peqt_local_comm_bytes =
      std::max(sender_peqt_local_comm_bytes, receiver_peqt_local_comm_bytes);
  const size_t sender_peqt_comm_bytes =
      sender_peqt_local_comm_bytes + sender_online_stats.peqt_link_sent_bytes +
      sender_online_stats.peqt_link_recv_bytes;
  const size_t receiver_peqt_comm_bytes =
      receiver_peqt_local_comm_bytes +
      receiver_online_stats.peqt_link_sent_bytes +
      receiver_online_stats.peqt_link_recv_bytes;
  const size_t peqt_comm_bytes =
      std::max(sender_peqt_comm_bytes, receiver_peqt_comm_bytes);

  PrintStats("OSLMS (module benchmark)", lctxs[0], lctxs[1], online_time_s,
             recovered_values.size(), expected_non_members.size(),
             sender_offline_elapsed.count(),
             sender_offline_elapsed.count() + online_wall_s, false,
             fhe_key_comm_bytes, setup_time_s, online_wall_s,
             perm_setup_time_s, peqt_setup_time_s, perm_apply_time_s,
             peqt_time_s, perm_setup_comm_bytes, peqt_setup_local_comm_bytes,
             perm_apply_comm_bytes, peqt_comm_bytes, peqt_local_comm_bytes, 0);
  std::cout << "  OSLMS exact values: " << (correct ? "yes" : "no")
            << std::endl;
  return correct ? 0 : 1;
}

std::shared_ptr<upsu::net::Context> MakeBrpcLink(const std::string& parties,
                                                  size_t rank) {
  auto hosts = SplitCsv(parties);
  if (hosts.size() != 2) {
    throw std::invalid_argument("PSU_PARTIES must have exactly 2 hosts");
  }

  const uint64_t timeout_ms =
      GetEnvSize("PSU_LINK_RECV_TIMEOUT_MS", 10 * 60 * 1000);
  return upsu::net::Context::Connect(hosts, rank, timeout_ms);
}

int RunDistributedRole() {
  const std::string mode = GetEnvString("PSU_MODE", "benchmark");
  const bool is_receiver = (mode == "receiver");
  const bool is_sender = (mode == "sender");
  if (!is_receiver && !is_sender) {
    return -1;
  }

  const size_t rank = is_receiver ? 0 : 1;
  const std::string parties =
      GetEnvString("PSU_PARTIES", "127.0.0.1:9300,127.0.0.1:9301");
  const size_t nx = GetEnvSize("PSU_MEDIUM_NX", size_t{1} << 16);
  const size_t ny = GetEnvSize("PSU_MEDIUM_NY", 512);
  const size_t cap = GetEnvSize("PSU_MEDIUM_CAP", 64);
  const bool timing_only = EnvFlagEnabled("PSU_SYNTHETIC_ONLINE");
  const size_t configured_threads = GetEnvSize(
      "PSU_THREADS",
      static_cast<size_t>(upsu::intraop_default_num_threads()));
  const int offline_thread_count = static_cast<int>(
      GetEnvSize("PSU_OFFLINE_THREADS", configured_threads));
  const int online_thread_count = static_cast<int>(
      GetEnvSize("PSU_ONLINE_THREADS", configured_threads));

  ProtocolParams params;
  ConfigureReferenceParams(&params, nx, ny);
  params.reveal_match_items = true;
  if (const char* depth_env = std::getenv("PSU_QUERY_DEPTH")) {
    params.query_powers_max_depth =
        static_cast<size_t>(std::strtoull(depth_env, nullptr, 10));
  }

  std::cout << "\n=== Distributed Two-Party Mode ===" << std::endl;
  std::cout << "Mode: " << (is_receiver ? "receiver" : "sender")
            << ", protocol: "
            << ProtocolOutputName()
            << ", parties: " << parties << std::endl;
  std::cout << "|X|=" << nx << ", |Y|=" << ny << ", |X∩Y|=" << cap
            << std::endl;
  const size_t fhe_key_comm_bytes = EstimateFheKeyCommBytes(params);
  auto ctx = MakeBrpcLink(parties, rank);
  constexpr char kReadyTag[] = "UPSI:ready";

  if (is_receiver) {
    auto x = CreateRangeItems(0, nx);
    auto sender_offline_start = std::chrono::high_resolution_clock::now();
    upsu::set_num_threads(offline_thread_count);
    auto prepared = PrepareSender(x, params);
    MaterializeSenderOnlineCache(prepared, params);
    auto sender_offline_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> sender_offline_elapsed =
        sender_offline_end - sender_offline_start;

    upsu::set_num_threads(online_thread_count);
    const char ready = 1;
    ctx->SendAsync(ctx->NextRank(), upsu::Bytes(&ready, 1),
                   kReadyTag);
    OnlineStats sender_online_stats;
    auto online_start = std::chrono::high_resolution_clock::now();
    auto receiver_share =
        SendPreparedDirectOteChoices(ctx, prepared, params, &sender_online_stats);
    auto ote_result = ote::RunEqValueReceiverRole(ctx, receiver_share);
    auto online_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> online_elapsed = online_end - online_start;
    const double online_wall_s = online_elapsed.count();
    const double setup_time_s = sender_online_stats.setup_time_s;
    const double perm_setup_time_s = sender_online_stats.perm_setup_time_s;
    const double peqt_setup_time_s = sender_online_stats.peqt_setup_time_s;
    const double online_time_s = std::max(0.0, online_wall_s - setup_time_s);
    const double perm_apply_time_s = sender_online_stats.perm_apply_time_s;
    const size_t perm_setup_comm_bytes = sender_online_stats.perm_setup_bytes;
    const size_t peqt_setup_comm_bytes =
        sender_online_stats.peqt_setup_local_sent_bytes +
        sender_online_stats.peqt_setup_local_recv_bytes;
    const size_t perm_apply_comm_bytes = sender_online_stats.perm_apply_bytes;
    const size_t peqt_local_comm_bytes =
        sender_online_stats.peqt_local_sent_bytes +
        sender_online_stats.peqt_local_recv_bytes;
    const size_t peqt_comm_bytes =
        peqt_local_comm_bytes + sender_online_stats.peqt_link_sent_bytes +
        sender_online_stats.peqt_link_recv_bytes;
    const size_t recovered_y_unique = static_cast<size_t>(std::count_if(
        ote_result.values.begin(), ote_result.values.end(),
        [](uint64_t v) { return v != 0; }));
    const size_t union_cardinality = nx + recovered_y_unique;
    const size_t true_intersection = std::min(std::min(cap, ny), nx);
    const size_t true_union = nx + ny - true_intersection;

    PrintSinglePartyStats(
        std::string("PolyLinks-") +
            ProtocolOutputName() +
            " (distributed)",
        "receiver", ctx, online_time_s, union_cardinality, true_union,
        sender_offline_elapsed.count(),
        sender_offline_elapsed.count() + online_wall_s, timing_only,
        fhe_key_comm_bytes, setup_time_s, online_wall_s,
        sender_online_stats.peqt_time_s, perm_setup_time_s, peqt_setup_time_s,
        perm_apply_time_s, perm_setup_comm_bytes, peqt_setup_comm_bytes,
        perm_apply_comm_bytes,
        peqt_comm_bytes,
        peqt_local_comm_bytes,
        ote_result.backend == ote::Backend::kSilent ? size_t{0}
                                                    : ote_result.bytes);
    std::cout << "  PSU OTE backend:   " << ote::OteBackendName(ote_result.backend)
              << std::endl;
    std::cout << "  PSU OTE bytes:     " << ote_result.bytes << std::endl;
    std::cout << "  PSU OTE time:      " << ote_result.time_s << " s"
              << std::endl;
    if (ote_result.backend == ote::Backend::kSilent) {
      std::cout << "  NOTE: silent OTE bytes are out-of-band and not included in"
                   " link comm stats"
                << std::endl;
    }
    return 0;
  }

  auto y = CreateRangeItems(nx - cap, ny);
  auto ready_buf = ctx->Recv(ctx->PrevRank(), kReadyTag);
  (void)ready_buf;
  OnlineStats receiver_online_stats;
  auto online_start = std::chrono::high_resolution_clock::now();
  auto direct_ote_inputs =
      RecvDirectOteSenderInputs(ctx, y, params, &receiver_online_stats);
  auto ote_result = ote::RunEqValueSenderRole(
      ctx, direct_ote_inputs.sender_values, direct_ote_inputs.sender_share);
  auto online_end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> online_elapsed = online_end - online_start;
  const double online_wall_s = online_elapsed.count();
  const double setup_time_s = receiver_online_stats.setup_time_s;
  const double perm_setup_time_s = receiver_online_stats.perm_setup_time_s;
  const double peqt_setup_time_s = receiver_online_stats.peqt_setup_time_s;
  const double online_time_s = std::max(0.0, online_wall_s - setup_time_s);
  const double perm_apply_time_s = receiver_online_stats.perm_apply_time_s;
  const size_t perm_setup_comm_bytes = receiver_online_stats.perm_setup_bytes;
  const size_t peqt_setup_comm_bytes =
      receiver_online_stats.peqt_setup_local_sent_bytes +
      receiver_online_stats.peqt_setup_local_recv_bytes;
  const size_t perm_apply_comm_bytes = receiver_online_stats.perm_apply_bytes;
  const size_t peqt_local_comm_bytes =
      receiver_online_stats.peqt_local_sent_bytes +
      receiver_online_stats.peqt_local_recv_bytes;
  const size_t peqt_comm_bytes =
      peqt_local_comm_bytes + receiver_online_stats.peqt_link_sent_bytes +
      receiver_online_stats.peqt_link_recv_bytes;

  PrintSinglePartyStats(
      std::string("PolyLinks-") +
          ProtocolOutputName() +
          " (distributed)",
      "sender", ctx, online_time_s, std::nullopt, std::nullopt, -1.0,
      -1.0, timing_only, fhe_key_comm_bytes, setup_time_s, online_wall_s,
      receiver_online_stats.peqt_time_s, perm_setup_time_s, peqt_setup_time_s,
      perm_apply_time_s, perm_setup_comm_bytes, peqt_setup_comm_bytes,
      perm_apply_comm_bytes, peqt_comm_bytes,
      peqt_local_comm_bytes,
      ote_result.backend == ote::Backend::kSilent ? size_t{0}
                                                  : ote_result.bytes);
  std::cout << "  PSU OTE backend:   " << ote::OteBackendName(ote_result.backend)
            << std::endl;
  std::cout << "  PSU OTE bytes:     " << ote_result.bytes << std::endl;
  std::cout << "  PSU OTE time:      " << ote_result.time_s << " s"
            << std::endl;
  if (ote_result.backend == ote::Backend::kSilent) {
    std::cout << "  NOTE: silent OTE bytes are out-of-band and not included in"
                 " link comm stats"
              << std::endl;
  }
  return 0;
}

int RunOlmtDistributedRole() {
  const std::string mode = GetEnvString("PSU_MODE", "benchmark");
  const bool is_receiver =
      (mode == "olmt-receiver" || mode == "olmt_receiver");
  const bool is_sender =
      (mode == "olmt-sender" || mode == "olmt_sender");
  if (!is_receiver && !is_sender) {
    return -1;
  }

  const size_t rank = is_receiver ? 0 : 1;
  const std::string parties =
      GetEnvString("PSU_PARTIES", "127.0.0.1:9300,127.0.0.1:9301");
  const size_t nx = GetEnvSize("PSU_MEDIUM_NX", size_t{1} << 16);
  const size_t ny = GetEnvSize("PSU_MEDIUM_NY", 512);
  const size_t cap = GetEnvSize("PSU_MEDIUM_CAP", 64);
  const size_t configured_threads = GetEnvSize(
      "PSU_THREADS",
      static_cast<size_t>(upsu::intraop_default_num_threads()));
  const int offline_thread_count = static_cast<int>(
      GetEnvSize("PSU_OFFLINE_THREADS", configured_threads));
  const int online_thread_count = static_cast<int>(
      GetEnvSize("PSU_ONLINE_THREADS", configured_threads));

  ProtocolParams params;
  ConfigureReferenceParams(&params, nx, ny);
  params.use_dh_oprf = false;
  params.reveal_match_items = true;
  if (const char* depth_env = std::getenv("PSU_QUERY_DEPTH")) {
    params.query_powers_max_depth =
        static_cast<size_t>(std::strtoull(depth_env, nullptr, 10));
  }

  std::cout << "\n=== Distributed OSLMS Mode ===" << std::endl;
  std::cout << "Mode: " << (is_receiver ? "receiver" : "sender")
            << ", protocol: OSLMS"
            << ", parties: " << parties << std::endl;
  std::cout << "|X|=" << nx << ", |Y|=" << ny << ", |X∩Y|=" << cap
            << std::endl;

  auto ctx = MakeBrpcLink(parties, rank);
  constexpr char kReadyTag[] = "UPSI:olmt_ready";
  constexpr char kOlmtChoiceShareTag[] = "UPSI:olmt_choice_share";

  if (is_receiver) {
    auto x = CreateRangeItems(0, nx);
    auto sender_offline_start = std::chrono::high_resolution_clock::now();
    upsu::set_num_threads(offline_thread_count);
    auto prepared = PrepareSender(x, params);
    MaterializeSenderOnlineCache(prepared, params);
    auto sender_offline_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> sender_offline_elapsed =
        sender_offline_end - sender_offline_start;

    upsu::set_num_threads(online_thread_count);
    const char ready = 1;
    ctx->SendAsync(ctx->NextRank(), upsu::Bytes(&ready, 1),
                   kReadyTag);

    OnlineStats sender_online_stats;
    std::vector<uint8_t> sender_choice_share;
    auto online_start = std::chrono::high_resolution_clock::now();
    sender_choice_share =
        RunOlmtSender(ctx, prepared, params, &sender_online_stats);
    auto online_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> online_elapsed = online_end - online_start;
    const double online_wall_s = online_elapsed.count();
    const double setup_time_s = sender_online_stats.setup_time_s;
    const double perm_setup_time_s = sender_online_stats.perm_setup_time_s;
    const double peqt_setup_time_s = sender_online_stats.peqt_setup_time_s;
    const double online_time_s = std::max(0.0, online_wall_s - setup_time_s);
    const double perm_apply_time_s = sender_online_stats.perm_apply_time_s;
    const size_t perm_setup_comm_bytes = sender_online_stats.perm_setup_bytes;
    const size_t peqt_setup_comm_bytes =
        sender_online_stats.peqt_setup_local_sent_bytes +
        sender_online_stats.peqt_setup_local_recv_bytes;
    const size_t perm_apply_comm_bytes = sender_online_stats.perm_apply_bytes;
    const size_t peqt_local_comm_bytes =
        sender_online_stats.peqt_local_sent_bytes +
        sender_online_stats.peqt_local_recv_bytes;
    const size_t peqt_comm_bytes =
        peqt_local_comm_bytes + sender_online_stats.peqt_link_sent_bytes +
        sender_online_stats.peqt_link_recv_bytes;
    const size_t fhe_key_comm_bytes = EstimateFheKeyCommBytes(params);

    PrintSinglePartyStats(
        "OSLMS (distributed)", "receiver", ctx, online_time_s, std::nullopt,
        std::nullopt, sender_offline_elapsed.count(),
        sender_offline_elapsed.count() + online_wall_s, false,
        fhe_key_comm_bytes, setup_time_s, online_wall_s,
        sender_online_stats.peqt_time_s, perm_setup_time_s, peqt_setup_time_s,
        perm_apply_time_s, perm_setup_comm_bytes, peqt_setup_comm_bytes,
        perm_apply_comm_bytes, peqt_comm_bytes, peqt_local_comm_bytes, 0);

    if (!sender_choice_share.empty()) {
      ctx->SendAsync(ctx->NextRank(),
                     upsu::Bytes(sender_choice_share.data(),
                                             sender_choice_share.size()),
                     kOlmtChoiceShareTag);
    } else {
      static const char kEmpty = 0;
      ctx->SendAsync(ctx->NextRank(), upsu::Bytes(&kEmpty, 0),
                     kOlmtChoiceShareTag);
    }
    return 0;
  }

  auto y = CreateRangeItems(nx - cap, ny);
  auto ready_buf = ctx->Recv(ctx->PrevRank(), kReadyTag);
  (void)ready_buf;

  upsu::set_num_threads(online_thread_count);
  OnlineStats receiver_online_stats;
  OlmtReceiverOutput olmt_output;
  auto online_start = std::chrono::high_resolution_clock::now();
  olmt_output = RunOlmtReceiver(ctx, y, params, &receiver_online_stats);
  auto online_end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> online_elapsed = online_end - online_start;
  const double online_wall_s = online_elapsed.count();
  const double setup_time_s = receiver_online_stats.setup_time_s;
  const double perm_setup_time_s = receiver_online_stats.perm_setup_time_s;
  const double peqt_setup_time_s = receiver_online_stats.peqt_setup_time_s;
  const double online_time_s = std::max(0.0, online_wall_s - setup_time_s);
  const double perm_apply_time_s = receiver_online_stats.perm_apply_time_s;
  const size_t perm_setup_comm_bytes = receiver_online_stats.perm_setup_bytes;
  const size_t peqt_setup_comm_bytes =
      receiver_online_stats.peqt_setup_local_sent_bytes +
      receiver_online_stats.peqt_setup_local_recv_bytes;
  const size_t perm_apply_comm_bytes = receiver_online_stats.perm_apply_bytes;
  const size_t peqt_local_comm_bytes =
      receiver_online_stats.peqt_local_sent_bytes +
      receiver_online_stats.peqt_local_recv_bytes;
  const size_t peqt_comm_bytes =
      peqt_local_comm_bytes + receiver_online_stats.peqt_link_sent_bytes +
      receiver_online_stats.peqt_link_recv_bytes;
  const size_t fhe_key_comm_bytes = EstimateFheKeyCommBytes(params);

  PrintSinglePartyStats(
      "OSLMS (distributed)", "sender", ctx, online_time_s, std::nullopt,
      std::nullopt, -1.0, -1.0, false, fhe_key_comm_bytes, setup_time_s,
      online_wall_s, receiver_online_stats.peqt_time_s, perm_setup_time_s,
      peqt_setup_time_s, perm_apply_time_s, perm_setup_comm_bytes,
      peqt_setup_comm_bytes, perm_apply_comm_bytes, peqt_comm_bytes,
      peqt_local_comm_bytes, 0);

  auto sender_share_buf = ctx->Recv(ctx->PrevRank(), kOlmtChoiceShareTag);
  UPSU_ENFORCE(static_cast<size_t>(sender_share_buf.size()) ==
                   olmt_output.choice_share.size(),
               "OSLMS sender-share size mismatch: got {}, expect {}",
               sender_share_buf.size(), olmt_output.choice_share.size());

  std::vector<uint64_t> recovered_values;
  recovered_values.reserve(olmt_output.aligned_values.size());
  for (size_t i = 0; i < olmt_output.choice_share.size(); ++i) {
    const uint8_t sender_share =
        static_cast<const uint8_t*>(sender_share_buf.data())[i];
    const uint8_t match =
        static_cast<uint8_t>((sender_share ^ olmt_output.choice_share[i]) & 1U);
    const uint64_t value = olmt_output.aligned_values[i];
    if (match == 0 && value != 0) {
      recovered_values.push_back(value);
    }
  }
  std::sort(recovered_values.begin(), recovered_values.end());
  recovered_values.erase(
      std::unique(recovered_values.begin(), recovered_values.end()),
      recovered_values.end());

  auto expected_values = EncodeItemsForFinalOte(y);
  std::vector<uint64_t> expected_non_members;
  expected_non_members.reserve(expected_values.size());
  for (size_t i = 0; i < y.size(); ++i) {
    if (static_cast<size_t>(std::strtoull(y[i].c_str(), nullptr, 10)) >= nx) {
      expected_non_members.push_back(expected_values[i]);
    }
  }
  std::sort(expected_non_members.begin(), expected_non_members.end());

  const bool correct = (recovered_values == expected_non_members);
  std::cout << "  OSLMS non-members:  " << recovered_values.size()
            << " (true: " << expected_non_members.size() << ")"
            << (correct ? " [CORRECT]" : " [WRONG!]") << std::endl;
  std::cout << "  OSLMS exact values: " << (correct ? "yes" : "no")
            << std::endl;
  return correct ? 0 : 1;
}

int RunPrepareCacheRole() {
  std::cout << "\n=== Prepare Cache Mode Disabled ===" << std::endl;
  std::cout << "Persistent cache is disabled. The sender state is prepared "
               "in-memory during setup."
            << std::endl;
  return 1;
}

int RunOteProbe() {
  const size_t n = GetEnvSize("PSU_MEDIUM_NY", 512);
  std::cout << "\n=== OTE Backend Probe ===" << std::endl;
  std::cout << "n=" << n << " (using current fixed Y size)" << std::endl;
  std::cout << "payload_bits=" << ote::EqOtePayloadBits() << std::endl;

  auto values = upsu::RandVec<uint64_t>(n, true);
  for (auto& value : values) {
    value = ote::NormalizeEqOteValue(value);
  }
  auto sender_share = SampleRandomBits(n);
  auto receiver_share = SampleRandomBits(n);

  struct ProbeRow {
    std::string backend;
    size_t bytes = 0;
    double time_s = 0;
    bool correct = false;
  };
  std::vector<ProbeRow> rows;

  const char* original_backend_env = std::getenv("PSU_OTE_BACKEND");
  std::string original_backend = original_backend_env ? original_backend_env : "";

  for (const std::string backend : {"iknp", "softspoken", "silent"}) {
    setenv("PSU_OTE_BACKEND", backend.c_str(), 1);
    auto lctxs = upsu::net::Context::SetupWorld(2);
    lctxs[0]->SetRecvTimeout(600000);
    lctxs[1]->SetRecvTimeout(600000);

    ote::SenderResult sender_result;
    ote::ReceiverResult receiver_result;
    std::future<void> sender_fut = std::async(std::launch::async, [&]() {
      sender_result = ote::RunEqValueSenderRole(lctxs[0], values, sender_share);
    });
    std::future<void> receiver_fut = std::async(std::launch::async, [&]() {
      receiver_result = ote::RunEqValueReceiverRole(lctxs[1], receiver_share);
    });
    sender_fut.get();
    receiver_fut.get();

    bool correct = (receiver_result.values.size() == values.size());
    if (correct) {
      for (size_t i = 0; i < values.size(); ++i) {
        const uint64_t expect =
            ((sender_share[i] & 1U) == (receiver_share[i] & 1U))
                ? ote::NormalizeEqOteValue(values[i])
                : 0;
        if (receiver_result.values[i] != expect) {
          correct = false;
          break;
        }
      }
    }

    rows.push_back(ProbeRow{
        .backend = backend,
        .bytes = std::max(sender_result.bytes, receiver_result.bytes),
        .time_s = std::max(sender_result.time_s, receiver_result.time_s),
        .correct = correct,
    });
  }

  if (original_backend.empty()) {
    unsetenv("PSU_OTE_BACKEND");
  } else {
    setenv("PSU_OTE_BACKEND", original_backend.c_str(), 1);
  }

  std::sort(rows.begin(), rows.end(),
            [](const ProbeRow& a, const ProbeRow& b) { return a.bytes < b.bytes; });

  for (const auto& row : rows) {
    std::cout << "  " << row.backend << ": bytes=" << row.bytes
              << ", time=" << row.time_s << " s"
              << ", correct=" << (row.correct ? "yes" : "no") << std::endl;
  }

  UPSU_ENFORCE(!rows.empty(), "ote probe produced no results");
  UPSU_ENFORCE(rows.front().correct, "best backend failed correctness check");
  std::cout << "Best backend for n=" << n << ": " << rows.front().backend
            << std::endl;
  std::cout << "Set this for fixed use: PSU_OTE_BACKEND="
            << rows.front().backend << std::endl;
  return 0;
}

std::string JoinInts(const std::vector<int>& values) {
  std::ostringstream oss;
  for (size_t i = 0; i < values.size(); ++i) {
    if (i != 0) {
      oss << ",";
    }
    oss << values[i];
  }
  return oss.str();
}

std::vector<const char*> CandidateOverrideEnvKeys() {
  return {
      "PSU_POLY_MODULUS_DEGREE",
      "PSU_COEFF_MODULUS_BITS",
      "PSU_PLAIN_MODULUS",
      "PSU_MOD_SWITCH_STEPS",
      "PSU_QUERY_DEPTH",
      "PSU_PS_LOW_DEGREE",
      "PSU_QUERY_POWERS",
  };
}

double BytesToMB(size_t bytes) {
  return static_cast<double>(bytes) / (1024.0 * 1024.0);
}

void PrintPrimitiveBenchStats(const std::string& name,
                              const PrimitiveBenchMetrics& metrics) {
  std::cout << "\n=== " << name << " ===" << std::endl;
  std::cout << "n=" << metrics.input_size << std::endl;
  if (metrics.bit_width > 0) {
    std::cout << "bit_width=" << metrics.bit_width << std::endl;
  }
  if (metrics.block_size > 1) {
    std::cout << "block_size=" << metrics.block_size << std::endl;
  }
  if (metrics.row_bytes > 0) {
    std::cout << "row_bytes=" << metrics.row_bytes << std::endl;
  }
  std::cout << "  Setup time:        " << metrics.setup_time_s << " s"
            << std::endl;
  std::cout << "  Online time:       " << metrics.online_time_s << " s"
            << std::endl;
  std::cout << "  Setup comm:        " << BytesToMB(metrics.setup_comm_bytes)
            << " MB" << std::endl;
  std::cout << "  Online comm:       " << BytesToMB(metrics.online_comm_bytes)
            << " MB" << std::endl;
  std::cout << "  Total comm (S↔R):  " << BytesToMB(metrics.total_comm_bytes)
            << " MB" << std::endl;
  std::cout << "  Output ones:       " << metrics.result_true_count
            << " (expect: " << metrics.expected_true_count << ")"
            << (metrics.correct ? " [CORRECT]" : " [WRONG!]") << std::endl;
  std::cout << "  Correct:           "
            << (metrics.correct ? "yes" : "no") << std::endl;
}

int RunPackedZeroPrimitiveBench() {
  const size_t n = GetEnvSize("PSU_PRIMITIVE_N", size_t{1} << 11);
  const size_t bit_width = GetEnvSize("PSU_PACKED_ZERO_BITS", 48);
  const auto metrics = RunLocalPackedZeroTestBench(n, bit_width);
  PrintPrimitiveBenchStats("Packed Zero Test Benchmark", metrics);
  return metrics.correct ? 0 : 1;
}

int RunPermutationPrimitiveBench() {
  const size_t n = GetEnvSize("PSU_PRIMITIVE_N", size_t{1} << 11);
  const size_t block_size = GetEnvSize("PSU_PERM_BLOCK_SIZE", 1);
  const auto metrics = RunLocalRandomPermutationBench(n, block_size);
  PrintPrimitiveBenchStats("Random Permutation Benchmark", metrics);
  return metrics.correct ? 0 : 1;
}

std::vector<uint128_t> MakePolyInterpBenchItems(size_t point_count, size_t ks,
                                                size_t sigma2_bits,
                                                uint64_t prime,
                                                uint64_t seed) {
  const uint64_t slice_mod =
      (sigma2_bits >= 63)
          ? (prime - 1)
          : std::min<uint64_t>(prime - 1, (uint64_t{1} << sigma2_bits) - 1);
  UPSU_ENFORCE(point_count <= slice_mod,
               "point_count={} exceeds unique first-slice domain={}",
               point_count, slice_mod);

  std::vector<uint128_t> items;
  items.reserve(point_count);
  for (size_t i = 0; i < point_count; ++i) {
    std::vector<uint64_t> slices(ks, 0);
    slices[0] = static_cast<uint64_t>(i + 1);
    for (size_t s = 1; s < ks; ++s) {
      const uint64_t mixed =
          seed + 0x9e3779b97f4a7c15ULL * static_cast<uint64_t>(i + 1) +
          0xbf58476d1ce4e5b9ULL * static_cast<uint64_t>(s + 1);
      slices[s] = (mixed % slice_mod) + 1;
    }
    items.push_back(UnsliceItem(slices, sigma2_bits));
  }
  return items;
}

struct PolyInterpTiming {
  double avg_s = 0.0;
  double min_s = 0.0;
  size_t checksum = 0;
};

size_t BuildNewtonPolyLinkSubBinForBench(const std::vector<uint128_t>& items,
                                         size_t ks, size_t sigma2_bits,
                                         uint64_t prime) {
  if (items.empty()) {
    return ks * sizeof(uint64_t);
  }

  std::vector<std::vector<uint64_t>> slices(items.size(),
                                            std::vector<uint64_t>(ks));
  for (size_t j = 0; j < items.size(); ++j) {
    slices[j] = SliceItem(items[j], ks, sigma2_bits);
    for (size_t i = 0; i < ks; ++i) {
      slices[j][i] %= prime;
    }
  }

  std::vector<uint64_t> first_slices(items.size());
  for (size_t j = 0; j < items.size(); ++j) {
    first_slices[j] = slices[j][0];
  }

  size_t bytes = 0;
  for (size_t i = 1; i < ks; ++i) {
    std::vector<uint64_t> tag_values(items.size());
    for (size_t j = 0; j < items.size(); ++j) {
      tag_values[j] = slices[j][i];
    }
    const auto coeffs =
        upsu::NewtonInterpolate(first_slices, tag_values, prime);
    bytes += coeffs.size() * sizeof(uint64_t);
  }
  return bytes;
}

PolyInterpTiming TimePolyInterpMethod(
    const std::vector<std::vector<uint128_t>>& item_batches, size_t ks,
    size_t sigma2_bits, uint64_t prime, bool use_fast, size_t warmup,
    size_t trials) {
  UPSU_ENFORCE(!item_batches.empty(), "item_batches must not be empty");
  size_t checksum = 0;
  for (size_t i = 0; i < warmup; ++i) {
    std::vector<size_t> local_checks(item_batches.size(), 0);
    upsu::parallel_for(0, static_cast<int64_t>(item_batches.size()),
                       [&](int64_t begin, int64_t end) {
      for (int64_t batch_idx = begin; batch_idx < end; ++batch_idx) {
        if (use_fast) {
          auto sub_bin = BuildPolyLinkSubBin(
              item_batches[static_cast<size_t>(batch_idx)], ks, sigma2_bits,
              prime, true);
          local_checks[static_cast<size_t>(batch_idx)] =
              EstimatePolyLinkStorageBytes(sub_bin) + sub_bin.poly_coeffs.size();
        } else {
          local_checks[static_cast<size_t>(batch_idx)] =
              BuildNewtonPolyLinkSubBinForBench(
                  item_batches[static_cast<size_t>(batch_idx)], ks,
                  sigma2_bits, prime);
        }
      }
    });
    for (size_t value : local_checks) {
      checksum ^= value;
    }
  }

  double total_s = 0.0;
  double min_s = 0.0;
  for (size_t i = 0; i < trials; ++i) {
    std::vector<size_t> local_checks(item_batches.size(), 0);
    const auto begin = std::chrono::high_resolution_clock::now();
    upsu::parallel_for(0, static_cast<int64_t>(item_batches.size()),
                       [&](int64_t begin_idx, int64_t end_idx) {
      for (int64_t batch_idx = begin_idx; batch_idx < end_idx; ++batch_idx) {
        if (use_fast) {
          auto sub_bin = BuildPolyLinkSubBin(
              item_batches[static_cast<size_t>(batch_idx)], ks, sigma2_bits,
              prime, true);
          local_checks[static_cast<size_t>(batch_idx)] =
              EstimatePolyLinkStorageBytes(sub_bin) + sub_bin.poly_coeffs.size();
        } else {
          local_checks[static_cast<size_t>(batch_idx)] =
              BuildNewtonPolyLinkSubBinForBench(
                  item_batches[static_cast<size_t>(batch_idx)], ks,
                  sigma2_bits, prime);
        }
      }
    });
    const auto end = std::chrono::high_resolution_clock::now();
    const double elapsed_s = std::chrono::duration<double>(end - begin).count();
    total_s += elapsed_s;
    if (i == 0 || elapsed_s < min_s) {
      min_s = elapsed_s;
    }
    for (size_t value : local_checks) {
      checksum ^= value;
    }
  }

  return PolyInterpTiming{
      .avg_s = total_s / static_cast<double>(trials),
      .min_s = min_s,
      .checksum = checksum,
  };
}

int RunPolyInterpolationBench() {
  const size_t min_points = GetEnvSize("PSU_INTERP_MIN_POINTS", 50);
  const size_t max_points = GetEnvSize("PSU_INTERP_MAX_POINTS", 300);
  const size_t step = GetEnvSize("PSU_INTERP_STEP", 1);
  const size_t trials = GetEnvSize("PSU_INTERP_TRIALS", 20);
  const size_t warmup = GetEnvSize("PSU_INTERP_WARMUP", 3);
  const size_t jobs =
      GetEnvSize("PSU_INTERP_JOBS",
                 std::max<size_t>(1, upsu::get_num_threads()));
  const size_t ks = GetEnvSize("PSU_INTERP_KS", 4);
  const size_t sigma2_bits = GetEnvSize("PSU_INTERP_SIGMA2_BITS", 15);
  const uint64_t prime =
      static_cast<uint64_t>(GetEnvSize("PSU_INTERP_PLAIN_MODULUS", 65537));
  const uint64_t seed =
      static_cast<uint64_t>(GetEnvSize("PSU_INTERP_SEED", 1));
  const std::string output_path = GetEnvString("PSU_INTERP_OUTPUT");

  UPSU_ENFORCE(min_points > 0, "min point count must be positive");
  UPSU_ENFORCE(max_points >= min_points,
               "max_points must be >= min_points");
  UPSU_ENFORCE(step > 0, "step must be positive");
  UPSU_ENFORCE(trials > 0, "trials must be positive");
  UPSU_ENFORCE(jobs > 0, "jobs must be positive");
  UPSU_ENFORCE(ks > 1, "ks must be at least 2");
  UPSU_ENFORCE(sigma2_bits > 0 && ks * sigma2_bits <= 128,
               "invalid ks/sigma2_bits combination");

  std::ofstream output_file;
  std::ostream* out = &std::cout;
  if (!output_path.empty()) {
    output_file.open(output_path, std::ios::out | std::ios::trunc);
    UPSU_ENFORCE(output_file.good(),
                 "failed to open interpolation output file: {}", output_path);
    out = &output_file;
  }

  *out << "points,newton_avg_s,newton_min_s,fast_avg_s,fast_min_s,winner,"
       << "avg_speedup,ks,sigma2_bits,plain_modulus,trials,warmup,threads,"
       << "jobs\n";

  std::cout << "\n=== PolyLinks Interpolation Benchmark ===" << std::endl;
  std::cout << "points=" << min_points << ".." << max_points
            << ", step=" << step << ", trials=" << trials
            << ", warmup=" << warmup << ", threads=" << upsu::get_num_threads()
            << ", jobs=" << jobs << std::endl;

  for (size_t points = min_points; points <= max_points; points += step) {
    std::vector<std::vector<uint128_t>> item_batches;
    item_batches.reserve(jobs);
    for (size_t job_idx = 0; job_idx < jobs; ++job_idx) {
      item_batches.push_back(MakePolyInterpBenchItems(
          points, ks, sigma2_bits, prime, seed + job_idx * 1315423911ULL));
    }
    const auto newton = TimePolyInterpMethod(
        item_batches, ks, sigma2_bits, prime, false, warmup, trials);
    const auto fast = TimePolyInterpMethod(
        item_batches, ks, sigma2_bits, prime, true, warmup, trials);
    const bool fast_is_faster = fast.avg_s < newton.avg_s;
    const double avg_speedup =
        fast_is_faster ? (newton.avg_s / fast.avg_s)
                       : (fast.avg_s / newton.avg_s);

    *out << points << ',' << std::fixed << std::setprecision(9)
         << newton.avg_s << ',' << newton.min_s << ','
         << fast.avg_s << ',' << fast.min_s << ','
         << (fast_is_faster ? "fast" : "newton") << ','
         << avg_speedup << ',' << ks << ',' << sigma2_bits << ','
         << prime << ',' << trials << ',' << warmup << ','
         << upsu::get_num_threads() << ',' << jobs << '\n';
    out->flush();

    std::cout << "  points=" << points
              << ": newton_avg=" << newton.avg_s
              << " s, fast_avg=" << fast.avg_s << " s, winner="
              << (fast_is_faster ? "fast" : "newton") << std::endl;
  }

  if (!output_path.empty()) {
    std::cout << "CSV: " << output_path << std::endl;
  }
  return 0;
}

int RunListProfiles() {
  const auto profiles = LoadConfiguredProfiles();
  for (const auto& profile : profiles) {
    std::cout << profile << std::endl;
  }
  return 0;
}

int RunFheSweep() {
  const std::string profile = GetEnvString("PSU_PROFILE");
  const size_t nx = GetEnvSize("PSU_MEDIUM_NX", size_t{1} << 16);
  const size_t ny = GetEnvSize("PSU_MEDIUM_NY", 512);
  const size_t cap = GetEnvSize("PSU_MEDIUM_CAP", 64);
  const auto candidates = LoadConfiguredCandidateNames(profile);
  UPSU_ENFORCE(!candidates.empty(),
               "no FHE candidates configured for profile '{}'",
               profile.empty() ? "default" : profile);

  std::ofstream output_file;
  const std::string output_path =
      GetEnvString("PSU_FHE_SWEEP_OUTPUT");
  if (!output_path.empty()) {
    output_file.open(output_path, std::ios::out | std::ios::trunc);
    UPSU_ENFORCE(output_file.good(),
                 "failed to open FHE sweep output file: {}", output_path);
    output_file
        << "profile\tcandidate\tstatus\tcorrect\ttotal_comm_bytes\tonline_comm_bytes"
        << "\tfhe_key_comm_bytes\tpeqt_comm_bytes\tote_bytes\tsender_offline_s"
        << "\tsetup_time_s"
        << "\tonline_s\tpoly_modulus_degree\tcoeff_modulus_bits\tplain_modulus"
        << "\tmod_switch_steps\tquery_depth\tps_low_degree\n";
  }

  std::vector<std::pair<std::string, std::optional<std::string>>> baseline_envs;
  for (const char* name : CandidateOverrideEnvKeys()) {
    baseline_envs.emplace_back(name, GetEnvOptional(name));
  }

  struct SweepRow {
    std::string candidate;
    ProtocolParams params;
    SweepMetrics metrics;
  };
  std::vector<SweepRow> rows;

  std::cout << "\n=== FHE Sweep ===" << std::endl;
  std::cout << "Profile: " << (profile.empty() ? "(default)" : profile)
            << std::endl;
  std::cout << "|X|=" << nx << ", |Y|=" << ny << ", |X∩Y|=" << cap
            << std::endl;

  for (const auto& candidate : candidates) {
    for (const auto& [name, value] : baseline_envs) {
      SetOrUnsetEnv(name.c_str(), value);
    }
    ApplyFheCandidateBlock(candidate);

    SweepRow row;
    row.candidate = candidate;
    ConfigureReferenceParams(&row.params, nx, ny);
    if (const char* depth_env = std::getenv("PSU_QUERY_DEPTH")) {
      row.params.query_powers_max_depth =
          static_cast<size_t>(std::strtoull(depth_env, nullptr, 10));
    }

    try {
      row.metrics = RunLocalPsuOnce(nx, ny, cap, row.params);
      std::cout << "  " << candidate
                << ": total_comm_bytes=" << row.metrics.total_comm_bytes
                << ", online_s=" << row.metrics.online_s
                << ", correct=" << (row.metrics.correct ? "yes" : "no")
                << ", degree=" << row.params.poly_modulus_degree
                << ", coeff=[" << JoinInts(row.params.coeff_modulus_bits) << "]"
                << ", plain=" << row.params.plain_modulus
                << ", mod_switch=" << row.params.response_mod_switch_steps
                << std::endl;
    } catch (const std::exception& ex) {
      row.metrics.success = false;
      row.metrics.correct = false;
      row.metrics.error = ex.what();
      std::cout << "  " << candidate << ": FAILED (" << row.metrics.error
                << ")" << std::endl;
    }

    if (output_file.is_open()) {
      output_file
          << (profile.empty() ? "default" : profile) << '\t'
          << candidate << '\t'
          << (row.metrics.success ? "ok" : "failed") << '\t'
          << (row.metrics.correct ? "yes" : "no") << '\t'
          << row.metrics.total_comm_bytes << '\t'
          << row.metrics.online_comm_bytes << '\t'
          << row.metrics.fhe_key_comm_bytes << '\t'
          << row.metrics.peqt_comm_bytes << '\t'
          << row.metrics.ote_bytes << '\t'
          << row.metrics.sender_offline_s << '\t'
          << row.metrics.setup_time_s << '\t'
          << row.metrics.online_s << '\t'
          << row.params.poly_modulus_degree << '\t'
          << '"' << JoinInts(row.params.coeff_modulus_bits) << '"' << '\t'
          << row.params.plain_modulus << '\t'
          << row.params.response_mod_switch_steps << '\t'
          << row.params.query_powers_max_depth << '\t'
          << row.params.ps_low_degree << '\n';
    }
    rows.push_back(std::move(row));
  }

  for (const auto& [name, value] : baseline_envs) {
    SetOrUnsetEnv(name.c_str(), value);
  }

  std::vector<SweepRow> successful_rows;
  for (const auto& row : rows) {
    if (row.metrics.success && row.metrics.correct) {
      successful_rows.push_back(row);
    }
  }
  UPSU_ENFORCE(!successful_rows.empty(),
               "all FHE sweep candidates failed for profile '{}'",
               profile.empty() ? "default" : profile);

  std::sort(successful_rows.begin(), successful_rows.end(),
            [](const SweepRow& lhs, const SweepRow& rhs) {
              if (lhs.metrics.total_comm_bytes != rhs.metrics.total_comm_bytes) {
                return lhs.metrics.total_comm_bytes < rhs.metrics.total_comm_bytes;
              }
              return lhs.metrics.online_s < rhs.metrics.online_s;
            });

  const auto& best = successful_rows.front();
  std::cout << "Best candidate: " << best.candidate
            << " (total_comm_bytes=" << best.metrics.total_comm_bytes
            << ", degree=" << best.params.poly_modulus_degree
            << ", coeff=[" << JoinInts(best.params.coeff_modulus_bits) << "]"
            << ", plain=" << best.params.plain_modulus
            << ", mod_switch=" << best.params.response_mod_switch_steps
            << ")" << std::endl;
  if (output_file.is_open()) {
    output_file << "# best\t" << (profile.empty() ? "default" : profile) << '\t'
                << best.candidate << '\t' << best.metrics.total_comm_bytes
                << '\n';
  }
  return 0;
}

void WriteAlphaSweepHeader(std::ostream& out) {
  out << "label\ttrial\tnx\tny\tsimple_hash_bins\tsimple_hash_count"
      << "\tsigma1_bits\titem_bits\tks\tsigma2_bits\tplain_modulus"
      << "\talpha_min\tmax_items_per_bin\trequired_alpha\talpha"
      << "\tmax_bin_size\tsub_bin_size\toprf_alpha_time_s\n";
}

int RunAlphaSweep() {
  const size_t nx = GetEnvSize("PSU_MEDIUM_NX", size_t{1} << 16);
  const size_t ny = GetEnvSize("PSU_MEDIUM_NY", 512);
  const size_t trials = GetEnvSize("PSU_ALPHA_TRIALS", 1);
  const std::string profile = GetEnvString("PSU_PROFILE");
  const std::string label =
      GetEnvString("PSU_ALPHA_LABEL", profile.empty() ? "custom" : profile);
  const std::string output_path = GetEnvString("PSU_ALPHA_OUTPUT");

  ProtocolParams params;
  ConfigureReferenceParams(&params, nx, ny);

  std::ofstream output_file;
  std::ostream* out = &std::cout;
  if (!output_path.empty()) {
    output_file.open(output_path, std::ios::out | std::ios::app);
    UPSU_ENFORCE(output_file.good(),
                 "failed to open alpha output file: {}", output_path);
    out = &output_file;
  }

  if (output_path.empty() || EnvFlagEnabled("PSU_ALPHA_WRITE_HEADER")) {
    WriteAlphaSweepHeader(*out);
  }

  std::cout << "\n=== Alpha Sweep (DH-OPRF only) ===" << std::endl;
  std::cout << "label=" << label << ", |X|=" << nx << ", |Y|=" << ny
            << ", trials=" << trials << std::endl;
  std::cout << "simple_hash_bins=" << params.simple_hash_bins
            << ", sigma1_bits=" << params.sigma1_bits
            << ", ks=" << params.ks
            << ", sigma2_bits=" << params.sigma2_bits
            << ", plain_modulus=" << params.plain_modulus << std::endl;

  const auto sender_items = CreateRangeItems(0, nx);
  for (size_t trial = 1; trial <= trials; ++trial) {
    const auto begin = std::chrono::high_resolution_clock::now();
    const auto metrics = SampleAlphaAfterOprf(sender_items, ny, params);
    const auto end = std::chrono::high_resolution_clock::now();
    const double elapsed_s = std::chrono::duration<double>(end - begin).count();

    *out << label << '\t' << trial << '\t' << metrics.sender_size << '\t'
         << metrics.receiver_size << '\t' << metrics.simple_hash_bins << '\t'
         << metrics.simple_hash_count << '\t' << metrics.sigma1_bits << '\t'
         << metrics.item_bit_count << '\t' << metrics.ks << '\t'
         << metrics.sigma2_bits << '\t' << metrics.plain_modulus << '\t'
         << metrics.alpha_min << '\t' << metrics.max_items_per_bin << '\t'
         << metrics.required_alpha << '\t' << metrics.alpha << '\t'
         << metrics.max_bin_size << '\t' << metrics.sub_bin_size << '\t'
         << std::fixed << std::setprecision(6) << elapsed_s << '\n';
    out->flush();

    std::cout << "  trial " << trial << "/" << trials
              << ": required_alpha=" << metrics.required_alpha
              << ", alpha=" << metrics.alpha
              << ", B=" << metrics.max_bin_size
              << ", sub_bin_size=" << metrics.sub_bin_size
              << ", time=" << elapsed_s << " s" << std::endl;
  }

  if (!output_path.empty()) {
    std::cout << "alpha rows appended to: " << output_path << std::endl;
  }
  return 0;
}


int main() {
  ApplySettingsJson();
  const std::string mode = GetEnvString("PSU_MODE", "benchmark");
  if (mode == "list-profiles" || mode == "list_profiles") {
    return RunListProfiles();
  }
  size_t configured_threads = GetEnvSize(
      "PSU_THREADS",
      static_cast<size_t>(upsu::intraop_default_num_threads()));
  if (mode == "prepare-cache" || mode == "prepare_cache" ||
      mode == "prepare-receiver-cache" ||
      mode == "prepare_receiver_cache") {
    configured_threads = GetEnvSize("PSU_OFFLINE_THREADS",
                                    configured_threads);
  } else if (mode == "sender" || mode == "receiver") {
    const size_t online_threads =
        GetEnvSize("PSU_ONLINE_THREADS", configured_threads);
    const size_t offline_threads =
        GetEnvSize("PSU_OFFLINE_THREADS", configured_threads);
    if (mode == "receiver") {
      configured_threads = std::max(online_threads, offline_threads);
    } else {
      configured_threads = online_threads;
    }
  }
  const int thread_count = static_cast<int>(configured_threads);
  upsu::set_num_threads(thread_count);

  std::cout << "==========================================================="
            << std::endl;
  std::cout << "PSU Implementation" << std::endl;
  std::cout << "  Pipeline: PolyLinks with packed PEQT and OTE union recovery"
            << std::endl;
  std::cout << "Threads: " << upsu::get_num_threads() << std::endl;
  const std::string active_profile = GetEnvString("PSU_PROFILE");
  if (!active_profile.empty()) {
    std::cout << "Profile: " << active_profile << std::endl;
  }
  std::cout << "==========================================================="
            << std::endl;

  if (mode == "sender" || mode == "receiver") {
    return RunDistributedRole();
  }

  if (mode == "olmt-receiver" || mode == "olmt_receiver" ||
      mode == "olmt-sender" || mode == "olmt_sender") {
    return RunOlmtDistributedRole();
  }

  if (mode == "prepare-cache" || mode == "prepare_cache" ||
      mode == "prepare-receiver-cache" ||
      mode == "prepare_receiver_cache") {
    return RunPrepareCacheRole();
  }

  if (mode == "ote-probe" || mode == "ote_probe") {
    return RunOteProbe();
  }

  if (mode == "packed-zero-bench" || mode == "packed_zero_bench") {
    return RunPackedZeroPrimitiveBench();
  }

  if (mode == "perm-bench" || mode == "perm_bench" ||
      mode == "permutation-bench" || mode == "permutation_bench") {
    return RunPermutationPrimitiveBench();
  }

  if (mode == "poly-interp-bench" || mode == "poly_interp_bench" ||
      mode == "interpolation-bench" || mode == "interpolation_bench") {
    return RunPolyInterpolationBench();
  }

  if (mode == "olmt-bench" || mode == "olmt_bench") {
    return RunOlmtBench();
  }

  if (mode == "fhe-sweep" || mode == "fhe_sweep") {
    return RunFheSweep();
  }

  if (mode == "alpha-sweep" || mode == "alpha_sweep") {
    return RunAlphaSweep();
  }

  TestPolyLinks();
  {
    ProtocolParams self_test_params;
    self_test_params.Finalize();
    SelfTestWindowedPowers(self_test_params);
  }

  std::cout << "\n=== Correctness tests (small scale) ===" << std::endl;

  if (ShouldRunBenchmark(
          "PolyLinks-PSU (small: nx=1000, ny=100, cap=20)")) {
    RunBenchmark("PolyLinks-PSU (small: nx=1000, ny=100, cap=20)",
                 1000, 100, 20);
  }

  std::cout << "\n=== Medium-scale benchmarks ===" << std::endl;
  std::cout << "(Reference medium setting: nx=2^20, ny=2048)" << std::endl;

  size_t nx_med = GetEnvSize("PSU_MEDIUM_NX", size_t{1} << 16);
  size_t ny_med = GetEnvSize("PSU_MEDIUM_NY", 512);
  size_t cap_med = GetEnvSize("PSU_MEDIUM_CAP", 64);

  if (ShouldRunBenchmark("PolyLinks-PSU (medium)")) {
    RunBenchmark("PolyLinks-PSU (medium)", nx_med, ny_med, cap_med);
  }

  std::cout << "\n=== Done ===" << std::endl;
  return 0;
}

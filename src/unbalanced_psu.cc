
#include "upsu/unbalanced_psu.h"
#include "upsu/benchmark_diagnostics.h"
#include "upsu/paper_encoding.h"
#include "upsu/paper_placement.h"
#include "upsu/paper_powers.h"
#include "upsu/fused_ntt.h"
#include "upsu/common.h"
#include "upsu/net/context.h"
#include "upsu/parallel.h"
#include "upsu/item.h"
#include "upsu/serialization.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <immintrin.h>
#include <iostream>
#include <limits>
#include <numeric>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <streambuf>
#include <stdexcept>
#include <string>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <seal/seal.h>

#include "upsu/powers_dag.h"
#include "coproto/Socket/AsioSocket.h"
#include "coproto/coproto.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "upsu/polynomial_links.h"
#include "upsu/peqt.h"
#include "upsu/response_sanitizer.h"

namespace osuCrypto {

template <typename To, typename From>
inline span<To> asSpan(const span<From>& in) {
  using ToRaw = typename std::remove_const<To>::type;
  using FromRaw = typename std::remove_const<From>::type;
  static_assert(std::is_trivially_copyable<ToRaw>::value,
                "asSpan requires trivially copyable destination type");
  static_assert(std::is_trivially_copyable<FromRaw>::value,
                "asSpan requires trivially copyable source type");
  static_assert(!std::is_const<From>::value || std::is_const<To>::value,
                "asSpan cannot cast away const");

  const u64 bytes = static_cast<u64>(in.size()) * sizeof(FromRaw);
  if (bytes % sizeof(ToRaw) != 0) {
    throw std::runtime_error(LOCATION);
  }

  using ToPtr = typename std::conditional<std::is_const<To>::value,
                                          const ToRaw*, ToRaw*>::type;
  return span<To>(reinterpret_cast<ToPtr>(in.data()), bytes / sizeof(ToRaw));
}

template <typename DstT, typename SrcT>
inline void copyBytes(span<DstT> dst, span<SrcT> src) {
  using DstRaw = typename std::remove_const<DstT>::type;
  using SrcRaw = typename std::remove_const<SrcT>::type;
  static_assert(std::is_trivially_copyable<DstRaw>::value,
                "copyBytes requires trivially copyable destination");
  static_assert(std::is_trivially_copyable<SrcRaw>::value,
                "copyBytes requires trivially copyable source");

  const u64 dst_bytes = static_cast<u64>(dst.size()) * sizeof(DstRaw);
  const u64 src_bytes = static_cast<u64>(src.size()) * sizeof(SrcRaw);
  if (dst_bytes != src_bytes) {
    throw std::runtime_error(LOCATION);
  }
  if (dst_bytes != 0) {
    std::memcpy(dst.data(), src.data(), static_cast<size_t>(dst_bytes));
  }
}

template <typename T>
inline void setBytes(span<T> dst, int value) {
  using Raw = typename std::remove_const<T>::type;
  static_assert(std::is_trivially_copyable<Raw>::value,
                "setBytes requires trivially copyable destination");
  const u64 bytes = static_cast<u64>(dst.size()) * sizeof(Raw);
  if (bytes != 0) {
    std::memset(dst.data(), value, static_cast<size_t>(bytes));
  }
}

template <typename T>
inline void setBytes(T& dst, int value) {
  static_assert(std::is_trivially_copyable<T>::value,
                "setBytes requires trivially copyable destination");
  std::memset(&dst, value, sizeof(T));
}

}

#include "secure-join/CorGenerator/CorGenerator.h"
#include "secure-join/Perm/AltModPerm.h"

namespace psu {

namespace {

constexpr const char* kMetaTag = "UPSI:meta";
constexpr const char* kPublicKeyTag = "UPSI:fhe_pk";
constexpr const char* kRelinKeysTag = "UPSI:fhe_relin";
constexpr const char* kQueryCiphertextTag = "UPSI:query_cts";
constexpr const char* kEvalCiphertextTag = "UPSI:eval_cts";
constexpr const char* kPeqtShareTag = "UPSI:peqt_shares";

bool TraceEnabled() {
  static const bool enabled = []() {
    const char* value = std::getenv("PSU_TRACE");
    if (!value || !*value) {
      return false;
    }
    std::string lowered(value);
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::tolower);
    return lowered != "0" && lowered != "false" && lowered != "no" &&
           lowered != "off";
  }();
  return enabled;
}

bool SyntheticOnlineEnabled() {
  static const bool enabled = []() {
    const char* value = std::getenv("PSU_SYNTHETIC_ONLINE");
    if (!value || !*value) {
      return false;
    }
    std::string lowered(value);
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::tolower);
    return lowered != "0" && lowered != "false" && lowered != "no" &&
           lowered != "off";
  }();
  return enabled;
}

bool NttPlainEvalEnabled() {
  const char* value = std::getenv("PSU_NTT_PLAIN_EVAL");
  if (!value || !*value) {
    return true;
  }
  std::string lowered(value);
  std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::tolower);
  return lowered != "0" && lowered != "false" && lowered != "no" &&
         lowered != "off";
}

size_t FieldBitWidth(uint64_t prime) {
  size_t bits = 0;
  uint64_t value = prime - 1;
  while (value > 0) {
    ++bits;
    value >>= 1;
  }
  return std::max<size_t>(1, bits);
}

uint128_t PackFieldElements(const std::vector<uint64_t>& elems,
                            size_t elem_bit_width) {
  UPSU_ENFORCE(elem_bit_width > 0, "elem_bit_width must be positive");
  UPSU_ENFORCE(elems.size() * elem_bit_width <= 128,
               "packed field elements exceed 128 bits: count={} width={}",
               elems.size(), elem_bit_width);
  uint128_t packed = 0;
  for (size_t i = 0; i < elems.size(); ++i) {
    packed |= (uint128_t(elems[i]) << (i * elem_bit_width));
  }
  return packed;
}

std::vector<uint128_t> EncodeItemsForFinalOteImpl(
    const std::vector<std::string>& items) {
  std::vector<uint128_t> out(items.size(), 0);
  upsu::parallel_for(
      0, static_cast<int64_t>(items.size()),
      [&](int64_t begin, int64_t end) {
        for (int64_t idx = begin; idx < end; ++idx) {
          const std::string& item = items[static_cast<size_t>(idx)];
          out[static_cast<size_t>(idx)] = upsu::ParseItem(item);
        }
      });
  return out;
}

uint128_t MaskBits(uint128_t value, size_t bit_count);

std::vector<uint128_t> EncodeItemsAsProtocolTokens(
    const std::vector<std::string>& items, size_t bit_count) {
  UPSU_ENFORCE(bit_count > 0 && bit_count <= 128,
               "bit_count must be in [1, 128], got {}", bit_count);
  std::vector<uint128_t> out(items.size(), 0);
  upsu::parallel_for(
      0, static_cast<int64_t>(items.size()),
      [&](int64_t begin, int64_t end) {
        for (int64_t idx = begin; idx < end; ++idx) {
          const std::string& item = items[static_cast<size_t>(idx)];
          const uint128_t hashed =
              upsu::Hash128(upsu::Bytes(
                  item.data(), item.size()));
          out[static_cast<size_t>(idx)] = MaskBits(hashed, bit_count);
        }
      });
  return out;
}

bool CircuitPeqtEnabled(const ProtocolParams& params) {
  return params.use_circuit_peqt;
}

size_t OutputSliceBegin(const ProtocolParams& params) {
  return params.drop_first_poly ? 1 : 0;
}

size_t OutputPolyCount(const ProtocolParams& params, size_t ks) {
  const size_t begin = OutputSliceBegin(params);
  UPSU_ENFORCE(begin < ks, "drop_first_poly requires ks >= 2, got {}", ks);
  return ks - begin;
}

struct LinkCommSnapshot {
  size_t sent_bytes = 0;
  size_t recv_bytes = 0;
};

LinkCommSnapshot TakeLinkCommSnapshot(
    const std::shared_ptr<upsu::net::Context>& ctx) {
  auto stats = ctx->GetStats();
  return LinkCommSnapshot{
      .sent_bytes = stats->sent_bytes.load(),
      .recv_bytes = stats->recv_bytes.load(),
  };
}

LinkCommSnapshot DiffLinkCommSnapshot(const LinkCommSnapshot& begin,
                                      const LinkCommSnapshot& end) {
  return LinkCommSnapshot{
      .sent_bytes = end.sent_bytes - begin.sent_bytes,
      .recv_bytes = end.recv_bytes - begin.recv_bytes,
  };
}

struct LocalPeqtCommSnapshot {
  size_t sent_bytes = 0;
  size_t recv_bytes = 0;
};

struct SocketCommSnapshot {
  size_t sent_bytes = 0;
  size_t recv_bytes = 0;
};

struct PermSenderState {
  coproto::AsioSocket sock;
  secJoin::PermCorReceiver correlation;
  size_t row_bytes = 0;
};

struct PermReceiverState {
  coproto::AsioSocket sock;
  secJoin::PermCorSender correlation;
  size_t row_bytes = 0;
  size_t block_size = 1;
};

LocalPeqtCommSnapshot TakeLocalPeqtCommSnapshot(size_t rank) {
  const auto stats = peqt::GetLocalCommStats();
  return LocalPeqtCommSnapshot{
      .sent_bytes = static_cast<size_t>(stats.sent.at(rank)),
      .recv_bytes = static_cast<size_t>(stats.recv.at(rank)),
  };
}

LocalPeqtCommSnapshot DiffLocalPeqtCommSnapshot(
    const LocalPeqtCommSnapshot& begin, const LocalPeqtCommSnapshot& end) {
  return LocalPeqtCommSnapshot{
      .sent_bytes = end.sent_bytes - begin.sent_bytes,
      .recv_bytes = end.recv_bytes - begin.recv_bytes,
  };
}

SocketCommSnapshot TakeSocketCommSnapshot(coproto::Socket& sock) {
  return SocketCommSnapshot{
      .sent_bytes = sock.bytesSent(),
      .recv_bytes = sock.bytesReceived(),
  };
}

size_t TotalSocketBytesDelta(const SocketCommSnapshot& begin,
                             const SocketCommSnapshot& end) {
  return (end.sent_bytes - begin.sent_bytes) +
         (end.recv_bytes - begin.recv_bytes);
}

std::string PermBaseAddress() {
  if (const char* env = std::getenv("PSU_PERM_ADDRESS")) {
    if (*env != '\0') {
      return std::string(env);
    }
  }
  return "127.0.0.1:13015";
}

void TraceStage(const char* role, const std::string& message);

coproto::AsioSocket ConnectPermSocket(const std::string& address,
                                      bool is_listener) {
  if (is_listener) {
    return coproto::asioConnect(address, true);
  }

  constexpr int kMaxRetry = 200;
  for (int attempt = 0; attempt < kMaxRetry; ++attempt) {
    try {
      return coproto::asioConnect(address, false);
    } catch (const std::exception&) {
      if (attempt + 1 == kMaxRetry) {
        throw;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }
  UPSU_THROW("failed to connect permutation socket: {}", address);
}

bool PermutedPeqtEnabled(const ProtocolParams& params) {
  if (!CircuitPeqtEnabled(params)) {
    return false;
  }
  const char* env = std::getenv("PSU_PERMUTE_R");
  if (!env || !*env) {
    return true;
  }
  std::string lowered(env);
  std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::tolower);
  return lowered != "0" && lowered != "false" && lowered != "no" &&
         lowered != "off";
}

size_t PermThreadCount() {
  if (upsu::experiment_phase_threads_enabled()) return upsu::get_num_threads();
  const char* env = std::getenv("PSU_PERM_THREADS");
  if (!env || !*env) {
    return 1;
  }
  char* end = nullptr;
  const auto parsed = std::strtoull(env, &end, 10);
  if (end == env || *end != '\0' || parsed == 0) {
    return 1;
  }
  return static_cast<size_t>(parsed);
}

size_t PermBatchSize() {
  const char* env = std::getenv("PSU_PERM_BATCH_ROWS");
  if (!env || !*env) {
    return static_cast<size_t>(1) << 18;
  }
  char* end = nullptr;
  const auto parsed = std::strtoull(env, &end, 10);
  if (end == env || *end != '\0' || parsed == 0) {
    return static_cast<size_t>(1) << 18;
  }
  return static_cast<size_t>(parsed);
}

oc::block RandomOcBlock() {
  return oc::toBlock(upsu::SecureRandU64(), upsu::SecureRandU64());
}

size_t PackedRowBytes(size_t packed_bits) {
  return std::max<size_t>(1, (packed_bits + 7) / 8);
}

oc::Matrix<oc::u8> U128VecToByteMatrix(const std::vector<uint128_t>& values,
                                       size_t row_bytes) {
  oc::Matrix<oc::u8> matrix(values.size(), row_bytes);
  for (size_t i = 0; i < values.size(); ++i) {
    std::memcpy(matrix.data(i), &values[i], row_bytes);
  }
  return matrix;
}

std::vector<uint128_t> ByteMatrixToU128Vec(const oc::Matrix<oc::u8>& matrix,
                                           size_t row_bytes) {
  std::vector<uint128_t> values(matrix.rows(), 0);
  for (oc::u64 i = 0; i < matrix.rows(); ++i) {
    std::memcpy(&values[static_cast<size_t>(i)], matrix.data(i), row_bytes);
  }
  return values;
}

PermSenderState SetupPermutedPeqtSender(size_t row_count, size_t row_bytes,
                                        OnlineStats* online_stats) {
  const auto start = std::chrono::high_resolution_clock::now();
  PermSenderState state;
  state.row_bytes = row_bytes;
  TraceStage("perm-send", fmt::format("listening on {} for {} rows",
                                      PermBaseAddress(), row_count));
  state.sock = ConnectPermSocket(PermBaseAddress(), true);
  TraceStage("perm-send", "permutation socket connected");

  secJoin::CorGenerator cor;
  oc::PRNG cor_prng(RandomOcBlock());
  oc::PRNG gen_prng(RandomOcBlock());
  cor.init(state.sock.fork(), cor_prng, 0, PermThreadCount(), PermBatchSize(),
           false);

  secJoin::AltModPermGenReceiver generator;
  generator.init(static_cast<oc::u64>(row_count),
                 static_cast<oc::u64>(row_bytes), cor);
  generator.preprocess();
  TraceStage("perm-send", "secure-join generator initialized");

  const auto bytes_begin = TakeSocketCommSnapshot(state.sock);
  auto tasks = coproto::sync_wait(coproto::when_all_ready(
      cor.start(),
      generator.generate(gen_prng, state.sock, state.correlation)));
  std::get<0>(tasks).result();
  std::get<1>(tasks).result();
  coproto::sync_wait(state.sock.flush());
  const auto bytes_end = TakeSocketCommSnapshot(state.sock);
  const auto end = std::chrono::high_resolution_clock::now();

  if (online_stats) {
    const double elapsed = std::chrono::duration<double>(end - start).count();
    online_stats->setup_time_s += elapsed;
    online_stats->perm_setup_time_s += elapsed;
    online_stats->perm_setup_bytes +=
        TotalSocketBytesDelta(bytes_begin, bytes_end);
  }

  return state;
}

secJoin::Perm BuildBlockPermutation(size_t row_count, size_t block_size,
                                    oc::PRNG* prng) {
  UPSU_ENFORCE(block_size > 0, "block_size must be positive");
  UPSU_ENFORCE(row_count % block_size == 0,
               "row_count {} is not divisible by block_size {}",
               row_count, block_size);
  const size_t block_count = row_count / block_size;
  if (block_size == 1) {
    return secJoin::Perm(static_cast<oc::u64>(row_count), *prng);
  }

  std::vector<oc::u32> block_perm(block_count);
  std::iota(block_perm.begin(), block_perm.end(), 0U);
  for (size_t i = 0; i < block_count; ++i) {
    const size_t swap_idx =
        i + ((*prng).get<oc::u32>() % static_cast<oc::u32>(block_count - i));
    std::swap(block_perm[i], block_perm[swap_idx]);
  }

  std::vector<oc::u32> row_perm(row_count);
  for (size_t perm_block = 0; perm_block < block_count; ++perm_block) {
    const size_t orig_block = static_cast<size_t>(block_perm[perm_block]);
    for (size_t offset = 0; offset < block_size; ++offset) {
      row_perm[perm_block * block_size + offset] =
          static_cast<oc::u32>(orig_block * block_size + offset);
    }
  }
  return secJoin::Perm(static_cast<oc::u64>(row_count), std::move(row_perm));
}

PermReceiverState SetupPermutedPeqtReceiver(size_t row_count, size_t row_bytes,
                                            size_t block_size,
                                            OnlineStats* online_stats) {
  const auto start = std::chrono::high_resolution_clock::now();
  PermReceiverState state;
  state.row_bytes = row_bytes;
  state.block_size = block_size;
  TraceStage("perm-recv", fmt::format("connecting to {} for {} rows",
                                      PermBaseAddress(), row_count));
  state.sock = ConnectPermSocket(PermBaseAddress(), false);
  TraceStage("perm-recv", "permutation socket connected");

  secJoin::CorGenerator cor;
  oc::PRNG cor_prng(RandomOcBlock());
  oc::PRNG gen_prng(RandomOcBlock());
  cor.init(state.sock.fork(), cor_prng, 1, PermThreadCount(), PermBatchSize(),
           false);

  secJoin::Perm perm = BuildBlockPermutation(row_count, block_size, &gen_prng);
  secJoin::AltModPermGenSender generator;
  generator.init(static_cast<oc::u64>(row_count),
                 static_cast<oc::u64>(row_bytes), cor);
  generator.preprocess();
  TraceStage("perm-recv", "secure-join generator initialized");

  const auto bytes_begin = TakeSocketCommSnapshot(state.sock);
  auto tasks = coproto::sync_wait(coproto::when_all_ready(
      cor.start(),
      generator.generate(std::move(perm), gen_prng, state.sock,
                         state.correlation)));
  std::get<0>(tasks).result();
  std::get<1>(tasks).result();
  coproto::sync_wait(state.sock.flush());
  const auto bytes_end = TakeSocketCommSnapshot(state.sock);
  const auto end = std::chrono::high_resolution_clock::now();

  if (online_stats) {
    const double elapsed = std::chrono::duration<double>(end - start).count();
    online_stats->setup_time_s += elapsed;
    online_stats->perm_setup_time_s += elapsed;
    online_stats->perm_setup_bytes +=
        TotalSocketBytesDelta(bytes_begin, bytes_end);
  }

  return state;
}

std::vector<uint128_t> ApplyPermutedPeqtSender(
    const std::vector<uint128_t>& values, PermSenderState* state,
    OnlineStats* online_stats) {
  UPSU_ENFORCE(state != nullptr, "perm sender state must not be null");
  auto input = U128VecToByteMatrix(values, state->row_bytes);
  oc::Matrix<oc::u8> output(input.rows(), input.cols());

  const auto start = std::chrono::high_resolution_clock::now();
  const auto bytes_begin = TakeSocketCommSnapshot(state->sock);
  coproto::sync_wait(state->correlation.apply<oc::u8>(
      secJoin::PermOp::Regular, input, output, state->sock));
  coproto::sync_wait(state->sock.flush());
  const auto bytes_end = TakeSocketCommSnapshot(state->sock);
  const auto end = std::chrono::high_resolution_clock::now();

  if (online_stats) {
    online_stats->perm_apply_time_s +=
        std::chrono::duration<double>(end - start).count();
    online_stats->perm_apply_bytes +=
        TotalSocketBytesDelta(bytes_begin, bytes_end);
  }

  return ByteMatrixToU128Vec(output, state->row_bytes);
}

std::vector<uint128_t> ApplyPermutedPeqtReceiver(
    const std::vector<uint128_t>& values, PermReceiverState* state,
    OnlineStats* online_stats) {
  UPSU_ENFORCE(state != nullptr, "perm receiver state must not be null");
  auto input = U128VecToByteMatrix(values, state->row_bytes);
  oc::Matrix<oc::u8> output(input.rows(), input.cols());

  const auto start = std::chrono::high_resolution_clock::now();
  const auto bytes_begin = TakeSocketCommSnapshot(state->sock);
  coproto::sync_wait(state->correlation.apply<oc::u8>(
      secJoin::PermOp::Regular, input, output, state->sock));
  coproto::sync_wait(state->sock.flush());
  const auto bytes_end = TakeSocketCommSnapshot(state->sock);
  const auto end = std::chrono::high_resolution_clock::now();

  if (online_stats) {
    online_stats->perm_apply_time_s +=
        std::chrono::duration<double>(end - start).count();
    online_stats->perm_apply_bytes +=
        TotalSocketBytesDelta(bytes_begin, bytes_end);
  }

  return ByteMatrixToU128Vec(output, state->row_bytes);
}

std::vector<uint8_t> ApplyPermutedByteSharesSender(
    const std::vector<uint8_t>& values, PermSenderState* state,
    OnlineStats* online_stats) {
  UPSU_ENFORCE(state != nullptr, "perm sender state must not be null");
  UPSU_ENFORCE(state->row_bytes == 1,
               "byte-share permutation requires row_bytes=1, got={}",
               state->row_bytes);
  oc::Matrix<oc::u8> input(values.size(), 1);
  oc::Matrix<oc::u8> output(values.size(), 1);
  for (size_t i = 0; i < values.size(); ++i) {
    input(static_cast<oc::u64>(i), 0) = values[i];
  }

  const auto start = std::chrono::high_resolution_clock::now();
  const auto bytes_begin = TakeSocketCommSnapshot(state->sock);
  coproto::sync_wait(state->correlation.apply<oc::u8>(
      secJoin::PermOp::Regular, input, output, state->sock));
  coproto::sync_wait(state->sock.flush());
  const auto bytes_end = TakeSocketCommSnapshot(state->sock);
  const auto end = std::chrono::high_resolution_clock::now();

  if (online_stats) {
    online_stats->perm_apply_time_s +=
        std::chrono::duration<double>(end - start).count();
    online_stats->perm_apply_bytes +=
        TotalSocketBytesDelta(bytes_begin, bytes_end);
  }

  std::vector<uint8_t> permuted(values.size(), 0);
  for (size_t i = 0; i < permuted.size(); ++i) {
    permuted[i] = output(static_cast<oc::u64>(i), 0);
  }
  return permuted;
}

std::vector<uint8_t> ApplyPermutedByteSharesReceiver(
    const std::vector<uint8_t>& values, PermReceiverState* state,
    OnlineStats* online_stats) {
  UPSU_ENFORCE(state != nullptr, "perm receiver state must not be null");
  UPSU_ENFORCE(state->row_bytes == 1,
               "byte-share permutation requires row_bytes=1, got={}",
               state->row_bytes);
  oc::Matrix<oc::u8> input(values.size(), 1);
  oc::Matrix<oc::u8> output(values.size(), 1);
  for (size_t i = 0; i < values.size(); ++i) {
    input(static_cast<oc::u64>(i), 0) = values[i];
  }

  const auto start = std::chrono::high_resolution_clock::now();
  const auto bytes_begin = TakeSocketCommSnapshot(state->sock);
  coproto::sync_wait(state->correlation.apply<oc::u8>(
      secJoin::PermOp::Regular, input, output, state->sock));
  coproto::sync_wait(state->sock.flush());
  const auto bytes_end = TakeSocketCommSnapshot(state->sock);
  const auto end = std::chrono::high_resolution_clock::now();

  if (online_stats) {
    online_stats->perm_apply_time_s +=
        std::chrono::duration<double>(end - start).count();
    online_stats->perm_apply_bytes +=
        TotalSocketBytesDelta(bytes_begin, bytes_end);
  }

  std::vector<uint8_t> permuted(values.size(), 0);
  for (size_t i = 0; i < permuted.size(); ++i) {
    permuted[i] = output(static_cast<oc::u64>(i), 0);
  }
  return permuted;
}

template <typename T>
std::vector<T> PermuteValuesByPermutation(const std::vector<T>& original_values,
                                          const PermReceiverState& state) {
  const auto& pi = state.correlation.mPerm.mPi;
  UPSU_ENFORCE(pi.size() == original_values.size(),
               "permutation size mismatch: got {}, expect {}", pi.size(),
               original_values.size());
  std::vector<T> permuted_values(original_values.size(), 0);
  for (size_t perm_idx = 0; perm_idx < permuted_values.size(); ++perm_idx) {
    const size_t orig_idx = static_cast<size_t>(pi[perm_idx]);
    UPSU_ENFORCE(orig_idx < original_values.size(),
                 "original index {} out of range {}", orig_idx,
                 original_values.size());
    permuted_values[perm_idx] = original_values[orig_idx];
  }
  return permuted_values;
}

void TraceStage(const char* role, const std::string& message) {
  if (!TraceEnabled()) {
    return;
  }
  if (std::getenv("PSU_TRACE_TIMES")) {
    static const auto start = std::chrono::steady_clock::now();
    const double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - start).count();
    std::cerr << "[stage_seconds=" << elapsed << "] ";
  }
  std::cerr << "[psu:" << role << "] " << message << std::endl;
}

double SecondsSince(const std::chrono::high_resolution_clock::time_point& start,
                    const std::chrono::high_resolution_clock::time_point& end) {
  return std::chrono::duration<double>(end - start).count();
}

struct HashedTableItem {
  uint128_t full_item = 0;
  uint128_t stored_item = 0;
};

bool IsPowerOfTwo(size_t value) {
  return value != 0 && (value & (value - 1)) == 0;
}

size_t FloorLog2(size_t value) {
  UPSU_ENFORCE(value > 0, "value must be positive");
  size_t bits = 0;
  while (value > 1) {
    value >>= 1;
    ++bits;
  }
  return bits;
}

uint128_t MaskBits(uint128_t value, size_t bit_count);

uint64_t SimpleHashBin(uint128_t item, size_t hash_idx, size_t num_bins) {
  const auto [item_lo, item_hi] = upsu::DecomposeUInt128(item);
  const std::array<uint64_t, 3> salted = {
      item_lo, item_hi, static_cast<uint64_t>(hash_idx + 0xDEADBEEF)};
  uint64_t h = static_cast<uint64_t>(upsu::Hash128(
      upsu::Bytes(&salted, sizeof(salted))));
  return h % num_bins;
}

uint64_t TableHashBin(const HashedTableItem& item, size_t hash_idx,
                      size_t table_size, bool, size_t) {
  return paper::CandidateBins(item.full_item, table_size).at(hash_idx - 1);
}

uint64_t MulMod(uint64_t a, uint64_t b, uint64_t p) {
  return static_cast<uint64_t>((static_cast<__uint128_t>(a) * b) % p);
}

uint32_t MulMod65537(uint32_t a, uint32_t b) {
  constexpr uint64_t kPrime = 65537;
  const uint64_t product = static_cast<uint64_t>(a) * b;
  int64_t reduced = static_cast<int64_t>(product & 0xFFFFULL) -
                    static_cast<int64_t>(product >> 16);
  if (reduced < 0) {
    reduced += static_cast<int64_t>(kPrime);
  }
  return static_cast<uint32_t>(reduced);
}

void MulMod65537ArrayInPlace(uint32_t* power, const uint32_t* base, size_t n) {
  if (paper::Avx512Enabled()) {
    const size_t processed = paper::Mul65537Avx512(power, base, n);
    for (size_t i = processed; i < n; ++i) power[i] = MulMod65537(power[i], base[i]);
    return;
  }
#if defined(__AVX2__)
  constexpr int64_t kPrime = 65537;
  const __m256i zero = _mm256_setzero_si256();
  const __m256i mask16 = _mm256_set1_epi64x(0xFFFF);
  const __m256i prime = _mm256_set1_epi64x(kPrime);
  alignas(32) uint64_t even_out[4];
  alignas(32) uint64_t odd_out[4];
  size_t idx = 0;
  for (; idx + 8 <= n; idx += 8) {
    const __m256i lhs =
        _mm256_loadu_si256(reinterpret_cast<const __m256i*>(power + idx));
    const __m256i rhs =
        _mm256_loadu_si256(reinterpret_cast<const __m256i*>(base + idx));
    const __m256i lhs_hi = _mm256_srli_epi64(lhs, 32);
    const __m256i rhs_hi = _mm256_srli_epi64(rhs, 32);

    const __m256i even_prod = _mm256_mul_epu32(lhs, rhs);
    const __m256i odd_prod = _mm256_mul_epu32(lhs_hi, rhs_hi);

    const auto reduce = [&](const __m256i& prod) {
      const __m256i lo = _mm256_and_si256(prod, mask16);
      const __m256i hi = _mm256_srli_epi64(prod, 16);
      const __m256i diff = _mm256_sub_epi64(lo, hi);
      const __m256i neg_mask = _mm256_cmpgt_epi64(zero, diff);
      return _mm256_add_epi64(diff, _mm256_and_si256(neg_mask, prime));
    };

    _mm256_store_si256(reinterpret_cast<__m256i*>(even_out), reduce(even_prod));
    _mm256_store_si256(reinterpret_cast<__m256i*>(odd_out), reduce(odd_prod));
    power[idx + 0] = static_cast<uint32_t>(even_out[0]);
    power[idx + 1] = static_cast<uint32_t>(odd_out[0]);
    power[idx + 2] = static_cast<uint32_t>(even_out[1]);
    power[idx + 3] = static_cast<uint32_t>(odd_out[1]);
    power[idx + 4] = static_cast<uint32_t>(even_out[2]);
    power[idx + 5] = static_cast<uint32_t>(odd_out[2]);
    power[idx + 6] = static_cast<uint32_t>(even_out[3]);
    power[idx + 7] = static_cast<uint32_t>(odd_out[3]);
  }
  for (; idx < n; ++idx) {
    power[idx] = MulMod65537(power[idx], base[idx]);
  }
#else
  for (size_t idx = 0; idx < n; ++idx) {
    power[idx] = MulMod65537(power[idx], base[idx]);
  }
#endif
}

uint64_t SplitMix64(uint64_t value) {
  value += 0x9e3779b97f4a7c15ULL;
  value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
  value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
  return value ^ (value >> 31);
}

uint128_t MaskBits(uint128_t value, size_t bit_count) {
  if (bit_count >= 128) {
    return value;
  }
  return value & ((uint128_t{1} << bit_count) - 1);
}

[[maybe_unused]] uint128_t HashOprfValue(uint128_t oprf_value, size_t bit_count) {
  UPSU_ENFORCE(bit_count > 0 && bit_count <= 128,
               "bit_count must be in [1, 128], got {}", bit_count);
  const uint128_t hashed =
      upsu::Hash128(upsu::Bytes(&oprf_value,
                                                       sizeof(oprf_value)));
  return MaskBits(hashed, bit_count);
}

std::vector<uint128_t> ComputeReducedHashesFromOprf(
    const std::vector<uint128_t>& oprf_values, size_t bit_count) {
  std::vector<uint128_t> reduced(oprf_values.size());
  upsu::parallel_for(
      0, static_cast<int64_t>(oprf_values.size()),
      [&](int64_t begin, int64_t end) {
        for (int64_t idx = begin; idx < end; ++idx) {
          reduced[static_cast<size_t>(idx)] =
              MaskBits(oprf_values[static_cast<size_t>(idx)], bit_count);
        }
      });
  return reduced;
}

uint128_t RandomUint128() {
  return (static_cast<uint128_t>(upsu::SecureRandU64()) << 64) |
         static_cast<uint128_t>(upsu::SecureRandU64());
}

uint128_t RandomMaskedItem(size_t bit_count) {
  UPSU_ENFORCE(bit_count > 0 && bit_count <= 128,
               "item bit_count must be in [1, 128], got {}", bit_count);
  return MaskBits(RandomUint128(), bit_count);
}

uint128_t SetFirstSlice(uint128_t item, uint64_t first_slice,
                        size_t sigma2_bits, size_t item_bit_count) {
  UPSU_ENFORCE(sigma2_bits > 0 && sigma2_bits <= 64,
               "sigma2_bits must be in [1, 64], got {}", sigma2_bits);
  const uint128_t slice_mask =
      (sigma2_bits == 64)
          ? static_cast<uint128_t>(UINT64_MAX)
          : ((static_cast<uint128_t>(1) << sigma2_bits) - 1);
  uint128_t updated = MaskBits(item, item_bit_count);
  updated &= ~slice_mask;
  updated |= (static_cast<uint128_t>(first_slice) & slice_mask);
  return MaskBits(updated, item_bit_count);
}

uint64_t ExtractSliceOfItem(uint128_t item, size_t slice_idx,
                            size_t sigma2_bits) {
  UPSU_ENFORCE(sigma2_bits > 0 && sigma2_bits <= 64,
               "sigma2_bits must be in [1, 64], got {}", sigma2_bits);
  UPSU_ENFORCE((slice_idx + 1) * sigma2_bits <= 128,
               "slice extraction exceeds 128-bit item width");
  const uint128_t mask =
      (sigma2_bits == 64)
          ? static_cast<uint128_t>(UINT64_MAX)
          : ((static_cast<uint128_t>(1) << sigma2_bits) - 1);
  return static_cast<uint64_t>((item >> (slice_idx * sigma2_bits)) & mask);
}

size_t CeilLog2(size_t value) {
  UPSU_ENFORCE(value > 0, "value must be positive");
  size_t bits = 0;
  size_t cur = 1;
  while (cur < value) {
    cur <<= 1;
    ++bits;
  }
  return bits;
}

size_t MaxItemBitsRepresentable(uint64_t plain_modulus) {
  UPSU_ENFORCE(plain_modulus > 1, "plain_modulus must exceed 1");
  size_t bits = 0;
  uint64_t bound = plain_modulus - 1;
  while (bound > 1) {
    bound >>= 1;
    ++bits;
  }
  return bits;
}

size_t EffectiveItemBitCount(size_t sigma1_bits, size_t table_size,
                             bool use_permutation_hashing) {
  if (!use_permutation_hashing) {
    return sigma1_bits;
  }
  const size_t reduction_bits = FloorLog2(table_size);
  UPSU_ENFORCE(sigma1_bits > reduction_bits,
               "effective item bit count must stay positive: sigma1_bits={} "
               "reduction_bits={}",
               sigma1_bits, reduction_bits);
  return sigma1_bits - reduction_bits;
}

HashedTableItem BuildHashedTableItem(uint128_t full_item, size_t payload_bits,
                                     size_t, bool) {
  return HashedTableItem{full_item, MaskBits(full_item, payload_bits)};
}

std::vector<HashedTableItem> BuildHashedTableItems(
    const std::vector<uint128_t>& full_items, size_t sigma1_bits,
    size_t table_size, bool use_permutation_hashing) {
  std::vector<HashedTableItem> hashed_items(full_items.size());
  upsu::parallel_for(
      0, static_cast<int64_t>(full_items.size()),
      [&](int64_t begin, int64_t end) {
        for (int64_t idx = begin; idx < end; ++idx) {
          hashed_items[static_cast<size_t>(idx)] =
              BuildHashedTableItem(full_items[static_cast<size_t>(idx)],
                                   sigma1_bits, table_size,
                                   use_permutation_hashing);
        }
      });
  return hashed_items;
}

void AppendU64(std::vector<uint8_t>* out, uint64_t value) {
  const size_t old_size = out->size();
  out->resize(old_size + sizeof(uint64_t));
  std::memcpy(out->data() + old_size, &value, sizeof(uint64_t));
}

uint64_t ReadU64(const uint8_t* data, size_t size, size_t* offset) {
  UPSU_ENFORCE(*offset + sizeof(uint64_t) <= size, "buffer underflow");
  uint64_t v = 0;
  std::memcpy(&v, data + *offset, sizeof(uint64_t));
  *offset += sizeof(uint64_t);
  return v;
}

class VectorAppendStreamBuf final : public std::streambuf {
 public:
  explicit VectorAppendStreamBuf(std::vector<uint8_t>* out) : out_(out) {
    UPSU_ENFORCE(out_ != nullptr, "output buffer must not be null");
  }

 protected:
  std::streamsize xsputn(const char* s, std::streamsize count) override {
    if (count <= 0) {
      return 0;
    }
    const auto* bytes = reinterpret_cast<const uint8_t*>(s);
    out_->insert(out_->end(), bytes, bytes + count);
    return count;
  }

  int overflow(int ch) override {
    if (ch == traits_type::eof()) {
      return traits_type::not_eof(ch);
    }
    out_->push_back(static_cast<uint8_t>(ch));
    return ch;
  }

 private:
  std::vector<uint8_t>* out_;
};

class SpanInputStreamBuf final : public std::streambuf {
 public:
  SpanInputStreamBuf(const uint8_t* data, size_t size) {
    begin_ = reinterpret_cast<char*>(const_cast<uint8_t*>(data));
    end_ = begin_ + size;
    setg(begin_, begin_, end_);
  }

 protected:
  pos_type seekoff(off_type off, std::ios_base::seekdir way,
                   std::ios_base::openmode which) override {
    if (!(which & std::ios_base::in)) {
      return pos_type(off_type(-1));
    }
    char* new_pos = nullptr;
    if (way == std::ios_base::beg) {
      new_pos = begin_ + off;
    } else if (way == std::ios_base::cur) {
      new_pos = gptr() + off;
    } else if (way == std::ios_base::end) {
      new_pos = end_ + off;
    } else {
      return pos_type(off_type(-1));
    }
    if (new_pos < begin_ || new_pos > end_) {
      return pos_type(off_type(-1));
    }
    setg(begin_, new_pos, end_);
    return pos_type(new_pos - begin_);
  }

  pos_type seekpos(pos_type pos, std::ios_base::openmode which) override {
    return seekoff(static_cast<off_type>(pos), std::ios_base::beg, which);
  }

 private:
  char* begin_ = nullptr;
  char* end_ = nullptr;
};

struct PackedBlobCursor {
  const uint8_t* data = nullptr;
  size_t size = 0;
  size_t offset = 0;
  size_t count = 0;
  size_t index = 0;

  explicit PackedBlobCursor(const upsu::net::Context::Buffer& packed)
      : data(reinterpret_cast<const uint8_t*>(packed.data())),
        size(packed.size()),
        offset(0) {
    count = static_cast<size_t>(ReadU64(data, size, &offset));
  }

  std::pair<const uint8_t*, size_t> Next() {
    UPSU_ENFORCE(index < count, "blob cursor exhausted");
    const uint64_t len = ReadU64(data, size, &offset);
    UPSU_ENFORCE(offset + len <= size, "invalid blob vector encoding");
    const uint8_t* blob_data = data + offset;
    offset += static_cast<size_t>(len);
    ++index;
    return {blob_data, static_cast<size_t>(len)};
  }

  void EnforceFinished() const {
    UPSU_ENFORCE(index == count, "blob cursor count mismatch");
    UPSU_ENFORCE(offset == size, "invalid blob vector trailing bytes");
  }
};

std::vector<uint8_t> BeginPackedBlobVector(size_t count,
                                           size_t reserve_bytes = 0) {
  std::vector<uint8_t> out;
  out.reserve(sizeof(uint64_t) + reserve_bytes);
  AppendU64(&out, static_cast<uint64_t>(count));
  return out;
}

template <typename T>
std::string SerializeSealObject(const T& obj) {
  std::stringstream ss;
  obj.save(ss);
  return upsu::serialization::Pack(ss.str());
}

template <typename T>
T DeserializeSealObject(const std::shared_ptr<seal::SEALContext>& context,
                        const uint8_t* blob_data, size_t blob_size) {
  T obj;
  std::string unpacked;
  if(upsu::serialization::IsCompressed(blob_data,blob_size)) {
    unpacked=upsu::serialization::Unpack(blob_data,blob_size);
    blob_data=reinterpret_cast<const uint8_t*>(unpacked.data());
    blob_size=unpacked.size();
  }
  SpanInputStreamBuf buffer(blob_data, blob_size);
  std::istream input(&buffer);
  obj.load(*context, input);
  return obj;
}

template <typename T>
T DeserializeSealObject(const std::shared_ptr<seal::SEALContext>& context,
                        const std::string& blob) {
  return DeserializeSealObject<T>(
      context, reinterpret_cast<const uint8_t*>(blob.data()), blob.size());
}

template <typename T>
void AppendSerializedSealObject(std::vector<uint8_t>* out, const T& obj) {
  if(upsu::serialization::CompressionEnabled()) {
    auto bytes=SerializeSealObject(obj);
    AppendU64(out,bytes.size());
    out->insert(out->end(),bytes.begin(),bytes.end());
    return;
  }
  const size_t size_pos = out->size();
  AppendU64(out, 0);
  const size_t payload_begin = out->size();
  VectorAppendStreamBuf buffer(out);
  std::ostream output(&buffer);
  obj.save(output);
  output.flush();
  const uint64_t payload_size = static_cast<uint64_t>(out->size() - payload_begin);
  std::memcpy(out->data() + size_pos, &payload_size, sizeof(uint64_t));
}

std::shared_ptr<seal::SEALContext> CreateBfvContext(const ProtocolParams& params) {
  seal::EncryptionParameters parms(seal::scheme_type::bfv);
  parms.set_poly_modulus_degree(params.poly_modulus_degree);
  UPSU_ENFORCE(!params.coeff_modulus_bits.empty(),
               "coeff_modulus_bits cannot be empty");
  parms.set_coeff_modulus(seal::CoeffModulus::Create(
      params.poly_modulus_degree, params.coeff_modulus_bits));
  parms.set_plain_modulus(params.plain_modulus);

  auto context = std::make_shared<seal::SEALContext>(parms);
  UPSU_ENFORCE(context->parameters_set(), "invalid BFV parameters");
  UPSU_ENFORCE(context->first_context_data()->qualifiers().using_batching,
               "BFV parameters must support batching");
  return context;
}

size_t CeilDiv(size_t value, size_t divisor) {
  UPSU_ENFORCE(divisor > 0, "divisor must be positive");
  return (value + divisor - 1) / divisor;
}

seal::Plaintext EncodeSlots(seal::BatchEncoder& encoder,
                            const std::vector<uint64_t>& values,
                            uint64_t prime) {
  std::vector<uint64_t> slots(encoder.slot_count(), 0ULL);
  const size_t active_slots = std::min(values.size(), slots.size());
  for (size_t i = 0; i < active_slots; ++i) {
    slots[i] = values[i] % prime;
  }
  seal::Plaintext pt;
  encoder.encode(slots, pt);
  return pt;
}

seal::Plaintext EncodeSlots(seal::BatchEncoder& encoder,
                            const std::vector<uint32_t>& values,
                            uint64_t prime) {
  std::vector<uint64_t> slots(encoder.slot_count(), 0ULL);
  const size_t active_slots = std::min(values.size(), slots.size());
  for (size_t i = 0; i < active_slots; ++i) {
    slots[i] = static_cast<uint64_t>(values[i]) % prime;
  }
  seal::Plaintext pt;
  encoder.encode(slots, pt);
  return pt;
}

std::vector<uint64_t> DecodeSlots(const seal::Plaintext& pt,
                                  seal::BatchEncoder& encoder,
                                  size_t active_slots, uint64_t prime) {
  std::vector<uint64_t> slots;
  encoder.decode(pt, slots);
  UPSU_ENFORCE(active_slots <= slots.size(),
               "active_slots {} exceeds available slot count {}",
               active_slots, slots.size());
  std::vector<uint64_t> out(active_slots, 0ULL);
  for (size_t i = 0; i < active_slots; ++i) {
    out[i] = slots[i] % prime;
  }
  return out;
}

size_t QueryCipherIndex(size_t batch_idx, size_t slice_idx,
                        size_t query_slice_count, size_t source_power_count,
                        size_t power_idx) {
  return ((batch_idx * query_slice_count + slice_idx) * source_power_count) +
         power_idx;
}

size_t ChoosePsLowDegree(size_t max_degree, size_t requested_ps_low_degree) {
  if (requested_ps_low_degree > 0) {
    return std::min(requested_ps_low_degree, max_degree > 0 ? max_degree - 1 : 0);
  }
  if (max_degree < 64) {
    return 0;
  }
  const auto auto_degree = static_cast<size_t>(
      std::sqrt(static_cast<long double>(max_degree) * 1.5L));
  return std::min(max_degree - 1, std::max<size_t>(1, auto_degree));
}

std::set<std::uint32_t> BuildTargetPowerSet(size_t max_degree,
                                            size_t ps_low_degree) {
  std::set<std::uint32_t> target_powers;
  if (ps_low_degree == 0 || ps_low_degree >= max_degree) {
    for (size_t d = 1; d <= max_degree; ++d) {
      target_powers.insert(static_cast<std::uint32_t>(d));
    }
    return target_powers;
  }

  for (size_t d = 1; d <= ps_low_degree; ++d) {
    target_powers.insert(static_cast<std::uint32_t>(d));
  }
  const size_t step = ps_low_degree + 1;
  for (size_t d = step; d <= max_degree; d += step) {
    target_powers.insert(static_cast<std::uint32_t>(d));
  }
  return target_powers;
}

std::set<std::uint32_t> BuildSourcePowerSet(
    const std::set<std::uint32_t>& target_powers, size_t max_depth,
    const std::vector<std::uint32_t>& explicit_query_powers) {
  return paper::SourcePowers(target_powers, max_depth, explicit_query_powers);
}

std::vector<std::uint32_t> ToSortedVector(
    const std::set<std::uint32_t>& values) {
  return std::vector<std::uint32_t>(values.begin(), values.end());
}

std::string JoinPowers(const std::vector<std::uint32_t>& values) {
  std::ostringstream oss;
  for (size_t i = 0; i < values.size(); ++i) {
    if (i) {
      oss << ",";
    }
    oss << values[i];
  }
  return oss.str();
}

struct CuckooTable {
  static constexpr size_t kHashCount = 3;
  static constexpr size_t kMaxIter = 500;
  static constexpr size_t kInvalidItemId = std::numeric_limits<size_t>::max();

  size_t table_size;
  bool use_permutation_hashing;
  size_t permutation_index_bits;
  std::vector<uint128_t> bins;
  std::vector<uint128_t> full_bins;
  std::vector<size_t> item_ids;
  std::vector<bool> occupied;
  std::vector<bool> is_spy;

  explicit CuckooTable(size_t table_size_arg,
                       bool use_permutation_hashing_arg = false,
                       size_t permutation_index_bits_arg = 0)
      : table_size(table_size_arg),
        use_permutation_hashing(use_permutation_hashing_arg),
        permutation_index_bits(permutation_index_bits_arg),
        bins(table_size_arg, 0),
        full_bins(table_size_arg, 0),
        item_ids(table_size_arg, kInvalidItemId),
        occupied(table_size_arg, false),
        is_spy(table_size_arg, false) {}

  void FillSpies(bool enable, size_t stored_item_bits, size_t full_item_bits) {
    if (!enable) {
      return;
    }
    for (size_t i = 0; i < table_size; ++i) {
      if (!occupied[i]) {
        bins[i] = RandomMaskedItem(stored_item_bits);
        full_bins[i] = RandomMaskedItem(full_item_bits);
        item_ids[i] = kInvalidItemId;
        occupied[i] = true;
        is_spy[i] = true;
      }
    }
  }
};

struct SimpleHashTable {
  size_t num_bins;
  size_t max_bin_size;
  bool use_permutation_hashing;
  size_t permutation_index_bits;
  std::vector<std::vector<uint128_t>> bins;

  explicit SimpleHashTable(size_t m, bool use_permutation_hashing_arg = false,
                           size_t permutation_index_bits_arg = 0)
      : num_bins(m),
        max_bin_size(0),
        use_permutation_hashing(use_permutation_hashing_arg),
        permutation_index_bits(permutation_index_bits_arg),
        bins(m) {}

  void InsertAll(const std::vector<HashedTableItem>& items, size_t kv) {
    const size_t n = items.size() / kv;
    for (size_t i = 0; i < n; ++i) {
      for (size_t j = 0; j < kv; ++j) {
        const auto& sub_item = items[i * kv + j];
        for (size_t bin : paper::CandidateBins(sub_item.full_item, num_bins)) {
          bins[bin].push_back(sub_item.stored_item);
        }
      }
    }
    for (const auto& b : bins) {
      max_bin_size = std::max(max_bin_size, b.size());
    }
  }

  void PadBins() {
    for (auto& b : bins) {
      while (b.size() < max_bin_size) {
        b.push_back(upsu::SecureRandU64());
      }
    }
  }
};

struct BinPolySet {
  std::vector<std::vector<uint64_t>> poly_coeffs;
  size_t ks = 0;
  uint64_t prime = 0;
};

struct BatchedPlaintextPolySet {
  std::vector<std::vector<seal::Plaintext>> coeff_plaintexts;
  std::vector<std::vector<seal::Plaintext>> coeff_plaintexts_ntt;
  std::vector<std::vector<std::vector<uint32_t>>> coeff_quotients;
  std::vector<std::vector<uint8_t>> has_coeff_plaintexts;
  std::vector<std::vector<uint32_t>> normal_non_zero_degrees;
  std::vector<std::vector<uint32_t>> ntt_non_zero_degrees;
  bool non_constant_ntt = false;
};

}

std::vector<uint128_t> EncodeItemsForFinalOte(
    const std::vector<std::string>& items) {
  return EncodeItemsForFinalOteImpl(items);
}

struct PreparedSender {
  encoding::Salt encoding_salt{};
  bool salt_disclosed = false;
  std::vector<std::vector<BinPolySet>> bin_polys;
  std::vector<std::vector<BatchedPlaintextPolySet>> packed_bin_plaintexts;
  std::vector<std::uint32_t> source_power_vec;
  std::set<std::uint32_t> target_powers;
  size_t ks = 0;
  size_t sigma2_bits = 0;
  size_t item_bit_count = 0;
  size_t alpha_eff = 1;
  size_t max_degree = 1;
  size_t ps_low_degree = 0;
  size_t m = 0;
  bool packed_plaintexts_online_ready = false;
};

namespace {

struct PartitionedBins {
  size_t alpha = 1;
  size_t sub_bin_size = 1;
  std::vector<std::vector<std::vector<uint128_t>>> bins;
};

struct PartitionShape {
  size_t alpha = 1;
  size_t sub_bin_size = 1;
};

struct SelectedKsConfig {
  size_t ks = 0;
  size_t sigma2_bits = 0;
  size_t item_bit_count = 0;
  size_t alpha_eff = 1;
  size_t max_degree = 1;
  size_t ps_low_degree = 0;
  size_t query_slice_count = 1;
  size_t query_cipher_count = 0;
  size_t eval_cipher_count = 0;
  std::vector<uint32_t> source_power_vec;
  std::set<uint32_t> target_powers;
  PartitionedBins partitioned;
};

uint64_t FirstSliceOfItem(uint128_t item, size_t ks, size_t sigma2_bits,
                          uint64_t prime) {
  UPSU_ENFORCE(ks > 0 && ks * sigma2_bits <= 128,
               "slicing exceeds 128-bit item width");
  return ExtractSliceOfItem(item, 0, sigma2_bits) % prime;
}

PartitionShape EstimatePartitionShape(const SimpleHashTable& sh_table,
                                      size_t alpha_min, size_t ks,
                                      size_t sigma2_bits, uint64_t prime,
                                      size_t max_items_per_bin,
                                      size_t public_sub_bin_size = 0) {
  const size_t dense_domain_size =
      (sigma2_bits < 63)
          ? std::min<size_t>(static_cast<size_t>(prime), size_t{1} << sigma2_bits)
          : 0;
  const size_t required_alpha = upsu::parallel_reduce<size_t>(
      0, sh_table.num_bins, 1,
      [&](int64_t begin, int64_t end) {
        size_t local_required_alpha = 1;
        std::vector<size_t> dense_freq;
        std::vector<uint32_t> touched;
        if (dense_domain_size > 0 && dense_domain_size <= (1u << 20)) {
          dense_freq.assign(dense_domain_size, 0);
        }
        for (int64_t bin_idx = begin; bin_idx < end; ++bin_idx) {
          if (!dense_freq.empty()) {
            touched.clear();
            for (uint128_t item : sh_table.bins[bin_idx]) {
              const uint32_t first = static_cast<uint32_t>(
                  FirstSliceOfItem(item, ks, sigma2_bits, prime));
              if (dense_freq[first]++ == 0) {
                touched.push_back(first);
              }
            }
            for (uint32_t key : touched) {
              local_required_alpha =
                  std::max(local_required_alpha, dense_freq[key]);
              dense_freq[key] = 0;
            }
            continue;
          }

          std::unordered_map<uint64_t, size_t> freq;
          freq.reserve(sh_table.bins[bin_idx].size());
          for (uint128_t item : sh_table.bins[bin_idx]) {
            const uint64_t first =
                FirstSliceOfItem(item, ks, sigma2_bits, prime);
            ++freq[first];
          }
          for (const auto& kv : freq) {
            local_required_alpha = std::max(local_required_alpha, kv.second);
          }
        }
        return local_required_alpha;
      },
      [](size_t lhs, size_t rhs) { return std::max(lhs, rhs); });

  PartitionShape shape;
  if (public_sub_bin_size != 0) {
    UPSU_ENFORCE(alpha_min >= required_alpha && alpha_min > 0,
                 "public alpha exceeded by first-slice multiplicity");
    UPSU_ENFORCE(sh_table.max_bin_size <= alpha_min * public_sub_bin_size,
                 "public padded bin capacity exceeded");
    UPSU_ENFORCE(public_sub_bin_size <= max_items_per_bin,
                 "public degree exceeds the supported maximum");
    return {.alpha = alpha_min, .sub_bin_size = public_sub_bin_size};
  }
  shape.alpha = std::max(alpha_min, required_alpha);
  if (max_items_per_bin > 0) {
    const size_t alpha_for_cap =
        std::max<size_t>(1, (sh_table.max_bin_size + max_items_per_bin - 1) /
                                max_items_per_bin);
    shape.alpha = std::max(shape.alpha, alpha_for_cap);
  }
  if (shape.alpha == 0) {
    shape.alpha = 1;
  }
  shape.sub_bin_size =
      std::max<size_t>(1, (sh_table.max_bin_size + shape.alpha - 1) /
                              shape.alpha);
  return shape;
}

PartitionedBins BuildPartitionedBins(const SimpleHashTable& sh_table,
                                     size_t alpha_min, size_t ks,
                                     size_t item_bit_count,
                                     size_t sigma2_bits, uint64_t prime,
                                     bool require_unique_first_slice,
                                     size_t max_items_per_bin,
                                     size_t public_sub_bin_size = 0) {
  PartitionedBins out;
  const size_t group_dense_domain_size =
      (sigma2_bits < 63)
          ? std::min<size_t>(static_cast<size_t>(prime), size_t{1} << sigma2_bits)
          : 0;
  const PartitionShape shape =
      EstimatePartitionShape(sh_table, alpha_min, ks, sigma2_bits, prime,
                             max_items_per_bin, public_sub_bin_size);
  out.alpha = shape.alpha;
  out.sub_bin_size = shape.sub_bin_size;
  out.bins.assign(sh_table.num_bins,
                  std::vector<std::vector<uint128_t>>(out.alpha));

  if (require_unique_first_slice && sigma2_bits < 63) {
    const size_t max_unique = size_t{1} << sigma2_bits;
    UPSU_ENFORCE(out.sub_bin_size <= max_unique,
                 "sub-bin size {} exceeds unique first-slice capacity {}",
                 out.sub_bin_size, max_unique);
  }

  upsu::parallel_for(0, sh_table.num_bins, [&](int64_t begin, int64_t end) {
    std::vector<uint32_t> dense_group_count;
    std::vector<uint32_t> dense_group_pos;
    std::vector<uint32_t> touched;
    if (group_dense_domain_size > 0 && group_dense_domain_size <= (1u << 20)) {
      dense_group_count.assign(group_dense_domain_size, 0);
      dense_group_pos.assign(group_dense_domain_size,
                             std::numeric_limits<uint32_t>::max());
    }
    for (int64_t bin_idx = begin; bin_idx < end; ++bin_idx) {
      for (size_t sub_idx = 0; sub_idx < out.alpha; ++sub_idx) {
        out.bins[bin_idx][sub_idx].reserve(out.sub_bin_size);
      }
      size_t next_base = 0;
      if (!dense_group_count.empty()) {
        touched.clear();
        for (uint128_t item : sh_table.bins[bin_idx]) {
          const uint32_t first = static_cast<uint32_t>(
              FirstSliceOfItem(item, ks, sigma2_bits, prime));
          if (dense_group_count[first]++ == 0) {
            touched.push_back(first);
          }
        }

        std::vector<std::vector<uint128_t>> groups(touched.size());
        for (size_t i = 0; i < touched.size(); ++i) {
          const uint32_t key = touched[i];
          dense_group_pos[key] = static_cast<uint32_t>(i);
          groups[i].reserve(dense_group_count[key]);
        }

        for (uint128_t item : sh_table.bins[bin_idx]) {
          const uint32_t first = static_cast<uint32_t>(
              FirstSliceOfItem(item, ks, sigma2_bits, prime));
          groups[dense_group_pos[first]].push_back(item);
        }

        for (auto& group_items : groups) {
          for (size_t idx = 0; idx < group_items.size(); ++idx) {
            const size_t slot = (next_base + idx) % out.alpha;
            out.bins[bin_idx][slot].push_back(group_items[idx]);
          }
          next_base = (next_base + group_items.size()) % out.alpha;
        }

        for (uint32_t key : touched) {
          dense_group_count[key] = 0;
          dense_group_pos[key] = std::numeric_limits<uint32_t>::max();
        }
        continue;
      }

      std::unordered_map<uint64_t, std::vector<uint128_t>> groups;
      groups.reserve(sh_table.bins[bin_idx].size());
      for (uint128_t item : sh_table.bins[bin_idx]) {
        const uint64_t first = FirstSliceOfItem(item, ks, sigma2_bits, prime);
        groups[first].push_back(item);
      }

      for (auto& group_kv : groups) {
        auto& group_items = group_kv.second;
        for (size_t idx = 0; idx < group_items.size(); ++idx) {
          const size_t slot = (next_base + idx) % out.alpha;
          out.bins[bin_idx][slot].push_back(group_items[idx]);
        }
        next_base = (next_base + group_items.size()) % out.alpha;
      }
    }
  });

  upsu::parallel_for(0, sh_table.num_bins, [&](int64_t begin, int64_t end) {
    const size_t field_bits = FieldBitWidth(prime);
    std::vector<uint8_t> used(prime, 0);
    std::vector<size_t> touched;
    paper::FieldSampler sampler;
    for (int64_t bin_idx = begin; bin_idx < end; ++bin_idx) {
      for (size_t sub_idx = 0; sub_idx < out.alpha; ++sub_idx) {
        auto& sub_bin = out.bins[bin_idx][sub_idx];
        touched.clear();
        for (auto& item : sub_bin) {
          const auto slices = SliceItem(item, ks, sigma2_bits);
          const size_t anchor = slices[0];
          UPSU_ENFORCE(!used[anchor], "duplicate real anchor in partitioned sub-bin");
          used[anchor] = 1;
          touched.push_back(anchor);
          item = PackFieldElements(slices, field_bits);
        }
        UPSU_ENFORCE(sub_bin.size() <= out.sub_bin_size && out.sub_bin_size <= prime,
                     "public sub-bin capacity exceeded");
        while (sub_bin.size() < out.sub_bin_size) {
          uint64_t anchor;
          do { anchor = sampler(prime); } while (used[anchor]);
          used[anchor] = 1;
          touched.push_back(anchor);
          std::vector<uint64_t> slices(ks);
          slices[0] = anchor;
          for (size_t j = 1; j < ks; ++j) slices[j] = sampler(prime);
          sub_bin.push_back(PackFieldElements(slices, field_bits));
        }
        for (size_t anchor : touched) used[anchor] = 0;
      }
    }
  });

  return out;
}

SelectedKsConfig SelectKsConfig(const SimpleHashTable& sh_table,
                                const ProtocolParams& params,
                                size_t item_bit_count, uint64_t prime,
                                bool require_unique_first_slice) {
  const size_t candidate_ks = params.ks;
  const size_t max_slice_bits = MaxItemBitsRepresentable(params.plain_modulus);

  SelectedKsConfig best;
  const size_t sigma2_bits = CeilDiv(item_bit_count, candidate_ks);
  UPSU_ENFORCE(sigma2_bits > 0 && candidate_ks * sigma2_bits <= 128 &&
                   sigma2_bits <= 62 && sigma2_bits <= max_slice_bits,
               "fixed ks={} is incompatible with item_bits={} plain_modulus={}",
               candidate_ks, item_bit_count, params.plain_modulus);

  const PartitionShape shape = EstimatePartitionShape(
      sh_table, params.alpha, candidate_ks, sigma2_bits, prime,
      params.max_items_per_bin, params.public_sub_bin_size);
  if (require_unique_first_slice && sigma2_bits < 63) {
    const size_t max_unique = size_t{1} << sigma2_bits;
    UPSU_ENFORCE(shape.sub_bin_size <= max_unique,
                 "fixed ks={} yields sub_bin_size={} exceeding unique "
                 "first-slice capacity={}",
                 candidate_ks, shape.sub_bin_size, max_unique);
  }

  const size_t ps_low_degree =
      ChoosePsLowDegree(shape.sub_bin_size, params.ps_low_degree);
  const auto target_powers =
      BuildTargetPowerSet(shape.sub_bin_size, ps_low_degree);
  const auto source_powers = BuildSourcePowerSet(
      target_powers, params.query_powers_max_depth, params.query_powers);
  const auto source_power_vec = ToSortedVector(source_powers);
  const size_t query_slice_count = 1;
  const size_t query_cipher_count = query_slice_count * source_power_vec.size();
  const size_t eval_cipher_count =
      shape.alpha * OutputPolyCount(params, candidate_ks);

  TraceStage("params",
             "fixed ks=" + std::to_string(candidate_ks) +
                 ", sigma2_bits=" + std::to_string(sigma2_bits) +
                 ", alpha=" + std::to_string(shape.alpha) +
                 ", max_degree=" + std::to_string(shape.sub_bin_size) +
                 ", |W|=" + std::to_string(source_power_vec.size()) +
                 ", q_ct=" + std::to_string(query_cipher_count) +
                 ", r_ct=" + std::to_string(eval_cipher_count));

  best.ks = candidate_ks;
  best.sigma2_bits = sigma2_bits;
  best.item_bit_count = item_bit_count;
  best.alpha_eff = shape.alpha;
  best.max_degree = shape.sub_bin_size;
  best.ps_low_degree = ps_low_degree;
  best.query_slice_count = query_slice_count;
  best.query_cipher_count = query_cipher_count;
  best.eval_cipher_count = eval_cipher_count;
  best.source_power_vec = source_power_vec;
  best.target_powers = target_powers;

  best.partitioned = BuildPartitionedBins(
      sh_table, params.alpha, best.ks, item_bit_count, best.sigma2_bits, prime,
      require_unique_first_slice, params.max_items_per_bin, params.public_sub_bin_size);
  return best;
}

BinPolySet BuildPolyLinkBinPolySet(const std::vector<uint128_t>& sub_bin_items,
                              size_t ks, size_t sigma2_bits, uint64_t prime,
                              bool drop_first_poly) {
  BinPolySet result;
  result.ks = ks;
  result.prime = prime;
  PolyLinkSubBin pol_sub_bin =
      BuildPolyLinkSubBin(sub_bin_items, ks, sigma2_bits, prime,
                          drop_first_poly);
  result.poly_coeffs = std::move(pol_sub_bin.poly_coeffs);
  return result;
}

void RebuildPackedDegreeIndex(BatchedPlaintextPolySet* packed, size_t ks,
                              size_t max_degree);

std::vector<std::vector<BatchedPlaintextPolySet>> BuildPackedPlaintextPolyCache(
    const std::vector<std::vector<BinPolySet>>& bin_polys, size_t alpha_eff,
    size_t ks, size_t m, size_t max_degree, uint64_t prime,
    const std::shared_ptr<seal::SEALContext>& context) {
  seal::BatchEncoder slot_probe(*context);
  const size_t slot_count = slot_probe.slot_count();
  const size_t packed_bin_batch_count = CeilDiv(m, slot_count);

  std::vector<std::vector<BatchedPlaintextPolySet>> packed_plaintexts(
      packed_bin_batch_count);
  for (auto& batch : packed_plaintexts) {
    batch.resize(alpha_eff);
  }

  upsu::parallel_for(0, packed_bin_batch_count,
                     [&](int64_t begin, int64_t end) {
    seal::BatchEncoder encoder(*context);
    for (int64_t batch_idx = begin; batch_idx < end; ++batch_idx) {
      const size_t slot_offset = static_cast<size_t>(batch_idx) * slot_count;
      const size_t active_slots = std::min(slot_count, m - slot_offset);

      for (size_t sub_idx = 0; sub_idx < alpha_eff; ++sub_idx) {
        auto& packed = packed_plaintexts[batch_idx][sub_idx];
        packed.coeff_plaintexts.resize(ks);
        packed.has_coeff_plaintexts.resize(ks);
        packed.normal_non_zero_degrees.resize(ks);
        packed.ntt_non_zero_degrees.resize(ks);

        for (size_t output_slice = 0; output_slice < ks; ++output_slice) {
          packed.coeff_plaintexts[output_slice].resize(max_degree + 1);
          packed.has_coeff_plaintexts[output_slice].assign(max_degree + 1, 0);
          std::vector<uint64_t> coeff_slots(slot_count, 0ULL);

          for (size_t degree = 0; degree <= max_degree; ++degree) {
            bool has_non_zero_coeff = false;
            for (size_t slot_idx = 0; slot_idx < active_slots; ++slot_idx) {
              const size_t bin_idx = slot_offset + slot_idx;
              const auto& coeffs =
                  bin_polys[bin_idx][sub_idx].poly_coeffs[output_slice];
              const uint64_t coeff =
                  (degree < coeffs.size()) ? (coeffs[degree] % prime)
                                           : uint64_t{0};
              coeff_slots[slot_idx] = coeff;
              has_non_zero_coeff |= (coeff != 0);
            }

            if (!has_non_zero_coeff) {
              continue;
            }

            encoder.encode(coeff_slots,
                           packed.coeff_plaintexts[output_slice][degree]);
            packed.has_coeff_plaintexts[output_slice][degree] = 1;
          }
        }
        RebuildPackedDegreeIndex(&packed, ks, max_degree);
      }
    }
  });

  return packed_plaintexts;
}

bool DegreeNeedsNormalPlaintext(size_t degree, size_t max_degree,
                                size_t ps_low_degree) {
  if (degree == 0) {
    return true;
  }
  if (ps_low_degree == 0 || ps_low_degree >= max_degree) {
    return false;
  }
  const size_t step = ps_low_degree + 1;
  return (degree % step) == 0;
}

void RebuildPackedDegreeIndex(BatchedPlaintextPolySet* packed, size_t ks,
                              size_t max_degree) {
  packed->normal_non_zero_degrees.assign(ks, {});
  packed->ntt_non_zero_degrees.assign(ks, {});
  for (size_t output_slice = 0; output_slice < ks; ++output_slice) {
    packed->normal_non_zero_degrees[output_slice].reserve(max_degree);
    packed->ntt_non_zero_degrees[output_slice].reserve(max_degree);
    for (size_t degree = 1; degree <= max_degree; ++degree) {
      if (!packed->has_coeff_plaintexts[output_slice][degree]) {
        continue;
      }
      const bool stored_as_ntt =
          packed->non_constant_ntt &&
          degree < packed->coeff_plaintexts_ntt[output_slice].size() &&
          packed->coeff_plaintexts_ntt[output_slice][degree].coeff_count() > 0;
      auto& out = stored_as_ntt ? packed->ntt_non_zero_degrees[output_slice]
                                : packed->normal_non_zero_degrees[output_slice];
      out.push_back(static_cast<uint32_t>(degree));
    }
  }
}

std::vector<seal::Ciphertext> TransformCiphertextsToNtt(
    const std::vector<seal::Ciphertext>& all_powers, seal::Evaluator& evaluator) {
  std::vector<seal::Ciphertext> all_powers_ntt(all_powers.size());
  for (size_t degree = 1; degree < all_powers.size(); ++degree) {
    if (all_powers[degree].size() == 0) {
      continue;
    }
    all_powers_ntt[degree] = all_powers[degree];
    evaluator.transform_to_ntt_inplace(all_powers_ntt[degree]);
  }
  return all_powers_ntt;
}

seal::Ciphertext EvalPolyOnPackedSlots(
    const BatchedPlaintextPolySet& packed_polys,
    const std::vector<seal::Ciphertext>& all_powers, size_t output_slice,
    size_t max_degree, size_t ps_low_degree, const seal::RelinKeys& relin_keys,
    seal::Evaluator& evaluator, seal::Encryptor& encryptor,
    const seal::SEALContext& context,
    const std::vector<seal::Ciphertext>* all_powers_ntt = nullptr) {
  auto eval_direct = [&](size_t coeff_begin,
                         size_t coeff_end,
                         size_t power_offset) -> seal::Ciphertext {
    const auto& coeff_plaintexts = packed_polys.coeff_plaintexts[output_slice];
    const bool use_ntt = packed_polys.non_constant_ntt && all_powers_ntt;

    if (use_ntt) {
      seal::Ciphertext acc_ntt;
      bool has_term = false;
      const char* fused_option = std::getenv("PSU_FUSED_NTT");
      if (fused_option && std::strcmp(fused_option, "1") == 0) {
        std::vector<paper::NttProduct> terms;
        for (uint32_t d : packed_polys.ntt_non_zero_degrees[output_slice]) {
          if (d <= coeff_begin || d > coeff_end) continue;
          const size_t power_degree = power_offset + d - coeff_begin;
          terms.push_back({&all_powers_ntt->at(power_degree),
                           &packed_polys.coeff_plaintexts_ntt[output_slice][d],
                           &packed_polys.coeff_quotients[output_slice][d]});
        }
        has_term = paper::FusedNttDot(terms, context, acc_ntt);
      }
      const bool fused = has_term;
      for (uint32_t d : packed_polys.ntt_non_zero_degrees[output_slice]) {
        if (fused) break;
        if (d <= coeff_begin || d > coeff_end) {
          continue;
        }
        const size_t power_degree = power_offset + (d - coeff_begin);
        UPSU_ENFORCE(power_degree < all_powers_ntt->size(),
                     "power {} out of range {}", power_degree,
                     all_powers_ntt->size());
        UPSU_ENFORCE((*all_powers_ntt)[power_degree].size() != 0,
                     "missing NTT power {}", power_degree);

        seal::Ciphertext term = (*all_powers_ntt)[power_degree];
        evaluator.multiply_plain(
            term, packed_polys.coeff_plaintexts_ntt[output_slice][d], term);
        if (!has_term) {
          acc_ntt = std::move(term);
          has_term = true;
        } else {
          evaluator.add_inplace(acc_ntt, term);
        }
      }

      seal::Ciphertext acc;
      if (has_term) {
        acc = std::move(acc_ntt);
        evaluator.transform_from_ntt_inplace(acc);
      } else {
        encryptor.encrypt_zero(acc);
      }

      for (uint32_t d : packed_polys.normal_non_zero_degrees[output_slice]) {
        if (d <= coeff_begin || d > coeff_end) {
          continue;
        }
        const size_t power_degree = power_offset + (d - coeff_begin);
        UPSU_ENFORCE(power_degree < all_powers.size(), "power {} out of range {}",
                     power_degree, all_powers.size());
        seal::Ciphertext term;
        evaluator.multiply_plain(all_powers[power_degree], coeff_plaintexts[d],
                                 term);
        evaluator.add_inplace(acc, term);
      }

      if (coeff_begin < packed_polys.has_coeff_plaintexts[output_slice].size() &&
          packed_polys.has_coeff_plaintexts[output_slice][coeff_begin]) {
        evaluator.add_plain_inplace(acc, coeff_plaintexts[coeff_begin]);
      }
      return acc;
    }

    seal::Ciphertext acc;
    encryptor.encrypt_zero(acc);

    for (uint32_t d : packed_polys.normal_non_zero_degrees[output_slice]) {
      if (d <= coeff_begin || d > coeff_end) {
        continue;
      }
      const size_t power_degree = power_offset + (d - coeff_begin);
      UPSU_ENFORCE(power_degree < all_powers.size(), "power {} out of range {}",
                   power_degree, all_powers.size());
      seal::Ciphertext term;
      evaluator.multiply_plain(all_powers[power_degree], coeff_plaintexts[d],
                               term);
      evaluator.add_inplace(acc, term);
    }

    if (coeff_begin < packed_polys.has_coeff_plaintexts[output_slice].size() &&
        packed_polys.has_coeff_plaintexts[output_slice][coeff_begin]) {
      evaluator.add_plain_inplace(acc, coeff_plaintexts[coeff_begin]);
    }

    return acc;
  };

  if (ps_low_degree == 0 || ps_low_degree >= max_degree) {
    return eval_direct(0, max_degree, 0);
  }

  const size_t step = ps_low_degree + 1;
  const char* optimized_option = std::getenv("PSU_FUSED_NTT");
  const bool optimized = optimized_option && std::strcmp(optimized_option, "1") == 0;
  const size_t poly_degree = optimized && output_slice > 0 ? max_degree - 1 : max_degree;
  const char* lazy_option = std::getenv("PSU_LAZY_RELINEARIZE");
  const bool lazy_relinearize = lazy_option && std::strcmp(lazy_option, "1") == 0;
  seal::Ciphertext acc;
  if (!optimized) encryptor.encrypt_zero(acc);

  for (size_t block = 0; block * step <= poly_degree; ++block) {
    const size_t block_base = block * step;
    const size_t block_end = std::min(poly_degree, block_base + ps_low_degree);
    if (optimized && block > 0 && block_base == block_end) {
      if (packed_polys.has_coeff_plaintexts[output_slice][block_base]) {
        seal::Ciphertext term;
        evaluator.multiply_plain(all_powers[block_base],
            packed_polys.coeff_plaintexts[output_slice][block_base], term);
        evaluator.add_inplace(acc, term);
      }
      continue;
    }
    seal::Ciphertext inner = eval_direct(block_base, block_end, 0);
    if (block == 0) {
      if (optimized) acc = std::move(inner);
      else evaluator.add_inplace(acc, inner);
      continue;
    }

    UPSU_ENFORCE(block_base < all_powers.size(),
                 "high power {} out of range {}", block_base,
                 all_powers.size());
    seal::Ciphertext term;
    evaluator.multiply(inner, all_powers[block_base], term);
    if (!lazy_relinearize) evaluator.relinearize_inplace(term, relin_keys);
    evaluator.add_inplace(acc, term);
  }

  if (lazy_relinearize && acc.size() > 2) evaluator.relinearize_inplace(acc, relin_keys);
  return acc;
}

uint64_t SyntheticCoeff(size_t bin_idx, size_t sub_idx, size_t output_slice,
                        size_t degree, size_t poly_degree, uint64_t prime) {
  if (degree > poly_degree) {
    return 0;
  }

  uint64_t seed = SplitMix64(static_cast<uint64_t>(bin_idx + 1));
  seed ^= SplitMix64((static_cast<uint64_t>(sub_idx + 1) << 20) ^
                     static_cast<uint64_t>(output_slice + 1));
  seed ^= SplitMix64(static_cast<uint64_t>(degree + 1) << 32);
  uint64_t coeff = seed % prime;
  if (coeff == 0 && degree <= poly_degree) {
    coeff = 1;
  }
  return coeff;
}

seal::Ciphertext EvalSyntheticPolyOnPackedSlots(
    const std::vector<seal::Ciphertext>& all_powers, size_t slot_offset,
    size_t active_slots, size_t sub_idx, size_t output_slice,
    size_t max_degree, size_t ps_low_degree, uint64_t prime,
    const seal::RelinKeys& relin_keys, seal::Evaluator& evaluator,
    seal::Encryptor& encryptor, seal::BatchEncoder& encoder) {
  const size_t poly_degree =
      (output_slice == 0 || max_degree == 0) ? max_degree : (max_degree - 1);

  auto eval_direct = [&](size_t coeff_begin, size_t coeff_end,
                         size_t power_offset) -> seal::Ciphertext {
    seal::Ciphertext acc;
    encryptor.encrypt_zero(acc);
    std::vector<uint64_t> coeff_slots(active_slots, 0ULL);

    for (size_t d = coeff_begin + 1; d <= coeff_end; ++d) {
      const size_t power_degree = power_offset + (d - coeff_begin);
      bool has_non_zero_coeff = false;
      for (size_t slot_idx = 0; slot_idx < active_slots; ++slot_idx) {
        const size_t bin_idx = slot_offset + slot_idx;
        const uint64_t coeff =
            SyntheticCoeff(bin_idx, sub_idx, output_slice, d, poly_degree,
                           prime);
        coeff_slots[slot_idx] = coeff;
        has_non_zero_coeff |= (coeff != 0);
      }

      if (!has_non_zero_coeff) {
        continue;
      }

      UPSU_ENFORCE(power_degree < all_powers.size(),
                   "synthetic power {} out of range {}", power_degree,
                   all_powers.size());
      auto coeff_pt = EncodeSlots(encoder, coeff_slots, prime);
      seal::Ciphertext term;
      evaluator.multiply_plain(all_powers[power_degree], coeff_pt, term);
      evaluator.add_inplace(acc, term);
    }

    bool has_constant = false;
    for (size_t slot_idx = 0; slot_idx < active_slots; ++slot_idx) {
      const size_t bin_idx = slot_offset + slot_idx;
      const uint64_t c0 =
          SyntheticCoeff(bin_idx, sub_idx, output_slice, coeff_begin,
                         poly_degree, prime);
      coeff_slots[slot_idx] = c0;
      has_constant |= (c0 != 0);
    }
    if (has_constant) {
      auto c0_pt = EncodeSlots(encoder, coeff_slots, prime);
      evaluator.add_plain_inplace(acc, c0_pt);
    }

    return acc;
  };

  if (ps_low_degree == 0 || ps_low_degree >= max_degree) {
    return eval_direct(0, poly_degree, 0);
  }

  const size_t step = ps_low_degree + 1;
  seal::Ciphertext acc;
  encryptor.encrypt_zero(acc);

  for (size_t block = 0; block * step <= poly_degree; ++block) {
    const size_t block_base = block * step;
    const size_t block_end = std::min(poly_degree, block_base + ps_low_degree);
    seal::Ciphertext inner = eval_direct(block_base, block_end, 0);
    if (block == 0) {
      evaluator.add_inplace(acc, inner);
      continue;
    }

    seal::Ciphertext term;
    evaluator.multiply(inner, all_powers[block_base], term);
    evaluator.relinearize_inplace(term, relin_keys);
    evaluator.add_inplace(acc, term);
  }

  return acc;
}

std::vector<seal::Ciphertext> ComputeAllPowersFromSources(
    const std::vector<seal::Ciphertext>& source_ciphertexts,
    const std::vector<std::uint32_t>& source_power_vec,
    const std::set<std::uint32_t>& target_powers,
    const seal::RelinKeys& relin_keys, seal::Evaluator& evaluator, size_t max_depth) {
  UPSU_ENFORCE(!target_powers.empty(), "target powers cannot be empty");
  const size_t max_degree = *target_powers.rbegin();
  std::set<std::uint32_t> source_powers(source_power_vec.begin(),
                                        source_power_vec.end());
  upsu::PowersDag dag;
  UPSU_ENFORCE(dag.configure(source_powers, target_powers),
               "failed to configure PowersDag");
  UPSU_ENFORCE(dag.depth() <= max_depth,
               "source-power depth {} exceeds public limit {}", dag.depth(), max_depth);
  UPSU_ENFORCE(source_ciphertexts.size() == source_power_vec.size(),
               "source ciphertext count {} mismatches source powers {}",
               source_ciphertexts.size(), source_power_vec.size());

  std::vector<seal::Ciphertext> all_powers(max_degree + 1);
  for (size_t i = 0; i < source_power_vec.size(); ++i) {
    all_powers[source_power_vec[i]] = source_ciphertexts[i];
  }

  dag.apply([&](const upsu::PowersDag::PowersNode& node) {
    if (node.is_source()) {
      return;
    }

    UPSU_ENFORCE(node.power <= max_degree, "node power {} exceeds max_degree {}",
                 node.power, max_degree);
    UPSU_ENFORCE(node.parents.first > 0 && node.parents.second > 0,
                 "invalid PowersDag parents");

    seal::Ciphertext product;
    evaluator.multiply(all_powers[node.parents.first],
                       all_powers[node.parents.second], product);
    evaluator.relinearize_inplace(product, relin_keys);
    all_powers[node.power] = std::move(product);
  });

  return all_powers;
}

void MaterializeSenderOnlineCacheImpl(
    const std::shared_ptr<PreparedSender>& prepared,
    const ProtocolParams& params) {
  if (!prepared || SyntheticOnlineEnabled() || !NttPlainEvalEnabled() ||
      prepared->packed_plaintexts_online_ready ||
      prepared->packed_bin_plaintexts.empty()) {
    return;
  }

  auto context = CreateBfvContext(params);
  auto context_data = context->first_context_data();
  UPSU_ENFORCE(context_data != nullptr, "missing first BFV context data");
  const auto parms_id = context_data->parms_id();

  upsu::parallel_for(
      0, static_cast<int64_t>(prepared->packed_bin_plaintexts.size()),
      [&](int64_t begin, int64_t end) {
        seal::Evaluator evaluator(*context);
        for (int64_t batch_idx = begin; batch_idx < end; ++batch_idx) {
          for (auto& packed : prepared->packed_bin_plaintexts[batch_idx]) {
            if (packed.non_constant_ntt) {
              RebuildPackedDegreeIndex(&packed, prepared->ks,
                                       prepared->max_degree);
              continue;
            }
            const char* fused_option = std::getenv("PSU_FUSED_NTT");
            const bool precompute = fused_option && std::strcmp(fused_option, "1") == 0 &&
                context_data->parms().coeff_modulus().front().bit_count() > 52;
            packed.coeff_quotients.resize(prepared->ks);
            packed.coeff_plaintexts_ntt.resize(prepared->ks);
            for (size_t output_slice = 0; output_slice < prepared->ks;
                 ++output_slice) {
              packed.coeff_plaintexts_ntt[output_slice].resize(
                  prepared->max_degree + 1);
              packed.coeff_quotients[output_slice].resize(prepared->max_degree + 1);
              for (size_t degree = 1; degree <= prepared->max_degree; ++degree) {
                if (!packed.has_coeff_plaintexts[output_slice][degree]) {
                  continue;
                }
                if (DegreeNeedsNormalPlaintext(degree, prepared->max_degree,
                                              prepared->ps_low_degree)) {
                  continue;
                }
                packed.coeff_plaintexts_ntt[output_slice][degree] =
                    packed.coeff_plaintexts[output_slice][degree];
                evaluator.transform_to_ntt_inplace(
                    packed.coeff_plaintexts_ntt[output_slice][degree], parms_id);
                if (precompute) packed.coeff_quotients[output_slice][degree] =
                    paper::NttQuotients(packed.coeff_plaintexts_ntt[output_slice][degree], *context);
                packed.coeff_plaintexts[output_slice][degree].release();
              }
            }
            packed.non_constant_ntt = true;
            RebuildPackedDegreeIndex(&packed, prepared->ks,
                                     prepared->max_degree);
          }
        }
      });

  prepared->packed_plaintexts_online_ready = true;
}

}

void MaterializeSenderOnlineCache(
    const std::shared_ptr<PreparedSender>& prepared,
    const ProtocolParams& params) {
  MaterializeSenderOnlineCacheImpl(prepared, params);
}

size_t ComputePolyLinkHashBits(size_t sender_set_size, size_t receiver_set_size,
                          size_t lambda) {
  return CeilLog2(sender_set_size) + CeilLog2(receiver_set_size) + lambda;
}

uint64_t ChoosePlainModulus(size_t poly_modulus_degree, size_t sigma2_bits) {
  UPSU_ENFORCE(sigma2_bits > 0 && sigma2_bits < 63,
               "sigma2_bits must be in [1, 62], got {}", sigma2_bits);
  for (size_t bit_size = sigma2_bits + 1; bit_size <= 60; ++bit_size) {
    try {
      const auto plain_modulus = seal::PlainModulus::Batching(
          poly_modulus_degree, static_cast<int>(bit_size));
      return plain_modulus.value();
    } catch (const std::logic_error&) {
      continue;
    }
  }
  UPSU_THROW("failed to find batching plain modulus for poly_modulus_degree={} "
             "and sigma2_bits={}",
             poly_modulus_degree, sigma2_bits);
}

size_t EstimateFheKeyCommBytes(const ProtocolParams& params) {
  auto context = CreateBfvContext(params);
  seal::KeyGenerator keygen(*context);
  seal::PublicKey public_key;
  keygen.create_public_key(public_key);
  seal::RelinKeys relin_keys;
  keygen.create_relin_keys(relin_keys);
  const auto pk_blob = SerializeSealObject(public_key);
  const auto relin_blob = SerializeSealObject(relin_keys);
  return pk_blob.size() + relin_blob.size();
}

AlphaSampleMetrics SampleAlphaAfterEncoding(
    const std::vector<std::string>& sender_items, size_t receiver_set_size,
    const ProtocolParams& params) {
  constexpr size_t kSimpleHashCount = 3;
  const size_t m = params.simple_hash_bins;
  const uint64_t prime = params.plain_modulus;
  const size_t item_bit_count =
      params.EffectiveItemBitCount();
  const size_t sigma2_bits = CeilDiv(item_bit_count, params.ks);
  const size_t first_domain_size =
      (sigma2_bits < 63)
          ? std::min<size_t>(static_cast<size_t>(prime),
                             size_t{1} << sigma2_bits)
          : 0;

  UPSU_ENFORCE(!sender_items.empty(), "sender item set must not be empty");
  UPSU_ENFORCE(receiver_set_size > 0, "receiver set size must be positive");
  UPSU_ENFORCE(m > 0, "simple_hash_bins must be positive");
  UPSU_ENFORCE(params.ks > 0, "ks must be positive");
  UPSU_ENFORCE(sigma2_bits > 0 && sigma2_bits <= 62,
               "sigma2_bits must be in [1, 62], got {}", sigma2_bits);
  UPSU_ENFORCE(first_domain_size > 0,
               "first-slice domain must be positive");
  UPSU_ENFORCE(sender_items.size() <=
                   std::numeric_limits<size_t>::max() / kSimpleHashCount,
               "sender item set too large for alpha sampling");

  const size_t bin_bits = CeilLog2(m);
  const size_t first_bits = CeilLog2(first_domain_size);
  UPSU_ENFORCE(bin_bits + first_bits <= 64,
               "alpha sampler key is too wide to pack: bin_bits={} "
               "first_bits={}",
               bin_bits, first_bits);
  const uint64_t first_mask =
      (first_bits == 64) ? UINT64_MAX : ((uint64_t{1} << first_bits) - 1);

  auto x_oprf = encoding::Encode(encoding::FreshSalt(), sender_items);

  std::vector<size_t> bin_counts(m, 0);
  std::vector<uint64_t> packed_keys;
  packed_keys.reserve(sender_items.size() * kSimpleHashCount);
  for (uint128_t oprf_value : x_oprf) {
    const uint128_t sender_token = MaskBits(oprf_value, params.sigma1_bits);
    const HashedTableItem item =
        BuildHashedTableItem(sender_token, item_bit_count, m,
                             params.use_permutation_hashing);
    const uint64_t first =
        FirstSliceOfItem(item.stored_item, params.ks, sigma2_bits, prime);
    UPSU_ENFORCE(first <= first_mask,
                 "first-slice value {} exceeds packed mask {}", first,
                 first_mask);
    for (size_t h = 1; h <= kSimpleHashCount; ++h) {
      const size_t bin =
          static_cast<size_t>(TableHashBin(item, h, m,
                                           params.use_permutation_hashing,
                                           params.PermutationIndexBits()));
      ++bin_counts[bin];
      packed_keys.push_back((static_cast<uint64_t>(bin) << first_bits) | first);
    }
  }
  x_oprf.clear();
  x_oprf.shrink_to_fit();

  std::sort(packed_keys.begin(), packed_keys.end());
  size_t required_alpha = 1;
  size_t run_length = 0;
  uint64_t previous_key = 0;
  for (uint64_t key : packed_keys) {
    if (run_length > 0 && key == previous_key) {
      ++run_length;
    } else {
      run_length = 1;
      previous_key = key;
    }
    required_alpha = std::max(required_alpha, run_length);
  }

  const size_t max_bin_size =
      *std::max_element(bin_counts.begin(), bin_counts.end());
  size_t alpha = std::max(params.alpha, required_alpha);
  if (params.max_items_per_bin > 0) {
    const size_t alpha_for_cap =
        std::max<size_t>(1, (max_bin_size + params.max_items_per_bin - 1) /
                                params.max_items_per_bin);
    alpha = std::max(alpha, alpha_for_cap);
  }
  if (alpha == 0) {
    alpha = 1;
  }

  AlphaSampleMetrics metrics;
  metrics.sender_size = sender_items.size();
  metrics.receiver_size = receiver_set_size;
  metrics.simple_hash_bins = m;
  metrics.simple_hash_count = kSimpleHashCount;
  metrics.sigma1_bits = params.sigma1_bits;
  metrics.item_bit_count = item_bit_count;
  metrics.ks = params.ks;
  metrics.sigma2_bits = sigma2_bits;
  metrics.plain_modulus = params.plain_modulus;
  metrics.alpha_min = params.alpha;
  metrics.max_items_per_bin = params.max_items_per_bin;
  metrics.required_alpha = required_alpha;
  metrics.alpha = alpha;
  metrics.max_bin_size = max_bin_size;
  metrics.sub_bin_size =
      std::max<size_t>(1, (max_bin_size + alpha - 1) / alpha);
  return metrics;
}

std::shared_ptr<PreparedSender> PrepareSender(
    const std::vector<std::string>& sender_items, const ProtocolParams& params) {
  const auto prep_start = std::chrono::high_resolution_clock::now();
  const uint64_t prime = params.plain_modulus;
  const size_t m = params.simple_hash_bins;
  const size_t item_bit_count =
      params.EffectiveItemBitCount();

  UPSU_ENFORCE(m > 0, "simple_hash_bins must be positive");
  UPSU_ENFORCE(params.ks > 0, "ks must be positive");

  auto prepared = std::make_shared<PreparedSender>();
  std::vector<uint128_t> sender_tokens;
  if (params.use_salted_hash) {
    const auto hash_start = std::chrono::high_resolution_clock::now();
    prepared->encoding_salt = encoding::FreshSalt();
    sender_tokens = encoding::Encode(prepared->encoding_salt, sender_items);
    TraceStage("send", "computed receiver offline salted BLAKE3 encodings in " +
                           std::to_string(SecondsSince(hash_start, std::chrono::high_resolution_clock::now())) + " s");
  } else {
    const auto token_start = std::chrono::high_resolution_clock::now();
    sender_tokens =
        EncodeItemsAsProtocolTokens(sender_items, params.sigma1_bits);
    const auto token_end = std::chrono::high_resolution_clock::now();
    TraceStage("send", "decoded S3MT input encodings in " +
                           std::to_string(
                               SecondsSince(token_start, token_end)) +
                           " s");
  }
  paper::RequireDistinctEncodings(sender_tokens);
  const auto hash_start = std::chrono::high_resolution_clock::now();
  const size_t effective_kv = 1;
  SimpleHashTable sh_table(m, params.use_permutation_hashing,
                           params.PermutationIndexBits());
  const auto hash_items_start = std::chrono::high_resolution_clock::now();
  auto hashed_items =
      BuildHashedTableItems(sender_tokens, item_bit_count, m,
                            params.use_permutation_hashing);
  const auto hash_items_end = std::chrono::high_resolution_clock::now();
  TraceStage("send", "built sender hashed table items in " +
                         std::to_string(
                             SecondsSince(hash_items_start, hash_items_end)) +
                         " s");

  const auto insert_start = std::chrono::high_resolution_clock::now();
  sh_table.InsertAll(hashed_items, effective_kv);
  const auto insert_end = std::chrono::high_resolution_clock::now();
  TraceStage("send", "inserted sender simple-hash table in " +
                         std::to_string(SecondsSince(insert_start, insert_end)) +
                         " s");

  const bool require_unique_first_slice = true;
  const auto shape_start = std::chrono::high_resolution_clock::now();
  SelectedKsConfig selected = SelectKsConfig(
      sh_table, params, item_bit_count, prime, require_unique_first_slice);
  const auto shape_end = std::chrono::high_resolution_clock::now();
  TraceStage("send", "estimated sender shape and built partitioned bins in " +
                         std::to_string(SecondsSince(shape_start, shape_end)) +
                         " s");
  const auto hash_end = std::chrono::high_resolution_clock::now();
  prepared->ks = selected.ks;
  prepared->sigma2_bits = selected.sigma2_bits;
  prepared->item_bit_count = selected.item_bit_count;
  prepared->alpha_eff = selected.alpha_eff;
  prepared->max_degree = selected.max_degree;
  prepared->ps_low_degree = selected.ps_low_degree;
  prepared->target_powers = selected.target_powers;
  prepared->source_power_vec = selected.source_power_vec;
  prepared->m = m;
  const auto target_power_vec = ToSortedVector(prepared->target_powers);
  const size_t sub_bin_count = prepared->m * prepared->alpha_eff;
  TraceStage(
      "send", "selected ks=" + std::to_string(prepared->ks) +
                  ", sigma2_bits=" + std::to_string(prepared->sigma2_bits) +
                  ", item_bits=" + std::to_string(prepared->item_bit_count) +
                  ", drop_first_poly=" +
                  std::string(params.drop_first_poly ? "on" : "off") +
                  ", permutation_hashing=" +
                  std::string(params.use_permutation_hashing ? "on" : "off") +
                  ", q_ct=" + std::to_string(selected.query_cipher_count) +
                  ", r_ct=" + std::to_string(selected.eval_cipher_count));
  TraceStage("send", "window source powers count=" +
                         std::to_string(prepared->source_power_vec.size()) +
                         ", B=" + std::to_string(sh_table.max_bin_size) +
                         ", alpha=" + std::to_string(prepared->alpha_eff) +
                         ", max_degree=" + std::to_string(prepared->max_degree) +
                         ", sub_bins=" + std::to_string(sub_bin_count) +
                         ", ps_low_degree=" +
                         std::to_string(prepared->ps_low_degree) +
                         ", W={" + JoinPowers(prepared->source_power_vec) + "}" +
                         ", T={" + JoinPowers(target_power_vec) + "}");
  TraceStage("send", "sender hashing + partitioning in " +
                         std::to_string(SecondsSince(hash_start, hash_end)) +
                         " s");

  if (SyntheticOnlineEnabled()) {
    TraceStage("send",
               "synthetic online timing mode: skipping sender polynomial "
               "construction");
    return prepared;
  }

  const auto poly_start = std::chrono::high_resolution_clock::now();
  prepared->bin_polys.assign(
      m, std::vector<BinPolySet>(prepared->alpha_eff));
  std::atomic<size_t> bins_completed{0};
  const size_t report_every_bins = std::max<size_t>(1, m / 16);
  upsu::parallel_for(0, m, [&](int64_t begin, int64_t end) {
    for (int64_t bin_idx = begin; bin_idx < end; ++bin_idx) {
      for (size_t sub_idx = 0; sub_idx < prepared->alpha_eff; ++sub_idx) {
        const auto& sub_bin_items = selected.partitioned.bins[bin_idx][sub_idx];
        prepared->bin_polys[bin_idx][sub_idx] =
            BuildPolyLinkBinPolySet(sub_bin_items, prepared->ks,
                                    FieldBitWidth(prime), prime,
                                    params.drop_first_poly);
      }

      const size_t done = bins_completed.fetch_add(1, std::memory_order_relaxed) + 1;
      if (done == m || (done % report_every_bins) == 0) {
        const auto now = std::chrono::high_resolution_clock::now();
        const double elapsed_s = SecondsSince(poly_start, now);
        const double bins_per_s = (elapsed_s > 0.0)
                                      ? static_cast<double>(done) / elapsed_s
                                      : 0.0;
        const double remaining_bins =
            static_cast<double>(m > done ? (m - done) : 0);
        const double eta_s =
            (bins_per_s > 0.0) ? (remaining_bins / bins_per_s) : 0.0;
        const size_t percent = (done * 100) / m;
        TraceStage("send",
                   "building sender polynomial tables: " +
                       std::to_string(done) + "/" + std::to_string(m) +
                       " simple bins (" + std::to_string(percent) +
                       "%, sub-bins=" +
                       std::to_string(done * prepared->alpha_eff) + "/" +
                       std::to_string(sub_bin_count) + ", elapsed=" +
                       std::to_string(elapsed_s) + " s, eta~" +
                       std::to_string(eta_s) + " s)");
      }
    }
  });
  const auto poly_end = std::chrono::high_resolution_clock::now();
  TraceStage("send", "built sender polynomial tables in " +
                         std::to_string(SecondsSince(poly_start, poly_end)) +
                         " s");

  const auto pack_start = std::chrono::high_resolution_clock::now();
  auto context = CreateBfvContext(params);
  prepared->packed_bin_plaintexts = BuildPackedPlaintextPolyCache(
      prepared->bin_polys, prepared->alpha_eff, prepared->ks, m,
      prepared->max_degree, prime, context);
  const auto pack_end = std::chrono::high_resolution_clock::now();
  TraceStage("send", "cached sender batched plaintext coefficients in " +
                         std::to_string(SecondsSince(pack_start, pack_end)) +
                         " s");
  prepared->bin_polys.clear();
  prepared->bin_polys.shrink_to_fit();

  const auto prep_end = std::chrono::high_resolution_clock::now();
  TraceStage("send", "sender prepare total " +
                         std::to_string(SecondsSince(prep_start, prep_end)) +
                         " s");

  return prepared;
}

std::optional<std::vector<uint8_t>> SendPreparedImpl(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::shared_ptr<PreparedSender>& prepared,
    const ProtocolParams& params, bool direct_ote,
    OnlineStats* online_stats) {
  const auto offline_phase_start = std::chrono::high_resolution_clock::now();
  upsu::set_experiment_phase(true, "interactive_setup");
  const uint64_t prime = params.plain_modulus;
  const size_t ks = prepared->ks;
  const bool use_circuit_peqt = CircuitPeqtEnabled(params);
  const size_t output_slice_begin = OutputSliceBegin(params);
  const size_t output_poly_count = OutputPolyCount(params, ks);
  const size_t m = prepared->m;
  const size_t alpha_eff = prepared->alpha_eff;
  const size_t max_degree = prepared->max_degree;
  const size_t ps_low_degree = prepared->ps_low_degree;
  const auto& source_power_vec = prepared->source_power_vec;
  const size_t peqt_field_bits = FieldBitWidth(prime);
  const size_t peqt_packed_bits = output_poly_count * peqt_field_bits;
  UPSU_ENFORCE(!use_circuit_peqt || !SyntheticOnlineEnabled(),
               "packed circuit PEQT requires real PolyLinks evaluations");
  UPSU_ENFORCE(!use_circuit_peqt || peqt_packed_bits <= 128,
               "packed circuit PEQT exceeds 128 bits: ks={} field_bits={}",
               ks, peqt_field_bits);
  const bool use_permuted_peqt = PermutedPeqtEnabled(params);
  const size_t perm_row_bytes = PackedRowBytes(peqt_packed_bits);
  std::vector<uint128_t> sender_peqt_masks;
  if (use_circuit_peqt) {
    sender_peqt_masks.resize(m * alpha_eff, 0);
  }
  std::optional<PermSenderState> perm_state;
  std::unique_ptr<peqt::PreparedCircuitGmwState> peqt_prepared;


  std::vector<uint64_t> meta = {static_cast<uint64_t>(m),
                                static_cast<uint64_t>(alpha_eff),
                                static_cast<uint64_t>(max_degree),
                                static_cast<uint64_t>(prepared->ks),
                                static_cast<uint64_t>(prepared->sigma2_bits),
                                static_cast<uint64_t>(prepared->ps_low_degree)};
  ctx->SendAsync(ctx->NextRank(),
                 upsu::Bytes(meta.data(),
                                         meta.size() * sizeof(uint64_t)),
                 kMetaTag);
  TraceStage("send", "sent metadata");
  if (use_permuted_peqt) {
    const size_t perm_row_count = direct_ote ? m : (m * alpha_eff);
    const size_t setup_row_bytes = direct_ote ? 1 : perm_row_bytes;
    perm_state.emplace(
        SetupPermutedPeqtSender(perm_row_count, setup_row_bytes, online_stats));
    TraceStage("send", direct_ote ? "finished direct OTE permutation setup"
                                  : "finished PEQT permutation setup");
  }
  if (use_circuit_peqt) {
    const auto peqt_setup_start = std::chrono::high_resolution_clock::now();
    if (direct_ote) {
      peqt_prepared = std::make_unique<peqt::PreparedCircuitGmwState>(
          peqt::PrepareAnyZeroU128Blocks2PC(ctx, ctx->Rank(), m, alpha_eff,
                                            peqt_packed_bits,
                                            "PSU_PEQT_ANYZERO"));
    } else {
      peqt_prepared = std::make_unique<peqt::PreparedCircuitGmwState>(
          peqt::PrepareEqU128Vec2PCPreRot(ctx, ctx->Rank(), m * alpha_eff,
                                          peqt_packed_bits, "PSU_PEQT"));
    }
    const auto peqt_setup_end = std::chrono::high_resolution_clock::now();
    if (online_stats) {
      const double elapsed = SecondsSince(peqt_setup_start, peqt_setup_end);
      online_stats->setup_time_s += elapsed;
      online_stats->peqt_setup_time_s += elapsed;
      online_stats->peqt_setup_local_sent_bytes +=
          peqt_prepared->setup_sent_bytes;
      online_stats->peqt_setup_local_recv_bytes +=
          peqt_prepared->setup_recv_bytes;
    }
    TraceStage("send", "finished PEQT triple setup");
  }

  const auto setup_start = std::chrono::high_resolution_clock::now();
  auto context = CreateBfvContext(params);
  TraceStage("send", "waiting for receiver public key");
  auto pk_buf = ctx->Recv(ctx->PrevRank(), kPublicKeyTag);
  std::string pk_blob(reinterpret_cast<const char*>(pk_buf.data()),
                      pk_buf.size());
  seal::PublicKey public_key =
      DeserializeSealObject<seal::PublicKey>(context, pk_blob);
  auto relin_buf = ctx->Recv(ctx->PrevRank(), kRelinKeysTag);
  std::string relin_blob(reinterpret_cast<const char*>(relin_buf.data()),
                         relin_buf.size());
  seal::RelinKeys relin_keys =
      DeserializeSealObject<seal::RelinKeys>(context, relin_blob);
  if(online_stats) {
    online_stats->fhe_key_comm_bytes=
        ctx->MessageBytes(pk_blob.size(),kPublicKeyTag)+ctx->MessageBytes(relin_blob.size(),kRelinKeysTag);
    online_stats->fhe_key_saved_bytes=
        upsu::serialization::UncompressedSize(reinterpret_cast<const uint8_t*>(pk_blob.data()),pk_blob.size())+
        upsu::serialization::UncompressedSize(reinterpret_cast<const uint8_t*>(relin_blob.data()),relin_blob.size())-
        pk_blob.size()-relin_blob.size();
  }
  seal::Evaluator evaluator(*context);
  seal::BatchEncoder encoder(*context);
  const size_t slot_count = encoder.slot_count();
  const size_t packed_bin_batch_count = CeilDiv(m, slot_count);
  const size_t evals_per_batch = alpha_eff * output_poly_count;
  const size_t response_count = packed_bin_batch_count * evals_per_batch;
  const auto sanitize_parms_id = context->first_parms_id();
  const auto response_parms_id = SelectResponseParmsId(
      *context, sanitize_parms_id, params.response_mod_switch_steps);

  const auto setup_end = std::chrono::high_resolution_clock::now();
  if (online_stats) {
    online_stats->setup_time_s += SecondsSince(setup_start, setup_end);
  }
  TraceStage("send", "received receiver public key");
  const char offline_ready = 1;
  ctx->Send(ctx->NextRank(), upsu::Bytes(&offline_ready, 1), "PSU:offline_ready_v2");
  upsu::set_experiment_phase(false, "before_online_encoding");
  if (upsu::experiment_phase_threads_enabled() && online_stats) {
    online_stats->setup_time_s = SecondsSince(offline_phase_start, std::chrono::high_resolution_clock::now());
  }

  if (params.use_salted_hash) {
    UPSU_ENFORCE(!prepared->salt_disclosed, "salted preprocessing is single-use");
    const auto hash_start = std::chrono::high_resolution_clock::now();
    ctx->Send(ctx->NextRank(), upsu::Bytes(prepared->encoding_salt.data(), prepared->encoding_salt.size()), encoding::kSaltTag);
    prepared->salt_disclosed = true;
    if (online_stats) {
      online_stats->encoding_time_s += SecondsSince(hash_start, std::chrono::high_resolution_clock::now());
      online_stats->encoding_comm_bytes += ctx->MessageBytes(prepared->encoding_salt.size(), encoding::kSaltTag);
    }
    std::cout << "[input_encoding] receiver sent salt_bits=128 hash=BLAKE3 phase=online" << std::endl;
  }

  std::vector<ResponseMaskToken> response_masks(response_count);
  upsu::parallel_for(
      0, static_cast<int64_t>(response_count),
      [&](int64_t begin, int64_t end) {
        seal::Encryptor local_encryptor(*context, public_key);
        seal::Evaluator local_evaluator(*context);
        seal::BatchEncoder local_encoder(*context);
        auto pool = seal::MemoryPoolHandle::ThreadLocal();
        for (int64_t response_idx = begin; response_idx < end;
             ++response_idx) {
          const size_t batch_idx =
              static_cast<size_t>(response_idx) / evals_per_batch;
          const size_t slot_offset = batch_idx * slot_count;
          const size_t active_slots = std::min(slot_count, m - slot_offset);
          std::vector<uint64_t> mask_slots(slot_count, 0);
          if (use_circuit_peqt) {
            mask_slots = SampleResponseMask(slot_count, prime);
          }
          response_masks[static_cast<size_t>(response_idx)] =
              PrepareResponseMask(
                  *context, local_encryptor, local_evaluator, local_encoder,
                  sanitize_parms_id, params.response_flood_bits, mask_slots,
                  pool);
        }
      });
  TraceStage("send",
             "prepared " + std::to_string(response_count) +
                 " one-time response masks (flood_bits=" +
                 std::to_string(params.response_flood_bits) + ")");

  if (use_circuit_peqt) {
    for (size_t batch_idx = 0; batch_idx < packed_bin_batch_count;
         ++batch_idx) {
      const size_t slot_offset = batch_idx * slot_count;
      const size_t active_slots = std::min(slot_count, m - slot_offset);
      for (size_t slot_idx = 0; slot_idx < active_slots; ++slot_idx) {
        const size_t bin_idx = slot_offset + slot_idx;
        for (size_t sub_idx = 0; sub_idx < alpha_eff; ++sub_idx) {
          std::vector<uint64_t> elems(output_poly_count, 0);
          for (size_t output_idx = 0; output_idx < output_poly_count;
               ++output_idx) {
            const size_t eval_idx =
                sub_idx * output_poly_count + output_idx;
            const size_t response_idx =
                batch_idx * evals_per_batch + eval_idx;
            elems[output_idx] =
                response_masks[response_idx].additive_mask[slot_idx];
          }
          sender_peqt_masks[bin_idx * alpha_eff + sub_idx] =
              PackFieldElements(elems, peqt_field_bits);
        }
      }
    }
  }

  const size_t query_slice_count = 1;
  TraceStage("send", "waiting for encrypted query powers");
  auto query_buf = ctx->Recv(ctx->PrevRank(), kQueryCiphertextTag);
  PackedBlobCursor query_cursor(query_buf);
  const size_t expected_query_ct_count =
      packed_bin_batch_count * query_slice_count * source_power_vec.size();
  UPSU_ENFORCE(query_cursor.count == expected_query_ct_count,
               "query ciphertext count mismatch: got {}, expect {}",
               query_cursor.count, expected_query_ct_count);
  TraceStage("send", "received " + std::to_string(query_cursor.count) +
                         " encrypted query ciphertexts");

  std::vector<seal::Ciphertext> query_ciphertexts(expected_query_ct_count);
  for (size_t idx = 0; idx < expected_query_ct_count; ++idx) {
    const auto [blob_data, blob_size] = query_cursor.Next();
    query_ciphertexts[idx] =
        DeserializeSealObject<seal::Ciphertext>(context, blob_data, blob_size);
  }
  query_cursor.EnforceFinished();

  std::vector<seal::Ciphertext> eval_ciphertexts(packed_bin_batch_count *
                                                 evals_per_batch);
  for (size_t batch_idx = 0; batch_idx < packed_bin_batch_count; ++batch_idx) {
    const size_t slot_offset = batch_idx * slot_count;
    const size_t active_slots = std::min(slot_count, m - slot_offset);
    std::vector<std::vector<seal::Ciphertext>> reconstructed_powers(
        query_slice_count);
    std::vector<std::vector<seal::Ciphertext>> reconstructed_powers_ntt(
        query_slice_count);

    for (size_t query_slice_idx = 0; query_slice_idx < query_slice_count;
         ++query_slice_idx) {
      std::vector<seal::Ciphertext> source_ciphertexts;
      source_ciphertexts.reserve(source_power_vec.size());
      for (size_t source_idx = 0; source_idx < source_power_vec.size();
           ++source_idx) {
        const size_t query_index =
            QueryCipherIndex(batch_idx, query_slice_idx, query_slice_count,
                             source_power_vec.size(), source_idx);
        UPSU_ENFORCE(query_index < query_ciphertexts.size(),
                     "query ciphertext index {} out of range {}",
                     query_index, query_ciphertexts.size());
        source_ciphertexts.push_back(query_ciphertexts[query_index]);
      }
      reconstructed_powers[query_slice_idx] = ComputeAllPowersFromSources(
          source_ciphertexts, source_power_vec, prepared->target_powers,
          relin_keys,
          evaluator, params.query_powers_max_depth);
      if (prepared->packed_plaintexts_online_ready) {
        reconstructed_powers_ntt[query_slice_idx] =
            TransformCiphertextsToNtt(reconstructed_powers[query_slice_idx],
                                      evaluator);
      }
    }
    TraceStage("send", "derived encrypted target powers for batch " + std::to_string(batch_idx));

    upsu::parallel_for(
        0, evals_per_batch, [&](int64_t begin, int64_t end) {
          seal::Evaluator local_evaluator(*context);
          seal::Encryptor local_encryptor(*context, public_key);
          seal::BatchEncoder local_encoder(*context);
          auto pool = seal::MemoryPoolHandle::ThreadLocal();

          for (int64_t eval_idx = begin; eval_idx < end; ++eval_idx) {
            const size_t sub_idx =
                static_cast<size_t>(eval_idx) / output_poly_count;
            const size_t output_idx =
                static_cast<size_t>(eval_idx) % output_poly_count;
            const size_t s = output_slice_begin + output_idx;
            const size_t variable_slice = 0;
            seal::Ciphertext eval_ct =
                SyntheticOnlineEnabled()
                    ? EvalSyntheticPolyOnPackedSlots(
                          reconstructed_powers[variable_slice], slot_offset,
                          active_slots, sub_idx, s, max_degree, ps_low_degree,
                          prime, relin_keys, local_evaluator, local_encryptor,
                          local_encoder)
                    : EvalPolyOnPackedSlots(
                          prepared->packed_bin_plaintexts[batch_idx][sub_idx],
                          reconstructed_powers[variable_slice], s, max_degree,
                          ps_low_degree, relin_keys, local_evaluator,
                          local_encryptor, *context,
                          prepared->packed_plaintexts_online_ready
                              ? &reconstructed_powers_ntt[variable_slice]
                              : nullptr);
            const size_t response_idx =
                batch_idx * evals_per_batch +
                static_cast<size_t>(eval_idx);
            ApplyResponseMask(eval_ct,
                              std::move(response_masks[response_idx]),
                              response_parms_id, *context, local_evaluator,
                              pool);
            eval_ciphertexts[response_idx] = std::move(eval_ct);
          }
        });
  }
  TraceStage("send", "evaluated all packed polynomials");

  auto packed_eval = BeginPackedBlobVector(eval_ciphertexts.size());
  for (const auto& eval_ct : eval_ciphertexts) {
    AppendSerializedSealObject(&packed_eval, eval_ct);
  }
  ctx->SendAsync(ctx->NextRank(),
                 upsu::Bytes(packed_eval.data(),
                                         packed_eval.size()),
                 kEvalCiphertextTag);
  TraceStage("send", "sent " + std::to_string(eval_ciphertexts.size()) +
                         " encrypted evaluation ciphertexts");
  if (use_circuit_peqt) {
    std::vector<uint128_t> sender_peqt_shares = sender_peqt_masks;
    if (use_permuted_peqt && !direct_ote) {
      sender_peqt_shares =
          ApplyPermutedPeqtSender(sender_peqt_masks, &*perm_state, online_stats);
      TraceStage("send", "applied PEQT permutation share");
    }
    const auto peqt_link_begin = TakeLinkCommSnapshot(ctx);
    const auto peqt_local_begin =
        TakeLocalPeqtCommSnapshot(static_cast<size_t>(ctx->Rank()));
    const auto peqt_start = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> sender_eq_shares;
    if (direct_ote) {
      UPSU_ENFORCE(peqt_prepared != nullptr,
                   "direct PEQT state must be prepared before online run");
      sender_eq_shares = peqt::RunPreparedAnyZeroU128Blocks2PC(
          *peqt_prepared, sender_peqt_shares, alpha_eff, "PSU_PEQT_ANYZERO");
    } else {
      UPSU_ENFORCE(peqt_prepared != nullptr,
                   "PEQT state must be prepared before online run");
      sender_eq_shares = peqt::RunPreparedEqU128Vec2PCPreRot(
          *peqt_prepared, sender_peqt_shares, "PSU_PEQT");
    }
    const auto peqt_end = std::chrono::high_resolution_clock::now();
    const auto peqt_link_end = TakeLinkCommSnapshot(ctx);
    const auto peqt_local_end =
        TakeLocalPeqtCommSnapshot(static_cast<size_t>(ctx->Rank()));
    const auto peqt_link_diff =
        DiffLinkCommSnapshot(peqt_link_begin, peqt_link_end);
    const auto peqt_local_diff =
        DiffLocalPeqtCommSnapshot(peqt_local_begin, peqt_local_end);
    if (online_stats) {
      online_stats->peqt_time_s = SecondsSince(peqt_start, peqt_end);
      online_stats->peqt_link_sent_bytes += peqt_link_diff.sent_bytes;
      online_stats->peqt_link_recv_bytes += peqt_link_diff.recv_bytes;
      online_stats->peqt_local_sent_bytes += peqt_local_diff.sent_bytes;
      online_stats->peqt_local_recv_bytes += peqt_local_diff.recv_bytes;
    }
    if (!direct_ote) {
      ctx->SendAsync(ctx->NextRank(),
                     upsu::Bytes(sender_eq_shares.data(),
                                             sender_eq_shares.size()),
                     kPeqtShareTag);
      TraceStage("send", "finished packed PEQT and sent sender output shares");
      return std::nullopt;
    }

    upsu::diagnostics::Write("sender_masks.bin",sender_peqt_masks);
    upsu::diagnostics::Write("sender_eq.bin",sender_eq_shares);
    auto bin_membership_share = std::move(sender_eq_shares);
    if (use_permuted_peqt) {
      bin_membership_share = ApplyPermutedByteSharesSender(
          bin_membership_share, &*perm_state, online_stats);
          TraceStage("send", "applied direct OTE permutation share");
    }
    TraceStage("send",
               "finished packed PEQT and derived bin-level direct OTE shares");
    upsu::diagnostics::Write("sender_permuted.bin",bin_membership_share);
    return bin_membership_share;
  }

  return std::nullopt;
}

void SendPrepared(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::shared_ptr<PreparedSender>& prepared,
    const ProtocolParams& params, OnlineStats* online_stats) {
  (void)SendPreparedImpl(ctx, prepared, params, false, online_stats);
}

std::vector<uint8_t> SendPreparedDirectOteChoices(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::shared_ptr<PreparedSender>& prepared,
    const ProtocolParams& params, OnlineStats* online_stats) {
  auto maybe_share = SendPreparedImpl(ctx, prepared, params, true, online_stats);
  UPSU_ENFORCE(maybe_share.has_value(),
               "direct OTE share path requires packed PEQT to be enabled");
  return std::move(*maybe_share);
}

std::vector<uint8_t> RunS3mtSender(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::shared_ptr<PreparedSender>& prepared,
    const ProtocolParams& params, OnlineStats* online_stats) {
  return SendPreparedDirectOteChoices(ctx, prepared, params, online_stats);
}

void ProtocolSend(const std::shared_ptr<upsu::net::Context>& ctx,
                const std::vector<std::string>& sender_items,
                const ProtocolParams& params, OnlineStats* online_stats) {
  auto prepared = PrepareSender(sender_items, params);
  SendPrepared(ctx, prepared, params, online_stats);
}

struct RecvPhaseOutputs {
  std::vector<uint8_t> membership_bits;
  BinOteSenderInputs direct_ote_inputs;
};

RecvPhaseOutputs RecvPhaseCore(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::vector<std::string>& receiver_items, const ProtocolParams& params,
    bool direct_ote, OnlineStats* online_stats) {
  const auto offline_phase_start = std::chrono::high_resolution_clock::now();
  upsu::set_experiment_phase(true, "interactive_setup");
  const size_t ny = receiver_items.size();
  const uint64_t prime = params.plain_modulus;
  const bool use_circuit_peqt = CircuitPeqtEnabled(params);
  const bool use_permuted_peqt = PermutedPeqtEnabled(params);
  const size_t effective_kv = 1;
  const size_t peqt_field_bits = FieldBitWidth(prime);
  const size_t output_slice_begin = OutputSliceBegin(params);

  auto meta_buf = ctx->Recv(ctx->PrevRank(), kMetaTag);
  UPSU_ENFORCE(meta_buf.size() == 6 * sizeof(uint64_t),
               "invalid UPSI meta size");
  const auto* meta_ptr = reinterpret_cast<const uint64_t*>(meta_buf.data());
  const size_t m = static_cast<size_t>(meta_ptr[0]);
  const size_t alpha_eff = static_cast<size_t>(meta_ptr[1]);
  const size_t max_degree = static_cast<size_t>(meta_ptr[2]);
  const size_t ks = static_cast<size_t>(meta_ptr[3]);
  const size_t sigma2_bits = static_cast<size_t>(meta_ptr[4]);
  const size_t ps_low_degree = static_cast<size_t>(meta_ptr[5]);
  const auto target_powers = BuildTargetPowerSet(max_degree, ps_low_degree);
  const auto source_powers = BuildSourcePowerSet(
      target_powers, params.query_powers_max_depth, params.query_powers);
  const auto source_power_vec = ToSortedVector(source_powers);
  TraceStage("recv", "window source powers count=" +
                         std::to_string(source_power_vec.size()) +
                         ", ks=" + std::to_string(ks) +
                         ", sigma2_bits=" + std::to_string(sigma2_bits) +
                         ", max_degree=" + std::to_string(max_degree) +
                         ", ps_low_degree=" + std::to_string(ps_low_degree) +
                         ", W={" + JoinPowers(source_power_vec) + "}");
  UPSU_ENFORCE(m == params.simple_hash_bins,
               "receiver simple_hash_bins {} mismatches sender {}",
               params.simple_hash_bins, m);
  const size_t receiver_item_bit_count =
      params.EffectiveItemBitCount();
  UPSU_ENFORCE(ks > 0, "ks must be positive");
  UPSU_ENFORCE(alpha_eff > 0, "alpha_eff must be positive");
  UPSU_ENFORCE(max_degree > 0, "max_degree must be positive");
  UPSU_ENFORCE(!use_circuit_peqt || !SyntheticOnlineEnabled(),
               "packed circuit PEQT requires real PolyLinks evaluations");
  const size_t output_poly_count = OutputPolyCount(params, ks);
  UPSU_ENFORCE(!use_circuit_peqt || output_poly_count * peqt_field_bits <= 128,
               "packed circuit PEQT exceeds 128 bits: ks={} field_bits={}",
               ks, peqt_field_bits);
  const size_t peqt_packed_bits = output_poly_count * peqt_field_bits;
  const size_t perm_row_bytes = PackedRowBytes(peqt_packed_bits);
  TraceStage("recv", "received metadata");
  std::optional<PermReceiverState> perm_state;
  std::unique_ptr<peqt::PreparedCircuitGmwState> peqt_prepared;
  if (use_permuted_peqt) {
    const size_t perm_row_count = direct_ote ? m : (m * alpha_eff);
    const size_t setup_row_bytes = direct_ote ? 1 : perm_row_bytes;
    perm_state.emplace(SetupPermutedPeqtReceiver(
        perm_row_count, setup_row_bytes, 1, online_stats));
    TraceStage("recv", direct_ote ? "finished direct OTE permutation setup"
                                  : "finished PEQT permutation setup");
  }
  if (use_circuit_peqt) {
    const auto peqt_setup_start = std::chrono::high_resolution_clock::now();
    if (direct_ote) {
      peqt_prepared = std::make_unique<peqt::PreparedCircuitGmwState>(
          peqt::PrepareAnyZeroU128Blocks2PC(ctx, ctx->Rank(), m, alpha_eff,
                                            peqt_packed_bits,
                                            "PSU_PEQT_ANYZERO"));
    } else {
      peqt_prepared = std::make_unique<peqt::PreparedCircuitGmwState>(
          peqt::PrepareEqU128Vec2PCPreRot(ctx, ctx->Rank(), m * alpha_eff,
                                          peqt_packed_bits, "PSU_PEQT"));
    }
    const auto peqt_setup_end = std::chrono::high_resolution_clock::now();
    if (online_stats) {
      const double elapsed = SecondsSince(peqt_setup_start, peqt_setup_end);
      online_stats->setup_time_s += elapsed;
      online_stats->peqt_setup_time_s += elapsed;
      online_stats->peqt_setup_local_sent_bytes +=
          peqt_prepared->setup_sent_bytes;
      online_stats->peqt_setup_local_recv_bytes +=
          peqt_prepared->setup_recv_bytes;
    }
    TraceStage("recv", "finished PEQT triple setup");
  }

  const auto setup_start = std::chrono::high_resolution_clock::now();
  auto context = CreateBfvContext(params);
  seal::KeyGenerator keygen(*context);
  seal::SecretKey secret_key = keygen.secret_key();
  seal::PublicKey public_key;
  keygen.create_public_key(public_key);
  seal::RelinKeys relin_keys;
  keygen.create_relin_keys(relin_keys);
  seal::BatchEncoder encoder(*context);
  seal::Encryptor encryptor(*context, public_key);
  encryptor.set_secret_key(secret_key);
  const char* seeded_option = std::getenv("PSU_SEEDED_QUERY");
  const bool seeded_query = seeded_option && std::strcmp(seeded_option, "1") == 0;
  seal::Decryptor decryptor(*context, secret_key);
  const size_t slot_count = encoder.slot_count();
  const size_t packed_bin_batch_count = CeilDiv(m, slot_count);

  auto pk_blob = SerializeSealObject(public_key);
  ctx->SendAsync(ctx->NextRank(),
                 upsu::Bytes(pk_blob.data(), pk_blob.size()),
                 kPublicKeyTag);
  auto relin_blob = SerializeSealObject(relin_keys);
  ctx->SendAsync(ctx->NextRank(),
                 upsu::Bytes(relin_blob.data(), relin_blob.size()),
                 kRelinKeysTag);
  if(online_stats) {
    online_stats->fhe_key_comm_bytes=
        ctx->MessageBytes(pk_blob.size(),kPublicKeyTag)+ctx->MessageBytes(relin_blob.size(),kRelinKeysTag);
    online_stats->fhe_key_saved_bytes=
        upsu::serialization::UncompressedSize(reinterpret_cast<const uint8_t*>(pk_blob.data()),pk_blob.size())+
        upsu::serialization::UncompressedSize(reinterpret_cast<const uint8_t*>(relin_blob.data()),relin_blob.size())-
        pk_blob.size()-relin_blob.size();
  }
  (void)ctx->Recv(ctx->PrevRank(), "PSU:offline_ready_v2");
  const auto setup_end = std::chrono::high_resolution_clock::now();
  if (online_stats) {
    online_stats->setup_time_s += SecondsSince(setup_start, setup_end);
  }
  TraceStage("recv", "sent receiver public key");
  upsu::set_experiment_phase(false, "before_online_encoding");
  if (upsu::experiment_phase_threads_enabled() && online_stats) {
    online_stats->setup_time_s = SecondsSince(offline_phase_start, std::chrono::high_resolution_clock::now());
  }

  const auto token_start = std::chrono::high_resolution_clock::now();
  std::vector<uint128_t> full_hashed_items;
  if (params.use_salted_hash) {
    const auto bytes = ctx->Recv(ctx->PrevRank(), encoding::kSaltTag);
    UPSU_ENFORCE(bytes.size() == encoding::Salt{}.size(), "invalid encoding salt size");
    encoding::Salt salt{};
    std::memcpy(salt.data(), bytes.data(), salt.size());
    full_hashed_items = encoding::Encode(salt, receiver_items);
    if (online_stats) online_stats->encoding_comm_bytes += ctx->MessageBytes(salt.size(), encoding::kSaltTag);
    std::cout << "[input_encoding] sender received salt_bits=128 hash=BLAKE3 phase=online" << std::endl;
  } else {
    full_hashed_items =
        EncodeItemsAsProtocolTokens(receiver_items, params.sigma1_bits);
  }
  const auto token_end = std::chrono::high_resolution_clock::now();
  if (online_stats) {
    online_stats->encoding_time_s += SecondsSince(token_start, token_end);
  }
  TraceStage("recv", std::string(params.use_salted_hash
                         ? "computed sender online salted BLAKE3 encodings in "
                         : "decoded S3MT input encodings in ") +
                         std::to_string(SecondsSince(token_start, token_end)) + " s");

  paper::RequireDistinctEncodings(full_hashed_items);
  auto y_items = BuildHashedTableItems(full_hashed_items, receiver_item_bit_count, m,
                                       params.use_permutation_hashing);
  const size_t total_sub_items = ny * effective_kv;
  CuckooTable ct(m, false, 0);
  std::vector<std::array<size_t, 3>> candidates;
  candidates.reserve(y_items.size());
  for (const auto& item : y_items) candidates.push_back(paper::CandidateBins(item.full_item, m));
  ct.item_ids = paper::PlaceCuckoo(candidates, m);
  for (size_t bin = 0; bin < m; ++bin) {
    const size_t id = ct.item_ids[bin];
    if (id == CuckooTable::kInvalidItemId) continue;
    ct.occupied[bin] = true;
    ct.bins[bin] = y_items[id].stored_item;
    ct.full_bins[bin] = y_items[id].full_item;
  }
  TraceStage("recv", "built receiver cuckoo table");

  const bool enable_spy_detection = false;
  ct.FillSpies(enable_spy_detection, receiver_item_bit_count,
               params.sigma1_bits);
  TraceStage("recv", "filled spy bins if needed");

  std::vector<uint64_t> slices_buf(m * ks, 0);
  paper::FieldSampler dummy_sampler;
  for (size_t bin_idx = 0; bin_idx < m; ++bin_idx) {
    for (size_t j = 0; j < ks; ++j) {
      slices_buf[bin_idx * ks + j] = ct.occupied[bin_idx]
          ? ExtractSliceOfItem(ct.bins[bin_idx], j, sigma2_bits)
          : dummy_sampler(prime);
    }
  }
  TraceStage("recv", "prepared receiver slices");

  const size_t query_slice_count = 1;
  const size_t expected_query_ct_count =
      packed_bin_batch_count * query_slice_count * source_power_vec.size();
  auto packed_query = BeginPackedBlobVector(expected_query_ct_count);
  for (size_t batch_idx = 0; batch_idx < packed_bin_batch_count; ++batch_idx) {
    const size_t slot_offset = batch_idx * slot_count;
    const size_t active_slots = std::min(slot_count, m - slot_offset);

    for (size_t s = 0; s < query_slice_count; ++s) {
      if (prime == 65537) {
        std::vector<uint32_t> base_slots(active_slots, 0U);
        for (size_t slot_idx = 0; slot_idx < active_slots; ++slot_idx) {
          const size_t bin_idx = slot_offset + slot_idx;
          base_slots[slot_idx] =
              static_cast<uint32_t>(slices_buf[bin_idx * ks + s] % prime);
        }

        std::vector<uint32_t> power_slots(active_slots, 1U);
        size_t current_power = 0;
        for (uint32_t target_power : source_power_vec) {
          while (current_power < target_power) {
            if (current_power == 0) {
              power_slots = base_slots;
            } else {
              MulMod65537ArrayInPlace(power_slots.data(), base_slots.data(),
                                      active_slots);
            }
            ++current_power;
          }
          auto power_pt = EncodeSlots(encoder, power_slots, prime);
          if (seeded_query) {
            auto power_ct = encryptor.encrypt_symmetric(power_pt);
            AppendSerializedSealObject(&packed_query, power_ct);
          } else {
            auto power_ct = encryptor.encrypt(power_pt);
            AppendSerializedSealObject(&packed_query, power_ct);
          }
        }
      } else {
        std::vector<uint64_t> base_slots(active_slots, 0ULL);
        for (size_t slot_idx = 0; slot_idx < active_slots; ++slot_idx) {
          const size_t bin_idx = slot_offset + slot_idx;
          base_slots[slot_idx] = slices_buf[bin_idx * ks + s] % prime;
        }

        std::vector<uint64_t> power_slots(active_slots, 1ULL);
        size_t current_power = 0;
        for (uint32_t target_power : source_power_vec) {
          while (current_power < target_power) {
            if (current_power == 0) {
              power_slots = base_slots;
            } else {
              for (size_t slot_idx = 0; slot_idx < active_slots; ++slot_idx) {
                power_slots[slot_idx] = MulMod(power_slots[slot_idx],
                                               base_slots[slot_idx], prime);
              }
            }
            ++current_power;
          }
          auto power_pt = EncodeSlots(encoder, power_slots, prime);
          if (seeded_query) {
            auto power_ct = encryptor.encrypt_symmetric(power_pt);
            AppendSerializedSealObject(&packed_query, power_ct);
          } else {
            auto power_ct = encryptor.encrypt(power_pt);
            AppendSerializedSealObject(&packed_query, power_ct);
          }
        }
      }
    }
  }

  ctx->SendAsync(ctx->NextRank(),
                 upsu::Bytes(packed_query.data(),
                                         packed_query.size()),
                 kQueryCiphertextTag);
  TraceStage("recv", "sent " + std::to_string(expected_query_ct_count) +
                         " encrypted query ciphertexts");

  TraceStage("recv", "waiting for encrypted evaluations");
  auto eval_buf = ctx->Recv(ctx->PrevRank(), kEvalCiphertextTag);
  PackedBlobCursor eval_cursor(eval_buf);
  const size_t expected_eval_ct_count =
      packed_bin_batch_count * alpha_eff * output_poly_count;
  UPSU_ENFORCE(eval_cursor.count == expected_eval_ct_count,
               "eval ciphertext count mismatch: got {}, expect {}",
               eval_cursor.count, expected_eval_ct_count);
  TraceStage("recv", "received " + std::to_string(eval_cursor.count) +
                         " encrypted evaluation ciphertexts");

  std::vector<bool> bin_matched(m, false);
  std::vector<uint128_t> receiver_peqt_inputs;
  if (use_circuit_peqt) {
    receiver_peqt_inputs.resize(m * alpha_eff, 0);
  }
  bool deception_detected = false;
  size_t matched_spy_bins = 0;
  size_t eval_blob_idx = 0;
  int min_noise_budget = std::numeric_limits<int>::max();
  int max_noise_budget = std::numeric_limits<int>::min();
  size_t non_positive_noise_budget = 0;
  for (size_t batch_idx = 0; batch_idx < packed_bin_batch_count; ++batch_idx) {
    const size_t slot_offset = batch_idx * slot_count;
    const size_t active_slots = std::min(slot_count, m - slot_offset);
    std::vector<std::vector<std::vector<uint64_t>>> decoded_batch(
        alpha_eff,
        std::vector<std::vector<uint64_t>>(output_poly_count,
                                           std::vector<uint64_t>(active_slots, 0ULL)));

    for (size_t sub_idx = 0; sub_idx < alpha_eff; ++sub_idx) {
      for (size_t output_idx = 0; output_idx < output_poly_count; ++output_idx) {
        UPSU_ENFORCE(eval_blob_idx < expected_eval_ct_count,
                     "eval ciphertext index {} out of range {}",
                     eval_blob_idx, expected_eval_ct_count);
        const auto [blob_data, blob_size] = eval_cursor.Next();
        ++eval_blob_idx;
        seal::Ciphertext eval_ct =
            DeserializeSealObject<seal::Ciphertext>(context, blob_data,
                                                    blob_size);
        const int noise_budget = decryptor.invariant_noise_budget(eval_ct);
        min_noise_budget = std::min(min_noise_budget, noise_budget);
        max_noise_budget = std::max(max_noise_budget, noise_budget);
        if (noise_budget <= 0) {
          ++non_positive_noise_budget;
        }
        seal::Plaintext dec_pt;
        decryptor.decrypt(eval_ct, dec_pt);
        decoded_batch[sub_idx][output_idx] =
            DecodeSlots(dec_pt, encoder, active_slots, prime);
      }
    }

    for (size_t slot_idx = 0; slot_idx < active_slots; ++slot_idx) {
      const size_t bin_idx = slot_offset + slot_idx;
      if (use_circuit_peqt) {
        for (size_t sub_idx = 0; sub_idx < alpha_eff; ++sub_idx) {
          std::vector<uint64_t> packed_elems(output_poly_count, 0ULL);
          for (size_t output_idx = 0; output_idx < output_poly_count;
               ++output_idx) {
            const size_t actual_slice = output_slice_begin + output_idx;
            const uint64_t eval_value =
                decoded_batch[sub_idx][output_idx][slot_idx];
            const uint64_t expected =
                (actual_slice == 0)
                    ? 0ULL
                    : (slices_buf[bin_idx * ks + actual_slice] % prime);
            packed_elems[output_idx] =
                (eval_value >= expected) ? (eval_value - expected)
                                         : (eval_value + prime - expected);
          }
          receiver_peqt_inputs[bin_idx * alpha_eff + sub_idx] =
              PackFieldElements(packed_elems, peqt_field_bits);
        }
        continue;
      }

      bool matched_any_sub_bin = false;

      for (size_t sub_idx = 0; sub_idx < alpha_eff; ++sub_idx) {
        bool candidate = true;
        for (size_t output_idx = 0; output_idx < output_poly_count;
             ++output_idx) {
          const size_t actual_slice = output_slice_begin + output_idx;
          const uint64_t eval_value =
              decoded_batch[sub_idx][output_idx][slot_idx];

          if (actual_slice == 0) {
            if (eval_value != 0) {
              candidate = false;
              break;
            }
          } else {
            const uint64_t expected =
                slices_buf[bin_idx * ks + actual_slice] % prime;
            if (eval_value != expected) {
              candidate = false;
              break;
            }
          }
        }

        if (candidate) {
          matched_any_sub_bin = true;
          break;
        }
      }

      if (ct.is_spy[bin_idx]) {
        if (matched_any_sub_bin) {
          deception_detected = true;
          ++matched_spy_bins;
        }
        continue;
      }
      if (!ct.occupied[bin_idx]) {
        continue;
      }

      bin_matched[bin_idx] = matched_any_sub_bin;
    }
  }
  UPSU_ENFORCE(eval_blob_idx == expected_eval_ct_count,
               "unused eval ciphertexts remain: used {}, total {}",
               eval_blob_idx, expected_eval_ct_count);
  eval_cursor.EnforceFinished();
  if (TraceEnabled() && expected_eval_ct_count > 0) {
    TraceStage("recv",
               "eval noise budget range=[" +
                   std::to_string(min_noise_budget) + ", " +
                   std::to_string(max_noise_budget) +
                   "] bits, non_positive=" +
                   std::to_string(non_positive_noise_budget) + "/" +
                   std::to_string(expected_eval_ct_count));
  }

  if (use_circuit_peqt) {
    std::vector<uint128_t> receiver_peqt_shares = receiver_peqt_inputs;
    if (use_permuted_peqt && !direct_ote) {
      receiver_peqt_shares = ApplyPermutedPeqtReceiver(receiver_peqt_inputs,
                                                       &*perm_state,
                                                       online_stats);
      TraceStage("recv", "applied PEQT permutation share");
    }
    const auto peqt_link_begin = TakeLinkCommSnapshot(ctx);
    const auto peqt_local_begin =
        TakeLocalPeqtCommSnapshot(static_cast<size_t>(ctx->Rank()));
    const auto peqt_start = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> receiver_eq_shares;
    if (direct_ote) {
      UPSU_ENFORCE(peqt_prepared != nullptr,
                   "direct PEQT state must be prepared before online run");
      receiver_eq_shares = peqt::RunPreparedAnyZeroU128Blocks2PC(
          *peqt_prepared, receiver_peqt_shares, alpha_eff,
          "PSU_PEQT_ANYZERO");
    } else {
      UPSU_ENFORCE(peqt_prepared != nullptr,
                   "PEQT state must be prepared before online run");
      receiver_eq_shares = peqt::RunPreparedEqU128Vec2PCPreRot(
          *peqt_prepared, receiver_peqt_shares, "PSU_PEQT");
    }
    std::optional<upsu::net::Context::Buffer> sender_share_buf;
    if (!direct_ote) {
      sender_share_buf = ctx->Recv(ctx->PrevRank(), kPeqtShareTag);
    }
    const auto peqt_end = std::chrono::high_resolution_clock::now();
    const auto peqt_link_end = TakeLinkCommSnapshot(ctx);
    const auto peqt_local_end =
        TakeLocalPeqtCommSnapshot(static_cast<size_t>(ctx->Rank()));
    const auto peqt_link_diff =
        DiffLinkCommSnapshot(peqt_link_begin, peqt_link_end);
    const auto peqt_local_diff =
        DiffLocalPeqtCommSnapshot(peqt_local_begin, peqt_local_end);
    if (online_stats) {
      online_stats->peqt_time_s = SecondsSince(peqt_start, peqt_end);
      online_stats->peqt_link_sent_bytes += peqt_link_diff.sent_bytes;
      online_stats->peqt_link_recv_bytes += peqt_link_diff.recv_bytes;
      online_stats->peqt_local_sent_bytes += peqt_local_diff.sent_bytes;
      online_stats->peqt_local_recv_bytes += peqt_local_diff.recv_bytes;
    }
    if (direct_ote) {
      upsu::diagnostics::Write("receiver_decoded.bin",receiver_peqt_inputs);
      upsu::diagnostics::Write("receiver_eq.bin",receiver_eq_shares);
      upsu::diagnostics::Write("receiver_ids.bin",ct.item_ids);
      auto bin_share = std::move(receiver_eq_shares);
      auto encoded_ote_values = EncodeItemsForFinalOte(receiver_items);
      std::vector<uint128_t> bin_values(m, 0);
      std::vector<uint8_t> bin_valid(m, 0);
      for (size_t bin_idx = 0; bin_idx < m; ++bin_idx) {
        if (!ct.occupied[bin_idx] || ct.is_spy[bin_idx]) {
          continue;
        }
        const size_t item_id = ct.item_ids[bin_idx];
        if (item_id != CuckooTable::kInvalidItemId &&
            item_id < encoded_ote_values.size()) {
          bin_values[bin_idx] = encoded_ote_values[item_id];
          bin_valid[bin_idx] = 1;
        }
      }
      if (use_permuted_peqt) {
        bin_share = ApplyPermutedByteSharesReceiver(bin_share, &*perm_state,
                                                    online_stats);
        bin_values = PermuteValuesByPermutation(bin_values, *perm_state);
        bin_valid = PermuteValuesByPermutation(bin_valid, *perm_state);
        TraceStage("recv", "applied direct OTE permutation share");
      }
      RecvPhaseOutputs outputs;
      upsu::diagnostics::Write("receiver_permuted.bin",bin_share);
      upsu::diagnostics::Write("receiver_values.bin",bin_values);
      outputs.direct_ote_inputs.sender_share = std::move(bin_share);
      outputs.direct_ote_inputs.sender_values = std::move(bin_values);
      outputs.direct_ote_inputs.sender_valid = std::move(bin_valid);
      TraceStage("recv", "finished sender-side direct EQ-OTE input derivation");
      return outputs;
    } else {
      UPSU_ENFORCE(sender_share_buf.has_value(),
                   "sender PEQT share buffer is missing");
      UPSU_ENFORCE(static_cast<size_t>(sender_share_buf->size()) ==
                       receiver_eq_shares.size(),
                   "sender PEQT share size mismatch: got {}, expect {}",
                   sender_share_buf->size(), receiver_eq_shares.size());
      std::vector<bool> original_match(m * alpha_eff, false);
      for (size_t permuted_idx = 0; permuted_idx < m * alpha_eff; ++permuted_idx) {
        const uint8_t sender_share =
            static_cast<const uint8_t*>(sender_share_buf->data())[permuted_idx];
        const uint8_t q =
            static_cast<uint8_t>(receiver_eq_shares[permuted_idx] ^ sender_share);
        const size_t original_idx = use_permuted_peqt
                                        ? static_cast<size_t>(
                                              perm_state->correlation.mPerm
                                                  .mPi[permuted_idx])
                                        : permuted_idx;
        UPSU_ENFORCE(original_idx < original_match.size(),
                     "original PEQT index {} out of range {}",
                     original_idx, original_match.size());
        original_match[original_idx] = (q & 1U) != 0U;
      }
      for (size_t bin_idx = 0; bin_idx < m; ++bin_idx) {
        bool matched_any_sub_bin = false;
        for (size_t sub_idx = 0; sub_idx < alpha_eff; ++sub_idx) {
          const size_t idx = bin_idx * alpha_eff + sub_idx;
          UPSU_ENFORCE(idx < original_match.size(),
                       "receiver PEQT index {} out of range {}",
                       idx, original_match.size());
          if (original_match[idx]) {
            matched_any_sub_bin = true;
            break;
          }
        }

        if (ct.is_spy[bin_idx]) {
          if (matched_any_sub_bin) {
            deception_detected = true;
            ++matched_spy_bins;
          }
          continue;
        }
        if (!ct.occupied[bin_idx]) {
          continue;
        }
        bin_matched[bin_idx] = matched_any_sub_bin;
      }
    }
  }

  if (enable_spy_detection && deception_detected) {
    TraceStage("recv", "spy matches detected in " +
                           std::to_string(matched_spy_bins) + " bins");
  }

  std::vector<bool> sub_item_matched(total_sub_items, false);
  for (size_t bin_idx = 0; bin_idx < m; ++bin_idx) {
    if (!ct.occupied[bin_idx] || ct.is_spy[bin_idx]) {
      continue;
    }
    const size_t item_id = ct.item_ids[bin_idx];
    if (item_id != CuckooTable::kInvalidItemId && item_id < total_sub_items) {
      sub_item_matched[item_id] = bin_matched[bin_idx];
    }
  }

  std::vector<uint8_t> membership_bits(ny, 0);
  for (size_t i = 0; i < ny; ++i) {
    bool all_matched = true;
    for (size_t j = 0; j < effective_kv; ++j) {
      const size_t item_id = i * effective_kv + j;
      if (!sub_item_matched[item_id]) {
        all_matched = false;
        break;
      }
    }
    membership_bits[i] = all_matched ? 1U : 0U;
  }
  TraceStage("recv", "finished sender-side result extraction");
  RecvPhaseOutputs outputs;
  outputs.membership_bits = std::move(membership_bits);
  return outputs;
}

std::vector<uint8_t> RecvMembershipBits(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::vector<std::string>& receiver_items, const ProtocolParams& params,
    OnlineStats* online_stats) {
  return RecvPhaseCore(ctx, receiver_items, params, false, online_stats)
      .membership_bits;
}

BinOteSenderInputs RecvDirectOteSenderInputs(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::vector<std::string>& receiver_items, const ProtocolParams& params,
    OnlineStats* online_stats) {
  return RecvPhaseCore(ctx, receiver_items, params, true, online_stats)
      .direct_ote_inputs;
}

S3mtReceiverOutput RunS3mtReceiver(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::vector<std::string>& receiver_items, const ProtocolParams& params,
    OnlineStats* online_stats) {
  auto direct = RecvDirectOteSenderInputs(ctx, receiver_items, params,
                                          online_stats);
  S3mtReceiverOutput output;
  output.choice_share = std::move(direct.sender_share);
  output.aligned_values = std::move(direct.sender_values);
  output.aligned_valid = std::move(direct.sender_valid);
  return output;
}

std::vector<size_t> RecvMatchedIndices(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::vector<std::string>& receiver_items, const ProtocolParams& params,
    OnlineStats* online_stats) {
  const auto membership_bits =
      RecvMembershipBits(ctx, receiver_items, params, online_stats);
  std::vector<size_t> matched_indices;
  matched_indices.reserve(membership_bits.size());
  for (size_t i = 0; i < membership_bits.size(); ++i) {
    if ((membership_bits[i] & 1U) != 0U) {
      matched_indices.push_back(i);
    }
  }
  return matched_indices;
}

size_t RecvCount(const std::shared_ptr<upsu::net::Context>& ctx,
                  const std::vector<std::string>& receiver_items,
                  const ProtocolParams& params,
                  OnlineStats* online_stats) {
  return RecvMatchedIndices(ctx, receiver_items, params, online_stats)
      .size();
}

std::vector<std::string> RecvItems(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::vector<std::string>& receiver_items, const ProtocolParams& params,
    OnlineStats* online_stats) {
  const auto matched_indices =
      RecvMatchedIndices(ctx, receiver_items, params, online_stats);
  std::vector<std::string> matched_items;
  matched_items.reserve(matched_indices.size());
  for (size_t idx : matched_indices) {
    UPSU_ENFORCE(idx < receiver_items.size(),
                 "matched receiver index {} out of range {}", idx,
                 receiver_items.size());
    matched_items.push_back(receiver_items[idx]);
  }
  return matched_items;
}

PrimitiveBenchMetrics RunLocalPackedZeroTestBench(size_t n, size_t bit_width) {
  if (upsu::experiment_phase_threads_enabled()) upsu::set_num_threads(8);
  UPSU_ENFORCE(n > 0, "packed zero-test bench requires n > 0");
  UPSU_ENFORCE(bit_width > 0 && bit_width <= 128,
               "packed zero-test bit_width must be in [1, 128], got={}",
               bit_width);

  PrimitiveBenchMetrics metrics;
  metrics.input_size = n;
  metrics.bit_width = bit_width;
  metrics.row_bytes = std::max<size_t>(1, (bit_width + 7) / 8);

  auto lctxs = upsu::net::Context::SetupWorld(2);
  lctxs[0]->SetRecvTimeout(600000);
  lctxs[1]->SetRecvTimeout(600000);

  std::mt19937_64 prng(0x5A17D3C4B29E4F11ULL);
  std::vector<uint128_t> sender_rows(n, 0);
  std::vector<uint128_t> receiver_rows(n, 0);
  std::vector<uint8_t> expected(n, 0);
  for (size_t i = 0; i < n; ++i) {
    const uint128_t base =
        MaskBits((uint128_t(prng()) << 64) | uint128_t(prng()), bit_width);
    const bool equal = ((i & 1U) == 0U);
    sender_rows[i] = base;
    receiver_rows[i] = equal ? base : MaskBits(base ^ uint128_t{1}, bit_width);
    expected[i] = equal ? 1U : 0U;
  }

  struct PackedZeroPartyRun {
    peqt::PreparedCircuitGmwState prepared;
    std::vector<uint8_t> shares;
    double setup_time_s = 0;
    double online_time_s = 0;
    size_t setup_comm_bytes = 0;
    size_t online_comm_bytes = 0;
  };

  auto setup_party = [&](int rank) -> PackedZeroPartyRun {
    upsu::pin_benchmark_thread(rank, true);
    PackedZeroPartyRun run;
    const auto link_begin = TakeLinkCommSnapshot(lctxs[rank]);
    const auto start = std::chrono::high_resolution_clock::now();
    run.prepared = peqt::PrepareEqU128Vec2PCPreRot(
        lctxs[rank], rank, n, bit_width, "PSU_PRIMITIVE_PACKED_ZERO");
    const auto end = std::chrono::high_resolution_clock::now();
    const auto link_end = TakeLinkCommSnapshot(lctxs[rank]);
    const auto link_diff = DiffLinkCommSnapshot(link_begin, link_end);
    run.setup_time_s = SecondsSince(start, end);
    run.setup_comm_bytes =
        run.prepared.setup_sent_bytes + run.prepared.setup_recv_bytes +
        link_diff.sent_bytes + link_diff.recv_bytes;
    return run;
  };

  auto sender_setup_fut =
      std::async(std::launch::async, [&] { return setup_party(0); });
  auto receiver_setup_fut =
      std::async(std::launch::async, [&] { return setup_party(1); });
  auto sender_run = sender_setup_fut.get();
  auto receiver_run = receiver_setup_fut.get();

  if (upsu::experiment_phase_threads_enabled()) upsu::set_num_threads(1);

  peqt::ResetLocalCommStats();

  auto run_party = [&](int rank, PackedZeroPartyRun* run,
                       const std::vector<uint128_t>& input) {
    upsu::pin_benchmark_thread(rank);
    const auto link_begin = TakeLinkCommSnapshot(lctxs[rank]);
    const auto start = std::chrono::high_resolution_clock::now();
    run->shares = peqt::RunPreparedEqU128Vec2PCPreRot(
        run->prepared, input, "PSU_PRIMITIVE_PACKED_ZERO");
    const auto end = std::chrono::high_resolution_clock::now();
    const auto link_end = TakeLinkCommSnapshot(lctxs[rank]);
    const auto link_diff = DiffLinkCommSnapshot(link_begin, link_end);
    run->online_time_s = SecondsSince(start, end);
    run->online_comm_bytes = link_diff.sent_bytes + link_diff.recv_bytes;
  };

  auto sender_online_fut = std::async(std::launch::async, [&] {
    run_party(0, &sender_run, sender_rows);
  });
  auto receiver_online_fut = std::async(std::launch::async, [&] {
    run_party(1, &receiver_run, receiver_rows);
  });
  sender_online_fut.get();
  receiver_online_fut.get();

  const auto local_stats = peqt::GetLocalCommStats();
  sender_run.online_comm_bytes += local_stats.sent[0] + local_stats.recv[0];
  receiver_run.online_comm_bytes += local_stats.sent[1] + local_stats.recv[1];

  UPSU_ENFORCE(sender_run.shares.size() == n,
               "packed zero-test sender output size mismatch: got {}, expect {}",
               sender_run.shares.size(), n);
  UPSU_ENFORCE(
      receiver_run.shares.size() == n,
      "packed zero-test receiver output size mismatch: got {}, expect {}",
      receiver_run.shares.size(), n);

  std::vector<uint8_t> combined(n, 0);
  for (size_t i = 0; i < n; ++i) {
    combined[i] =
        static_cast<uint8_t>((sender_run.shares[i] ^ receiver_run.shares[i]) &
                             1U);
  }

  metrics.result_true_count = static_cast<size_t>(std::count(
      combined.begin(), combined.end(), static_cast<uint8_t>(1)));
  metrics.expected_true_count = static_cast<size_t>(std::count(
      expected.begin(), expected.end(), static_cast<uint8_t>(1)));
  metrics.setup_time_s =
      std::max(sender_run.setup_time_s, receiver_run.setup_time_s);
  metrics.online_time_s =
      std::max(sender_run.online_time_s, receiver_run.online_time_s);
  metrics.setup_comm_bytes =
      std::max(sender_run.setup_comm_bytes, receiver_run.setup_comm_bytes);
  metrics.online_comm_bytes =
      std::max(sender_run.online_comm_bytes, receiver_run.online_comm_bytes);
  metrics.total_comm_bytes =
      metrics.setup_comm_bytes + metrics.online_comm_bytes;
  metrics.correct = (combined == expected);
  return metrics;
}

PrimitiveBenchMetrics RunLocalRandomPermutationBench(size_t n,
                                                     size_t block_size) {
  if (upsu::experiment_phase_threads_enabled()) upsu::set_num_threads(8);
  UPSU_ENFORCE(n > 0, "permutation bench requires n > 0");
  UPSU_ENFORCE(block_size > 0, "permutation bench block_size must be > 0");
  UPSU_ENFORCE(n % block_size == 0,
               "permutation bench requires n={} divisible by block_size={}", n,
               block_size);

  PrimitiveBenchMetrics metrics;
  metrics.input_size = n;
  metrics.bit_width = 8;
  metrics.block_size = block_size;
  metrics.row_bytes = 1;

  std::mt19937_64 prng(0x91B8D7F24A6C3E15ULL);
  std::vector<uint8_t> original_bits(n, 0);
  std::vector<uint8_t> sender_share(n, 0);
  std::vector<uint8_t> receiver_share(n, 0);
  for (size_t i = 0; i < n; ++i) {
    const uint8_t bit = static_cast<uint8_t>(prng() & 1U);
    const uint8_t mask = static_cast<uint8_t>((prng() >> 1) & 1U);
    original_bits[i] = bit;
    sender_share[i] = mask;
    receiver_share[i] = static_cast<uint8_t>(bit ^ mask);
  }

  OnlineStats sender_stats;
  OnlineStats receiver_stats;

  auto sender_setup_fut = std::async(std::launch::async, [&] {
    upsu::pin_benchmark_thread(0, true);
    return SetupPermutedPeqtSender(n, 1, &sender_stats);
  });
  auto receiver_setup_fut = std::async(std::launch::async, [&] {
    upsu::pin_benchmark_thread(1, true);
    return SetupPermutedPeqtReceiver(n, 1, block_size, &receiver_stats);
  });
  auto sender_state = sender_setup_fut.get();
  auto receiver_state = receiver_setup_fut.get();

  if (upsu::experiment_phase_threads_enabled()) upsu::set_num_threads(1);

  std::vector<uint8_t> sender_out;
  std::vector<uint8_t> receiver_out;
  auto sender_apply_fut = std::async(std::launch::async, [&] {
    upsu::pin_benchmark_thread(0);
    sender_out =
        ApplyPermutedByteSharesSender(sender_share, &sender_state, &sender_stats);
  });
  auto receiver_apply_fut = std::async(std::launch::async, [&] {
    upsu::pin_benchmark_thread(1);
    receiver_out = ApplyPermutedByteSharesReceiver(receiver_share,
                                                   &receiver_state,
                                                   &receiver_stats);
  });
  sender_apply_fut.get();
  receiver_apply_fut.get();

  UPSU_ENFORCE(sender_out.size() == n,
               "permutation sender output size mismatch: got {}, expect {}",
               sender_out.size(), n);
  UPSU_ENFORCE(receiver_out.size() == n,
               "permutation receiver output size mismatch: got {}, expect {}",
               receiver_out.size(), n);

  const auto& pi = receiver_state.correlation.mPerm.mPi;
  UPSU_ENFORCE(pi.size() == n,
               "permutation size mismatch: got {}, expect {}", pi.size(), n);

  std::vector<uint8_t> expected(n, 0);
  std::vector<uint8_t> combined(n, 0);
  for (size_t perm_idx = 0; perm_idx < n; ++perm_idx) {
    const size_t orig_idx = static_cast<size_t>(pi[perm_idx]);
    UPSU_ENFORCE(orig_idx < n, "permutation index {} out of range {}",
                 orig_idx, n);
    expected[perm_idx] = original_bits[orig_idx];
    combined[perm_idx] =
        static_cast<uint8_t>((sender_out[perm_idx] ^ receiver_out[perm_idx]) &
                             1U);
  }

  metrics.result_true_count = static_cast<size_t>(std::count(
      combined.begin(), combined.end(), static_cast<uint8_t>(1)));
  metrics.expected_true_count = static_cast<size_t>(std::count(
      expected.begin(), expected.end(), static_cast<uint8_t>(1)));
  metrics.setup_time_s =
      std::max(sender_stats.perm_setup_time_s, receiver_stats.perm_setup_time_s);
  metrics.online_time_s =
      std::max(sender_stats.perm_apply_time_s, receiver_stats.perm_apply_time_s);
  metrics.setup_comm_bytes =
      std::max(sender_stats.perm_setup_bytes, receiver_stats.perm_setup_bytes);
  metrics.online_comm_bytes =
      std::max(sender_stats.perm_apply_bytes, receiver_stats.perm_apply_bytes);
  metrics.total_comm_bytes =
      metrics.setup_comm_bytes + metrics.online_comm_bytes;
  metrics.correct = (combined == expected);
  return metrics;
}

}

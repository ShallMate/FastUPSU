
#pragma once

#include "upsu/common.h"
#include "upsu/net/context.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>


namespace psu {

struct PreparedSender;

struct ProtocolParams {
  size_t kappa = 128;
  size_t lambda = 40;

  size_t poly_modulus_degree = 8192;
  std::vector<int> coeff_modulus_bits = {56, 56, 56, 50};
  uint64_t plain_modulus = 65537;

  size_t sigma1_bits = 128;
  bool use_permutation_hashing = false;
  bool use_salted_hash = true;

  size_t ks = 4;
  size_t sigma2_bits = 10;

  size_t hash_func_count = 3;
  double cuckoo_scale = 1.27;

  size_t simple_hash_bins = 512;
  size_t alpha = 1;
  size_t max_items_per_bin = 2048;
  size_t public_sub_bin_size = 0;

  size_t query_powers_max_depth = 2;
  size_t ps_low_degree = 0;
  std::vector<uint32_t> query_powers;
  size_t response_mod_switch_steps = 1;
  size_t response_flood_bits = 80;
  bool use_circuit_peqt = true;
  bool drop_first_poly = false;
  bool reveal_match_items = true;

  size_t PermutationIndexBits() const {
    if (!use_permutation_hashing) {
      return 0;
    }
    size_t bits = 0;
    size_t value = simple_hash_bins;
    while (value > 1) {
      value >>= 1;
      ++bits;
    }
    return bits;
  }

  size_t EffectiveItemBitCount() const {
    size_t slice_bits = 0;
    for (uint64_t v = plain_modulus; v > 1; v >>= 1) ++slice_bits;
    UPSU_ENFORCE(ks * slice_bits <= 128, "payload slices exceed full encoding width");
    return ks * slice_bits;
  }

  void Finalize() {
    sigma2_bits = (EffectiveItemBitCount() + ks - 1) / ks;
    UPSU_ENFORCE(ks * sigma2_bits <= 128,
                 "slicing exceeds 128-bit item width: ks={} sigma2_bits={}",
                 ks, sigma2_bits);
  }
};

struct ProtocolResult {
  size_t cardinality = 0;
  double comm_bytes = 0;
  double online_time_s = 0;
  double receiver_offline_time_s = 0;
};

struct OnlineStats {
  double setup_time_s = 0;
  double encoding_time_s = 0;
  size_t encoding_comm_bytes = 0;
  size_t fhe_key_comm_bytes = 0;
  size_t fhe_key_saved_bytes = 0;
  double perm_setup_time_s = 0;
  double peqt_setup_time_s = 0;
  double perm_apply_time_s = 0;
  double peqt_time_s = 0;
  size_t perm_setup_bytes = 0;
  size_t perm_apply_bytes = 0;
  size_t peqt_setup_local_sent_bytes = 0;
  size_t peqt_setup_local_recv_bytes = 0;
  size_t peqt_local_sent_bytes = 0;
  size_t peqt_local_recv_bytes = 0;
  size_t peqt_link_sent_bytes = 0;
  size_t peqt_link_recv_bytes = 0;
};

struct PrimitiveBenchMetrics {
  size_t input_size = 0;
  size_t bit_width = 0;
  size_t block_size = 1;
  size_t row_bytes = 0;
  size_t result_true_count = 0;
  size_t expected_true_count = 0;
  double setup_time_s = 0;
  double online_time_s = 0;
  size_t setup_comm_bytes = 0;
  size_t online_comm_bytes = 0;
  size_t total_comm_bytes = 0;
  bool correct = false;
};

struct AlphaSampleMetrics {
  size_t sender_size = 0;
  size_t receiver_size = 0;
  size_t simple_hash_bins = 0;
  size_t simple_hash_count = 3;
  size_t sigma1_bits = 0;
  size_t item_bit_count = 0;
  size_t ks = 0;
  size_t sigma2_bits = 0;
  uint64_t plain_modulus = 0;
  size_t alpha_min = 1;
  size_t max_items_per_bin = 0;
  size_t required_alpha = 1;
  size_t alpha = 1;
  size_t max_bin_size = 0;
  size_t sub_bin_size = 1;
};

struct BinOteSenderInputs {
  std::vector<uint8_t> sender_share;
  std::vector<uint128_t> sender_values;
  std::vector<uint8_t> sender_valid;
};

struct S3mtReceiverOutput {
  std::vector<uint8_t> choice_share;
  std::vector<uint128_t> aligned_values;
  std::vector<uint8_t> aligned_valid;
};


void ProtocolSend(const std::shared_ptr<upsu::net::Context>& ctx,
                  const std::vector<std::string>& sender_items,
                  const ProtocolParams& params,
                  OnlineStats* online_stats = nullptr);

std::shared_ptr<PreparedSender> PrepareSender(
    const std::vector<std::string>& sender_items, const ProtocolParams& params);

void MaterializeSenderOnlineCache(
    const std::shared_ptr<PreparedSender>& prepared,
    const ProtocolParams& params);

std::vector<uint8_t> SendPreparedDirectOteChoices(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::shared_ptr<PreparedSender>& prepared,
    const ProtocolParams& params,
    OnlineStats* online_stats = nullptr);

std::vector<uint8_t> RunS3mtSender(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::shared_ptr<PreparedSender>& prepared,
    const ProtocolParams& params,
    OnlineStats* online_stats = nullptr);

void SendPrepared(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::shared_ptr<PreparedSender>& prepared,
    const ProtocolParams& params,
    OnlineStats* online_stats = nullptr);

size_t RecvCount(const std::shared_ptr<upsu::net::Context>& ctx,
                 const std::vector<std::string>& receiver_items,
                 const ProtocolParams& params,
                 OnlineStats* online_stats = nullptr);

std::vector<uint8_t> RecvMembershipBits(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::vector<std::string>& receiver_items, const ProtocolParams& params,
    OnlineStats* online_stats = nullptr);

BinOteSenderInputs RecvDirectOteSenderInputs(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::vector<std::string>& receiver_items, const ProtocolParams& params,
    OnlineStats* online_stats = nullptr);

S3mtReceiverOutput RunS3mtReceiver(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::vector<std::string>& receiver_items,
    const ProtocolParams& params,
    OnlineStats* online_stats = nullptr);

std::vector<uint128_t> EncodeItemsForFinalOte(
    const std::vector<std::string>& items);

std::vector<std::string> RecvItems(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::vector<std::string>& receiver_items, const ProtocolParams& params,
    OnlineStats* online_stats = nullptr);

size_t ComputePolyLinkHashBits(size_t sender_set_size, size_t receiver_set_size,
                          size_t lambda);

uint64_t ChoosePlainModulus(size_t poly_modulus_degree, size_t sigma2_bits);

size_t EstimateFheKeyCommBytes(const ProtocolParams& params);

AlphaSampleMetrics SampleAlphaAfterEncoding(
    const std::vector<std::string>& sender_items, size_t receiver_set_size,
    const ProtocolParams& params);

PrimitiveBenchMetrics RunLocalPackedZeroTestBench(size_t n, size_t bit_width);

PrimitiveBenchMetrics RunLocalRandomPermutationBench(size_t n,
                                                     size_t block_size = 1);

}

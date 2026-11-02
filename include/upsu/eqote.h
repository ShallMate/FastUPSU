#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <openssl/sha.h>

#include "coproto/Socket/AsioSocket.h"
#include "coproto/coproto.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
#include "upsu/common.h"
#include "upsu/net/context.h"

namespace psu::ote {

enum class Backend { kIknp = 0, kSoftspoken = 1, kSilent = 2 };

struct SenderResult {
  size_t bytes = 0;
  double time_s = 0;
  Backend backend = Backend::kIknp;
};

struct ReceiverResult {
  std::vector<uint128_t> values;
  std::vector<uint8_t> present;
  size_t bytes = 0;
  double time_s = 0;
  Backend backend = Backend::kIknp;
};

namespace {

inline const char* BackendName(Backend backend) {
  switch (backend) {
    case Backend::kIknp: return "iknp";
    case Backend::kSoftspoken: return "softspoken";
    case Backend::kSilent: return "silent";
  }
  return "unknown";
}

inline size_t ParsePositiveEnv(const char* name, size_t fallback) {
  const char* value = std::getenv(name);
  if (!value || !*value) return fallback;
  char* end = nullptr;
  const auto parsed = std::strtoull(value, &end, 10);
  return end != value && *end == '\0' && parsed != 0
             ? static_cast<size_t>(parsed)
             : fallback;
}

inline size_t ValueBits() {
  const size_t bits = ParsePositiveEnv("PSU_OTE_VALUE_BITS", 128);
  UPSU_ENFORCE(bits > 0 && bits <= 128 && bits % 8 == 0,
               "PSU_OTE_VALUE_BITS must be a positive multiple of 8 and <= 128");
  return bits;
}

inline uint128_t ValueMask() {
  return ValueBits() == 128 ? ~uint128_t{0} : (uint128_t{1} << ValueBits()) - 1;
}

inline uint128_t Normalize(uint128_t value) { return value & ValueMask(); }

inline size_t BatchItems(Backend backend) {
  return backend == Backend::kSilent
             ? ParsePositiveEnv("PSU_SILENT_OTE_BATCH_ITEMS", size_t{1} << 15)
             : ParsePositiveEnv("PSU_OTE_BATCH_ITEMS", size_t{1} << 16);
}

inline size_t ThreadCount() { return ParsePositiveEnv("PSU_OTE_THREADS", 1); }

inline std::string ToLower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

inline Backend ResolveBackend(size_t count) {
  if (const char* env = std::getenv("PSU_OTE_BACKEND")) {
    const std::string value = ToLower(env);
    if (value == "iknp") return Backend::kIknp;
    if (value == "softspoken") return Backend::kSoftspoken;
    if (value == "silent") return Backend::kSilent;
    UPSU_ENFORCE(value == "auto", "invalid PSU_OTE_BACKEND: {}", value);
  }
  if (count <= ParsePositiveEnv("PSU_OTE_AUTO_IKNP_MAX", 4096))
    return Backend::kIknp;
  if (count <= ParsePositiveEnv("PSU_OTE_AUTO_SOFTSPOKEN_MAX", 262144))
    return Backend::kSoftspoken;
  return Backend::kSilent;
}

struct Endpoint {
  std::string host;
  uint16_t port;
};

inline Endpoint ParseAddress(const std::string& address) {
  const auto split = address.rfind(':');
  UPSU_ENFORCE(split != std::string::npos, "OTE address must be host:port");
  int port = 0;
  try {
    port = std::stoi(address.substr(split + 1));
  } catch (...) {
    UPSU_THROW("invalid OTE address: {}", address);
  }
  UPSU_ENFORCE(port > 0 && port <= 65535, "invalid OTE port: {}", port);
  return {address.substr(0, split), static_cast<uint16_t>(port)};
}

inline std::string BatchAddress(size_t batch_index) {
  const std::string base = std::getenv("PSU_OTE_ADDRESS")
                               ? std::getenv("PSU_OTE_ADDRESS")
                               : "127.0.0.1:15050";
  const auto endpoint = ParseAddress(base);
  const uint32_t port = static_cast<uint32_t>(endpoint.port) + batch_index;
  UPSU_ENFORCE(port <= 65535, "OTE batch port overflow");
  return fmt::format("{}:{}", endpoint.host, port);
}

inline coproto::AsioSocket ConnectSocket(const std::string& address,
                                         bool listener) {
  if (listener) return coproto::asioConnect(address, true);
  for (int attempt = 0; attempt < 200; ++attempt) {
    try {
      return coproto::asioConnect(address, false);
    } catch (...) {
      if (attempt == 199) throw;
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }
  UPSU_THROW("failed to connect OTE socket: {}", address);
}

inline osuCrypto::block ToBlock(uint128_t value) {
  osuCrypto::block block = osuCrypto::ZeroBlock;
  value = Normalize(value);
  std::memcpy(&block, &value, sizeof(value));
  return block;
}

inline uint128_t FromBlock(const osuCrypto::block& block) {
  uint128_t value = 0;
  std::memcpy(&value, &block, sizeof(value));
  return Normalize(value);
}

inline osuCrypto::PRNG MakePrng() {
  return osuCrypto::PRNG(
      osuCrypto::toBlock(upsu::SecureRandU64(), upsu::SecureRandU64()));
}

inline osuCrypto::BitVector ToChoices(const std::vector<uint8_t>& shares,
                                      size_t offset, size_t count) {
  osuCrypto::BitVector choices(count);
  for (size_t i = 0; i < count; ++i) choices[i] = shares[offset + i] & 1U;
  return choices;
}

template <typename Sender>
void SendBatch(Sender& sender, osuCrypto::span<std::array<osuCrypto::block, 2>> messages,
               osuCrypto::PRNG& prng, coproto::Socket& socket) {
  coproto::sync_wait(sender.send(messages, prng, socket));
}

template <typename Receiver>
void ReceiveBatch(Receiver& receiver, const osuCrypto::BitVector& choices,
                  osuCrypto::span<osuCrypto::block> messages,
                  osuCrypto::PRNG& prng, coproto::Socket& socket) {
  coproto::sync_wait(receiver.receive(choices, messages, prng, socket));
}

// Expand each random OT key to a tagged 128-bit payload, keeping bottom outside
// the raw-item domain. This adds one validity byte to each chosen-message branch.
inline std::array<uint8_t, 32> PayloadPad(const osuCrypto::block& key) {
  std::array<uint8_t, 32> input{}, output{};
  std::memcpy(input.data(), "UPSU-EQOTE-v2", 13);
  std::memcpy(input.data() + 16, &key, 16);
  SHA256(input.data(), input.size(), output.data());
  return output;
}
using TaggedMessages = std::array<uint8_t, 34>;

inline SenderResult RunSender(Backend backend,
                              const std::vector<uint128_t>& values,
                              const std::vector<uint8_t>& shares,
                              const std::vector<uint8_t>& valid) {
  SenderResult result{.backend = backend};
  const auto begin = std::chrono::steady_clock::now();
  const size_t batch_items = BatchItems(backend);
  for (size_t offset = 0, batch = 0; offset < values.size();
       offset += batch_items, ++batch) {
    const size_t count = std::min(batch_items, values.size() - offset);
    auto socket = ConnectSocket(BatchAddress(batch), true);
    osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> messages(count);
    auto prng = MakePrng();
    if (backend == Backend::kIknp) {
      osuCrypto::IknpOtExtSender sender;
      SendBatch(sender, messages, prng, socket);
    } else if (backend == Backend::kSoftspoken) {
      osuCrypto::SoftSpokenShOtSender<> sender;
      sender.init(2, true, ThreadCount());
      SendBatch(sender, messages, prng, socket);
    } else {
      osuCrypto::SilentOtExtSender sender;
      sender.configure(count, 2, ThreadCount(), osuCrypto::SilentSecType::SemiHonest);
      SendBatch(sender, messages, prng, socket);
    }
    std::vector<TaggedMessages> ciphertexts(count);
    for (size_t i = 0; i < count; ++i) {
      for (size_t choice = 0; choice < 2; ++choice) {
        const auto pad = PayloadPad(messages[i][choice]);
        const bool selected = choice == (shares[offset + i] & 1U);
        const uint128_t value = selected ? Normalize(values[offset + i]) : 0;
        const uint8_t exists = selected && (valid.empty() || valid[offset + i]);
        for (size_t j = 0; j < 16; ++j)
          ciphertexts[i][17 * choice + j] = pad[j] ^ static_cast<uint8_t>(value >> (8 * j));
        ciphertexts[i][17 * choice + 16] = pad[16] ^ exists;
      }
    }
    coproto::sync_wait(socket.send(std::move(ciphertexts)));
    coproto::sync_wait(socket.flush());
    result.bytes += static_cast<size_t>(socket.bytesSent() + socket.bytesReceived());
  }
  result.time_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - begin).count();
  return result;
}

inline ReceiverResult RunReceiver(Backend backend,
                                  const std::vector<uint8_t>& shares) {
  ReceiverResult result{.values = std::vector<uint128_t>(shares.size()),
                        .present = std::vector<uint8_t>(shares.size()),
                        .backend = backend};
  const auto begin = std::chrono::steady_clock::now();
  const size_t batch_items = BatchItems(backend);
  for (size_t offset = 0, batch = 0; offset < shares.size();
       offset += batch_items, ++batch) {
    const size_t count = std::min(batch_items, shares.size() - offset);
    auto socket = ConnectSocket(BatchAddress(batch), false);
    const auto choices = ToChoices(shares, offset, count);
    osuCrypto::AlignedUnVector<osuCrypto::block> messages(count);
    auto prng = MakePrng();
    if (backend == Backend::kIknp) {
      osuCrypto::IknpOtExtReceiver receiver;
      ReceiveBatch(receiver, choices, messages, prng, socket);
    } else if (backend == Backend::kSoftspoken) {
      osuCrypto::SoftSpokenShOtReceiver<> receiver;
      receiver.init(2, true, ThreadCount());
      ReceiveBatch(receiver, choices, messages, prng, socket);
    } else {
      osuCrypto::SilentOtExtReceiver receiver;
      receiver.configure(count, 2, ThreadCount(), osuCrypto::SilentSecType::SemiHonest);
      ReceiveBatch(receiver, choices, messages, prng, socket);
    }
    std::vector<TaggedMessages> ciphertexts(count);
    coproto::sync_wait(socket.recv(ciphertexts));
    for (size_t i = 0; i < count; ++i) {
      const auto pad = PayloadPad(messages[i]);
      const size_t choice = choices[i];
      uint128_t value = 0;
      for (size_t j = 0; j < 16; ++j)
        value |= uint128_t{static_cast<uint8_t>(ciphertexts[i][17 * choice + j] ^ pad[j])} << (8 * j);
      const uint8_t present = ciphertexts[i][17 * choice + 16] ^ pad[16];
      UPSU_ENFORCE(present <= 1, "invalid EQOTE validity tag");
      result.values[offset + i] = value;
      result.present[offset + i] = present;
    }
    coproto::sync_wait(socket.flush());
    result.bytes += static_cast<size_t>(socket.bytesSent() + socket.bytesReceived());
  }
  result.time_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - begin).count();
  return result;
}

}  // namespace

inline const char* OteBackendName(Backend backend) { return BackendName(backend); }
inline size_t EqOtePayloadBits() { return ValueBits(); }
inline uint128_t NormalizeEqOteValue(uint128_t value) { return Normalize(value); }

inline SenderResult RunEqValueSenderRole(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::vector<uint128_t>& values,
    const std::vector<uint8_t>& sender_share,
    const std::vector<uint8_t>& valid = {}) {
  UPSU_ENFORCE(ctx && values.size() == sender_share.size() && (valid.empty() || valid.size() == values.size()),
               "invalid EQ-OTE sender inputs");
  return RunSender(ResolveBackend(values.size()), values, sender_share, valid);
}

inline ReceiverResult RunEqValueReceiverRole(
    const std::shared_ptr<upsu::net::Context>& ctx,
    const std::vector<uint8_t>& receiver_share) {
  UPSU_ENFORCE(ctx, "EQ-OTE receiver context is null");
  return RunReceiver(ResolveBackend(receiver_share.size()), receiver_share);
}

}  // namespace psu::ote

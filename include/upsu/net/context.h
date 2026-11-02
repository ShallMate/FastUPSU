#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "upsu/common.h"

namespace upsu::net {

struct LinkStats {
  std::atomic<uint64_t> sent_bytes{0};
  std::atomic<uint64_t> recv_bytes{0};
};

class Context {
 public:
  using Buffer = std::vector<uint8_t>;

  static std::shared_ptr<Context> Connect(const std::vector<std::string>& parties,
                                          size_t rank,
                                          uint64_t timeout_ms);
  static std::vector<std::shared_ptr<Context>> SetupWorld(size_t party_count);

  ~Context() = default;
  Context(const Context&) = delete;
  Context& operator=(const Context&) = delete;

  size_t Rank() const { return rank_; }
  size_t NextRank() const { return (rank_ + 1) % 2; }
  size_t PrevRank() const { return (rank_ + 1) % 2; }
  void ConnectToMesh() {}
  void SetRecvTimeout(uint64_t timeout_ms);
  void SetThrottleWindowSize(size_t) {}
  void SetChunkParallelSendSize(uint32_t) {}

  void Send(size_t destination, ByteView data, const std::string& tag);
  void SendAsync(size_t destination, ByteView data, const std::string& tag) {
    Send(destination, data, tag);
  }
  Buffer Recv(size_t source, const std::string& tag);
  std::unique_ptr<Context> Spawn(const std::string& suffix) const;
  std::shared_ptr<LinkStats> GetStats() const;
  size_t MessageBytes(size_t payload_size, const std::string& tag) const;

 private:
  struct Transport;
  Context(std::shared_ptr<Transport> transport, size_t rank,
          std::string channel, uint64_t timeout_ms);

  std::shared_ptr<Transport> transport_;
  size_t rank_;
  std::string channel_;
  std::atomic<uint64_t> timeout_ms_;
};

}  // namespace upsu::net

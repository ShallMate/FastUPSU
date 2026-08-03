#include "upsu/net/context.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <thread>

namespace upsu::net {
namespace {

constexpr uint32_t kFrameMagic = 0x55505355;
constexpr uint64_t kMaxMessageSize = uint64_t{8} << 30;

struct Endpoint {
  std::string host;
  std::string port;
};

Endpoint ParseEndpoint(const std::string& value) {
  const size_t split = value.rfind(':');
  UPSU_ENFORCE(split != std::string::npos && split != 0 && split + 1 < value.size(),
               "invalid endpoint '{}'; expected host:port", value);
  return {value.substr(0, split), value.substr(split + 1)};
}

void WriteAll(int fd, const void* data, size_t size) {
  const auto* cursor = static_cast<const uint8_t*>(data);
  while (size != 0) {
    const ssize_t written = ::send(fd, cursor, size, MSG_NOSIGNAL);
    if (written < 0 && errno == EINTR) continue;
    UPSU_ENFORCE(written > 0, "socket send failed: {}", std::strerror(errno));
    cursor += written;
    size -= static_cast<size_t>(written);
  }
}

bool ReadAll(int fd, void* data, size_t size) {
  auto* cursor = static_cast<uint8_t*>(data);
  while (size != 0) {
    const ssize_t received = ::recv(fd, cursor, size, 0);
    if (received < 0 && errno == EINTR) continue;
    if (received == 0) return false;
    UPSU_ENFORCE(received > 0, "socket receive failed: {}", std::strerror(errno));
    cursor += received;
    size -= static_cast<size_t>(received);
  }
  return true;
}

int MakeListener(const Endpoint& endpoint) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* results = nullptr;
  const char* host = endpoint.host == "0.0.0.0" || endpoint.host == "*"
                         ? nullptr
                         : endpoint.host.c_str();
  UPSU_ENFORCE(getaddrinfo(host, endpoint.port.c_str(), &hints, &results) == 0,
               "cannot resolve listen endpoint {}:{}", endpoint.host, endpoint.port);
  int fd = -1;
  for (addrinfo* it = results; it != nullptr; it = it->ai_next) {
    fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd < 0) continue;
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (::bind(fd, it->ai_addr, it->ai_addrlen) == 0 && ::listen(fd, 1) == 0) break;
    ::close(fd);
    fd = -1;
  }
  freeaddrinfo(results);
  UPSU_ENFORCE(fd >= 0, "failed to listen on {}:{}: {}", endpoint.host,
               endpoint.port, std::strerror(errno));
  return fd;
}

int ConnectWithRetry(const Endpoint& endpoint, uint64_t timeout_ms) {
  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(timeout_ms);
  std::string last_error;
  while (std::chrono::steady_clock::now() < deadline) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* results = nullptr;
    if (getaddrinfo(endpoint.host.c_str(), endpoint.port.c_str(), &hints,
                    &results) != 0) {
      last_error = "name resolution failed";
    } else {
      for (addrinfo* it = results; it != nullptr; it = it->ai_next) {
        int fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, it->ai_addr, it->ai_addrlen) == 0) {
          freeaddrinfo(results);
          return fd;
        }
        last_error = std::strerror(errno);
        ::close(fd);
      }
      freeaddrinfo(results);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  UPSU_THROW("failed to connect to {}:{}: {}", endpoint.host, endpoint.port,
             last_error);
}

#pragma pack(push, 1)
struct FrameHeader {
  uint32_t magic;
  uint32_t channel_size;
  uint32_t tag_size;
  uint64_t payload_size;
};
#pragma pack(pop)

std::string MessageKey(std::string_view channel, std::string_view tag) {
  return fmt::format("{}:{}{}", channel.size(), channel, tag);
}

}  // namespace

struct Context::Transport {
  explicit Transport(int socket_fd) : fd(socket_fd), reader([this] { ReadLoop(); }) {}

  ~Transport() {
    stopping.store(true);
    ::shutdown(fd, SHUT_RDWR);
    if (reader.joinable()) reader.join();
    ::close(fd);
  }

  void ReadLoop() {
    try {
      while (!stopping.load()) {
        FrameHeader header{};
        if (!ReadAll(fd, &header, sizeof(header))) break;
        UPSU_ENFORCE(header.magic == kFrameMagic, "invalid link frame magic");
        UPSU_ENFORCE(header.channel_size <= 4096 && header.tag_size <= 65536,
                     "link frame metadata is too large");
        UPSU_ENFORCE(header.payload_size <= kMaxMessageSize,
                     "link frame payload is too large: {}", header.payload_size);
        std::string channel(header.channel_size, '\0');
        std::string tag(header.tag_size, '\0');
        Buffer payload(static_cast<size_t>(header.payload_size));
        if (!ReadAll(fd, channel.data(), channel.size()) ||
            !ReadAll(fd, tag.data(), tag.size()) ||
            !ReadAll(fd, payload.data(), payload.size())) {
          throw std::runtime_error("peer closed a partial link frame");
        }
        stats->recv_bytes.fetch_add(sizeof(header) + channel.size() + tag.size() +
                                    payload.size());
        {
          std::lock_guard lock(queue_mutex);
          queues[MessageKey(channel, tag)].push_back(std::move(payload));
        }
        queue_cv.notify_all();
      }
    } catch (const std::exception& error) {
      std::lock_guard lock(queue_mutex);
      read_error = error.what();
    }
    closed.store(true);
    queue_cv.notify_all();
  }

  int fd;
  std::mutex write_mutex;
  std::mutex queue_mutex;
  std::condition_variable queue_cv;
  std::unordered_map<std::string, std::deque<Buffer>> queues;
  std::string read_error;
  std::shared_ptr<LinkStats> stats = std::make_shared<LinkStats>();
  std::atomic<bool> stopping{false};
  std::atomic<bool> closed{false};
  std::thread reader;
};

Context::Context(std::shared_ptr<Transport> transport, size_t rank,
                 std::string channel, uint64_t timeout_ms)
    : transport_(std::move(transport)),
      rank_(rank),
      channel_(std::move(channel)),
      timeout_ms_(timeout_ms) {}

std::shared_ptr<Context> Context::Connect(const std::vector<std::string>& parties,
                                          size_t rank, uint64_t timeout_ms) {
  UPSU_ENFORCE(parties.size() == 2, "exactly two parties are required");
  UPSU_ENFORCE(rank < 2, "invalid party rank {}", rank);
  const Endpoint receiver = ParseEndpoint(parties[0]);
  int fd = -1;
  if (rank == 0) {
    const int listener = MakeListener(receiver);
    fd = ::accept(listener, nullptr, nullptr);
    const int accept_error = errno;
    ::close(listener);
    UPSU_ENFORCE(fd >= 0, "accept failed: {}", std::strerror(accept_error));
  } else {
    fd = ConnectWithRetry(receiver, timeout_ms);
  }
  return std::shared_ptr<Context>(
      new Context(std::make_shared<Transport>(fd), rank, "root", timeout_ms));
}

std::vector<std::shared_ptr<Context>> Context::SetupWorld(size_t party_count) {
  UPSU_ENFORCE(party_count == 2, "only two-party worlds are supported");
  int sockets[2] = {-1, -1};
  UPSU_ENFORCE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0,
               "socketpair failed: {}", std::strerror(errno));
  constexpr uint64_t kDefaultTimeoutMs = 10 * 60 * 1000;
  return {
      std::shared_ptr<Context>(new Context(std::make_shared<Transport>(sockets[0]),
                                           0, "root", kDefaultTimeoutMs)),
      std::shared_ptr<Context>(new Context(std::make_shared<Transport>(sockets[1]),
                                           1, "root", kDefaultTimeoutMs))};
}

void Context::SetRecvTimeout(uint64_t timeout_ms) { timeout_ms_.store(timeout_ms); }

void Context::Send(size_t destination, ByteView data, const std::string& tag) {
  UPSU_ENFORCE(destination < 2 && destination != rank_,
               "invalid link destination {} from rank {}", destination, rank_);
  UPSU_ENFORCE(channel_.size() <= UINT32_MAX && tag.size() <= UINT32_MAX,
               "link metadata is too large");
  FrameHeader header{kFrameMagic, static_cast<uint32_t>(channel_.size()),
                     static_cast<uint32_t>(tag.size()), data.size()};
  std::lock_guard lock(transport_->write_mutex);
  WriteAll(transport_->fd, &header, sizeof(header));
  WriteAll(transport_->fd, channel_.data(), channel_.size());
  WriteAll(transport_->fd, tag.data(), tag.size());
  WriteAll(transport_->fd, data.data(), data.size());
  transport_->stats->sent_bytes.fetch_add(sizeof(header) + channel_.size() +
                                           tag.size() + data.size());
}

Context::Buffer Context::Recv(size_t source, const std::string& tag) {
  UPSU_ENFORCE(source < 2 && source != rank_,
               "invalid link source {} for rank {}", source, rank_);
  const std::string key = MessageKey(channel_, tag);
  std::unique_lock lock(transport_->queue_mutex);
  const auto ready = [&] {
    auto it = transport_->queues.find(key);
    return (it != transport_->queues.end() && !it->second.empty()) ||
           transport_->closed.load();
  };
  UPSU_ENFORCE(transport_->queue_cv.wait_for(
                   lock, std::chrono::milliseconds(timeout_ms_.load()), ready),
               "timed out waiting for link message '{}'", tag);
  auto it = transport_->queues.find(key);
  if (it == transport_->queues.end() || it->second.empty()) {
    UPSU_THROW("link closed while waiting for '{}': {}", tag,
               transport_->read_error.empty() ? "peer disconnected"
                                              : transport_->read_error);
  }
  Buffer result = std::move(it->second.front());
  it->second.pop_front();
  if (it->second.empty()) transport_->queues.erase(it);
  return result;
}

std::unique_ptr<Context> Context::Spawn(const std::string& suffix) const {
  return std::unique_ptr<Context>(new Context(
      transport_, rank_, fmt::format("{}/{}", channel_, suffix), timeout_ms_.load()));
}

std::shared_ptr<LinkStats> Context::GetStats() const { return transport_->stats; }

}  // namespace upsu::net

#pragma once

#include <mutex>

#include "coproto/Socket/AsioSocket.h"

namespace coproto::detail {

inline optional<GlobalIOContext> global_asio_io_context;
inline std::mutex global_asio_io_context_mutex;

}  

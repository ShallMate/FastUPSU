#pragma once

#include <cstring>
#include <stdexcept>
#include <type_traits>

#include "cryptoTools/Common/Defines.h"

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

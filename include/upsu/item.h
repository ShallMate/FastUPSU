#pragma once

#include "upsu/common.h"
#include <string_view>

namespace upsu {

inline uint128_t ParseItem(std::string_view text) {
  const bool hexadecimal = text.starts_with("0x");
  if (hexadecimal) text.remove_prefix(2);
  UPSU_ENFORCE(!text.empty(), "empty item encoding");
  const unsigned base = hexadecimal ? 16 : 10;
  uint128_t value = 0;
  for (char c : text) {
    const unsigned digit = c >= '0' && c <= '9' ? c - '0'
        : c >= 'a' && c <= 'f' ? c - 'a' + 10
        : c >= 'A' && c <= 'F' ? c - 'A' + 10 : 255;
    UPSU_ENFORCE(digit < base && value <= (~uint128_t{0} - digit) / base,
                 "invalid 128-bit item");
    value = value * base + digit;
  }
  return value;
}

inline std::string ItemHex(uint128_t value) {
  return fmt::format("0x{:016x}{:016x}", Uint128High64(value), Uint128Low64(value));
}

}  // namespace upsu

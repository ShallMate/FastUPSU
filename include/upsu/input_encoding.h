#pragma once

#include <array>
#include <string>
#include <vector>
#include "upsu/common.h"

namespace psu::encoding {
using Salt = std::array<uint8_t, 16>;
inline constexpr char kSaltTag[] = "PSU:encoding_salt_v1";
Salt FreshSalt();
std::array<uint8_t, 32> Blake3Digest(upsu::ByteView input);
uint128_t Hash(const Salt& salt, std::string_view item);
std::vector<uint128_t> Encode(const Salt& salt,
                             const std::vector<std::string>& items);
}  // namespace psu::encoding

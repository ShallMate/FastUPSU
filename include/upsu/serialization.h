#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

namespace upsu::serialization {
bool CompressionEnabled();
bool IsCompressed(const std::uint8_t* data, std::size_t size);
std::size_t UncompressedSize(const std::uint8_t* data, std::size_t size);
std::size_t SavedBytes();
std::string Pack(std::string bytes);
std::string Unpack(const std::uint8_t* data, std::size_t size);
}

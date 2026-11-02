#include "upsu/serialization.h"
#include "upsu/common.h"
#include <cstdlib>
#include <cstring>
#include <atomic>
#ifdef UPSU_HAVE_ZSTD
#include <zstd.h>
#endif

namespace upsu::serialization {
namespace {
constexpr std::uint64_t kMagic=0x3154535a55535055ULL;
constexpr std::uint64_t kShuffleMagic=0x3254535a55535055ULL;
constexpr std::size_t kHeader=16;
std::atomic<std::size_t> saved_bytes{0};
std::string Shuffle(const std::string& input,bool inverse) {
  std::string output(input.size(),'\0');
  const std::size_t words=input.size()/8;
  for(std::size_t plane=0;plane<8;++plane)
    for(std::size_t word=0;word<words;++word)
      if(inverse) output[8*word+plane]=input[plane*words+word];
      else output[plane*words+word]=input[8*word+plane];
  for(std::size_t i=8*words;i<input.size();++i) output[i]=input[i];
  return output;
}
}
bool CompressionEnabled() {
  const char* mode=std::getenv("PSU_SERIALIZATION_COMPRESSION");
  return mode && (std::strcmp(mode,"1")==0 || std::strcmp(mode,"zstd")==0);
}
bool IsCompressed(const std::uint8_t* data, std::size_t size) {
  std::uint64_t magic=0;
  if(size>=kHeader) std::memcpy(&magic,data,sizeof(magic));
  return magic==kMagic || magic==kShuffleMagic;
}
std::size_t UncompressedSize(const std::uint8_t* data,std::size_t size) {
  if(!IsCompressed(data,size)) return size;
  std::uint64_t original=0;
  std::memcpy(&original,data+8,8);
  return static_cast<std::size_t>(original);
}
std::size_t SavedBytes() { return saved_bytes.load(); }
std::string Pack(std::string bytes) {
  if(!CompressionEnabled() || bytes.size()<4096) return bytes;
#ifdef UPSU_HAVE_ZSTD
  // Transpose byte positions to expose the zero high bytes of RNS coefficients.
  // This is a reversible byte permutation, independent of the protocol inputs.
  const auto shuffled=Shuffle(bytes,false);
  std::string compressed(kHeader+ZSTD_compressBound(bytes.size()),'\0');
  const std::size_t written=ZSTD_compress(compressed.data()+kHeader,
      compressed.size()-kHeader,shuffled.data(),shuffled.size(),1);
  UPSU_ENFORCE(!ZSTD_isError(written),"Zstandard compression failed");
  if(written+kHeader>=bytes.size()) return bytes;
  const std::uint64_t raw_size=bytes.size();
  std::memcpy(compressed.data(),&kShuffleMagic,8);
  std::memcpy(compressed.data()+8,&raw_size,8);
  compressed.resize(written+kHeader);
  if(std::getenv("PSU_DIAGNOSTIC_DIR"))
    UPSU_ENFORCE(Unpack(reinterpret_cast<const std::uint8_t*>(compressed.data()),compressed.size())==bytes,
                 "serialization round trip changed SEAL bytes");
  saved_bytes.fetch_add(bytes.size()-compressed.size());
  return compressed;
#else
  UPSU_THROW("compression requested without UPSU_ENABLE_ZSTD");
#endif
}
std::string Unpack(const std::uint8_t* data, std::size_t size) {
  UPSU_ENFORCE(IsCompressed(data,size),"invalid compressed SEAL object");
#ifdef UPSU_HAVE_ZSTD
  std::uint64_t raw_size=0;
  std::memcpy(&raw_size,data+8,8);
  UPSU_ENFORCE(raw_size>0 && raw_size<=(std::uint64_t{8}<<30),"invalid decoded size");
  std::string bytes(static_cast<std::size_t>(raw_size),'\0');
  const std::size_t written=ZSTD_decompress(bytes.data(),bytes.size(),data+kHeader,size-kHeader);
  UPSU_ENFORCE(!ZSTD_isError(written) && written==bytes.size(),"invalid compressed SEAL object");
  std::uint64_t magic=0;
  std::memcpy(&magic,data,8);
  return magic==kShuffleMagic ? Shuffle(bytes,true) : bytes;
#else
  UPSU_THROW("compressed message requires UPSU_ENABLE_ZSTD");
#endif
}
}

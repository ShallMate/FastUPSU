#include "upsu/input_encoding.h"
#include "upsu/paper_encoding.h"
#include "upsu/parallel.h"
#include <iostream>

int main() {
  const auto digest = psu::encoding::Blake3Digest(upsu::Bytes(""));
  constexpr std::array<uint8_t,32> expected{
    0xaf,0x13,0x49,0xb9,0xf5,0xf9,0xa1,0xa6,0xa0,0x40,0x4d,0xea,0x36,0xdc,0xc9,0x49,
    0x9b,0xcb,0x25,0xc9,0xad,0xc1,0x12,0xb7,0xcc,0x9a,0x93,0xca,0xe4,0x1f,0x32,0x62};
  UPSU_ENFORCE(digest == expected, "BLAKE3 known-answer mismatch");
  psu::encoding::Salt salt{}, other{};other[15]=1;
  std::vector<std::string> items{"", "a", std::string("a\0b",3), "ab", "00000000000000000000000000000000"};
  for(size_t i=0;i<4096;++i) items.push_back(std::to_string(i));
  upsu::set_num_threads(1);const auto serial=psu::encoding::Encode(salt,items);
  upsu::set_num_threads(8);const auto parallel=psu::encoding::Encode(salt,items);
  UPSU_ENFORCE(serial==parallel,"parallel encoding changed input order or values");
  psu::paper::RequireDistinctEncodings(serial);
  for(size_t i=0;i<items.size();++i) {
    UPSU_ENFORCE(serial[i]==psu::encoding::Hash(salt,items[i]),"encoding mismatch");
    UPSU_ENFORCE(serial[i]!=psu::encoding::Hash(other,items[i]),"salt separation failed");
    for(size_t m : {size_t{3},size_t{5202},size_t{10404},size_t{20808}}) {
      const auto b=psu::paper::CandidateBins(serial[i],m);
      UPSU_ENFORCE(b[0]<m && b[1]<m && b[2]<m && b[0]!=b[1] && b[0]!=b[2] && b[1]!=b[2],"invalid bins");
    }
  }
  bool rejected=false;
  try {psu::paper::RequireDistinctEncodings({serial[0],serial[0]});}
  catch(const std::runtime_error&) {rejected=true;}
  UPSU_ENFORCE(rejected,"local encoding collisions must abort");
  std::cout << "salted BLAKE3 KAT, domain/salt separation, ordering, 1/8-thread equality and distinct-bin checks PASS\n";
}

#pragma once



















#include "GMW/Defines.h"
#include "GMW/config.h"

#ifdef VOLE_PSI_ENABLE_GMW

#include <memory>
#include <vector>

#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"

namespace volePSI {

Proto generateBase(RequiredBase base, u64 partyIdx, oc::PRNG& prng,
                   coproto::Socket& chl, span<block> recvMsg,
                   span<std::array<block, 2>> sendMsg,
                   oc::Timer* timer = nullptr);

Proto extend(RequiredBase b, span<std::array<block, 2>> baseMsg,
             oc::PRNG& prng, coproto::Socket& chl, span<block> recvMsgP,
             span<std::array<block, 2>> sendMsgP);

Proto extend(RequiredBase b, oc::BitVector baseChoice, span<block> baseMsg,
             oc::PRNG& prng, coproto::Socket& chl, span<block> recvMsgP,
             span<std::array<block, 2>> sendMsgP);

class SilentTripleGen : public oc::TimerAdapter {
 public:
  bool mHasBase = false;
  u64 mN = 0;
  u64 mBatchSize = 0;
  u64 mNumPer = 0;
  Mode mMode = Mode::Sender;
  oc::PRNG mPrng;

  std::unique_ptr<oc::SilentOtExtSender[]> mBackingSenderOT;
  std::unique_ptr<oc::SilentOtExtReceiver[]> mBackingRecverOT;

  span<oc::SilentOtExtSender> mSenderOT;
  span<oc::SilentOtExtReceiver> mRecverOT;

  void init(u64 n, u64 batchSize, u64 numThreads, Mode mode, block seed);

  RequiredBase mBase;

  RequiredBase requiredBaseOts();

  void setBaseOts(span<block> recvOts, span<std::array<block, 2>> sendOts);

  Proto expand(coproto::Socket& chl);

  bool hasBaseOts() { return mHasBase; }

  Proto generateBaseOts(u64 partyIdx, oc::PRNG& prng, coproto::Socket& chl) {
    auto rMsg = std::vector<block>{};
    auto sMsg = std::vector<std::array<block, 2>>{};
    auto b = RequiredBase{};

    setTimePoint("TripleGen::generateBaseOts begin");
    b = requiredBaseOts();

    if (b.mNumSend || b.mRecvChoiceBits.size()) {
      rMsg.resize(b.mRecvChoiceBits.size());
      sMsg.resize(b.mNumSend);
      co_await(generateBase(b, partyIdx, prng, chl, rMsg, sMsg, mTimer));
      setBaseOts(rMsg, sMsg);
    }
    setTimePoint("TripleGen::generateBaseOts end");
  }

  span<block> mMult, mAdd;
  std::vector<block> mAVec, mBVec, mDVec;
  oc::BitVector mCBitVec;
};

}  
#endif

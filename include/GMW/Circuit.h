#pragma once



















#include "GMW/Defines.h"
#include "GMW/config.h"

#ifdef VOLE_PSI_ENABLE_GMW
#include "cryptoTools/Circuit/BetaCircuit.h"

namespace volePSI {
#ifndef ENABLE_CIRCUITS
static_assert(0, "ENABLE_CIRCUITS not defined in cryptoTools");
#endif

using BetaCircuit = oc::BetaCircuit;
using BetaBundle = oc::BetaBundle;

BetaCircuit isZeroCircuit(u64 bits);
BetaCircuit orCircuit(u64 bits);
BetaCircuit anyZeroCircuit(u64 rows, u64 bits_per_row);
void evaluate(BetaCircuit& parent, const BetaCircuit& cir,
              span<BetaBundle> inputs, span<BetaBundle> outputs);

void isZeroCircuit_Test();

}  

#endif

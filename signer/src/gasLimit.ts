// Sets the VERIFY frame's execution limit from the exact work of the signature.
// The signed message is the signature hash, which covers the limit itself, so the limit is
// chosen in a short loop until it covers the steps of the hash it is part of.
import { hexToBytes, type Hex } from "viem";
import { verifySteps, type Params } from "./wots";
import { computeSigHash, type FrameTx } from "./frameTx";

export interface GasModel { intercept: number; perStep: number; maxResidual: number }

export const MAX_VERIFY_GAS = 100_000n; // simulator/rules.json
export const SIG_GAS_ARBITRARY = 100n; // simulator/rules.json
export const MARGIN = 2_000n; // covers frame entry and real opcode costs beyond the bench build

export function limitForSteps(m: GasModel, steps: number): bigint {
  return BigInt(Math.ceil(m.intercept + m.perStep * steps + Math.max(0, m.maxResidual))) + MARGIN;
}

export function chooseVerifyLimit(tx: FrameTx, m: GasModel, p: Params, seed: Uint8Array, chainId: bigint, leaf: number): { limit: bigint; steps: number; sigHash: Hex } {
  let limit = tx.frames[0].limits.execution;
  for (let round = 0; round < 8; round++) {
    tx.frames[0].limits.execution = limit;
    const sigHash = computeSigHash(tx, "devnet");
    const steps = verifySteps(p, seed, chainId, leaf, hexToBytes(sigHash));
    const need = limitForSteps(m, steps);
    if (need <= limit) return { limit, steps, sigHash };
    limit = need;
  }
  throw new Error("could not settle the VERIFY limit");
}

export function fitsPublicCap(limit: bigint): boolean {
  return limit + SIG_GAS_ARBITRARY <= MAX_VERIFY_GAS;
}

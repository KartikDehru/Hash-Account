import { expect, test } from "bun:test";
import { hexToBytes } from "viem";
import { chooseVerifyLimit, fitsPublicCap, limitForSteps } from "../src/gasLimit";
import { lamportPayment, computeSigHash } from "../src/frameTx";
import { verifySteps, PROFILE_A } from "../src/wots";

const model = { intercept: 26225, perStep: 81.405, maxResidual: 334.6 };

test("chosen limit covers the steps of the final signature hash", () => {
  const seed = new Uint8Array(32).fill(9);
  for (let leaf = 0; leaf < 20; leaf++) {
    const tx = lamportPayment({
      chainId: 1337n, sender: "0x000000000000000000000000000000000000a11c", leaf,
      to: "0x000000000000000000000000000000000000b0b0", value: 1n, verifyGas: 60_000n, senderGas: 30_000n,
      fees: { maxPriorityFeePerGas: 1n, maxFeePerGas: 2n, maxFeePerBlobGas: 0n }, signatureLength: 2468,
    });
    const r = chooseVerifyLimit(tx, model, PROFILE_A, seed, 1337n, leaf);
    expect(tx.frames[0].limits.execution).toBe(r.limit);
    expect(computeSigHash(tx)).toBe(r.sigHash);
    const steps = verifySteps(PROFILE_A, seed, 1337n, leaf, hexToBytes(r.sigHash));
    expect(r.limit >= limitForSteps(model, steps)).toBe(true);
    expect(fitsPublicCap(r.limit)).toBe(true);
  }
});

test("the worst possible signature (990 steps) does not fit the public cap", () => {
  expect(fitsPublicCap(limitForSteps(model, 990))).toBe(false);
});

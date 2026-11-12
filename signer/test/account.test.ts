import { expect, test } from "bun:test";
import { hexToBytes, keccak256, toBytes, bytesToHex } from "viem";
import { AccountKey, ACCOUNT_SIG_BYTES, legacyNonce } from "../src/account";
import { lamportPayment, nonceKeyForLeaf, rotationFrame, LEAF_KEY_BASE } from "../src/frameTx";
import { KeyTree, verify } from "../src/wots";

test("account signature is seed || root || Lamport signature (2,532 bytes)", () => {
  const tree = new KeyTree({ logW: 4, height: 10 }, new Uint8Array(32).fill(3), new Uint8Array(32).fill(4), 9n);
  const m = keccak256(toBytes("m"), "bytes");
  const sig = new AccountKey(tree, 1).signWithLeaf(5, m);
  expect(sig.length).toBe(ACCOUNT_SIG_BYTES);
  expect(bytesToHex(sig.slice(0, 32))).toBe(bytesToHex(tree.seed));
  expect(bytesToHex(sig.slice(32, 64))).toBe(bytesToHex(tree.root));
  expect(verify(tree.p, tree.seed, tree.root, 9n, m, sig.slice(64))).toBe(true);
}, 60_000);

test("nonce key and legacy nonce encode the epoch", () => {
  expect(nonceKeyForLeaf(7, LEAF_KEY_BASE, 2)).toBe(LEAF_KEY_BASE + (2n << 16n) + 7n);
  expect(legacyNonce(2, 7)).toBe(2055n);
  const fees = { maxPriorityFeePerGas: 1n, maxFeePerGas: 1n, maxFeePerBlobGas: 0n };
  const base = { chainId: 9n, sender: "0x000000000000000000000000000000000000a11c" as const, leaf: 7, to: "0x000000000000000000000000000000000000b0b0" as const,
    value: 0n, verifyGas: 1n, senderGas: 1n, fees, signatureLength: ACCOUNT_SIG_BYTES, epoch: 2 };
  expect(lamportPayment(base).nonceKeys).toEqual([LEAF_KEY_BASE + (2n << 16n) + 7n]);
  const legacy = lamportPayment({ ...base, nonceMode: "legacy" });
  expect(legacy.nonceKeys).toEqual([0n]);
  expect(legacy.nonceSeq).toBe(2055n);
});

test("rotation frame calls the account itself with 0x02 || seed || root", () => {
  const seed = bytesToHex(new Uint8Array(32).fill(1));
  const root = bytesToHex(new Uint8Array(32).fill(2));
  const f = rotationFrame("0x000000000000000000000000000000000000a11c", seed, root);
  expect(f.target).toBe("0x000000000000000000000000000000000000a11c");
  expect(hexToBytes(f.data).length).toBe(65);
  expect(hexToBytes(f.data)[0]).toBe(2);
});

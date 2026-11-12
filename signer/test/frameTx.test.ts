import { expect, test } from "bun:test";
import { RLP } from "@ethereumjs/rlp";
import { bytesToHex, hexToBytes, keccak256, toBytes, toHex } from "viem";
import { computeSigHash, lamportPayment, rawFrameTx, nonceKeyForLeaf } from "../src/frameTx";
import { nonceSlot } from "../src/leafState";
import { Journal, LeafReuseError, Signer } from "../src/signer";
import { KeyTree } from "../src/wots";

const fees = { maxPriorityFeePerGas: 1_000_000_000n, maxFeePerGas: 20_000_000_000n, maxFeePerBlobGas: 0n, maxFee: 10n ** 16n };
const tx = () => lamportPayment({
  chainId: 1337n, sender: "0x000000000000000000000000000000000000a11c", leaf: 3,
  to: "0x000000000000000000000000000000000000b0b0", value: 10n ** 15n, verifyGas: 90_000n, senderGas: 30_000n,
  fees: { ...fees }, signatureLength: 2468,
});

// Independent encoder (the RLP library the sidecar uses), following sidecar codec.ts field order.
function sidecarSigHash(t: ReturnType<typeof tx>): string {
  const int = (n: bigint | number) => (BigInt(n) === 0n ? new Uint8Array() : toBytes(toHex(BigInt(n))));
  const structure = [
    int(t.chainId), t.nonceKeys.map(int), int(t.nonceSeq), toBytes(t.sender),
    t.frames.map((f) => [int(f.mode), int(f.flags), f.target ? toBytes(f.target) : new Uint8Array(), [int(f.limits.execution), int(f.limits.state)], int(f.value), toBytes(f.data)]),
    t.signatures.map((s) => [int(s.scheme), toBytes(s.signer), toBytes(s.msg), s.msg === "0x" ? new Uint8Array() : toBytes(s.signature)]),
    [int(t.fees.maxPriorityFeePerGas), int(t.fees.maxFeePerGas), int(t.fees.maxFeePerBlobGas)],
    [], [],
  ];
  return keccak256(new Uint8Array([6, ...RLP.encode(structure as never)]));
}

test("devnet signature hash matches an independent encoding of the sidecar codec", () => {
  expect(computeSigHash(tx(), "devnet")).toBe(sidecarSigHash(tx()) as `0x${string}`);
});

test("signature bytes do not change the hash; fees, frames and keys do", () => {
  const a = tx();
  const b = tx();
  b.signatures[0].signature = toHex(new Uint8Array(2468).fill(7));
  expect(computeSigHash(a)).toBe(computeSigHash(b));
  const c = tx(); c.fees.maxFeePerGas += 1n;
  const d = tx(); d.frames[1].value += 1n;
  const e = tx(); e.nonceKeys = [nonceKeyForLeaf(4)];
  for (const x of [c, d, e]) expect(computeSigHash(x)).not.toBe(computeSigHash(a));
  // The EIP-text encoding commits to the signature length.
  const f = tx(); f.signatures[0].signature = toHex(new Uint8Array(2467));
  expect(computeSigHash(f, "eip")).not.toBe(computeSigHash(a, "eip"));
});

test("raw transaction decodes to nine fields", () => {
  const raw = hexToBytes(rawFrameTx(tx()));
  expect(raw[0]).toBe(6);
  expect((RLP.decode(raw.slice(1)) as unknown[]).length).toBe(9);
});

test("NONCE_MANAGER slot follows keccak256(pad32(sender) || be32(key))", () => {
  const sender = "0x000000000000000000000000000000000000a11c";
  const key = nonceKeyForLeaf(0);
  const expected = keccak256(new Uint8Array([...new Uint8Array(12), ...hexToBytes(sender), ...toBytes(key, { size: 32 })]));
  expect(nonceSlot(sender, key)).toBe(expected);
});

test("signer refuses spent, pending and journalled leaves", async () => {
  const tree = new KeyTree({ logW: 4, height: 2 }, new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), 1337n);
  const spent = new Set([0]);
  const pending = new Set([1]);
  const state = { isSpent: async (l: number) => spent.has(l), isPending: async (l: number) => pending.has(l) };
  const signer = new Signer(tree, state, new Journal());
  expect(await signer.nextUnusedLeaf()).toBe(2);
  const m = keccak256(toBytes("m"));
  await signer.signWithLeaf(2, m);
  expect(signer.signWithLeaf(2, keccak256(toBytes("other")))).rejects.toBeInstanceOf(LeafReuseError);
  expect(signer.signWithLeaf(0, m)).rejects.toBeInstanceOf(LeafReuseError);
  expect(signer.signWithLeaf(1, m)).rejects.toBeInstanceOf(LeafReuseError);
  expect(await signer.nextUnusedLeaf()).toBe(3);
  expect(bytesToHex(tree.root).length).toBe(66);
});

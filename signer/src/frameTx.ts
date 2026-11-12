// EIP-8141 frame transaction (with EIP-8250 keyed nonces) encoding and signature hash.
// Two encodings exist (docs/SPEC_FACTS.md, "Devnet implementation differs"):
//   "devnet": forshtat/ethrex eip8141-tracer@9aa3645 and the sidecar: three fee fields,
//             recent-root list, elided signature bytes replaced by empty bytes.
//   "eip":    EIP text read 2026-10-24: fees [max_fee, max_priority_fee_per_gas], no recent
//             roots, elided bytes replaced by their length.
import { keccak256, toRlp, fromRlp, toHex, concat, hexToBigInt, type Hex } from "viem";

export const FRAME_TX_TYPE = 0x06;
export const MODE = { DEFAULT: 0, VERIFY: 1, SENDER: 2 } as const;
export const SCHEME = { ARBITRARY: 0, SECP256K1: 1, P256: 2 } as const;
export const LEAF_KEY_BASE = BigInt(0x4c414d50) << 224n; // "LAMP", Profile A
export const XMSS_KEY_BASE = BigInt(0x4c4d5042) << 224n; // "LMPB", Profile B
export const DEVNET_NONCE_MANAGER = "0x0000000000000000000000000000000000008250" as const;

export type Encoding = "devnet" | "eip";
export type NonceMode = "keyed" | "legacy";

export interface Frame {
  mode: number;
  flags: number;
  target: Hex | null;
  limits: { execution: bigint; state: bigint };
  value: bigint;
  data: Hex;
}
export interface SignatureEntry { scheme: number; signer: Hex; msg: Hex; signature: Hex }
export interface Fees { maxPriorityFeePerGas: bigint; maxFeePerGas: bigint; maxFeePerBlobGas: bigint; maxFee?: bigint }
export interface FrameTx {
  chainId: bigint;
  nonceKeys: bigint[];
  nonceSeq: bigint;
  sender: Hex;
  frames: Frame[];
  signatures: SignatureEntry[];
  fees: Fees;
  blobVersionedHashes: Hex[];
  recentRootReferences: { sourceId: Hex; slot: bigint; root: Hex }[];
}

/** Nonce key of a leaf: base + (epoch << 16) + leaf (Profile A epochs; Profile B uses epoch 0). */
export const nonceKeyForLeaf = (leaf: number, base: bigint = LEAF_KEY_BASE, epoch = 0): bigint =>
  base + (BigInt(epoch) << 16n) + BigInt(leaf);

// RLP integers are minimal big-endian byte strings; 0 is the empty string.
const int = (n: bigint | number): Hex => (BigInt(n) === 0n ? "0x" : toHex(BigInt(n)));

function fields(tx: FrameTx, enc: Encoding, elide: boolean) {
  const frames = tx.frames.map((f) => [int(f.mode), int(f.flags), f.target ?? "0x", [int(f.limits.execution), int(f.limits.state)], int(f.value), f.data]);
  const sigs = tx.signatures.map((s) => {
    let sig: Hex = s.signature;
    if (elide && s.msg === "0x") sig = enc === "devnet" ? "0x" : int((s.signature.length - 2) / 2);
    return [int(s.scheme), s.signer, s.msg, sig];
  });
  const base = [int(tx.chainId), tx.nonceKeys.map(int), int(tx.nonceSeq), tx.sender, frames, sigs];
  if (enc === "devnet") {
    return [
      ...base,
      [int(tx.fees.maxPriorityFeePerGas), int(tx.fees.maxFeePerGas), int(tx.fees.maxFeePerBlobGas)],
      tx.blobVersionedHashes,
      tx.recentRootReferences.map((r) => [r.sourceId, int(r.slot), r.root]),
    ];
  }
  if (tx.fees.maxFee === undefined) throw new Error("EIP encoding needs fees.maxFee");
  return [...base, [int(tx.fees.maxFee), int(tx.fees.maxPriorityFeePerGas)], tx.blobVersionedHashes];
}

export function rawFrameTx(tx: FrameTx, enc: Encoding = "devnet"): Hex {
  return concat([toHex(FRAME_TX_TYPE, { size: 1 }), toRlp(fields(tx, enc, false) as never)]);
}

/** Canonical signature hash: what TXPARAM(0x08) returns and what the account verifies. */
export function computeSigHash(tx: FrameTx, enc: Encoding = "devnet"): Hex {
  return keccak256(concat([toHex(FRAME_TX_TYPE, { size: 1 }), toRlp(fields(tx, enc, true) as never)]));
}

/** JSON-RPC param for eth_sendFrameTransaction / eth_estimateFrameTransactionGas (sidecar DTO). */
export function toRpc(tx: FrameTx) {
  const q = (n: bigint) => toHex(n);
  return {
    chainId: q(tx.chainId),
    nonceKeys: tx.nonceKeys.map(q),
    nonceSeq: q(tx.nonceSeq),
    sender: tx.sender,
    frames: tx.frames.map((f) => ({
      mode: f.mode, flags: f.flags, target: f.target,
      limits: { execution: q(f.limits.execution), state: q(f.limits.state) },
      value: q(f.value), data: f.data,
    })),
    signatures: tx.signatures,
    fees: {
      maxPriorityFeePerGas: q(tx.fees.maxPriorityFeePerGas),
      maxFeePerGas: q(tx.fees.maxFeePerGas),
      maxFeePerBlobGas: q(tx.fees.maxFeePerBlobGas),
    },
    blobVersionedHashes: tx.blobVersionedHashes,
    recentRootReferences: tx.recentRootReferences.map((r) => ({ ...r, slot: q(r.slot) })),
  };
}

/** Lamport payment: [VERIFY self (approve 3), SENDER transfer]. Signature entry 0 is filled later. */
/** Key rotation frame: the account calls itself with 0x02 || seed || root (registers the next tree). */
export function rotationFrame(account: Hex, seed: Hex, root: Hex): Frame {
  return { mode: MODE.SENDER, flags: 0, target: account, limits: { execution: 60_000n, state: 300_000n }, value: 0n, data: concat(["0x02", seed, root]) };
}

export function lamportPayment(opts: {
  chainId: bigint; sender: Hex; leaf: number; to: Hex; value: bigint; data?: Hex;
  verifyGas: bigint; senderGas: bigint; fees: Fees; signatureLength: number; keyBase?: bigint;
  nonceMode?: NonceMode; senderState?: bigint; epoch?: number; frames?: Frame[];
}): FrameTx {
  const legacy = opts.nonceMode === "legacy";
  return {
    chainId: opts.chainId,
    // keyed: leaf i uses nonce key LAMP+i at sequence 0; legacy: the leaf is the account nonce.
    nonceKeys: legacy ? [0n] : [nonceKeyForLeaf(opts.leaf, opts.keyBase, opts.epoch ?? 0)],
    nonceSeq: legacy ? BigInt(opts.epoch ?? 0) * 1024n + BigInt(opts.leaf) : 0n,
    sender: opts.sender,
    frames: [
      { mode: MODE.VERIFY, flags: 3, target: null, limits: { execution: opts.verifyGas, state: 0n }, value: 0n, data: "0x0100" },
      // Extra frames replace the default payment (key rotation calls the account itself).
      ...(opts.frames ?? [
        // State gas covers creating the recipient account (EIP-8037: 120 bytes x 1,530 = 183,600 on the devnet build).
        { mode: MODE.SENDER, flags: 0, target: opts.to, limits: { execution: opts.senderGas, state: opts.senderState ?? 200_000n }, value: opts.value, data: opts.data ?? "0x" },
      ]),
    ],
    // Placeholder of the final length: the devnet hash elides the bytes; the EIP hash commits to the length.
    signatures: [{ scheme: SCHEME.ARBITRARY, signer: "0x", msg: "0x", signature: toHex(new Uint8Array(opts.signatureLength)) }],
    fees: opts.fees,
    blobVersionedHashes: [],
    recentRootReferences: [],
  };
}

/** Inverse of rawFrameTx for the devnet encoding (used to rebroadcast an already-signed transaction). */
export function decodeRawFrameTx(raw: Hex): FrameTx {
  if (!raw.startsWith("0x06")) throw new Error("not a frame transaction");
  const f = fromRlp(`0x${raw.slice(4)}`, "hex") as any[];
  const n = (x: Hex) => (x === "0x" ? 0n : hexToBigInt(x));
  return {
    chainId: n(f[0]), nonceKeys: (f[1] as Hex[]).map(n), nonceSeq: n(f[2]), sender: f[3],
    frames: (f[4] as any[]).map((fr) => ({ mode: Number(n(fr[0])), flags: Number(n(fr[1])), target: fr[2] === "0x" ? null : fr[2],
      limits: { execution: n(fr[3][0]), state: n(fr[3][1]) }, value: n(fr[4]), data: fr[5] })),
    signatures: (f[5] as any[]).map((sg) => ({ scheme: Number(n(sg[0])), signer: sg[1], msg: sg[2], signature: sg[3] })),
    fees: { maxPriorityFeePerGas: n(f[6][0]), maxFeePerGas: n(f[6][1]), maxFeePerBlobGas: n(f[6][2]) },
    blobVersionedHashes: f[7], recentRootReferences: (f[8] as any[]).map((r) => ({ sourceId: r[0], slot: n(r[1]), root: r[2] })),
  };
}

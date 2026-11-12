// Winternitz one-time signatures in a Merkle tree. Same encoding as reference/SPEC.md.
// Unaudited research code. Test keys only.
import { keccak256, concat, toBytes, bytesToHex, type Hex } from "viem";

export const CHAIN = 1n, LEAF_PK = 2n, TREE = 3n, MSG = 4n;

export interface Params { logW: number; height: number }
export const PROFILE_A: Params = { logW: 4, height: 10 };

export function lengths(p: Params): { len1: number; len2: number; len: number } {
  const w = 1 << p.logW;
  const len1 = 256 / p.logW;
  const maxChecksum = len1 * (w - 1);
  const len2 = Math.floor((maxChecksum.toString(2).length - 1) / p.logW) + 1;
  return { len1, len2, len: len1 + len2 };
}

export function signatureBytes(p: Params): number {
  return 4 + 32 * (lengths(p).len + p.height);
}

const h = (data: Uint8Array): Uint8Array => keccak256(data, "bytes");

export function adrs(kind: bigint, chainId: bigint, a = 0n, b = 0n, c = 0n): Uint8Array {
  const word = (kind << 248n) | (chainId << 184n) | (a << 152n) | (b << 120n) | (c << 88n);
  return toBytes(word, { size: 32 });
}

function chain(seed: Uint8Array, chainId: bigint, leaf: number, index: number, x: Uint8Array, start: number, end: number): Uint8Array {
  // One buffer per chain: seed | adrs | x, only the step field and x change.
  const buf = new Uint8Array(96);
  buf.set(seed, 0);
  for (let step = start; step < end; step++) {
    buf.set(adrs(CHAIN, chainId, BigInt(leaf), BigInt(index), BigInt(step)), 32);
    buf.set(x, 64);
    x = h(buf);
  }
  return x;
}

export function digits(p: Params, digest: Uint8Array): number[] {
  const { len1, len2 } = lengths(p);
  const mask = (1 << p.logW) - 1;
  const value = BigInt(bytesToHex(digest));
  const out: number[] = [];
  for (let i = 0; i < len1; i++) out.push(Number((value >> BigInt(256 - p.logW * (i + 1))) & BigInt(mask)));
  const checksum = out.reduce((s, d) => s + (mask - d), 0);
  for (let k = 0; k < len2; k++) out.push((checksum >> (p.logW * (len2 - 1 - k))) & mask);
  return out;
}

export function messageDigest(p: Params, seed: Uint8Array, chainId: bigint, leaf: number, message: Uint8Array): Uint8Array {
  return h(concat([seed, adrs(MSG, chainId, BigInt(leaf), 0n, BigInt(p.logW)), message]));
}

function secretStart(skSeed: Uint8Array, leaf: number, index: number): Uint8Array {
  return h(concat([new TextEncoder().encode("LAMPORT-SK"), skSeed, toBytes(leaf, { size: 4 }), toBytes(index, { size: 4 })]));
}

export function keygenLeaf(p: Params, skSeed: Uint8Array, seed: Uint8Array, chainId: bigint, leaf: number): Uint8Array {
  const { len } = lengths(p);
  const w = 1 << p.logW;
  const ends: Uint8Array[] = [];
  for (let i = 0; i < len; i++) ends.push(chain(seed, chainId, leaf, i, secretStart(skSeed, leaf, i), 0, w - 1));
  return h(concat([seed, adrs(LEAF_PK, chainId, BigInt(leaf), 0n, BigInt(p.logW)), ...ends]));
}

export function treeNode(seed: Uint8Array, chainId: bigint, level: number, index: number, left: Uint8Array, right: Uint8Array): Uint8Array {
  return h(concat([seed, adrs(TREE, chainId, BigInt(level), BigInt(index)), left, right]));
}

export class KeyTree {
  readonly levels: Uint8Array[][];

  constructor(readonly p: Params, private readonly skSeed: Uint8Array, readonly seed: Uint8Array, readonly chainId: bigint) {
    let nodes: Uint8Array[] = [];
    for (let i = 0; i < 1 << p.height; i++) nodes.push(keygenLeaf(p, skSeed, seed, chainId, i));
    this.levels = [nodes];
    for (let level = 1; level <= p.height; level++) {
      const prev = this.levels[level - 1];
      nodes = [];
      for (let k = 0; k < prev.length / 2; k++) nodes.push(treeNode(seed, chainId, level, k, prev[2 * k], prev[2 * k + 1]));
      this.levels.push(nodes);
    }
  }

  get root(): Uint8Array {
    return this.levels[this.p.height][0];
  }

  get leaves(): number {
    return 1 << this.p.height;
  }

  path(leaf: number): Uint8Array[] {
    const out: Uint8Array[] = [];
    for (let level = 0; level < this.p.height; level++) out.push(this.levels[level][(leaf >> level) ^ 1]);
    return out;
  }

  /** Raw one-time signing. Does not check reuse: use Signer (signer.ts), never this, outside tests. */
  signWithLeaf(leaf: number, message: Uint8Array): Uint8Array {
    const ds = digits(this.p, messageDigest(this.p, this.seed, this.chainId, leaf, message));
    const values = ds.map((d, i) => chain(this.seed, this.chainId, leaf, i, secretStart(this.skSeed, leaf, i), 0, d));
    return concat([toBytes(leaf, { size: 4 }), ...values, ...this.path(leaf)]);
  }
}

export function verify(p: Params, seed: Uint8Array, root: Uint8Array, chainId: bigint, message: Uint8Array, sig: Uint8Array): boolean {
  const { len } = lengths(p);
  if (sig.length !== signatureBytes(p) || message.length !== 32) return false;
  const leaf = Number(BigInt(bytesToHex(sig.slice(0, 4))));
  if (leaf >= 1 << p.height) return false;
  const w = 1 << p.logW;
  const ds = digits(p, messageDigest(p, seed, chainId, leaf, message));
  const ends = ds.map((d, i) => chain(seed, chainId, leaf, i, sig.slice(4 + 32 * i, 36 + 32 * i), d, w - 1));
  let node = h(concat([seed, adrs(LEAF_PK, chainId, BigInt(leaf), 0n, BigInt(p.logW)), ...ends]));
  for (let level = 1; level <= p.height; level++) {
    const off = 4 + 32 * (len + level - 1);
    const sibling = sig.slice(off, off + 32);
    const index = leaf >> level;
    node = (leaf >> (level - 1)) & 1 ? treeNode(seed, chainId, level, index, sibling, node) : treeNode(seed, chainId, level, index, node, sibling);
  }
  return bytesToHex(node) === bytesToHex(root);
}

export const hex = (b: Uint8Array): Hex => bytesToHex(b);

/** Hash steps the verifier performs for a signature by leaf `leaf` on `message`. */
export function verifySteps(p: Params, seed: Uint8Array, chainId: bigint, leaf: number, message: Uint8Array): number {
  const mask = (1 << p.logW) - 1;
  return digits(p, messageDigest(p, seed, chainId, leaf, message)).reduce((s, d) => s + (mask - d), 0);
}

import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { hexToBytes, keccak256, toBytes } from "viem";
import { KeyTree, verify, lengths, type Params } from "../src/wots";

const vectors = ["profile_a_h10.json", "w4_h4.json", "w256_h2.json", "w2_h1.json"];

test("parameter table matches the reference", () => {
  expect([1, 2, 4, 8].map((logW) => lengths({ logW, height: 0 }).len)).toEqual([265, 133, 67, 34]);
});

for (const file of vectors) {
  test(`Python vectors verify and re-sign byte-for-byte: ${file}`, () => {
    const v = JSON.parse(readFileSync(`../reference/vectors/${file}`, "utf8"));
    const p: Params = { logW: v.logW, height: v.height };
    const seed = hexToBytes(v.seed);
    const root = hexToBytes(v.root);
    for (const s of v.signatures) {
      const sig = hexToBytes(s.signature);
      expect(verify(p, seed, root, BigInt(v.chainId), hexToBytes(s.message), sig)).toBe(true);
      const bad = sig.slice();
      bad[50] ^= 1;
      expect(verify(p, seed, root, BigInt(v.chainId), hexToBytes(s.message), bad)).toBe(false);
    }
    if (v.height <= 4) {
      const tree = new KeyTree(p, hexToBytes(v.skSeed), seed, BigInt(v.chainId));
      expect(tree.root).toEqual(root);
      for (const s of v.signatures) {
        expect(tree.signWithLeaf(s.leaf, hexToBytes(s.message))).toEqual(hexToBytes(s.signature));
      }
    }
  });
}

test("full height-10 tree matches the Python root", () => {
  const v = JSON.parse(readFileSync("../reference/vectors/profile_a_h10.json", "utf8"));
  const tree = new KeyTree({ logW: 4, height: 10 }, hexToBytes(v.skSeed), hexToBytes(v.seed), BigInt(v.chainId));
  expect(tree.root).toEqual(hexToBytes(v.root));
  const m = keccak256(toBytes("x"), "bytes");
  expect(verify(tree.p, tree.seed, tree.root, tree.chainId, m, tree.signWithLeaf(1023, m))).toBe(true);
}, 120_000);

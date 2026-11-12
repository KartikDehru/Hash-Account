import { expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keccak256, toBytes } from "viem";
import { XmssKey } from "../src/xmss";
import { Journal, LeafReuseError, Signer } from "../src/signer";

test("Profile B signer: right length, leaf prefix, and reuse refused", async () => {
  const key = XmssKey.keygen(3, join(mkdtempSync(join(tmpdir(), "lamport-")), "x.json"));
  const signer = new Signer(key, { isSpent: async (l) => l === 0, isPending: async () => false }, new Journal());
  expect(await signer.nextUnusedLeaf()).toBe(1);
  const m = keccak256(toBytes("pay"));
  const sig = await signer.signWithLeaf(1, m);
  expect(sig.length).toBe(4 + 32 * (68 + 3));
  expect(sig[3]).toBe(1);
  expect(signer.signWithLeaf(1, m)).rejects.toBeInstanceOf(LeafReuseError);
});

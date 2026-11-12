// Profile A account keys: one Winternitz key tree per epoch (key rotation registers the next tree).
// The account signature is seed || root || Lamport signature, so the account can check the tree
// against the commitment it stores for the epoch (contracts/account/LamportAccount.yul.in).
import { concat } from "viem";
import { KeyTree, signatureBytes, PROFILE_A } from "./wots";

export const ACCOUNT_SIG_BYTES = 64 + signatureBytes(PROFILE_A); // 2,532
export const LEAVES_PER_EPOCH = 1024;

export class AccountKey {
  constructor(readonly tree: KeyTree, readonly epoch = 0) {}

  get leaves(): number {
    return LEAVES_PER_EPOCH;
  }

  /** Raw signing. Does not check reuse: go through Signer, never call this directly outside tests. */
  signWithLeaf(leaf: number, message: Uint8Array): Uint8Array {
    return concat([this.tree.seed, this.tree.root, this.tree.signWithLeaf(leaf, message)]);
  }
}

/** Legacy nonce mode: nonce n is epoch n >> 10, leaf n & 1023. */
export const legacyNonce = (epoch: number, leaf: number): bigint => BigInt(epoch) * 1024n + BigInt(leaf);

// Reads which leaves are spent from chain state. No local counter.
// A leaf is spent when its EIP-8250 nonce key has a non-zero sequence in NONCE_MANAGER storage:
// slot = keccak256(pad32(sender) || be32(key)).
import { keccak256, concat, pad, toHex, type Hex } from "viem";
import { DEVNET_NONCE_MANAGER, LEAF_KEY_BASE, nonceKeyForLeaf } from "./frameTx";

export interface LeafState {
  isSpent(leaf: number): Promise<boolean>;
  isPending(leaf: number): Promise<boolean>;
}

export function nonceSlot(sender: Hex, key: bigint): Hex {
  return keccak256(concat([pad(sender, { size: 32 }), toHex(key, { size: 32 })]));
}

async function rpc(url: string, method: string, params: unknown[]): Promise<any> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

export class ChainLeafState implements LeafState {
  constructor(
    readonly rpcUrl: string,
    readonly sender: Hex,
    readonly bundlerUrl?: string,
    readonly nonceManager: Hex = DEVNET_NONCE_MANAGER,
    readonly keyBase: bigint = LEAF_KEY_BASE,
    readonly epoch = 0,
  ) {}

  async isSpent(leaf: number): Promise<boolean> {
    const value = await rpc(this.rpcUrl, "eth_getStorageAt", [this.nonceManager, nonceSlot(this.sender, nonceKeyForLeaf(leaf, this.keyBase, this.epoch)), "latest"]);
    return BigInt(value) !== 0n;
  }

  /** Best effort: asks the bundler's mempool dump for a pending transaction on this key. */
  async isPending(leaf: number): Promise<boolean> {
    if (!this.bundlerUrl) return false;
    const key = nonceKeyForLeaf(leaf, this.keyBase, this.epoch);
    const dump = await rpc(this.bundlerUrl, "debug_bundler_dumpMempool", []);
    const entries: any[] = Array.isArray(dump) ? dump : Object.values(dump ?? {}).flat();
    return entries.some((e: any) => {
      const tx = e?.transaction ?? e?.tx ?? e;
      return tx?.sender?.toLowerCase() === this.sender.toLowerCase() && (tx?.nonceKeys ?? []).some((k: string) => BigInt(k) === key);
    });
  }
}

/** Legacy nonce mode: nonce = epoch * 1024 + leaf, so every leaf below the current nonce is spent. */
export class LegacyLeafState implements LeafState {
  constructor(readonly rpcUrl: string, readonly sender: Hex, readonly bundlerUrl?: string, readonly epoch = 0) {}

  /** The only leaf this epoch may sign next (the current nonce), or an error if the nonce is in another epoch. */
  async currentLeaf(): Promise<number> {
    const n = await this.nonce();
    const leaf = n - this.epoch * 1024;
    if (leaf < 0 || leaf >= 1024) throw new Error(`account nonce ${n} is not in epoch ${this.epoch}: use the key of epoch ${Math.floor(n / 1024)}`);
    return leaf;
  }

  async nonce(): Promise<number> {
    return Number(BigInt(await rpc(this.rpcUrl, "eth_getTransactionCount", [this.sender, "latest"])));
  }

  async isSpent(leaf: number): Promise<boolean> {
    return this.epoch * 1024 + leaf < (await this.nonce());
  }

  async isPending(leaf: number): Promise<boolean> {
    if (!this.bundlerUrl) return false;
    const dump = await rpc(this.bundlerUrl, "debug_bundler_dumpMempool", []);
    const entries: any[] = Array.isArray(dump) ? dump : Object.values(dump ?? {}).flat();
    return entries.some((e: any) => {
      const tx = e?.transaction ?? e?.tx ?? e;
      const keys: string[] = tx?.nonceKeys ?? [];
      return tx?.sender?.toLowerCase() === this.sender.toLowerCase() && keys.every((k) => BigInt(k) === 0n) && BigInt(tx?.nonceSeq ?? -1) === BigInt(this.epoch * 1024 + leaf);
    });
  }
}

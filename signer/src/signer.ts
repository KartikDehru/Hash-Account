// Stateful signer: never signs twice with one leaf. Mirrors reference/lamport/signer.py.
// It keeps no counter: it reads spent and pending leaves from the network and keeps an
// append-only journal of leaves it has signed with (written before a signature is returned).
import { appendFileSync, existsSync, readFileSync, openSync, fsyncSync, closeSync } from "node:fs";
import { type Hex } from "viem";

/** Any set of one-time keys: Profile A's KeyTree or Profile B's XmssKey. */
export interface OneTimeKeys {
  readonly leaves: number;
  signWithLeaf(leaf: number, message: Uint8Array): Uint8Array;
}
import { type LeafState } from "./leafState";

export class LeafReuseError extends Error {}

export class Journal {
  private readonly leaves = new Set<number>();
  constructor(readonly path?: string) {
    if (path && existsSync(path)) {
      for (const line of readFileSync(path, "utf8").split("\n")) if (line.trim()) this.leaves.add(JSON.parse(line).leaf);
    }
  }
  has(leaf: number): boolean {
    return this.leaves.has(leaf);
  }
  record(leaf: number, message: Hex): void {
    if (this.path) {
      appendFileSync(this.path, JSON.stringify({ leaf, message }) + "\n");
      const fd = openSync(this.path, "r");
      fsyncSync(fd);
      closeSync(fd);
    }
    this.leaves.add(leaf);
  }
}

export class Signer {
  constructor(readonly tree: OneTimeKeys, readonly state: LeafState, readonly journal = new Journal()) {}

  async usable(leaf: number): Promise<boolean> {
    if (this.journal.has(leaf)) return false;
    if (await this.state.isSpent(leaf)) return false;
    return !(await this.state.isPending(leaf));
  }

  async nextUnusedLeaf(): Promise<number> {
    for (let leaf = 0; leaf < this.tree.leaves; leaf++) if (await this.usable(leaf)) return leaf;
    throw new LeafReuseError("all one-time keys are used; rotate to a new key tree");
  }

  async signWithLeaf(leaf: number, message: Hex): Promise<Uint8Array> {
    if (!(await this.usable(leaf))) throw new LeafReuseError(`leaf ${leaf} is already used or pending; refusing to sign`);
    this.journal.record(leaf, message);
    return this.tree.signWithLeaf(leaf, Buffer.from(message.slice(2), "hex"));
  }
}

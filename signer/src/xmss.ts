// Profile B one-time keys: XMSS-SHA2 (RFC 8391), signed by the vendored Skale Python reference
// through reference/xmss/cli.py. Test keys only.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { bytesToHex, hexToBytes, type Hex } from "viem";

const ROOT = join(import.meta.dir, "..", "..");

export class XmssKey {
  readonly height: number;
  readonly root: Hex;
  readonly seed: Hex;

  constructor(readonly path: string, readonly python = join(ROOT, ".venv/bin/python")) {
    const k = JSON.parse(readFileSync(path, "utf8"));
    this.height = k.height;
    this.root = k.root;
    this.seed = k.seed;
  }

  get leaves(): number {
    return 1 << this.height;
  }

  get signatureLength(): number {
    return 4 + 32 * (68 + this.height);
  }

  signWithLeaf(leaf: number, message: Uint8Array): Uint8Array {
    const r = Bun.spawnSync([this.python, join(ROOT, "reference/xmss/cli.py"), "sign", this.path, String(leaf), bytesToHex(message)]);
    if (r.exitCode !== 0) throw new Error(`xmss sign failed: ${r.stderr.toString()}`);
    return hexToBytes(r.stdout.toString().trim() as Hex);
  }

  static keygen(height: number, out: string, python = join(ROOT, ".venv/bin/python")): XmssKey {
    const r = Bun.spawnSync([python, join(ROOT, "reference/xmss/cli.py"), "keygen", String(height), out]);
    if (r.exitCode !== 0) throw new Error(`xmss keygen failed: ${r.stderr.toString()}`);
    return new XmssKey(out, python);
  }
}

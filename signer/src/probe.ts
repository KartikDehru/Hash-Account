// Local-chain experiments that the plain send command does not cover. LOCAL RESULTS ONLY.
//   bun run src/probe.ts control|banned|deploy|bigsig --rpc URL --bundler URL --local ../.local
// control: an account whose VERIFY code only calls APPROVE(3) (pipeline check)
// banned:  the same plus TIMESTAMP before APPROVE (banned in validation)
// deploy:  deploy + self_verify in one transaction (Lamport account created in the deploy frame)
// bigsig:  Profile A transaction plus an unused 30,000-byte ARBITRARY entry (does signature size
//          count toward MAX_VERIFY_GAS? OPEN_QUESTIONS Q1)
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { concat, getContractAddress, hexToBytes, keccak256, pad, toHex, type Hex } from "viem";
import { computeSigHash, lamportPayment, rawFrameTx, toRpc, MODE, SCHEME, type FrameTx } from "./frameTx";
import { chooseVerifyLimit, type GasModel } from "./gasLimit";
import { KeyTree, PROFILE_A, hex } from "./wots";
import { AccountKey, ACCOUNT_SIG_BYTES } from "./account";
import { ChainLeafState, LegacyLeafState } from "./leafState";
import { Journal, Signer } from "./signer";

const ROOT = join(import.meta.dir, "..", "..");
export const CONTROL = "0x000000000000000000000000000000000000c0de" as const;
export const BANNED = "0x000000000000000000000000000000000000b4d0" as const;
const ARACHNID = "0x4e59b44847b379578588920ca78fbf26c0b4956c" as const;

const arg = (n: string, d?: string) => {
  const i = process.argv.indexOf(`--${n}`);
  if (i >= 0) return process.argv[i + 1];
  if (d !== undefined) return d;
  throw new Error(`missing --${n}`);
};
const replacer = (_: string, v: unknown) => (typeof v === "bigint" ? toHex(v) : v);
async function rpc(url: string, method: string, params: unknown[]) {
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  return r.json();
}
const fees = { maxPriorityFeePerGas: 1_000_000_000n, maxFeePerGas: 50_000_000_000n, maxFeePerBlobGas: 0n };

function loadTree(path: string) {
  const k = JSON.parse(readFileSync(path, "utf8"));
  return new KeyTree(PROFILE_A, hexToBytes(k.skSeed), hexToBytes(k.seed), BigInt(k.chainId));
}

function bareTx(sender: Hex, key: bigint): FrameTx {
  return {
    chainId: 9n, nonceKeys: [key], nonceSeq: 0n, sender,
    frames: [
      { mode: MODE.VERIFY, flags: 3, target: null, limits: { execution: 50_000n, state: 0n }, value: 0n, data: "0x0100" },
      { mode: MODE.SENDER, flags: 0, target: "0x000000000000000000000000000000000000dEaD", limits: { execution: 30_000n, state: 0n }, value: 1n, data: "0x" },
    ],
    signatures: [], fees, blobVersionedHashes: [], recentRootReferences: [],
  };
}

async function run(name: string, tx: FrameTx, note: string) {
  const rpcUrl = arg("rpc", "http://127.0.0.1:8545");
  const bundler = arg("bundler", "http://127.0.0.1:14337/rpc/");
  const raw = rawFrameTx(tx, "devnet");
  const record = {
    experiment: name, note, scope: "LOCAL ethrex eip8141-tracer + local sidecar, not the public devnet",
    time: new Date().toISOString(), sigHash: computeSigHash(tx, "devnet"), tx: toRpc(tx),
    simulation: await rpc(rpcUrl, "ethrex_simulateFrameTransaction", [raw, "latest", { trace: false }]),
    estimate: await rpc(bundler, "eth_estimateFrameTransactionGas", [toRpc(tx)]),
    response: await rpc(bundler, "eth_sendFrameTransaction", [toRpc(tx)]),
  };
  const dir = join(ROOT, "results/local");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `probe-${name}.json`), JSON.stringify(record, replacer, 1) + "\n");
  console.log(JSON.stringify({ experiment: name, simulation: record.simulation, response: record.response }, replacer, 1));
}

async function main() {
  const which = process.argv[2];
  const local = arg("local", join(ROOT, ".local"));
  const model: GasModel = JSON.parse(readFileSync(join(ROOT, "results/verify_gas_model.json"), "utf8"));
  if (which === "calibrate") return calibrate(local, Number(arg("n", "48")), arg("mode", "keyed") === "legacy");
  if (which === "control-legacy") {
    const tx = bareTx(CONTROL, 0n);
    tx.nonceSeq = BigInt((await rpc(arg("rpc", "http://127.0.0.1:8545"), "eth_getTransactionCount", [CONTROL, "latest"])).result);
    return run("control-legacy", tx, "same control account with the legacy nonce (nonce_keys = [0]); compare with control to isolate the keyed-nonce cost");
  }
  if (which === "control") return run("control", bareTx(CONTROL, 1n), "VERIFY code is only APPROVE(3); expected: admitted");
  if (which === "banned") return run("banned", bareTx(BANNED, 1n), "VERIFY code runs TIMESTAMP then APPROVE(3); expected: refused (banned opcode)");
  if (which === "bigsig" || which === "deploy") {
    const keyFile = which === "bigsig" ? join(local, "key-a.json") : join(local, "key-c.json");
    const tree = loadTree(keyFile);
    let sender: Hex;
    let deployFrame: FrameTx["frames"][number] | undefined;
    if (which === "deploy") {
      const code = readFileSync(join(ROOT, "contracts/account/LamportAccount.initcode.hex"), "utf8").trim();
      const init = concat([`0x${code}`, hex(tree.seed), hex(tree.root), pad(toHex(tree.chainId), { size: 32 }), pad("0x00", { size: 32 })]);
      const salt = keccak256(concat([toHex("lamport-account"), hex(tree.root)]));
      sender = getContractAddress({ opcode: "CREATE2", from: ARACHNID, salt, bytecode: init });
      deployFrame = { mode: MODE.DEFAULT, flags: 0, target: ARACHNID, limits: { execution: BigInt(arg("deploy-gas", "400000")), state: BigInt(arg("deploy-state", "2000000")) }, value: 0n, data: concat([salt, init]) };
    } else {
      sender = JSON.parse(readFileSync(join(local, "accounts.json"), "utf8")).accountA;
    }
    const state = new ChainLeafState(arg("rpc", "http://127.0.0.1:8545"), sender);
    const signer = new Signer(new AccountKey(tree), state, new Journal(`${keyFile}.journal`));
    const leaf = await signer.nextUnusedLeaf();
    const tx = lamportPayment({ chainId: tree.chainId, sender, leaf, to: "0x000000000000000000000000000000000000dEaD", value: 1n,
      verifyGas: 60_000n, senderGas: 30_000n, fees, signatureLength: ACCOUNT_SIG_BYTES });
    if (deployFrame) tx.frames.unshift(deployFrame);
    if (which === "bigsig") tx.signatures.push({ scheme: SCHEME.ARBITRARY, signer: "0x", msg: "0x", signature: toHex(new Uint8Array(30_000).fill(0xab)) });
    // VERIFY frame index moves with a deploy frame; the limit model applies to whichever frame is VERIFY.
    const vi = tx.frames.findIndex((f) => f.mode === MODE.VERIFY);
    const tmp = { ...tx, frames: [tx.frames[vi], ...tx.frames.filter((_, i) => i !== vi)] };
    chooseVerifyLimit(tmp, model, PROFILE_A, tree.seed, tree.chainId, leaf);
    tx.frames[vi].limits.execution = tmp.frames[0].limits.execution;
    // Re-settle on the real frame order (the hash covers frame order).
    for (let round = 0; round < 8; round++) {
      const h = computeSigHash(tx, "devnet");
      const { verifySteps } = await import("./wots");
      const need = BigInt(Math.ceil(model.intercept + model.perStep * verifySteps(PROFILE_A, tree.seed, tree.chainId, leaf, hexToBytes(h)) + model.maxResidual)) + 2_000n;
      if (need <= tx.frames[vi].limits.execution) break;
      tx.frames[vi].limits.execution = need;
    }
    tx.signatures[0].signature = hex(await signer.signWithLeaf(leaf, computeSigHash(tx, "devnet")));
    return run(which, tx, which === "bigsig"
      ? "Profile A plus an unused 30,000-byte ARBITRARY entry; if signature bytes counted toward MAX_VERIFY_GAS (16 gas/byte = 480,000) it would be refused"
      : "deploy (CREATE2 via deterministic proxy) + self_verify in one transaction; the deploy frame limit counts toward MAX_VERIFY_GAS");
  }
  throw new Error("probe: control | banned | deploy | bigsig");
}

/** Real VERIFY gas on ethrex for Profile A: simulate n payments (each signed with a fresh leaf,
 * high limit, not sent to the sidecar) and record (hash steps, frame 0 gas used). */
async function calibrate(local: string, n: number, legacy: boolean) {
  const rpcUrl = arg("rpc", "http://127.0.0.1:8545");
  const keyFile = join(local, legacy ? "key-l.json" : "key-a.json");
  const tree = loadTree(keyFile);
  const keyedSender: Hex = JSON.parse(readFileSync(join(local, "accounts.json"), "utf8")).accountA;
  const journal = new Journal(`${keyFile}.journal`);
  const { verifySteps } = await import("./wots");
  const samples: { leaf: number; steps: number; gas: number }[] = [];
  for (let k = 0; k < n; k++) {
    // Legacy: copy k of the legacy account sits at 0xca1b0000 + k with nonce k + 101 (local genesis),
    // so its leaves never meet those of the main legacy account (which starts at nonce 1).
    const sender: Hex = legacy ? (`0x${(0xca1b0000 + k).toString(16).padStart(40, "0")}` as Hex) : keyedSender;
    const legacyState = legacy ? new LegacyLeafState(rpcUrl, sender) : undefined;
    const signer = new Signer(new AccountKey(tree), legacyState ?? new ChainLeafState(rpcUrl, sender), journal);
    const leaf = legacyState ? await legacyState.nonce() : await signer.nextUnusedLeaf();
    const tx = lamportPayment({ chainId: tree.chainId, sender, leaf, to: sender, value: 0n, verifyGas: 300_000n, senderGas: 30_000n,
      fees, signatureLength: ACCOUNT_SIG_BYTES, nonceMode: legacy ? "legacy" : "keyed" });
    const sigHash = computeSigHash(tx, "devnet");
    tx.signatures[0].signature = hex(await signer.signWithLeaf(leaf, sigHash));
    const sim = await rpc(rpcUrl, "ethrex_simulateFrameTransaction", [rawFrameTx(tx, "devnet"), "latest", { trace: false }]);
    const f0 = sim.result?.frames?.[0];
    if (!f0?.succeeded) throw new Error(`calibration sample ${k} failed: ${JSON.stringify(sim).slice(0, 300)}`);
    samples.push({ leaf, steps: verifySteps(PROFILE_A, tree.seed, tree.chainId, leaf, hexToBytes(sigHash)), gas: Number(BigInt(f0.gasUsed)) });
  }
  const dir = join(ROOT, "results/local");
  mkdirSync(dir, { recursive: true });
  const out = { scope: "LOCAL ethrex eip8141-tracer simulation (real EIP-8141 opcodes and keyed-nonce charges)", time: new Date().toISOString(),
    steps: samples.map((s) => s.steps), gas: samples.map((s) => s.gas), leaves: samples.map((s) => s.leaf) };
  writeFileSync(join(dir, `calibration_${legacy ? "legacy" : "keyed"}.json`), JSON.stringify({ nonceMode: legacy ? "legacy" : "keyed", ...out }, null, 1) + "\n");
  console.log(JSON.stringify({ samples: n, minGas: Math.min(...out.gas), maxGas: Math.max(...out.gas) }));
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});

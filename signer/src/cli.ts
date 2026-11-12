// HashAccount command line. Unaudited research code. TEST KEYS ONLY; never use with real funds.
//   bun run src/cli.ts keygen  --out keys/test-key.json [--chain-id 1337]
//   bun run src/cli.ts keygen  --profile b --out keys/xmss-key.json      (XMSS h = 10, Profile B)
//   add --profile b to address and send for the XMSS account (alt mempool: needs --allow-over-cap)
//   bun run src/cli.ts address --key keys/test-key.json
//   bun run src/cli.ts keygen  --epoch 1 --account 0xACCOUNT --out keys/epoch1.json [--nonce-mode ..]
//   bun run src/cli.ts rotate  --key keys/test-key.json --new-key keys/epoch1.json --rpc URL --bundler URL
//     (registers the new tree as the next epoch, signed with the current key; then send with the new key file)
//   bun run src/cli.ts send    --key keys/test-key.json --rpc URL --bundler URL --to 0x.. --value WEI
//                              [--verify-gas N] [--sender-gas 30000] [--dry-run] [--allow-over-cap]
// Without --verify-gas the VERIFY limit is set from results/verify_gas_model.json and the exact
// hash steps of this signature.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { concat, getContractAddress, hexToBytes, keccak256, pad, toHex, type Hex } from "viem";
import { computeSigHash, lamportPayment, rawFrameTx, rotationFrame, toRpc, XMSS_KEY_BASE, type Frame } from "./frameTx";
import { AccountKey, ACCOUNT_SIG_BYTES } from "./account";
import { XmssKey } from "./xmss";
import { ChainLeafState, LegacyLeafState } from "./leafState";
import { chooseVerifyLimit, fitsPublicCap, type GasModel } from "./gasLimit";
import { Journal, Signer } from "./signer";
import { KeyTree, PROFILE_A, signatureBytes, hex } from "./wots";

const ROOT = join(import.meta.dir, "..", "..");
const ARACHNID_CREATE2 = "0x4e59b44847b379578588920ca78fbf26c0b4956c" as const; // deterministic deployment proxy

function arg(name: string, fallback?: string): string {
  const i = process.argv.indexOf(`--${name}`);
  if (i >= 0 && process.argv[i + 1]) return process.argv[i + 1];
  if (fallback !== undefined) return fallback;
  throw new Error(`missing --${name}`);
}
const flag = (name: string) => process.argv.includes(`--${name}`);

interface KeyFile {
  warning: string; chainId: string; skSeed: Hex; seed: Hex; root?: Hex; nonceMode?: "keyed" | "legacy";
  epoch?: number; // key tree epoch (0 = the tree the account was created with)
  account?: Hex; // account address, required for epoch > 0 (the address derives from the epoch-0 tree)
}

function loadKey(path: string): { key: KeyFile; tree: KeyTree } {
  const key: KeyFile = JSON.parse(readFileSync(path, "utf8"));
  const tree = new KeyTree(PROFILE_A, hexToBytes(key.skSeed), hexToBytes(key.seed), BigInt(key.chainId));
  if (key.root && key.root !== hex(tree.root)) throw new Error("key file root does not match the rebuilt tree");
  return { key, tree };
}

function initcode(tree: KeyTree, mode: "keyed" | "legacy"): Hex {
  const code = readFileSync(join(ROOT, "contracts/account/LamportAccount.initcode.hex"), "utf8").trim();
  return concat([`0x${code.replace(/^0x/, "")}`, hex(tree.seed), hex(tree.root), pad(toHex(tree.chainId), { size: 32 }),
    pad(toHex(mode === "legacy" ? 1 : 0), { size: 32 })]);
}

function account(tree: KeyTree, mode: "keyed" | "legacy" = "keyed") {
  const salt = keccak256(concat([toHex("lamport-account"), hex(tree.root)]));
  const code = initcode(tree, mode);
  const address = getContractAddress({ opcode: "CREATE2", from: ARACHNID_CREATE2, salt, bytecode: code });
  return { address, deployTo: ARACHNID_CREATE2, deployData: concat([salt, code]) };
}

function create2(salt: Hex, code: Hex) {
  return { address: getContractAddress({ opcode: "CREATE2", from: ARACHNID_CREATE2, salt, bytecode: code }), deployTo: ARACHNID_CREATE2, deployData: concat([salt, code]) };
}

/** Profile B: the shared XMSS verifier contract and the account bound to one XMSS key. */
function accountB(key: XmssKey) {
  const artifact = JSON.parse(readFileSync(join(ROOT, "contracts/out/LamportXmssVerifier.sol/LamportXmssVerifier.json"), "utf8"));
  const verifier = create2(keccak256(toHex("lamport-xmss-verifier")), artifact.bytecode.object as Hex);
  const code = readFileSync(join(ROOT, "contracts/account/LamportXmssAccount.initcode.hex"), "utf8").trim();
  const init = concat([`0x${code.replace(/^0x/, "")}`, pad(verifier.address, { size: 32 }), key.root, key.seed]);
  return { verifier, ...create2(keccak256(concat([toHex("lamport-xmss-account"), key.root])), init) };
}

async function rpc(url: string, method: string, params: unknown[]): Promise<any> {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  return res.json();
}

const replacer = (_: string, v: unknown) => (typeof v === "bigint" ? toHex(v) : v);

async function main() {
  const cmd = process.argv[2];
  const profileB = arg("profile", "a").toLowerCase() === "b";
  if (cmd === "keygen" && profileB) {
    const out = arg("out", "keys/xmss-key.json");
    mkdirSync(dirname(out), { recursive: true });
    console.error("building the XMSS h=10 tree with the Python reference (about a minute)...");
    const key = XmssKey.keygen(10, out);
    console.log(JSON.stringify({ written: out, root: key.root, ...accountB(key) }, null, 1));
    return;
  }
  if (cmd === "keygen") {
    const out = arg("out", "keys/test-key.json");
    const chainId = arg("chain-id", "1337");
    const rnd = () => hex(crypto.getRandomValues(new Uint8Array(32)));
    const nonceMode = arg("nonce-mode", "keyed") === "legacy" ? "legacy" : "keyed";
    const epoch = Number(arg("epoch", "0"));
    const key: KeyFile = { warning: "TEST KEY ONLY. Never use with real funds.", chainId, skSeed: rnd(), seed: rnd(), nonceMode, epoch };
    if (epoch > 0) key.account = arg("account") as Hex;
    console.error("building the 1,024-leaf key tree (about 10 seconds)...");
    const tree = new KeyTree(PROFILE_A, hexToBytes(key.skSeed), hexToBytes(key.seed), BigInt(chainId));
    key.root = hex(tree.root);
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, JSON.stringify(key, null, 1) + "\n", { mode: 0o600 });
    const info = epoch > 0 ? { address: key.account, note: "register this tree with: cli rotate --new-key " + out } : account(tree, nonceMode);
    console.log(JSON.stringify({ written: out, root: key.root, nonceMode, epoch, ...info }, null, 1));
    return;
  }
  if (profileB) {
    const xkey = new XmssKey(arg("key"));
    const acctB = accountB(xkey);
    if (cmd === "address") {
      console.log(JSON.stringify(acctB, null, 1));
      return;
    }
    if (cmd === "send") return sendB(xkey, acctB.address);
  }
  const { key, tree } = loadKey(arg("key"));
  const mode = key.nonceMode ?? "keyed";
  const acct = account(tree, mode);
  if (key.epoch && key.epoch > 0) {
    if (!key.account) throw new Error("key files for epoch > 0 must name the account");
    acct.address = key.account;
  }
  if (cmd === "address") {
    console.log(JSON.stringify(acct, null, 1));
    return;
  }
  if (cmd === "send") return sendA(key, tree, acct.address, undefined, "send");
  if (cmd === "rotate") {
    const next = loadKey(arg("new-key"));
    if ((next.key.epoch ?? 0) !== (key.epoch ?? 0) + 1) throw new Error("the new key file must be for the next epoch");
    if ((next.key.nonceMode ?? "keyed") !== mode) throw new Error("the new key file must use the same nonce mode");
    return sendA(key, tree, acct.address, [rotationFrame(acct.address, hex(next.tree.seed), hex(next.tree.root))], "rotate");
  }
  throw new Error("commands: keygen, address, send, rotate");
}

/** Signs and submits a Profile A transaction: a payment, or extra frames (key rotation). */
async function sendA(key: KeyFile, tree: KeyTree, sender: Hex, frames: Frame[] | undefined, kind: string) {
  const mode = key.nonceMode ?? "keyed";
  const epoch = key.epoch ?? 0;
  const rpcUrl = arg("rpc");
  const bundler = arg("bundler");
  const legacyState = mode === "legacy" ? new LegacyLeafState(rpcUrl, sender, bundler, epoch) : undefined;
  const state = legacyState ?? new ChainLeafState(rpcUrl, sender, bundler, undefined, undefined, epoch);
  const signer = new Signer(new AccountKey(tree, epoch), state, new Journal(arg("journal", `${arg("key")}.journal`)));
  // Legacy mode: the only usable leaf is the current account nonce (signWithLeaf still checks it).
  const leaf = legacyState ? await legacyState.currentLeaf() : await signer.nextUnusedLeaf();
  if (leaf >= 1000 && kind === "send") console.error(`warning: leaf ${leaf} of 1,024 in epoch ${epoch}; rotate soon (cli rotate)`);
  const gasPrice = BigInt((await rpc(rpcUrl, "eth_gasPrice", [])).result ?? "0x3b9aca00");
  const tx = lamportPayment({
    chainId: tree.chainId, sender, leaf, to: frames ? sender : (arg("to") as Hex), value: frames ? 0n : BigInt(arg("value")),
    verifyGas: BigInt(arg("verify-gas", "60000")), senderGas: BigInt(arg("sender-gas", "30000")),
    fees: { maxPriorityFeePerGas: 1_000_000_000n, maxFeePerGas: gasPrice * 3n + 1_000_000_000n, maxFeePerBlobGas: 0n },
    signatureLength: ACCOUNT_SIG_BYTES, nonceMode: mode, epoch, frames,
  });
  const modelPath = join(ROOT, `results/verify_gas_model${mode === "legacy" ? "_legacy" : ""}.json`);
  let steps: number | undefined;
  if (!process.argv.includes("--verify-gas") && existsSync(modelPath)) {
    const model: GasModel = JSON.parse(readFileSync(modelPath, "utf8"));
    steps = chooseVerifyLimit(tx, model, PROFILE_A, tree.seed, tree.chainId, leaf).steps;
  }
  const verifyLimit = tx.frames[0].limits.execution;
  if (!fitsPublicCap(verifyLimit) && !flag("allow-over-cap")) {
    throw new Error(`VERIFY limit ${verifyLimit} is over the public cap; pass --allow-over-cap for the alt mempool`);
  }
  const sigHash = computeSigHash(tx, "devnet");
  const record: Record<string, unknown> = { time: new Date().toISOString(), profile: "A", kind, nonceMode: mode, epoch, rpc: rpcUrl, bundler, sender, leaf, sigHash, verifyLimit, steps };
  if (flag("dry-run")) {
    console.log(JSON.stringify({ ...record, note: "dry run: nothing signed or sent", tx: toRpc(tx) }, replacer, 1));
    return;
  }
  tx.signatures[0].signature = hex(await signer.signWithLeaf(leaf, sigHash));
  record.raw = rawFrameTx(tx, "devnet");
  // ethrex's own simulation: per-frame gas used and success, with the real EIP-8141 opcodes.
  record.simulation = await rpc(rpcUrl, "ethrex_simulateFrameTransaction", [record.raw, "latest", { trace: false }]);
  record.estimate = await rpc(bundler, "eth_estimateFrameTransactionGas", [toRpc(tx)]);
  record.response = await rpc(bundler, "eth_sendFrameTransaction", [toRpc(tx)]);
  const dir = join(ROOT, arg("results-dir", "results/devnet"));
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${kind}-${record.time}.json`.replace(/:/g, "-"));
  writeFileSync(file, JSON.stringify(record, replacer, 1) + "\n");
  console.log(JSON.stringify({ saved: file, simulation: record.simulation, estimate: record.estimate, response: record.response }, replacer, 1));

}

/** Profile B send: the VERIFY limit is a flag (XMSS gas does not depend on the message much). */
async function sendB(xkey: XmssKey, sender: Hex) {
  const rpcUrl = arg("rpc");
  const bundler = arg("bundler");
  const state = new ChainLeafState(rpcUrl, sender, bundler, undefined, XMSS_KEY_BASE);
  const signer = new Signer(xkey, state, new Journal(arg("journal", `${arg("key")}.journal`)));
  const leaf = await signer.nextUnusedLeaf();
  const gasPrice = BigInt((await rpc(rpcUrl, "eth_gasPrice", [])).result ?? "0x3b9aca00");
  const tx = lamportPayment({
    chainId: BigInt(arg("chain-id", "1337")), sender, leaf, to: arg("to") as Hex, value: BigInt(arg("value")),
    verifyGas: BigInt(arg("verify-gas", "900000")), senderGas: BigInt(arg("sender-gas", "30000")),
    fees: { maxPriorityFeePerGas: 1_000_000_000n, maxFeePerGas: gasPrice * 3n + 1_000_000_000n, maxFeePerBlobGas: 0n },
    signatureLength: xkey.signatureLength, keyBase: XMSS_KEY_BASE,
  });
  if (!fitsPublicCap(tx.frames[0].limits.execution) && !flag("allow-over-cap")) {
    throw new Error("Profile B is over the public cap by design; pass --allow-over-cap to send it to the alt mempool");
  }
  const sigHash = computeSigHash(tx, "devnet");
  const record: Record<string, unknown> = { time: new Date().toISOString(), profile: "B", rpc: rpcUrl, bundler, sender, leaf, sigHash };
  if (flag("dry-run")) {
    console.log(JSON.stringify({ ...record, note: "dry run: nothing signed or sent", tx: toRpc(tx) }, replacer, 1));
    return;
  }
  tx.signatures[0].signature = hex(await signer.signWithLeaf(leaf, sigHash));
  record.raw = rawFrameTx(tx, "devnet");
  record.simulation = await rpc(rpcUrl, "ethrex_simulateFrameTransaction", [record.raw, "latest", { trace: false }]);
  record.estimate = await rpc(bundler, "eth_estimateFrameTransactionGas", [toRpc(tx)]);
  record.response = await rpc(bundler, "eth_sendFrameTransaction", [toRpc(tx)]);
  const dir = join(ROOT, arg("results-dir", "results/devnet"));
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `send-b-${record.time}.json`.replace(/:/g, "-"));
  writeFileSync(file, JSON.stringify(record, replacer, 1) + "\n");
  console.log(JSON.stringify({ saved: file, simulation: record.simulation, estimate: record.estimate, response: record.response }, replacer, 1));
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});

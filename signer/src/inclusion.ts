// Inclusion experiment on the LOCAL chain (OPEN_QUESTIONS Q4): is a leaf spent once for real?
//   bun run src/inclusion.ts --local ../.local [--mode keyed|legacy]
// 1. sign a Profile A payment with the next unused leaf (read from chain) and submit it to the sidecar
// 2. ask the sidecar to relay it (debug_bundler_sendBundleNow) and build a block (scripts/local_blocks.py)
// 3. read the receipt and the leaf's chain state (NONCE_MANAGER slot, or the account nonce)
// 4. REUSE ATTEMPT: sign a different payment with the SAME leaf, bypassing the signer's refusal on
//    purpose (local test key only), and check that ethrex and the sidecar refuse it
//    and the same leaf at the next nonce sequence, which the account itself must refuse
// 5. the signer's next leaf now comes from chain state
// Writes results/local/inclusion-<mode>.json with every raw response.
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { hexToBytes, toHex, type Hex } from "viem";
import { decodeRawFrameTx, computeSigHash, lamportPayment, nonceKeyForLeaf, rawFrameTx, toRpc, DEVNET_NONCE_MANAGER, type NonceMode } from "./frameTx";
import { chooseVerifyLimit, type GasModel } from "./gasLimit";
import { ChainLeafState, LegacyLeafState, nonceSlot } from "./leafState";
import { Journal, Signer } from "./signer";
import { KeyTree, PROFILE_A, hex } from "./wots";
import { AccountKey, ACCOUNT_SIG_BYTES } from "./account";

const ROOT = join(import.meta.dir, "..", "..");
const RPC = "http://127.0.0.1:8545";
const BUNDLER = "http://127.0.0.1:14337/rpc/";
const arg = (n: string, d: string) => {
  const i = process.argv.indexOf(`--${n}`);
  return i >= 0 ? process.argv[i + 1] : d;
};
async function rpc(url: string, method: string, params: unknown[]) {
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  return r.json();
}
const replacer = (_: string, v: unknown) => (typeof v === "bigint" ? toHex(v) : v);
const fees = { maxPriorityFeePerGas: 1_000_000_000n, maxFeePerGas: 50_000_000_000n, maxFeePerBlobGas: 0n };
const RECIPIENT = "0x000000000000000000000000000000000000bEEF" as const;

function block(): unknown {
  const r = Bun.spawnSync([join(ROOT, ".venv/bin/python"), join(ROOT, "scripts/local_blocks.py"), "1"]);
  if (r.exitCode !== 0) throw new Error(r.stderr.toString());
  return JSON.parse(r.stdout.toString().trim());
}

/** Profile B straight to the node (no sidecar): needs ethrex started with a raised --mempool.max-verify-gas. */
async function xmss(local: string, viaSidecar = false) {
  const { XmssKey } = await import("./xmss");
  const { XMSS_KEY_BASE } = await import("./frameTx");
  const key = new XmssKey(join(local, "key-b.json"));
  const sender: Hex = JSON.parse(readFileSync(join(local, "accounts.json"), "utf8")).accountB;
  const signer = new Signer(key, new ChainLeafState(RPC, sender, undefined, DEVNET_NONCE_MANAGER, XMSS_KEY_BASE), new Journal(join(local, "key-b.json.journal")));
  const leaf = await signer.nextUnusedLeaf();
  const tx = lamportPayment({ chainId: 9n, sender, leaf, to: RECIPIENT, value: 1_000_000_000_000_000n, verifyGas: 900_000n, senderGas: 30_000n,
    fees, signatureLength: key.signatureLength, keyBase: XMSS_KEY_BASE });
  tx.signatures[0].signature = hex(await signer.signWithLeaf(leaf, computeSigHash(tx)));
  const raw = rawFrameTx(tx);
  const slot = nonceSlot(sender, nonceKeyForLeaf(leaf, XMSS_KEY_BASE));
  const log: Record<string, unknown> = {
    scope: "LOCAL ethrex with --mempool.max-verify-gas raised to 1,000,000, transaction sent to the node directly (no sidecar). Shows what a larger validation budget allows; NOT an alt-mempool admission.",
    leaf, sidecarNote: "the sidecar at fcb4885 refuses this transaction (100,000 cap), see send-b-*.json",
    slotBefore: (await rpc(RPC, "eth_getStorageAt", [DEVNET_NONCE_MANAGER, slot, "latest"])).result,
    simulation: await rpc(RPC, "ethrex_simulateFrameTransaction", [raw, "latest", { trace: false }]),
    nodeSubmit: viaSidecar ? undefined : await rpc(RPC, "eth_sendRawTransaction", [raw]),
  };
  if (viaSidecar) {
    log.scope = "LOCAL ethrex (--mempool.max-verify-gas 1,000,000) + PATCHED sidecar (SKANDHA_MAX_VERIFY_GAS=1,000,000, patches/sidecar-configurable-verify-budget.patch) configured with SKANDHA_PRECOMPILES = standard precompiles 0x01-0x11 and 0x100. Shows the proposed rule fix; NOT the unpatched sidecar and NOT the public devnet.";
    log.sidecarNote = "the unpatched sidecar refuses this transaction (100,000 cap), see send-b-*.json";
    log.sidecarSubmit = await rpc(BUNDLER, "eth_sendFrameTransaction", [toRpc(tx)]);
    log.relay = await rpc(BUNDLER, "debug_bundler_sendBundleNow", []);
    log.nodeSubmit = { result: (log.sidecarSubmit as any).result };
  }
  log.block = block();
  log.receipt = await rpc(RPC, "eth_getTransactionReceipt", [(log.nodeSubmit as any).result]);
  log.slotAfter = (await rpc(RPC, "eth_getStorageAt", [DEVNET_NONCE_MANAGER, slot, "latest"])).result;
  const name = viaSidecar ? "inclusion-xmss-patched-sidecar.json" : "inclusion-xmss-raised-node-budget.json";
  writeFileSync(join(ROOT, "results/local", name), JSON.stringify(log, replacer, 1) + "\n");
  console.log(JSON.stringify({ leaf, sidecarSubmit: log.sidecarSubmit, nodeSubmit: log.nodeSubmit, block: log.block, status: (log.receipt as any)?.result?.status,
    slotBefore: log.slotBefore, slotAfter: log.slotAfter, frames: (log.simulation as any)?.result?.frames }, replacer, 1));
}

async function main() {
  const local = arg("local", join(ROOT, ".local"));
  if (arg("mode", "keyed") === "xmss") return xmss(local);
  if (arg("mode", "keyed") === "xmss-sidecar") return xmss(local, true);
  const mode = (arg("mode", "keyed") === "legacy" ? "legacy" : "keyed") as NonceMode;
  const keyFile = join(local, mode === "legacy" ? "key-l.json" : "key-a.json");
  const k = JSON.parse(readFileSync(keyFile, "utf8"));
  const tree = new KeyTree(PROFILE_A, hexToBytes(k.skSeed), hexToBytes(k.seed), BigInt(k.chainId));
  const accounts = JSON.parse(readFileSync(join(local, "accounts.json"), "utf8"));
  const sender: Hex = mode === "legacy" ? accounts.accountALegacy : accounts.accountA;
  const legacyState = mode === "legacy" ? new LegacyLeafState(RPC, sender, BUNDLER) : undefined;
  const signer = new Signer(new AccountKey(tree), legacyState ?? new ChainLeafState(RPC, sender, BUNDLER), new Journal(`${keyFile}.journal`));
  const model: GasModel = JSON.parse(readFileSync(join(ROOT, `results/verify_gas_model${mode === "legacy" ? "_legacy" : ""}.json`), "utf8"));
  const leafState = async (leaf: number) =>
    mode === "legacy"
      ? { accountNonce: (await rpc(RPC, "eth_getTransactionCount", [sender, "latest"])).result }
      : { nonceManagerSlot: (await rpc(RPC, "eth_getStorageAt", [DEVNET_NONCE_MANAGER, nonceSlot(sender, nonceKeyForLeaf(leaf)), "latest"])).result };
  const build = (leaf: number, value: bigint) => {
    const tx = lamportPayment({ chainId: tree.chainId, sender, leaf, to: RECIPIENT, value, verifyGas: 60_000n, senderGas: 30_000n,
      fees, signatureLength: ACCOUNT_SIG_BYTES, nonceMode: mode });
    chooseVerifyLimit(tx, model, PROFILE_A, tree.seed, tree.chainId, leaf);
    return tx;
  };
  const log: Record<string, unknown> = { scope: "LOCAL ethrex eip8141-tracer + local sidecar + local block driver, not the public devnet", mode, sender };

  // 1. first payment. Legacy mode: if the current nonce's leaf was already signed (journal), the only
  // safe move is to rebroadcast that saved, already-signed transaction; never sign a new one.
  const leaf = legacyState ? await legacyState.nonce() : await signer.nextUnusedLeaf();
  let tx1;
  const saved = readdirSync(join(ROOT, "results/local")).filter((f) => f.startsWith("send-") && !f.startsWith("send-b"))
    .map((f) => JSON.parse(readFileSync(join(ROOT, "results/local", f), "utf8")))
    .find((r) => r.raw && r.leaf === leaf && String(r.sender).toLowerCase() === sender.toLowerCase());
  if (signer.journal.has(leaf) && saved) {
    tx1 = decodeRawFrameTx(saved.raw);
    log.rebroadcast = `leaf ${leaf} was already signed (journal); rebroadcasting the saved signed transaction`;
  } else {
    tx1 = build(leaf, 1_000_000_000_000_000n);
    tx1.signatures[0].signature = hex(await signer.signWithLeaf(leaf, computeSigHash(tx1)));
  }
  log.leaf = leaf;
  log.leafStateBefore = await leafState(leaf);
  log.recipientBalanceBefore = (await rpc(RPC, "eth_getBalance", [RECIPIENT, "latest"])).result;
  log.send1 = await rpc(BUNDLER, "eth_sendFrameTransaction", [toRpc(tx1)]);
  // 2. relay and include
  log.relay = await rpc(BUNDLER, "debug_bundler_sendBundleNow", []);
  log.block1 = block();
  const hash1 = (log.send1 as any).result;
  log.receiptSidecar = await rpc(BUNDLER, "eth_getFrameTransactionReceipt", [hash1]);
  log.receiptNode = await rpc(RPC, "eth_getTransactionReceipt", [hash1]);
  // 3. chain state after inclusion
  log.leafStateAfter = await leafState(leaf);
  log.recipientBalanceAfter = (await rpc(RPC, "eth_getBalance", [RECIPIENT, "latest"])).result;
  // 4. reuse attempt with the same leaf and a different message (deliberately bypassing the signer)
  const tx2 = build(leaf, 2_000_000_000_000_000n);
  tx2.signatures[0].signature = hex(new AccountKey(tree).signWithLeaf(leaf, hexToBytes(computeSigHash(tx2))));
  log.reuseSimulation = await rpc(RPC, "ethrex_simulateFrameTransaction", [rawFrameTx(tx2), "latest", { trace: false }]);
  log.reuseSidecar = await rpc(BUNDLER, "eth_sendFrameTransaction", [toRpc(tx2)]);
  // 4b. same leaf at the next sequence (keyed) / next nonce (legacy): valid nonce, but the account must refuse
  const tx3 = build(leaf, 3_000_000_000_000_000n);
  tx3.nonceSeq = tx3.nonceSeq + 1n;
  chooseVerifyLimit(tx3, model, PROFILE_A, tree.seed, tree.chainId, leaf);
  tx3.signatures[0].signature = hex(new AccountKey(tree).signWithLeaf(leaf, hexToBytes(computeSigHash(tx3))));
  log.reuseNextSeqSimulation = await rpc(RPC, "ethrex_simulateFrameTransaction", [rawFrameTx(tx3), "latest", { trace: false }]);
  log.reuseNextSeqSidecar = await rpc(BUNDLER, "eth_sendFrameTransaction", [toRpc(tx3)]);
  try {
    await signer.signWithLeaf(leaf, computeSigHash(tx2));
    log.reuseSigner = "ERROR: signer produced a second signature";
  } catch (e) {
    log.reuseSigner = `refused: ${(e as Error).message}`;
  }
  // 5. the next leaf comes from chain state
  log.nextLeaf = legacyState ? await legacyState.nonce() : await signer.nextUnusedLeaf();

  const dir = join(ROOT, "results/local");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `inclusion-${mode}.json`), JSON.stringify(log, replacer, 1) + "\n");
  const brief = {
    mode, leaf, rebroadcast: log.rebroadcast, send1: log.send1, block1: log.block1,
    receiptStatus: (log.receiptNode as any)?.result?.status ?? (log.receiptSidecar as any)?.result ?? log.receiptNode,
    leafStateBefore: log.leafStateBefore, leafStateAfter: log.leafStateAfter,
    recipient: [log.recipientBalanceBefore, log.recipientBalanceAfter],
    reuseSimulation: (log.reuseSimulation as any)?.error ?? (log.reuseSimulation as any)?.result?.executionError,
    reuseSidecar: (log.reuseSidecar as any)?.error?.message ?? (log.reuseSidecar as any)?.result,
    reuseNextSeqSimulation: (log.reuseNextSeqSimulation as any)?.error ?? (log.reuseNextSeqSimulation as any)?.result?.executionError,
    reuseNextSeqSidecar: (log.reuseNextSeqSidecar as any)?.error?.message ?? (log.reuseNextSeqSidecar as any)?.result,
    reuseSigner: log.reuseSigner, nextLeaf: log.nextLeaf,
  };
  console.log(JSON.stringify(brief, replacer, 1));
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});

#!/usr/bin/env python3
"""Frontier: which hash-based schemes fit the public mempool and which need the alt mempool.

Reads only generated measurements:
  results/gas.json               Lamport library per w (scripts/gas_report.py)
  results/account_bench_gas.json Lamport account VERIFY frame, w = 16 (LamportAccount.t.sol)
  results/xmss_gas_raw.json      Skale XMSS (XmssGas.t.sol)
  results/account_xmss_bench_gas.json  Profile B account VERIFY frame (LamportXmssAccount.t.sol)
and runs each row through simulator/admit.py. Writes results/frontier.{json,md,svg}.

The admission column uses the largest gas seen in the samples, not a proven worst case.
Only the w = 16 row is a full account VERIFY frame. Other rows are the verifier library call
alone; a frame adds context reads and APPROVE, but the hand-written Yul account is cheaper than
the Solidity library (w = 16: account frame max below library max), so no adjustment is applied.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results")
sys.path.insert(0, os.path.join(ROOT, "simulator"))
from admit import check, load_rules  # noqa: E402

SENDER = "0x000000000000000000000000000000000000a11c"


def load(name: str) -> dict:
    with open(os.path.join(RES, name)) as f:
        return json.load(f)


def admission(verify_limit: int, sig_bytes: int, rules: dict, alt_budget: int | None) -> dict:
    tx = {
        "name": "row", "sender": SENDER, "nonceKeys": [1],
        "frames": [
            {"mode": 1, "flags": 3, "target": "sender", "limits": {"execution": verify_limit, "state": 0},
             "trace": {"opcodes": [], "storageReads": [], "gasUsed": verify_limit}},
            {"mode": 2, "flags": 0, "target": SENDER, "limits": {"execution": 30000, "state": 0}},
        ],
        "signatures": [{"scheme": 0, "bytes": sig_bytes, "msgEmpty": True}],
    }
    rep = check(tx, rules, alt_budget)
    return {"public": rep.verdict(rep.public), "alt": rep.verdict(rep.alt),
            "reason": next((c.detail for c in rep.public if c.ok is False), "")}


def main() -> None:
    rules = load_rules()
    alt_budget = int(sys.argv[1]) if len(sys.argv) > 1 else None
    gas, bench, xmss = load("gas.json"), load("account_bench_gas.json"), load("xmss_gas_raw.json")
    lib = {r["w"]: r for r in gas["rows"]}
    lib16_max = int(lib[16]["measured"]["fullCall"]["max"])
    rows = []
    for w in (2, 4, 16, 256):
        r = lib[w]
        mean, mx = int(r["measured"]["fullCall"]["mean"]), int(r["measured"]["fullCall"]["max"])
        if w == 16:
            name, kind = "HashAccount, Winternitz w=16 (Profile A)", "measured (account VERIFY frame, bench build)"
            mean, mx = int(bench["mean"]), int(bench["max"])
            samples = int(bench["samples"])
        else:
            name, kind = f"HashAccount library, Winternitz w={w}", "measured library call only"
            samples = r["samples"]
        rows.append({"name": name, "basis": kind, "signatureBytes": r["signatureBytes"], "chains": r["chains"],
                     "meanGas": mean, "maxGas": mx, "samples": samples,
                     "dataGasStandard": r["arithmetic"]["signatureDataGasStandard"]})
    for h in ("h10", "h20"):
        x = xmss[h]
        mean, mx = int(x["mean"]), int(x["max"])
        sig = int(x["signatureBytes"])
        rows.append({"name": f"XMSS-SHA2 h={x['height']} (Skale, vendored)",
                     "basis": "measured library call only",
                     "signatureBytes": sig, "chains": 67, "meanGas": mean, "maxGas": mx, "samples": int(x["samples"]),
                     "dataGasStandard": rules["STANDARD_TOKEN_COST"] * rules["TOKENS_PER_NONZERO_BYTE"] * sig})
    xb = load("account_xmss_bench_gas.json")
    rows.append({"name": "HashAccount, XMSS h=10 (Profile B)",
                 "basis": "measured (account VERIFY frame incl. verifier call, bench build)",
                 "signatureBytes": int(xb["signatureBytes"]), "chains": 67, "meanGas": int(xb["mean"]),
                 "maxGas": int(xb["max"]), "samples": int(xb["samples"]),
                 "dataGasStandard": rules["STANDARD_TOKEN_COST"] * rules["TOKENS_PER_NONZERO_BYTE"] * int(xb["signatureBytes"])})
    # Real VERIFY frames on a LOCAL ethrex eip8141-tracer (simulation), when the local runs exist.
    import glob
    for mode in ("keyed", "legacy"):
        p = os.path.join(RES, "local", f"calibration_{mode}.json")
        if os.path.exists(p):
            g = json.load(open(p))["gas"]
            rows.append({"name": f"HashAccount, w=16, {mode} nonce (Profile A) on ethrex",
                         "basis": f"LOCAL ethrex simulation, real opcodes{' incl. 20,000 keyed-nonce charge' if mode == 'keyed' else ''}",
                         "signatureBytes": 2468, "chains": 67, "meanGas": sum(g) // len(g), "maxGas": max(g), "samples": len(g),
                         "dataGasStandard": rules["STANDARD_TOKEN_COST"] * rules["TOKENS_PER_NONZERO_BYTE"] * 2468})
    sends_b = sorted(glob.glob(os.path.join(RES, "local", "send-b-*.json")))
    if sends_b:
        sim = json.load(open(sends_b[-1]))["simulation"]["result"]
        gb = int(sim["frames"][0]["gasUsed"], 16)
        rows.append({"name": "HashAccount, XMSS h=10 (Profile B) on ethrex",
                     "basis": "LOCAL ethrex simulation, real opcodes incl. 20,000 keyed-nonce charge (1 sample)",
                     "signatureBytes": 2500, "chains": 67, "meanGas": gb, "maxGas": gb, "samples": 1,
                     "dataGasStandard": rules["STANDARD_TOKEN_COST"] * rules["TOKENS_PER_NONZERO_BYTE"] * 2500})
    for row in rows:
        row["admission"] = admission(row["maxGas"], row["signatureBytes"], rules, alt_budget)

    out = {"source": "scripts/frontier.py", "library16Max": lib16_max, "altBudget": alt_budget, "rows": rows}
    with open(os.path.join(RES, "frontier.json"), "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")

    md = ["# Frontier (generated by scripts/frontier.py; do not edit)", "",
          f"VERIFY limit = largest gas seen in the samples. Public rule: declared VERIFY limit + 100 (ARBITRARY) <= {rules['MAX_VERIFY_GAS']:,}. "
          f"Alt-mempool budget: {alt_budget if alt_budget is not None else 'unknown (no devnet value yet)'}.",
          f"Rows named 'HashAccount' are full account VERIFY frames. Other rows are the verifier call alone (no frame adjustment; "
          f"for comparison the w=16 library call max is {lib16_max:,} and the w=16 account frame max is {int(bench['max']):,}).", "",
          "| scheme | signature bytes | VERIFY gas mean | VERIFY gas max | basis | signature data gas (16/byte) | public mempool | alt mempool |",
          "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        a = r["admission"]
        md.append(f"| {r['name']} | {r['signatureBytes']:,} | {r['meanGas']:,} | {r['maxGas']:,} | {r['basis']} | "
                  f"{r['dataGasStandard']:,} | {a['public']} | {a['alt']} |")
    with open(os.path.join(RES, "frontier.md"), "w") as f:
        f.write("\n".join(md) + "\n")
    with open(os.path.join(RES, "frontier.svg"), "w") as f:
        f.write(svg(rows, rules["MAX_VERIFY_GAS"]))
    readme = os.path.join(ROOT, "README.md")
    with open(readme) as f:
        text = f.read()
    start, end = "<!-- results:start -->", "<!-- results:end -->"
    if start in text and end in text:
        with open(os.path.join(RES, "account_bench_gas.json")) as f:
            b = json.load(f)
        block = "\n".join([
            start,
            f"Profile A account VERIFY frame (w=16, h=10): mean {int(b['mean']):,} gas, {int(b['min']):,} to {int(b['max']):,} over "
            f"{int(b['samples'])} random keys and messages (bench build, results/account_bench_gas.json). Signature {rows[2]['signatureBytes']:,} bytes.",
            "",
            *md[2:],
            "",
            "Per-phase gas: [results/gas.md](results/gas.md). Differential test: [results/differential_10000.txt](results/differential_10000.txt).",
            end,
        ])
        text = text[: text.index(start)] + block + text[text.index(end) + len(end):]
        with open(readme, "w") as f:
            f.write(text)
    print("\n".join(md))


def svg(rows: list[dict], cap: int) -> str:
    """Horizontal bars of the largest VERIFY gas seen, with the public cap as a reference line."""
    W, left, right, top, bar, gap = 760, 300, 90, 84, 22, 14
    H = top + len(rows) * (bar + gap) + 40
    vmax = max(r["maxGas"] for r in rows) * 1.05
    x = lambda v: left + (W - left - right) * v / vmax  # noqa: E731
    ink, ink2, surface, fill = "#0b0b0b", "#52514e", "#fcfcfb", "#2a78d6"
    p = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" font-family="system-ui, sans-serif" font-size="12">',
         f'<title>VERIFY gas per scheme against the 100,000 public-mempool cap</title>',
         f'<rect width="{W}" height="{H}" fill="{surface}"/>',
         f'<text x="16" y="24" font-size="15" fill="{ink}" font-weight="600">Gas to verify one signature (largest seen in the samples)</text>',
         f'<text x="16" y="42" fill="{ink2}">All bars measured; account rows are full VERIFY frames. Generated by scripts/frontier.py.</text>']
    for t in range(0, int(vmax) + 1, 100000):
        p.append(f'<line x1="{x(t):.1f}" x2="{x(t):.1f}" y1="{top - 6}" y2="{H - 30}" stroke="#e4e3df" stroke-width="1"/>')
        p.append(f'<text x="{x(t):.1f}" y="{H - 14}" fill="{ink2}" text-anchor="middle">{t // 1000}k</text>')
    for i, r in enumerate(rows):
        y = top + i * (bar + gap)
        w = x(r["maxGas"]) - left
        label = r["name"].split(" (")[0] + (" (ethrex)" if r["name"].endswith("on ethrex") else " (bench)" if "bench build" in r["basis"] else "")
        label = label.replace("HashAccount, w=16, ", "HashAccount w=16, ")
        p.append(f'<text x="{left - 8}" y="{y + bar / 2 + 4}" fill="{ink}" text-anchor="end">{label}</text>')
        p.append(f'<rect x="{left}" y="{y}" width="{w:.1f}" height="{bar}" rx="4" fill="{fill}"><title>{r["name"]}: max {r["maxGas"]:,}, mean {r["meanGas"]:,} gas</title></rect>')
        verdict = "fits public" if r["admission"]["public"] == "ACCEPTED" else "over cap"
        lx = max(left + w, x(cap) + 2) + 6
        p.append(f'<text x="{lx:.1f}" y="{y + bar / 2 + 4}" fill="{ink2}">{r["maxGas"] // 1000}k, {verdict}</text>')
    p.append(f'<line x1="{x(cap):.1f}" x2="{x(cap):.1f}" y1="{top - 10}" y2="{H - 30}" stroke="{ink}" stroke-width="2" stroke-dasharray="5 4"/>')
    p.append(f'<text x="{x(cap) + 4:.1f}" y="{top - 14}" fill="{ink}">public mempool cap {cap // 1000}k</text>')
    p.append("</svg>\n")
    return "\n".join(p)


if __name__ == "__main__":
    main()

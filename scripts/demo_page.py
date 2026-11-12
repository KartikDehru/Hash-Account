#!/usr/bin/env python3
"""Build results/demo.html: one self-contained page for the demo, from the result files only.

Reads results/frontier.json, results/local/*.json, results/attack.json and
results/differential_10000.txt. Every number on the page comes from those files.
"""
import glob
import html
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results")
LOC = os.path.join(RES, "local")


def load(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def esc(x) -> str:
    return html.escape(str(x))


def bar_chart(rows, cap):
    """Horizontal bars of the largest VERIFY gas seen, cap as a reference line (single series)."""
    W, left, right, top, bar, gap = 760, 270, 120, 30, 20, 10
    H = top + len(rows) * (bar + gap) + 34
    vmax = max(r["maxGas"] for r in rows) * 1.05
    x = lambda v: left + (W - left - right) * v / vmax  # noqa: E731
    out = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="VERIFY gas per scheme against the public cap">']
    for t in range(0, int(vmax) + 1, 100000):
        out.append(f'<line class="grid" x1="{x(t):.1f}" x2="{x(t):.1f}" y1="{top - 4}" y2="{H - 28}"/>')
        out.append(f'<text class="muted" x="{x(t):.1f}" y="{H - 12}" text-anchor="middle">{t // 1000}k</text>')
    for i, r in enumerate(rows):
        y = top + i * (bar + gap)
        w = x(r["maxGas"]) - left
        name = r["name"].replace("Lamport account, ", "Lamport ").replace(" (Skale, vendored)", " (Skale lib)")
        name = name.replace(" (Profile A) on ethrex", ", ethrex").replace(" (Profile B) on ethrex", ", ethrex")
        name = name.replace(" (Profile A)", ", bench").replace(" (Profile B)", ", bench").replace("Lamport library, ", "Lib ")
        verdict = "fits public cap" if r["admission"]["public"] == "ACCEPTED" else "over public cap"
        out.append(f'<text class="ink" x="{left - 8}" y="{y + bar / 2 + 4}" text-anchor="end">{esc(name)}</text>')
        out.append(f'<rect class="bar" x="{left}" y="{y}" width="{w:.1f}" height="{bar}" rx="4">'
                   f'<title>{esc(r["name"])}: max {r["maxGas"]:,}, mean {r["meanGas"]:,} gas ({esc(r["basis"])})</title></rect>')
        lx = max(left + w, x(cap) + 2) + 6
        out.append(f'<text class="muted" x="{lx:.1f}" y="{y + bar / 2 + 4}">{r["maxGas"] // 1000}k, {verdict}</text>')
    out.append(f'<line class="cap" x1="{x(cap):.1f}" x2="{x(cap):.1f}" y1="{top - 10}" y2="{H - 28}"/>')
    out.append(f'<text class="ink" x="{x(cap) + 4:.1f}" y="{top - 14}">public cap {cap // 1000}k</text>')
    out.append("</svg>")
    return "\n".join(out)


def rotation_html(rot) -> str:
    if not rot:
        return ""
    ro, pay = rot["rotation"], rot["paymentEpoch1"]
    return (f"<h2>Key rotation (LOCAL)</h2><p>When a tree of 1,024 keys runs low, one transaction signed by the current tree registers the next one. "
            f"On the local chain the rotation was included in block {ro['block']['number']} (status {esc(ro['receiptStatus'])}), the account "
            f"stored the new tree's commitment ({'matches' if ro['slot1Matches'] else 'MISMATCH'}), and a payment signed with the new tree was included "
            f"in block {pay['block']['number']} (status {esc(pay['receiptStatus'])}, VERIFY {pay['verifyGas']:,} gas). A key tree that was never registered is refused.</p>")


def main() -> None:
    fr = load(os.path.join(RES, "frontier.json"))
    rules = {k: v["value"] for k, v in load(os.path.join(ROOT, "simulator", "rules.json")).items() if not k.startswith("_")}
    cal = {m: load(os.path.join(LOC, f"calibration_{m}.json")) for m in ("keyed", "legacy")}
    inc = {m: load(os.path.join(LOC, f"inclusion-{m}.json")) for m in ("keyed", "legacy")}
    patched = load(os.path.join(LOC, "inclusion-xmss-patched-sidecar.json"))
    deploy = load(os.path.join(LOC, "deploy_state.json"))
    rot = load(os.path.join(LOC, "rotation", "summary.json"))
    attack = load(os.path.join(RES, "attack.json"))
    diff_txt = open(os.path.join(RES, "differential_10000.txt")).read() if os.path.exists(os.path.join(RES, "differential_10000.txt")) else ""
    runs = re.search(r"runs: (\d+)", diff_txt)
    diff_cases = int(runs.group(1)) * 100 if runs and "PASS" in diff_txt else None
    sends_b = sorted(glob.glob(os.path.join(LOC, "send-b-*.json")))
    b_refusal = (load(sends_b[-1])["response"].get("error") or {}).get("message") if sends_b else None

    tiles = []
    if cal["legacy"]:
        g = cal["legacy"]["gas"]
        tiles.append(("Profile A VERIFY, legacy nonce", f"{max(g):,}", f"largest of {len(g)} real ethrex runs (mean {sum(g) // len(g):,})"))
    if cal["keyed"]:
        g = cal["keyed"]["gas"]
        tiles.append(("Profile A VERIFY, keyed nonce", f"{max(g):,}", f"largest of {len(g)} runs; includes the 20,000-gas key charge"))
    if patched:
        g = int(patched["simulation"]["result"]["frames"][0]["gasUsed"], 16)
        tiles.append(("Profile B (XMSS) VERIFY", f"{g:,}", "included through the patched sidecar (LOCAL)"))
    if diff_cases:
        tiles.append(("Python vs Solidity cases", f"{diff_cases:,}", "random valid and mutated signatures, all agree"))

    inc_rows = []
    for m in ("keyed", "legacy"):
        d = inc[m]
        if not d:
            continue
        st = (d.get("receiptNode") or {}).get("result") or {}
        msg = lambda r: (r.get("error") or {}).get("message") or ((r.get("result") or {}).get("executionError")) or "-"  # noqa: E731
        inc_rows.append(f"<tr><td>Profile A, {m} nonce</td><td>leaf {d['leaf']}</td><td>block {d['block1']['number']}, status {esc(st.get('status'))}</td>"
                        f"<td>{esc(msg(d['reuseSidecar']))}</td><td>{esc(d['reuseSigner'])}</td><td>{d['nextLeaf']}</td></tr>")

    attack_line = ""
    if attack:
        a1, a2 = attack["oneSignaturePerKey"], attack["twoSignaturesOnOneKey"]
        attack_line = (f"With toy 16-bit digits, a stand-in attacker forged {a2['forged']} of {a2['trials']} keys that signed twice "
                       f"(median {a2['medianTries']} attempts), against {a1['forged']} of {a1['trials']} keys that signed once "
                       f"(median {a1['medianTries']:,} attempts).")

    tiles_html = "".join(f'<div class="tile"><div class="label">{esc(a)}</div><div class="num">{esc(b)}</div><div class="muted small">{esc(c)}</div></div>' for a, b, c in tiles)
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>HashAccount demo</title>
<style>
:root {{ --surface:#fcfcfb; --card:#f4f3f0; --ink:#0b0b0b; --ink2:#52514e; --grid:#e4e3df; --bar:#2a78d6; }}
@media (prefers-color-scheme: dark) {{ :root {{ --surface:#1a1a19; --card:#242422; --ink:#f0efec; --ink2:#c3c2b7; --grid:#383835; --bar:#3987e5; }} }}
* {{ box-sizing:border-box; }}
body {{ background:var(--surface); color:var(--ink); font:15px/1.55 system-ui, sans-serif; margin:0 auto; max-width:860px; padding:28px 16px 48px; }}
h1 {{ font-size:26px; margin:0 0 6px; }} h2 {{ font-size:18px; margin:32px 0 8px; }}
.muted {{ color:var(--ink2); fill:var(--ink2); }} .small {{ font-size:12px; }} .ink {{ fill:var(--ink); font-size:12px; }}
svg text.muted {{ font-size:12px; }}
.tiles {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:10px; margin:18px 0; }}
.tile {{ background:var(--card); border-radius:8px; padding:12px 14px; }} .tile .label {{ font-size:13px; color:var(--ink2); }}
.tile .num {{ font-size:26px; font-weight:600; margin:2px 0; font-variant-numeric:tabular-nums; }}
svg {{ width:100%; height:auto; }} .grid {{ stroke:var(--grid); stroke-width:1; }} .bar {{ fill:var(--bar); }} .bar:hover {{ opacity:.8; }}
.cap {{ stroke:var(--ink); stroke-width:2; stroke-dasharray:5 4; }}
.table-wrap {{ overflow-x:auto; }} table {{ border-collapse:collapse; width:100%; font-size:14px; }}
td, th {{ border-bottom:1px solid var(--grid); padding:6px 8px; text-align:left; vertical-align:top; }}
.note {{ background:var(--card); border-radius:8px; padding:10px 14px; font-size:14px; }}
</style></head><body>
<h1>HashAccount: an Ethereum account with no ECDSA key</h1>
<p class="muted">Hash-based one-time signatures (Winternitz, in a Merkle tree of 1,024 keys), verified in an EIP-8141 frame transaction. Each key is spent through the transaction nonce. Hash-based, believed to resist known quantum attacks. Unaudited research code.</p>
<div class="note">Results marked LOCAL come from our own ethrex <code>eip8141-tracer</code> node, sidecar and block driver, not the public devnet. Public-devnet results: pending. Generated by <code>scripts/demo_page.py</code> from <code>results/</code>.</div>
<div class="tiles">{tiles_html}</div>

<h2>Which schemes fit the public mempool?</h2>
<p class="muted">Largest VERIFY gas seen per scheme; the public mempool allows {rules['MAX_VERIFY_GAS']:,}. Hover a bar for mean and basis.</p>
{bar_chart(fr['rows'], rules['MAX_VERIFY_GAS'])}

<h2>A spent key cannot be used again (LOCAL, included in blocks)</h2>
<div class="table-wrap"><table><tr><th>Payment</th><th>Key</th><th>Included</th><th>Same key again, at the node and sidecar</th><th>Signer</th><th>Next key from chain</th></tr>
{''.join(inc_rows)}</table></div>

{rotation_html(rot)}
<h2>Heavy signatures and the alternative mempool</h2>
<p>Profile B (XMSS) needs far more than {rules['MAX_VERIFY_GAS']:,} gas. The sidecar we ran refuses it: <span class="muted">{esc(b_refusal or 'n/a')}</span>.
With our proposed fix (a configurable budget and the standard precompiles allowed), the sidecar accepted it, relayed it, and it was included
{f"in block {patched['block']['number']} with status {esc(((patched.get('receipt') or {}).get('result') or {}).get('status'))}" if patched else ''}.
See <code>docs/RULE_FINDINGS.md</code>.</p>
{f"<p>Deploying the account inside the same transaction needs about {deploy['deployStateGasSucceeds']:,} state gas; the public cap is {deploy['publicMaxVerifyStateGas']:,}, so the account is deployed first.</p>" if deploy else ''}

<h2>Why reuse matters</h2>
<p>{esc(attack_line)} Full view: <code>results/attack.html</code>.</p>
</body></html>
"""
    with open(os.path.join(RES, "demo.html"), "w") as f:
        f.write(page)
    print("wrote results/demo.html")


if __name__ == "__main__":
    main()

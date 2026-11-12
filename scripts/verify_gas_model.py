#!/usr/bin/env python3
"""Fit the Profile A VERIFY frame gas as a + b * steps.

Preferred input: real ethrex simulations, results/local/calibration_{keyed,legacy}.json (written by
`signer/src/probe.ts calibrate`; they include the EIP-8250 keyed-nonce charge the bench build
cannot see). Fallback: results/account_bench_gas.json (bench build). Outputs
results/verify_gas_model.json (keyed nonce mode) and results/verify_gas_model_legacy.json, which
the signer uses to set the VERIFY frame's execution limit for each signature.
"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results")


def fit(source: str, xs: list[int], ys: list[int], out_name: str, mode: str) -> None:
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    a = my - b * mx
    residuals = [y - (a + b * x) for x, y in zip(xs, ys)]
    model = {
        "source": f"scripts/verify_gas_model.py from {source}",
        "nonceMode": mode,
        "samples": n,
        "intercept": round(a, 1),
        "perStep": round(b, 3),
        "maxResidual": round(max(residuals), 1),
        "minResidual": round(min(residuals), 1),
        "stepsRange": [min(xs), max(xs)],
        "worstCaseSteps": 990,
        "worstCaseGasPredicted": round(a + b * 990 + max(residuals)),
        "note": "The signer adds the max residual and a 2,000-gas margin.",
    }
    with open(os.path.join(RES, out_name), "w") as f:
        json.dump(model, f, indent=1)
        f.write("\n")
    print(out_name, json.dumps({k: model[k] for k in ("source", "intercept", "perStep", "maxResidual", "worstCaseGasPredicted")}))


def main() -> None:
    with open(os.path.join(RES, "account_bench_gas.json")) as f:
        bench = json.load(f)
    fit("results/account_bench_gas.json (bench build, no keyed-nonce charge)",
        [int(v) for v in bench["steps"]], [int(v) for v in bench["gas"]], "verify_gas_model_bench.json", "bench")
    for mode, out_name in (("keyed", "verify_gas_model.json"), ("legacy", "verify_gas_model_legacy.json")):
        path = os.path.join(RES, "local", f"calibration_{mode}.json")
        if os.path.exists(path):
            with open(path) as f:
                cal = json.load(f)
            fit(f"results/local/calibration_{mode}.json (LOCAL ethrex simulation)", cal["steps"], cal["gas"], out_name, mode)
        else:
            print(f"no {path}; {out_name} not refreshed")


if __name__ == "__main__":
    main()

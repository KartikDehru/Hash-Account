#!/usr/bin/env python3
"""Minimal block driver for the local ethrex (Hegota): stands in for a consensus client.

ethrex's own dev block producer cannot drive Hegota at 9aa3645, so this script calls the
Engine API directly: forkchoiceUpdatedV5 (with payload attributes) -> getPayloadV6 ->
newPayloadV6 -> forkchoiceUpdatedV5. LOCAL test chain only.

Usage: local_blocks.py <count> [--jwt .local/jwt.hex] [--engine http://127.0.0.1:8551]
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def jwt(secret_hex: str) -> str:
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps({"iat": int(time.time())}).encode())
    sig = hmac.new(bytes.fromhex(secret_hex.strip().removeprefix("0x")), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64(sig)}"


def call(url: str, method: str, params: list, token: str | None = None):
    req = urllib.request.Request(url, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
                                 headers={"content-type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
    out = json.load(urllib.request.urlopen(req))
    if "error" in out:
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


def produce(engine: str, rpc: str, secret: str) -> dict:
    head = call(rpc, "eth_getBlockByNumber", ["latest", False])
    zero = "0x" + "00" * 32
    ts = max(int(time.time()), int(head["timestamp"], 16) + 1)
    state = {"headBlockHash": head["hash"], "safeBlockHash": head["hash"], "finalizedBlockHash": head["hash"]}
    attrs = {"timestamp": hex(ts), "prevRandao": zero, "suggestedFeeRecipient": "0x" + "00" * 20, "withdrawals": [],
             "parentBeaconBlockRoot": zero, "slotNumber": hex(int(head.get("slotNumber", "0x0"), 16) + 1),
             "inclusionListTransactions": [], "targetGasLimit": head["gasLimit"]}
    fcu = call(engine, "engine_forkchoiceUpdatedV5", [state, attrs], jwt(secret))
    pid = fcu["payloadId"]
    time.sleep(0.5)
    built = call(engine, "engine_getPayloadV6", [pid], jwt(secret))
    payload = built["executionPayload"]
    status = call(engine, "engine_newPayloadV6", [payload, [], zero, built.get("executionRequests", []), []], jwt(secret))
    if status.get("status") != "VALID":
        raise RuntimeError(f"newPayloadV6: {status}")
    new = {"headBlockHash": payload["blockHash"], "safeBlockHash": payload["blockHash"], "finalizedBlockHash": payload["blockHash"]}
    call(engine, "engine_forkchoiceUpdatedV5", [new, None], jwt(secret))
    return {"number": int(payload["blockNumber"], 16), "hash": payload["blockHash"], "transactions": len(payload["transactions"])}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("count", type=int)
    ap.add_argument("--jwt", default=os.path.join(ROOT, ".local", "jwt.hex"))
    ap.add_argument("--engine", default="http://127.0.0.1:8551")
    ap.add_argument("--rpc", default="http://127.0.0.1:8545")
    args = ap.parse_args()
    secret = open(args.jwt).read()
    for _ in range(args.count):
        print(json.dumps(produce(args.engine, args.rpc, secret)))


if __name__ == "__main__":
    main()

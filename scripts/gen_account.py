#!/usr/bin/env python3
"""Generate the real, test and bench builds of each Lamport account from one template.

Templates: contracts/account/LamportAccount.yul.in (Profile A) and LamportXmssAccount.yul.in
(Profile B). The builds differ only in the four context functions below. Run after editing a
template; `--check` fails if the outputs are stale.
Both builds are compiled here with solc (same settings) into *.initcode.hex next to the Yul
files; Foundry tests load the test build's init code. Constructor arguments (seed, root,
chainId) are appended at deploy time.
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACCOUNT_DIR = os.path.join(ROOT, "contracts", "account")
TEMPLATES = ["LamportAccount", "LamportXmssAccount"]
SUFFIX = {"real": "", "mock": "Mock", "bench": "Bench"}
OUTPUTS = {
    os.path.join(ACCOUNT_DIR, f"{name}{SUFFIX[kind]}.yul"): (name, kind)
    for name in TEMPLATES for kind in SUFFIX
}

REAL = """// EIP-8141 opcodes: TXPARAM 0xb0, SIGPARAM 0xb4, SIGDATACOPY 0xb5, APPROVE 0xaa.
            function txparam(p) -> v { v := verbatim_1i_1o(hex"b0", p) }
            function sigparam(i, p) -> v { v := verbatim_2i_1o(hex"b4", i, p) }
            function sigdatacopy(mem, off, len, i) { verbatim_4i_0o(hex"b5", mem, off, len, i) }
            function approve(scope) { verbatim_3i_0o(hex"aa", 0, 0, scope) }"""

MOCK = """// TEST BUILD ONLY: frame context read from a mock contract at 0x...8141c0 (FrameContextMock).
            // APPROVE is replaced by returning the word 0xaa00..00||scope.
            function ctx() -> a { a := 0x00000000000000000000000000000000008141c0 }
            function ctxcall(sel, x, y) -> ok {
                let fp := mload(0x40) // the call input uses 0x00..0x5f; keep the free memory pointer
                mstore(0, sel)
                mstore(32, x)
                mstore(64, y)
                ok := staticcall(gas(), ctx(), 0, 96, 0, 0)
                mstore(0x40, fp)
                if iszero(ok) { revert(0, 0) }
            }
            function txparam(p) -> v {
                pop(ctxcall(1, p, 0))
                returndatacopy(0, 0, 32)
                v := mload(0)
            }
            function sigparam(i, p) -> v {
                pop(ctxcall(2, i, p))
                returndatacopy(0, 0, 32)
                v := mload(0)
            }
            function sigdatacopy(mem, off, len, i) {
                pop(ctxcall(3, i, 0))
                if gt(add(off, len), returndatasize()) { revert(0, 0) }
                returndatacopy(mem, off, len)
            }
            function approve(scope) {
                mstore(0, or(shl(248, 0xaa), scope))
                return(0, 32)
            }"""


BENCH = """// GAS BENCH BUILD ONLY: the frame context is read from calldata instead of the EIP-8141
            // opcodes. Layout after the 2-byte entry: nonce_seq, sig hash, key count, key 0, scheme,
            // signature length (one word each), then the signature bytes. CALLDATACOPY has the same
            // gas formula as SIGDATACOPY. APPROVE is replaced by returning 0xaa00..00||scope.
            function txparam(p) -> v {
                switch p
                case 0x01 { v := calldataload(2) }
                case 0x08 { v := calldataload(34) }
                case 0x0E { v := calldataload(66) }
                default { v := calldataload(98) }
            }
            function sigparam(i, p) -> v {
                switch p
                case 0x01 { v := calldataload(130) }
                default { v := calldataload(162) }
            }
            function sigdatacopy(mem, off, len, i) { calldatacopy(mem, add(194, off), len) }
            function approve(scope) {
                mstore(0, or(shl(248, 0xaa), scope))
                return(0, 32)
            }"""

CONTEXT = {"real": REAL, "mock": MOCK, "bench": BENCH}


def render(name: str, kind: str) -> str:
    with open(os.path.join(ACCOUNT_DIR, f"{name}.yul.in")) as f:
        src = f.read()
    marker = "// @@CONTEXT@@"
    assert src.count(marker) == 1
    head = f"/// GENERATED FILE: edit contracts/account/{name}.yul.in and run scripts/gen_account.py\n"
    return head + src.replace(marker, CONTEXT[kind])


SOLC = os.path.expanduser("~/.svm/0.8.37/solc-0.8.37")


def compile_yul(path: str) -> str:
    out = subprocess.run(
        [SOLC, "--strict-assembly", "--evm-version", "prague", "--optimize", "--bin", path],
        check=True, capture_output=True, text=True,
    ).stdout
    lines = out.splitlines()
    return lines[lines.index("Binary representation:") + 1].strip()


def main() -> None:
    stale = []
    for path, (name, kind) in OUTPUTS.items():
        text = render(name, kind)
        current = open(path).read() if os.path.exists(path) else None
        if current != text:
            if "--check" in sys.argv:
                stale.append(path)
            else:
                with open(path, "w") as f:
                    f.write(text)
                print(f"wrote {os.path.relpath(path, ROOT)}")
    for src in OUTPUTS:
        initcode = src.replace(".yul", ".initcode.hex")
        code = compile_yul(src) + "\n"
        current = open(initcode).read() if os.path.exists(initcode) else None
        if current != code:
            if "--check" in sys.argv:
                stale.append(initcode)
            else:
                with open(initcode, "w") as f:
                    f.write(code)
                print(f"wrote {os.path.relpath(initcode, ROOT)} ({len(code) // 2} bytes)")
    if stale:
        sys.exit(f"stale generated files: {stale}")


if __name__ == "__main__":
    main()

# Vendored: Skale xmss-solidity

- Source: https://github.com/skalenetwork/xmss-solidity
- Commit: 749593da6a09a2a8279bbdb8664b9e0a5c1c0f90 (2026-10-08), copied 2026-10-24
- Files: `src/XMSS.sol` (unchanged), `LICENSE` (MIT, Copyright (c) 2026 SKALE Labs); test vectors `test/vectors/xmss_h10.json`, `xmss_h20.json` copied to `contracts/test/vectors/xmss/`.
- Status: proven equivalent to RFC 8391 verification with Halmos for bytecode from solc 0.8.37, via-IR, 200 runs (this repository uses the same settings). Formally checked, **not audited**.
- Use in Lamport: Profile B (heavy, needs the alternative mempool). Lamport does not modify the verifier; it only adds an account adapter and its own leaf-reuse protection.

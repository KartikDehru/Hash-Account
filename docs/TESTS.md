# Test plan

1. **Differential**: random messages and keys, Python reference against Solidity verifier, 10,000 cases.
2. **Mutation**: change one byte of the signature, path, leaf index, chain id or account address; expect failure each time.
3. **Reuse**: with toy parameters, sign two messages with one leaf and show a third message can be forged; with real parameters, show the signer refusing the second signature.
4. **Checksum**: random and adversarial messages (all-zero digits, all-maximum digits) must not allow forgery.
5. **Gas regression**: snapshot gas per phase (calldata copy, chain steps, key hash, path walk, root check); fail the build if Profile A rises above target.
6. **Admission golden cases**: Profile A accepted by public rules; Profile B refused for validation gas; the alt-mempool budget in `simulator/rules.json` is unknown, so the simulator reports that instead of accepting Profile B; a banned-opcode case refused. The sidecar at fcb4885 also refuses Profile B at 100,000 (`docs/RULE_FINDINGS.md`).
7. **Frame glue** (needs ethrex build): the account is deployed in an earlier transaction; a transaction using leaf 0 is admitted; a second use of that leaf is refused. Deploying inside the frame exceeds both the 100,000 execution cap and the 500,000 state-gas cap.
8. **Signer**: reads used leaves from chain; refuses to sign twice for one leaf; works after a simulated backup restore.

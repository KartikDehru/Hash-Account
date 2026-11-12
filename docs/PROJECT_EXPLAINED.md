# HashAccount in simple terms

## The problem
Today, almost every Ethereum account is protected by one secret key and a signature method called ECDSA. A large enough quantum computer could, in principle, work out that secret key from public information and take the funds. Such computers do not exist yet, but accounts and their funds last for years, so it is worth having accounts that do not depend on ECDSA at all.

## The idea
There is an old kind of signature that relies only on hash functions (the same "fingerprint" functions Ethereum already uses everywhere). These hash-based signatures are believed to resist known quantum attacks. Their catch: each key may sign **only once**. Signing twice with the same key lets an attacker forge new signatures.

HashAccount builds an Ethereum account around this. The code still says Lamport, after Leslie Lamport's one-time signature:
- The account holds **1,024 one-time keys**, packed into a structure called a Merkle tree, so the account only needs to store one short fingerprint (the "root") of all of them.
- Each transaction uses the next unused key.
- On the frame-transaction design, each key is tied to the transaction's **nonce**. Once a transaction with that nonce is included, the same nonce cannot be used again. Local runs show the node refusing that second use. Ethereum mainnet does not have frame transactions yet, so this guarantee is not live there.
- The account never has an ECDSA key at all.
- When the 1,024 keys run low, one signed transaction adds a fresh set of 1,024 keys ("key rotation") without changing the account's address.

## How it fits into Ethereum
A proposed Ethereum upgrade, **EIP-8141 "frame transactions"**, lets an account check its own signatures with its own code, instead of the built-in ECDSA check. A transaction is split into "frames": a VERIFY frame where the account checks the signature and approves, then frames that do the actual work (for example, a payment).

The catch is a budget: to keep nodes safe from spam, the normal (public) transaction pool only accepts transactions whose checking step costs at most **100,000 gas**. A second, "alternative" pool is being designed for transactions that need more. Profile A is measured against the public cap. Profile B shows which schemes need the larger budget.

## What we built
- **Profile A**: the account described above, using a signature type called Winternitz. It is small enough for the public pool: in our measurements its checking step cost at most 74,942 gas with the ordinary nonce and 96,114 with the newer "keyed" nonce.
- **Profile B**: the same idea with a heavier, standardised scheme (XMSS, reusing an open-source verifier from SKALE). It costs about three quarters of a million gas, so it can only go through the alternative pool.
- **A signer** (the program that creates signatures). It asks the chain which keys are already used, keeps its own written record, and refuses to sign twice with one key.
- **Measurements and tools**: scripts that measure the gas of each signature type, a checker that predicts whether a transaction would be admitted, an "attack view" that shows why reusing a key is dangerous, and a demo page (`results/demo.html`).

## What we found
Because the public test network was not reachable from our build machine, we built the network software ourselves and ran it locally. There we saw:
1. Payments are accepted and included in local blocks, and a second use of a spent key is refused by the node, the sidecar, the account, and the signer.
2. The alternative-pool software we tested still refused anything above 100,000 gas, and it also refused calls to built-in helper functions (precompiles) that heavy signatures need. With a small change we made, it accepted and included the heavy Profile B transaction.
3. The newer keyed nonces cost 20,000 gas of the 100,000 budget, which is a lot for accounts like ours.
4. Creating the account inside its first transaction is too expensive under current rules, so the account is created in a separate step.
These are written up as suggested rule changes in `docs/RULE_FINDINGS.md`.

## What it does not do
- It is **unaudited research code**: nobody independent has checked it. Use test funds only.
- Each key tree allows 1,024 transactions; before it runs out, the account can switch to a fresh tree with one signed transaction (key rotation). Old trees are not cancelled, so their secret files must still be kept safe.
- A stuck transaction cannot be "sped up" with a higher fee, because that would need a second signature with the same key.
- It protects the account's own authorisation, not the rest of Ethereum (the network's consensus, other contracts, or ordinary accounts).
- No public-devnet transaction has been sent. See `docs/DEVNET_RUNBOOK.md`. EIP-8141 is not on mainnet.

## Words used
- **Gas**: the unit of computing work on Ethereum; every operation costs gas.
- **Mempool**: the waiting room where nodes keep transactions before they go into a block.
- **Nonce**: a number that makes each transaction from an account unique and usable once.
- **Merkle tree / root**: a way to summarise many values in one short fingerprint, with a short proof that a value belongs to it.
- **Precompile**: a built-in function at a fixed address, such as SHA-256.
- **Local**: run on our own copy of the network software, not the shared public test network.

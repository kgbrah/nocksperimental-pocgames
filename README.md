# Forfeit Flip

A **provably-fair, two-sided commit-reveal coinflip** as a Nockchain NockApp — and the
first of three games whose real purpose is to demonstrate a **forensic fairness-and-
exploit-proofing system**: every claim is a recomputable or signed artifact, never a
promise. A disputing party resolves any question by recomputation from public data,
*not* by trusting the house.

It is the corrected successor to `coinflip.hoon`, which had a fatal bug: its `[%state ~]`
peek leaked the secret seed, so a player could read it, predict the flip, and only ever
bet on a win.

## What's here

| Path | What it is | Status |
|---|---|---|
| `kernels/forfeit-flip.hoon` | The game kernel — commit-only peek surface; never holds an unrevealed seed | **compiles clean** (`hoonc`, "no panic!") |
| `verifier/forfeit-flip-verifier.mjs` | Standalone forensic verifier: recompute any round, detect tamper, demo the cheat-vs-fix | **green** |
| `verifier/fairness-receipt.mjs` | Ed25519-signed receipts + append-only evidence chain + fail-closed pre-reveal redaction | **green** |
| `docs/FAIRNESS-DOSSIER.md` | The publishable proof: fairness construction, exploit catalog, per-step lab gates, honest residuals | — |

## Run the proofs

```bash
npm test          # runs both forensic self-tests
npm run compile-gate   # hoonc compile-gate the kernel (needs ../nockchain/hoon; ~minutes)
```

The verifier output is the thesis in one screen:

```
coinflip (seed peekable):    attacker win rate = 100.0%   ← the bug
forfeit-flip (commit-only):  attacker win rate =  49.6%   ← the fix
```

and the receipt chain proves tamper-evidence:

```
tampered chain rejected: entryHash mismatch (round edited)
reordered chain rejected: broken append-only link
pre-reveal receipt carrying a seed is rejected before signing
```

## Provable fairness (two-sided commit-reveal)

```
commit_H = H(serverSeed)                      house publishes before any bet
commit_P = H(clientSeed)                      player publishes before the house reveals
outcome  = lowbit(H(serverSeed ‖ clientSeed ‖ nonce))     0 = house, 1 = player
```

Unpredictable (each commits before seeing the other's seed), unbiasable (the
`H(seed)==commit` hashlock is checked at reveal), and auditor-verifiable (deterministic
VM ⇒ every outcome reproducible from public data).

## Honest scope (read the dossier)

Forfeit Flip is **trustless on fairness** and **forensically provable**. Settlement on
Nockchain mainnet today is **HTLC-grade, not contract-grade**: the consensus lock-
primitive set is closed to `%pkh/%tim/%hax/%brn`, so no on-chain primitive can condition
a payout on the outcome. The anti-abort guarantee is therefore an escrow + bonded
timeout-forfeit construction (an economic guarantee + disclosed residuals), not a pure
"the chain pays the winner." See `docs/FAIRNESS-DOSSIER.md` §1 and §7 — we disclose this
loudly rather than overclaim.

## Roadmap (3 games, escalating rigor)

1. **Forfeit Flip** *(this repo)* — even-money coinflip; the minimal fix + the forensic core.
2. **Forfeit Dice** — even-money over/under; adds a provable-distribution dossier (chi-square recomputed from raw rolls).
3. **Forfeit Dice (bonded)** / Forfeit Channel — bigger-bond anti-abort, or an off-chain channel (the forensic-dispute showcase, honestly weaker on cross-round anti-abort).

The single dependency that moves these from "provable in fixtures" to "playable on
mainnet" is **G-TOOL**: a wallet/tx-builder extension to construct the `%hax`+`%tim`
HTLC escrow (supported by consensus, not yet by the shipped CLI). It is *not* a consensus
change.

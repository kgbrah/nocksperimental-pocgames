# Fakenet settlement bridge — wiring the funded house wallet into a provably-fair round

This is the Phase-5 "fakenet-first" bridge: it takes the already-trustless **fairness** of
Forfeit Flip and adds the **settlement** leg with real (fakenet) value, end to end, before
anything touches mainnet. `settlement/fakenet-settle.mjs` is the orchestrator.

## What it does

For each round it runs the two-sided commit-reveal, recomputes the outcome from public data
(`verifier/forfeit-flip-verifier.mjs`), and on a **player win** has the funded house wallet
**sign and broadcast a real fakenet NOCK payout** (`nockchain-wallet create-tx` → `send-tx`).
Every round — commit phase and resolved phase — is written into the signed, append-only fairness
receipt chain (`verifier/fairness-receipt.mjs`), which anyone can recompute and verify from public
data plus the issuer key. The commit-phase receipt is fail-closed against carrying a seed.

```
node settlement/fakenet-settle.mjs            # ROUNDS=4 by default
HOUSE_ADDRESS=… PLAYER_ADDRESS=… POT_NICKS=… ROUNDS=… node settlement/fakenet-settle.mjs
```

Prereqs: a fakenet node mining + serving the private gRPC on `127.0.0.1:5555`, and a funded house
wallet whose master address is `HOUSE_ADDRESS`. **Every wallet call passes `--fakenet`** so the
wallet's blockchain constants match the node (without it the wallet derives the wrong note names —
this is the bug that hid the mining rewards; see below).

## Honest scope — settlement is HTLC-grade, not contract-grade

Nockchain consensus has **no covenant/script primitive** (the lock set is `%pkh/%tim/%hax/%brn`),
so a payout **cannot be forced by the chain on a game outcome**. Settlement here is therefore
**cooperative**: the house *signs* the payout when the player wins.

- **Fairness is fully trustless** — every outcome is recomputable from public reveals; neither party
  can predict or bias it, and a lying house is caught by recomputation.
- **Payout liveness is the disclosed residual** — a house that refuses to sign is publicly evident
  (the resolved round is on the receipt chain; the missing settlement tx is its own evidence), but
  the chain cannot compel it.
- The trust-minimizing upgrade is a **two-sided HTLC escrow** (hashlock-on-winner-reveal OR
  timeout-refund), which needs the wallet's `HtlcEscrow` recipient (G-TOOL) — a follow-up.

## Verified end-to-end on a live fakenet node

- The node mines fakenet and the house wallet accrues real coinbase (millions of NOCK).
- `create-tx` builds a correctly-locked, house-signed payout tx to a player p2pkh address.
- `send-tx` validates the tx; the node logs `heard-tx: Heard new valid transaction` and the miner
  includes it in a candidate block within a few blocks (the house wallet's input note disappears and
  a change note appears — proof it mined).
- **The payout confirms at the recipient.** The player address holds the paid notes (verified: four
  1,000,000,000-nick payouts = 4,000,000,000 nicks at the demo player address; a fresh recipient's
  own wallet shows the paid note with a 1-of-1 PKH lock to its key — confirmed and spendable).
- The orchestrator runs the rounds, settles player-wins, confirms the player balance on-chain, and
  the receipt chain **verifies** (recompute + Ed25519 + append-only link, all from public data).

### Observing a payout from a wallet that doesn't own the recipient key

`list-notes-by-address <addr>` returns only notes the *calling* wallet has synced, and the wallet
drops notes for keys it neither owns nor watches. So to *observe* a payout to a third party from the
house wallet you must `watch` the address first — then the next sync keeps and returns its notes.
This is purely observational: **payments confirm regardless of whether anyone is watching** (the
recipient's own wallet, which tracks its key, sees the note immediately). The orchestrator does this
`watch` automatically in its on-chain confirmation step. (This observability gap, not a payment bug,
was the "payout not landing" red herring during bring-up.)

## The coinbase-crediting fix (for reference)

Mining rewards initially showed `0` in the wallet despite 150+ blocks. Root cause was **not** the
mining key (`--mining-pkh <master-address>` was correct). It was the wallet client:
1. a **stale balance cache** pinned to a dead chain's height, so live updates were dropped; and
2. the wallet running **without `--fakenet`**, so it computed coinbase note-names with mainnet's
   `coinbase-timelock-min=100` while the node named them with fakenet's `=1` → no match → `0 notes`.

Fix: reset only the cached balance state (keys preserved via `export-keys`/`import-keys`) and run
**all** wallet commands with `--fakenet`. `list-notes` is the authoritative balance view
(`show-balance` has a separate display-only bug for coinbase-lock notes).

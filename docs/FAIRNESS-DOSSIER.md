# Forfeit Flip — Fairness Dossier

A publishable, independently-verifiable proof that this game is fair and that each known
exploit is prevented. The thesis of this project: **every claim is a recomputable or
signed artifact, not a promise.** A disputing party resolves any question by
recomputation from public data — never by trusting the house.

> **Honesty banner (read first).** Forfeit Flip is *trustless on fairness* and
> *forensically provable*, but settlement on Nockchain mainnet today is **HTLC-grade,
> not contract-grade**. The consensus lock-primitive set is closed to
> `%pkh / %tim / %hax / %brn` (verified: `nockchain/hoon/common/tx-engine-1.hoon:1238-1245`),
> so **no on-chain primitive can condition a payout on the game outcome.** A fully
> "loser-cannot-deny-winner" forced payout is therefore *not expressible* on mainnet
> right now. What is achievable today is provable fairness + a no-theft escrow +
> bonded cooperative/timeout settlement, with the residuals below disclosed. We say so
> loudly rather than overclaim — that is the whole point.

---

## 1. The game

A two-party, even-money coinflip. One **house**, one **player**, one bet, 50/50, with a
disclosed house edge of **0%** in this reference (a rake can be added transparently).
It is the corrected successor to `coinflip.hoon`.

## 2. Provable fairness — two-sided commit-reveal

```
commit_H  = H(serverSeed)                      house publishes BEFORE any bet
commit_P  = H(clientSeed)                       player publishes BEFORE the house reveals
outcome   = lowbit( H(serverSeed ‖ clientSeed ‖ nonce) )      0 = house wins, 1 = player wins
reveal:   house & player reveal their seeds; the kernel checks
          H(serverSeed)==commit_H  AND  H(clientSeed)==commit_P, then computes outcome.
```

- **Unpredictable:** each party commits before seeing the other's seed, so neither knows
  both inputs to `H(...)` until after the bet is locked.
- **Unbiasable:** the `H(seed)==commit` hashlock is checked at reveal, so a party cannot
  grind a different seed after the fact — the commitment binds them.
- **Auditor-verifiable:** the deterministic VM makes every outcome reproducible from the
  public `{commit_H, commit_P, nonce, serverSeed, clientSeed}`. See
  `verifier/forfeit-flip-verifier.mjs`.

*Hash note:* the reference verifier uses SHA-256 for trivial cross-runtime checking. For
on-chain settlement the kernel + verifier switch to **tip5** (Nockchain's native hash,
`hoon/common/ztd/three.hoon`) so the kernel commitment and the on-chain `%hax` hashlock
are the *same object*. The strongest verification (roadmap Phase 2) recomputes by poking
the **actual compiled kernel** via `nockapp-run`, not just the JS re-implementation.

## 3. Why it cannot be peek-cheated (the `coinflip.hoon` bug, fixed structurally)

`coinflip.hoon` stored the secret `seed` in kernel state and exposed it via the
`[%state ~]` peek path (`coinflip.hoon:56-57`). A player peeked the seed, computed the
next flip, and only ever bet on a win. Its "seed is never exposed via peek" comment is
false.

**Forfeit Flip never holds an unrevealed seed.** The house and player each poke only a
**commitment** (`shax` of their secret). The kernel learns a seed solely at `%reveal` —
i.e. when it is already public. So there is *nothing secret in peekable state to leak*.
The peek surface (`kernels/forfeit-flip.hoon`) returns commitments, nonce, and
post-reveal data only; there is deliberately **no path** that returns an unrevealed seed.

**Proof (runnable):** `node verifier/forfeit-flip-verifier.mjs` simulates both designs:

```
coinflip (seed peekable):     attacker win rate ≈ 100%
forfeit-flip (commit-only):   attacker win rate ≈ 50%   (no prediction advantage)
```

## 4. The forensic proof system (built on the hardened nocksperimental evidence stack)

- **Per-round signed Fairness Receipt** — Ed25519 (`evidence-receipt-signing.ts`) over a
  canonical `{game, kernelHash, roundId, nonce, commit_H, commit_P, outcome,
  revealedSeeds (post-reveal only), payout, settlementRef}`. Pre-reveal, the
  secret-field scrubber is a hard reject gate so no seed leaks; the receipt store is
  create-only so a signed receipt cannot be clobbered.
- **Append-only evidence chain** — each round is one `appendTrustUpdateToLog` entry,
  hash-chained and Ed25519-signed; `validateTrustUpdateChain` recomputes links and flags
  any broken link or invalid signature. Back-dating a commit to match an outcome breaks
  both the chain and the signature. The `rootHash` is periodically **anchored on-chain**
  via note-data to close operator equivocation.
- **Standalone reproducible verifier** — from public data alone: check the commitments,
  recompute the outcome, Ed25519-verify the receipt, confirm chain linkage. The block
  height of the settling spend is itself the forensic proof of which settlement case
  occurred (a single-preimage claim *after* the timeout is, on its face, an
  abort-forfeit). **Disputes are resolved by recomputation, not trust.**

## 5. Exploit catalog — each attack has a prevention AND a proof-of-prevention

Every attack below is (a) prevented by the kernel/escrow design and (b) demonstrated by a
nocksperimental **negative-control fixture** that performs the attack and MUST be
rejected — the signed rejection is the proof-of-prevention.

| Exploit | Prevention | Proof-of-prevention (nocklab) |
|---|---|---|
| Peek-to-win / seed leak (the coinflip bug) | Commit-only peek surface; kernel holds no unrevealed seed | `attack-peek-leaks-seed` must be rejected by `commit-only-peek` |
| RNG grind (change seed after seeing clientSeed) | `shax(seed)==commit` hashlock checked at reveal | `attack-grind-seed` (seed ≠ commit) rejected |
| Wrong-seed reveal | Same hashlock check | `attack-wrong-seed-reveal` rejected |
| **Selective abort (house withholds reveal after losing)** | On-chain: sole-revealer sweeps stake+bond via single-preimage `%tim` default branch; aborter forfeits bond (−EV) | `attack-house-withholds-reveal` → terminal beneficiary must be the player |
| Refuse-to-pay winner | Default branch is broadcastable by anyone; `sig-hash` binds outputs | `attack-payout-to-loser` rejected by `forced-payout` |
| House insolvency | Stake+bond locked in the escrow note up front | `attack-house-insolvent` rejected by `solvency-covers-payout` |
| Nonce replay | Kernel monotonic nonce; replayed bet references a spent note | `attack-replay-nonce` rejected by `nonce-monotonic` |
| Mint-from-nothing in payout | Pot = sum of locked notes; consensus `check-gifts-and-fee` | `attack-mint-payout` rejected by `supply-conserved` |
| Claim off the deadline | `%tim` gates absolute block height | `attack-default-before-deadline` → consensus rejects (`%v1-spend-1-lock-failed`) |

## 6. How nocksperimental gates every build step

| Phase | nocksperimental gate |
|---|---|
| 0 Lab hardening | `expectRejected` field + `commit-only-peek`/`commit-binds-seed` custom-fns + `nonce-monotonic` kind; `npm run lab:ci` green |
| 1 Kernel compile | `hoonc` compile-gate (real compiler; failure blocks) |
| 2 Real-VM poke/peek | `nockapp-run`: peek returns commitments, **never a seed** — the headline proof vs the bug |
| 3 Positive invariants | full fairness/solvency/ordering pack passes `--strict` |
| 4 Negative-control battery | every exploit fixture in §5 is rejected → exploits provably prevented |
| 5 Fakenet escrow | build the `%hax`+`%tim` OR-tree, prove early default-spend rejected / post-`T` accepted |
| 6 Signed receipts | each run → Ed25519 receipt, scrubbed, appended; chain validates append-only |
| 7 x402 metering | verifier/dossier access metered; no silent stub fallback |
| 8 Settlement provenance | receipts carry confirmed `inclusionBlock`, not node-acceptance |
| 9 Mainnet cutover | real issuer key; `rootHash` anchored on-chain; dossier reproduces every round |

## 7. Residual assumptions (disclosed, per the threat model)

1. **No auto-payout / liveness:** a party (or watchtower) must broadcast the claim; safety
   (no theft, abort = forfeit) is enforced, *liveness* depends on block production. A
   censoring miner can **delay, not steal**.
2. **Wallet-tooling gap (G-TOOL):** the `%hax`+`%tim` OR-tree escrow is supported by
   consensus but not yet constructible from the shipped wallet CLI (`recipient.rs` exposes
   only `P2pkh/Multisig/BridgeDeposit`). Until that wallet/tx-builder extension lands, the
   game is provable in fixtures/fakenet, not push-button on mainnet. *This is the single
   dependency that moves the game to mainnet, and it is not a consensus change.*
3. **Bonded-cooperative settlement, not forced payout:** because consensus can't gate a
   spend on the outcome, the anti-abort guarantee is an **economic** one (aborting
   forfeits a bond, making it strictly −EV) plus the timeout-default branches — not a pure
   cryptographic "the chain pays the winner." This must be rigorously verified, and is
   disclosed here.
4. **Block-height, not wall-clock, timeouts** — size deadlines with a reorg-confirmation margin.
5. **Mock-model ≠ kernel proof** — JS-model invariants prove the model and that invariants
   are well-formed; they do not prove the *compiled Hoon* upholds them until generic-cause
   kernel poke/peek lands (`nockapp-run` is counter-interface-only today).
6. **Dev issuer keys** — receipts prove tamper-evidence, not authenticity, until a real
   `NOCKS_BADGE_ISSUER_SIGNING_SEED` is configured.

---

*Key source citations: `tx-engine-1.hoon:1238-1245` (closed lock-primitive set),
`:1821-1828` (`%hax`), `:1858-1873` (`%tim`); `coinflip.hoon:56-57` (the seed-leak bug
this game fixes).*

# NIP-FAIR: a `%fair` lock primitive for trustless provable-fairness settlement

**Status:** Draft / proof-of-concept (implemented + demonstrated on fakenet)
**Layer:** Consensus (tx-engine lock set)
**Author:** nocksperimental
**Depends on:** the v1 lock model (`Lock`/`SpendCondition`/`LockPrimitive`), tip5 hashing

## Abstract

Nockchain's lock set is deliberately closed to `%pkh`, `%tim`, `%hax`, `%brn`
(`hoon/common/tx-engine-1.hoon:1235`). None of them can bind a payout to the
outcome of a two-party commit-reveal game, so on-chain settlement for a
provably-fair game is at best **HTLC-grade** (bonded-cooperative, via multisig /
OR-tree escrows) — the chain cannot make the *winner* take the pot. This NIP adds
one bounded lock primitive, `%fair`, that closes the gap: it makes a branch
spendable **iff** the revealed seeds hash to their pre-committed values *and*
compute to that branch's required outcome bit. Composed into a two-branch
`Lock::V2`, this lets the chain itself enforce "only the provably-fair winner can
spend the pot" — **contract-grade settlement with no multisig and no
output-introspecting covenant.**

## Motivation

A two-sided commit-reveal game is already fully trustless on *fairness*: the
outcome `b = lowbit(tip5(serverSeed ‖ clientSeed ‖ nonce))` is recomputable by
anyone from public reveals, and neither party can predict or bias it (each
commits before seeing the other's seed; the hashlock `tip5(seed)==commit` is
checked at reveal). What is *not* trustless is **settlement**: paying the winner
requires either a trusted house (cooperative) or a bonded escrow that punishes
but cannot compel (HTLC-grade). The user requirement — *no party must trust the
other for anything; every aspect must be provable* — is unreachable with the
current lock set.

## Why not the obvious alternatives

- **HTLC / multisig OR-tree escrow.** Bonded-cooperative only: the chain can
  refund-on-timeout and forfeit a bond, but cannot pay the *winner*; it uses
  multisig-shaped locks. Rejected: doesn't meet "no trust", and is the workaround
  this NIP removes.
- **A general covenant (run arbitrary Nock over the spending tx's outputs).**
  Would work, but the lock-check `check-context`
  (`tx-engine-1.hoon`, `++ check-context`) deliberately contains only
  `{now, since, sig-hash, witness, bythos-phase}` — **not the spending tx's
  outputs.** Threading outputs into every lock check is invasive and re-opens the
  DoS surface the closed set avoids.
- **Schnorr adaptor signatures.** No consensus change, but needs an interactive
  2-of-2 funding (multisig-shaped) and heavy off-chain crypto.

## Key insight

Settlement does **not** require constraining outputs. It is sufficient to make
each *branch* of an OR-tree **unlockable only by the party who won under that
branch's outcome**. That is a pure *witness-checked unlock condition* — exactly
the shape `%hax`/`%pkh`/`%tim` already are — so it slots into the existing
`check-context` with **no output introspection** and stays **bounded** (two hash
checks + one tip5 + a bit compare).

## Specification

### The primitive

Add `[%fair fair]` to the `lock-primitive` tagged union
(`tx-engine-1.hoon:1240`):

```hoon
+$  form
  $%  [%pkh pkh]
      [%tim tim]
      [%hax hax]
      [%fair fair]   ::  <- new
      [%brn ~]
  ==
```

```hoon
::  $fair: settlement-by-provable-outcome lock primitive
++  fair
  +$  form
    $:  commit-h=hash   ::  tip5(serverSeed)  — house's pre-committed seed hash
        commit-p=hash   ::  tip5(clientSeed)  — player's pre-committed seed hash
        nonce=@         ::  round nonce (replay domain separation)
        win-bit=@       ::  the outcome bit (0/1) that makes THIS branch spendable
    ==
```

`win-bit` MUST be `0` or `1`. `nonce` MUST be `based` (atom below the field
prime). `commit-h`/`commit-p` are tip5 hashes.

### Outcome function (consensus-fixed)

```hoon
++  outcome-bit
  |=  [server=* client=* nonce=@]
  ^-  @
  (mod (snag 0 (hash-noun:fair [server client nonce])) 2)
```

`hash-noun` is the kernel's tip5 noun hash (identical to `++ hash-noun` in the
`hax` core). `outcome-bit` takes the low bit of the first field element of the
tip5 digest of the noun `[server client nonce]`. It is total and deterministic.

### The check

```hoon
++  check
  |=  [=form ctx=check-context]
  ^-  ?
  =/  server  (~(get z-by hax.witness.ctx) commit-h.form)
  =/  client  (~(get z-by hax.witness.ctx) commit-p.form)
  ?~  server  %|
  ?~  client  %|
  ?&  =(commit-h.form (hash-noun:fair u.server))   ::  reveal binds the house commitment
      =(commit-p.form (hash-noun:fair u.client))   ::  reveal binds the player commitment
      =(win-bit.form (outcome-bit u.server u.client nonce.form))  ::  outcome selects this branch
  ==
```

The revealed seeds are carried in the **same witness `hax` map** the `%hax`
primitive already uses (`hax.witness.ctx`, a `(z-by hash preimage)`), keyed by
their commitments — **no new witness field is required**. The primitive is added
to the dispatch (`tx-engine-1.hoon:1959`) and to `based:lock-primitive` /
`hashable:lock-primitive` so the lock-root commits to it.

### The escrow (OR-tree, no multisig)

The pot is funded to a two-branch `Lock::V2`:

```
Lock::V2 {
  p (player-wins) : SpendCondition[ {%fair commit_H commit_P nonce win_bit=1}, {%pkh 1-of-1 player} ],
  q (house-wins)  : SpendCondition[ {%fair commit_H commit_P nonce win_bit=0}, {%pkh 1-of-1 house}  ],
}
```

- If `outcome==1`: branch `p`'s `%fair` passes and only the player can satisfy
  the `%pkh` → **player sweeps the pot**; branch `q`'s `%fair` fails (`win_bit`
  mismatch), so the house cannot.
- If `outcome==0`: symmetric → **house keeps the pot**.

The winner spends with a `LockMerkleProof::Full` selecting their branch, the two
seed preimages in the witness `hax` map, and their Schnorr `%pkh` signature. The
chain enforces winner-takes-pot; the loser's branch is unspendable.

### Liveness (the only residual, and it is narrow)

Settlement needs `serverSeed` public (the player holds only `clientSeed`). Two
mitigations, both standard:

1. **Reveal-or-forfeit timeout.** Add a third branch
   `[{%tim abs.min=T} {%pkh player}]` (refund/sweep-to-player after height `T`).
   If the house withholds `serverSeed` past `T`, the player sweeps unconditionally
   → withholding is strictly dominated, so a rational house always reveals.
2. **Symmetric stakes.** Both parties fund equal stakes into the same escrow;
   the timeout returns the player's stake (and optionally the house's to the
   player), so griefing only loses the griefer money.

This is a *liveness* assumption (the house must act), not a *trust* assumption
(the house cannot steal): the worst case is the timeout, which pays the honest
party. Crucially, **fairness and winner-selection are fully enforced by
consensus** — the improvement over HTLC-grade.

### Activation & safety

- **Versioning.** Gate `%fair` behind a phase height (mirror the existing
  `bythos-phase` gate on multi-leaf `LockMerkleProof::Full`,
  `tx-engine-1.hoon:213`), so pre-activation txs that use it are invalid and
  there is a clean fork boundary.
- **Boundedness / DoS.** The check is O(1): two map lookups, two tip5 noun
  hashes, one tip5 noun hash for the outcome, one modulo. No loops, no
  unbounded recursion, no output scan. Cost is comparable to a 2-entry `%hax`.
- **No output covenant.** `check-context` is unchanged; outputs are never
  introspected. The primitive only *authorizes* a spend.
- **Replay / cross-round.** `nonce` domain-separates rounds; `commit-h`/`commit-p`
  bind a specific seed pair; the lock-root (and the note first-name derived from
  it) is unique per escrow.
- **Hash agreement.** The game's commitments and the verifier MUST use the
  kernel's tip5 `hash-noun` (not the SHA-256 reference used in the off-chain
  demo) so `commit==tip5(seed)` and the outcome match what consensus computes.

## Rust mirror

Add `Fair(Fair)` to `LockPrimitive` (`crates/nockchain-types/src/tx_engine/v1/tx.rs`)
with the noun-serde tag `%fair`, a `struct Fair { commit_h: Hash, commit_p: Hash,
nonce: Belt, win_bit: Belt }`, and `hashable`/`based`/`hash` mirroring the hoon
byte-for-byte (the wallet builds the lock-root the kernel re-derives).

## Wallet (G-TOOL)

- `RecipientSpec::Fair { commit_h, commit_p, nonce, player_pkh, house_pkh,
  timeout, amount }` builds the `Lock::V2` (+ optional timeout branch) and the
  funding output.
- Spend path: given the revealed `serverSeed`/`clientSeed`, compute the outcome,
  select the winner's branch, build the `LockMerkleProof::Full`, attach the two
  preimages to the witness `hax` map, and sign the `%pkh`.
- CLI: `create-tx --recipient '{"kind":"fair",...}'` to fund; a claim path that
  takes `--server-seed`/`--client-seed` to settle.

## Comparison

| Property | %pkh/%tim/%hax (today) | HTLC OR-tree | **%fair** | general covenant |
|---|---|---|---|---|
| Winner takes pot, chain-enforced | ✗ | ✗ (bonded only) | **✓** | ✓ |
| No multisig | — | ✗ | **✓** | ✓ |
| No output introspection | ✓ | ✓ | **✓** | ✗ |
| Bounded / DoS-safe | ✓ | ✓ | **✓** | ✗ (needs metering) |
| Consensus change | — | none | **one primitive** | invasive |

## Reference implementation

Implemented in this repo's companion Nockchain build: the hoon primitive
(`hoon/common/tx-engine-1.hoon`), the Rust mirror
(`crates/nockchain-types/.../tx.rs`), and the wallet construct/spend
(`crates/nockchain-wallet`, `crates/wallet-tx-builder`), demonstrated end-to-end
on fakenet (fund a `%fair` escrow → reveal → the winner — and only the winner —
sweeps the pot).

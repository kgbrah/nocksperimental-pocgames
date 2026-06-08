# Forfeit Dice — Fairness Dossier (Game 2)

Forfeit Dice shares Forfeit Flip's entire trustless-fairness + forensic-proof core (see
`FAIRNESS-DOSSIER.md`): two-sided commit-reveal, a commit-only peek surface, Ed25519
signed append-only receipts, the reproducible verifier, the same exploit catalog, and the
**same honest residuals** (HTLC-grade settlement, bonded cooperative + timeout-forfeit,
the G-TOOL wallet gap). This dossier documents only the **delta**: the provable-distribution
capability.

## The game

A two-party, **even-money** dice wager. The outcome is a uniform roll in `0..9999`; the
player wins iff `roll >= 5000`. House edge: **0%**.

## Why the line is fixed at 5000

This is an even-money, 2-outcome wager. A **player-chosen line would change the odds** (a
player picks a line near the extreme and wins almost always), and a *line-proportional
multiplier* payout is **inexpressible** on Nockchain consensus (no outcome-conditional
spend — see the Flip dossier §1). So the line is a fixed kernel constant. What is novel and
proven here is not the line mechanic but that the **roll is uniform across the whole range**.

## Provable distribution — the new capability

The single-bit flip only needs balance; a dice roll needs the full distribution to be
uniform. Two parts:

**1. Rejection-sampling removes modulo bias.** The roll is reduced from
`H(serverSeed ‖ clientSeed ‖ nonce)` (a 256-bit value) into `0..9999`. A naive `mod 10000`
is slightly biased because `2^256` is not a multiple of `10000`. The kernel instead
rejection-samples: accept `h mod 10000` only when `h < ⌊2^256/10000⌋·10000`, else re-hash
and retry, **publishing the rejection index** so the reduction is auditable. (Rejection is
astronomically rare — `~10000/2^256` — but doing it makes uniformity *exact*, not
approximate.) Kernel: `kernels/forfeit-dice.hoon` `++sample-roll`.

**2. Chi-square goodness-of-fit, recomputed from public data.** The verifier recomputes
every roll from the published `{serverSeed, clientSeed, nonce}`, bins them into 10 equal
buckets, and computes a chi-square statistic (df = 9). It is reported and gated at the
strict **p = 0.001** critical value (27.877) — so honest sampling variation never
false-flags, but a real bias (which produces chi-square in the tens-to-hundreds) is caught.

> **Forensic property — the test catches bias.** The verifier includes a **negative
> control**: a deliberately biased roll stream (e.g. squashed into half the range) produces
> chi-square ≈ 20000 and is correctly rejected as non-uniform. So "the rolls are uniform"
> is not asserted — it is *demonstrated*, alongside a proof that the demonstration would
> catch a cheat. Run: `node verifier/forfeit-dice-verifier.mjs`:
> ```
> honest:  rolls=5000  chi2=5.94    -> uniform  (PASS)
> biased:  chi2=20000  buckets=[2507,2493,0,...]  -> caught (PASS, must fail uniformity)
> ```

**Honest limit (disclosed):** nocklab has no statistics evaluator, so the **verifier**, not
the lab, recomputes the chi-square from the raw published rolls. A lab `numeric-range`
gate over a fixture-supplied statistic is only a sanity check; the real distribution proof
is the reproducible verifier over public data.

## Everything else is inherited

Fairness construction, commit-only peek surface, the signed/append-only receipt chain, the
reproducible verifier, the exploit catalog (peek-to-win, RNG-grind, selective-abort,
refuse-to-pay, insolvency, replay, …), the per-step nocksperimental gates, and the residual
assumptions are **identical to Forfeit Flip** — see `FAIRNESS-DOSSIER.md`. Because the game
is still even-money / 2-outcome, the HTLC escrow is unchanged.

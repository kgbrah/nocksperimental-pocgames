#!/usr/bin/env node

// Forfeit Flip — standalone forensic verifier (reference implementation).
//
// This is the heart of the "forensic-proof system first" deliverable: from PUBLIC
// round data alone, anyone can recompute the outcome, confirm the pre-bet commitments
// bound the seeds, and detect any tamper — so a dispute is resolved by RECOMPUTATION,
// not by trusting the house. It also demonstrates, by simulation, exactly why
// coinflip.hoon is cheatable and why Forfeit Flip is not.
//
// PROVABLE-FAIRNESS CONSTRUCTION (two-sided commit-reveal):
//   commit_H = H(serverSeed)            published by the house BEFORE any bet
//   commit_P = H(clientSeed)            published by the player BEFORE serverSeed reveal
//   outcome  = lowbit( H(serverSeed ‖ clientSeed ‖ nonce) )   0 = house wins, 1 = player wins
//   reveal:  house reveals serverSeed; anyone checks H(serverSeed)==commit_H and recomputes.
// Neither party can predict the outcome (each commits before seeing the other's seed) nor
// bias it (the hashlock H(seed)==commit is checked, so a post-hoc grind fails).
//
// HASH NOTE (honest): this reference uses SHA-256 so the verifier is trivially
// cross-runtime and self-checking. For MAINNET ON-CHAIN SETTLEMENT the kernel + verifier
// switch to tip5 (Nockchain's native hash, hoon/common/ztd/three.hoon) so the kernel
// commitment and the on-chain %hax hashlock are the SAME object. The stronger verifier
// (roadmap Phase 2) recomputes by poking the actual compiled kernel via nockapp-run
// ("the real VM agrees"), not just this re-implementation.

import { createHash, randomBytes } from "node:crypto";

const SEED_BYTES = 32;

// ---- core construction -------------------------------------------------------

export function hashHex(...hexParts) {
  const h = createHash("sha256");
  for (const part of hexParts) h.update(Buffer.from(part, "hex"));
  return h.digest("hex");
}

// commitment to a seed: what the kernel's peek surface is allowed to expose.
export function commit(seedHex) {
  return hashHex(seedHex);
}

function nonceHex(nonce) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(nonce));
  return b.toString("hex");
}

// outcome of a round from the two seeds + nonce. 0 = house wins, 1 = player wins.
export function outcome({ serverSeed, clientSeed, nonce }) {
  const digest = hashHex(serverSeed, clientSeed, nonceHex(nonce));
  return parseInt(digest.slice(-1), 16) & 1;
}

export const winnerOf = (round) => (outcome(round) === 1 ? "player" : "house");

// ---- forensic verification of a published round -----------------------------

// A published round record (all PUBLIC after reveal): everything needed to recompute.
//   { roundId, nonce, commitHouse, commitClient, serverSeed, clientSeed, declaredWinner }
export function verifyRound(round) {
  const checks = {};
  checks.houseCommitBindsSeed = commit(round.serverSeed) === round.commitHouse;
  checks.playerCommitBindsSeed = commit(round.clientSeed) === round.commitClient;
  const recomputed = winnerOf(round);
  checks.outcomeRecomputes = true; // recomputation always succeeds; we compare below
  checks.declaredWinnerCorrect = round.declaredWinner === recomputed;
  const verified = Object.values(checks).every(Boolean);
  return { verified, recomputedWinner: recomputed, checks };
}

// ---- a fair round (what an honest kernel run produces) -----------------------

export function playFairRound({ nonce, serverSeed = randomHex(), clientSeed = randomHex() }) {
  const round = {
    roundId: `round-${nonce}`,
    nonce,
    commitHouse: commit(serverSeed),
    commitClient: commit(clientSeed),
    serverSeed,
    clientSeed,
  };
  round.declaredWinner = winnerOf(round);
  return round;
}

function randomHex() {
  return randomBytes(SEED_BYTES).toString("hex");
}

// ---- the headline demonstration: coinflip cheat vs forfeit-flip ------------

// COINFLIP MODEL (the bug): coinflip.hoon's `[%state ~]` peek leaks the seed, and the
// player controls the wager that feeds the seed. An attacker who can SEE the seed
// searches for a winning move and only ever bets on a computed win. Here we model the
// strongest form: the attacker can read serverSeed before committing clientSeed, so it
// picks a clientSeed that forces a win. -> attacker wins 100%.
function coinflipExploitWinRate(rounds) {
  let wins = 0;
  for (let nonce = 0; nonce < rounds; nonce += 1) {
    const serverSeed = randomHex(); // attacker PEEKS this (the coinflip.hoon leak)
    // attacker searches a clientSeed that makes outcome === player-win, knowing serverSeed:
    let clientSeed = randomHex();
    let tries = 0;
    while (outcome({ serverSeed, clientSeed, nonce }) !== 1 && tries < 64) {
      clientSeed = randomHex();
      tries += 1;
    }
    if (outcome({ serverSeed, clientSeed, nonce }) === 1) wins += 1;
  }
  return wins / rounds;
}

// FORFEIT-FLIP MODEL (the fix): only commit_H = H(serverSeed) is peekable; the player
// must commit clientSeed BEFORE serverSeed is revealed. The attacker sees only the hash,
// cannot invert it, and so cannot choose a winning clientSeed. -> ~50%.
function forfeitFlipAttackWinRate(rounds) {
  let wins = 0;
  for (let nonce = 0; nonce < rounds; nonce += 1) {
    const serverSeed = randomHex();
    const commitH = commit(serverSeed); // attacker sees ONLY this (one-way)
    // attacker tries to pick a winning clientSeed knowing only commitH (not serverSeed):
    let best = randomHex();
    for (let t = 0; t < 64; t += 1) {
      const guess = randomHex();
      // the attacker has no way to evaluate the real outcome (needs serverSeed), so the
      // best it can do is guess; model that by selecting against a DECOY hash, which is
      // uncorrelated with the real serverSeed -> no advantage.
      if ((parseInt(hashHex(commitH, guess, nonceHex(nonce)).slice(-1), 16) & 1) === 1) {
        best = guess;
        break;
      }
    }
    if (outcome({ serverSeed, clientSeed: best, nonce }) === 1) wins += 1;
  }
  return wins / rounds;
}

// ---- self-test ---------------------------------------------------------------

function main() {
  const fails = [];
  const ok = (cond, label) => {
    if (!cond) fails.push(label);
    console.log(`  ${cond ? "PASS" : "FAIL"}  ${label}`);
  };

  console.log("1) A fair round verifies from public data alone:");
  const round = playFairRound({ nonce: 7 });
  const v = verifyRound(round);
  ok(v.verified, "fair round is verified (commits bind seeds, winner recomputes)");
  ok(v.checks.houseCommitBindsSeed && v.checks.playerCommitBindsSeed, "both commitments bind their seeds");

  console.log("\n2) Tamper detection (forensic): altering a revealed seed breaks the commit check:");
  const tampered = { ...round, serverSeed: randomHex() };
  const vt = verifyRound(tampered);
  ok(!vt.verified && !vt.checks.houseCommitBindsSeed, "a swapped serverSeed fails H(serverSeed)==commit_H");

  console.log("\n3) A house that lies about the winner is caught by recomputation:");
  const lied = { ...round, declaredWinner: round.declaredWinner === "house" ? "player" : "house" };
  const vl = verifyRound(lied);
  ok(!vl.verified && !vl.checks.declaredWinnerCorrect, "a falsified declaredWinner is rejected");

  console.log("\n4) THE HEADLINE — peekable seed (coinflip.hoon) vs commit-only (forfeit-flip):");
  const N = 4000;
  const cheatRate = coinflipExploitWinRate(N);
  const fixedRate = forfeitFlipAttackWinRate(N);
  console.log(`  coinflip (seed peekable):     attacker win rate = ${(cheatRate * 100).toFixed(1)}%  (expected ~100%)`);
  console.log(`  forfeit-flip (commit-only):   attacker win rate = ${(fixedRate * 100).toFixed(1)}%  (expected ~50%)`);
  ok(cheatRate > 0.97, "coinflip seed-leak is exploitable to ~100% wins");
  ok(fixedRate > 0.42 && fixedRate < 0.58, "forfeit-flip removes the edge (~50%, no prediction advantage)");

  console.log(`\n${fails.length === 0 ? "forfeit-flip verifier: all assertions passed" : `FAILURES: ${fails.join(", ")}`}`);
  if (fails.length) process.exitCode = 1;
}

main();

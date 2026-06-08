#!/usr/bin/env node

// Forfeit Dice — standalone forensic verifier (reference implementation).
//
// Game 2. Same two-sided commit-reveal fairness as Forfeit Flip, but the outcome is a
// uniform roll in 0..9999 vs a FIXED 50/50 line (5000). The new forensic capability is a
// PROVABLE DISTRIBUTION: anyone recomputes the rolls from public data and runs a chi-square
// test to prove the reduction is uniform (not just balanced on one bit).
//
// roll = REJECTION-SAMPLED reduction of H(serverSeed ‖ clientSeed ‖ nonce) into 0..9999,
//        which removes the modulo bias a naive `mod 10000` would introduce; the rejection
//        index is published so the reduction is auditable. player wins iff roll >= 5000.
//
// HASH NOTE (honest, same as Forfeit Flip): SHA-256 reference for cross-runtime checking;
// mainnet settlement uses tip5 to match the on-chain %hax, and the strongest verifier pokes
// the compiled kernel via nockapp-run. The chi-square proof is over the published rolls and
// is independent of the hash choice.

import { createHash, randomBytes } from "node:crypto";

const SEED_BYTES = 32;
const LINE = 5000n; // fixed 50/50 threshold (player wins iff roll >= LINE)
const MODULUS = 10000n; // roll range 0..9999
const LIMIT = (2n ** 256n / MODULUS) * MODULUS; // largest multiple of MODULUS below 2^256
// chi-square critical value, df=9, p=0.001. A strict significance level: we only reject
// uniformity on EXTREME deviation, so honest sampling variation never false-flags but a
// real bias (which produces chi2 in the tens-to-hundreds) is caught cleanly.
const CHI2_CRIT_DF9 = 27.877;

export function hashHex(...hexParts) {
  const h = createHash("sha256");
  for (const part of hexParts) h.update(Buffer.from(part, "hex"));
  return h.digest("hex");
}
export const commit = (seedHex) => hashHex(seedHex);
const nonceHex = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b.toString("hex"); };
const bigToHex32 = (x) => x.toString(16).padStart(64, "0");

// recompute the roll + rejection-index from the two seeds + nonce
export function rollFrom({ serverSeed, clientSeed, nonce }) {
  let h = BigInt(`0x${hashHex(serverSeed, clientSeed, nonceHex(nonce))}`);
  let rejectionIndex = 0;
  while (h >= LIMIT) {
    h = BigInt(`0x${hashHex(bigToHex32(h), nonceHex(rejectionIndex))}`);
    rejectionIndex += 1;
  }
  return { roll: Number(h % MODULUS), rejectionIndex };
}
export const winnerOf = (round) => (BigInt(rollFrom(round).roll) >= LINE ? "player" : "house");

// forensic verification of a published round from PUBLIC data alone
export function verifyRound(round) {
  const checks = {};
  checks.houseCommitBindsSeed = commit(round.serverSeed) === round.commitHouse;
  checks.playerCommitBindsSeed = commit(round.clientSeed) === round.commitClient;
  const { roll, rejectionIndex } = rollFrom(round);
  checks.rollRecomputes = round.roll === roll;
  checks.rejectionIndexRecomputes = round.rejectionIndex === rejectionIndex;
  const recomputed = roll >= Number(LINE) ? "player" : "house";
  checks.declaredWinnerCorrect = round.declaredWinner === recomputed;
  const verified = Object.values(checks).every(Boolean);
  return { verified, recomputedRoll: roll, recomputedWinner: recomputed, checks };
}

export function playFairRound({ nonce, serverSeed = rnd(), clientSeed = rnd() }) {
  const { roll, rejectionIndex } = rollFrom({ serverSeed, clientSeed, nonce });
  const round = { roundId: `round-${nonce}`, nonce, commitHouse: commit(serverSeed), commitClient: commit(clientSeed), serverSeed, clientSeed, roll, rejectionIndex };
  round.declaredWinner = roll >= Number(LINE) ? "player" : "house";
  return round;
}
const rnd = () => randomBytes(SEED_BYTES).toString("hex");

// chi-square goodness-of-fit over published rolls: 10 equal buckets, df=9.
export function chiSquareOverRolls(rolls) {
  const buckets = new Array(10).fill(0);
  for (const r of rolls) buckets[Math.min(9, Math.floor(r / 1000))] += 1;
  const expected = rolls.length / 10;
  const chi2 = buckets.reduce((s, obs) => s + (obs - expected) ** 2 / expected, 0);
  return { chi2, buckets, uniform: chi2 < CHI2_CRIT_DF9, criticalValue: CHI2_CRIT_DF9 };
}

// Deterministic seed for reproducible (non-flaky) distribution tests + auditing.
const detSeed = (tag, i) => hashHex(Buffer.from(`forfeit-dice|${tag}|${i}`).toString("hex"));

function main() {
  const fails = [];
  const ok = (cond, label) => { if (!cond) fails.push(label); console.log(`  ${cond ? "PASS" : "FAIL"}  ${label}`); };

  console.log("1) A fair dice round verifies from public data (commits, roll, winner):");
  const round = playFairRound({ nonce: 42 });
  const v = verifyRound(round);
  ok(v.verified, `fair round verified (roll=${v.recomputedRoll}, winner=${v.recomputedWinner})`);

  console.log("\n2) Tamper detection — a swapped seed fails its commitment, a faked roll is caught:");
  ok(!verifyRound({ ...round, serverSeed: rnd() }).verified, "swapped serverSeed fails the hashlock");
  ok(!verifyRound({ ...round, roll: (round.roll + 1) % 10000 }).verified, "a falsified roll is rejected (recomputed mismatch)");

  console.log("\n3) THE HEADLINE — provable UNIFORM distribution via chi-square over recomputed rolls:");
  const N = 5000;
  // Deterministic rolls so the chi-square is reproducible (a forensic test must not be flaky).
  const rolls = [];
  for (let n = 0; n < N; n += 1) rolls.push(rollFrom({ serverSeed: detSeed("s", n), clientSeed: detSeed("c", n), nonce: n }).roll);
  const cs = chiSquareOverRolls(rolls);
  console.log(`  rolls=${N}  chi2=${cs.chi2.toFixed(2)}  (df=9 critical@p=0.001 = ${cs.criticalValue})  buckets=[${cs.buckets.join(",")}]`);
  ok(cs.uniform, "honest roll distribution is uniform (chi2 below the p=0.001 critical value)");

  console.log("\n3b) Negative control — a BIASED roll stream must be caught by the same test:");
  const biased = rolls.map((r) => r % 2000); // squash all rolls into 0..1999 -> grossly non-uniform
  const csb = chiSquareOverRolls(biased);
  console.log(`  biased chi2=${csb.chi2.toFixed(0)}  buckets=[${csb.buckets.join(",")}]`);
  ok(!csb.uniform, "a biased (non-uniform) stream FAILS the uniformity test (chi2 above critical)");

  console.log("\n4) Even-money: player win rate ≈ 50% over the fixed 5000 line:");
  const wins = rolls.filter((r) => r >= Number(LINE)).length / N;
  console.log(`  player win rate = ${(wins * 100).toFixed(1)}%`);
  ok(wins > 0.47 && wins < 0.53, "house edge is 0% (even money) at the fixed line");

  console.log(`\n${fails.length === 0 ? "forfeit-dice verifier: all assertions passed" : `FAILURES: ${fails.join(", ")}`}`);
  if (fails.length) process.exitCode = 1;
}

if (import.meta.url === `file://${process.argv[1]}`) main();

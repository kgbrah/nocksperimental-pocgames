#!/usr/bin/env node

// Fakenet game settlement — wires the funded house wallet into a provably-fair Forfeit Flip
// round so that a PLAYER WIN triggers a REAL fakenet NOCK payout signed by the house, and every
// round emits a signed receipt linking the commit-reveal fairness proof to the on-chain tx.
//
// This is the Phase-5 "fakenet-first" bridge: fairness is already fully trustless (the standalone
// verifier recomputes every outcome from public data); this module adds the *settlement* leg with
// real (fakenet) value, end to end, before anything touches mainnet.
//
// HONEST SCOPE (disclosed, matches the dossiers): settlement here is COOPERATIVE — the house signs
// the payout transaction when the player wins. Nockchain consensus has no covenant/script primitive
// (lock set is %pkh/%tim/%hax/%brn), so a payout CANNOT be forced by the chain on a game outcome.
// Therefore this is HTLC-grade, not contract-grade: FAIRNESS is trustless and recomputable; the
// payout's LIVENESS is the disclosed residual. The signed receipt makes a house that refuses to pay
// publicly evident (the resolved round + the absence of a settlement tx are both on the record). The
// trust-minimizing upgrade is a two-sided HTLC escrow (hashlock-on-winner-reveal OR timeout-refund),
// which needs the wallet's HtlcEscrow recipient (G-TOOL) — a follow-up.
//
// Prereqs: a fakenet node mining + serving the private gRPC (127.0.0.1:5555), and a funded house
// wallet whose master address == HOUSE_ADDRESS below. ALL wallet calls pass --fakenet so the
// wallet's blockchain constants match the node (without it the wallet derives wrong note names).

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { outcome, playFairRound, verifyRound, winnerOf } from "../verifier/forfeit-flip-verifier.mjs";
import { FairnessChain, verifyFairnessChain } from "../verifier/fairness-receipt.mjs";

const moduleDir = path.dirname(fileURLToPath(import.meta.url));

const CONFIG = {
  wallet: process.env.NOCKCHAIN_WALLET || "nockchain-wallet",
  // The funded house wallet's master address (mining proceeds land here).
  house: process.env.HOUSE_ADDRESS || "AU6cMNQ9vMyBwSGkwTghPsTGf6uLREziKnpDrM3y6Jk2zNsvRWdYFVx",
  // The player's payout address (a valid v1 p2pkh recipient).
  player: process.env.PLAYER_ADDRESS || "CQmyBcvsLP34J1hN3H7NQHwXtysoTtKoK65rove2BDd77QbFN5YoPmQ",
  potNicks: Number(process.env.POT_NICKS || 1_000_000_000), // paid to the player on a player win
  rounds: Number(process.env.ROUNDS || 4),
  // Dev issuer seed for the receipt chain (PUBLIC; mainnet uses a real env seed). Tamper-evident.
  issuerSeed: process.env.ISSUER_SEED || "11".repeat(32),
  // Working dir for the wallet's generated tx files + our receipts.
  workDir: process.env.SETTLE_WORKDIR || path.join(moduleDir, "out"),
  // Per wallet-command timeout so a hung node/wallet can't block the run forever.
  walletTimeoutMs: Number(process.env.WALLET_TIMEOUT_MS || 300_000)
};

for (const key of ["potNicks", "rounds", "walletTimeoutMs"]) {
  if (!Number.isFinite(CONFIG[key]) || CONFIG[key] < 0) {
    throw new Error(`invalid numeric config ${key}=${CONFIG[key]} (check the matching env var)`);
  }
}

const WALLET_BASE = ["--fakenet", "--client", "private"];

function runWallet(args) {
  return execFileSync(CONFIG.wallet, [...WALLET_BASE, ...args], {
    encoding: "utf8",
    cwd: CONFIG.workDir,
    maxBuffer: 256 * 1024 * 1024,
    timeout: CONFIG.walletTimeoutMs
  });
}

// The wallet prints ~20s of kernel boot logs; the meaningful output is interleaved. We capture all
// of it and pull signals out by pattern rather than trying to filter the noise.
function runWalletCapture(args) {
  try {
    return { ok: true, out: runWallet(args) };
  } catch (error) {
    return { ok: false, out: `${error.stdout || ""}${error.stderr || ""}`, error };
  }
}

const stripAnsi = (text) => String(text).replace(/\x1b\[[0-9;]*m/g, "");

function newestTxFile() {
  const txDir = path.join(CONFIG.workDir, "txs");
  if (!existsSync(txDir)) return null;
  const files = readdirSync(txDir)
    .filter((name) => name.endsWith(".tx"))
    .map((name) => {
      const full = path.join(txDir, name);
      return { name, path: full, mtime: statSync(full).mtimeMs };
    })
    .sort((a, b) => b.mtime - a.mtime);
  return files.length ? files[0] : null;
}

// House pays `nicks` to `address`: build (create-tx) -> broadcast (send-tx). Returns the settlement
// record (the tx id + the raw wallet output for the audit trail).
function housePayout(address, nicks) {
  const recipient = JSON.stringify({ kind: "p2pkh", address, amount: nicks });
  const create = runWalletCapture(["create-tx", "--recipient", recipient]);
  if (!create.ok) throw new Error(`create-tx failed: ${tail(create.out)}`);

  const txFile = newestTxFile();
  if (!txFile) throw new Error(`create-tx produced no tx file in ${path.join(CONFIG.workDir, "txs")}`);

  const send = runWalletCapture(["send-tx", txFile.path]);
  // Only count it submitted when send-tx exited cleanly AND the node confirmed acceptance — a
  // non-zero exit whose error text happens to contain the success phrase must not read as submitted.
  const submitted = send.ok && /TX has been submitted to node|Validation for TX .* passed/i.test(send.out);

  return { txId: txFile.name.replace(/\.tx$/, ""), txFile: txFile.path, submitted };
}

// Confirm a payout ON-CHAIN from the house wallet's vantage point. `list-notes-by-address` only
// returns notes the *calling* wallet has synced, and the wallet drops notes for keys it neither
// owns nor watches — so to observe a payout to a third party we must `watch` the address first,
// then the next sync keeps and returns its notes. (This is purely observational; payments confirm
// regardless of whether anyone is watching.) Returns { notes, nicks }.
function confirmReceived(address) {
  runWalletCapture(["watch", "address", address]);
  const clean = stripAnsi(runWalletCapture(["list-notes-by-address", address]).out);
  const notes = (clean.match(/Note Information/g) || []).length;
  let nicks = 0;
  for (const m of clean.matchAll(/Assets \(nicks\):\s*([0-9]+)/g)) nicks += Number(m[1]);
  return { notes, nicks };
}

function tail(text, n = 6) {
  return String(text).split("\n").slice(-n).join("\n");
}

function main() {
  // Guard the destructive reset: the work dir must be a dedicated, non-root path. This refuses to
  // wipe a misconfigured SETTLE_WORKDIR (e.g. "/" or "$HOME") by requiring a deep, named directory.
  const resolvedWork = path.resolve(CONFIG.workDir);
  if (resolvedWork.split(path.sep).filter(Boolean).length < 2 || resolvedWork === path.resolve(process.env.HOME || "")) {
    throw new Error(`refusing to reset unsafe SETTLE_WORKDIR=${resolvedWork} (use a dedicated subdirectory)`);
  }
  if (existsSync(resolvedWork)) rmSync(resolvedWork, { recursive: true, force: true });
  mkdirSync(path.join(CONFIG.workDir, "txs"), { recursive: true });

  console.log("Fakenet game settlement — Forfeit Flip");
  console.log(`  house  : ${CONFIG.house}`);
  console.log(`  player : ${CONFIG.player}`);
  console.log(`  pot    : ${CONFIG.potNicks.toLocaleString()} nicks on a player win`);
  console.log(`  rounds : ${CONFIG.rounds}`);
  console.log("  settlement: COOPERATIVE house-signed payout (HTLC-grade; fairness trustless, payout liveness disclosed)\n");

  const chain = new FairnessChain(CONFIG.issuerSeed);
  const results = [];

  for (let nonce = 0; nonce < CONFIG.rounds; nonce += 1) {
    // --- provably-fair round (two-sided commit-reveal) ---
    const round = playFairRound({ nonce });
    const verification = verifyRound(round);
    const winner = winnerOf(round);

    // Commit-phase receipt (no seeds — the fail-closed gate enforces this) then resolved receipt.
    chain.append({
      roundId: round.roundId,
      phase: "commit",
      nonce,
      commitHouse: round.commitHouse,
      commitClient: round.commitClient
    });

    // --- settlement leg ---
    let settlement = { settled: false, reason: winner === "house" ? "house won — no payout" : null };
    if (winner === "player") {
      try {
        const pay = housePayout(CONFIG.player, CONFIG.potNicks);
        settlement = {
          settled: pay.submitted,
          payTo: CONFIG.player,
          amountNicks: CONFIG.potNicks,
          txId: pay.txId,
          note: pay.submitted
            ? "house-signed payout broadcast to fakenet"
            : "payout build/broadcast did not confirm submission"
        };
      } catch (error) {
        settlement = { settled: false, reason: `payout error: ${error.message}` };
      }
    }

    const resolved = chain.append({
      roundId: round.roundId,
      phase: "resolved",
      nonce,
      commitHouse: round.commitHouse,
      commitClient: round.commitClient,
      serverSeed: round.serverSeed,
      clientSeed: round.clientSeed,
      outcome: outcome(round),
      winner,
      verified: verification.verified,
      settlement
    });

    results.push({ nonce, winner, verified: verification.verified, settlement, rootHash: resolved.rootHash });
    console.log(
      `round ${nonce}: winner=${winner.padEnd(6)} verified=${verification.verified} ` +
        (winner === "player"
          ? settlement.settled
            ? `→ PAID ${CONFIG.potNicks.toLocaleString()} nicks, tx=${settlement.txId}`
            : `→ payout not confirmed (${settlement.reason || settlement.note})`
          : "→ no payout (house won)")
    );
  }

  // Confirm the payouts actually landed at the player address on-chain (give the last tx a few
  // blocks to mine first).
  const submitted = results.filter((r) => r.settlement.settled);
  let confirmation = null;
  if (submitted.length) {
    // The two wallet boots inside confirmReceived (~20s each) are themselves enough settle delay
    // for the last payout to mine (fakenet mines a block every ~2s).
    process.stdout.write("\nconfirming payouts on-chain (watching player address)...\n");
    confirmation = confirmReceived(CONFIG.player);
    console.log(
      `player received: ${confirmation.notes} note(s), ${confirmation.nicks.toLocaleString()} nicks ` +
        `(this run paid ${(submitted.length * CONFIG.potNicks).toLocaleString()} nicks across ${submitted.length} payout(s))`
    );
  }

  // Anyone can recompute + verify the whole receipt chain from public data + the issuer key.
  const chainCheck = verifyFairnessChain(chain.entries);
  const summary = {
    game: "forfeit-flip",
    network: "fakenet",
    house: CONFIG.house,
    player: CONFIG.player,
    potNicks: CONFIG.potNicks,
    rounds: CONFIG.rounds,
    playerWins: results.filter((r) => r.winner === "player").length,
    payoutsSubmitted: results.filter((r) => r.settlement.settled).length,
    settlementModel: "cooperative-house-signed (HTLC-grade; fairness trustless, payout liveness disclosed)",
    playerConfirmedOnChain: confirmation,
    receiptChain: chainCheck,
    results
  };

  writeFileSync(path.join(CONFIG.workDir, "receipt-chain.json"), `${JSON.stringify(chain.entries, null, 2)}\n`);
  writeFileSync(path.join(CONFIG.workDir, "settlement-summary.json"), `${JSON.stringify(summary, null, 2)}\n`);

  console.log(`\nreceipt chain: ${chainCheck.ok ? "VERIFIED" : `BROKEN (${chainCheck.reason})`} ` +
    `(${chainCheck.count} receipts, latestRoot ${String(chainCheck.latestRoot).slice(0, 16)}…)`);
  console.log(`player wins: ${summary.playerWins} · payouts submitted: ${summary.payoutsSubmitted}`);
  console.log(`artifacts: ${path.join(CONFIG.workDir, "receipt-chain.json")} + settlement-summary.json`);

  if (!chainCheck.ok) process.exitCode = 1;
}

main();

#!/usr/bin/env node

// Forfeit Flip — signed fairness receipts + append-only evidence chain.
//
// Self-contained forensic backbone (no dependency on nocksperimental, so the game is
// independently publishable). Mirrors the hardened nocksperimental evidence stack:
//   - Ed25519-signed receipts (node:crypto, deterministic seed -> keypair)
//   - canonical, key-sorted serialization (sign/verify agree byte-for-byte)
//   - hash-chained append-only log (previousRoot -> entryHash -> rootHash)
//   - a pre-reveal secret-redaction GATE so a seed can never be signed into a
//     commit-phase receipt (the fairness property depends on seeds staying hidden
//     until reveal).
//
// Forensic guarantee: given the published chain + the issuer public key, ANYONE
// recomputes every link and verifies every signature from public data. Back-dating a
// commit to match an outcome, or editing any round, breaks both the hash chain and the
// signature. Disputes are resolved by recomputation, not trust.

import { createHash, createPrivateKey, createPublicKey, sign, verify, randomBytes } from "node:crypto";

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

// ---- Ed25519 (deterministic from a 32-byte seed) ----------------------------

export function privKeyFromSeed(seedHex) {
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seedHex, "hex")]), format: "der", type: "pkcs8" });
}
export function publicKeyFromSeed(seedHex) {
  return createPublicKey(privKeyFromSeed(seedHex)).export({ format: "der", type: "spki" }).toString("base64");
}

// ---- canonical serialization (key-sorted; matches sign & verify) ------------

export function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256Hex(str) {
  return `sha256:${createHash("sha256").update(str).digest("hex")}`;
}
function signPayload(payload, seedHex) {
  return sign(null, Buffer.from(canonicalize(payload), "utf8"), privKeyFromSeed(seedHex)).toString("base64");
}
function verifyPayload(payload, sigB64, spkiB64) {
  try {
    const pub = createPublicKey({ key: Buffer.from(spkiB64, "base64"), format: "der", type: "spki" });
    return verify(null, Buffer.from(canonicalize(payload), "utf8"), pub, Buffer.from(sigB64, "base64"));
  } catch {
    return false;
  }
}

// ---- pre-reveal secret-redaction gate ---------------------------------------

// Forfeit Flip's fairness depends on seeds staying secret until reveal. A commit-phase
// receipt MUST NOT carry a seed. This is a hard gate at sign time (fail-closed), mirroring
// nocksperimental's secret-field scrubber: never let a secret be signed/published early.
//
// We match by secret-NAMED key (seed/secret/preimage/private/mnemonic/passphrase), NOT by value
// shape: a public commitment (commitHouse/commitClient) is a long hex string indistinguishable by
// shape from a seed, so a value-shape rule both false-positives on commitments and false-negatives
// on differently-shaped secrets. Naming is the reliable signal (same conclusion reached in the
// nocksperimental peek-reveals-no-secret invariant).
const SECRET_KEY = /seed|secret|preimage|private|mnemonic|passphrase/i;
export function assertNoUnrevealedSecret(body) {
  const phase = body.phase;
  if (phase === "reveal" || phase === "resolved") return; // seeds are public post-reveal
  const walk = (v, keyPath) => {
    if (typeof v === "string" && SECRET_KEY.test(keyPath)) {
      throw new Error(`fail-closed: pre-reveal receipt would leak a secret at "${keyPath}"`);
    }
    if (v && typeof v === "object") for (const [k, val] of Object.entries(v)) walk(val, `${keyPath}.${k}`);
  };
  walk(body, "body");
}

// ---- append-only fairness chain ---------------------------------------------

export class FairnessChain {
  constructor(issuerSeedHex) {
    this.issuerSeed = issuerSeedHex;
    this.issuerKey = publicKeyFromSeed(issuerSeedHex);
    this.entries = [];
  }
  get latestRoot() {
    return this.entries.length ? this.entries[this.entries.length - 1].rootHash : "genesis";
  }
  // body: the round's PUBLIC data (commit-phase: commitments only; reveal-phase: + seeds/outcome)
  append(body) {
    assertNoUnrevealedSecret(body); // fail-closed before anything is signed
    const previousRoot = this.latestRoot;
    const entryHash = sha256Hex(canonicalize(body));
    const rootHash = sha256Hex(`${previousRoot}|${entryHash}`);
    const signedPayload = { body, previousRoot, entryHash, rootHash, issuerKey: this.issuerKey };
    const signature = signPayload(signedPayload, this.issuerSeed);
    const entry = { body, previousRoot, entryHash, rootHash, issuerKey: this.issuerKey, signature };
    this.entries.push(entry);
    return entry;
  }
}

// Independent verification from public data alone (no chain object, no secrets).
export function verifyFairnessChain(entries) {
  let prev = "genesis";
  for (let i = 0; i < entries.length; i += 1) {
    const e = entries[i];
    const at = e.body?.roundId ?? `index-${i}`;
    const entryHash = sha256Hex(canonicalize(e.body));
    if (entryHash !== e.entryHash) return { ok: false, reason: "entryHash mismatch (round edited)", at };
    if (e.previousRoot !== prev) return { ok: false, reason: "broken append-only link", at };
    const rootHash = sha256Hex(`${prev}|${entryHash}`);
    if (rootHash !== e.rootHash) return { ok: false, reason: "rootHash mismatch", at };
    const signedPayload = { body: e.body, previousRoot: e.previousRoot, entryHash: e.entryHash, rootHash: e.rootHash, issuerKey: e.issuerKey };
    if (!verifyPayload(signedPayload, e.signature, e.issuerKey)) return { ok: false, reason: "invalid Ed25519 signature", at };
    prev = e.rootHash;
  }
  return { ok: true, count: entries.length, latestRoot: prev };
}

// ---- self-test ---------------------------------------------------------------

function main() {
  const fails = [];
  const ok = (cond, label) => { if (!cond) fails.push(label); console.log(`  ${cond ? "PASS" : "FAIL"}  ${label}`); };

  const ISSUER_SEED = "11".repeat(32); // dev issuer seed (public; mainnet uses a real env seed)
  const chain = new FairnessChain(ISSUER_SEED);

  console.log("1) Emit signed fairness receipts for 5 rounds into the append-only chain:");
  for (let n = 0; n < 5; n += 1) {
    // commit phase (no seeds) then resolved phase (seeds public) — two receipts per round
    chain.append({ roundId: `round-${n}`, phase: "commit", nonce: n, commitHouse: sha256Hex(`h${n}`), commitClient: sha256Hex(`c${n}`) });
    chain.append({ roundId: `round-${n}`, phase: "resolved", nonce: n, commitHouse: sha256Hex(`h${n}`), commitClient: sha256Hex(`c${n}`), serverSeed: `${n}`.repeat(64).slice(0, 64), clientSeed: `${n}`.repeat(64).slice(0, 64), outcome: n % 2 });
  }
  ok(chain.entries.length === 10, "10 receipts appended");

  console.log("\n2) Anyone verifies the whole chain from public data + the issuer key:");
  const v = verifyFairnessChain(chain.entries);
  ok(v.ok && v.count === 10, `chain verifies: ${JSON.stringify(v)}`);

  console.log("\n3) Tamper detection — editing a resolved round breaks hash + signature:");
  const tampered = chain.entries.map((e) => ({ ...e, body: { ...e.body } }));
  tampered[3].body.outcome = tampered[3].body.outcome ? 0 : 1; // flip a recorded outcome
  const vt = verifyFairnessChain(tampered);
  ok(!vt.ok, `tampered chain rejected: ${vt.reason} @ ${vt.at}`);

  console.log("\n4) Append-only — deleting/reordering a round breaks the link chain:");
  const reordered = [chain.entries[0], chain.entries[2], ...chain.entries.slice(1, 2), ...chain.entries.slice(3)];
  const vr = verifyFairnessChain(reordered);
  ok(!vr.ok, `reordered chain rejected: ${vr.reason} @ ${vr.at}`);

  console.log("\n5) Fail-closed redaction — a commit-phase receipt cannot carry a seed:");
  let blocked = false;
  try {
    chain.append({ roundId: "evil", phase: "commit", nonce: 99, serverSeed: "ab".repeat(32) });
  } catch (e) {
    blocked = /leak a secret/.test(e.message);
  }
  ok(blocked, "pre-reveal receipt carrying a seed is rejected before signing");

  console.log(`\n${fails.length === 0 ? "fairness-receipt: all assertions passed" : `FAILURES: ${fails.join(", ")}`}`);
  if (fails.length) process.exitCode = 1;
}

if (import.meta.url === `file://${process.argv[1]}`) main();

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * The offline chain verifier. PURE — no network, no database. The
 * single source of chain-verification truth: the `zarel verify` CLI and any
 * evidence-bundle verifier wrap this one function. Ed25519 is verified with `node:crypto`
 * (no libsodium dependency here); a golden interop test proves parity with the
 * libsodium signer.
 */

import { createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { type ChainedEventContent } from './event-encode.js';
import { GENESIS, chainHash, buildCheckpointMessage, checkpointHash, type CheckpointSignable, type TerminalDescriptor } from './chain-hash.js';

export interface TrustKey {
    readonly kid: string;
    readonly publicKeyB64: string; // base64url (URLSAFE_NO_PADDING) raw 32-byte Ed25519 key
    // Optional validity window (ISO-8601). Absent ⇒ no bound on that edge, which
    // keeps windowless trust keys verifying exactly as they always have.
    // The cutoff is sound ONLY for honest rotation/decommission — `signed_at` is
    // operator-controlled, so it orders honest retirements but does NOT defend
    // against a compromised key (which can backdate `signed_at`); that needs an
    // external time anchor (an RFC 3161 TSA timestamp).
    readonly validFrom?: string | null; // inclusive lower bound: signed_at >= validFrom
    readonly validUntil?: string | null; // exclusive upper bound: signed_at < validUntil
    readonly revokedAt?: string | null; // exclusive cutoff: signed_at < revokedAt
}

export interface VerifierEventRow {
    readonly seq: number;
    readonly prevHash: Uint8Array;
    readonly eventHash: Uint8Array;
    readonly content: ChainedEventContent;
    readonly deletedAt: string | null;
}

export interface VerifierCheckpoint {
    readonly tenantName: string;
    readonly logName: string;
    readonly seq: number;
    readonly headHash: Uint8Array;
    readonly prevCheckpointHash: Uint8Array | null;
    readonly checkpointHash: Uint8Array;
    readonly windowId: string;
    readonly kid: string;
    readonly signatureB64: string;
    readonly signedAt: string;
    // Terminal seal: the V2 signed fields. Absent ⇒ V1 checkpoint
    // (verified exactly as before — dual-version dispatch). Present ⇒ the
    // signature covers them, so a verified terminal descriptor is authentic.
    readonly schemaVersion?: number;
    readonly terminal?: TerminalDescriptor;
}

export type VerifyFailureReason =
    | 'event_hash_mismatch'
    | 'prev_hash_mismatch'
    | 'seq_gap'
    | 'seq_duplicate'
    | 'soft_deleted_event'
    | 'checkpoint_chain_broken'
    | 'checkpoint_signature_invalid'
    | 'checkpoint_anchor_mismatch'
    | 'no_verified_checkpoint'
    | 'unknown_kid'
    | 'kid_not_yet_valid'
    | 'kid_expired'
    | 'kid_revoked';

export interface Verdict {
    readonly ok: boolean;
    readonly coveredRange: { from: number; to: number } | null;
    readonly checkpointsVerified: number;
    readonly keyKid: string | null;
    readonly failures: ReadonlyArray<{ seq: number; reason: VerifyFailureReason }>;
    /**
     * The terminal descriptor of a SIGNATURE-VERIFIED terminal
     * checkpoint in this chain, or null. Because it is signature-covered, a
     * non-null value is an authentic offline proof that the chain was terminally
     * sealed (or was empty). Only set when the terminal checkpoint's signature +
     * anchor verified — never trusted from an unverified checkpoint.
     */
    readonly terminal: TerminalDescriptor | null;
}

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false;
    }
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
}

/**
 * Enforce a trust key's validity window against a checkpoint's `signed_at`.
 * Returns the specific failure reason, or null when the timestamp is inside the
 * window (or no window is declared). Bounds are compared as instants (epoch ms),
 * not lexicographically, so manifests with varied ISO precision/offset still
 * compare correctly.
 *
 * Fail-closed: if a key declares ANY window/revocation bound but `signed_at` is
 * unparseable, the checkpoint is rejected (we cannot place it inside the window)
 * — a windowed key with no usable timestamp is never given the benefit of the
 * doubt. `signed_at` is the artifact-under-test's field,
 * so failing closed here is the security-relevant edge. A window-less key is
 * unaffected (no bound → null) and verifies exactly as before. An unparseable
 * *bound* is skipped per-edge: the trust-keys are the operator-supplied trust
 * anchor (like a CA bundle), not the artifact under test, so a malformed bound is
 * operator misconfiguration (to be caught when the trust keys are published),
 * not an attack surface; the other edges still apply.
 */
function keyWindowFailure(key: TrustKey, signedAt: string): VerifyFailureReason | null {
    const hasBound = key.validFrom != null || key.validUntil != null || key.revokedAt != null;
    const at = Date.parse(signedAt);
    if (Number.isNaN(at)) {
        if (!hasBound) {
            return null;
        }
        // Most-severe-first: we cannot prove the checkpoint predates retirement.
        if (key.revokedAt != null) {
            return 'kid_revoked';
        }
        if (key.validUntil != null) {
            return 'kid_expired';
        }
        return 'kid_not_yet_valid';
    }
    if (key.validFrom != null) {
        const from = Date.parse(key.validFrom);
        if (!Number.isNaN(from) && at < from) {
            return 'kid_not_yet_valid';
        }
    }
    if (key.validUntil != null) {
        const until = Date.parse(key.validUntil);
        if (!Number.isNaN(until) && at >= until) {
            return 'kid_expired';
        }
    }
    if (key.revokedAt != null) {
        const revoked = Date.parse(key.revokedAt);
        if (!Number.isNaN(revoked) && at >= revoked) {
            return 'kid_revoked';
        }
    }
    return null;
}

function publicKeyFromRaw(raw: Buffer): KeyObject {
    return createPublicKey({
        key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
        format: 'der',
        type: 'spki',
    });
}

/**
 * Verify an Ed25519 signature (base64url) over `message` with a RAW 32-byte
 * public key. The SINGLE Ed25519 checkpoint-verification primitive (SPKI-wrap +
 * `verify(null, …)` — `null` is required for Ed25519). Fails closed to `false` on
 * any malformed key/signature. Exported so a caller that checks a single
 * checkpoint signature reuses it rather than re-deriving the SPKI prefix + crypto
 * call (one place to change the key encoding). `verifyChain` uses it internally too.
 */
export function verifyEd25519Raw(message: Uint8Array, publicKeyRaw: Uint8Array, signatureB64: string): boolean {
    try {
        return cryptoVerify(
            null,
            Buffer.from(message),
            publicKeyFromRaw(Buffer.from(publicKeyRaw)),
            Buffer.from(signatureB64, 'base64url'),
        );
    } catch {
        return false;
    }
}

function toSignable(cp: VerifierCheckpoint): CheckpointSignable {
    // Reproduce the EXACT signed message. V1 checkpoints (no schemaVersion) omit
    // schema_version + terminal so `canonicalJson` drops them → the shipped bytes.
    // V2 (terminal) checkpoints re-include them so the signature reproduces and
    // the terminal descriptor is signature-covered.
    return {
        tenant_name: cp.tenantName,
        log_name: cp.logName,
        seq: cp.seq,
        head_hash_b64: Buffer.from(cp.headHash).toString('base64url'),
        prev_checkpoint_hash_b64: cp.prevCheckpointHash
            ? Buffer.from(cp.prevCheckpointHash).toString('base64url')
            : null,
        window_id: cp.windowId,
        signed_at: cp.signedAt,
        kid: cp.kid,
        ...(cp.schemaVersion !== undefined ? { schema_version: cp.schemaVersion } : {}),
        ...(cp.terminal !== undefined ? { terminal: cp.terminal } : {}),
    };
}

/**
 * Recompute the chain over the supplied segment + checkpoints and validate it
 * against the trust keys. Reports each anomaly at the exact `seq`. Events after
 * the last checkpoint are valid-but-unattested (reflected in `coveredRange`,
 * not a failure).
 */
export function verifyChain(input: {
    events: ReadonlyArray<VerifierEventRow>;
    checkpoints: ReadonlyArray<VerifierCheckpoint>;
    keys: ReadonlyArray<TrustKey>;
}): Verdict {
    const failures: { seq: number; reason: VerifyFailureReason }[] = [];
    const keyByKid = new Map(input.keys.map((k) => [k.kid, k]));

    // 1. Sort events by seq (verifier is order-tolerant on input). Checkpoints
    // sort by (seq, signed_at): a heartbeat checkpoint (one signed for a window in
    // which no new event was appended) shares its predecessor's seq, so
    // signed_at is the chain-link tiebreaker — without it same-seq checkpoints
    // could be checked out of link order and spuriously fail.
    const events = [...input.events].sort((a, b) => a.seq - b.seq);
    const checkpoints = [...input.checkpoints].sort(
        (a, b) => a.seq - b.seq || a.signedAt.localeCompare(b.signedAt),
    );

    let keyKid: string | null = null;
    let checkpointsVerified = 0;
    // Checkpoints whose Ed25519 signature verified — the terminal descriptor is
    // trusted (offline-provable) ONLY for one of these (it is signature-covered).
    const sigVerified = new Set<VerifierCheckpoint>();

    // 2. Verify each checkpoint signature + 3. the checkpoint-chain links.
    let prevCheckpointHash: Uint8Array | null = null;
    let firstCheckpoint = true;
    for (const cp of checkpoints) {
        keyKid = cp.kid;
        const key = keyByKid.get(cp.kid);
        if (!key) {
            failures.push({ seq: cp.seq, reason: 'unknown_kid' });
            continue;
        }
        // Validity-window enforcement: a checkpoint signed outside the
        // resolved key's window is rejected with the precise reason, mirroring
        // the unknown_kid path (skip signature + link checks; one clear reason).
        const windowReason = keyWindowFailure(key, cp.signedAt);
        if (windowReason) {
            failures.push({ seq: cp.seq, reason: windowReason });
            continue;
        }
        const sigOk = verifyEd25519Raw(
            buildCheckpointMessage(toSignable(cp)),
            Buffer.from(key.publicKeyB64, 'base64url'),
            cp.signatureB64,
        );
        if (!sigOk) {
            failures.push({ seq: cp.seq, reason: 'checkpoint_signature_invalid' });
        } else {
            checkpointsVerified += 1;
            sigVerified.add(cp);
        }

        // checkpoint-chain link: each prev_checkpoint_hash must equal the prior checkpoint's hash.
        const expectedPrev = firstCheckpoint ? null : prevCheckpointHash;
        const linkOk =
            (expectedPrev === null && cp.prevCheckpointHash === null) ||
            (expectedPrev !== null &&
                cp.prevCheckpointHash !== null &&
                bytesEqual(expectedPrev, cp.prevCheckpointHash));
        if (!linkOk) {
            failures.push({ seq: cp.seq, reason: 'checkpoint_chain_broken' });
        }
        // Link forward on the RECOMPUTED hash of the signed fields — never the
        // caller-supplied `cp.checkpointHash`, which is not a signed field and so
        // is forgeable. Trusting it would let an attacker drop a genuine
        // intermediate checkpoint and overwrite this field to bridge the gap.
        prevCheckpointHash = checkpointHash(toSignable(cp));
        firstCheckpoint = false;
    }

    // 4. Recompute the event chain.
    let expectedSeq = events.length > 0 ? events[0].seq : 0;
    let priorHash: Uint8Array | null = null;
    const headBySeq = new Map<number, Uint8Array>();
    for (const ev of events) {
        if (ev.seq < expectedSeq) {
            failures.push({ seq: ev.seq, reason: 'seq_duplicate' });
        } else if (ev.seq > expectedSeq) {
            failures.push({ seq: ev.seq, reason: 'seq_gap' });
        }
        expectedSeq = ev.seq + 1;

        const recomputed = chainHash({ content: ev.content, prevHash: ev.prevHash, seq: ev.seq });
        if (!bytesEqual(recomputed, ev.eventHash)) {
            failures.push({ seq: ev.seq, reason: 'event_hash_mismatch' });
        }
        if (priorHash !== null && !bytesEqual(priorHash, ev.prevHash)) {
            failures.push({ seq: ev.seq, reason: 'prev_hash_mismatch' });
        }
        if (ev.deletedAt !== null) {
            failures.push({ seq: ev.seq, reason: 'soft_deleted_event' });
        }
        // The recorded event_hash is the head AFTER this event — recompute, do not trust the stored one.
        headBySeq.set(ev.seq, recomputed);
        priorHash = recomputed;
    }

    // 5. Anchor each checkpoint to the recomputed head at its seq. A checkpoint
    // whose seq is not reconstructable from the supplied events (missing/
    // truncated events) is an anchor failure — the bundle does not actually
    // verify what the checkpoint attests; we must not pass it silently.
    //
    // Empty-chain terminal: a signed `empty_chain` terminal attests
    // seq 0 / GENESIS with NO events, so there is no recomputed head to anchor to
    // — its anchor IS GENESIS at seq 0. Because `terminal.kind` is signature-
    // covered, only a genuinely-signed empty-chain seal can take this branch.
    const anchorVerified = new Set<VerifierCheckpoint>();
    for (const cp of checkpoints) {
        if (cp.terminal?.kind === 'empty_chain') {
            if (cp.seq === 0 && bytesEqual(cp.headHash, GENESIS)) {
                anchorVerified.add(cp);
            } else {
                failures.push({ seq: cp.seq, reason: 'checkpoint_anchor_mismatch' });
            }
            continue;
        }
        const recomputedHead = headBySeq.get(cp.seq);
        if (!recomputedHead || !bytesEqual(recomputedHead, cp.headHash)) {
            failures.push({ seq: cp.seq, reason: 'checkpoint_anchor_mismatch' });
        } else {
            anchorVerified.add(cp);
        }
    }

    // The offline-provable terminal descriptor: a checkpoint whose signature AND
    // anchor verified and that carries a terminal marker. Prefer 'sealed' over a
    // co-present empty-chain (a sealed data-chain is the stronger statement).
    let terminal: TerminalDescriptor | null = null;
    for (const cp of checkpoints) {
        if (cp.terminal && sigVerified.has(cp) && anchorVerified.has(cp)) {
            terminal = cp.terminal;
            if (cp.terminal.kind === 'sealed') break;
        }
    }

    // 6. Attestation gate: the Ed25519 checkpoint signatures are the ONLY
    // cryptographic anchor. With zero verified checkpoints the verifier has proven
    // self-consistency, not authenticity — a forged fresh chain (every eventHash
    // recomputed) or an empty input would otherwise pass. `ok` requires at least
    // one signature-verified checkpoint (seq -1 marks this chain-level failure).
    if (checkpointsVerified === 0) {
        failures.push({ seq: -1, reason: 'no_verified_checkpoint' });
    }

    const coveredRange =
        events.length > 0 ? { from: events[0].seq, to: events[events.length - 1].seq } : null;

    return {
        ok: failures.length === 0,
        coveredRange,
        checkpointsVerified,
        keyKid,
        failures,
        terminal,
    };
}

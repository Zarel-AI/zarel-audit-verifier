// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * verifyChain tamper matrix. A clean chain verifies
 * GREEN; every tampering class (edit / delete / reorder / insertion / dropped
 * checkpoint / bad signature / soft-delete / anchor) fails at the EXACT seq
 * with the right reason.
 */

import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import {
    verifyChain,
    chainHash,
    checkpointHash,
    buildCheckpointMessage,
    GENESIS,
    type ChainedEventContent,
    type VerifierEventRow,
    type VerifierCheckpoint,
    type TrustKey,
    type CheckpointSignable,
} from '../src/index.js';

const ED25519_SPKI_PREFIX_LEN = 12;

function makeKey(): { trust: TrustKey; sign: (m: Uint8Array) => string } {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(ED25519_SPKI_PREFIX_LEN);
    return {
        trust: { kid: 'k_test', publicKeyB64: Buffer.from(raw).toString('base64url') },
        sign: (m) => Buffer.from(cryptoSign(null, m, privateKey)).toString('base64url'),
    };
}

function content(seq: number): ChainedEventContent {
    return {
        tenant_name: 'demo_tenant',
        instance_id: '11111111-1111-1111-1111-111111111111',
        field_name: 'status',
        from_state: `s${seq - 1}`,
        to_state: `s${seq}`,
        actor: 'alice',
        actor_role: 'owner',
        payload: { step: seq },
        policy_version: 'v1',
        rule_evaluations: null,
    };
}

/** Build a valid chain of `n` events. */
function buildChain(n: number): VerifierEventRow[] {
    const rows: VerifierEventRow[] = [];
    let prev = GENESIS;
    for (let seq = 1; seq <= n; seq++) {
        const c = content(seq);
        const eventHash = chainHash({ content: c, prevHash: prev, seq });
        rows.push({ seq, prevHash: prev, eventHash, content: c, deletedAt: null });
        prev = eventHash;
    }
    return rows;
}

function signCheckpoint(
    key: ReturnType<typeof makeKey>,
    events: VerifierEventRow[],
    seq: number,
    prevCheckpointHash: Uint8Array | null,
): VerifierCheckpoint {
    const head = events.find((e) => e.seq === seq)!.eventHash;
    const signable: CheckpointSignable = {
        tenant_name: 'demo_tenant',
        log_name: 'state_machine',
        seq,
        head_hash_b64: Buffer.from(head).toString('base64url'),
        prev_checkpoint_hash_b64: prevCheckpointHash
            ? Buffer.from(prevCheckpointHash).toString('base64url')
            : null,
        window_id: `2026061400-${seq}`,
        signed_at: '2026-06-14T01:00:00.000Z',
        kid: key.trust.kid,
    };
    return {
        tenantName: signable.tenant_name,
        logName: signable.log_name,
        seq,
        headHash: head,
        prevCheckpointHash,
        checkpointHash: checkpointHash(signable),
        windowId: signable.window_id,
        kid: signable.kid,
        signatureB64: key.sign(buildCheckpointMessage(signable)),
        signedAt: signable.signed_at,
    };
}

describe('verifyChain', () => {
    it('verifies a clean chain with a valid checkpoint → GREEN', () => {
        const key = makeKey();
        const events = buildChain(5);
        const cp = signCheckpoint(key, events, 5, null);
        const v = verifyChain({ events, checkpoints: [cp], keys: [key.trust] });
        expect(v.ok).toBe(true);
        expect(v.coveredRange).toEqual({ from: 1, to: 5 });
        expect(v.checkpointsVerified).toBe(1);
        expect(v.failures).toEqual([]);
    });

    it('detects an edited event at the exact seq', () => {
        const key = makeKey();
        const events = buildChain(5);
        // tamper seq 3 content without recomputing its hash
        events[2] = { ...events[2], content: { ...events[2].content, to_state: 'HACKED' } };
        const v = verifyChain({ events, checkpoints: [signCheckpoint(key, buildChain(5), 5, null)], keys: [key.trust] });
        expect(v.ok).toBe(false);
        expect(v.failures.some((f) => f.seq === 3 && f.reason === 'event_hash_mismatch')).toBe(true);
    });

    it('detects a deleted event as a seq gap', () => {
        const key = makeKey();
        const events = buildChain(5).filter((e) => e.seq !== 3);
        const v = verifyChain({ events, checkpoints: [], keys: [key.trust] });
        expect(v.ok).toBe(false);
        expect(v.failures.some((f) => f.seq === 4 && f.reason === 'seq_gap')).toBe(true);
    });

    it('detects a reordered/relinked event via prev_hash mismatch', () => {
        const key = makeKey();
        const events = buildChain(5);
        // give seq 4 a wrong prevHash (break the link) but keep its own hash consistent with that wrong prev
        const wrongPrev = GENESIS;
        const c4 = events[3].content;
        events[3] = {
            seq: 4,
            prevHash: wrongPrev,
            eventHash: chainHash({ content: c4, prevHash: wrongPrev, seq: 4 }),
            content: c4,
            deletedAt: null,
        };
        const v = verifyChain({ events, checkpoints: [], keys: [key.trust] });
        expect(v.failures.some((f) => f.seq === 4 && f.reason === 'prev_hash_mismatch')).toBe(true);
    });

    it('detects an inserted duplicate seq', () => {
        const key = makeKey();
        const events = buildChain(5);
        events.push({ ...events[2] }); // duplicate seq 3
        const v = verifyChain({ events, checkpoints: [], keys: [key.trust] });
        expect(v.failures.some((f) => f.reason === 'seq_duplicate')).toBe(true);
    });

    it('flags a soft-deleted but chained event as an anomaly', () => {
        const key = makeKey();
        const events = buildChain(5);
        events[1] = { ...events[1], deletedAt: '2026-06-14T02:00:00.000Z' };
        const v = verifyChain({ events, checkpoints: [], keys: [key.trust] });
        expect(v.failures.some((f) => f.seq === 2 && f.reason === 'soft_deleted_event')).toBe(true);
    });

    it('detects a dropped intermediate checkpoint via the checkpoint chain', () => {
        const key = makeKey();
        const events = buildChain(6);
        const cp1 = signCheckpoint(key, events, 2, null);
        const cp2 = signCheckpoint(key, events, 4, cp1.checkpointHash);
        const cp3 = signCheckpoint(key, events, 6, cp2.checkpointHash);
        // drop cp2 → cp3.prevCheckpointHash no longer links
        const v = verifyChain({ events, checkpoints: [cp1, cp3], keys: [key.trust] });
        expect(v.failures.some((f) => f.seq === 6 && f.reason === 'checkpoint_chain_broken')).toBe(true);
    });

    it('detects a bad checkpoint signature', () => {
        const key = makeKey();
        const events = buildChain(5);
        const cp = signCheckpoint(key, events, 5, null);
        const tampered = { ...cp, signatureB64: Buffer.from('not-a-valid-signature-bytes-000000000000000000000000000000000000').toString('base64url') };
        const v = verifyChain({ events, checkpoints: [tampered], keys: [key.trust] });
        expect(v.failures.some((f) => f.seq === 5 && f.reason === 'checkpoint_signature_invalid')).toBe(true);
    });

    it('detects an unknown kid', () => {
        const key = makeKey();
        const events = buildChain(3);
        const cp = signCheckpoint(key, events, 3, null);
        const v = verifyChain({ events, checkpoints: [cp], keys: [] });
        expect(v.failures.some((f) => f.seq === 3 && f.reason === 'unknown_kid')).toBe(true);
    });

    it('detects a checkpoint anchored to the wrong head', () => {
        const key = makeKey();
        const events = buildChain(5);
        const cp = signCheckpoint(key, events, 5, null);
        // forge a checkpoint whose signed head_hash does not match the recomputed head
        const wrongHead = GENESIS;
        const signable: CheckpointSignable = {
            tenant_name: 'demo_tenant',
            log_name: 'state_machine',
            seq: 5,
            head_hash_b64: Buffer.from(wrongHead).toString('base64url'),
            prev_checkpoint_hash_b64: null,
            window_id: 'w',
            signed_at: '2026-06-14T01:00:00.000Z',
            kid: key.trust.kid,
        };
        const forged: VerifierCheckpoint = {
            ...cp,
            headHash: wrongHead,
            checkpointHash: checkpointHash(signable),
            windowId: 'w',
            signatureB64: key.sign(buildCheckpointMessage(signable)),
        };
        const v = verifyChain({ events, checkpoints: [forged], keys: [key.trust] });
        expect(v.failures.some((f) => f.seq === 5 && f.reason === 'checkpoint_anchor_mismatch')).toBe(true);
    });

    it('treats events after the last checkpoint as valid-but-unattested (not a failure)', () => {
        const key = makeKey();
        const events = buildChain(5);
        const cp = signCheckpoint(key, events, 3, null);
        const v = verifyChain({ events, checkpoints: [cp], keys: [key.trust] });
        expect(v.ok).toBe(true);
        expect(v.coveredRange).toEqual({ from: 1, to: 5 });
    });

    it('rejects a self-consistent but UNATTESTED chain — no verified checkpoint is not ok', () => {
        // A forged fresh chain: every eventHash recomputes correctly, but nothing
        // is cryptographically signed. Self-consistency is not authenticity.
        const events = buildChain(5);
        const v = verifyChain({ events, checkpoints: [], keys: [] });
        expect(v.ok).toBe(false);
        expect(v.checkpointsVerified).toBe(0);
        expect(v.failures.some((f) => f.reason === 'no_verified_checkpoint')).toBe(true);
    });

    it('rejects empty input — nothing attested', () => {
        const v = verifyChain({ events: [], checkpoints: [], keys: [] });
        expect(v.ok).toBe(false);
        expect(v.failures.some((f) => f.reason === 'no_verified_checkpoint')).toBe(true);
    });

    it('recomputes the checkpoint link hash so a forged checkpointHash cannot hide a dropped checkpoint', () => {
        const key = makeKey();
        const events = buildChain(6);
        const cp1 = signCheckpoint(key, events, 2, null);
        const cp2 = signCheckpoint(key, events, 4, cp1.checkpointHash);
        const cp3 = signCheckpoint(key, events, 6, cp2.checkpointHash);
        // Attacker drops cp2 and forges cp1's UNSIGNED `checkpointHash` field to
        // equal cp2's hash (what cp3 links to). A verifier that trusts the input
        // field would accept [cp1, cp3] seamlessly; one that recomputes the link
        // from cp1's SIGNED fields sees the break.
        const forgedCp1 = { ...cp1, checkpointHash: cp2.checkpointHash };
        const v = verifyChain({ events, checkpoints: [forgedCp1, cp3], keys: [key.trust] });
        expect(v.ok).toBe(false);
        expect(v.failures.some((f) => f.seq === 6 && f.reason === 'checkpoint_chain_broken')).toBe(true);
    });

    it('heartbeat: same-seq checkpoints verify regardless of input order (sorted by signed_at)', () => {
        const key = makeKey();
        const events = buildChain(3);
        // Two heartbeat checkpoints at the SAME seq=3 across windows (no new
        // events): cpB links cpA. Build with distinct signed_at, feed REVERSED —
        // verifyChain must re-sort by (seq, signed_at) and still verify GREEN.
        const cpA = signCheckpoint(key, events, 3, null);
        const signableB: CheckpointSignable = {
            tenant_name: 'demo_tenant',
            log_name: 'state_machine',
            seq: 3,
            head_hash_b64: Buffer.from(events[2].eventHash).toString('base64url'),
            prev_checkpoint_hash_b64: Buffer.from(cpA.checkpointHash).toString('base64url'),
            window_id: 'w2',
            signed_at: '2026-06-14T05:00:00.000Z', // later than cpA's signCheckpoint default
            kid: key.trust.kid,
        };
        const cpB: VerifierCheckpoint = {
            tenantName: 'demo_tenant',
            logName: 'state_machine',
            seq: 3,
            headHash: events[2].eventHash,
            prevCheckpointHash: cpA.checkpointHash,
            checkpointHash: checkpointHash(signableB),
            windowId: 'w2',
            kid: key.trust.kid,
            signatureB64: key.sign(buildCheckpointMessage(signableB)),
            signedAt: signableB.signed_at,
        };
        const v = verifyChain({ events, checkpoints: [cpB, cpA], keys: [key.trust] });
        expect(v.ok).toBe(true);
        expect(v.checkpointsVerified).toBe(2);
    });
});

// Validity-window enforcement on the resolved trust key. The checkpoint's
// signCheckpoint default signed_at is fixed at SIGNED below; each case varies the
// key's window around that instant. Cutoff is "on or after" for valid_until /
// revoked_at (exclusive upper bound) and inclusive for valid_from.
describe('verifyChain — kid validity window', () => {
    const SIGNED = '2026-06-14T01:00:00.000Z'; // signCheckpoint default signed_at

    function verifyWithWindow(window: Partial<TrustKey>): ReturnType<typeof verifyChain> {
        const key = makeKey();
        const events = buildChain(3);
        const cp = signCheckpoint(key, events, 3, null);
        return verifyChain({ events, checkpoints: [cp], keys: [{ ...key.trust, ...window }] });
    }

    it('GREEN: signed_at strictly inside [valid_from, valid_until), not revoked', () => {
        const v = verifyWithWindow({
            validFrom: '2026-06-01T00:00:00.000Z',
            validUntil: '2026-07-01T00:00:00.000Z',
            revokedAt: null,
        });
        expect(v.ok).toBe(true);
        expect(v.checkpointsVerified).toBe(1);
        expect(v.failures).toEqual([]);
    });

    it('GREEN: archived kid (rotated out) still verifies its pre-retirement history', () => {
        // Key rotation: the operator rotated to a new active key; the old kid keeps a window
        // whose valid_until is AFTER this checkpoint's signed_at.
        const v = verifyWithWindow({
            validFrom: '2026-06-01T00:00:00.000Z',
            validUntil: '2026-06-20T00:00:00.000Z', // retired later than SIGNED
        });
        expect(v.ok).toBe(true);
    });

    it('RED: signed_at on/after valid_until → kid_expired', () => {
        const v = verifyWithWindow({ validUntil: '2026-06-14T00:00:00.000Z' }); // before SIGNED
        expect(v.ok).toBe(false);
        expect(v.failures.some((f) => f.seq === 3 && f.reason === 'kid_expired')).toBe(true);
        expect(v.checkpointsVerified).toBe(0);
    });

    it('RED: signed_at on/after revoked_at → kid_revoked', () => {
        const v = verifyWithWindow({ revokedAt: '2026-06-14T00:30:00.000Z' }); // before SIGNED
        expect(v.ok).toBe(false);
        expect(v.failures.some((f) => f.seq === 3 && f.reason === 'kid_revoked')).toBe(true);
    });

    it('RED: signed_at before valid_from → kid_not_yet_valid', () => {
        const v = verifyWithWindow({ validFrom: '2026-06-14T02:00:00.000Z' }); // after SIGNED
        expect(v.ok).toBe(false);
        expect(v.failures.some((f) => f.seq === 3 && f.reason === 'kid_not_yet_valid')).toBe(true);
    });

    it('boundary: signed_at == valid_from passes (inclusive lower bound)', () => {
        const v = verifyWithWindow({ validFrom: SIGNED });
        expect(v.ok).toBe(true);
    });

    it('boundary: signed_at == valid_until fails (exclusive upper bound)', () => {
        const v = verifyWithWindow({ validUntil: SIGNED });
        expect(v.failures.some((f) => f.reason === 'kid_expired')).toBe(true);
    });

    it('boundary: signed_at == revoked_at fails (exclusive cutoff)', () => {
        const v = verifyWithWindow({ revokedAt: SIGNED });
        expect(v.failures.some((f) => f.reason === 'kid_revoked')).toBe(true);
    });

    it('backward compat: windowless trust key verifies exactly as before', () => {
        // No validFrom/validUntil/revokedAt at all → no window check, GREEN.
        const v = verifyWithWindow({});
        expect(v.ok).toBe(true);
        expect(v.checkpointsVerified).toBe(1);
    });

    it('backward compat: explicit nulls are treated as no bound', () => {
        const v = verifyWithWindow({ validFrom: null, validUntil: null, revokedAt: null });
        expect(v.ok).toBe(true);
    });

    // Fail-closed: a windowed key whose checkpoint signed_at cannot be parsed must
    // be rejected (we cannot place it inside the window), not silently skipped.
    function verifyWithUnparseableSignedAt(window: Partial<TrustKey>): ReturnType<typeof verifyChain> {
        const key = makeKey();
        const events = buildChain(3);
        const cp = signCheckpoint(key, events, 3, null);
        const broken = { ...cp, signedAt: 'not-a-timestamp' };
        return verifyChain({ events, checkpoints: [broken], keys: [{ ...key.trust, ...window }] });
    }

    it('fail-closed: unparseable signed_at + revoked key → kid_revoked (not skipped)', () => {
        const v = verifyWithUnparseableSignedAt({ revokedAt: '2026-06-14T00:00:00.000Z' });
        expect(v.ok).toBe(false);
        expect(v.failures.some((f) => f.reason === 'kid_revoked')).toBe(true);
        expect(v.checkpointsVerified).toBe(0);
    });

    it('fail-closed: unparseable signed_at + expiring key → kid_expired', () => {
        const v = verifyWithUnparseableSignedAt({ validUntil: '2026-06-14T00:00:00.000Z' });
        expect(v.failures.some((f) => f.reason === 'kid_expired')).toBe(true);
    });

    it('fail-open is NOT triggered for a window-LESS key with an odd signed_at (backward compat)', () => {
        // No bounds declared → the window check is a no-op even if signed_at is
        // unparseable; the signature check governs (here it fails, but NOT for a
        // window reason).
        const v = verifyWithUnparseableSignedAt({});
        expect(v.failures.every((f) => f.reason !== 'kid_revoked' && f.reason !== 'kid_expired' && f.reason !== 'kid_not_yet_valid')).toBe(true);
    });
});

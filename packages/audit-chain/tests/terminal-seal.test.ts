// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Offline-provable terminal seal.
 *
 * (1) GOLDEN VECTORS: the signed checkpoint-message bytes for a V1 (periodic), a
 *     terminal (V2 'sealed'), and an empty-chain (V2 'empty_chain') checkpoint are
 *     frozen. If these move, the message format changed and every signed terminal
 *     is invalidated — a conscious break. The V1 vector is byte-identical to the
 *     original checkpoint format (dual-version = additive, no regression).
 * (2) DUAL-VERSION VERIFY: verifyChain reproduces the V2 message, proves the
 *     signature covers the terminal descriptor (reports `terminal` in the Verdict),
 *     anchors an empty-chain terminal to GENESIS/seq 0, and still verifies a V1
 *     checkpoint (no terminal). Tampering the signed terminal kind fails the sig.
 */

import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import {
    verifyChain,
    chainHash,
    checkpointHash,
    buildCheckpointMessage,
    GENESIS,
    CHECKPOINT_SCHEMA_VERSION_SEAL,
    type ChainedEventContent,
    type VerifierEventRow,
    type VerifierCheckpoint,
    type TrustKey,
    type CheckpointSignable,
    type TerminalDescriptor,
} from '../src/index.js';

const ED25519_SPKI_PREFIX_LEN = 12;
const dec = new TextDecoder();
const GENESIS_B64 = Buffer.from(GENESIS).toString('base64url');

function makeKey(): { trust: TrustKey; sign: (m: Uint8Array) => string } {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(ED25519_SPKI_PREFIX_LEN);
    return {
        trust: { kid: 'k_test', publicKeyB64: Buffer.from(raw).toString('base64url') },
        sign: (m) => Buffer.from(cryptoSign(null, m, privateKey)).toString('base64url'),
    };
}

function content(seq: number): ChainedEventContent {
    return { tenant_name: 'demo_tenant', instance_id: '11111111-1111-1111-1111-111111111111', field_name: 'status', from_state: `s${seq - 1}`, to_state: `s${seq}`, actor: 'alice', actor_role: 'owner', payload: { step: seq }, policy_version: 'v1', rule_evaluations: null };
}
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

function signTerminal(key: ReturnType<typeof makeKey>, headHash: Uint8Array, seq: number, kind: TerminalDescriptor['kind']): VerifierCheckpoint {
    const signable: CheckpointSignable = {
        tenant_name: 'demo_tenant', log_name: 'state_machine', seq,
        head_hash_b64: Buffer.from(headHash).toString('base64url'), prev_checkpoint_hash_b64: null,
        window_id: 'seal:state_machine', signed_at: '2026-07-10T12:00:00.000Z', kid: key.trust.kid,
        schema_version: CHECKPOINT_SCHEMA_VERSION_SEAL, terminal: { kind },
    };
    return {
        tenantName: signable.tenant_name, logName: signable.log_name, seq, headHash,
        prevCheckpointHash: null, checkpointHash: checkpointHash(signable), windowId: signable.window_id,
        kid: signable.kid, signatureB64: key.sign(buildCheckpointMessage(signable)), signedAt: signable.signed_at,
        schemaVersion: CHECKPOINT_SCHEMA_VERSION_SEAL, terminal: { kind },
    };
}

describe('terminal-seal golden vectors', () => {
    const base: CheckpointSignable = {
        tenant_name: 'demo_tenant', log_name: 'state_machine', seq: 7, head_hash_b64: 'aGVhZA',
        prev_checkpoint_hash_b64: null, window_id: '2026071012', signed_at: '2026-07-10T12:00:00.000Z', kid: 'k_test',
    };

    it('V1 (periodic) message is byte-identical to the original checkpoint format', () => {
        expect(dec.decode(buildCheckpointMessage(base))).toBe(
            '{"head_hash_b64":"aGVhZA","kid":"k_test","log_name":"state_machine","prev_checkpoint_hash_b64":null,"seq":7,"signed_at":"2026-07-10T12:00:00.000Z","tenant_name":"demo_tenant","window_id":"2026071012"}',
        );
    });

    it('terminal (V2 sealed) message is frozen', () => {
        const terminal: CheckpointSignable = { ...base, window_id: 'seal:state_machine', schema_version: 2, terminal: { kind: 'sealed' } };
        expect(dec.decode(buildCheckpointMessage(terminal))).toBe(
            '{"head_hash_b64":"aGVhZA","kid":"k_test","log_name":"state_machine","prev_checkpoint_hash_b64":null,"schema_version":2,"seq":7,"signed_at":"2026-07-10T12:00:00.000Z","tenant_name":"demo_tenant","terminal":{"kind":"sealed"},"window_id":"seal:state_machine"}',
        );
    });

    it('empty-chain (V2) message is frozen (seq 0 / GENESIS)', () => {
        const empty: CheckpointSignable = { tenant_name: 'demo_tenant', log_name: 'flows', seq: 0, head_hash_b64: GENESIS_B64, prev_checkpoint_hash_b64: null, window_id: 'seal:flows', signed_at: '2026-07-10T12:00:00.000Z', kid: 'k_test', schema_version: 2, terminal: { kind: 'empty_chain' } };
        expect(dec.decode(buildCheckpointMessage(empty))).toBe(
            `{"head_hash_b64":"${GENESIS_B64}","kid":"k_test","log_name":"flows","prev_checkpoint_hash_b64":null,"schema_version":2,"seq":0,"signed_at":"2026-07-10T12:00:00.000Z","tenant_name":"demo_tenant","terminal":{"kind":"empty_chain"},"window_id":"seal:flows"}`,
        );
    });
});

describe('verifyChain dual-version terminal dispatch', () => {
    it('a V2 terminal (sealed) checkpoint verifies and reports terminal-sealed', () => {
        const key = makeKey();
        const events = buildChain(3);
        const cp = signTerminal(key, events[2]!.eventHash, 3, 'sealed');
        const v = verifyChain({ events, checkpoints: [cp], keys: [key.trust] });
        expect(v.ok).toBe(true);
        expect(v.terminal).toEqual({ kind: 'sealed' });
    });

    it('an empty-chain terminal (no events) verifies and reports empty_chain', () => {
        const key = makeKey();
        const cp = signTerminal(key, GENESIS, 0, 'empty_chain');
        const v = verifyChain({ events: [], checkpoints: [cp], keys: [key.trust] });
        expect(v.ok).toBe(true);
        expect(v.terminal).toEqual({ kind: 'empty_chain' });
    });

    it('a V1 checkpoint still verifies with no terminal (no regression)', () => {
        const key = makeKey();
        const events = buildChain(2);
        const signable: CheckpointSignable = {
            tenant_name: 'demo_tenant', log_name: 'state_machine', seq: 2,
            head_hash_b64: Buffer.from(events[1]!.eventHash).toString('base64url'), prev_checkpoint_hash_b64: null,
            window_id: '2026071012', signed_at: '2026-07-10T12:00:00.000Z', kid: key.trust.kid,
        };
        const cp: VerifierCheckpoint = {
            tenantName: 'demo_tenant', logName: 'state_machine', seq: 2, headHash: events[1]!.eventHash,
            prevCheckpointHash: null, checkpointHash: checkpointHash(signable), windowId: signable.window_id,
            kid: key.trust.kid, signatureB64: key.sign(buildCheckpointMessage(signable)), signedAt: signable.signed_at,
        };
        const v = verifyChain({ events, checkpoints: [cp], keys: [key.trust] });
        expect(v.ok).toBe(true);
        expect(v.terminal).toBeNull();
    });

    it('tampering the signed terminal kind fails the signature (terminality is signature-covered)', () => {
        const key = makeKey();
        const events = buildChain(1);
        const cp = signTerminal(key, events[0]!.eventHash, 1, 'sealed');
        // Forge the descriptor without re-signing → message diverges → sig invalid.
        const forged: VerifierCheckpoint = { ...cp, terminal: { kind: 'empty_chain' } };
        const v = verifyChain({ events, checkpoints: [forged], keys: [key.trust] });
        expect(v.ok).toBe(false);
        expect(v.terminal).toBeNull();
    });
});

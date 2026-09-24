// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Interop gate — the signer that produces Zarel's checkpoints uses libsodium; this
 * verifier uses node:crypto. This test signs a
 * checkpoint with libsodium and verifies it through verifyChain (node:crypto)
 * to prove the two agree byte-for-byte. If they ever diverge, every signed
 * checkpoint becomes unverifiable — so this parity is load-bearing.
 */

import _sodium from 'libsodium-wrappers';
import {
    verifyChain,
    chainHash,
    checkpointHash,
    buildCheckpointMessage,
    GENESIS,
    type VerifierEventRow,
    type VerifierCheckpoint,
    type CheckpointSignable,
    type ChainedEventContent,
} from '../src/index.js';

const content = (seq: number): ChainedEventContent => ({
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
});

describe('libsodium signer ↔ node:crypto verifier parity', () => {
    it('a checkpoint signed with libsodium Ed25519 verifies via verifyChain', async () => {
        await _sodium.ready;
        const sodium = _sodium;
        const kp = sodium.crypto_sign_keypair();
        const publicKeyB64 = sodium.to_base64(kp.publicKey, sodium.base64_variants.URLSAFE_NO_PADDING);

        // build a 3-event chain
        const events: VerifierEventRow[] = [];
        let prev = GENESIS;
        for (let seq = 1; seq <= 3; seq++) {
            const c = content(seq);
            const eventHash = chainHash({ content: c, prevHash: prev, seq });
            events.push({ seq, prevHash: prev, eventHash, content: c, deletedAt: null });
            prev = eventHash;
        }

        const signable: CheckpointSignable = {
            tenant_name: 'demo_tenant',
            log_name: 'state_machine',
            seq: 3,
            head_hash_b64: Buffer.from(events[2].eventHash).toString('base64url'),
            prev_checkpoint_hash_b64: null,
            window_id: '2026061400',
            signed_at: '2026-06-14T01:00:00.000Z',
            kid: 'k_libsodium',
        };
        const message = buildCheckpointMessage(signable);
        const signature = sodium.crypto_sign_detached(message, kp.privateKey);
        const signatureB64 = sodium.to_base64(signature, sodium.base64_variants.URLSAFE_NO_PADDING);

        const cp: VerifierCheckpoint = {
            tenantName: signable.tenant_name,
            logName: signable.log_name,
            seq: 3,
            headHash: events[2].eventHash,
            prevCheckpointHash: null,
            checkpointHash: checkpointHash(signable),
            windowId: signable.window_id,
            kid: signable.kid,
            signatureB64,
            signedAt: signable.signed_at,
        };

        const v = verifyChain({
            events,
            checkpoints: [cp],
            keys: [{ kid: 'k_libsodium', publicKeyB64 }],
        });
        expect(v.ok).toBe(true);
        expect(v.checkpointsVerified).toBe(1);
    });
});

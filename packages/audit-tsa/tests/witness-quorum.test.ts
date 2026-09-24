// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Witness quorum + independence-floor evaluation.
 *
 * The non-equivocation HALF: count only DISTINCT, policy-matching, cryptographically
 * valid cosignatures, and gate the honest label on the independence floor (≥3 units, ≥1
 * external, ≥1 EU/EEA). Fail-closed: duplicates collapse, foreign/forged/wrong-key
 * cosignatures never inflate the count. Cosignatures are deterministic (fixed seeds).
 */

import { cosignatureMessage } from '../src/cosignature.js';
import {
    evaluateWitnessQuorum,
    EU_EEA_REGIONS,
    type WitnessVerifierPolicy,
    type WitnessVerifierEntry,
    type CheckpointCosignature,
} from '../src/witness-quorum.js';
import { ed25519FromSeed, type TestKey } from './helpers/ed25519.js';

const BODY = 'zarel.audit.log\n12\nabcdEFGHabcdEFGHabcdEFGHabcdEFGH\n';
const TS = 1_712_000_000n;

function key(seed: number): TestKey {
    return ed25519FromSeed(new Uint8Array(32).fill(seed));
}
function cosign(k: TestKey, keyName: string, ts: bigint = TS): CheckpointCosignature {
    return { keyName, timestamp: ts, signature: k.sign(cosignatureMessage(BODY, ts)) };
}
function entry(k: TestKey, keyName: string, isExternal: boolean, jurisdiction: string | null): WitnessVerifierEntry {
    return { keyName, publicKey: k.rawPublicKey, isExternal, jurisdiction };
}

// Four witnesses: an EU external, a US external, an AR internal, a NO external.
const kEu = key(0x11);
const kUs = key(0x22);
const kAr = key(0x33);
const kNo = key(0x44);
const POLICY: WitnessVerifierPolicy = {
    name: 'test-policy',
    origin: 'zarel.audit.log',
    threshold: 3,
    witnesses: [
        entry(kEu, 'w-eu', true, 'DE'),
        entry(kUs, 'w-us', true, 'US'),
        entry(kAr, 'w-ar', false, 'AR'),
        entry(kNo, 'w-no', true, 'NO'),
    ],
};

describe('EU_EEA_REGIONS', () => {
    it('includes EU + EEA members and excludes non-members', () => {
        expect(EU_EEA_REGIONS.has('DE')).toBe(true);
        expect(EU_EEA_REGIONS.has('NO')).toBe(true); // EEA
        expect(EU_EEA_REGIONS.has('IS')).toBe(true); // EEA
        expect(EU_EEA_REGIONS.has('EL')).toBe(true); // Greece (EU's own code, not just ISO 'GR')
        expect(EU_EEA_REGIONS.has('US')).toBe(false);
        expect(EU_EEA_REGIONS.has('AR')).toBe(false);
    });
});

describe('evaluateWitnessQuorum: counting', () => {
    it('counts distinct policy-matching valid cosignatures and meets the floor', () => {
        const cosigs = [cosign(kEu, 'w-eu'), cosign(kUs, 'w-us'), cosign(kAr, 'w-ar')];
        const v = evaluateWitnessQuorum(BODY, cosigs, POLICY);
        expect([...v.matchedKeyNames].sort()).toEqual(['w-ar', 'w-eu', 'w-us']);
        expect(v.quorumMet).toBe(true); // 3 >= 3
        expect(v.externalCount).toBe(2); // eu, us
        expect(v.euEeaCount).toBe(1); // de
        expect(v.floorMet).toBe(true);
    });

    it('collapses a duplicate / replayed cosignature to one', () => {
        const cosigs = [cosign(kEu, 'w-eu'), cosign(kEu, 'w-eu', 999n), cosign(kUs, 'w-us'), cosign(kAr, 'w-ar')];
        const v = evaluateWitnessQuorum(BODY, cosigs, POLICY);
        expect(v.matchedKeyNames).toHaveLength(3); // w-eu once
    });

    it('excludes a cosignature whose keyName is not in the policy', () => {
        const kX = key(0x55);
        const v = evaluateWitnessQuorum(BODY, [cosign(kX, 'w-unknown'), cosign(kEu, 'w-eu')], POLICY);
        expect([...v.matchedKeyNames]).toEqual(['w-eu']);
    });

    it('excludes a forged cosignature (right keyName, wrong signing key)', () => {
        // claims w-us but signed by the EU key → fails Ed25519 under the policy pubkey
        const forged: CheckpointCosignature = { keyName: 'w-us', timestamp: TS, signature: kEu.sign(cosignatureMessage(BODY, TS)) };
        const v = evaluateWitnessQuorum(BODY, [forged, cosign(kEu, 'w-eu')], POLICY);
        expect([...v.matchedKeyNames]).toEqual(['w-eu']);
    });

    it('excludes a cosignature over a DIFFERENT body (fail-closed)', () => {
        const wrongBody: CheckpointCosignature = { keyName: 'w-eu', timestamp: TS, signature: kEu.sign(cosignatureMessage('other-body\n', TS)) };
        const v = evaluateWitnessQuorum(BODY, [wrongBody], POLICY);
        expect(v.matchedKeyNames).toHaveLength(0);
    });

    it('counts one physical key listed under two keyNames ONCE (independence is per-pubkey)', () => {
        // The cosignature binds body+timestamp, NOT the keyName, so a single key
        // relabeled under two policy slots must not fill two independent units.
        const aliasPolicy: WitnessVerifierPolicy = {
            name: 'aliased', origin: 'zarel.audit.log', threshold: 3,
            witnesses: [
                entry(kEu, 'w-eu-a', true, 'DE'),
                entry(kEu, 'w-eu-b', true, 'FR'), // SAME pubkey, different name/jurisdiction
                entry(kUs, 'w-us', true, 'US'),
            ],
        };
        const v = evaluateWitnessQuorum(BODY, [cosign(kEu, 'w-eu-a'), cosign(kEu, 'w-eu-b'), cosign(kUs, 'w-us')], aliasPolicy);
        expect(v.matchedKeyNames).toHaveLength(2); // kEu once + kUs
        expect(v.floorMet).toBe(false); // only 2 independent units
    });
});

describe('evaluateWitnessQuorum: independence floor — each leg is load-bearing', () => {
    it('count short of 3 ⇒ floor not met (even if external + EU present)', () => {
        const v = evaluateWitnessQuorum(BODY, [cosign(kEu, 'w-eu'), cosign(kUs, 'w-us')], POLICY);
        expect(v.matchedKeyNames).toHaveLength(2);
        expect(v.floorMet).toBe(false);
    });

    it('no external among matched ⇒ floor not met', () => {
        // policy where the only cosigners are internal
        const internalPolicy: WitnessVerifierPolicy = {
            name: 'internal-only', origin: 'zarel.audit.log', threshold: 3,
            witnesses: [entry(kEu, 'w-eu', false, 'DE'), entry(kUs, 'w-us', false, 'FR'), entry(kAr, 'w-ar', false, 'IT')],
        };
        const v = evaluateWitnessQuorum(BODY, [cosign(kEu, 'w-eu'), cosign(kUs, 'w-us'), cosign(kAr, 'w-ar')], internalPolicy);
        expect(v.quorumMet).toBe(true);
        expect(v.externalCount).toBe(0);
        expect(v.floorMet).toBe(false);
    });

    it('no EU/EEA among matched ⇒ floor not met', () => {
        const nonEuPolicy: WitnessVerifierPolicy = {
            name: 'no-eu', origin: 'zarel.audit.log', threshold: 3,
            witnesses: [entry(kUs, 'w-us', true, 'US'), entry(kAr, 'w-ar', true, 'AR'), entry(kNo, 'w-no', false, null)],
        };
        const v = evaluateWitnessQuorum(BODY, [cosign(kUs, 'w-us'), cosign(kAr, 'w-ar'), cosign(kNo, 'w-no')], nonEuPolicy);
        expect(v.quorumMet).toBe(true);
        expect(v.euEeaCount).toBe(0);
        expect(v.floorMet).toBe(false);
    });

    it('an untagged (null jurisdiction) witness cannot satisfy the EU/EEA leg', () => {
        const v = evaluateWitnessQuorum(BODY, [
            cosign(kEu, 'w-eu'), cosign(kUs, 'w-us'),
            { keyName: 'w-no', timestamp: TS, signature: kNo.sign(cosignatureMessage(BODY, TS)) },
        ], { ...POLICY, witnesses: [entry(kEu, 'w-eu', true, null), entry(kUs, 'w-us', true, 'US'), entry(kNo, 'w-no', true, null)] });
        expect(v.euEeaCount).toBe(0);
        expect(v.floorMet).toBe(false);
    });

    it('all three legs satisfied ⇒ floor met', () => {
        const v = evaluateWitnessQuorum(BODY, [cosign(kEu, 'w-eu'), cosign(kUs, 'w-us'), cosign(kNo, 'w-no')], POLICY);
        expect(v.matchedKeyNames).toHaveLength(3);
        expect(v.externalCount).toBe(3);
        expect(v.euEeaCount).toBe(2); // DE (EU) + NO (EEA)
        expect(v.floorMet).toBe(true);
    });
});

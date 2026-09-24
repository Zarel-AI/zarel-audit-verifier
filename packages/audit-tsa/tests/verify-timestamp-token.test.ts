// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Offline structural verification of RFC 3161 tokens.
 *
 * A valid token verifies with a pinned root and ZERO network; each tamper /
 * misconfiguration fails closed with the honest first-failure label. The mock
 * TSA (helpers/mock-tsa) makes this deterministic and offline; conformance
 * against a commercial TSA is the separate executable gate (tsa-gate-live-token).
 */

import { verifyTimestampToken } from '../src/verify-timestamp-token.js';
import { createMockTsa, forgeTokenViaNonCaIntermediate, flipByte, sha256, type MockTsa } from './helpers/mock-tsa.js';

const ROOT = sha256('window-merkle-root');
const GEN_TIME = new Date('2026-06-01T12:00:00Z');

let good: MockTsa;
let otherCa: MockTsa;
let noEku: MockTsa;
let nonCriticalEku: MockTsa;
let shortLived: MockTsa;
let validToken: Uint8Array;

beforeAll(async () => {
    [good, otherCa, noEku, nonCriticalEku, shortLived] = await Promise.all([
        createMockTsa({ name: 'Good' }),
        createMockTsa({ name: 'Other' }),
        createMockTsa({ name: 'NoEku', eku: 'none' }),
        createMockTsa({ name: 'NonCrit', eku: 'non-critical' }),
        createMockTsa({ name: 'Short', notBefore: new Date('2026-01-01T00:00:00Z'), notAfter: new Date('2026-02-01T00:00:00Z') }),
    ]);
    validToken = await good.issue(ROOT, GEN_TIME);
}, 30000);

describe('verifyTimestampToken — valid', () => {
    it('verifies offline against the pinned root and returns the attested genTime', () => {
        const verdict = verifyTimestampToken({ token: validToken, expectedRoot: ROOT, pinnedRoots: [good.pinnedRootDer] });
        // notAfter (the signer cert's expiry) is surfaced for the long-term-validation verifier.
        expect(verdict).toEqual({ ok: true, genTime: GEN_TIME.toISOString(), notAfter: '2030-01-01T00:00:00.000Z' });
    });

    it('accepts multiple pinned roots when one of them is the real anchor', () => {
        const verdict = verifyTimestampToken({
            token: validToken, expectedRoot: ROOT, pinnedRoots: [otherCa.pinnedRootDer, good.pinnedRootDer],
        });
        expect(verdict.ok).toBe(true);
    });
});

describe('verifyTimestampToken — fail-closed', () => {
    it('no pinned root → no_pinned_root (the bundle cannot be its own trust anchor)', () => {
        const verdict = verifyTimestampToken({ token: validToken, expectedRoot: ROOT, pinnedRoots: [] });
        expect(verdict).toEqual({ ok: false, genTime: null, failure: 'no_pinned_root' });
    });

    it('garbage bytes → malformed_token', () => {
        const verdict = verifyTimestampToken({ token: sha256('not-a-token'), expectedRoot: ROOT, pinnedRoots: [good.pinnedRootDer] });
        expect(verdict.failure).toBe('malformed_token');
        expect(verdict.genTime).toBeNull();
    });

    it('tampered token signature → cms_signature', () => {
        const verdict = verifyTimestampToken({ token: flipByte(validToken), expectedRoot: ROOT, pinnedRoots: [good.pinnedRootDer] });
        expect(verdict.failure).toBe('cms_signature');
    });

    it('signer cert without the timestamping EKU → eku_timestamping', async () => {
        const token = await noEku.issue(ROOT, GEN_TIME);
        const verdict = verifyTimestampToken({ token, expectedRoot: ROOT, pinnedRoots: [noEku.pinnedRootDer] });
        expect(verdict.failure).toBe('eku_timestamping');
    });

    it('non-critical timestamping EKU → eku_timestamping', async () => {
        const token = await nonCriticalEku.issue(ROOT, GEN_TIME);
        const verdict = verifyTimestampToken({ token, expectedRoot: ROOT, pinnedRoots: [nonCriticalEku.pinnedRootDer] });
        expect(verdict.failure).toBe('eku_timestamping');
    });

    it('signer chains to a different CA than the pinned root → chain_to_pinned_root', () => {
        const verdict = verifyTimestampToken({ token: validToken, expectedRoot: ROOT, pinnedRoots: [otherCa.pinnedRootDer] });
        expect(verdict.failure).toBe('chain_to_pinned_root');
    });

    it('chain routed through a NON-CA cert under the pinned root → chain_to_pinned_root (basicConstraints enforced)', async () => {
        // Security regression (CVE-2002-0862 class): an attacker-controlled chain
        // S → L → root where L is a legit but NON-CA leaf must NOT verify.
        const forged = await forgeTokenViaNonCaIntermediate(ROOT, GEN_TIME);
        const verdict = verifyTimestampToken({ token: forged.token, expectedRoot: ROOT, pinnedRoots: [forged.pinnedRootDer] });
        expect(verdict.ok).toBe(false);
        expect(verdict.failure).toBe('chain_to_pinned_root');
    });

    it('genTime outside the signer cert validity → gentime_outside_validity', async () => {
        // shortLived cert validity ends 2026-02-01; GEN_TIME (2026-06-01) is past it.
        const token = await shortLived.issue(ROOT, GEN_TIME);
        const verdict = verifyTimestampToken({ token, expectedRoot: ROOT, pinnedRoots: [shortLived.pinnedRootDer] });
        expect(verdict.failure).toBe('gentime_outside_validity');
    });

    it('expectedRoot differs from the token imprint → imprint_mismatch', () => {
        const verdict = verifyTimestampToken({ token: validToken, expectedRoot: sha256('a-different-root'), pinnedRoots: [good.pinnedRootDer] });
        expect(verdict.failure).toBe('imprint_mismatch');
    });

    it('every failure verdict carries a null genTime (fail-closed)', async () => {
        const noEkuToken = await noEku.issue(ROOT, GEN_TIME);
        for (const verdict of [
            verifyTimestampToken({ token: validToken, expectedRoot: ROOT, pinnedRoots: [] }),
            verifyTimestampToken({ token: flipByte(validToken), expectedRoot: ROOT, pinnedRoots: [good.pinnedRootDer] }),
            verifyTimestampToken({ token: noEkuToken, expectedRoot: ROOT, pinnedRoots: [noEku.pinnedRootDer] }),
            verifyTimestampToken({ token: validToken, expectedRoot: ROOT, pinnedRoots: [otherCa.pinnedRootDer] }),
            verifyTimestampToken({ token: validToken, expectedRoot: sha256('x'), pinnedRoots: [good.pinnedRootDer] }),
        ]) {
            expect(verdict.ok).toBe(false);
            expect(verdict.genTime).toBeNull();
        }
    });
});

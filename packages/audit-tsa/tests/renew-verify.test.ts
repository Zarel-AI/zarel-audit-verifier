// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Longevity, broken-chain fail-closed, and hash-tree / algorithm migration —
 * the load-bearing proof of long-term validation: a window whose original
 * TSA cert has EXPIRED still verifies via its renewal chain, while a lapsed or
 * tampered chain fails closed with a precise reason.
 *
 * Setup uses two mock TSAs: `old` (short-lived cert) issues the initial window
 * anchor; `next` (long-lived cert) issues the renewals. Both roots are pinned.
 * Verification time is advanced past `old`'s expiry but before `next`'s.
 */

import { createHash } from 'node:crypto';
import { buildTimestampRenewal, buildHashTreeRenewal } from '../src/renew.js';
import { verifyEvidenceRecord } from '../src/verify-evidence-record.js';
import { assembleEvidenceRecord } from '../src/assemble-evidence-record.js';
import { encodeEvidenceRecord, decodeEvidenceRecord } from '../src/evidence-record.js';
import type { EvidenceRecord, ErsArchiveTimeStamp, ErsChain } from '../src/types.js';
import { createMockTsa, type MockTsa } from './helpers/mock-tsa';

function sha256(b: Uint8Array | Buffer): Uint8Array {
    return new Uint8Array(createHash('sha256').update(b).digest());
}

const T = {
    initialGen: new Date('2026-06-15T00:00:00Z'),
    oldNotAfter: new Date('2027-01-01T00:00:00Z'),
    renewGen: new Date('2026-12-01T00:00:00Z'), // before oldNotAfter — a valid renewal
    nextNotAfter: new Date('2031-01-01T00:00:00Z'),
    verifyNow: new Date('2029-01-01T00:00:00Z'), // past old expiry, before next expiry
};

let oldTsa: MockTsa;
let nextTsa: MockTsa;
let pinnedRoots: Uint8Array[];

beforeAll(async () => {
    oldTsa = await createMockTsa({ name: 'Old', notBefore: new Date('2026-01-01T00:00:00Z'), notAfter: T.oldNotAfter });
    nextTsa = await createMockTsa({ name: 'Next', notBefore: new Date('2026-01-01T00:00:00Z'), notAfter: T.nextNotAfter });
    pinnedRoots = [oldTsa.pinnedRootDer, nextTsa.pinnedRootDer];
});

function ats(reducedHashtree: ErsArchiveTimeStamp['reducedHashtree'], timeStampDer: Uint8Array, digestAlg: ErsArchiveTimeStamp['digestAlg'] = 'SHA-256'): ErsArchiveTimeStamp {
    return { digestAlg, reducedHashtree, timeStampDer };
}

describe('longevity: an expired-cert window still verifies via renewal', () => {
    it('a 2-window timestamp renewal keeps window A verifiable after the old cert expired', async () => {
        const rootA = sha256(Buffer.from('window-A'));
        const rootB = sha256(Buffer.from('window-B'));
        const initA = await oldTsa.issue(rootA, T.initialGen);
        const initB = await oldTsa.issue(rootB, T.initialGen);

        const renewal = await buildTimestampRenewal(
            [
                { windowId: 'A', currentTopTokenDer: initA },
                { windowId: 'B', currentTopTokenDer: initB },
            ],
            (root) => nextTsa.issue(root, T.renewGen),
            'SHA-256',
        );

        const recordA: EvidenceRecord = {
            version: 1,
            digestAlgorithms: ['SHA-256'],
            sequence: [[ats([], initA), renewal.perWindow[0].ats]],
        };

        const verdict = verifyEvidenceRecord({ record: recordA, dataObjectHash: rootA, pinnedRoots, revocationPolicy: 'lenient', now: T.verifyNow });
        expect(verdict.ok).toBe(true);
        expect(verdict.chainDepth).toBe(2);
        expect(verdict.oldestGenTime).toBe(T.initialGen.toISOString());
        expect(verdict.latestNotAfter).toBe(T.nextNotAfter.toISOString());
    });

    it('the bundle path: assembleEvidenceRecord → DER → decode → verify (expired cert, renewed)', async () => {
        const rootA = sha256(Buffer.from('bundle-window'));
        const initA = await oldTsa.issue(rootA, T.initialGen);
        const renewal = await buildTimestampRenewal(
            [{ windowId: 'A', currentTopTokenDer: initA }],
            (root) => nextTsa.issue(root, T.renewGen),
            'SHA-256',
        );
        // Exactly what a server assembles into an evidence bundle from its stored rows.
        const record = assembleEvidenceRecord({
            anchorTokenDer: initA,
            renewals: [
                {
                    chainIndex: 0,
                    digestAlg: 'SHA-256',
                    reducedHashtree: renewal.perWindow[0].reducedHashtree,
                    timeStampDer: renewal.tokenDer,
                },
            ],
        });
        const decoded = decodeEvidenceRecord(encodeEvidenceRecord(record));
        const verdict = verifyEvidenceRecord({ record: decoded, dataObjectHash: rootA, pinnedRoots, revocationPolicy: 'lenient', now: T.verifyNow });
        expect(verdict.ok).toBe(true);
        expect(verdict.chainDepth).toBe(2);
    });

    it('WITHOUT renewal, the same window fails tsa_cert_expired after the cert lapsed', async () => {
        const rootA = sha256(Buffer.from('window-A-norenew'));
        const initA = await oldTsa.issue(rootA, T.initialGen);
        const record: EvidenceRecord = { version: 1, digestAlgorithms: ['SHA-256'], sequence: [[ats([], initA)]] };
        const verdict = verifyEvidenceRecord({ record, dataObjectHash: rootA, pinnedRoots, revocationPolicy: 'lenient', now: T.verifyNow });
        expect(verdict.ok).toBe(false);
        expect(verdict.failure).toBe('tsa_cert_expired');
    });

    it('a fully-renewed window IS valid at a time within the latest cert validity', async () => {
        const rootA = sha256(Buffer.from('window-A-fresh'));
        const initA = await oldTsa.issue(rootA, T.initialGen);
        const renewal = await buildTimestampRenewal(
            [{ windowId: 'A', currentTopTokenDer: initA }],
            (root) => nextTsa.issue(root, T.renewGen),
            'SHA-256',
        );
        const record: EvidenceRecord = { version: 1, digestAlgorithms: ['SHA-256'], sequence: [[ats([], initA), renewal.perWindow[0].ats]] };
        // now just before next cert expiry → valid; after → expired.
        expect(verifyEvidenceRecord({ record, dataObjectHash: rootA, pinnedRoots, revocationPolicy: 'lenient', now: new Date('2030-12-31T00:00:00Z') }).ok).toBe(true);
        expect(verifyEvidenceRecord({ record, dataObjectHash: rootA, pinnedRoots, revocationPolicy: 'lenient', now: new Date('2031-06-01T00:00:00Z') }).failure).toBe('tsa_cert_expired');
    });
});

describe('broken chain fails closed', () => {
    it('renewal_gap: a renewal genTime AFTER the prior cert expired is rejected', async () => {
        const rootA = sha256(Buffer.from('gap-window'));
        const initA = await oldTsa.issue(rootA, T.initialGen);
        // Renew at a time PAST the old cert's notAfter → a lapse.
        const lateRenewal = await buildTimestampRenewal(
            [{ windowId: 'A', currentTopTokenDer: initA }],
            (root) => nextTsa.issue(root, new Date('2028-01-01T00:00:00Z')),
            'SHA-256',
        );
        const record: EvidenceRecord = { version: 1, digestAlgorithms: ['SHA-256'], sequence: [[ats([], initA), lateRenewal.perWindow[0].ats]] };
        const verdict = verifyEvidenceRecord({ record, dataObjectHash: rootA, pinnedRoots, revocationPolicy: 'lenient', now: T.verifyNow });
        expect(verdict.ok).toBe(false);
        expect(verdict.failure).toBe('renewal_gap');
    });

    it('renewal_link_broken: a renewal that covered a DIFFERENT prior token is rejected', async () => {
        const rootA = sha256(Buffer.from('link-window'));
        const initA = await oldTsa.issue(rootA, T.initialGen);
        const otherToken = await oldTsa.issue(sha256(Buffer.from('unrelated')), T.initialGen);
        // The renewal covers H(otherToken), but the record's prior ATS is initA.
        const renewal = await buildTimestampRenewal(
            [{ windowId: 'A', currentTopTokenDer: otherToken }],
            (root) => nextTsa.issue(root, T.renewGen),
            'SHA-256',
        );
        const record: EvidenceRecord = { version: 1, digestAlgorithms: ['SHA-256'], sequence: [[ats([], initA), renewal.perWindow[0].ats]] };
        const verdict = verifyEvidenceRecord({ record, dataObjectHash: rootA, pinnedRoots, revocationPolicy: 'lenient', now: T.verifyNow });
        expect(verdict.ok).toBe(false);
        expect(verdict.failure).toBe('renewal_link_broken');
    });

    it('inclusion_mismatch: a wrong data object hash is rejected at the initial ATS', async () => {
        const rootA = sha256(Buffer.from('incl-window'));
        const initA = await oldTsa.issue(rootA, T.initialGen);
        const record: EvidenceRecord = { version: 1, digestAlgorithms: ['SHA-256'], sequence: [[ats([], initA)]] };
        const verdict = verifyEvidenceRecord({ record, dataObjectHash: sha256(Buffer.from('WRONG')), pinnedRoots, revocationPolicy: 'lenient', now: T.initialGen });
        expect(verdict.ok).toBe(false);
        expect(verdict.failure).toBe('inclusion_mismatch');
    });

    it('empty_sequence is rejected', () => {
        const verdict = verifyEvidenceRecord({ record: { version: 1, digestAlgorithms: ['SHA-256'], sequence: [] }, dataObjectHash: sha256(Buffer.from('x')), pinnedRoots, revocationPolicy: 'lenient', now: T.verifyNow });
        expect(verdict.failure).toBe('empty_sequence');
    });
});

describe('hash-tree renewal migrates the algorithm without invalidating history', () => {
    it('a SHA-256 chain renewed to SHA-384 (new chain) verifies end-to-end', async () => {
        const rootA = sha256(Buffer.from('migrate-window'));
        const initA = await oldTsa.issue(rootA, T.initialGen);
        const chain0: ErsChain = [ats([], initA)];

        const htRenewal = await buildHashTreeRenewal(
            [{ windowId: 'A', dataObjectHash: rootA, priorChains: [chain0] }],
            (root) => nextTsa.issue(root, T.renewGen),
            'SHA-384',
        );
        const record: EvidenceRecord = {
            version: 1,
            digestAlgorithms: ['SHA-256', 'SHA-384'],
            sequence: [chain0, [htRenewal.perWindow[0].ats]],
        };
        const verdict = verifyEvidenceRecord({ record, dataObjectHash: rootA, pinnedRoots, revocationPolicy: 'lenient', now: T.verifyNow });
        expect(verdict.ok).toBe(true);
        expect(verdict.chainDepth).toBe(2);
    });

    it('cross_chain_link_broken: tampering the pre-migration chain fails at the boundary', async () => {
        const rootA = sha256(Buffer.from('migrate-tamper'));
        const initA = await oldTsa.issue(rootA, T.initialGen);
        const chain0: ErsChain = [ats([], initA)];
        const htRenewal = await buildHashTreeRenewal(
            [{ windowId: 'A', dataObjectHash: rootA, priorChains: [chain0] }],
            (root) => nextTsa.issue(root, T.renewGen),
            'SHA-384',
        );
        // Swap chain0 for a DIFFERENT initial token after the renewal was bound to the original.
        const tamperedInit = await oldTsa.issue(rootA, new Date('2026-06-16T00:00:00Z'));
        const record: EvidenceRecord = {
            version: 1,
            digestAlgorithms: ['SHA-256', 'SHA-384'],
            sequence: [[ats([], tamperedInit)], [htRenewal.perWindow[0].ats]],
        };
        const verdict = verifyEvidenceRecord({ record, dataObjectHash: rootA, pinnedRoots, revocationPolicy: 'lenient', now: T.verifyNow });
        expect(verdict.ok).toBe(false);
        expect(verdict.failure).toBe('cross_chain_link_broken');
    });
});

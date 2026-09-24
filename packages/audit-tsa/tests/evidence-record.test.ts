// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * The EvidenceRecord wire format is **literal RFC 4998 ASN.1**,
 * not a JSON analog: it round-trips through a DER encode/decode, is byte-stable
 * (golden), preserves the embedded token + reduced hash tree exactly, and decode
 * is fail-closed on malformed input.
 */

import { createHash } from 'node:crypto';
import { encodeEvidenceRecord, decodeEvidenceRecord } from '../src/evidence-record.js';
import { buildErsTree } from '../src/ers-merkle.js';
import { verifyTimestampToken } from '../src/verify-timestamp-token.js';
import type { EvidenceRecord } from '../src/types.js';
import { createMockTsa } from './helpers/mock-tsa';

function sha256(b: Uint8Array | Buffer): Uint8Array {
    return new Uint8Array(createHash('sha256').update(b).digest());
}

describe('EvidenceRecord DER encode/decode', () => {
    let er: EvidenceRecord;
    let pinnedRootDer: Uint8Array;
    let renewalRoot: Uint8Array;

    beforeAll(async () => {
        const tsa = await createMockTsa();
        pinnedRootDer = tsa.pinnedRootDer;
        const windowRoot = sha256(Buffer.from('window-root'));
        const t1 = await tsa.issue(windowRoot, new Date('2026-06-15T00:00:00Z'));
        // A 2-window renewal batch → window 0's reducedHashtree is non-empty.
        const leaf0 = sha256(t1);
        const leaf1 = sha256(Buffer.from('other-window-token'));
        const tree = buildErsTree([leaf0, leaf1], 'SHA-256');
        renewalRoot = tree.root;
        const t2 = await tsa.issue(tree.root, new Date('2027-06-15T00:00:00Z'));
        er = {
            version: 1,
            digestAlgorithms: ['SHA-256'],
            sequence: [
                [
                    { digestAlg: 'SHA-256', reducedHashtree: [], timeStampDer: t1 },
                    { digestAlg: 'SHA-256', reducedHashtree: tree.paths[0], timeStampDer: t2 },
                ],
            ],
        };
    });

    it('round-trips structure through DER (encode → decode)', () => {
        const decoded = decodeEvidenceRecord(encodeEvidenceRecord(er));
        expect(decoded.version).toBe(1);
        expect(decoded.digestAlgorithms).toEqual(['SHA-256']);
        expect(decoded.sequence).toHaveLength(1);
        expect(decoded.sequence[0]).toHaveLength(2);
        expect(decoded.sequence[0][0].reducedHashtree).toHaveLength(0);
        expect(decoded.sequence[0][1].reducedHashtree.length).toBe(er.sequence[0][1].reducedHashtree.length);
    });

    it('DER is byte-stable: encode(decode(encode)) is identical (golden)', () => {
        const der1 = encodeEvidenceRecord(er);
        const der2 = encodeEvidenceRecord(decodeEvidenceRecord(der1));
        expect(Buffer.from(der1).equals(Buffer.from(der2))).toBe(true);
    });

    it('the embedded token survives the round-trip and still verifies', () => {
        const decoded = decodeEvidenceRecord(encodeEvidenceRecord(er));
        // The renewal ATS token must still verify against the renewal batch root.
        const verdict = verifyTimestampToken({
            token: decoded.sequence[0][1].timeStampDer,
            expectedRoot: renewalRoot,
            pinnedRoots: [pinnedRootDer],
        });
        expect(verdict.ok).toBe(true);
        expect(verdict.notAfter).toBeDefined();
    });

    it('reducedHashtree members survive exactly (byte-equal)', () => {
        const decoded = decodeEvidenceRecord(encodeEvidenceRecord(er));
        const orig = er.sequence[0][1].reducedHashtree;
        const got = decoded.sequence[0][1].reducedHashtree;
        expect(got.length).toBe(orig.length);
        for (let i = 0; i < orig.length; i++) {
            expect(got[i].length).toBe(orig[i].length);
            for (let j = 0; j < orig[i].length; j++) {
                expect(Buffer.from(got[i][j]).equals(Buffer.from(orig[i][j]))).toBe(true);
            }
        }
    });

    it('decode is fail-closed on malformed DER', () => {
        expect(() => decodeEvidenceRecord(new Uint8Array([0x05, 0x00]))).toThrow(); // NULL, not SEQUENCE
        expect(() => decodeEvidenceRecord(new Uint8Array([0x01, 0x02, 0x03]))).toThrow();
        expect(() => decodeEvidenceRecord(new Uint8Array([]))).toThrow();
    });
});

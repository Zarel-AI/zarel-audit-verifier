// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Commercial-TSA gate — credential-free closure of the COMMERCIAL-TSA
 * conformance claim.
 *
 * The mock-TSA tests (verify-timestamp-token.test) prove the verifier is correct
 * against OUR own CA — they do NOT prove a real qualified/commercial RFC 3161 TSA
 * issues a token our verifier accepts, nor that it honors SHA-256 + ESSCertIDv2 +
 * certReq=true. RFC 3161 is a ubiquitous standard, so this SHOULD hold — but
 * "should hold" is the spec, not an executed fact.
 *
 * This converts it to an executed, regression-locked fact WITHOUT CI credentials:
 * a one-time manual capture (see the `_doc` in the fixture) freezes a
 * REAL token over a fixed digest + the TSA's pinned root. This test then decodes
 * it and verifies it with the production verifier on every run.
 *
 * Until the vector is captured the suite is a visible `skip` (not silently green).
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as asn1js from 'asn1js';
import { ContentInfo, SignedData, TSTInfo } from 'pkijs';
import { verifyTimestampToken } from '../src/verify-timestamp-token.js';

interface Vector {
    status: string;
    expected_root_b64: string;
    token_b64: string;
    pinned_root_pem: string;
}

const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_SIGNING_CERTIFICATE_V2 = '1.2.840.113549.1.9.16.2.47'; // ESSCertIDv2 carrier

const vector = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'commercial-tsa-vector.json'), 'utf8')) as Vector;
const CAPTURED = vector.status === 'captured';

function pemToDer(pem: string): Uint8Array {
    const body = pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');
    return new Uint8Array(Buffer.from(body, 'base64'));
}

(CAPTURED ? describe : describe.skip)('commercial-TSA gate — real commercial TSA token (credential-free)', () => {
    const token = new Uint8Array(Buffer.from(vector.token_b64, 'base64'));
    const expectedRoot = new Uint8Array(Buffer.from(vector.expected_root_b64, 'base64url'));

    it('honors SHA-256 messageImprint over the submitted digest', () => {
        const ci = new ContentInfo({ schema: asn1js.fromBER(token).result });
        const sd = new SignedData({ schema: ci.content });
        const tst = new TSTInfo({ schema: asn1js.fromBER(Buffer.from(sd.encapContentInfo.eContent!.getValue())).result });
        expect(tst.messageImprint.hashAlgorithm.algorithmId).toBe(OID_SHA256);
        expect(Buffer.from(tst.messageImprint.hashedMessage.valueBlock.valueHexView).equals(Buffer.from(expectedRoot))).toBe(true);
    });

    it('honors certReq=true (embeds the signer cert chain) and carries ESSCertIDv2', () => {
        const ci = new ContentInfo({ schema: asn1js.fromBER(token).result });
        const sd = new SignedData({ schema: ci.content });
        expect((sd.certificates ?? []).length).toBeGreaterThan(0); // certReq honored
        const attrs = sd.signerInfos[0]?.signedAttrs?.attributes ?? [];
        expect(attrs.some((a) => a.type === OID_SIGNING_CERTIFICATE_V2)).toBe(true);
    });

    it('the production verifier accepts it against the pinned root', () => {
        const verdict = verifyTimestampToken({ token, expectedRoot, pinnedRoots: [pemToDer(vector.pinned_root_pem)] });
        expect(verdict.ok).toBe(true);
        expect(verdict.genTime).not.toBeNull();
    });
});

// Always-on guard so a malformed/empty fixture is loud, not silently skipped.
describe('commercial-TSA gate — fixture sanity', () => {
    it('the commercial-TSA vector is either pending or fully captured', () => {
        expect(['pending', 'captured']).toContain(vector.status);
        if (CAPTURED) {
            expect(vector.token_b64.length).toBeGreaterThan(0);
            expect(vector.pinned_root_pem).toContain('BEGIN CERTIFICATE');
            expect(vector.expected_root_b64.length).toBeGreaterThan(0);
        }
    });
});

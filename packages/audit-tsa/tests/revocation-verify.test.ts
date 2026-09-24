// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Revocation capture — offline verification.
 *   Core: valid contemporaneous OCSP/CRL "good" ⇒ NOT_REVOKED; revoked
 *     at-or-before genTime ⇒ REVOKED (hard fail through verifyEvidenceRecord).
 *   Fail-closed: forged signature / non-contemporaneous / wrong cert each
 *     ⇒ NOT_CAPTURED with a precise reason, never NOT_REVOKED.
 *   CRL path: non-revocation provable via a CertificateList.
 *   ASN.1 conformance: cryptoInfos round-trips byte-stable through the
 *     EvidenceRecord DER and the embedded members decode via pkijs RFC 5280/6960.
 */

import { createHash } from 'node:crypto';
import { BasicOCSPResponse, CertificateRevocationList, Certificate } from 'pkijs';
import { verifyRevocation } from '../src/verify-revocation.js';
import { verifyEvidenceRecord } from '../src/verify-evidence-record.js';
import { encodeEvidenceRecord, decodeEvidenceRecord } from '../src/evidence-record.js';
import type { CryptoInfos } from '../src/revocation.js';
import type { EvidenceRecord } from '../src/types.js';
import { createMockTsa, type MockTsa } from './helpers/mock-tsa';

function sha256(b: Uint8Array | Buffer): Uint8Array {
    return new Uint8Array(createHash('sha256').update(b).digest());
}

const GEN = new Date('2026-06-15T00:00:00Z');
// Capture happens AT/AFTER mint, so a contemporaneous proof has thisUpdate ≥ genTime
// (monotonic non-revocation: good-as-of-thisUpdate ⇒ not-revoked at the earlier genTime).
const WIN = { thisUpdate: new Date('2026-06-16T00:00:00Z'), nextUpdate: new Date('2026-06-25T00:00:00Z') };

let tsa: MockTsa;
let base: Omit<Parameters<typeof verifyRevocation>[0], 'cryptoInfos'>;

beforeAll(async () => {
    tsa = await createMockTsa();
    base = {
        signerCertDer: tsa.tsaCertDer,
        chainDer: [tsa.tsaCertDer],
        pinnedRootsDer: [tsa.pinnedRootDer],
        genTime: GEN,
    };
});

function ci(parts: Partial<CryptoInfos>): CryptoInfos {
    return { crls: parts.crls ?? [], ocsps: parts.ocsps ?? [] };
}

describe('OCSP core: good vs revoked', () => {
    it('a contemporaneous OCSP "good" ⇒ NOT_REVOKED', async () => {
        const ocsp = await tsa.issueOcsp({ status: 'good', ...WIN });
        expect(verifyRevocation({ ...base, cryptoInfos: ci({ ocsps: [ocsp] }) }).status).toBe('NOT_REVOKED');
    });

    it('revoked at-or-before genTime ⇒ REVOKED', async () => {
        const ocsp = await tsa.issueOcsp({ status: 'revoked', revocationTime: new Date('2026-06-10T00:00:00Z'), ...WIN });
        const v = verifyRevocation({ ...base, cryptoInfos: ci({ ocsps: [ocsp] }) });
        expect(v.status).toBe('REVOKED');
        expect(v.reason).toBe('revoked');
    });

    it('revoked AFTER genTime ⇒ NOT_REVOKED (valid at use-time)', async () => {
        const ocsp = await tsa.issueOcsp({ status: 'revoked', revocationTime: new Date('2026-06-18T00:00:00Z'), ...WIN });
        expect(verifyRevocation({ ...base, cryptoInfos: ci({ ocsps: [ocsp] }) }).status).toBe('NOT_REVOKED');
    });

    it('a delegated id-kp-OCSPSigning responder ⇒ NOT_REVOKED', async () => {
        const ocsp = await tsa.issueOcsp({ status: 'good', delegated: true, ...WIN });
        expect(verifyRevocation({ ...base, cryptoInfos: ci({ ocsps: [ocsp] }) }).status).toBe('NOT_REVOKED');
    });
});

describe('fail-closed: a present-but-unusable proof is NOT_CAPTURED, never NOT_REVOKED', () => {
    it('a forged signature ⇒ NOT_CAPTURED proof_signature', async () => {
        const ocsp = await tsa.issueOcsp({ status: 'good', tamperSignature: true, ...WIN });
        const v = verifyRevocation({ ...base, cryptoInfos: ci({ ocsps: [ocsp] }) });
        expect(v.status).toBe('NOT_CAPTURED');
        expect(v.reason).toBe('proof_signature');
    });

    it('a proof predating genTime ⇒ NOT_CAPTURED proof_not_contemporaneous (does not cover use-time)', async () => {
        // good-as-of 06-01 says nothing about a revocation in (06-01, genTime=06-15].
        const ocsp = await tsa.issueOcsp({ status: 'good', thisUpdate: new Date('2026-06-01T00:00:00Z'), nextUpdate: new Date('2026-06-10T00:00:00Z') });
        const v = verifyRevocation({ ...base, cryptoInfos: ci({ ocsps: [ocsp] }) });
        expect(v.status).toBe('NOT_CAPTURED');
        expect(v.reason).toBe('proof_not_contemporaneous');
    });

    it('a proof for a different cert ⇒ NOT_CAPTURED proof_cert_mismatch', async () => {
        const rootCert = Certificate.fromBER(tsa.pinnedRootDer); // serial 1 ≠ signer serial 2
        const ocsp = await tsa.issueOcsp({ status: 'good', targetCert: rootCert, ...WIN });
        const v = verifyRevocation({ ...base, cryptoInfos: ci({ ocsps: [ocsp] }) });
        expect(v.status).toBe('NOT_CAPTURED');
        expect(v.reason).toBe('proof_cert_mismatch');
    });

    it('no proof at all ⇒ NOT_CAPTURED no_proof', () => {
        const v = verifyRevocation({ ...base, cryptoInfos: ci({}) });
        expect(v.status).toBe('NOT_CAPTURED');
        expect(v.reason).toBe('no_proof');
    });

    it('a delegated responder issued by a FOREIGN CA (in the attacker cert bag) ⇒ NOT_CAPTURED, never NOT_REVOKED', async () => {
        // The exact masking attack: a forged "good" signed by a rogue OCSP responder
        // issued by an attacker CA appended to the token's (unsigned) cert bag. The
        // responder MUST be authorized only against the genuine issuer, so this rejects.
        const { ocsp, foreignCaDer } = await tsa.issueRogueDelegatedOcsp({ ...WIN });
        const v = verifyRevocation({
            ...base,
            chainDer: [tsa.tsaCertDer, foreignCaDer], // attacker appended the foreign CA
            cryptoInfos: ci({ ocsps: [ocsp] }),
        });
        expect(v.status).toBe('NOT_CAPTURED');
        expect(v.reason).toBe('proof_signature');
    });
});

describe('CRL path', () => {
    it('serial absent from a contemporaneous CRL ⇒ NOT_REVOKED', async () => {
        const crl = await tsa.issueCrl({ ...WIN, revoked: [] });
        expect(verifyRevocation({ ...base, cryptoInfos: ci({ crls: [crl] }) }).status).toBe('NOT_REVOKED');
    });

    it('serial revoked at-or-before genTime ⇒ REVOKED', async () => {
        const crl = await tsa.issueCrl({ ...WIN, revoked: [{ serial: 2, revocationDate: new Date('2026-06-10T00:00:00Z') }] });
        expect(verifyRevocation({ ...base, cryptoInfos: ci({ crls: [crl] }) }).status).toBe('REVOKED');
    });

    it('serial revoked AFTER genTime ⇒ NOT_REVOKED', async () => {
        const crl = await tsa.issueCrl({ ...WIN, revoked: [{ serial: 2, revocationDate: new Date('2026-06-19T00:00:00Z') }] });
        expect(verifyRevocation({ ...base, cryptoInfos: ci({ crls: [crl] }) }).status).toBe('NOT_REVOKED');
    });

    it('a tampered CRL signature ⇒ NOT_CAPTURED proof_signature', async () => {
        const crl = await tsa.issueCrl({ ...WIN, revoked: [], tamperSignature: true });
        expect(verifyRevocation({ ...base, cryptoInfos: ci({ crls: [crl] }) }).reason).toBe('proof_signature');
    });
});

describe('cryptoInfos ASN.1 conformance (round-trip + pkijs decode)', () => {
    it('cryptoInfos round-trips byte-stable and members decode via pkijs RFC 5280/6960', async () => {
        const ocsp = await tsa.issueOcsp({ status: 'good', ...WIN });
        const crl = await tsa.issueCrl({ ...WIN, revoked: [] });
        const t1 = await tsa.issue(sha256(Buffer.from('w')), GEN);
        const record: EvidenceRecord = {
            version: 1,
            digestAlgorithms: ['SHA-256'],
            cryptoInfos: { crls: [crl], ocsps: [ocsp] },
            sequence: [[{ digestAlg: 'SHA-256', reducedHashtree: [], timeStampDer: t1 }]],
        };
        const der1 = encodeEvidenceRecord(record);
        const decoded = decodeEvidenceRecord(der1);
        const der2 = encodeEvidenceRecord(decoded);
        expect(Buffer.from(der1).equals(Buffer.from(der2))).toBe(true);
        const got = decoded.cryptoInfos;
        expect(got).toBeDefined();
        if (!got) {
            throw new Error('cryptoInfos missing');
        }
        expect(Buffer.from(got.ocsps[0]).equals(Buffer.from(ocsp))).toBe(true);
        expect(Buffer.from(got.crls[0]).equals(Buffer.from(crl))).toBe(true);
        // The literal-CAdES gate: the embedded members are real RFC 5280/6960 structures.
        expect(() => BasicOCSPResponse.fromBER(got.ocsps[0])).not.toThrow();
        expect(() => CertificateRevocationList.fromBER(got.crls[0])).not.toThrow();
    });

    it('a record without revocation evidence (no cryptoInfos) stays byte-identical (absent slot)', async () => {
        const t1 = await tsa.issue(sha256(Buffer.from('w2')), GEN);
        const record: EvidenceRecord = { version: 1, digestAlgorithms: ['SHA-256'], sequence: [[{ digestAlg: 'SHA-256', reducedHashtree: [], timeStampDer: t1 }]] };
        const decoded = decodeEvidenceRecord(encodeEvidenceRecord(record));
        expect(decoded.cryptoInfos).toBeUndefined();
    });
});

describe('integration — verifyEvidenceRecord threads revocation', () => {
    it('a record with a good OCSP reports revocation NOT_REVOKED and verifies', async () => {
        const root = sha256(Buffer.from('iwin'));
        const t1 = await tsa.issue(root, GEN);
        const ocsp = await tsa.issueOcsp({ status: 'good', ...WIN });
        const record: EvidenceRecord = {
            version: 1, digestAlgorithms: ['SHA-256'],
            cryptoInfos: { crls: [], ocsps: [ocsp] },
            sequence: [[{ digestAlg: 'SHA-256', reducedHashtree: [], timeStampDer: t1 }]],
        };
        const v = verifyEvidenceRecord({ record, dataObjectHash: root, pinnedRoots: [tsa.pinnedRootDer], now: GEN, revocationPolicy: 'lenient' });
        expect(v.ok).toBe(true);
        expect(v.revocation).toEqual({ perToken: ['NOT_REVOKED'], checkedCount: 1, total: 1 });
    });

    it('a record whose token cert was revoked at use-time fails token_revoked', async () => {
        const root = sha256(Buffer.from('irevoked'));
        const t1 = await tsa.issue(root, GEN);
        const ocsp = await tsa.issueOcsp({ status: 'revoked', revocationTime: new Date('2026-06-10T00:00:00Z'), ...WIN });
        const record: EvidenceRecord = {
            version: 1, digestAlgorithms: ['SHA-256'],
            cryptoInfos: { crls: [], ocsps: [ocsp] },
            sequence: [[{ digestAlg: 'SHA-256', reducedHashtree: [], timeStampDer: t1 }]],
        };
        const v = verifyEvidenceRecord({ record, dataObjectHash: root, pinnedRoots: [tsa.pinnedRootDer], now: GEN, revocationPolicy: 'lenient' });
        expect(v.ok).toBe(false);
        expect(v.failure).toBe('token_revoked');
    });

    it('a record with no cryptoInfos reports no revocation summary', async () => {
        const root = sha256(Buffer.from('inocrypto'));
        const t1 = await tsa.issue(root, GEN);
        const record: EvidenceRecord = { version: 1, digestAlgorithms: ['SHA-256'], sequence: [[{ digestAlg: 'SHA-256', reducedHashtree: [], timeStampDer: t1 }]] };
        const v = verifyEvidenceRecord({ record, dataObjectHash: root, pinnedRoots: [tsa.pinnedRootDer], now: GEN, revocationPolicy: 'lenient' });
        expect(v.ok).toBe(true);
        expect(v.revocation).toBeUndefined();
    });
});

describe('revocation strict policy (stripping cannot upgrade fail→pass)', () => {
    async function revokedRecord(withCryptoInfos: boolean): Promise<{ record: EvidenceRecord; root: Uint8Array }> {
        const root = sha256(Buffer.from('strict-revoked'));
        const t1 = await tsa.issue(root, GEN);
        const ocsp = await tsa.issueOcsp({ status: 'revoked', revocationTime: new Date('2026-06-10T00:00:00Z'), ...WIN });
        const record: EvidenceRecord = {
            version: 1, digestAlgorithms: ['SHA-256'],
            ...(withCryptoInfos ? { cryptoInfos: { crls: [], ocsps: [ocsp] } } : {}),
            sequence: [[{ digestAlg: 'SHA-256', reducedHashtree: [], timeStampDer: t1 }]],
        };
        return { record, root };
    }

    it('a REVOKED signer is caught under both policies when its proof is present', async () => {
        const { record, root } = await revokedRecord(true);
        for (const revocationPolicy of ['lenient', 'strict'] as const) {
            const v = verifyEvidenceRecord({ record, dataObjectHash: root, pinnedRoots: [tsa.pinnedRootDer], now: GEN, revocationPolicy });
            expect(v.ok).toBe(false);
            expect(v.failure).toBe('token_revoked');
        }
    });

    it('stripping cryptoInfos downgrades to NOT_CAPTURED — strict fails, lenient tolerates', async () => {
        const { record, root } = await revokedRecord(false); // the RFC-4998 UNPROTECTED bag stripped
        const strict = verifyEvidenceRecord({ record, dataObjectHash: root, pinnedRoots: [tsa.pinnedRootDer], now: GEN, revocationPolicy: 'strict' });
        expect(strict.ok).toBe(false);
        expect(strict.failure).toBe('revocation_not_captured');
        // Lenient is the honest-degraded view; it CANNOT catch a stripped revocation
        // (documented residual). strict is the compliance posture that neutralises it.
        const lenient = verifyEvidenceRecord({ record, dataObjectHash: root, pinnedRoots: [tsa.pinnedRootDer], now: GEN, revocationPolicy: 'lenient' });
        expect(lenient.ok).toBe(true);
    });

    it('uniform strict includes the anchor — a record without revocation evidence fails at chainDepth 1', async () => {
        const root = sha256(Buffer.from('g25-anchor'));
        const t1 = await tsa.issue(root, GEN);
        const record: EvidenceRecord = { version: 1, digestAlgorithms: ['SHA-256'], sequence: [[{ digestAlg: 'SHA-256', reducedHashtree: [], timeStampDer: t1 }]] };
        const strict = verifyEvidenceRecord({ record, dataObjectHash: root, pinnedRoots: [tsa.pinnedRootDer], now: GEN, revocationPolicy: 'strict' });
        expect(strict.ok).toBe(false);
        expect(strict.failure).toBe('revocation_not_captured');
        expect(strict.chainDepth).toBe(1); // the anchor ATS, not just a renewal
    });

    it('strict passes with full positive non-revocation coverage', async () => {
        const root = sha256(Buffer.from('g26-good'));
        const t1 = await tsa.issue(root, GEN);
        const ocsp = await tsa.issueOcsp({ status: 'good', ...WIN });
        const record: EvidenceRecord = {
            version: 1, digestAlgorithms: ['SHA-256'],
            cryptoInfos: { crls: [], ocsps: [ocsp] },
            sequence: [[{ digestAlg: 'SHA-256', reducedHashtree: [], timeStampDer: t1 }]],
        };
        const v = verifyEvidenceRecord({ record, dataObjectHash: root, pinnedRoots: [tsa.pinnedRootDer], now: GEN, revocationPolicy: 'strict' });
        expect(v.ok).toBe(true);
        expect(v.revocation).toEqual({ perToken: ['NOT_REVOKED'], checkedCount: 1, total: 1 });
    });
});

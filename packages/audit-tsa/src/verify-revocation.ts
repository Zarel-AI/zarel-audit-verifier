// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Offline revocation verifier — pure, synchronous, fail-closed.
 *
 * Given an ATS signer cert, its issuing chain, the token's attested `genTime`, and
 * the captured CRL/OCSP from `cryptoInfos`, decide whether the signer cert was
 * revoked **at use-time** — i.e. as of a proof contemporaneous with `genTime`:
 *   - NOT_REVOKED: a valid, contemporaneous OCSP "good" / CRL-absence proves it.
 *   - REVOKED:     a valid proof shows revocation at-or-before `genTime` (hard fail).
 *   - NOT_CAPTURED: no usable proof (absent / unverifiable / stale / wrong cert).
 *
 * `cryptoInfos` is an UNPROTECTED hint bag (RFC 4998 §3.1): assurance comes ONLY
 * from each proof's OWN signature, re-verified here to a trust anchor — never from
 * its presence in the bundle. Mirroring verify-timestamp-token.ts, pkijs parses the
 * ASN.1 and `node:crypto` checks every signature, so the path stays sync + offline.
 */

import { createHash, verify as cryptoVerify, X509Certificate } from 'node:crypto';
import * as asn1js from 'asn1js';
import { BasicOCSPResponse, CertificateRevocationList, Certificate, ExtKeyUsage, type SingleResponse } from 'pkijs';
import type { CryptoInfos } from './revocation.js';
import type { TokenRevocationVerdict, RevocationRejectReason } from './types.js';
import { bytesEqual, toArrayBuffer } from './bytes.js';
import { toX509 } from './verify-timestamp-token.js';

const OID_EXT_KEY_USAGE = '2.5.29.37';
const OID_KP_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';

/** CertID / signature digest OIDs → node hash name. */
const DIGEST_OID_TO_HASH: Readonly<Record<string, string>> = {
    '2.16.840.1.101.3.4.2.1': 'sha256',
    '2.16.840.1.101.3.4.2.2': 'sha384',
    '2.16.840.1.101.3.4.2.3': 'sha512',
    '1.2.840.113549.1.1.11': 'sha256', // sha256WithRSAEncryption
    '1.2.840.113549.1.1.12': 'sha384',
    '1.2.840.113549.1.1.13': 'sha512',
    '1.2.840.10045.4.3.2': 'sha256', // ecdsa-with-SHA256
    '1.2.840.10045.4.3.3': 'sha384',
    '1.2.840.10045.4.3.4': 'sha512',
};

export interface VerifyRevocationInput {
    /** DER of the ATS signer cert whose revocation status is in question. */
    readonly signerCertDer: Uint8Array;
    /** DER of certs embedded in the token (issuer candidates + delegated responders). */
    readonly chainDer: ReadonlyArray<Uint8Array>;
    /** DER of the pinned trust anchors (also issuer candidates). */
    readonly pinnedRootsDer: ReadonlyArray<Uint8Array>;
    /** The token's attested genTime — the use-time a proof must bracket. */
    readonly genTime: Date;
    /** Captured CRL/OCSP from the EvidenceRecord's cryptoInfos. */
    readonly cryptoInfos: CryptoInfos;
}

function toPkijs(der: Uint8Array): Certificate | null {
    try {
        return Certificate.fromBER(toArrayBuffer(der));
    } catch {
        return null;
    }
}

function verifiesSig(hashName: string, tbs: Uint8Array, key: X509Certificate, sig: Uint8Array): boolean {
    try {
        return cryptoVerify(hashName, Buffer.from(tbs), key.publicKey, Buffer.from(sig));
    } catch {
        return false;
    }
}

/** Find the cert that issued `subject` among the candidates (signature + issuance check). */
function findIssuer(subject: X509Certificate, candidates: X509Certificate[]): X509Certificate | null {
    for (const cand of candidates) {
        try {
            if (subject.checkIssued(cand) && subject.verify(cand.publicKey)) {
                return cand;
            }
        } catch {
            // key-algorithm mismatch etc. → not the issuer
        }
    }
    return null;
}

/** RFC 6960 CertID hashes computed from the issuer cert under a given hash. */
function certIdHashes(issuer: Certificate, hashName: string): { nameHash: Uint8Array; keyHash: Uint8Array } {
    const nameDer = Buffer.from(issuer.subject.toSchema().toBER());
    const keyBits = Buffer.from(issuer.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
    return {
        nameHash: new Uint8Array(createHash(hashName).update(nameDer).digest()),
        keyHash: new Uint8Array(createHash(hashName).update(keyBits).digest()),
    };
}

function hasOcspSigningEku(cert: Certificate): boolean {
    const ext = (cert.extensions ?? []).find((e) => e.extnID === OID_EXT_KEY_USAGE);
    if (!ext) {
        return false;
    }
    try {
        const eku = new ExtKeyUsage({ schema: asn1js.fromBER(ext.extnValue.valueBlock.valueHexView).result });
        return eku.keyPurposes.includes(OID_KP_OCSP_SIGNING);
    } catch {
        return false;
    }
}

/** Internal per-proof outcome: a definitive verdict, or a reason it was unusable. */
type ProofResult =
    | { kind: 'not_revoked' }
    | { kind: 'revoked' }
    | { kind: 'reject'; reason: RevocationRejectReason };

function rank(reason: RevocationRejectReason): number {
    // When no proof is definitive, surface the reject reason closest to usable:
    // no_proof (nothing applicable) < wrong cert < bad signature < stale < revoked.
    return { no_proof: 0, proof_cert_mismatch: 1, proof_signature: 2, proof_not_contemporaneous: 3, revoked: 4 }[reason];
}

function checkOcsp(
    der: Uint8Array,
    signer: { serial: asn1js.Integer; pkijs: Certificate },
    issuer: { x509: X509Certificate; pkijs: Certificate },
    genTime: Date,
): ProofResult {
    let basic: BasicOCSPResponse;
    try {
        basic = BasicOCSPResponse.fromBER(toArrayBuffer(der));
    } catch {
        return { kind: 'reject', reason: 'proof_signature' };
    }

    // Match the SingleResponse for our signer cert FIRST — cheap — before the
    // expensive signature verification, so a bag of proofs for other tokens (the
    // merged window cryptoInfos holds them all) is skipped in O(1) each, not O(sig).
    let matched: SingleResponse | null = null;
    for (const single of basic.tbsResponseData.responses) {
        const cidHash = DIGEST_OID_TO_HASH[single.certID.hashAlgorithm.algorithmId];
        if (!cidHash || !single.certID.serialNumber.isEqual(signer.serial)) {
            continue;
        }
        const expected = certIdHashes(issuer.pkijs, cidHash);
        const gotName = new Uint8Array(single.certID.issuerNameHash.valueBlock.valueHexView);
        const gotKey = new Uint8Array(single.certID.issuerKeyHash.valueBlock.valueHexView);
        if (bytesEqual(gotName, expected.nameHash) && bytesEqual(gotKey, expected.keyHash)) {
            matched = single;
            break;
        }
    }
    if (!matched) {
        return { kind: 'reject', reason: 'proof_cert_mismatch' };
    }

    // Resolve + AUTHORIZE the responder. A delegated id-kp-OCSPSigning responder
    // MUST be issued by the SAME CA that issued the cert under check (`issuer.x509`),
    // per RFC 6960 §4.2.2.2 — NEVER by a cert from the token's embedded bag, which is
    // attacker-controlled (the CMS signature does not cover SignedData.certificates).
    // Trusting `chain` there would let a forged self-issued responder mint a "good"
    // that masks a revoked TSA cert (the exact property this verifier defends).
    let responder = issuer.x509;
    const embeddedResponder = (basic.certs ?? [])
        .map((c) => ({ pkijs: c, der: new Uint8Array(c.toSchema().toBER()) }))
        .find((c) => hasOcspSigningEku(c.pkijs));
    if (embeddedResponder) {
        const x = toX509(embeddedResponder.der);
        if (!x || !findIssuer(x, [issuer.x509])) {
            return { kind: 'reject', reason: 'proof_signature' };
        }
        responder = x;
    }

    // Verify the BasicOCSPResponse signature over tbsResponseData (the raw signed bytes).
    const hashName = DIGEST_OID_TO_HASH[basic.signatureAlgorithm.algorithmId];
    const tbs = basic.tbsResponseData.tbsView;
    const sig = new Uint8Array(basic.signature.valueBlock.valueHexView);
    if (!hashName || tbs.length === 0 || !verifiesSig(hashName, tbs, responder, sig)) {
        return { kind: 'reject', reason: 'proof_signature' };
    }

    // CertStatus CHOICE: good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo.
    const status = matched.certStatus as asn1js.BaseBlock;
    if (status.idBlock.tagClass === 3 && status.idBlock.tagNumber === 0) {
        // "good as of thisUpdate" ⇒ not revoked at every earlier instant (revocation is
        // monotonic), so it proves not-revoked-at-genTime ONLY if thisUpdate ≥ genTime.
        // A proof predating genTime says nothing about a revocation in (thisUpdate, genTime].
        if (matched.thisUpdate.getTime() < genTime.getTime()) {
            return { kind: 'reject', reason: 'proof_not_contemporaneous' };
        }
        return { kind: 'not_revoked' };
    }
    if (status.idBlock.tagClass === 3 && status.idBlock.tagNumber === 1) {
        const revTime = readRevocationTime(status);
        // Fail-closed: a cert MARKED revoked whose revocationTime is unparseable is
        // treated as revoked, never not-revoked. revocationDate is authoritative +
        // monotonic, so no thisUpdate gate is needed for the revoked determination.
        if (revTime === null || revTime.getTime() <= genTime.getTime()) {
            return { kind: 'revoked' };
        }
        return { kind: 'not_revoked' }; // revoked strictly AFTER use-time ⇒ valid at use-time
    }
    // unknown [2] or unparseable status: no usable info.
    return { kind: 'reject', reason: 'proof_cert_mismatch' };
}

/** RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime, ... } inside [1] IMPLICIT. */
function readRevocationTime(revokedInfo: asn1js.BaseBlock): Date | null {
    try {
        const first = (revokedInfo.valueBlock as unknown as { value?: asn1js.BaseBlock[] }).value?.[0];
        if (first instanceof asn1js.GeneralizedTime || first instanceof asn1js.UTCTime) {
            return first.toDate();
        }
    } catch {
        // fall through
    }
    return null;
}

function checkCrl(
    der: Uint8Array,
    signerSerial: asn1js.Integer,
    issuer: { x509: X509Certificate },
    genTime: Date,
): ProofResult {
    let crl: CertificateRevocationList;
    try {
        crl = CertificateRevocationList.fromBER(toArrayBuffer(der));
    } catch {
        return { kind: 'reject', reason: 'proof_signature' };
    }

    const hashName = DIGEST_OID_TO_HASH[crl.signatureAlgorithm.algorithmId];
    const sig = new Uint8Array(crl.signatureValue.valueBlock.valueHexView);
    if (!hashName || crl.tbsView.length === 0 || !verifiesSig(hashName, crl.tbsView, issuer.x509, sig)) {
        return { kind: 'reject', reason: 'proof_signature' };
    }

    // A revoked entry is authoritative + monotonic regardless of thisUpdate.
    for (const entry of crl.revokedCertificates ?? []) {
        if (entry.userCertificate.isEqual(signerSerial)) {
            const revTime = entry.revocationDate.value;
            if (revTime.getTime() <= genTime.getTime()) {
                return { kind: 'revoked' };
            }
            return { kind: 'not_revoked' }; // revoked AFTER use-time
        }
    }
    // Serial absent ⇒ "not revoked as of thisUpdate"; by monotonicity this proves
    // not-revoked-at-genTime ONLY if thisUpdate ≥ genTime (a CRL predating the token
    // cannot rule out a revocation between its thisUpdate and genTime).
    if (crl.thisUpdate.value.getTime() < genTime.getTime()) {
        return { kind: 'reject', reason: 'proof_not_contemporaneous' };
    }
    return { kind: 'not_revoked' };
}

export function verifyRevocation(input: VerifyRevocationInput): TokenRevocationVerdict {
    const { crls, ocsps } = input.cryptoInfos;
    if (crls.length === 0 && ocsps.length === 0) {
        return { status: 'NOT_CAPTURED', reason: 'no_proof' };
    }

    const signerX509 = toX509(input.signerCertDer);
    const signerPkijs = toPkijs(input.signerCertDer);
    if (!signerX509 || !signerPkijs) {
        return { status: 'NOT_CAPTURED', reason: 'no_proof' };
    }
    const signer = { serial: signerPkijs.serialNumber, pkijs: signerPkijs };

    const candidates = [...input.chainDer, ...input.pinnedRootsDer]
        .map(toX509)
        .filter((c): c is X509Certificate => c !== null);
    const issuerX509 = findIssuer(signerX509, candidates);
    if (!issuerX509) {
        return { status: 'NOT_CAPTURED', reason: 'no_proof' };
    }
    const issuerPkijs = toPkijs(new Uint8Array(issuerX509.raw));
    if (!issuerPkijs) {
        return { status: 'NOT_CAPTURED', reason: 'no_proof' };
    }
    const issuer = { x509: issuerX509, pkijs: issuerPkijs };

    let worstReject: RevocationRejectReason = 'no_proof';
    const consider = (r: ProofResult): TokenRevocationVerdict | null => {
        if (r.kind === 'revoked') {
            return { status: 'REVOKED', reason: 'revoked' };
        }
        if (r.kind === 'not_revoked') {
            return { status: 'NOT_REVOKED' };
        }
        if (rank(r.reason) > rank(worstReject)) {
            worstReject = r.reason;
        }
        return null;
    };

    // OCSP first (point-in-time, preferred), then CRL.
    for (const der of ocsps) {
        const v = consider(checkOcsp(der, signer, issuer, input.genTime));
        if (v) {
            return v;
        }
    }
    for (const der of crls) {
        const v = consider(checkCrl(der, signer.serial, issuer, input.genTime));
        if (v) {
            return v;
        }
    }
    return { status: 'NOT_CAPTURED', reason: worstReject };
}

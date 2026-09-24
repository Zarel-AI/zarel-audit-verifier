// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Offline RFC 3161 TimeStampToken verifier. Proves temporal precedence — that the Merkle root
 * (and therefore every checkpoint under it) existed before a third-party-attested
 * `genTime`. This is **anti-backdating** (unconditional: the TSA stamps its own
 * clock, so earlier existence cannot be forged). It is NOT unconditional
 * **anti-rewrite**: an operator who also distributes the bundle can rewrite a
 * window and re-anchor the new root — only a verifier holding the PRIOR anchor
 * detects it (full anti-rewrite needs the transparency log). It does NOT prove
 * content veracity, completeness, non-equivocation, or revocation.
 *
 * Trust model: the caller supplies an EXPLICIT set of pinned TSA root certs. The
 * verifier terminates the signer's chain at a pinned root and NEVER consults the
 * OS/ambient trust store — the bundle cannot be its own trust anchor. Empty
 * pinnedRoots ⇒ fail-closed.
 *
 * Parsing uses `pkijs` (the confined ASN.1/CMS surface); every signature
 * check uses `node:crypto` (`X509Certificate`, `crypto.verify`). Synchronous: the
 * signature is verified over the re-tagged DER of the signed attributes, so no
 * WebCrypto/async engine is needed on the verify path.
 */

import { createHash, verify as cryptoVerify, X509Certificate, type KeyObject } from 'node:crypto';
import * as asn1js from 'asn1js';
import { SignerInfo, SignedAndUnsignedAttributes, IssuerAndSerialNumber, ExtKeyUsage, Certificate } from 'pkijs';
import type { TokenFailure, TokenVerdict, VerifyTokenInput } from './types.js';
import { bytesEqual } from './bytes.js';
import { parseContentInfo, tstInfoFromContentInfo } from './cms.js';

const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_EXT_KEY_USAGE = '2.5.29.37';
const OID_KP_TIMESTAMPING = '1.3.6.1.5.5.7.3.8';

/** SHA-2 digest OID → node hash name. Anything else is unsupported → fail-closed. */
const DIGEST_OID_TO_HASH: Readonly<Record<string, string>> = {
    '2.16.840.1.101.3.4.2.1': 'sha256',
    '2.16.840.1.101.3.4.2.2': 'sha384',
    '2.16.840.1.101.3.4.2.3': 'sha512',
};

const CHAIN_MAX_DEPTH = 8;

function fail(failure: TokenFailure): TokenVerdict {
    return { ok: false, genTime: null, failure };
}

/** `cert.verify()` throws on a key-algorithm mismatch — treat any throw as "does not verify" (fail-closed). */
function verifies(cert: X509Certificate, issuerKey: KeyObject): boolean {
    try {
        return cert.verify(issuerKey);
    } catch {
        return false;
    }
}

interface ParsedToken {
    signerInfo: SignerInfo;
    signedAttrs: SignedAndUnsignedAttributes;
    signerCert: Certificate;
    signerX509: X509Certificate;
    embedded: X509Certificate[];
    tstBytes: Buffer;
    imprint: Uint8Array;
    genTime: Date;
}

/** Parse a DER TimeStampToken into the artifacts the verifier needs; null on any structural failure. */
function parseToken(token: Uint8Array): ParsedToken | null {
    try {
        const { signedData: sd, tstInfo: tst, tstBytes } = tstInfoFromContentInfo(parseContentInfo(token));
        const signerInfo = sd.signerInfos[0];
        if (!signerInfo || !signerInfo.signedAttrs) {
            return null;
        }

        const certs = (sd.certificates ?? []).filter((c): c is Certificate => c instanceof Certificate);
        const signerCert = findSignerCert(certs, signerInfo);
        if (!signerCert) {
            return null;
        }

        const imprint = new Uint8Array(tst.messageImprint.hashedMessage.valueBlock.valueHexView);

        return {
            signerInfo,
            signedAttrs: signerInfo.signedAttrs,
            signerCert,
            signerX509: new X509Certificate(Buffer.from(signerCert.toSchema().toBER())),
            embedded: certs.map((c) => new X509Certificate(Buffer.from(c.toSchema().toBER()))),
            tstBytes,
            imprint,
            genTime: tst.genTime,
        };
    } catch {
        return null;
    }
}

/** Resolve the SignerInfo's certificate (by IssuerAndSerialNumber, else the first
 *  embedded cert). Exported so the renewal-deadline reader uses the SAME resolution
 *  as verification — they must never disagree on "which cert is the TSA signer". */
export function findSignerCert(certs: Certificate[], signerInfo: SignerInfo): Certificate | undefined {
    const sid: unknown = signerInfo.sid;
    if (sid instanceof IssuerAndSerialNumber) {
        const match = certs.find(
            (c) => c.issuer.isEqual(sid.issuer) && c.serialNumber.isEqual(sid.serialNumber),
        );
        if (match) {
            return match;
        }
    }
    // SubjectKeyIdentifier sid (or no match): the token carries the signer cert — v1 uses the first.
    return certs[0];
}

/** Verify the CMS signature over the signed attributes (re-tagged [0] IMPLICIT → SET OF) + messageDigest binding. */
function verifyCmsSignature(parsed: ParsedToken): boolean {
    const { signerInfo, signedAttrs, signerX509, tstBytes } = parsed;
    const hashName = DIGEST_OID_TO_HASH[signerInfo.digestAlgorithm.algorithmId];
    if (!hashName) {
        return false;
    }

    // The signed attributes must bind to the eContent we will compare against.
    const mdAttr = signedAttrs.attributes.find((a) => a.type === OID_MESSAGE_DIGEST);
    const mdValue = mdAttr?.values[0] as asn1js.OctetString | undefined;
    if (!mdValue) {
        return false;
    }
    const expectedMd = createHash(hashName).update(tstBytes).digest();
    if (!bytesEqual(new Uint8Array(mdValue.valueBlock.valueHexView), new Uint8Array(expectedMd))) {
        return false;
    }

    // The signature covers the DER of the signed attributes with the tag changed
    // from [0] IMPLICIT (0xA0) to universal SET OF (0x31). Length/content identical.
    const attrsDer = Buffer.from(signedAttrs.encodedValue);
    if (attrsDer.length === 0) {
        return false;
    }
    const setEncoded = Buffer.from(attrsDer);
    setEncoded[0] = 0x31;
    const signature = Buffer.from(signerInfo.signature.valueBlock.valueHexView);
    try {
        return cryptoVerify(hashName, setEncoded, signerX509.publicKey, signature);
    } catch {
        return false;
    }
}

/** The signer cert carries a critical id-kp-timeStamping extended key usage. */
function hasCriticalTimestampingEku(signerCert: Certificate): boolean {
    const ext = (signerCert.extensions ?? []).find((e) => e.extnID === OID_EXT_KEY_USAGE);
    if (!ext || ext.critical !== true) {
        return false;
    }
    try {
        const eku = new ExtKeyUsage({ schema: asn1js.fromBER(ext.extnValue.valueBlock.valueHexView).result });
        return eku.keyPurposes.includes(OID_KP_TIMESTAMPING);
    } catch {
        return false;
    }
}

/**
 * Walk signer → embedded intermediates → a pinned root, verifying each issuance
 * signature AND the X.509 CA constraints on every intermediate.
 *
 * An embedded cert may only be used as an *issuer* if it is a CA
 * (`basicConstraints cA=TRUE`, surfaced by `X509Certificate.ca`). Without this,
 * an attacker holding ANY end-entity cert that chains to the pinned root could
 * use it as a forged "intermediate" to sign a forged TSA signer cert and mint
 * arbitrary tokens (the missing-basicConstraints class, CVE-2002-0862). Node's
 * `checkIssued` already rejects an issuer whose keyUsage omits keyCertSign, but
 * it does NOT consult basicConstraints — so the `ca` gate is required here. The
 * pinned root is the trust anchor (trusted by configuration) and is exempt; the
 * signer leaf is never used as an issuer, so it need not be a CA.
 */
function chainsToPinnedRoot(parsed: ParsedToken, pinnedRoots: X509Certificate[]): boolean {
    let current = parsed.signerX509;
    const seen = new Set<string>();
    for (let depth = 0; depth < CHAIN_MAX_DEPTH; depth++) {
        for (const root of pinnedRoots) {
            if (current.checkIssued(root) && verifies(current, root.publicKey)) {
                return true;
            }
        }
        seen.add(current.fingerprint256);
        const issuer = parsed.embedded.find(
            (c) => c.ca && !seen.has(c.fingerprint256) && current.checkIssued(c) && verifies(current, c.publicKey),
        );
        if (!issuer) {
            return false;
        }
        current = issuer;
    }
    return false;
}

/** Parse DER → node X509Certificate; null on any parse failure (fail-closed). Shared. */
export function toX509(der: Uint8Array): X509Certificate | null {
    try {
        return new X509Certificate(Buffer.from(der));
    } catch {
        return null;
    }
}

/** The signer cert, the embedded chain, and the attested genTime of a token —
 *  exposed so the revocation verifier resolves the SAME signer cert the
 *  token verifier does, and reuses the SAME genTime (the use-time a proof must
 *  bracket). Returns null on any structural failure (fail-closed). */
export function parseTokenCerts(
    tokenDer: Uint8Array,
): { signerCert: X509Certificate; chain: X509Certificate[]; genTime: Date } | null {
    const parsed = parseToken(tokenDer);
    if (!parsed) {
        return null;
    }
    return { signerCert: parsed.signerX509, chain: parsed.embedded, genTime: parsed.genTime };
}

export function verifyTimestampToken(input: VerifyTokenInput): TokenVerdict {
    if (input.pinnedRoots.length === 0) {
        return fail('no_pinned_root');
    }

    const parsed = parseToken(input.token);
    if (!parsed) {
        return fail('malformed_token');
    }

    if (!verifyCmsSignature(parsed)) {
        return fail('cms_signature');
    }

    if (!hasCriticalTimestampingEku(parsed.signerCert)) {
        return fail('eku_timestamping');
    }

    const pinnedRoots = input.pinnedRoots.map(toX509).filter((c): c is X509Certificate => c !== null);
    if (pinnedRoots.length === 0 || !chainsToPinnedRoot(parsed, pinnedRoots)) {
        return fail('chain_to_pinned_root');
    }

    const genTimeMs = parsed.genTime.getTime();
    const notBefore = new Date(parsed.signerX509.validFrom).getTime();
    const notAfter = new Date(parsed.signerX509.validTo).getTime();
    if (Number.isNaN(genTimeMs) || genTimeMs < notBefore || genTimeMs > notAfter) {
        return fail('gentime_outside_validity');
    }

    if (!bytesEqual(parsed.imprint, input.expectedRoot)) {
        return fail('imprint_mismatch');
    }

    return {
        ok: true,
        genTime: parsed.genTime.toISOString(),
        notAfter: new Date(parsed.signerX509.validTo).toISOString(),
    };
}

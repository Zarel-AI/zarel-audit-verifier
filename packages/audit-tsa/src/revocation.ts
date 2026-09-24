// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * RFC 4998 `cryptoInfos` carrying CAdES `revocation-values` — DER
 * encode/decode. This is the long-term-validation evidence a bare token lacks:
 * the captured CRL/OCSP evidence that proves the TSA signer cert was not revoked
 * at the token's use-time.
 *
 *   CryptoInfos ::= SEQUENCE SIZE (1..MAX) OF Attribute          -- RFC 4998 §3.1
 *   Attribute   ::= SEQUENCE { type OBJECT IDENTIFIER, values SET OF AttributeValue }
 *
 *   -- the single Attribute we emit (CAdES, RFC 5126 §6.3.4):
 *   id-aa-ets-revocationValues OBJECT IDENTIFIER ::= { ... 24 }  -- 1.2.840.113549.1.9.16.2.24
 *   RevocationValues ::= SEQUENCE {
 *     crlVals   [0] SEQUENCE OF CertificateList   OPTIONAL,
 *     ocspVals  [1] SEQUENCE OF BasicOCSPResponse OPTIONAL,
 *     otherRevVals [2] OtherRevVals               OPTIONAL }     -- never emitted; ignored on decode
 *
 * Tagging (load-bearing):
 *   - `cryptoInfos [0]` is IMPLICIT — the RFC 4998 module is IMPLICIT TAGS (same as
 *     evidence-record.ts), so the [0] tag REPLACES the CryptoInfos SEQUENCE tag.
 *   - `crlVals [0]` / `ocspVals [1]` are EXPLICIT — the CAdES/ESF module is EXPLICIT
 *     TAGS, matching the de-facto reference implementation (BouncyCastle
 *     `RevocationValues` emits `DERTaggedObject(true, n, DERSequence(...))`), so the
 *     [n] tag WRAPS the SEQUENCE OF. The tests pin this: each embedded member must decode
 *     through pkijs's RFC 5280 `CertificateRevocationList` / RFC 6960
 *     `BasicOCSPResponse`, and the whole structure must round-trip byte-stable.
 *
 * `cryptoInfos` is an UNPROTECTED hint bag (RFC 4998 §3.1) — its integrity is NOT
 * derived from the timestamps; each CRL/OCSP is self-signed by its issuer and is
 * re-verified by verify-revocation.ts. Decode is fail-closed: structural surprises
 * throw, so a malformed record never silently degrades the verifier.
 */

import * as asn1js from 'asn1js';
import { toArrayBuffer } from './bytes.js';

const OID_REVOCATION_VALUES = '1.2.840.113549.1.9.16.2.24';

const TAG_CONTEXT = 3;
const TAG_CRYPTO_INFOS = 0; // EvidenceRecord.cryptoInfos [0] (IMPLICIT)
const TAG_CRL_VALS = 0; // RevocationValues.crlVals [0] (EXPLICIT)
const TAG_OCSP_VALS = 1; // RevocationValues.ocspVals [1] (EXPLICIT)

/**
 * The decoded revocation evidence carried in `cryptoInfos`. CRLs and OCSP
 * responses are kept as opaque DER (the bytes their own issuer signed); the
 * verifier parses + signature-checks them. Empty arrays ⇒ nothing captured.
 */
export interface CryptoInfos {
    /** DER `CertificateList` (RFC 5280 CRL) values. */
    readonly crls: ReadonlyArray<Uint8Array>;
    /** DER `BasicOCSPResponse` (RFC 6960) values. */
    readonly ocsps: ReadonlyArray<Uint8Array>;
}

export function isCryptoInfosEmpty(ci: CryptoInfos | undefined): boolean {
    return !ci || (ci.crls.length === 0 && ci.ocsps.length === 0);
}

// ───────────────────────────── encode ─────────────────────────────

/** Embed a DER blob verbatim as an asn1js element (the bytes its issuer signed). */
function embed(der: Uint8Array, label: string): asn1js.BaseBlock {
    const parsed = asn1js.fromBER(toArrayBuffer(der));
    if (parsed.offset === -1) {
        throw new Error(`encodeCryptoInfos: ${label} is not valid DER`);
    }
    return parsed.result;
}

function encodeRevocationValues(ci: CryptoInfos): asn1js.Sequence {
    const value: asn1js.BaseBlock[] = [];
    if (ci.crls.length > 0) {
        value.push(
            new asn1js.Constructed({
                idBlock: { tagClass: TAG_CONTEXT, tagNumber: TAG_CRL_VALS },
                value: [new asn1js.Sequence({ value: ci.crls.map((c) => embed(c, 'crlVals member')) })],
            }),
        );
    }
    if (ci.ocsps.length > 0) {
        value.push(
            new asn1js.Constructed({
                idBlock: { tagClass: TAG_CONTEXT, tagNumber: TAG_OCSP_VALS },
                value: [new asn1js.Sequence({ value: ci.ocsps.map((o) => embed(o, 'ocspVals member')) })],
            }),
        );
    }
    return new asn1js.Sequence({ value });
}

/** Encode a bare `RevocationValues` SEQUENCE to DER — the bytes to store per token
 *  at capture time (the CAdES structure, ready to splice into cryptoInfos when a bundle is assembled). */
export function encodeRevocationValuesDer(ci: CryptoInfos): Uint8Array {
    return new Uint8Array(encodeRevocationValues(ci).toBER());
}

/** Decode a bare `RevocationValues` DER back to its CRL/OCSP members. Fail-closed. */
export function decodeRevocationValuesDer(der: Uint8Array): CryptoInfos {
    const parsed = asn1js.fromBER(toArrayBuffer(der));
    if (parsed.offset === -1) {
        throw new Error('decodeRevocationValuesDer: not valid DER');
    }
    return decodeRevocationValues(parsed.result);
}

/** Concatenate several captured `CryptoInfos` into one (the per-window record carries
 *  the union of its anchor + renewal tokens' revocation evidence). */
export function mergeCryptoInfos(parts: ReadonlyArray<CryptoInfos>): CryptoInfos {
    return {
        crls: parts.flatMap((p) => [...p.crls]),
        ocsps: parts.flatMap((p) => [...p.ocsps]),
    };
}

/** Encode `cryptoInfos [0]` (IMPLICIT) holding one `id-aa-ets-revocationValues`
 *  Attribute. Returns the context-[0] element to splice into the EvidenceRecord. */
export function encodeCryptoInfos(ci: CryptoInfos): asn1js.Constructed {
    const attribute = new asn1js.Sequence({
        value: [
            new asn1js.ObjectIdentifier({ value: OID_REVOCATION_VALUES }),
            new asn1js.Set({ value: [encodeRevocationValues(ci)] }),
        ],
    });
    // CryptoInfos ::= SEQUENCE OF Attribute, IMPLICIT-tagged [0] → constructed [0]
    // whose direct children are the Attribute members.
    return new asn1js.Constructed({
        idBlock: { tagClass: TAG_CONTEXT, tagNumber: TAG_CRYPTO_INFOS },
        value: [attribute],
    });
}

// ───────────────────────────── decode ─────────────────────────────

function childrenOf(el: asn1js.BaseBlock, ctx: string): asn1js.BaseBlock[] {
    const value = (el.valueBlock as unknown as { value?: asn1js.BaseBlock[] }).value;
    if (!Array.isArray(value)) {
        throw new Error(`decodeCryptoInfos: ${ctx} is not a constructed element`);
    }
    return value;
}

function isContext(el: asn1js.BaseBlock, tagNumber: number): boolean {
    return el.idBlock.tagClass === TAG_CONTEXT && el.idBlock.tagNumber === tagNumber;
}

function decodeRevocationValues(seq: asn1js.BaseBlock): CryptoInfos {
    const crls: Uint8Array[] = [];
    const ocsps: Uint8Array[] = [];
    for (const field of childrenOf(seq, 'RevocationValues')) {
        if (isContext(field, TAG_CRL_VALS)) {
            // EXPLICIT [0] → single SEQUENCE OF child holding the CertificateLists.
            const inner = childrenOf(field, 'crlVals')[0];
            for (const crl of childrenOf(inner, 'crlVals SEQUENCE OF')) {
                crls.push(new Uint8Array(crl.toBER()));
            }
        } else if (isContext(field, TAG_OCSP_VALS)) {
            const inner = childrenOf(field, 'ocspVals')[0];
            for (const ocsp of childrenOf(inner, 'ocspVals SEQUENCE OF')) {
                ocsps.push(new Uint8Array(ocsp.toBER()));
            }
        }
        // [2] otherRevVals or any future field: ignored (forward-compatible).
    }
    return { crls, ocsps };
}

/** Decode a `cryptoInfos [0]` element into the captured CRL/OCSP DER. Returns the
 *  revocation-values payload; non-revocation-values Attributes are ignored. */
export function decodeCryptoInfos(cryptoInfosEl: asn1js.BaseBlock): CryptoInfos {
    const attributes = childrenOf(cryptoInfosEl, 'CryptoInfos');
    for (const attr of attributes) {
        const fields = childrenOf(attr, 'Attribute');
        const oid = fields[0];
        if (!(oid instanceof asn1js.ObjectIdentifier)) {
            throw new Error('decodeCryptoInfos: Attribute type is not an OBJECT IDENTIFIER');
        }
        if (oid.valueBlock.toString() !== OID_REVOCATION_VALUES) {
            continue; // forward-compatible: ignore non-revocation-values attributes
        }
        const values = childrenOf(fields[1], 'Attribute values');
        if (values.length === 0) {
            throw new Error('decodeCryptoInfos: revocation-values Attribute has no value');
        }
        return decodeRevocationValues(values[0]);
    }
    return { crls: [], ocsps: [] };
}

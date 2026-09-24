// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * RFC 4998 §4 EvidenceRecord — DER encode/decode.
 *
 * pkijs ships no ERS module, so this builds the ASN.1 from raw `asn1js`
 * primitives against the verified RFC module. The module is
 * IMPLICIT TAGS, so the optional `[n]` fields are implicitly-tagged (the tag
 * replaces the base type's tag; contents are unchanged).
 *
 *   EvidenceRecord ::= SEQUENCE {
 *     version                   INTEGER,                       -- 1
 *     digestAlgorithms          SEQUENCE OF AlgorithmIdentifier,
 *     cryptoInfos               [0] CryptoInfos OPTIONAL,      -- captured CRL/OCSP, when present
 *     encryptionInfo            [1] EncryptionInfo OPTIONAL,   -- absent (we do not encrypt)
 *     archiveTimeStampSequence  ArchiveTimeStampSequence }
 *   ArchiveTimeStampChain ::= SEQUENCE OF ArchiveTimeStamp
 *   ArchiveTimeStamp ::= SEQUENCE {
 *     digestAlgorithm [0] AlgorithmIdentifier OPTIONAL,        -- always emitted (per-ATS alg)
 *     attributes      [1] Attributes OPTIONAL,                 -- absent
 *     reducedHashtree [2] SEQUENCE OF PartialHashtree OPTIONAL,
 *     timeStamp       ContentInfo }                            -- the DER RFC 3161 token
 *   PartialHashtree ::= SEQUENCE OF OCTET STRING
 *
 * Decode is fail-closed: any structural surprise throws, so a malformed record
 * never silently degrades the verifier.
 */

import * as asn1js from 'asn1js';
import type { EvidenceRecord, ErsArchiveTimeStamp, ErsChain } from './types.js';
import type { ErsHashAlg, PartialHashtree, ReducedHashtree } from './ers-merkle.js';
import { encodeCryptoInfos, decodeCryptoInfos, isCryptoInfosEmpty } from './revocation.js';
import { toArrayBuffer } from './bytes.js';

const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_SHA384 = '2.16.840.1.101.3.4.2.2';

const ALG_TO_OID: Record<ErsHashAlg, string> = { 'SHA-256': OID_SHA256, 'SHA-384': OID_SHA384 };
const OID_TO_ALG: Record<string, ErsHashAlg> = { [OID_SHA256]: 'SHA-256', [OID_SHA384]: 'SHA-384' };

const TAG_CONTEXT = 3;
const TAG_DIGEST_ALG = 0;
const TAG_REDUCED_HASHTREE = 2;

// ───────────────────────────── encode ─────────────────────────────

function algorithmIdentifier(alg: ErsHashAlg): asn1js.Sequence {
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID } — params absent (standard for SHA-2).
    return new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: ALG_TO_OID[alg] })] });
}

function partialHashtree(members: PartialHashtree): asn1js.Sequence {
    return new asn1js.Sequence({
        value: members.map((m) => new asn1js.OctetString({ valueHex: toArrayBuffer(m) })),
    });
}

function archiveTimeStamp(ats: ErsArchiveTimeStamp): asn1js.Sequence {
    const value: asn1js.BaseBlock[] = [];
    // [0] IMPLICIT AlgorithmIdentifier → constructed context-0 holding the OID.
    value.push(
        new asn1js.Constructed({
            idBlock: { tagClass: TAG_CONTEXT, tagNumber: TAG_DIGEST_ALG },
            value: [new asn1js.ObjectIdentifier({ value: ALG_TO_OID[ats.digestAlg] })],
        }),
    );
    // [2] IMPLICIT SEQUENCE OF PartialHashtree (omitted when the proof is empty).
    if (ats.reducedHashtree.length > 0) {
        value.push(
            new asn1js.Constructed({
                idBlock: { tagClass: TAG_CONTEXT, tagNumber: TAG_REDUCED_HASHTREE },
                value: ats.reducedHashtree.map(partialHashtree),
            }),
        );
    }
    // timeStamp ContentInfo — embed the token's parsed DER element verbatim.
    const parsed = asn1js.fromBER(toArrayBuffer(ats.timeStampDer));
    if (parsed.offset === -1) {
        throw new Error('encodeEvidenceRecord: timeStampDer is not valid DER');
    }
    value.push(parsed.result);
    return new asn1js.Sequence({ value });
}

/** Encode `ArchiveTimeStampSequence` (SEQUENCE OF ArchiveTimeStampChain) alone —
 * the `atsc(i)` whose hash binds a hash-tree-renewal chain to all prior ones
 * (RFC 4998 §5.3). The verifier and the renewal builder MUST agree on this byte
 * encoding, so it lives here, used by both. */
export function encodeArchiveTimeStampSequence(chains: ReadonlyArray<ErsChain>): Uint8Array {
    const seq = new asn1js.Sequence({
        value: chains.map((chain) => new asn1js.Sequence({ value: chain.map(archiveTimeStamp) })),
    });
    return new Uint8Array(seq.toBER());
}

export function encodeEvidenceRecord(record: EvidenceRecord): Uint8Array {
    const value: asn1js.BaseBlock[] = [
        new asn1js.Integer({ value: record.version }),
        new asn1js.Sequence({ value: record.digestAlgorithms.map(algorithmIdentifier) }),
    ];
    // cryptoInfos [0] (IMPLICIT) — emitted only when revocation evidence is present.
    if (record.cryptoInfos && !isCryptoInfosEmpty(record.cryptoInfos)) {
        value.push(encodeCryptoInfos(record.cryptoInfos));
    }
    // archiveTimeStampSequence ::= SEQUENCE OF (SEQUENCE OF ArchiveTimeStamp)
    value.push(
        new asn1js.Sequence({
            value: record.sequence.map((chain) => new asn1js.Sequence({ value: chain.map(archiveTimeStamp) })),
        }),
    );
    return new Uint8Array(new asn1js.Sequence({ value }).toBER());
}

// ───────────────────────────── decode ─────────────────────────────

function isContext(el: asn1js.BaseBlock, tagNumber: number): boolean {
    return el.idBlock.tagClass === TAG_CONTEXT && el.idBlock.tagNumber === tagNumber;
}

function oidOf(el: asn1js.BaseBlock): string {
    if (!(el instanceof asn1js.ObjectIdentifier)) {
        throw new Error('decodeEvidenceRecord: expected OBJECT IDENTIFIER');
    }
    return el.valueBlock.toString();
}

function algFromOid(oid: string): ErsHashAlg {
    const alg = OID_TO_ALG[oid];
    if (!alg) {
        throw new Error(`decodeEvidenceRecord: unsupported digest algorithm OID ${oid}`);
    }
    return alg;
}

function decodePartialHashtree(seq: asn1js.BaseBlock): PartialHashtree {
    const members = childrenOf(seq);
    return members.map((m) => {
        if (!(m instanceof asn1js.OctetString)) {
            throw new Error('decodeEvidenceRecord: PartialHashtree member is not OCTET STRING');
        }
        return new Uint8Array(m.valueBlock.valueHexView);
    });
}

function childrenOf(el: asn1js.BaseBlock): asn1js.BaseBlock[] {
    const value = (el.valueBlock as unknown as { value?: asn1js.BaseBlock[] }).value;
    if (!Array.isArray(value)) {
        throw new Error('decodeEvidenceRecord: expected a constructed element');
    }
    return value;
}

function decodeArchiveTimeStamp(seq: asn1js.BaseBlock): ErsArchiveTimeStamp {
    const els = childrenOf(seq);
    let digestAlg: ErsHashAlg | null = null;
    let reducedHashtree: ReducedHashtree = [];
    let timeStampDer: Uint8Array | null = null;

    for (const el of els) {
        if (isContext(el, TAG_DIGEST_ALG)) {
            digestAlg = algFromOid(oidOf(childrenOf(el)[0]));
        } else if (isContext(el, TAG_REDUCED_HASHTREE)) {
            reducedHashtree = childrenOf(el).map(decodePartialHashtree);
        } else if (el.idBlock.tagClass === TAG_CONTEXT) {
            // [1] attributes or an unknown future field — ignore (forward-compatible).
            continue;
        } else {
            // The single universal element is the timeStamp ContentInfo.
            timeStampDer = new Uint8Array(el.toBER());
        }
    }

    if (digestAlg === null) {
        throw new Error('decodeEvidenceRecord: ArchiveTimeStamp missing digestAlgorithm');
    }
    if (timeStampDer === null) {
        throw new Error('decodeEvidenceRecord: ArchiveTimeStamp missing timeStamp');
    }
    return { digestAlg, reducedHashtree, timeStampDer };
}

export function decodeEvidenceRecord(der: Uint8Array): EvidenceRecord {
    const parsed = asn1js.fromBER(toArrayBuffer(der));
    if (parsed.offset === -1) {
        throw new Error('decodeEvidenceRecord: not valid DER');
    }
    const top = childrenOf(parsed.result);
    if (top.length < 3) {
        throw new Error('decodeEvidenceRecord: EvidenceRecord has too few fields');
    }

    const version = top[0];
    if (!(version instanceof asn1js.Integer) || version.valueBlock.valueDec !== 1) {
        throw new Error('decodeEvidenceRecord: unsupported version (expected 1)');
    }

    const digestAlgorithms = childrenOf(top[1]).map((ai) => algFromOid(oidOf(childrenOf(ai)[0])));
    if (digestAlgorithms.length === 0) {
        throw new Error('decodeEvidenceRecord: empty digestAlgorithms');
    }

    // archiveTimeStampSequence is the last (mandatory) field; the optional [0]
    // cryptoInfos / [1] encryptionInfo sit between digestAlgorithms and it.
    const atsSequence = top[top.length - 1];
    if (atsSequence.idBlock.tagClass === TAG_CONTEXT) {
        throw new Error('decodeEvidenceRecord: missing archiveTimeStampSequence');
    }

    // cryptoInfos [0] (IMPLICIT), if present, carries the captured CRL/OCSP.
    let cryptoInfos: EvidenceRecord['cryptoInfos'];
    for (let i = 2; i < top.length - 1; i++) {
        const field = top[i];
        if (field.idBlock.tagClass === TAG_CONTEXT && field.idBlock.tagNumber === 0) {
            const decoded = decodeCryptoInfos(field);
            if (!isCryptoInfosEmpty(decoded)) {
                cryptoInfos = decoded;
            }
        }
    }

    const sequence: ErsChain[] = childrenOf(atsSequence).map((chain) =>
        childrenOf(chain).map(decodeArchiveTimeStamp),
    );
    if (sequence.length === 0) {
        throw new Error('decodeEvidenceRecord: empty archiveTimeStampSequence');
    }

    return cryptoInfos ? { version: 1, digestAlgorithms, cryptoInfos, sequence } : { version: 1, digestAlgorithms, sequence };
}

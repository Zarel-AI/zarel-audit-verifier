// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * RFC 4998 §5.4 EvidenceRecord verifier — pure, offline, fail-closed.
 *
 * Walks the ArchiveTimeStampSequence for ONE data object (a window's merkle_root)
 * and establishes that the evidence is still cryptographically valid TODAY despite
 * the original TSA cert having expired, by:
 *   1. the initial ATS covering the data object hash;
 *   2. each intra-chain renewal covering H_alg(the prior ATS's token) (§5.2);
 *   3. each later chain's first ATS covering H'(H'(data) ‖ H'(prior sequence)) (§5.3);
 *   4. each renewal's genTime falling BEFORE the prior ATS's cert notAfter (no lapse);
 *   5. the LAST ATS's cert being valid at the verification time `now`.
 *
 * Each ATS token is verified by the unchanged `verifyTimestampToken` (CMS sig,
 * chain→pinned root, EKU, genTime∈validity, imprint). This verifier adds only the
 * cross-ATS chaining + the freshness check. Honest label: "verifiable for years"
 * is CONDITIONAL on renewal before each expiry — a `renewal_gap` is irrecoverable.
 */

import { computeErsRoot, ersHash } from './ers-merkle.js';
import { encodeArchiveTimeStampSequence } from './evidence-record.js';
import { verifyTimestampToken, parseTokenCerts } from './verify-timestamp-token.js';
import { verifyRevocation } from './verify-revocation.js';
import type { EvidenceRecord, EvidenceRecordVerdict, RenewalFailure, RevocationPolicy, TokenRevocationStatus } from './types.js';

function fail(failure: RenewalFailure, chainDepth: number): EvidenceRecordVerdict {
    return { ok: false, chainDepth, oldestGenTime: null, latestGenTime: null, latestNotAfter: null, failure };
}

export interface VerifyEvidenceRecordInput {
    readonly record: EvidenceRecord;
    /** The data object the record covers — the window's recomputed merkle_root. */
    readonly dataObjectHash: Uint8Array;
    readonly pinnedRoots: ReadonlyArray<Uint8Array>;
    /** Verification time; the last ATS's cert must still be valid at this instant. */
    readonly now: Date;
    /** Revocation posture — required, no silent default. See RevocationPolicy. */
    readonly revocationPolicy: RevocationPolicy;
}

export function verifyEvidenceRecord(input: VerifyEvidenceRecordInput): EvidenceRecordVerdict {
    const { record, dataObjectHash, pinnedRoots, now, revocationPolicy } = input;
    if (record.sequence.length === 0 || record.sequence.every((c) => c.length === 0)) {
        return fail('empty_sequence', 0);
    }

    let depth = 0;
    let oldestGenTime: string | null = null;
    let latestGenTime: string | null = null;
    let latestNotAfter: string | null = null;
    let prevNotAfterMs: number | null = null;
    let prevTokenDer: Uint8Array | null = null;
    // Per-ATS revocation status, only when the record carried cryptoInfos.
    const cryptoInfos = record.cryptoInfos;
    const perTokenRevocation: TokenRevocationStatus[] = [];

    for (let chainIndex = 0; chainIndex < record.sequence.length; chainIndex++) {
        const chain = record.sequence[chainIndex];
        // The prior sequence (chains 0..chainIndex-1) binds a hash-tree-renewal chain.
        const priorSeqDer =
            chainIndex > 0 ? encodeArchiveTimeStampSequence(record.sequence.slice(0, chainIndex)) : null;

        for (let atsIndex = 0; atsIndex < chain.length; atsIndex++) {
            const ats = chain[atsIndex];
            depth++;

            // 1. Determine the leaf this ATS must cover, by position.
            let leaf: Uint8Array;
            let linkFailure: RenewalFailure;
            if (chainIndex === 0 && atsIndex === 0) {
                leaf = dataObjectHash;
                linkFailure = 'inclusion_mismatch';
            } else if (atsIndex === 0) {
                // Hash-tree renewal link (§5.3): H'(H'(data) ‖ H'(prior sequence)).
                const hData = ersHash(ats.digestAlg, dataObjectHash);
                const ha = ersHash(ats.digestAlg, priorSeqDer as Uint8Array);
                leaf = ersHash(ats.digestAlg, hData, ha);
                linkFailure = 'cross_chain_link_broken';
            } else {
                // Timestamp renewal link (§5.2): H_alg(prior ATS's token).
                leaf = ersHash(ats.digestAlg, prevTokenDer as Uint8Array);
                linkFailure = 'renewal_link_broken';
            }

            // 2. Recompute the tree root the leaf reaches; it MUST equal the token imprint.
            const root = computeErsRoot(leaf, ats.reducedHashtree, ats.digestAlg);
            if (root === null) {
                return fail(linkFailure, depth);
            }

            // 3. Verify the token cryptographically over that root.
            const verdict = verifyTimestampToken({ token: ats.timeStampDer, expectedRoot: root, pinnedRoots });
            if (!verdict.ok || verdict.genTime === null || verdict.notAfter === undefined) {
                // imprint_mismatch here means the proof rebuilt a different root than the
                // token covers → the same link is broken; report the link reason for the
                // initial/renewal positions, else token_invalid.
                if (verdict.failure === 'imprint_mismatch') {
                    return fail(linkFailure, depth);
                }
                return fail('token_invalid', depth);
            }

            // 4. Freshness: this ATS's genTime must fall before the PRIOR ATS expired,
            // i.e. the renewal happened while the prior token was still valid (no lapse).
            const genTimeMs = new Date(verdict.genTime).getTime();
            if (prevNotAfterMs !== null && genTimeMs > prevNotAfterMs) {
                return fail('renewal_gap', depth);
            }

            oldestGenTime ??= verdict.genTime;
            latestGenTime = verdict.genTime;
            latestNotAfter = verdict.notAfter;
            prevNotAfterMs = new Date(verdict.notAfter).getTime();
            prevTokenDer = ats.timeStampDer;

            // 5. Revocation for EVERY ATS. The pass/fail decision is NOT
            // gated on the strippable RFC-4998 UNPROTECTED cryptoInfos bag:
            // absent/stripped/unusable ⇒ NOT_CAPTURED, and the injected policy —
            // never a silent default — decides whether that is tolerable. Stripping
            // can only move a status toward NOT_CAPTURED, so under `strict` it can
            // never turn a failing bundle into a passing one.
            let status: TokenRevocationStatus = 'NOT_CAPTURED';
            if (cryptoInfos) {
                const certs = parseTokenCerts(ats.timeStampDer);
                if (certs) {
                    status = verifyRevocation({
                        signerCertDer: new Uint8Array(certs.signerCert.raw),
                        chainDer: certs.chain.map((c) => new Uint8Array(c.raw)),
                        pinnedRootsDer: pinnedRoots,
                        genTime: certs.genTime,
                        cryptoInfos,
                    }).status;
                }
            }
            if (status === 'REVOKED') {
                return fail('token_revoked', depth);
            }
            if (status === 'NOT_CAPTURED' && revocationPolicy === 'strict') {
                return fail('revocation_not_captured', depth);
            }
            // Summary stays present-only-when-captured: a lenient record (no
            // cryptoInfos) reports no revocation label rather than a vacuous 0/0.
            if (cryptoInfos) {
                perTokenRevocation.push(status);
            }
        }
    }

    // 6. The last ATS must still be valid at verification time (RFC §5.4 final check).
    if (latestNotAfter === null || now.getTime() > new Date(latestNotAfter).getTime()) {
        return fail('tsa_cert_expired', depth);
    }

    const revocation = cryptoInfos
        ? {
            perToken: perTokenRevocation,
            checkedCount: perTokenRevocation.filter((s) => s === 'NOT_REVOKED').length,
            total: perTokenRevocation.length,
        }
        : undefined;

    return { ok: true, chainDepth: depth, oldestGenTime, latestGenTime, latestNotAfter, revocation };
}

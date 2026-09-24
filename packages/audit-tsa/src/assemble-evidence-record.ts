// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Assemble a per-window RFC 4998 EvidenceRecord from the window's anchor token
 * plus the window's renewal ArchiveTimeStamps, for the evidence bundle.
 *
 * The initial ArchiveTimeStamp is the anchor token: it timestamps the window's
 * merkle_root DIRECTLY (its messageImprint IS the root), so its reducedHashtree is
 * empty. Each renewal ATS carries its reducedHashtree path into that round's batch
 * root. Renewals are grouped into chains by `chainIndex` (timestamp renewals share
 * chain 0; a hash-tree renewal opens a new chain), ordered within a chain by the
 * order supplied (the caller sorts by the round's gen_time).
 */

import type { ErsHashAlg, ReducedHashtree } from './ers-merkle.js';
import type { EvidenceRecord, ErsArchiveTimeStamp, ErsChain } from './types.js';
import { isCryptoInfosEmpty, type CryptoInfos } from './revocation.js';

export interface AssembleRenewalAts {
    readonly chainIndex: number;
    readonly digestAlg: ErsHashAlg;
    readonly reducedHashtree: ReducedHashtree;
    readonly timeStampDer: Uint8Array;
}

export interface AssembleEvidenceRecordInput {
    /** The window's anchor token — the initial ArchiveTimeStamp (chain 0, ATS 0). */
    readonly anchorTokenDer: Uint8Array;
    /** Renewal ATS in sequence order (caller pre-sorts by chainIndex, then gen_time). */
    readonly renewals: ReadonlyArray<AssembleRenewalAts>;
    /** Captured CRL/OCSP for this window's tokens → cryptoInfos; absent ⇒ a record without revocation evidence. */
    readonly cryptoInfos?: CryptoInfos;
}

export function assembleEvidenceRecord(input: AssembleEvidenceRecordInput): EvidenceRecord {
    const initial: ErsArchiveTimeStamp = {
        digestAlg: 'SHA-256', // the anchor token is SHA-256; it imprints the root directly
        reducedHashtree: [],
        timeStampDer: input.anchorTokenDer,
    };

    // Group renewals by chainIndex, preserving supplied order within each chain.
    const byChain = new Map<number, ErsArchiveTimeStamp[]>();
    byChain.set(0, [initial]);
    for (const r of input.renewals) {
        const ats: ErsArchiveTimeStamp = {
            digestAlg: r.digestAlg,
            reducedHashtree: r.reducedHashtree,
            timeStampDer: r.timeStampDer,
        };
        const chain = byChain.get(r.chainIndex);
        if (chain) {
            chain.push(ats);
        } else {
            byChain.set(r.chainIndex, [ats]);
        }
    }

    const chainIndices = [...byChain.keys()].sort((a, b) => a - b);
    const sequence: ErsChain[] = chainIndices.map((idx) => byChain.get(idx) as ErsChain);
    const digestAlgorithms = [...new Set(sequence.flat().map((a) => a.digestAlg))];

    return isCryptoInfosEmpty(input.cryptoInfos)
        ? { version: 1, digestAlgorithms, sequence }
        : { version: 1, digestAlgorithms, cryptoInfos: input.cryptoInfos, sequence };
}

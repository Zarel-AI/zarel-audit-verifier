// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * RFC 4998 §5 renewal builders (one batch covers every window being renewed).
 *
 * Both build ONE reduced hash tree over all still-valid windows and obtain ONE
 * TSA token over its root; each window gets a `reducedHashtree` path into that
 * shared root (RFC central-management batching, §1). The caller stores the
 * round (root + token) once and one inclusion per window.
 *
 *   - Timestamp renewal (§5.2): TSA cert about to expire, hash alg still strong.
 *     Each window's leaf = H_alg(its current top token). New ATS appends to the
 *     window's SAME chain, SAME algorithm.
 *   - Hash-tree renewal (§5.3): the hash algorithm itself is weakening. Each
 *     window's leaf = H'(H'(dataObjectHash) ‖ H'(encode(prior sequence))). A NEW
 *     chain (single ATS) is appended, under the new stronger algorithm H'.
 */

import { buildErsTree, ersHash, type ErsHashAlg, type ReducedHashtree } from './ers-merkle.js';
import { encodeArchiveTimeStampSequence } from './evidence-record.js';
import type { ErsArchiveTimeStamp, ErsChain } from './types.js';

/** Obtains a DER RFC 3161 TimeStampToken over `root` (in production a `TsaClient`; in tests a mock). */
export type IssueToken = (root: Uint8Array) => Promise<Uint8Array>;

export interface RenewalPerWindow {
    readonly windowId: string;
    readonly reducedHashtree: ReducedHashtree;
    /** The ATS to append to this window's record (same shared token across windows). */
    readonly ats: ErsArchiveTimeStamp;
}

export interface RenewalResult {
    readonly root: Uint8Array;
    readonly tokenDer: Uint8Array;
    readonly digestAlg: ErsHashAlg;
    readonly perWindow: ReadonlyArray<RenewalPerWindow>;
}

function assemble(
    windowIds: ReadonlyArray<string>,
    leaves: ReadonlyArray<Uint8Array>,
    tokenDer: Uint8Array,
    alg: ErsHashAlg,
): RenewalResult {
    const { root, paths } = buildErsTree(leaves, alg);
    const perWindow = windowIds.map((windowId, i) => ({
        windowId,
        reducedHashtree: paths[i],
        ats: { digestAlg: alg, reducedHashtree: paths[i], timeStampDer: tokenDer } as ErsArchiveTimeStamp,
    }));
    return { root, tokenDer, digestAlg: alg, perWindow };
}

export interface TimestampRenewalWindow {
    readonly windowId: string;
    /** The window's current latest ATS token — the token this renewal re-timestamps. */
    readonly currentTopTokenDer: Uint8Array;
}

/** Timestamp renewal (§5.2): leaf = H_alg(current top token); same chain/algorithm. */
export async function buildTimestampRenewal(
    windows: ReadonlyArray<TimestampRenewalWindow>,
    issue: IssueToken,
    alg: ErsHashAlg,
): Promise<RenewalResult> {
    if (windows.length === 0) {
        throw new Error('buildTimestampRenewal: at least one window is required');
    }
    const leaves = windows.map((w) => ersHash(alg, w.currentTopTokenDer));
    const root = buildErsTree(leaves, alg).root;
    const tokenDer = await issue(root);
    return assemble(windows.map((w) => w.windowId), leaves, tokenDer, alg);
}

export interface HashTreeRenewalWindow {
    readonly windowId: string;
    /** The original data object hash (the window's merkle_root). */
    readonly dataObjectHash: Uint8Array;
    /** The window's prior ArchiveTimeStampSequence (all chains so far). */
    readonly priorChains: ReadonlyArray<ErsChain>;
}

/** Hash-tree renewal (§5.3): leaf = H'(H'(data) ‖ H'(encode(prior sequence))); new chain. */
export async function buildHashTreeRenewal(
    windows: ReadonlyArray<HashTreeRenewalWindow>,
    issue: IssueToken,
    newAlg: ErsHashAlg,
): Promise<RenewalResult> {
    if (windows.length === 0) {
        throw new Error('buildHashTreeRenewal: at least one window is required');
    }
    const leaves = windows.map((w) => {
        const hData = ersHash(newAlg, w.dataObjectHash);
        const ha = ersHash(newAlg, encodeArchiveTimeStampSequence(w.priorChains));
        return ersHash(newAlg, hData, ha);
    });
    const root = buildErsTree(leaves, newAlg).root;
    const tokenDer = await issue(root);
    return assemble(windows.map((w) => w.windowId), leaves, tokenDer, newAlg);
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * RFC 6962 §2.1 domain-separated Merkle tree — pure node:crypto.
 *
 * The single Merkle primitive for the whole audit surface. Two trees consume it:
 *   - the per-window ANCHOR tree: leaves are checkpoint hashes; the
 *     root is TSA-timestamped and each checkpoint's bundle ships only its inclusion
 *     path, so a bundle for one chain is verifiable without the other chains' content.
 *   - the transparency-LOG tree: leaves are the anchored window
 *     roots; `ct-consistency.ts` proves append-only extension over the same tree.
 *
 * Domain separation (RFC 6962 §2.1) is load-bearing for second-preimage
 * resistance: leaf = SHA-256(0x00 ‖ d), interior node = SHA-256(0x01 ‖ left ‖
 * right). The largest-power-of-two split (not odd-node duplication) additionally
 * blocks CVE-2012-2459 root equivocation (`[a,b,c]` and `[a,b,c,c]` differ).
 * Callers pass RAW leaf bytes; this module applies the leaf hash.
 */

import { createHash } from 'node:crypto';
import { bytesEqual } from './bytes.js';

/**
 * Envelope tag naming the Merkle scheme this module implements. Written into the
 * exported evidence bundle (which crosses a trust/time boundary) so an offline
 * verifier fails closed on any bundle built under a different tree construction,
 * rather than silently verifying a root against the wrong algorithm.
 */
export const MERKLE_SCHEME = 'rfc6962-sha256';

export type MerkleSide = 'L' | 'R';

export interface MerkleSibling {
    readonly hash: Uint8Array;
    readonly side: MerkleSide;
}

/** RFC 6962 audit path, ordered leaf → root (closest sibling first). */
export type InclusionPath = ReadonlyArray<MerkleSibling>;

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

/** RFC 6962 §2.1 leaf hash: SHA-256(0x00 ‖ leaf). */
export function leafHash(leaf: Uint8Array): Uint8Array {
    const h = createHash('sha256');
    h.update(LEAF_PREFIX);
    h.update(leaf);
    return new Uint8Array(h.digest());
}

/** RFC 6962 §2.1 interior node hash: SHA-256(0x01 ‖ left ‖ right). */
export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
    const h = createHash('sha256');
    h.update(NODE_PREFIX);
    h.update(left);
    h.update(right);
    return new Uint8Array(h.digest());
}

/** Largest power of two strictly less than n (n > 1). Shared with ct-consistency.ts. */
export function splitPoint(n: number): number {
    let k = 1;
    while (k * 2 < n) {
        k *= 2;
    }
    return k;
}

function emptyRoot(): Uint8Array {
    // RFC 6962: MTH({}) = SHA-256().
    return new Uint8Array(createHash('sha256').digest());
}

/**
 * Build the RFC 6962 tree over pre-ordered raw leaves (caller sorts canonically,
 * e.g. by (tenant_name, log_name)). Returns the root and one audit path per leaf,
 * index-aligned with `leaves`. Empty input → SHA-256("").
 * O(n log n): each subtree root is computed once and shared into its leaves' paths.
 */
export function buildMerkleTree(
    leaves: ReadonlyArray<Uint8Array>,
): { root: Uint8Array; paths: InclusionPath[] } {
    if (leaves.length === 0) {
        return { root: emptyRoot(), paths: [] };
    }
    return build(leaves);
}

function build(leaves: ReadonlyArray<Uint8Array>): { root: Uint8Array; paths: MerkleSibling[][] } {
    if (leaves.length === 1) {
        return { root: leafHash(leaves[0]), paths: [[]] };
    }
    const k = splitPoint(leaves.length);
    const left = build(leaves.slice(0, k));
    const right = build(leaves.slice(k));
    const root = nodeHash(left.root, right.root);
    // RFC 6962: PATH(m, D[n]) = PATH(m, left) : MTH(right)  for m < k  (sibling on the right)
    //                          PATH(m-k, right) : MTH(left)  for m >= k (sibling on the left)
    const paths: MerkleSibling[][] = [
        ...left.paths.map((p) => [...p, { hash: right.root, side: 'R' as const }]),
        ...right.paths.map((p) => [...p, { hash: left.root, side: 'L' as const }]),
    ];
    return { root, paths };
}

/**
 * Verify that raw `leaf` is included under `root` via its audit `path`. Rebuilds
 * the root from the leaf hash and the sibling hashes; trusts nothing but the recompute.
 */
export function verifyInclusion(leaf: Uint8Array, path: InclusionPath, root: Uint8Array): boolean {
    let acc = leafHash(leaf);
    for (const sibling of path) {
        acc = sibling.side === 'L' ? nodeHash(sibling.hash, acc) : nodeHash(acc, sibling.hash);
    }
    return bytesEqual(acc, root);
}

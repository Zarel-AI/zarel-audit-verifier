// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * RFC 6962 §2.1.2 Merkle CONSISTENCY proof — generation (SUBPROOF) + verification
 * (RFC 9162 §2.1.4.2). Pure node:crypto; reuses the domain-separated hashing and
 * largest-power-of-two split of `merkle.ts` (0x00 leaf / 0x01 node), so it is the
 * same tree the inclusion proofs are taken over.
 *
 * The property this proves is the append-only-completeness HALF of non-equivocation:
 * tree n is an append-only extension of tree m — no leaf removed,
 * mutated, or reordered. (The single-global-view half needs independent witnesses;
 * see witness-quorum.ts.)
 */

import { buildMerkleTree, splitPoint, nodeHash } from './merkle.js';
import { bytesEqual } from './bytes.js';

export interface ConsistencyProof {
    readonly nodes: ReadonlyArray<Uint8Array>;
}

/** RFC 6962 Merkle Tree Hash over a leaf range (delegates to the trusted builder). */
function mth(leaves: ReadonlyArray<Uint8Array>): Uint8Array {
    return buildMerkleTree(leaves).root;
}

/**
 * RFC 6962 §2.1.2 PROOF(m, D[n]) = SUBPROOF(m, D[n], true). `leaves` are the RAW
 * size-n leaves (ordered); the proof lets a verifier holding the size-m and size-n
 * roots confirm append-only extension. Empty at the m==0 / m==n boundaries.
 */
export function buildConsistencyProof(leaves: ReadonlyArray<Uint8Array>, m: number): ConsistencyProof {
    const n = leaves.length;
    if (!Number.isInteger(m) || m < 0 || m > n) {
        throw new Error('buildConsistencyProof: require 0 <= m <= n');
    }
    if (m === 0 || m === n) {
        return { nodes: [] };
    }
    return { nodes: subproof(m, leaves, true) };
}

function subproof(m: number, leaves: ReadonlyArray<Uint8Array>, b: boolean): Uint8Array[] {
    const n = leaves.length;
    if (m === n) {
        return b ? [] : [mth(leaves)];
    }
    const k = splitPoint(n);
    if (m <= k) {
        // SUBPROOF(m, D[0:k], b) : MTH(D[k:n])
        return [...subproof(m, leaves.slice(0, k), b), mth(leaves.slice(k))];
    }
    // SUBPROOF(m-k, D[k:n], false) : MTH(D[0:k])
    return [...subproof(m - k, leaves.slice(k), false), mth(leaves.slice(0, k))];
}

function isPowerOfTwo(x: number): boolean {
    return x > 0 && (x & (x - 1)) === 0;
}

/**
 * RFC 9162 §2.1.4.2 — reconstruct BOTH the size-m and size-n roots from the proof
 * and accept iff each equals its committed root. Fail-closed: any boundary/size
 * violation or any mutated byte yields false (never throws into an accept).
 *
 * Boundaries (the iterative body assumes 0 < m < n):
 *   m > n            → false
 *   m == n           → true iff proof empty AND rootM == rootN
 *   m == 0           → true iff proof empty (empty tree is consistent with any tree)
 */
export function verifyConsistency(
    m: number,
    rootM: Uint8Array,
    n: number,
    rootN: Uint8Array,
    proof: ConsistencyProof,
): boolean {
    if (!Number.isInteger(m) || !Number.isInteger(n) || m < 0 || n < 0 || m > n) {
        return false;
    }
    const path = proof.nodes;
    if (m === n) {
        return path.length === 0 && bytesEqual(rootM, rootN);
    }
    if (m === 0) {
        return path.length === 0;
    }

    // 0 < m < n. If m is an exact power of two, the size-m root is the seed and is
    // NOT carried in the path; otherwise the first node is the seed.
    let rest: ReadonlyArray<Uint8Array>;
    let seed: Uint8Array;
    if (isPowerOfTwo(m)) {
        seed = rootM;
        rest = path;
    } else {
        if (path.length === 0) {
            return false;
        }
        seed = path[0];
        rest = path.slice(1);
    }

    let fn = m - 1;
    let sn = n - 1;
    while ((fn & 1) === 1) {
        fn >>= 1;
        sn >>= 1;
    }

    let fr = seed;
    let sr = seed;
    for (const c of rest) {
        if (sn === 0) {
            return false;
        }
        if ((fn & 1) === 1 || fn === sn) {
            fr = nodeHash(c, fr);
            sr = nodeHash(c, sr);
            while (fn !== 0 && (fn & 1) === 0) {
                fn >>= 1;
                sn >>= 1;
            }
        } else {
            sr = nodeHash(sr, c);
        }
        fn >>= 1;
        sn >>= 1;
    }

    return sn === 0 && bytesEqual(fr, rootM) && bytesEqual(sr, rootN);
}

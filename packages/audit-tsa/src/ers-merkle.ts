// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * RFC 4998 §4 reduced hash tree (Evidence Record Syntax) — pure node:crypto.
 *
 * DISTINCT from `merkle.ts` (the per-window anchor inclusion tree, which pairs
 * left→right and records `side: 'L'|'R'`). RFC 4998 uses a different convention,
 * and the two must NOT be conflated — so this is a separate module:
 *
 *   - A `PartialHashtree` is the FULL list of hash values sharing one parent
 *     node, **binary-ascending sorted**. The parent value is
 *     `H(sortedConcat(members))` — there is NO left/right marker; order is
 *     recovered by sorting (RFC 4998 §4.2/§4.3).
 *   - A data object's `reducedHashtree` is the ordered list of `PartialHashtree`s
 *     from its leaf up to the root.
 *
 * The hash algorithm is a parameter: timestamp renewal reuses the chain's
 * algorithm; hash-tree renewal migrates to a stronger one (e.g. SHA-256 → 384).
 */

import { createHash } from 'node:crypto';
import { bytesEqual } from './bytes.js';

export type ErsHashAlg = 'SHA-256' | 'SHA-384';

const NODE_HASH_NAME: Record<ErsHashAlg, string> = {
    'SHA-256': 'sha256',
    'SHA-384': 'sha384',
};

/** One level's full member list (binary-ascending sorted), per RFC 4998. */
export type PartialHashtree = ReadonlyArray<Uint8Array>;
/** A single data object's inclusion proof: leaf-level list first, root-level last. */
export type ReducedHashtree = ReadonlyArray<PartialHashtree>;

/** Binary ascending (lexicographic, most-significant-byte-first) comparison. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) {
        if (a[i] !== b[i]) {
            return a[i] - b[i];
        }
    }
    return a.length - b.length;
}

function sortAscending(values: ReadonlyArray<Uint8Array>): Uint8Array[] {
    return [...values].sort(compareBytes);
}

/**
 * Hash an ordered concatenation of `parts` with `alg`. The single source of the
 * ErsHashAlg→node-digest mapping, shared by the renewal builders and the verifier
 * (the renewal-leaf derivations) so they cannot drift. NOTE: this does NOT sort —
 * it is distinct from the sorted-concat NODE rule (`hashLevel`) used inside the tree.
 */
export function ersHash(alg: ErsHashAlg, ...parts: ReadonlyArray<Uint8Array>): Uint8Array {
    const h = createHash(NODE_HASH_NAME[alg]);
    for (const p of parts) {
        h.update(p);
    }
    return new Uint8Array(h.digest());
}

/** Parent value of a partialHashtree = H(concatenation of its sorted members). */
function hashLevel(members: ReadonlyArray<Uint8Array>, alg: ErsHashAlg): Uint8Array {
    return ersHash(alg, ...sortAscending(members));
}

/**
 * Build an RFC 4998 reduced hash tree over pre-ordered `leaves` with `alg`.
 * Returns the root and one `ReducedHashtree` per leaf (index-aligned). A
 * single-leaf tree has the leaf as its root and an empty proof.
 */
export function buildErsTree(
    leaves: ReadonlyArray<Uint8Array>,
    alg: ErsHashAlg,
): { root: Uint8Array; paths: ReducedHashtree[] } {
    if (leaves.length === 0) {
        throw new Error('buildErsTree: at least one leaf is required');
    }

    const paths: PartialHashtree[][] = leaves.map(() => []);
    const positions: number[] = leaves.map((_, i) => i);
    let level: Uint8Array[] = leaves.slice();

    while (level.length > 1) {
        // Record each leaf's partialHashtree (the full member list of its parent)
        // at this level, then advance to the parent position.
        for (let l = 0; l < positions.length; l++) {
            const pos = positions[l];
            const isRight = pos % 2 === 1;
            const siblingPos = isRight ? pos - 1 : pos + 1;
            const members =
                siblingPos < level.length ? [level[pos], level[siblingPos]] : [level[pos]];
            paths[l].push(sortAscending(members));
            positions[l] = Math.floor(pos / 2);
        }

        const next: Uint8Array[] = [];
        for (let i = 0; i < level.length; i += 2) {
            const members = i + 1 < level.length ? [level[i], level[i + 1]] : [level[i]];
            next.push(hashLevel(members, alg));
        }
        level = next;
    }

    const root = level[0];
    if (root === undefined) {
        throw new Error('buildErsTree: unreachable — non-empty input collapses to one root');
    }
    return { root, paths };
}

/**
 * Recompute the root a `leaf` reaches through `path` (RFC 4998 §5.4), or null if
 * the proof is structurally invalid (the leaf, or a derived value, is not a member
 * of its level's list). Used by the ERS verifier, where the root is not known in
 * advance — it is the token's message imprint, which must equal this return.
 */
export function computeErsRoot(
    leaf: Uint8Array,
    path: ReducedHashtree,
    alg: ErsHashAlg,
): Uint8Array | null {
    if (path.length === 0) {
        return leaf;
    }
    let computed = leaf;
    for (const members of path) {
        if (!members.some((m) => bytesEqual(m, computed))) {
            return null;
        }
        computed = hashLevel(members, alg);
    }
    return computed;
}

/**
 * Verify `leaf` is included under `root` via `path` (RFC 4998 §5.4 reduced hash
 * tree check). Trusts nothing beyond recomputing to `root`.
 */
export function verifyErsInclusion(
    leaf: Uint8Array,
    path: ReducedHashtree,
    root: Uint8Array,
    alg: ErsHashAlg,
): boolean {
    const computed = computeErsRoot(leaf, path, alg);
    return computed !== null && bytesEqual(computed, root);
}

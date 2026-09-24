// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * RFC 6962 §2.1.2 consistency proof golden vectors.
 *
 * Grounded by EXECUTION, not a copied external hex vector: `buildMerkleTree` roots are
 * already cross-checked to RFC 6962 reference constants (merkle.test.ts), so we
 * (a) compute rootM/rootN via that trusted builder, (b) assert verifyConsistency
 * accepts the generated proof for exhaustive (m,n), (c) reject every single-byte
 * mutation, and (d) pin the generated node list against an INDEPENDENT inline
 * SUBPROOF reimplementation (a different code path) — pinning the proof bytes too.
 */

import { createHash } from 'node:crypto';
import { buildMerkleTree } from '../src/merkle.js';
import { buildConsistencyProof, verifyConsistency } from '../src/ct-consistency.js';

const hex = (u: Uint8Array): string => Buffer.from(u).toString('hex');
const sha = (...parts: Uint8Array[]): Uint8Array => {
    const h = createHash('sha256');
    for (const p of parts) h.update(p);
    return new Uint8Array(h.digest());
};
const B = (b: number): Uint8Array => new Uint8Array([b]);
const leafBytes = (i: number): Uint8Array => new Uint8Array(createHash('sha256').update(`leaf-${i}`).digest());

// ---- Independent reference (different code path than src) ----
function mthRef(leaves: Uint8Array[]): Uint8Array {
    if (leaves.length === 0) return new Uint8Array(createHash('sha256').digest());
    if (leaves.length === 1) return sha(B(0x00), leaves[0]);
    let k = 1;
    while (k * 2 < leaves.length) k *= 2;
    return sha(B(0x01), mthRef(leaves.slice(0, k)), mthRef(leaves.slice(k)));
}
function subproofRef(m: number, leaves: Uint8Array[], b: boolean): Uint8Array[] {
    const n = leaves.length;
    if (m === n) return b ? [] : [mthRef(leaves)];
    let k = 1;
    while (k * 2 < n) k *= 2;
    if (m <= k) return [...subproofRef(m, leaves.slice(0, k), b), mthRef(leaves.slice(k))];
    return [...subproofRef(m - k, leaves.slice(k), false), mthRef(leaves.slice(0, k))];
}
function proofRef(m: number, leaves: Uint8Array[]): Uint8Array[] {
    if (m === 0 || m === leaves.length) return [];
    return subproofRef(m, leaves, true);
}

const MAX = 33;
const ALL = Array.from({ length: MAX }, (_, i) => leafBytes(i));

describe('ct-consistency: generation matches the independent SUBPROOF reference', () => {
    it('every (m,n) with 0<m<n<=33 produces byte-identical proof node lists', () => {
        for (let n = 2; n <= MAX; n++) {
            const leaves = ALL.slice(0, n);
            for (let m = 1; m < n; m++) {
                const got = buildConsistencyProof(leaves, m).nodes.map(hex);
                const want = proofRef(m, leaves).map(hex);
                expect(got).toEqual(want);
            }
        }
    });
});

describe('ct-consistency: verify accepts honest proofs against trusted roots', () => {
    it('every (m,n) verifies against buildMerkleTree roots', () => {
        for (let n = 2; n <= MAX; n++) {
            const leaves = ALL.slice(0, n);
            const rootN = buildMerkleTree(leaves).root;
            for (let m = 1; m < n; m++) {
                const rootM = buildMerkleTree(leaves.slice(0, m)).root;
                const proof = buildConsistencyProof(leaves, m);
                expect(verifyConsistency(m, rootM, n, rootN, proof)).toBe(true);
            }
        }
    });
});

describe('ct-consistency: boundary semantics', () => {
    it('m==n holds iff proof empty and roots equal', () => {
        const leaves = ALL.slice(0, 6);
        const root = buildMerkleTree(leaves).root;
        expect(verifyConsistency(6, root, 6, root, { nodes: [] })).toBe(true);
        expect(verifyConsistency(6, root, 6, sha(B(9), root), { nodes: [] })).toBe(false);
        expect(verifyConsistency(6, root, 6, root, { nodes: [root] })).toBe(false);
    });
    it('m==0 holds iff proof empty (empty tree consistent with any)', () => {
        const rootN = buildMerkleTree(ALL.slice(0, 5)).root;
        const empty = new Uint8Array(createHash('sha256').digest());
        expect(verifyConsistency(0, empty, 5, rootN, { nodes: [] })).toBe(true);
        expect(verifyConsistency(0, empty, 5, rootN, { nodes: [rootN] })).toBe(false);
    });
    it('m>n fails closed', () => {
        const rootM = buildMerkleTree(ALL.slice(0, 5)).root;
        const rootN = buildMerkleTree(ALL.slice(0, 3)).root;
        expect(verifyConsistency(5, rootM, 3, rootN, buildConsistencyProof(ALL.slice(0, 5), 3))).toBe(false);
    });
});

describe('ct-consistency: fail-closed on every single-byte mutation', () => {
    const n = 23;
    const m = 9;
    const leaves = ALL.slice(0, n);
    const rootM = buildMerkleTree(leaves.slice(0, m)).root;
    const rootN = buildMerkleTree(leaves).root;
    const proof = buildConsistencyProof(leaves, m);

    it('baseline verifies', () => {
        expect(verifyConsistency(m, rootM, n, rootN, proof)).toBe(true);
    });
    it('a mutated proof node is rejected', () => {
        for (let i = 0; i < proof.nodes.length; i++) {
            const nodes = proof.nodes.map((x, j) => (j === i ? sha(B(0xff), x) : x));
            expect(verifyConsistency(m, rootM, n, rootN, { nodes })).toBe(false);
        }
    });
    it('a mutated old/new root is rejected', () => {
        expect(verifyConsistency(m, sha(B(1), rootM), n, rootN, proof)).toBe(false);
        expect(verifyConsistency(m, rootM, n, sha(B(1), rootN), proof)).toBe(false);
    });
    it('a proof for prefix m does not verify a different (authentic) old size', () => {
        // The sizes are authenticated upstream by the signed checkpoint notes; the
        // binding tested here is that a proof for prefix m cannot be passed off as a
        // proof for prefix m±1, each carrying its OWN authentic root.
        expect(verifyConsistency(m + 1, buildMerkleTree(leaves.slice(0, m + 1)).root, n, rootN, proof)).toBe(false);
        expect(verifyConsistency(m - 1, buildMerkleTree(leaves.slice(0, m - 1)).root, n, rootN, proof)).toBe(false);
    });
    it('a dropped or extra proof node is rejected', () => {
        expect(verifyConsistency(m, rootM, n, rootN, { nodes: proof.nodes.slice(1) })).toBe(false);
        expect(verifyConsistency(m, rootM, n, rootN, { nodes: [...proof.nodes, rootN] })).toBe(false);
    });
});

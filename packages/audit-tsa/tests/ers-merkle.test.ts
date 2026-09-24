// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * RFC 4998 reduced hash tree. A valid inclusion
 * proof rebuilds the root; any tamper fails; the build/verify pair is consistent
 * across tree sizes and across SHA-256 / SHA-384 (the hash-tree-renewal alg).
 */

import { createHash } from 'node:crypto';
import { buildErsTree, verifyErsInclusion, type ErsHashAlg } from '../src/ers-merkle.js';

function leaf(tag: string, alg: ErsHashAlg = 'SHA-256'): Uint8Array {
    return new Uint8Array(createHash(alg === 'SHA-256' ? 'sha256' : 'sha384').update(tag).digest());
}

describe.each<ErsHashAlg>(['SHA-256', 'SHA-384'])('buildErsTree / verifyErsInclusion (%s)', (alg) => {
    it('single leaf: root equals the leaf, empty proof verifies', () => {
        const l0 = leaf('a', alg);
        const { root, paths } = buildErsTree([l0], alg);
        expect(Buffer.from(root).equals(Buffer.from(l0))).toBe(true);
        expect(paths[0]).toHaveLength(0);
        expect(verifyErsInclusion(l0, paths[0], root, alg)).toBe(true);
    });

    it('throws on no leaves', () => {
        expect(() => buildErsTree([], alg)).toThrow(/at least one leaf/);
    });

    it.each([2, 3, 4, 5, 8, 13])('every leaf of an %i-leaf tree has a verifying proof', (n) => {
        const leaves = Array.from({ length: n }, (_, i) => leaf(`leaf-${i}`, alg));
        const { root, paths } = buildErsTree(leaves, alg);
        for (let i = 0; i < n; i++) {
            expect(verifyErsInclusion(leaves[i], paths[i], root, alg)).toBe(true);
        }
    });

    it('a leaf in a different subtree does not verify under another leaf proof', () => {
        // NOTE: RFC 4998 siblings share their first partialHashtree, so co-located
        // leaves legitimately cross-verify (both ARE in the tree). Use leaves in
        // disjoint subtrees (0 and 4 of an 8-leaf tree) — leaf 4 is absent from
        // leaf 0's proof, so it must fail.
        const leaves = Array.from({ length: 8 }, (_, i) => leaf(`leaf-${i}`, alg));
        const { root, paths } = buildErsTree(leaves, alg);
        expect(verifyErsInclusion(leaves[4], paths[0], root, alg)).toBe(false);
    });

    it('tampering a proof member fails verification', () => {
        const leaves = [leaf('a', alg), leaf('b', alg), leaf('c', alg), leaf('d', alg)];
        const { root, paths } = buildErsTree(leaves, alg);
        const tampered = paths[0].map((lvl, idx) =>
            idx === 0 ? [...lvl.slice(0, lvl.length - 1), leaf('evil', alg)] : lvl,
        );
        expect(verifyErsInclusion(leaves[0], tampered, root, alg)).toBe(false);
    });

    it('tampering the root fails verification', () => {
        const leaves = [leaf('a', alg), leaf('b', alg), leaf('c', alg)];
        const { paths } = buildErsTree(leaves, alg);
        const evilRoot = leaf('evil-root', alg);
        expect(verifyErsInclusion(leaves[0], paths[0], evilRoot, alg)).toBe(false);
    });

    it('leaf order does not change the root (sorted-concat is order-independent within a level)', () => {
        // RFC 4998 sorts each level's members, so swapping two adjacent leaves that
        // share a parent yields the same parent hash — but different leaves overall
        // change the tree. Here we assert a STABLE root for a fixed leaf set.
        const leaves = [leaf('x', alg), leaf('y', alg)];
        const a = buildErsTree(leaves, alg).root;
        const b = buildErsTree([leaves[1], leaves[0]], alg).root;
        expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true); // 2-leaf parent is sort-stable
    });
});

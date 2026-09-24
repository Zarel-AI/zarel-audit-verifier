// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * RFC 6962 Merkle tree — golden vectors, inclusion paths, and the two
 * security properties the domain separation exists for:
 *   - second-preimage resistance: an interior node presented as a leaf fails.
 *   - CVE-2012-2459 resistance: [a,b,c] and [a,b,c,c] have DIFFERENT roots.
 *
 * Golden roots are cross-checked against an INDEPENDENT inline implementation
 * (different code path) plus the pinned RFC 6962 empty-tree constant.
 */

import { createHash } from 'node:crypto';
import { buildMerkleTree, verifyInclusion, leafHash, nodeHash } from '../src/merkle.js';

function sha256(...parts: Uint8Array[]): Uint8Array {
    const h = createHash('sha256');
    for (const p of parts) {
        h.update(p);
    }
    return new Uint8Array(h.digest());
}

const B = (b: number): Uint8Array => new Uint8Array([b]);
const leaf = (x: Uint8Array): Uint8Array => sha256(B(0x00), x);
const node = (l: Uint8Array, r: Uint8Array): Uint8Array => sha256(B(0x01), l, r);
const d = (tag: string): Uint8Array => new Uint8Array(createHash('sha256').update(tag).digest());
const hex = (u: Uint8Array): string => Buffer.from(u).toString('hex');

describe('merkle: domain-separated hashing (RFC 6962 §2.1)', () => {
    it('leafHash = SHA-256(0x00 || d)', () => {
        const x = d('leaf');
        expect(hex(leafHash(x))).toBe(hex(sha256(B(0x00), x)));
    });

    it('nodeHash = SHA-256(0x01 || L || R)', () => {
        const l = d('l');
        const r = d('r');
        expect(hex(nodeHash(l, r))).toBe(hex(sha256(B(0x01), l, r)));
    });

    it('leaf and node hashing are domain-separated (0x00 vs 0x01)', () => {
        const x = d('same');
        expect(hex(leafHash(x))).not.toBe(hex(nodeHash(x, x)));
    });
});

describe('merkle: golden-vector roots', () => {
    it('empty tree root = SHA-256("") (RFC 6962 MTH({}))', () => {
        const { root, paths } = buildMerkleTree([]);
        expect(hex(root)).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
        expect(paths).toHaveLength(0);
    });

    it('single leaf: root = leafHash(d0) (NOT the raw leaf), empty path', () => {
        const d0 = d('a');
        const { root, paths } = buildMerkleTree([d0]);
        expect(hex(root)).toBe(hex(leaf(d0)));
        // The raw leaf must not equal the root — a raw-leaf root would itself be a
        // second-preimage (indistinguishable from a leaf-of-a-leaf).
        expect(hex(root)).not.toBe(hex(d0));
        expect(paths[0]).toHaveLength(0);
        expect(verifyInclusion(d0, paths[0], root)).toBe(true);
    });

    it('two leaves: root = node(leaf0, leaf1)', () => {
        const d0 = d('a');
        const d1 = d('b');
        expect(hex(buildMerkleTree([d0, d1]).root)).toBe(hex(node(leaf(d0), leaf(d1))));
    });

    it('three leaves: k=2 split → node(node(l0,l1), l2)', () => {
        const ds = [0, 1, 2].map((i) => d(`x${i}`));
        const ls = ds.map(leaf);
        expect(hex(buildMerkleTree(ds).root)).toBe(hex(node(node(ls[0], ls[1]), ls[2])));
    });

    it('five leaves: largest-power-of-two split (k=4)', () => {
        const ds = [0, 1, 2, 3, 4].map((i) => d(`leaf-${i}`));
        const ls = ds.map(leaf);
        const left = node(node(ls[0], ls[1]), node(ls[2], ls[3]));
        expect(hex(buildMerkleTree(ds).root)).toBe(hex(node(left, ls[4])));
    });

    it('is deterministic for the same ordered leaves', () => {
        const ds = [d('p'), d('q'), d('r')];
        expect(hex(buildMerkleTree(ds).root)).toBe(hex(buildMerkleTree(ds).root));
    });
});

describe('merkle: inclusion paths', () => {
    it.each([1, 2, 3, 4, 5, 7, 8, 9, 16, 17])('every leaf in an %i-leaf tree verifies', (n) => {
        const ds = Array.from({ length: n }, (_, i) => d(`m-${i}`));
        const { root, paths } = buildMerkleTree(ds);
        for (let i = 0; i < n; i++) {
            expect(verifyInclusion(ds[i], paths[i], root)).toBe(true);
        }
    });

    it('fails when the root is tampered', () => {
        const ds = [0, 1, 2, 3].map((i) => d(`r${i}`));
        const { root, paths } = buildMerkleTree(ds);
        const bad = Buffer.from(root);
        bad[0] ^= 0xff;
        expect(verifyInclusion(ds[1], paths[1], new Uint8Array(bad))).toBe(false);
    });

    it('fails when a sibling hash is tampered', () => {
        const ds = [0, 1, 2, 3].map((i) => d(`t${i}`));
        const { root, paths } = buildMerkleTree(ds);
        const tampered = paths[2].map((s, i) => (i === 0 ? { ...s, hash: d('evil') } : s));
        expect(verifyInclusion(ds[2], tampered, root)).toBe(false);
    });

    it('fails when a sibling side is flipped', () => {
        const ds = [0, 1, 2, 3].map((i) => d(`s${i}`));
        const { root, paths } = buildMerkleTree(ds);
        const flipped = paths[0].map((s) => ({ hash: s.hash, side: s.side === 'L' ? 'R' as const : 'L' as const }));
        expect(verifyInclusion(ds[0], flipped, root)).toBe(false);
    });
});

describe('merkle: security invariants (the reason for domain separation)', () => {
    it('second-preimage: an interior node presented as a leaf does NOT verify', () => {
        // 4-leaf balanced tree: root = node( node(l0,l1), node(l2,l3) ).
        const ds = [0, 1, 2, 3].map((i) => d(`sp${i}`));
        const { root } = buildMerkleTree(ds);
        const leftSub = node(leaf(ds[0]), leaf(ds[1]));   // an INTERIOR node value
        const rightSub = node(leaf(ds[2]), leaf(ds[3]));
        // Forge: claim `leftSub` is a raw leaf with `rightSub` as its only sibling.
        // verifyInclusion applies leafHash → nodeHash(leafHash(leftSub), rightSub),
        // which ≠ root because leafHash(leftSub) (0x00-prefixed) ≠ leftSub (a node).
        expect(verifyInclusion(leftSub, [{ hash: rightSub, side: 'R' }], root)).toBe(false);
    });

    it('CVE-2012-2459: [a,b,c] and [a,b,c,c] have DIFFERENT roots', () => {
        const a = d('a');
        const b = d('b');
        const c = d('c');
        const three = buildMerkleTree([a, b, c]).root;
        const fourDup = buildMerkleTree([a, b, c, c]).root;
        expect(hex(three)).not.toBe(hex(fourDup));
    });
});

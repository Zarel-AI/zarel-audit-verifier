// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Golden vectors. A fixed event content → a fixed hex hash,
 * pinned so any future verifier (or a reimplementation in another language)
 * agrees byte-for-byte. If these change, the chain format changed and every
 * previously-signed checkpoint is invalidated — that must be a conscious break.
 */

import { chainHash, GENESIS, canonicalEventEncode, type ChainedEventContent } from '../src/index.js';

const CONTENT: ChainedEventContent = {
    tenant_name: 'demo_tenant',
    instance_id: '11111111-1111-1111-1111-111111111111',
    field_name: 'status',
    from_state: 'draft',
    to_state: 'submitted',
    actor: 'alice',
    actor_role: 'owner',
    payload: { amount: 100, note: 'hello' },
    policy_version: 'v1',
    rule_evaluations: null,
};

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

describe('audit-chain golden vectors', () => {
    it('GENESIS is the documented domain-separated constant', () => {
        expect(hex(GENESIS)).toBe('e7cd8018d4e541a329017dd8ee37d8479642e598408e7ef490b6ef88aa120320');
    });

    it('genesis event (seq=1, prev=GENESIS) hashes to the pinned value', () => {
        const h = chainHash({ content: CONTENT, prevHash: GENESIS, seq: 1 });
        expect(hex(h)).toBe('dd3773fbfd9cc05aab1c9e48c242442702a9533acd7fa03789605afaf8a443a7');
    });

    it('second event links to the genesis head and hashes to the pinned value', () => {
        const h1 = chainHash({ content: CONTENT, prevHash: GENESIS, seq: 1 });
        const h2 = chainHash({
            content: { ...CONTENT, from_state: 'submitted', to_state: 'approved' },
            prevHash: h1,
            seq: 2,
        });
        expect(hex(h2)).toBe('591a3ecd07876e33b1119269a438d9c3b8fb992a0b2a0fb5704d08001bb1d761');
    });

    it('canonical encoding is independent of key insertion order (incl. nested JSON)', () => {
        const reordered: ChainedEventContent = {
            actor: CONTENT.actor,
            tenant_name: CONTENT.tenant_name,
            instance_id: CONTENT.instance_id,
            field_name: CONTENT.field_name,
            from_state: CONTENT.from_state,
            to_state: CONTENT.to_state,
            actor_role: CONTENT.actor_role,
            payload: { note: 'hello', amount: 100 },
            policy_version: CONTENT.policy_version,
            rule_evaluations: null,
        };
        expect(hex(canonicalEventEncode(reordered))).toBe(hex(canonicalEventEncode(CONTENT)));
    });

    it('omitting an undefined field equals not setting it (stable per-log shape)', () => {
        const withUndef = { ...CONTENT, event_type: undefined } as ChainedEventContent;
        expect(hex(canonicalEventEncode(withUndef))).toBe(hex(canonicalEventEncode(CONTENT)));
    });

    // Number-domain golden vectors. These pin the RFC 8785 §3.2.2.3
    // number canonicalization so a database JSON round-trip (which may re-serialize a
    // number's TEXT) cannot move the hash. Each pair encodes to identical bytes
    // because the underlying double value is identical.
    const numContent = (payload: unknown): ChainedEventContent => ({
        ...CONTENT,
        payload,
    });

    it('decimals: 100.5 hashes to its pinned value and trailing-zero text is identical', () => {
        const h = chainHash({ content: numContent({ amount: 100.5 }), prevHash: GENESIS, seq: 1 });
        expect(hex(h)).toBe(
            hex(chainHash({ content: numContent({ amount: 100.50 }), prevHash: GENESIS, seq: 1 })),
        );
        expect(hex(h)).toBe('037fde32ec07a091381911545563c6f5a8b7ea140171dc5427e5e8aae4753fff');
    });

    it('integer ≡ decimal ≡ exponent: 100, 100.0, 1e2 share one canonical hash', () => {
        const a = hex(chainHash({ content: numContent({ v: 100 }), prevHash: GENESIS, seq: 1 }));
        const b = hex(chainHash({ content: numContent({ v: 100.0 }), prevHash: GENESIS, seq: 1 }));
        const c = hex(chainHash({ content: numContent({ v: 1e2 }), prevHash: GENESIS, seq: 1 }));
        expect(a).toBe(b);
        expect(b).toBe(c);
    });

    it('negative zero canonicalizes identically to zero', () => {
        const negZero = hex(canonicalEventEncode(numContent({ v: -0 })));
        const zero = hex(canonicalEventEncode(numContent({ v: 0 })));
        expect(negZero).toBe(zero);
    });

    it('integer-like JSON keys hash in numeric key order (shipped-format byte-compat)', () => {
        // A payload keyed by numeric ids. ECMAScript orders integer-index keys
        // numeric-ascending, so the canonical bytes are "1","2","10" — the order
        // the original chain format used. Pinned so a future encoder change
        // that flips to lexical ("1","10","2") fails here instead of silently
        // invalidating every checkpoint over such a payload.
        const enc = Buffer.from(canonicalEventEncode(numContent({ '10': 'a', '2': 'b', '1': 'c' }))).toString('utf8');
        expect(enc).toContain('"payload":{"1":"c","2":"b","10":"a"}');
        const h = chainHash({ content: numContent({ '10': 'a', '2': 'b', '1': 'c' }), prevHash: GENESIS, seq: 1 });
        expect(hex(h)).toBe('ad184e55fa574549f18c70879125f8d4c8391da67ff559fa48708f6adc426e94');
    });

    it('large/small magnitudes & exponents are stable (pinned encoding)', () => {
        const enc = (payload: unknown): string =>
            Buffer.from(canonicalEventEncode(numContent(payload))).toString('utf8');
        expect(enc({ big: 1e21, small: 1e-7, micro: 0.000001, huge: 1.5e300 })).toContain('"big":1e+21');
        expect(enc({ big: 1e21, small: 1e-7, micro: 0.000001, huge: 1.5e300 })).toContain('"small":1e-7');
        expect(enc({ big: 1e21, small: 1e-7, micro: 0.000001, huge: 1.5e300 })).toContain('"micro":0.000001');
        expect(enc({ big: 1e21, small: 1e-7, micro: 0.000001, huge: 1.5e300 })).toContain('"huge":1.5e+300');
    });
});

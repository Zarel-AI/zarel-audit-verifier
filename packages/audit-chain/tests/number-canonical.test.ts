// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * RFC 8785 §3.2.2.3 number serialization is the
 * single canonical number authority. These gates pin the value-not-text rule
 * (so a database JSON round-trip cannot produce a false event_hash_mismatch), the -0
 * normalization, and the non-finite rejection.
 */

import { canonicalJson, serializeNumber } from '../src/index.js';

describe('serializeNumber (RFC 8785 §3.2.2.3)', () => {
    it('same double value → same bytes regardless of source text (100 ≡ 100.0 ≡ 1e2)', () => {
        expect(serializeNumber(100)).toBe('100');
        expect(serializeNumber(100.0)).toBe('100');
        expect(serializeNumber(1e2)).toBe('100');
        // and through the full encoder, inside a payload
        const a = canonicalJson({ amount: 100 });
        const b = canonicalJson({ amount: 100.0 });
        const c = canonicalJson({ amount: 1e2 });
        expect(a).toBe(b);
        expect(b).toBe(c);
    });

    it('negative zero normalizes to "0"', () => {
        expect(serializeNumber(-0)).toBe('0');
        expect(canonicalJson({ x: -0 })).toBe('{"x":0}');
    });

    it('rejects non-finite numbers (no silent null coercion)', () => {
        expect(() => serializeNumber(NaN)).toThrow();
        expect(() => serializeNumber(Infinity)).toThrow();
        expect(() => serializeNumber(-Infinity)).toThrow();
        expect(() => canonicalJson({ x: NaN })).toThrow();
        expect(() => canonicalJson([1, Infinity])).toThrow();
    });

    it('decimals / trailing-zeros / exponents / magnitudes are stable and value-based', () => {
        expect(serializeNumber(100.5)).toBe('100.5');
        expect(serializeNumber(100.50)).toBe('100.5'); // trailing zero is the same double
        expect(serializeNumber(0.1)).toBe('0.1');
        expect(serializeNumber(1e21)).toBe('1e+21');
        expect(serializeNumber(1e-7)).toBe('1e-7');
        expect(serializeNumber(0.000001)).toBe('0.000001'); // 1e-6 boundary stays decimal
        expect(serializeNumber(1.5e300)).toBe('1.5e+300');
        expect(serializeNumber(-123.456)).toBe('-123.456');
    });

    it('the canonical number form equals ECMAScript Number::toString for finite values', () => {
        const sample = [0, 1, -1, 100, 100.5, 0.1, 1e21, 1e-7, 0.000001, 1.5e300, 9007199254740992, -42.5];
        for (const n of sample) {
            expect(serializeNumber(n)).toBe(String(n));
        }
    });
});

describe('canonicalJson byte-compatibility with the prior encoder (valid inputs unchanged)', () => {
    // The prior encoder was JSON.stringify(sortDeep(value)). For every finite,
    // JSON-safe input the new encoder MUST produce identical bytes, so existing
    // golden vectors / signed checkpoints stay valid.
    const sortDeep = (value: unknown): unknown => {
        if (Array.isArray(value)) return value.map(sortDeep);
        if (value !== null && typeof value === 'object') {
            const obj = value as Record<string, unknown>;
            const out: Record<string, unknown> = {};
            for (const k of Object.keys(obj).sort()) out[k] = sortDeep(obj[k]);
            return out;
        }
        return value;
    };
    const oldEncode = (v: unknown): string => JSON.stringify(sortDeep(v));

    const cases: unknown[] = [
        100,
        'hello',
        true,
        null,
        { b: 1, a: 2 },
        { z: { y: 'x', a: [1, 2, 3] }, m: 100.5 },
        [3, 2, 1, { k: 'v\nnewline\t"quote"' }],
        { amount: 100, note: 'hi', nested: { d: 0.000001, e: 1e21 } },
        { unicode: 'café — ünïcödé', emoji: '🔐' },
        { empty: {}, arr: [], zero: 0, negzero: -0 },
        [null, undefined, 'after-undef'], // array undefined → null in both
        { keep: 1, drop: undefined }, // object undefined member dropped in both
        // INTEGER-LIKE KEYS — the case the original byte-compat suite missed.
        // ECMAScript orders integer-index keys numeric-ascending FIRST, so a
        // JSON map keyed by numeric ids must serialize as "1","2","10" (NOT the
        // lexical "1","10","2"). A regression here silently invalidates every
        // already-signed checkpoint over such payloads.
        { '10': 1, '2': 2, '1': 3 },
        { '3': 'c', '1': 'a', '2': 'b' },
        { nested: { '20': 1, '3': 2 } },
        { '0': 'x', amount: 1, '100': 'y' }, // integer keys precede string keys
    ];

    it.each(cases.map((c, i) => [i, c] as const))('case %i matches prior bytes', (_i, c) => {
        expect(canonicalJson(c)).toBe(oldEncode(c));
    });

    it('integer-like keys serialize in numeric (not lexical) order — shipped-format byte-compat', () => {
        expect(canonicalJson({ '10': 1, '2': 2, '1': 3 })).toBe('{"1":3,"2":2,"10":1}');
        expect(canonicalJson({ nested: { '20': 1, '3': 2 } })).toBe('{"nested":{"3":2,"20":1}}');
        expect(canonicalJson({ '0': 'x', amount: 1, '100': 'y' })).toBe('{"0":"x","100":"y","amount":1}');
    });
});

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Canonical JSON serialization for the audit hash chain.
 *
 * Single-sourced in `@zarel-ai/audit-chain` so there is exactly ONE
 * canonical encoder: the signer that produces checkpoints, the code that
 * computes each event hash when it is written, and this offline verifier all reproduce
 * byte-identical bytes from it. Divergence between signer and
 * verifier would void every tamper-evidence guarantee, so this MUST stay
 * single-sourced.
 *
 * Encoding rules:
 * - The value tree is first normalized by `sortDeep`, which rebuilds every
 *   object with its keys reinserted in sorted order. Property iteration order is
 *   therefore the ECMAScript own-property order of that rebuilt object:
 *   **integer-index-like keys first in ascending numeric order, then the
 *   remaining keys in lexicographic order.** This is the EXACT ordering the
 *   original chain format used (it serialized `JSON.stringify(sortDeep(v))`),
 *   so existing event hashes and signed checkpoints stay valid.
 * - Numbers are serialized via `serializeNumber` (RFC 8785 §3.2.2.3), the SINGLE
 *   number authority in the canonical path — never via bare `JSON.stringify`.
 * - Strings/keys are emitted via `JSON.stringify` of the single primitive
 *   (identical RFC 8259 escaping); booleans/null as their JSON literals.
 *
 * The result is byte-identical to the previous `JSON.stringify(sortDeep(value))`
 * encoder for every finite, JSON-safe value — the only behavioral change is that
 * a non-finite number is now REJECTED rather than silently coerced to `null`.
 *
 * Number normalization covers the IEEE-754-double-representable subset (which is
 * the entirety of JSON's number domain in JavaScript): identical double value ⇒
 * identical bytes regardless of source textual form (`100` ≡ `100.0` ≡ `1e2`),
 * so a value that was stored and re-serialized (for example by a database JSON
 * column) cannot produce a false `event_hash_mismatch`. Values
 * that exceed double precision remain out of scope.
 *
 * NOTE — key ordering is NOT yet full RFC 8785 §3.2.3 (which sorts ALL keys,
 * including integer-like ones, by UTF-16 code unit). Adopting strict lexical
 * ordering for integer-like keys would change the bytes for such payloads and
 * invalidate every already-signed checkpoint, so it is deliberately deferred to
 * a re-baseline decision (and is only needed for a non-JS external verifier; the
 * shipped `zarel verify` is itself JS and reproduces this ordering exactly).
 */

/**
 * RFC 8785 §3.2.2.3 number serialization — the single canonical number
 * authority. ECMAScript `Number::toString` is the algorithm RFC 8785 cites, and
 * `String(n)` emits exactly that for every finite double (shortest round-trip
 * form; integers without a decimal point/exponent within ±2^53; the `e+`/`e-`
 * exponent boundaries match), so `String(n)` IS the canonical form. We add the
 * two rules RFC 8785 mandates beyond the bare `toString`:
 * - non-finite (`NaN`, `±Infinity`) is rejected (never silently coerced to
 *   `null` the way `JSON.stringify` would);
 * - negative zero normalizes to `0`.
 */
export function serializeNumber(n: number): string {
    if (!Number.isFinite(n)) {
        throw new Error(`canonicalJson: non-finite number cannot be canonically encoded: ${String(n)}`);
    }
    if (Object.is(n, -0)) {
        return '0';
    }
    return String(n);
}

export function canonicalJson(value: unknown): string {
    // Normalize key order via sortDeep (reproducing the shipped ECMAScript
    // own-property ordering exactly), then serialize routing numbers through
    // serializeNumber. Byte-identical to JSON.stringify(sortDeep(value)) for
    // valid content; rejects non-finite numbers.
    return encodeNode(sortDeep(value));
}

function encodeNode(value: unknown): string {
    if (value === null) {
        return 'null';
    }
    const t = typeof value;
    if (t === 'number') {
        return serializeNumber(value as number);
    }
    if (t === 'string') {
        // JSON.stringify of a single string primitive = exact RFC 8259 escaping.
        return JSON.stringify(value);
    }
    if (t === 'boolean') {
        return value ? 'true' : 'false';
    }
    if (Array.isArray(value)) {
        return '[' + value.map(encodeArrayElement).join(',') + ']';
    }
    if (t === 'object') {
        const obj = value as Record<string, unknown>;
        const parts: string[] = [];
        // `obj` came from sortDeep, so own-property order is already canonical
        // (integer keys numeric-ascending, then lexical). Do NOT re-sort here —
        // re-sorting would force lexical order on integer keys and diverge from
        // the shipped format.
        for (const key of Object.keys(obj)) {
            const v = obj[key];
            // Match JSON.stringify: object members whose value is undefined, a
            // function, or a symbol are omitted entirely.
            if (v === undefined || typeof v === 'function' || typeof v === 'symbol') {
                continue;
            }
            parts.push(JSON.stringify(key) + ':' + encodeNode(v));
        }
        return '{' + parts.join(',') + '}';
    }
    // bigint / undefined / function / symbol at the top level: JSON has no
    // representation. JSON.stringify would return `undefined` (or throw for
    // bigint); a canonical encoder must not silently produce a non-string.
    throw new Error(`canonicalJson: unsupported value of type ${t}`);
}

function encodeArrayElement(el: unknown): string {
    // Match JSON.stringify: undefined / function / symbol array elements
    // serialize as `null` (they cannot be dropped without shifting indices).
    if (el === undefined || typeof el === 'function' || typeof el === 'symbol') {
        return 'null';
    }
    return encodeNode(el);
}

/**
 * Recursively rebuild every object with its keys reinserted in sorted order.
 * The rebuild is what produces the canonical ECMAScript own-property order
 * (integer-like keys numeric-ascending first, then lexical) that the encoder
 * relies on. Pure structural transform — no number handling.
 */
export function sortDeep(value: unknown): unknown {
    if (Array.isArray(value)) {
        return value.map(sortDeep);
    }
    if (value !== null && typeof value === 'object') {
        const obj = value as Record<string, unknown>;
        const sorted: Record<string, unknown> = {};
        for (const key of Object.keys(obj).sort()) {
            sorted[key] = sortDeep(obj[key]);
        }
        return sorted;
    }
    return value;
}

export function utf8Bytes(s: string): Uint8Array {
    return new TextEncoder().encode(s);
}

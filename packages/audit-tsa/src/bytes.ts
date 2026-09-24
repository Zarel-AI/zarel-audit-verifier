// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
import { timingSafeEqual } from 'node:crypto';

/**
 * Length-checked, constant-time byte comparison. Used for every hash / imprint /
 * Merkle-root equality in this package — all security-sensitive, so they share
 * ONE constant-time implementation rather than drifting per-call-site.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false;
    }
    return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/**
 * View a `Uint8Array`'s exact bytes as a standalone `ArrayBuffer` — the input that
 * `asn1js.fromBER` / pkijs `*.fromBER` require. Slices on byteOffset/byteLength so a
 * subarray view is not over-read. The single shared copy for the whole package.
 */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

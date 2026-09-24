// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Ed25519 verification over RAW 32-byte public keys — node:crypto only.
 *
 * node:crypto has no `format: 'raw'` import for Ed25519, so we wrap the 32 raw
 * public-key bytes in the fixed SPKI DER envelope and let `createPublicKey` parse
 * it. This is the standard interop trick; the prefix is constant for Ed25519.
 */

import { createHash, createPublicKey, verify as nodeVerify, type KeyObject } from 'node:crypto';

const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** Build an Ed25519 public `KeyObject` from raw 32-byte key material. */
export function ed25519PublicKeyFromRaw(raw: Uint8Array): KeyObject | null {
    if (raw.length !== 32) {
        return null;
    }
    try {
        return createPublicKey({
            key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(raw)]),
            format: 'der',
            type: 'spki',
        });
    } catch {
        return null;
    }
}

/** Verify an Ed25519 signature over `message` against a raw public key. Fail-closed. */
export function ed25519Verify(message: Uint8Array, signature: Uint8Array, rawPublicKey: Uint8Array): boolean {
    if (signature.length !== 64) {
        return false;
    }
    const key = ed25519PublicKeyFromRaw(rawPublicKey);
    if (key === null) {
        return false;
    }
    try {
        return nodeVerify(null, Buffer.from(message), key, Buffer.from(signature));
    } catch {
        return false;
    }
}

/**
 * C2SP key id = SHA-256(name || 0x0A || algByte || rawPublicKey)[:4].
 * algByte is 0x01 for a signed-note Ed25519 log key, 0x04 for a cosignature key.
 */
export function c2spKeyId(name: string, algByte: number, rawPublicKey: Uint8Array): Uint8Array {
    const h = createHash('sha256');
    h.update(Buffer.from(name, 'utf8'));
    h.update(Buffer.from([0x0a, algByte]));
    h.update(Buffer.from(rawPublicKey));
    return new Uint8Array(h.digest()).subarray(0, 4);
}

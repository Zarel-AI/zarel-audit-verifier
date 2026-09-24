// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Deterministic Ed25519 test keys for the transparency-log golden vectors.
 *
 * A key is fully determined by its 32-byte seed (RFC 8032), so wrapping a fixed
 * seed in the PKCS8 DER envelope yields a reproducible keypair and — since
 * Ed25519 signing is deterministic — reproducible signatures. We pin the WIRE
 * FORMAT (key-id derivation, base64 layout, message construction) byte-exactly;
 * the signature value is exercised by round-trip verify, not memorised.
 */

import { createPrivateKey, createPublicKey, sign as nodeSign, type KeyObject } from 'node:crypto';

// PKCS8 DER prefix for an Ed25519 private key, followed by the 32-byte seed.
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
// SPKI DER prefix for an Ed25519 public key, followed by the 32-byte public key.
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export interface TestKey {
    readonly privateKey: KeyObject;
    readonly publicKey: KeyObject;
    /** Raw 32-byte Ed25519 public key. */
    readonly rawPublicKey: Uint8Array;
    /** Deterministic Ed25519 signature over `msg`. */
    sign(msg: Uint8Array): Uint8Array;
}

export function ed25519FromSeed(seed: Uint8Array): TestKey {
    if (seed.length !== 32) {
        throw new Error('ed25519FromSeed: seed must be 32 bytes');
    }
    const privateKey = createPrivateKey({
        key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]),
        format: 'der',
        type: 'pkcs8',
    });
    const publicKey = createPublicKey(privateKey);
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    const rawPublicKey = new Uint8Array(spki.subarray(spki.length - 32));
    return {
        privateKey,
        publicKey,
        rawPublicKey,
        sign: (msg) => new Uint8Array(nodeSign(null, Buffer.from(msg), privateKey)),
    };
}

/** A fixed log signing key (seed = 0x01 repeated) and witness key (seed = 0x02 repeated). */
export const LOG_KEY = ed25519FromSeed(new Uint8Array(32).fill(0x01));
export const WITNESS_KEY = ed25519FromSeed(new Uint8Array(32).fill(0x02));
export const SPKI_RAW_PREFIX = SPKI_ED25519_PREFIX;

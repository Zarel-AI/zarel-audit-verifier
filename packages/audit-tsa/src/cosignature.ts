// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * C2SP cosignature/v1 parse + single-cosignature verify.
 *
 * Signature line: "— <keyName> base64(keyId[4] || u64BE timestamp || sig[64])".
 * Cosigner key id = SHA-256(name || 0x0A || 0x04 || pubkey)[:4]  (algorithm 0x04).
 * The witness signs the timestamped checkpoint:
 *   "cosignature/v1\n" + "time <decimal>\n" + <checkpoint note body>
 *
 * This is the verification PRIMITIVE for ONE cosignature. The N-of-M quorum /
 * named-policy evaluation + the non-equivocation label live in witness-quorum.ts — NOT here.
 */

import { c2spKeyId, ed25519Verify } from './ed25519.js';

const EM_DASH = '—';
const COSIG_KEY_ALG = 0x04;
const BLOB_LEN = 4 + 8 + 64;

export interface Cosignature {
    readonly keyName: string;
    readonly keyId: Uint8Array; // 4 bytes
    readonly timestamp: bigint; // POSIX seconds
    readonly signature: Uint8Array; // 64-byte Ed25519
}

/** The timestamped message a witness signs over a checkpoint body. */
export function cosignatureMessage(checkpointBody: string, timestamp: bigint): Uint8Array {
    return new Uint8Array(Buffer.from(`cosignature/v1\ntime ${timestamp.toString()}\n${checkpointBody}`, 'utf8'));
}

/** Format a cosignature/v1 signature line (used by tests + a witness mock). */
export function formatCosignatureLine(
    keyName: string,
    publicKey: Uint8Array,
    timestamp: bigint,
    signature: Uint8Array,
): string {
    if (signature.length !== 64) {
        throw new Error('formatCosignatureLine: Ed25519 signature must be 64 bytes');
    }
    const keyId = c2spKeyId(keyName, COSIG_KEY_ALG, publicKey);
    const ts = Buffer.alloc(8);
    ts.writeBigUInt64BE(timestamp);
    const blob = Buffer.concat([Buffer.from(keyId), ts, Buffer.from(signature)]);
    return `${EM_DASH} ${keyName} ${blob.toString('base64')}\n`;
}

/** Parse one cosignature/v1 line. Returns null if malformed (fail-closed). */
export function parseCosignature(line: string): Cosignature | null {
    const trimmed = line.endsWith('\n') ? line.slice(0, -1) : line;
    const prefix = `${EM_DASH} `;
    if (!trimmed.startsWith(prefix)) {
        return null;
    }
    const rest = trimmed.slice(prefix.length);
    const sp = rest.indexOf(' ');
    if (sp <= 0) {
        return null;
    }
    const keyName = rest.slice(0, sp);
    const b64 = rest.slice(sp + 1);
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) {
        return null;
    }
    const blob = Buffer.from(b64, 'base64');
    if (blob.length !== BLOB_LEN) {
        return null;
    }
    return {
        keyName,
        keyId: new Uint8Array(blob.subarray(0, 4)),
        timestamp: blob.readBigUInt64BE(4),
        signature: new Uint8Array(blob.subarray(12)),
    };
}

/**
 * Verify a single cosignature against the witness raw public key + the cosigned
 * checkpoint body. Binds the cosignature's key id to the public key, then checks
 * the Ed25519 signature over the timestamped message. Fail-closed. NO quorum logic.
 */
export function verifyCosignature(cosig: Cosignature, checkpointBody: string, witnessPublicKey: Uint8Array): boolean {
    const expectedKeyId = c2spKeyId(cosig.keyName, COSIG_KEY_ALG, witnessPublicKey);
    if (!Buffer.from(cosig.keyId).equals(Buffer.from(expectedKeyId))) {
        return false;
    }
    const message = cosignatureMessage(checkpointBody, cosig.timestamp);
    return ed25519Verify(message, cosig.signature, witnessPublicKey);
}

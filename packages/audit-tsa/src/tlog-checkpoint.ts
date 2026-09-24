// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * C2SP tlog-checkpoint + signed-note encode / decode / verify.
 *
 * Body (3 newline-terminated lines): origin, ASCII-decimal tree size, base64 root.
 * Signed note: body text, a blank line, then a signature line
 *   "— <keyName> base64(keyId[4] || signature[64])"   (em-dash U+2014, space)
 * where keyId = SHA-256(name || 0x0A || 0x01 || pubkey)[:4] and the Ed25519
 * signature is over the note TEXT (the body, including its trailing newline).
 *
 * Signing itself is NOT here — the log's private key stays with whoever operates
 * the log, which signs `Buffer.from(body)` and hands the raw signature to
 * `assembleSignedNote`. This module stays pure and offline.
 */

import { c2spKeyId, ed25519Verify } from './ed25519.js';
import { bytesEqual } from './bytes.js';

const EM_DASH = '—';
const NOTE_KEY_ALG = 0x01;
const SHA256_LEN = 32;

/** Strict standard-base64 → bytes; returns null on any non-base64 input (no lenient drop). */
function strictBase64(s: string): Uint8Array | null {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) {
        return null;
    }
    return new Uint8Array(Buffer.from(s, 'base64'));
}

export interface TlogCheckpoint {
    readonly origin: string;
    readonly treeSize: bigint;
    readonly rootHash: Uint8Array;
}

/** Encode the 3-line checkpoint note body. */
export function encodeCheckpointBody(cp: TlogCheckpoint): string {
    if (cp.origin.length === 0 || cp.origin.includes('\n')) {
        throw new Error('encodeCheckpointBody: invalid origin');
    }
    if (cp.treeSize < 0n) {
        throw new Error('encodeCheckpointBody: negative tree size');
    }
    const rootB64 = Buffer.from(cp.rootHash).toString('base64');
    return `${cp.origin}\n${cp.treeSize.toString()}\n${rootB64}\n`;
}

/** Parse a checkpoint note body back to its fields. Strict; throws on malformed. */
export function decodeCheckpointBody(body: string): TlogCheckpoint {
    const lines = body.split('\n');
    // body ends in '\n' → at least ['origin','size','root',''].
    if (lines.length < 4) {
        throw new Error('decodeCheckpointBody: expected at least three lines');
    }
    const [origin, sizeStr, rootB64] = lines;
    if (!origin) {
        throw new Error('decodeCheckpointBody: empty origin');
    }
    if (!/^[0-9]+$/.test(sizeStr)) {
        throw new Error('decodeCheckpointBody: tree size is not an ASCII decimal');
    }
    const rootHash = strictBase64(rootB64);
    if (rootHash === null || rootHash.length !== SHA256_LEN) {
        throw new Error('decodeCheckpointBody: root hash is not a base64 SHA-256 digest');
    }
    return { origin, treeSize: BigInt(sizeStr), rootHash };
}

/**
 * Assemble a signed note from a body, the signer's name + raw public key, and the
 * raw Ed25519 signature over `Buffer.from(body)`. Returns the full note text.
 */
export function assembleSignedNote(
    body: string,
    keyName: string,
    publicKey: Uint8Array,
    signature: Uint8Array,
): string {
    if (signature.length !== 64) {
        throw new Error('assembleSignedNote: Ed25519 signature must be 64 bytes');
    }
    const keyId = c2spKeyId(keyName, NOTE_KEY_ALG, publicKey);
    const blob = Buffer.concat([Buffer.from(keyId), Buffer.from(signature)]);
    return `${body}\n${EM_DASH} ${keyName} ${blob.toString('base64')}\n`;
}

/**
 * Verify a signed checkpoint note against `keyName` + raw `publicKey`; return the
 * parsed checkpoint, or null on any structural / cryptographic failure (fail-closed).
 */
export function verifyCheckpointNote(note: string, keyName: string, publicKey: Uint8Array): TlogCheckpoint | null {
    // Split body (text + trailing newline) from the blank-line-separated signatures.
    const sep = note.indexOf('\n\n');
    if (sep < 0) {
        return null;
    }
    const body = note.slice(0, sep + 1); // include the body's trailing newline (the signed text)
    const sigBlock = note.slice(sep + 2);

    const prefix = `${EM_DASH} ${keyName} `;
    const sigLine = sigBlock
        .split('\n')
        .find((l) => l.startsWith(prefix));
    if (sigLine === undefined) {
        return null;
    }
    const blob = strictBase64(sigLine.slice(prefix.length));
    if (blob === null || blob.length !== 4 + 64) {
        return null;
    }
    const keyId = blob.subarray(0, 4);
    const signature = new Uint8Array(blob.subarray(4));
    const expectedKeyId = c2spKeyId(keyName, NOTE_KEY_ALG, publicKey);
    if (!bytesEqual(keyId, expectedKeyId)) {
        return null;
    }
    if (!ed25519Verify(Buffer.from(body, 'utf8'), signature, publicKey)) {
        return null;
    }
    try {
        // origin SHOULD match the signature key name (C2SP) but is not required to.
        return decodeCheckpointBody(body);
    } catch {
        return null;
    }
}

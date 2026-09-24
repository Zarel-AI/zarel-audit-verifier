// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * C2SP tlog-checkpoint + signed-note golden vectors.
 *
 * Body = 3 newline-terminated lines (origin, decimal tree size, base64 root).
 * Signature line = "— <keyName> base64(keyId[4] || sig)", em-dash U+2014, key id
 * = SHA-256(name || 0x0A || 0x01 || pubkey)[:4], signature over the note text.
 * The wire format is pinned byte-exactly; the signature is exercised by round-trip.
 */

import { createHash } from 'node:crypto';
import {
    encodeCheckpointBody,
    decodeCheckpointBody,
    assembleSignedNote,
    verifyCheckpointNote,
    type TlogCheckpoint,
} from '../src/tlog-checkpoint.js';
import { LOG_KEY } from './helpers/ed25519.js';

const ORIGIN = 'zarel.audit.log';
const ROOT = new Uint8Array(createHash('sha256').update('root').digest());
const CP: TlogCheckpoint = { origin: ORIGIN, treeSize: 42n, rootHash: ROOT };

function noteKeyId(name: string, pubkey: Uint8Array): Uint8Array {
    const h = createHash('sha256');
    h.update(Buffer.from(name, 'utf8'));
    h.update(Buffer.from([0x0a, 0x01]));
    h.update(Buffer.from(pubkey));
    return new Uint8Array(h.digest()).subarray(0, 4);
}

describe('tlog-checkpoint body encode/decode', () => {
    it('encodes exactly three newline-terminated lines', () => {
        const body = encodeCheckpointBody(CP);
        expect(body).toBe(`${ORIGIN}\n42\n${Buffer.from(ROOT).toString('base64')}\n`);
    });

    it('round-trips encode → decode', () => {
        const back = decodeCheckpointBody(encodeCheckpointBody(CP));
        expect(back.origin).toBe(ORIGIN);
        expect(back.treeSize).toBe(42n);
        expect(Buffer.from(back.rootHash).equals(Buffer.from(ROOT))).toBe(true);
    });

    it('rejects malformed bodies (fail-closed)', () => {
        expect(() => decodeCheckpointBody('only-two\nlines\n')).toThrow();
        expect(() => decodeCheckpointBody(`${ORIGIN}\nNOTNUMBER\nx\n`)).toThrow();
    });

    it('rejects a root hash that is not a 32-byte SHA-256 digest', () => {
        const shortRoot = Buffer.from('abcd', 'hex').toString('base64'); // 2 bytes
        expect(() => decodeCheckpointBody(`${ORIGIN}\n5\n${shortRoot}\n`)).toThrow(/SHA-256/);
    });

    it('rejects a root field that is not strict base64 (no lenient drop)', () => {
        expect(() => decodeCheckpointBody(`${ORIGIN}\n5\nnot valid base64!!\n`)).toThrow();
    });
});

describe('signed note (signature line format)', () => {
    it('key id = SHA-256(name || 0x0A || 0x01 || pubkey)[:4]', () => {
        const body = encodeCheckpointBody(CP);
        const sig = LOG_KEY.sign(Buffer.from(body, 'utf8'));
        const note = assembleSignedNote(body, ORIGIN, LOG_KEY.rawPublicKey, sig);
        const expectedKeyId = noteKeyId(ORIGIN, LOG_KEY.rawPublicKey);

        // structure: body + blank line + "— <name> <base64>\n"
        const lines = note.split('\n');
        const sigLine = lines[lines.length - 2]; // trailing newline → last element is ''
        expect(sigLine.startsWith(`— ${ORIGIN} `)).toBe(true);

        const b64 = sigLine.slice(`— ${ORIGIN} `.length);
        const blob = Buffer.from(b64, 'base64');
        expect(blob.subarray(0, 4).equals(Buffer.from(expectedKeyId))).toBe(true);
        expect(blob.subarray(4).equals(Buffer.from(sig))).toBe(true);
        expect(blob.length).toBe(4 + 64);
    });

    it('note text is body + blank line + sig line', () => {
        const body = encodeCheckpointBody(CP);
        const sig = LOG_KEY.sign(Buffer.from(body, 'utf8'));
        const note = assembleSignedNote(body, ORIGIN, LOG_KEY.rawPublicKey, sig);
        expect(note.startsWith(`${body}\n— `)).toBe(true);
    });
});

describe('verifyCheckpointNote (round-trip + fail-closed)', () => {
    it('verifies a well-formed signed note and recovers the checkpoint', () => {
        const body = encodeCheckpointBody(CP);
        const sig = LOG_KEY.sign(Buffer.from(body, 'utf8'));
        const note = assembleSignedNote(body, ORIGIN, LOG_KEY.rawPublicKey, sig);
        const cp = verifyCheckpointNote(note, ORIGIN, LOG_KEY.rawPublicKey);
        expect(cp).not.toBeNull();
        expect(cp?.treeSize).toBe(42n);
        expect(cp?.origin).toBe(ORIGIN);
    });

    it('returns null when the body is tampered after signing', () => {
        const body = encodeCheckpointBody(CP);
        const sig = LOG_KEY.sign(Buffer.from(body, 'utf8'));
        const note = assembleSignedNote(body, ORIGIN, LOG_KEY.rawPublicKey, sig);
        const tampered = note.replace('42', '99');
        expect(verifyCheckpointNote(tampered, ORIGIN, LOG_KEY.rawPublicKey)).toBeNull();
    });

    it('returns null for a wrong public key', () => {
        const body = encodeCheckpointBody(CP);
        const sig = LOG_KEY.sign(Buffer.from(body, 'utf8'));
        const note = assembleSignedNote(body, ORIGIN, LOG_KEY.rawPublicKey, sig);
        const wrongPub = new Uint8Array(LOG_KEY.rawPublicKey);
        wrongPub[0] ^= 0xff;
        expect(verifyCheckpointNote(note, ORIGIN, wrongPub)).toBeNull();
    });

    it('returns null when the key name does not match the signature line', () => {
        const body = encodeCheckpointBody(CP);
        const sig = LOG_KEY.sign(Buffer.from(body, 'utf8'));
        const note = assembleSignedNote(body, ORIGIN, LOG_KEY.rawPublicKey, sig);
        expect(verifyCheckpointNote(note, 'other.origin', LOG_KEY.rawPublicKey)).toBeNull();
    });
});

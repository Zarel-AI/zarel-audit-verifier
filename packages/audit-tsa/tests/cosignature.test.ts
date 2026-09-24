// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * C2SP cosignature/v1 golden vectors.
 *
 * Signature line = "— <keyName> base64(keyId[4] || u64BE timestamp || sig[64])".
 * Cosigner key id = SHA-256(name || 0x0A || 0x04 || pubkey)[:4] (algorithm 0x04).
 * Signed message = "cosignature/v1\n" + "time <decimal>\n" + checkpoint note body.
 * Single-cosignature verify only — quorum/policy is witness-quorum's concern.
 */

import { createHash } from 'node:crypto';
import {
    parseCosignature,
    cosignatureMessage,
    verifyCosignature,
    formatCosignatureLine,
} from '../src/cosignature.js';
import { WITNESS_KEY } from './helpers/ed25519.js';

const WITNESS_NAME = 'https://witness.example/zarel';
const TS = 1679315147n;
const BODY = 'zarel.audit.log\n42\n' + Buffer.from('rootbytes').toString('base64') + '\n';

function cosignKeyId(name: string, pubkey: Uint8Array): Uint8Array {
    const h = createHash('sha256');
    h.update(Buffer.from(name, 'utf8'));
    h.update(Buffer.from([0x0a, 0x04]));
    h.update(Buffer.from(pubkey));
    return new Uint8Array(h.digest()).subarray(0, 4);
}

describe('cosignatureMessage', () => {
    it('is "cosignature/v1\\n" + "time <ts>\\n" + body (byte-exact)', () => {
        const msg = cosignatureMessage(BODY, TS);
        const expected = Buffer.from(`cosignature/v1\ntime ${TS}\n${BODY}`, 'utf8');
        expect(Buffer.from(msg).equals(expected)).toBe(true);
    });
});

describe('cosignature/v1 line format', () => {
    it('round-trips format → parse with key id (0x04), big-endian timestamp, 64-byte sig', () => {
        const msg = cosignatureMessage(BODY, TS);
        const sig = WITNESS_KEY.sign(msg);
        const line = formatCosignatureLine(WITNESS_NAME, WITNESS_KEY.rawPublicKey, TS, sig);

        const parsed = parseCosignature(line);
        expect(parsed).not.toBeNull();
        expect(parsed?.keyName).toBe(WITNESS_NAME);
        expect(parsed?.timestamp).toBe(TS);
        expect(Buffer.from(parsed!.keyId).equals(Buffer.from(cosignKeyId(WITNESS_NAME, WITNESS_KEY.rawPublicKey)))).toBe(
            true,
        );
        expect(parsed?.signature.length).toBe(64);
        expect(Buffer.from(parsed!.signature).equals(Buffer.from(sig))).toBe(true);
    });

    it('encodes the blob as keyId[4] || u64BE ts || sig[64] = 76 bytes', () => {
        const sig = WITNESS_KEY.sign(cosignatureMessage(BODY, TS));
        const line = formatCosignatureLine(WITNESS_NAME, WITNESS_KEY.rawPublicKey, TS, sig);
        const b64 = line.slice(`— ${WITNESS_NAME} `.length).trimEnd();
        const blob = Buffer.from(b64, 'base64');
        expect(blob.length).toBe(4 + 8 + 64);
        expect(blob.readBigUInt64BE(4)).toBe(TS);
    });

    it('rejects malformed lines (fail-closed)', () => {
        expect(parseCosignature('not a cosignature')).toBeNull();
        expect(parseCosignature(`— ${WITNESS_NAME} not-base64!!`)).toBeNull();
    });
});

describe('verifyCosignature (single; fail-closed)', () => {
    it('verifies a witness cosignature over the checkpoint body', () => {
        const sig = WITNESS_KEY.sign(cosignatureMessage(BODY, TS));
        const line = formatCosignatureLine(WITNESS_NAME, WITNESS_KEY.rawPublicKey, TS, sig);
        const cosig = parseCosignature(line)!;
        expect(verifyCosignature(cosig, BODY, WITNESS_KEY.rawPublicKey)).toBe(true);
    });

    it('fails on a wrong timestamp (message mismatch)', () => {
        const sig = WITNESS_KEY.sign(cosignatureMessage(BODY, TS));
        const line = formatCosignatureLine(WITNESS_NAME, WITNESS_KEY.rawPublicKey, TS, sig);
        const cosig = { ...parseCosignature(line)!, timestamp: TS + 1n };
        expect(verifyCosignature(cosig, BODY, WITNESS_KEY.rawPublicKey)).toBe(false);
    });

    it('fails on a wrong witness public key', () => {
        const sig = WITNESS_KEY.sign(cosignatureMessage(BODY, TS));
        const cosig = parseCosignature(formatCosignatureLine(WITNESS_NAME, WITNESS_KEY.rawPublicKey, TS, sig))!;
        const wrong = new Uint8Array(WITNESS_KEY.rawPublicKey);
        wrong[5] ^= 0xff;
        expect(verifyCosignature(cosig, BODY, wrong)).toBe(false);
    });

    it('fails when the key id does not match the witness key (binding check)', () => {
        const sig = WITNESS_KEY.sign(cosignatureMessage(BODY, TS));
        const cosig = parseCosignature(formatCosignatureLine(WITNESS_NAME, WITNESS_KEY.rawPublicKey, TS, sig))!;
        const tampered = { ...cosig, keyId: new Uint8Array([0, 0, 0, 0]) };
        expect(verifyCosignature(tampered, BODY, WITNESS_KEY.rawPublicKey)).toBe(false);
    });
});

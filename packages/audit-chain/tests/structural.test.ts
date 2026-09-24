// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Structural gate — verifyChain is a PURE in-memory routine: it must not
 * import any network/DB/IO module, and it must be the single chain-verification
 * entry point. canonicalJson's single-source rule also lives here: it is defined
 * in this package, and this package has no cross-package (@zarel-ai/*) import.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const SRC = join(__dirname, '..', 'src');

function allSrc(): string[] {
    return readdirSync(SRC).filter((f) => f.endsWith('.ts')).map((f) => join(SRC, f));
}

describe('structural', () => {
    it('verify-chain imports no network/DB module (pure)', () => {
        const text = readFileSync(join(SRC, 'verify-chain.ts'), 'utf8');
        const forbidden = ['knex', 'pg', 'http', 'https', 'net', 'node:http', 'node:net', 'fetch('];
        for (const f of forbidden) {
            expect(text.includes(`'${f}'`)).toBe(false);
        }
    });

    it('audit-chain has no cross-package @zarel-ai import (no dependency on other Zarel packages)', () => {
        for (const file of allSrc()) {
            const text = readFileSync(file, 'utf8');
            expect(/from '@zarel-ai\//.test(text)).toBe(false);
        }
    });

    it('canonicalJson is defined exactly once in this package', () => {
        const defs = allSrc().filter((f) =>
            /export function canonicalJson/.test(readFileSync(f, 'utf8')),
        );
        expect(defs.length).toBe(1);
    });

    it('serializeNumber (the single canonical number authority) is defined exactly once, in canonical-json.ts', () => {
        const defs = allSrc().filter((f) =>
            /export function serializeNumber/.test(readFileSync(f, 'utf8')),
        );
        expect(defs.map((f) => f.split('/').pop())).toEqual(['canonical-json.ts']);
    });

    it('no encoder file routes numbers through bare JSON.stringify (canonical-json builds the string itself)', () => {
        // The chain/event encoders must compose canonicalJson, never re-encode a
        // value via JSON.stringify (which would bypass serializeNumber and could
        // diverge from the verifier). Only canonical-json.ts may call
        // JSON.stringify — and only for the single string/key primitive.
        for (const file of allSrc()) {
            const base = file.split('/').pop();
            if (base === 'canonical-json.ts') continue;
            const text = readFileSync(file, 'utf8');
            expect(text.includes('JSON.stringify(')).toBe(false);
        }
    });
});

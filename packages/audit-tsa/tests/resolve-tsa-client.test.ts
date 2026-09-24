// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * resolveTsaClient — building the TSA client from environment variables.
 * Fail-closed in production; disabled (null) in non-production when no endpoint is
 * configured — never a silent "anchored" claim.
 */

import { resolveTsaClient, type WarnLogger } from '../src/resolve-tsa-client.js';

function capturingLogger(): WarnLogger & { messages: string[] } {
    const messages: string[] = [];
    return { messages, warn: (m: string) => messages.push(m) };
}

describe('resolveTsaClient', () => {
    it('returns a usable client when an endpoint is configured', () => {
        const client = resolveTsaClient({ NODE_ENV: 'production', AUDIT_TSA_ENDPOINT: 'https://tsa.example/tsr' });
        expect(client).not.toBeNull();
        expect(typeof client?.requestTimestamp).toBe('function');
    });

    it('non-production with no endpoint → null + a warning (anchoring disabled)', () => {
        const logger = capturingLogger();
        const client = resolveTsaClient({ NODE_ENV: 'development' }, logger);
        expect(client).toBeNull();
        expect(logger.messages.some((m) => m.includes('disabled'))).toBe(true);
    });

    it('production with no endpoint → throws (fail-closed)', () => {
        expect(() => resolveTsaClient({ NODE_ENV: 'production' })).toThrow(/AUDIT_TSA_ENDPOINT must be set in production/);
    });

    it('treats an empty endpoint string as unset', () => {
        expect(() => resolveTsaClient({ NODE_ENV: 'production', AUDIT_TSA_ENDPOINT: '' })).toThrow(/must be set in production/);
    });
});

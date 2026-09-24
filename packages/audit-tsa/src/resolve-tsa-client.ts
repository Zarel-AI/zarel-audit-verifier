// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Resolve the external TSA client from environment variables, for an application
 * that anchors its own windows.
 *
 * Provider-agnostic: `AUDIT_TSA_ENDPOINT` (+ optional `AUDIT_TSA_AUTH_HEADER`)
 * points at any conformant RFC 3161 endpoint — a hosted commercial TSA or a
 * self-managed one. Which TSA a deployment may use is that deployment's policy,
 * set in its configuration; the code stays provider-agnostic.
 *
 * Fail-closed in production: a missing endpoint throws rather than silently
 * disabling anchoring. In non-production a missing endpoint returns `null`
 * (anchoring disabled for local development): the caller then anchors nothing,
 * and a window stays un-anchored until a later run anchors it — never a silent
 * "anchored" claim.
 */

import { HttpTsaClient, type TsaClient } from './tsa-client.js';

export interface WarnLogger {
    warn(message: string): void;
}

export function resolveTsaClient(
    env: {
        NODE_ENV?: string;
        AUDIT_TSA_ENDPOINT?: string;
        AUDIT_TSA_AUTH_HEADER?: string;
        AUDIT_TSA_TIMEOUT_MS?: string;
    },
    logger?: WarnLogger,
): TsaClient | null {
    const endpoint = env.AUDIT_TSA_ENDPOINT;
    if (endpoint === undefined || endpoint.length === 0) {
        if (env.NODE_ENV === 'production') {
            throw new Error(
                'AUDIT_TSA_ENDPOINT must be set in production: external timestamp anchoring requires a contracted ' +
                    'RFC 3161 TSA. Fail closed — production must not silently skip anchoring.',
            );
        }
        logger?.warn('AUDIT_TSA_ENDPOINT not set — external timestamp anchoring is disabled (non-production).');
        return null;
    }

    const authHeader = env.AUDIT_TSA_AUTH_HEADER;
    const timeoutMs = parsePositiveInt(env.AUDIT_TSA_TIMEOUT_MS);
    // exactOptionalPropertyTypes: include optional keys only when defined.
    return new HttpTsaClient({
        endpoint,
        ...(authHeader !== undefined && authHeader.length > 0 ? { authHeader } : {}),
        ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    });
}

function parsePositiveInt(value: string | undefined): number | undefined {
    if (value === undefined || value.length === 0) {
        return undefined;
    }
    const parsed = Number.parseInt(value, 10);
    return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}

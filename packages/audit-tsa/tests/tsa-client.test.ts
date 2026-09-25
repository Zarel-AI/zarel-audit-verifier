// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * HttpTsaClient — RFC 3161 request/response over a real local HTTP server
 * (no external network). The mock TSA answers actual TimeStampReq DER with
 * TimeStampResp DER, so the client exercises its full path: build request →
 * POST → parse response → request-time sanity. Every failure mode is a
 * fail-closed Result, never a throw.
 */

import { createServer, type Server } from 'node:http';
import { once } from 'node:events';
import { HttpTsaClient } from '../src/tsa-client.js';
import { verifyTimestampToken } from '../src/verify-timestamp-token.js';
import { createMockTsa, sha256, type MockTsa, type RespondOptions } from './helpers/mock-tsa.js';

const ROOT = sha256('window-root-for-client');

type Handler = (reqDer: Uint8Array) => Promise<{ httpStatus?: number; body: Uint8Array }>;

interface TestServer {
    url: string;
    close(): Promise<void>;
}

async function startServer(handler: Handler): Promise<TestServer> {
    const server: Server = createServer((req, res): void => {
        const chunks: Buffer[] = [];
        req.on('data', (c: Buffer) => chunks.push(c));
        req.on('end', (): void => {
            void (async (): Promise<void> => {
                const { httpStatus = 200, body } = await handler(new Uint8Array(Buffer.concat(chunks)));
                res.writeHead(httpStatus, { 'Content-Type': 'application/timestamp-reply' });
                res.end(Buffer.from(body));
            })();
        });
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const address = server.address();
    const port = typeof address === 'object' && address ? address.port : 0;
    return {
        url: `http://127.0.0.1:${port}/tsa`,
        close: () => new Promise<void>((resolve) => {
            server.close(() => resolve());
            // `close` waits for open connections, and on Node 18.20 (measured) the client's
            // keep-alive socket stays open until it times out, holding `close` for seconds.
            server.closeAllConnections();
        }),
    };
}

let tsa: MockTsa;
beforeAll(async () => {
    tsa = await createMockTsa({ name: 'ClientMock' });
}, 30000);

function grantingHandler(options?: RespondOptions): Handler {
    return async (reqDer) => ({ body: await tsa.respond(reqDer, options) });
}

describe('HttpTsaClient.requestTimestamp', () => {
    it('happy path: returns a token that attests our root and verifies under the pinned root', async () => {
        const server = await startServer(grantingHandler());
        try {
            const client = new HttpTsaClient({ endpoint: server.url });
            const result = await client.requestTimestamp(ROOT);
            expect(result._tag).toBe('Ok');
            if (result._tag !== 'Ok') {
                return;
            }
            const verdict = verifyTimestampToken({ token: result.value, expectedRoot: ROOT, pinnedRoots: [tsa.pinnedRootDer] });
            expect(verdict.ok).toBe(true);
        } finally {
            await server.close();
        }
    });

    it('rejects a non-32-byte root before any network call → invalid_token', async () => {
        const client = new HttpTsaClient({ endpoint: 'http://127.0.0.1:1/unused' });
        const result = await client.requestTimestamp(new Uint8Array(16));
        expect(result).toMatchObject({ _tag: 'Err', error: { kind: 'invalid_token' } });
    });

    it('connection refused / unreachable endpoint → unreachable', async () => {
        const server = await startServer(grantingHandler());
        const { url } = server;
        await server.close(); // nothing is listening now
        const client = new HttpTsaClient({ endpoint: url });
        const result = await client.requestTimestamp(ROOT);
        expect(result).toMatchObject({ _tag: 'Err', error: { kind: 'unreachable' } });
    });

    it('non-2xx HTTP response → malformed_response', async () => {
        const server = await startServer(() => Promise.resolve({ httpStatus: 500, body: new Uint8Array() }));
        try {
            const client = new HttpTsaClient({ endpoint: server.url });
            const result = await client.requestTimestamp(ROOT);
            expect(result).toMatchObject({ _tag: 'Err', error: { kind: 'malformed_response' } });
        } finally {
            await server.close();
        }
    });

    it('TSA status rejection (no token) → malformed_response', async () => {
        const server = await startServer(grantingHandler({ status: 2 }));
        try {
            const client = new HttpTsaClient({ endpoint: server.url });
            const result = await client.requestTimestamp(ROOT);
            expect(result).toMatchObject({ _tag: 'Err', error: { kind: 'malformed_response' } });
        } finally {
            await server.close();
        }
    });

    it('token attests a different imprint than requested → invalid_token', async () => {
        const server = await startServer(grantingHandler({ tamperImprint: true }));
        try {
            const client = new HttpTsaClient({ endpoint: server.url });
            const result = await client.requestTimestamp(ROOT);
            expect(result).toMatchObject({ _tag: 'Err', error: { kind: 'invalid_token' } });
        } finally {
            await server.close();
        }
    });

    it('garbage body → malformed_response', async () => {
        const server = await startServer(() => Promise.resolve({ body: sha256('not-a-timestamp-response') }));
        try {
            const client = new HttpTsaClient({ endpoint: server.url });
            const result = await client.requestTimestamp(ROOT);
            expect(result).toMatchObject({ _tag: 'Err', error: { kind: 'malformed_response' } });
        } finally {
            await server.close();
        }
    });
});

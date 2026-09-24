// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * RFC 3161 TSA client.
 *
 * Requests a timestamp token over a SHA-256 Merkle root: builds a TimeStampReq
 * (`certReq=true` so the token embeds the TSA cert chain the offline verifier
 * pins; a random nonce binds the response to this request), POSTs it as
 * `application/timestamp-query`, and returns the DER TimeStampToken on success.
 *
 * Provider-agnostic: any conformant RFC 3161 HTTP endpoint works (hosted
 * commercial TSA or a self-managed one). All failure modes are
 * fail-closed `Result` errors, never throws: a caller can treat any error as
 * "not anchored this run" and catch up on a later run.
 */

import { randomBytes, X509Certificate } from 'node:crypto';
import * as asn1js from 'asn1js';
import { TimeStampReq, TimeStampResp, MessageImprint, AlgorithmIdentifier, ContentInfo, TSTInfo, Certificate } from 'pkijs';
import { type Result, ok, err } from './result.js';
import { bytesEqual } from './bytes.js';
import { parseContentInfo, tstInfoFromContentInfo } from './cms.js';
import { findSignerCert } from './verify-timestamp-token.js';

const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const SHA256_LEN = 32;
const PKI_STATUS_GRANTED = 0;
const PKI_STATUS_GRANTED_WITH_MODS = 1;
const CONTENT_TYPE_QUERY = 'application/timestamp-query';
const DEFAULT_TIMEOUT_MS = 15_000;

export type TimestampTokenDer = Uint8Array;

export type TsaError =
    | { kind: 'unreachable' } // network/timeout → fail-closed catch-up
    | { kind: 'malformed_response' } // non-2xx, non-token, or status rejection
    | { kind: 'invalid_token'; reason: string }; // imprint/nonce mismatch at request-time sanity

export interface TsaClient {
    /** Request an RFC 3161 token over the given SHA-256 digest (the Merkle root). */
    requestTimestamp(rootSha256: Uint8Array): Promise<Result<TimestampTokenDer, TsaError>>;
}

type FetchLike = (url: string, init: {
    method: string;
    headers: Record<string, string>;
    body: Uint8Array;
    signal: AbortSignal;
}) => Promise<{ ok: boolean; arrayBuffer(): Promise<ArrayBuffer> }>;

export interface HttpTsaClientConfig {
    readonly endpoint: string;
    /** Full `Authorization` header value (e.g. `Bearer …`), if the endpoint needs one. */
    readonly authHeader?: string;
    readonly timeoutMs?: number;
    /** Injectable fetch for tests; defaults to the global `fetch`. */
    readonly fetchImpl?: FetchLike;
}

export class HttpTsaClient implements TsaClient {
    private readonly endpoint: string;
    private readonly authHeader: string | undefined;
    private readonly timeoutMs: number;
    private readonly fetchImpl: FetchLike;

    constructor(config: HttpTsaClientConfig) {
        this.endpoint = config.endpoint;
        this.authHeader = config.authHeader;
        this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
        this.fetchImpl = config.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
    }

    async requestTimestamp(rootSha256: Uint8Array): Promise<Result<TimestampTokenDer, TsaError>> {
        if (rootSha256.length !== SHA256_LEN) {
            return err({ kind: 'invalid_token', reason: `expected a ${SHA256_LEN}-byte SHA-256 root, got ${rootSha256.length}` });
        }

        // Force the nonce to a positive, minimally-encoded ASN.1 INTEGER (first
        // byte 0x01–0x7f): a high-bit-set first byte is a NEGATIVE integer, and a
        // TSA that echoes the nonce in canonical positive form (prepending 0x00)
        // would then fail the byte-exact compare. One bit of entropy is immaterial.
        const nonce = new Uint8Array(randomBytes(16));
        nonce[0] = (nonce[0] & 0x7f) || 0x01;
        const requestDer = buildRequest(rootSha256, nonce);

        let body: ArrayBuffer;
        try {
            const response = await this.fetchImpl(this.endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': CONTENT_TYPE_QUERY,
                    ...(this.authHeader ? { Authorization: this.authHeader } : {}),
                },
                body: requestDer,
                signal: AbortSignal.timeout(this.timeoutMs),
            });
            if (!response.ok) {
                return err({ kind: 'malformed_response' });
            }
            body = await response.arrayBuffer();
        } catch {
            // Network error, DNS failure, connection refused, or timeout.
            return err({ kind: 'unreachable' });
        }

        return parseResponse(new Uint8Array(body), rootSha256, nonce);
    }
}

function buildRequest(root: Uint8Array, nonce: Uint8Array): Uint8Array {
    const request = new TimeStampReq({
        version: 1,
        messageImprint: new MessageImprint({
            hashAlgorithm: new AlgorithmIdentifier({ algorithmId: OID_SHA256 }),
            hashedMessage: new asn1js.OctetString({ valueHex: root }),
        }),
        certReq: true,
        nonce: new asn1js.Integer({ valueHex: nonce }),
    });
    return new Uint8Array(request.toSchema().toBER());
}

function parseResponse(body: Uint8Array, expectedRoot: Uint8Array, expectedNonce: Uint8Array): Result<TimestampTokenDer, TsaError> {
    let token: ContentInfo;
    let tst: TSTInfo;
    try {
        const response = new TimeStampResp({ schema: asn1js.fromBER(body).result });
        const status = Number(response.status.status);
        if (status !== PKI_STATUS_GRANTED && status !== PKI_STATUS_GRANTED_WITH_MODS) {
            return err({ kind: 'malformed_response' });
        }
        if (!response.timeStampToken) {
            return err({ kind: 'malformed_response' });
        }
        token = response.timeStampToken;
        tst = tstInfoFromContentInfo(token).tstInfo;
    } catch {
        return err({ kind: 'malformed_response' });
    }

    // Request-time sanity: the token must attest OUR root, and (if echoed) OUR nonce.
    const imprint = new Uint8Array(tst.messageImprint.hashedMessage.valueBlock.valueHexView);
    if (!bytesEqual(imprint, expectedRoot)) {
        return err({ kind: 'invalid_token', reason: 'token messageImprint does not match the requested root' });
    }
    if (tst.nonce) {
        const nonce = new Uint8Array(tst.nonce.valueBlock.valueHexView);
        if (!bytesEqual(nonce, expectedNonce)) {
            return err({ kind: 'invalid_token', reason: 'token nonce does not echo the request nonce' });
        }
    }

    return ok(new Uint8Array(token.toSchema().toBER()));
}

/**
 * Read the TSA-attested genTime (ISO 8601) from a DER TimeStampToken, or null if
 * it cannot be parsed. This is the time to store with a window's anchor — the
 * third-party-attested time that replaces the operator's self-asserted clock.
 */
export function readTokenGenTime(token: Uint8Array): string | null {
    try {
        return tstInfoFromContentInfo(parseContentInfo(token)).tstInfo.genTime.toISOString();
    } catch {
        return null;
    }
}

/**
 * Read the SIGNER certificate's `notAfter` (ISO 8601) from a DER TimeStampToken,
 * or null if it cannot be parsed. A renewal process uses this to compute each
 * window's renewal deadline (`notAfter − leadTime`): the instant after which the
 * token can no longer be re-timestamped under a still-valid cert.
 */
export function readTokenNotAfter(token: Uint8Array): string | null {
    try {
        const { signedData } = tstInfoFromContentInfo(parseContentInfo(token));
        const certs = (signedData.certificates ?? []).filter((c): c is Certificate => c instanceof Certificate);
        const signer = signedData.signerInfos[0];
        // SAME signer-cert resolution as the verifier (shared findSignerCert) — the
        // renewal deadline must come from the cert verification will actually use.
        const signerCert = signer ? findSignerCert(certs, signer) : undefined;
        if (!signerCert) {
            return null;
        }
        return new Date(new X509Certificate(Buffer.from(signerCert.toSchema().toBER())).validTo).toISOString();
    } catch {
        return null;
    }
}

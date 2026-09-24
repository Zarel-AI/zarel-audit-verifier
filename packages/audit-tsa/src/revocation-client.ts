// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Revocation capture client — the ONLINE half of revocation.
 *
 * Given a freshly-minted RFC 3161 token, fetches CRL/OCSP for its signer chain
 * (at use-time, when the responder is freshest) and returns the DER CAdES
 * `RevocationValues` to persist. This is the only network surface of revocation; the
 * VERIFIER (verify-revocation.ts) stays fully offline over the captured bytes.
 *
 * Split for testability (mirrors HttpTsaClient): the pure helpers — endpoint
 * extraction (AIA OCSP / CRL DP), OCSP-request building, and response→
 * RevocationValues assembly — are unit-tested offline; only the `fetch` glue in
 * `HttpRevocationClient.capture` needs a live responder, so only an end-to-end run
 * exercises it. All failures are fail-closed `Result` errors, never throws: a
 * caller can treat any error as "not captured this run" and retry later
 * (best-effort — capture need never block anchoring).
 */

import { webcrypto } from 'node:crypto';
import {
    CryptoEngine,
    Certificate,
    OCSPRequest,
    OCSPResponse,
    GeneralName,
    type RelativeDistinguishedNames,
} from 'pkijs';
import { type Result, ok, err } from './result.js';
import { toArrayBuffer } from './bytes.js';
import { parseContentInfo, tstInfoFromContentInfo } from './cms.js';
import { findSignerCert } from './verify-timestamp-token.js';
import { encodeRevocationValuesDer, type CryptoInfos } from './revocation.js';

const OID_AIA = '1.3.6.1.5.5.7.1.1';
const OID_AD_OCSP = '1.3.6.1.5.5.7.48.1';
const OID_CRL_DISTRIBUTION_POINTS = '2.5.29.31';
const OID_OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1';
const CONTENT_TYPE_OCSP_REQUEST = 'application/ocsp-request';
const DEFAULT_TIMEOUT_MS = 15_000;

const ocspEngine = new CryptoEngine({ name: 'g26-ocsp', crypto: webcrypto as unknown as Crypto });

export type RevocationSource = 'ocsp' | 'crl' | 'mixed';

export interface CapturedRevocation {
    /** DER `RevocationValues` (crlVals/ocspVals) for the signer chain. */
    readonly revocationValues: Uint8Array;
    readonly source: RevocationSource;
}

export type RevocationCaptureError =
    | { kind: 'malformed_token' } // the token's certs could not be parsed
    | { kind: 'no_endpoints' } // the signer cert advertises no OCSP/CRL URL
    | { kind: 'unreachable' }; // every advertised endpoint failed

export interface RevocationClient {
    /** Capture revocation evidence for the signer of an RFC 3161 token. */
    capture(tokenDer: Uint8Array): Promise<Result<CapturedRevocation, RevocationCaptureError>>;
}

// ───────────────────────── pure helpers (unit-tested) ─────────────────────────

/** First OCSP responder URL from the cert's Authority Information Access extension. */
export function extractOcspUrl(cert: Certificate): string | null {
    const ext = (cert.extensions ?? []).find((e) => e.extnID === OID_AIA);
    const accessDescriptions = (ext?.parsedValue as { accessDescriptions?: Array<{ accessMethod: string; accessLocation: GeneralName }> } | undefined)?.accessDescriptions;
    for (const ad of accessDescriptions ?? []) {
        if (ad.accessMethod === OID_AD_OCSP && ad.accessLocation.type === 6) {
            return String(ad.accessLocation.value);
        }
    }
    return null;
}

/** First CRL distribution-point URL from the cert's CRL Distribution Points extension. */
export function extractCrlUrl(cert: Certificate): string | null {
    const ext = (cert.extensions ?? []).find((e) => e.extnID === OID_CRL_DISTRIBUTION_POINTS);
    const points = (ext?.parsedValue as { distributionPoints?: Array<{ distributionPoint?: GeneralName[] }> } | undefined)?.distributionPoints;
    for (const dp of points ?? []) {
        for (const name of dp.distributionPoint ?? []) {
            if (name.type === 6) {
                return String(name.value);
            }
        }
    }
    return null;
}

/** Build a DER OCSP request for `target` issued by `issuer` (certReq CertID). */
export async function buildOcspRequestDer(target: Certificate, issuer: Certificate): Promise<Uint8Array> {
    const request = new OCSPRequest();
    await request.createForCertificate(target, { hashAlgorithm: 'SHA-256', issuerCertificate: issuer }, ocspEngine);
    return new Uint8Array(request.toSchema().toBER());
}

/** Extract the embedded `BasicOCSPResponse` DER from an OCSP response (status successful). */
export function basicResponseFromOcsp(ocspResponseDer: Uint8Array): Uint8Array | null {
    try {
        const resp = OCSPResponse.fromBER(toArrayBuffer(ocspResponseDer));
        if (resp.responseStatus.valueBlock.valueDec !== 0 || !resp.responseBytes) {
            return null; // not "successful", or no bytes
        }
        if (resp.responseBytes.responseType !== OID_OCSP_BASIC) {
            return null;
        }
        return new Uint8Array(resp.responseBytes.response.valueBlock.valueHexView);
    } catch {
        return null;
    }
}

/** Assemble DER `RevocationValues` + the source label from captured members. */
export function assembleRevocationValues(ocsps: Uint8Array[], crls: Uint8Array[]): CapturedRevocation | null {
    if (ocsps.length === 0 && crls.length === 0) {
        return null;
    }
    const cryptoInfos: CryptoInfos = { crls, ocsps };
    const source: RevocationSource = ocsps.length > 0 && crls.length > 0 ? 'mixed' : ocsps.length > 0 ? 'ocsp' : 'crl';
    return { revocationValues: encodeRevocationValuesDer(cryptoInfos), source };
}

/** Resolve the signer cert + embedded chain of a token (for capture targeting). */
function parseTokenChain(tokenDer: Uint8Array): { signer: Certificate; certs: Certificate[] } | null {
    try {
        const { signedData } = tstInfoFromContentInfo(parseContentInfo(tokenDer));
        const certs = (signedData.certificates ?? []).filter((c): c is Certificate => c instanceof Certificate);
        const signerInfo = signedData.signerInfos[0];
        const signer = signerInfo ? findSignerCert(certs, signerInfo) : undefined;
        if (!signer) {
            return null;
        }
        return { signer, certs };
    } catch {
        return null;
    }
}

function rdnEqual(a: RelativeDistinguishedNames, b: RelativeDistinguishedNames): boolean {
    return a.isEqual(b);
}

/** Find the embedded issuer of `cert` (for OCSP CertID); null if not bundled. */
function findEmbeddedIssuer(cert: Certificate, certs: Certificate[]): Certificate | null {
    return certs.find((c) => rdnEqual(c.subject, cert.issuer) && !rdnEqual(c.subject, cert.subject)) ?? null;
}

// ───────────────────────── HTTP client (needs a live responder) ─────────────────────────

type FetchLike = (url: string, init: {
    method: string;
    headers: Record<string, string>;
    body?: Uint8Array;
    signal: AbortSignal;
}) => Promise<{ ok: boolean; arrayBuffer(): Promise<ArrayBuffer> }>;

export interface HttpRevocationClientConfig {
    readonly timeoutMs?: number;
    /** Injectable fetch for tests; defaults to the global `fetch`. */
    readonly fetchImpl?: FetchLike;
}

export class HttpRevocationClient implements RevocationClient {
    private readonly timeoutMs: number;
    private readonly fetchImpl: FetchLike;

    constructor(config: HttpRevocationClientConfig = {}) {
        this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
        this.fetchImpl = config.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
    }

    async capture(tokenDer: Uint8Array): Promise<Result<CapturedRevocation, RevocationCaptureError>> {
        const parsed = parseTokenChain(tokenDer);
        if (!parsed) {
            return err({ kind: 'malformed_token' });
        }
        const { signer, certs } = parsed;

        const ocspUrl = extractOcspUrl(signer);
        const crlUrl = extractCrlUrl(signer);
        const issuer = findEmbeddedIssuer(signer, certs);
        if (!ocspUrl && !crlUrl) {
            return err({ kind: 'no_endpoints' });
        }

        const ocsps: Uint8Array[] = [];
        const crls: Uint8Array[] = [];

        if (ocspUrl && issuer) {
            try {
                const reqDer = await buildOcspRequestDer(signer, issuer);
                const respDer = await this.post(ocspUrl, reqDer, CONTENT_TYPE_OCSP_REQUEST);
                const basic = respDer && basicResponseFromOcsp(respDer);
                if (basic) {
                    ocsps.push(basic);
                }
            } catch {
                // best-effort: fall through to CRL
            }
        }
        if (crlUrl) {
            try {
                const crlDer = await this.get(crlUrl);
                if (crlDer) {
                    crls.push(crlDer);
                }
            } catch {
                // best-effort
            }
        }

        const captured = assembleRevocationValues(ocsps, crls);
        return captured ? ok(captured) : err({ kind: 'unreachable' });
    }

    private async post(url: string, body: Uint8Array, contentType: string): Promise<Uint8Array | null> {
        return await this.fetchDer(url, { method: 'POST', headers: { 'Content-Type': contentType }, body });
    }

    private async get(url: string): Promise<Uint8Array | null> {
        return await this.fetchDer(url, { method: 'GET', headers: {} });
    }

    private async fetchDer(
        url: string,
        init: { method: string; headers: Record<string, string>; body?: Uint8Array },
    ): Promise<Uint8Array | null> {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);
        try {
            const res = await this.fetchImpl(url, { ...init, signal: controller.signal });
            if (!res.ok) {
                return null;
            }
            return new Uint8Array(await res.arrayBuffer());
        } finally {
            clearTimeout(timer);
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Mock RFC 3161 TSA for offline, deterministic verifier tests.
 *
 * Generates a self-signed root CA → a TSA leaf cert → a real CMS `SignedData`
 * TimeStampToken over a given Merkle root, all via `pkijs` on Node's built-in
 * WebCrypto. The produced token is structurally a real RFC 3161 token: the
 * verifier's offline checks (CMS signature, chain→pinned root, critical
 * id-kp-timeStamping EKU, genTime∈validity, messageImprint) all exercise the
 * production code path.
 *
 * This is NOT a conformance fixture against a commercial/qualified TSA — that
 * byte-level claim stays a separate executable gate (tsa-gate-live-token). Here
 * the pinned root is our own mock CA.
 */

import { webcrypto, createHash } from 'node:crypto';
import * as asn1js from 'asn1js';
import {
    CryptoEngine,
    setEngine,
    Certificate,
    AttributeTypeAndValue,
    Extension,
    BasicConstraints,
    ExtKeyUsage,
    TSTInfo,
    MessageImprint,
    AlgorithmIdentifier,
    SignedData,
    SignerInfo,
    SignedAndUnsignedAttributes,
    Attribute,
    IssuerAndSerialNumber,
    EncapsulatedContentInfo,
    ContentInfo,
    TimeStampReq,
    TimeStampResp,
    PKIStatusInfo,
    ResponseData,
    SingleResponse,
    CertID,
    BasicOCSPResponse,
    CertificateRevocationList,
    RevokedCertificate,
    Time,
    type RelativeDistinguishedNames,
} from 'pkijs';

const engine = new CryptoEngine({ name: 'mock-tsa', crypto: webcrypto as unknown as Crypto });
setEngine('mock-tsa', engine);

const RSA = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) };
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const ID_KP_TIMESTAMPING = '1.3.6.1.5.5.7.3.8';
const ID_KP_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';

export type EkuMode = 'critical' | 'non-critical' | 'none';

export interface MockTsaOptions {
    /** Distinguishes independent CAs (so a token from one fails another's pinned root). */
    readonly name?: string;
    /** TSA-leaf EKU shape — drives the eku_timestamping negative cases. */
    readonly eku?: EkuMode;
    /** TSA-leaf validity window (genTime is checked against this). */
    readonly notBefore?: Date;
    readonly notAfter?: Date;
}

export interface RespondOptions {
    /** Override the PKIStatus (e.g. 2 = rejection) to drive negative client cases. */
    readonly status?: number;
    /** Issue the token over a different imprint than the request asked for (sanity-check negative). */
    readonly tamperImprint?: boolean;
    /** genTime to attest (default: within the TSA cert validity). */
    readonly genTime?: Date;
}

/** OCSP issuance knobs for the revocation-capture tests. */
export interface MockOcspOptions {
    /** good = not revoked; revoked = carries a revocationTime. */
    readonly status?: 'good' | 'revoked';
    /** When `revoked`, the time the cert was revoked (compared against the token genTime). */
    readonly revocationTime?: Date;
    /** OCSP ResponseData.producedAt (defaults to thisUpdate). */
    readonly producedAt?: Date;
    /** SingleResponse.thisUpdate (status-valid-from). */
    readonly thisUpdate?: Date;
    /** SingleResponse.nextUpdate (status-valid-until); omitted when absent. */
    readonly nextUpdate?: Date;
    /** Sign with a delegated id-kp-OCSPSigning responder cert (embedded) instead of the CA directly. */
    readonly delegated?: boolean;
    /** Build a CertID for a different cert than the TSA signer (drives proof_cert_mismatch). */
    readonly targetCert?: Certificate;
    /** Corrupt the signature after signing (drives proof_signature). */
    readonly tamperSignature?: boolean;
}

/** CRL issuance knobs for the revocation-capture tests. */
export interface MockCrlOptions {
    readonly thisUpdate?: Date;
    readonly nextUpdate?: Date;
    /** Serials listed as revoked, each with a revocationDate. */
    readonly revoked?: ReadonlyArray<{ serial: number; revocationDate: Date }>;
    readonly tamperSignature?: boolean;
}

export interface MockTsa {
    /** DER of the root CA — the pinned trust anchor handed to the verifier. */
    readonly pinnedRootDer: Uint8Array;
    /** DER of the TSA signer leaf cert (serial 2) — the cert revocation proofs cover. */
    readonly tsaCertDer: Uint8Array;
    /** Issue a DER TimeStampToken over `root` attesting `genTime`. */
    issue(root: Uint8Array, genTime: Date): Promise<Uint8Array>;
    /** Answer an RFC 3161 query (DER TimeStampReq) with a DER TimeStampResp. */
    respond(requestDer: Uint8Array, options?: RespondOptions): Promise<Uint8Array>;
    /** Issue a DER `BasicOCSPResponse` for the TSA signer cert (CAdES `ocspVals` member). */
    issueOcsp(options?: MockOcspOptions): Promise<Uint8Array>;
    /** Issue a DER `CertificateList` (CRL) signed by the root CA (CAdES `crlVals` member). */
    issueCrl(options?: MockCrlOptions): Promise<Uint8Array>;
    /**
     * The foreign-responder attack fixture: a "good" OCSP for the REAL signer cert (CertID under
     * the genuine issuer) but signed by a rogue id-kp-OCSPSigning responder issued by
     * a FOREIGN CA (not the genuine issuer). Returns the OCSP + the foreign CA DER (the
     * attacker would append it to the token's unsigned cert bag). A correct verifier
     * MUST reject it (a delegated responder must be issued by the genuine CA).
     */
    issueRogueDelegatedOcsp(options?: MockOcspOptions): Promise<{ ocsp: Uint8Array; foreignCaDer: Uint8Array }>;
}

function setCommonName(rdn: RelativeDistinguishedNames, cn: string): void {
    rdn.typesAndValues.push(new AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.Utf8String({ value: cn }) }));
}

async function makeCert(args: {
    cn: string;
    serial: number;
    subjectKey: CryptoKey;
    issuerKey: CryptoKey;
    issuerCn: string;
    notBefore: Date;
    notAfter: Date;
    ca: boolean;
    eku?: EkuMode;
    ekuOids?: string[];
}): Promise<Certificate> {
    const cert = new Certificate();
    cert.version = 2;
    cert.serialNumber = new asn1js.Integer({ value: args.serial });
    setCommonName(cert.subject, args.cn);
    setCommonName(cert.issuer, args.issuerCn);
    cert.notBefore.value = args.notBefore;
    cert.notAfter.value = args.notAfter;
    cert.extensions = [
        new Extension({ extnID: '2.5.29.19', critical: true, extnValue: new BasicConstraints({ cA: args.ca }).toSchema().toBER() }),
    ];
    if (args.ekuOids && args.ekuOids.length > 0) {
        cert.extensions.push(new Extension({
            extnID: '2.5.29.37',
            critical: false,
            extnValue: new ExtKeyUsage({ keyPurposes: args.ekuOids }).toSchema().toBER(),
        }));
    } else if (args.eku && args.eku !== 'none') {
        cert.extensions.push(new Extension({
            extnID: '2.5.29.37',
            critical: args.eku === 'critical',
            extnValue: new ExtKeyUsage({ keyPurposes: [ID_KP_TIMESTAMPING] }).toSchema().toBER(),
        }));
    }
    await cert.subjectPublicKeyInfo.importKey(args.subjectKey, engine);
    await cert.sign(args.issuerKey, 'SHA-256', engine);
    return cert;
}

export async function createMockTsa(options: MockTsaOptions = {}): Promise<MockTsa> {
    const name = options.name ?? 'Mock';
    const notBefore = options.notBefore ?? new Date('2026-01-01T00:00:00Z');
    const notAfter = options.notAfter ?? new Date('2030-01-01T00:00:00Z');

    const rootKeys = await engine.generateKey(RSA, true, ['sign', 'verify']);
    const tsaKeys = await engine.generateKey(RSA, true, ['sign', 'verify']);

    const rootCn = `${name} Root CA`;
    const rootCert = await makeCert({
        cn: rootCn, serial: 1, subjectKey: rootKeys.publicKey, issuerKey: rootKeys.privateKey, issuerCn: rootCn,
        notBefore: new Date('2026-01-01T00:00:00Z'), notAfter: new Date('2031-01-01T00:00:00Z'), ca: true,
    });
    const tsaCert = await makeCert({
        cn: `${name} TSA`, serial: 2, subjectKey: tsaKeys.publicKey, issuerKey: rootKeys.privateKey, issuerCn: rootCn,
        notBefore, notAfter, ca: false, eku: options.eku ?? 'critical',
    });

    const pinnedRootDer = new Uint8Array(rootCert.toSchema().toBER());

    async function buildToken(root: Uint8Array, genTime: Date, nonce?: Uint8Array): Promise<Uint8Array> {
        const tstInfo = new TSTInfo({
            version: 1,
            policy: '1.3.6.1.4.1.99999.1',
            messageImprint: new MessageImprint({
                hashAlgorithm: new AlgorithmIdentifier({ algorithmId: OID_SHA256 }),
                hashedMessage: new asn1js.OctetString({ valueHex: root }),
            }),
            serialNumber: new asn1js.Integer({ value: 0x42 }),
            genTime,
        });
        if (nonce) {
            tstInfo.nonce = new asn1js.Integer({ valueHex: nonce });
        }
        const tstDer = tstInfo.toSchema().toBER();
        const messageDigest = createHash('sha256').update(Buffer.from(tstDer)).digest();
        const signedData = new SignedData({
            version: 3,
            encapContentInfo: new EncapsulatedContentInfo({
                eContentType: OID_TST_INFO,
                eContent: new asn1js.OctetString({ valueHex: tstDer }),
            }),
            signerInfos: [new SignerInfo({
                version: 1,
                sid: new IssuerAndSerialNumber({ issuer: tsaCert.issuer, serialNumber: tsaCert.serialNumber }),
                signedAttrs: new SignedAndUnsignedAttributes({
                    type: 0,
                    attributes: [
                        new Attribute({ type: OID_CONTENT_TYPE, values: [new asn1js.ObjectIdentifier({ value: OID_TST_INFO })] }),
                        new Attribute({ type: OID_MESSAGE_DIGEST, values: [new asn1js.OctetString({ valueHex: messageDigest })] }),
                    ],
                }),
            })],
            certificates: [tsaCert],
        });
        await signedData.sign(tsaKeys.privateKey, 0, 'SHA-256', undefined, engine);
        const ci = new ContentInfo({ contentType: OID_SIGNED_DATA, content: signedData.toSchema() });
        return new Uint8Array(ci.toSchema().toBER());
    }

    async function issue(root: Uint8Array, genTime: Date): Promise<Uint8Array> {
        return await buildToken(root, genTime);
    }

    async function respond(requestDer: Uint8Array, options: RespondOptions = {}): Promise<Uint8Array> {
        const status = options.status ?? 0;
        if (status !== 0 && status !== 1) {
            // Rejection / non-granted: no token (e.g. the TSA refused the request).
            return new Uint8Array(new TimeStampResp({ status: new PKIStatusInfo({ status }) }).toSchema().toBER());
        }

        const request = new TimeStampReq({ schema: asn1js.fromBER(requestDer).result });
        const requestedImprint = new Uint8Array(request.messageImprint.hashedMessage.valueBlock.valueHexView);
        const nonce = request.nonce ? new Uint8Array(request.nonce.valueBlock.valueHexView) : undefined;

        const imprint = options.tamperImprint ? sha256('a-different-imprint') : requestedImprint;
        const genTime = options.genTime ?? new Date('2026-06-15T00:00:00Z');
        const tokenDer = await buildToken(imprint, genTime, nonce);

        const resp = new TimeStampResp({
            status: new PKIStatusInfo({ status }),
            timeStampToken: new ContentInfo({ schema: asn1js.fromBER(tokenDer).result }),
        });
        return new Uint8Array(resp.toSchema().toBER());
    }

    async function issueOcsp(options: MockOcspOptions = {}): Promise<Uint8Array> {
        const status = options.status ?? 'good';
        const thisUpdate = options.thisUpdate ?? new Date('2026-06-15T00:00:00Z');
        const producedAt = options.producedAt ?? thisUpdate;
        const target = options.targetCert ?? tsaCert;

        const certID = new CertID();
        await certID.createForCertificate(target, { hashAlgorithm: 'SHA-256', issuerCertificate: rootCert }, engine);

        const single = new SingleResponse({ certID });
        single.thisUpdate = thisUpdate;
        if (options.nextUpdate) {
            single.nextUpdate = options.nextUpdate;
        }
        // CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo }
        if (status === 'revoked') {
            const revTime = options.revocationTime ?? new Date('2026-06-01T00:00:00Z');
            single.certStatus = new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 1 },
                value: [new asn1js.GeneralizedTime({ valueDate: revTime })],
            });
        } else {
            single.certStatus = new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 } });
        }

        const responseData = new ResponseData({ producedAt, responses: [single] });

        let signerKey = rootKeys.privateKey;
        const basic = new BasicOCSPResponse({ tbsResponseData: responseData });
        if (options.delegated) {
            const delegateKeys = await engine.generateKey(RSA, true, ['sign', 'verify']);
            const delegateCert = await makeCert({
                cn: `${name} OCSP Responder`, serial: 7, subjectKey: delegateKeys.publicKey,
                issuerKey: rootKeys.privateKey, issuerCn: rootCn,
                notBefore: new Date('2026-01-01T00:00:00Z'), notAfter: new Date('2031-01-01T00:00:00Z'),
                ca: false, ekuOids: [ID_KP_OCSP_SIGNING],
            });
            // byKey responder id is awkward in pkijs; byName(delegate.subject) is fine for our verifier.
            responseData.responderID = delegateCert.subject;
            basic.certs = [delegateCert];
            signerKey = delegateKeys.privateKey;
        } else {
            responseData.responderID = rootCert.subject;
        }
        await basic.sign(signerKey, 'SHA-256', engine);

        let der = new Uint8Array(basic.toSchema().toBER());
        if (options.tamperSignature) {
            der = flipByte(der);
        }
        return der;
    }

    async function issueCrl(options: MockCrlOptions = {}): Promise<Uint8Array> {
        const thisUpdate = options.thisUpdate ?? new Date('2026-06-15T00:00:00Z');
        const crl = new CertificateRevocationList();
        crl.version = 1;
        crl.issuer = rootCert.subject;
        crl.thisUpdate = new Time({ type: 0, value: thisUpdate });
        if (options.nextUpdate) {
            crl.nextUpdate = new Time({ type: 0, value: options.nextUpdate });
        }
        if (options.revoked && options.revoked.length > 0) {
            crl.revokedCertificates = options.revoked.map(
                (r) =>
                    new RevokedCertificate({
                        userCertificate: new asn1js.Integer({ value: r.serial }),
                        revocationDate: new Time({ type: 0, value: r.revocationDate }),
                    }),
            );
        }
        await crl.sign(rootKeys.privateKey, 'SHA-256', engine);

        let der = new Uint8Array(crl.toSchema().toBER());
        if (options.tamperSignature) {
            der = flipByte(der);
        }
        return der;
    }

    async function issueRogueDelegatedOcsp(
        options: MockOcspOptions = {},
    ): Promise<{ ocsp: Uint8Array; foreignCaDer: Uint8Array }> {
        const thisUpdate = options.thisUpdate ?? new Date('2026-06-16T00:00:00Z');
        const producedAt = options.producedAt ?? thisUpdate;

        // A foreign CA the attacker controls + a rogue OCSP-signing responder under it.
        const foreignKeys = await engine.generateKey(RSA, true, ['sign', 'verify']);
        const rogueKeys = await engine.generateKey(RSA, true, ['sign', 'verify']);
        const foreignCn = 'Foreign Evil CA';
        const foreignCert = await makeCert({
            cn: foreignCn, serial: 11, subjectKey: foreignKeys.publicKey, issuerKey: foreignKeys.privateKey,
            issuerCn: foreignCn, notBefore: new Date('2026-01-01T00:00:00Z'), notAfter: new Date('2031-01-01T00:00:00Z'), ca: true,
        });
        const rogueCert = await makeCert({
            cn: 'Rogue OCSP Responder', serial: 12, subjectKey: rogueKeys.publicKey, issuerKey: foreignKeys.privateKey,
            issuerCn: foreignCn, notBefore: new Date('2026-01-01T00:00:00Z'), notAfter: new Date('2031-01-01T00:00:00Z'),
            ca: false, ekuOids: [ID_KP_OCSP_SIGNING],
        });

        // CertID still references the GENUINE issuer + signer (all public values).
        const certID = new CertID();
        await certID.createForCertificate(tsaCert, { hashAlgorithm: 'SHA-256', issuerCertificate: rootCert }, engine);
        const single = new SingleResponse({ certID });
        single.thisUpdate = thisUpdate;
        single.certStatus = new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 } }); // good
        const responseData = new ResponseData({ producedAt, responses: [single] });
        responseData.responderID = rogueCert.subject;
        const basic = new BasicOCSPResponse({ tbsResponseData: responseData });
        basic.certs = [rogueCert];
        await basic.sign(rogueKeys.privateKey, 'SHA-256', engine);

        return {
            ocsp: new Uint8Array(basic.toSchema().toBER()),
            foreignCaDer: new Uint8Array(foreignCert.toSchema().toBER()),
        };
    }

    return {
        pinnedRootDer,
        tsaCertDer: new Uint8Array(tsaCert.toSchema().toBER()),
        issue,
        respond,
        issueOcsp,
        issueCrl,
        issueRogueDelegatedOcsp,
    };
}

/**
 * Forge a token whose chain routes through a NON-CA cert under the pinned root —
 * the missing-basicConstraints exploit (CVE-2002-0862 class). The attacker holds
 * an end-entity cert `L` (cA=FALSE, no keyUsage so `checkIssued` accepts it) that
 * was legitimately issued by the pinned root, then uses `L`'s key to sign a forged
 * TSA signer `S`. A verifier that omits the `cA=TRUE` check on intermediates would
 * accept `S → L → root`. Returns the pinned root + the forged token.
 */
export async function forgeTokenViaNonCaIntermediate(
    root: Uint8Array,
    genTime: Date,
): Promise<{ pinnedRootDer: Uint8Array; token: Uint8Array }> {
    const span = { notBefore: new Date('2026-01-01T00:00:00Z'), notAfter: new Date('2030-01-01T00:00:00Z') };
    const rootKeys = await engine.generateKey(RSA, true, ['sign', 'verify']);
    const leafKeys = await engine.generateKey(RSA, true, ['sign', 'verify']);
    const signerKeys = await engine.generateKey(RSA, true, ['sign', 'verify']);

    const rootCn = 'Evil Root CA';
    const rootCert = await makeCert({ cn: rootCn, serial: 1, subjectKey: rootKeys.publicKey, issuerKey: rootKeys.privateKey, issuerCn: rootCn, notBefore: span.notBefore, notAfter: new Date('2031-01-01T00:00:00Z'), ca: true });
    const leafCn = 'Non-CA Leaf';
    const leafCert = await makeCert({ cn: leafCn, serial: 2, subjectKey: leafKeys.publicKey, issuerKey: rootKeys.privateKey, issuerCn: rootCn, ...span, ca: false }); // cA=FALSE, no keyUsage
    const signerCert = await makeCert({ cn: 'Forged TSA', serial: 3, subjectKey: signerKeys.publicKey, issuerKey: leafKeys.privateKey, issuerCn: leafCn, ...span, ca: false, eku: 'critical' });

    const tstInfo = new TSTInfo({
        version: 1, policy: '1.3.6.1.4.1.99999.1',
        messageImprint: new MessageImprint({ hashAlgorithm: new AlgorithmIdentifier({ algorithmId: OID_SHA256 }), hashedMessage: new asn1js.OctetString({ valueHex: root }) }),
        serialNumber: new asn1js.Integer({ value: 0x99 }), genTime,
    });
    const tstDer = tstInfo.toSchema().toBER();
    const messageDigest = createHash('sha256').update(Buffer.from(tstDer)).digest();
    const signedData = new SignedData({
        version: 3,
        encapContentInfo: new EncapsulatedContentInfo({ eContentType: OID_TST_INFO, eContent: new asn1js.OctetString({ valueHex: tstDer }) }),
        signerInfos: [new SignerInfo({
            version: 1,
            sid: new IssuerAndSerialNumber({ issuer: signerCert.issuer, serialNumber: signerCert.serialNumber }),
            signedAttrs: new SignedAndUnsignedAttributes({
                type: 0,
                attributes: [
                    new Attribute({ type: OID_CONTENT_TYPE, values: [new asn1js.ObjectIdentifier({ value: OID_TST_INFO })] }),
                    new Attribute({ type: OID_MESSAGE_DIGEST, values: [new asn1js.OctetString({ valueHex: messageDigest })] }),
                ],
            }),
        })],
        certificates: [signerCert, leafCert], // embedded chain the attacker controls
    });
    await signedData.sign(signerKeys.privateKey, 0, 'SHA-256', undefined, engine);
    const ci = new ContentInfo({ contentType: OID_SIGNED_DATA, content: signedData.toSchema() });
    return { pinnedRootDer: new Uint8Array(rootCert.toSchema().toBER()), token: new Uint8Array(ci.toSchema().toBER()) };
}

/** Flip one byte at `offset` (default: last) — the canonical "tamper" mutation. */
export function flipByte(bytes: Uint8Array, offset = bytes.length - 1): Uint8Array {
    const copy = Buffer.from(bytes);
    copy[offset] ^= 0xff;
    return new Uint8Array(copy);
}

export function sha256(tag: string): Uint8Array {
    return new Uint8Array(createHash('sha256').update(tag).digest());
}

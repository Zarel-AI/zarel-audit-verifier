// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
import * as asn1js from 'asn1js';
import { ContentInfo, SignedData, TSTInfo } from 'pkijs';

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';

/** Parse the outer CMS `ContentInfo` of a DER TimeStampToken. Throws on malformed DER. */
export function parseContentInfo(token: Uint8Array): ContentInfo {
    return new ContentInfo({ schema: asn1js.fromBER(token).result });
}

/**
 * The single CMS `SignedData`→`TSTInfo` extraction shared by the request-side
 * sanity check, the anchor-time `genTime` read, and the verify-side parse — so
 * the genTime stored at anchor time and the genTime checked at verify time can
 * never drift. Throws if the token is not CMS SignedData or carries no eContent.
 */
export function tstInfoFromContentInfo(ci: ContentInfo): { signedData: SignedData; tstInfo: TSTInfo; tstBytes: Buffer } {
    if (ci.contentType !== OID_SIGNED_DATA) {
        throw new Error('timeStampToken is not CMS SignedData');
    }
    const signedData = new SignedData({ schema: ci.content });
    const eContent = signedData.encapContentInfo.eContent;
    if (!eContent) {
        throw new Error('timeStampToken has no eContent');
    }
    // getValue() concatenates primitive/constructed OCTET STRING content; tstBytes
    // is the exact eContent the SignerInfo's messageDigest attribute binds to.
    const tstBytes = Buffer.from(eContent.getValue());
    const tstInfo = new TSTInfo({ schema: asn1js.fromBER(tstBytes).result });
    return { signedData, tstInfo, tstBytes };
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * @zarel-ai/audit-tsa — external timestamp anchoring.
 *
 * RFC 3161 TSA token request/verify + Merkle inclusion proofs. The sole home of
 * the ASN.1/CMS parsing dependency — the @zarel-ai/audit-chain core
 * stays node:crypto-only and mono-algorithm. The token verifier proves a
 * SEPARATE property (temporal precedence) from chain integrity, so it lives in
 * its own module rather than inside verifyChain.
 */

// The single RFC 6962 domain-separated Merkle primitive — consumed by both the
// per-window anchor tree and the transparency-log tree.
export {
    buildMerkleTree,
    verifyInclusion,
    leafHash,
    nodeHash,
    splitPoint,
    MERKLE_SCHEME,
    type MerkleSide,
    type MerkleSibling,
    type InclusionPath,
} from './merkle.js';

export { verifyTimestampToken } from './verify-timestamp-token.js';
export type { TokenFailure, TokenVerdict, VerifyTokenInput } from './types.js';

// Transparency log — C2SP tlog-checkpoint / cosignature over the Merkle tree above
export {
    encodeCheckpointBody,
    decodeCheckpointBody,
    assembleSignedNote,
    verifyCheckpointNote,
    type TlogCheckpoint,
} from './tlog-checkpoint.js';
export {
    parseCosignature,
    cosignatureMessage,
    formatCosignatureLine,
    verifyCosignature,
    type Cosignature,
} from './cosignature.js';
export { bytesEqual } from './bytes.js';
export {
    buildConsistencyProof,
    verifyConsistency,
    type ConsistencyProof,
} from './ct-consistency.js';
export {
    evaluateWitnessQuorum,
    EU_EEA_REGIONS,
    D21_MIN_UNITS,
    type WitnessVerifierEntry,
    type WitnessVerifierPolicy,
    type CheckpointCosignature,
    type QuorumVerdict,
} from './witness-quorum.js';

// RFC 4998 ERS long-term validation
export {
    buildErsTree,
    verifyErsInclusion,
    computeErsRoot,
    type ErsHashAlg,
    type PartialHashtree,
    type ReducedHashtree,
} from './ers-merkle.js';
export { encodeEvidenceRecord, decodeEvidenceRecord, encodeArchiveTimeStampSequence } from './evidence-record.js';
export {
    buildTimestampRenewal,
    buildHashTreeRenewal,
    type IssueToken,
    type RenewalResult,
    type RenewalPerWindow,
    type TimestampRenewalWindow,
    type HashTreeRenewalWindow,
} from './renew.js';
export { verifyEvidenceRecord, type VerifyEvidenceRecordInput } from './verify-evidence-record.js';
export {
    assembleEvidenceRecord,
    type AssembleEvidenceRecordInput,
    type AssembleRenewalAts,
} from './assemble-evidence-record.js';
export type {
    EvidenceRecord,
    ErsArchiveTimeStamp,
    ErsChain,
    RenewalFailure,
    EvidenceRecordVerdict,
    RevocationSummary,
    RevocationPolicy,
    TokenRevocationStatus,
    TokenRevocationVerdict,
    RevocationRejectReason,
} from './types.js';

// RFC 4998 cryptoInfos + CAdES revocation-values
export {
    encodeCryptoInfos,
    decodeCryptoInfos,
    isCryptoInfosEmpty,
    encodeRevocationValuesDer,
    decodeRevocationValuesDer,
    mergeCryptoInfos,
    type CryptoInfos,
} from './revocation.js';
export { verifyRevocation, type VerifyRevocationInput } from './verify-revocation.js';
export {
    HttpRevocationClient,
    extractOcspUrl,
    extractCrlUrl,
    buildOcspRequestDer,
    basicResponseFromOcsp,
    assembleRevocationValues,
    type RevocationClient,
    type CapturedRevocation,
    type RevocationCaptureError,
    type RevocationSource,
    type HttpRevocationClientConfig,
} from './revocation-client.js';

export { HttpTsaClient, readTokenGenTime, readTokenNotAfter } from './tsa-client.js';
export type { TsaClient, TsaError, TimestampTokenDer, HttpTsaClientConfig } from './tsa-client.js';
export { resolveTsaClient, type WarnLogger } from './resolve-tsa-client.js';

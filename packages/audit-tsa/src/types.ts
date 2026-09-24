// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Verify-side types for RFC 3161 token verification. The verifier is synchronous and offline: it takes a
 * DER token, the recomputed Merkle root, and an EXPLICIT set of pinned TSA roots
 * (never the OS trust store), and returns a fail-closed verdict.
 *
 * Request-side types (`TsaClient`/`TsaError`) live in `tsa-client.ts`, with the
 * client that uses them.
 */

/**
 * The single failing check, fail-closed (first failure wins). `malformed_token`
 * is a deliberate refinement of the failure enum: an unparseable DER token must
 * fail with an honest label rather than be coerced into `cms_signature`.
 */
export type TokenFailure =
    | 'no_pinned_root' // pinnedRoots empty → fail-closed; the bundle cannot be its own trust anchor
    | 'malformed_token' // token bytes are not a parseable RFC 3161 TimeStampToken
    | 'cms_signature' // SignedData signature over the signed attributes is invalid (or messageDigest unbound)
    | 'chain_to_pinned_root' // signer cert does not chain to any pinned root
    | 'eku_timestamping' // signer cert lacks the critical id-kp-timeStamping EKU
    | 'gentime_outside_validity' // attested genTime is outside the signer cert's validity window
    | 'imprint_mismatch'; // token messageImprint != the recomputed Merkle root

export interface VerifyTokenInput {
    /** DER `TimeStampToken` (CMS SignedData incl. its embedded intermediate chain). */
    readonly token: Uint8Array;
    /** The Merkle root the caller recomputed from the bundle (the expected message imprint). */
    readonly expectedRoot: Uint8Array;
    /** EXPLICIT pinned TSA root certificates (DER). Never sourced from the bundle or the OS store. */
    readonly pinnedRoots: ReadonlyArray<Uint8Array>;
}

export interface TokenVerdict {
    readonly ok: boolean;
    /** The TSA-attested time (ISO 8601) when `ok`; `null` otherwise. */
    readonly genTime: string | null;
    /** The signer cert's `notAfter` (ISO 8601) when `ok` — needed by the LTV/ERS
     * verifier to enforce "each ATS valid at the next ATS's genTime" and "the last
     * ATS valid at verification time" (RFC 4998 §5.4). Absent when `!ok`. */
    readonly notAfter?: string;
    /** The first failing check when `!ok` (fail-closed). Absent when `ok`. */
    readonly failure?: TokenFailure;
}

// ───────────────────────── RFC 4998 ERS ─────────────────────────

import type { ErsHashAlg, ReducedHashtree } from './ers-merkle.js';
import type { CryptoInfos } from './revocation.js';

/**
 * One `ArchiveTimeStamp` (RFC 4998 §4): a TimeStampToken plus the reduced hash
 * tree proving a data object's leaf reaches the token's message imprint. The
 * `digestAlg` is the tree's hash algorithm (a chain shares one). `reducedHashtree`
 * empty ⇒ the token timestamps the data object hash directly.
 */
export interface ErsArchiveTimeStamp {
    readonly digestAlg: ErsHashAlg;
    readonly reducedHashtree: ReducedHashtree;
    /** DER RFC 3161 `TimeStampToken` (the `timeStamp` ContentInfo). */
    readonly timeStampDer: Uint8Array;
}

/** An `ArchiveTimeStampChain` — all ATS share one hash algorithm. */
export type ErsChain = ReadonlyArray<ErsArchiveTimeStamp>;

/**
 * An `EvidenceRecord` (RFC 4998 §4) for ONE data object (a window's merkle_root).
 * `cryptoInfos` (revocation, [0]) carries captured CRL/OCSP; absent ⇒ no
 * revocation evidence. The sequence is ordered oldest-first;
 * chain 0's first ATS is the window's anchor token, later ATS/chains are renewals.
 */
export interface EvidenceRecord {
    readonly version: 1;
    /** All hash algorithms used across the sequence (RFC `digestAlgorithms`). */
    readonly digestAlgorithms: ReadonlyArray<ErsHashAlg>;
    /** Captured revocation evidence; absent when none was captured. */
    readonly cryptoInfos?: CryptoInfos;
    readonly sequence: ReadonlyArray<ErsChain>;
}

// ───────────────────────── RFC 4998 ERS + revocation verdicts ─────────────────────────

/**
 * Per-token revocation status — three honest states, never two:
 *  - `NOT_REVOKED`: a valid, contemporaneous OCSP/CRL proves the signer cert was
 *    not revoked at the token's genTime.
 *  - `REVOKED`: a valid proof shows the cert revoked at-or-before genTime → hard fail.
 *  - `NOT_CAPTURED`: no usable proof (absent / unverifiable / stale / wrong cert) →
 *    honest degraded; that token keeps the structural-only label, never rendered as checked.
 */
export type TokenRevocationStatus = 'NOT_REVOKED' | 'REVOKED' | 'NOT_CAPTURED';

/**
 * Caller-selected revocation posture. Required — the verifier never
 * assumes a default, because a silent lenient default is exactly what let a
 * stripped-`cryptoInfos` downgrade pass.
 *
 *  - `lenient`: `NOT_CAPTURED` is tolerated (the honest-degraded view an
 *    everyday relying party sees). A proven `REVOKED` still hard-fails.
 *  - `strict`: only a positively-proven `NOT_REVOKED` passes; `NOT_CAPTURED`
 *    hard-fails. Since `cryptoInfos` lives in the RFC-4998 UNPROTECTED bag,
 *    stripping it can only move a status TOWARD `NOT_CAPTURED` — never turn a
 *    failing bundle into a passing one — so strict neutralises the downgrade
 *    without needing to distinguish absent-from-stripped (impossible offline).
 */
export type RevocationPolicy = 'lenient' | 'strict';

/** Why a present proof was unusable (→ `NOT_CAPTURED`), or `revoked` for a hard fail. */
export type RevocationRejectReason =
    | 'no_proof' // no CRL/OCSP in cryptoInfos covers this cert
    | 'proof_signature' // the proof's own signature does not verify to a trust anchor
    | 'proof_not_contemporaneous' // the proof's validity window does not bracket genTime
    | 'proof_cert_mismatch' // the proof is for a different cert (CertID/serial mismatch)
    | 'revoked'; // the cert was revoked at-or-before genTime (hard fail)

export interface TokenRevocationVerdict {
    readonly status: TokenRevocationStatus;
    readonly reason?: RevocationRejectReason;
}

/** The single failing check when an EvidenceRecord does not verify (fail-closed). */
export type RenewalFailure =
    | 'empty_sequence' // no chains / no ATS
    | 'unsupported_alg' // a digestAlgorithm we do not implement
    | 'inclusion_mismatch' // a data object's reducedHashtree does not reach the token imprint
    | 'token_invalid' // an ATS token fails verifyTimestampToken (reason folded in)
    | 'renewal_gap' // a renewal's genTime is after the prior token's notAfter (a lapse)
    | 'renewal_link_broken' // an intra-chain ATS does not cover H(prior token)
    | 'cross_chain_link_broken' // a later chain's first ATS does not cover H'(hash ‖ prior seq)
    | 'tsa_cert_expired' // the LAST ATS's signer cert is not valid at verification time
    | 'token_revoked' // an ATS signer cert was revoked at-or-before its genTime
    | 'revocation_not_captured'; // (strict policy) an ATS lacks a positive non-revocation proof (absent/stripped/unusable)

/**
 * Aggregate revocation outcome across the sequence. Present only when the
 * record carried `cryptoInfos`; absent ⇒ no revocation evidence was checked (the
 * structural-only state, honestly reported as such — never as "checked").
 */
export interface RevocationSummary {
    /** Per-ATS status, oldest-first, aligned with the walked sequence. */
    readonly perToken: ReadonlyArray<TokenRevocationStatus>;
    /** Count of ATS proven `NOT_REVOKED`. */
    readonly checkedCount: number;
    /** Total ATS walked. */
    readonly total: number;
}

export interface EvidenceRecordVerdict {
    readonly ok: boolean;
    /** Number of ArchiveTimeStamps walked (chain depth across the whole sequence). */
    readonly chainDepth: number;
    /** Oldest / latest TSA-attested genTime (ISO 8601) across the chain, when `ok`. */
    readonly oldestGenTime: string | null;
    readonly latestGenTime: string | null;
    /** The latest ATS signer cert's `notAfter` (ISO 8601) — the next renewal deadline. */
    readonly latestNotAfter: string | null;
    /** Revocation outcome; absent when the record carried no `cryptoInfos`. */
    readonly revocation?: RevocationSummary;
    readonly failure?: RenewalFailure;
}

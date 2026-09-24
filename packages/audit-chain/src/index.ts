// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * @zarel-ai/audit-chain — dependency-free audit tamper-evidence primitives.
 *
 * The single source of: canonical JSON (shared with the signer that produces
 * checkpoints), the per-(tenant,log) chain hash, the checkpoint signable-message,
 * and the pure offline verifier. node:crypto only — no runtime dependencies.
 */

export { canonicalJson, serializeNumber, sortDeep, utf8Bytes } from './canonical-json.js';
export { canonicalEventEncode, type ChainedEventContent } from './event-encode.js';
export {
    GENESIS,
    chainHash,
    buildCheckpointMessage,
    checkpointHash,
    CHECKPOINT_SCHEMA_VERSION_SEAL,
    GENESIS_B64,
    terminalKindForHead,
    type CheckpointSignable,
    type TerminalDescriptor,
} from './chain-hash.js';
export {
    verifyChain,
    verifyEd25519Raw,
    type TrustKey,
    type VerifierEventRow,
    type VerifierCheckpoint,
    type VerifyFailureReason,
    type Verdict,
} from './verify-chain.js';

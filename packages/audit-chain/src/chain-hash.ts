// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * The chain-hash primitive and the checkpoint signable-message
 * builder. Computed in exactly ONE place so the signer that writes the chain
 * and the offline verifier can never diverge.
 */

import { createHash } from 'node:crypto';
import { canonicalJson, utf8Bytes } from './canonical-json.js';
import { canonicalEventEncode, type ChainedEventContent } from './event-encode.js';

/**
 * Genesis seed for the first event of a `(tenant, log)` chain. A fixed,
 * domain-separated 32-byte constant: `SHA-256("ZAREL_AUDIT_CHAIN_GENESIS_V1")`.
 * Using a hash (not all-zeros) documents intent and avoids any ambiguity.
 */
export const GENESIS: Uint8Array = createHash('sha256')
    .update('ZAREL_AUDIT_CHAIN_GENESIS_V1')
    .digest();

/**
 * `event_hash = SHA-256( canonicalEventEncode(content) ‖ prevHash ‖ utf8(String(seq)) )`.
 * The new head of the chain.
 */
export function chainHash(input: {
    content: ChainedEventContent;
    prevHash: Uint8Array;
    seq: number;
}): Uint8Array {
    const h = createHash('sha256');
    h.update(canonicalEventEncode(input.content));
    h.update(input.prevHash);
    h.update(utf8Bytes(String(input.seq)));
    return h.digest();
}

/**
 * Signed-message schema versions (terminal seal).
 *
 * A checkpoint message is dispatched by the PRESENCE of `schema_version`:
 *   - absent  ⇒ V1 (the original checkpoint message, the 8 base fields only). A
 *     periodic checkpoint never sets it, so every already-signed checkpoint
 *     stays byte-identical and keeps verifying (`canonicalJson` drops undefined
 *     keys, so an absent field changes nothing).
 *   - `SEAL`  ⇒ V2, carrying the signed `terminal` descriptor. Emitted ONLY when
 *     a chain is terminally sealed, so "this chain was terminally sealed" is
 *     provable from the SIGNATURE offline, not from anything the producer stores.
 */
export const CHECKPOINT_SCHEMA_VERSION_SEAL = 2 as const;

/**
 * The signed terminal descriptor (present only on a terminal checkpoint):
 *   - `sealed`      → the chain is closed at `(seq, head_hash)`; no further append.
 *   - `empty_chain` → a positive "no events ever existed" statement (seq 0 / GENESIS).
 */
export interface TerminalDescriptor {
    readonly kind: 'sealed' | 'empty_chain';
}

/** GENESIS as the base64url head-hash string (the empty-chain head marker). */
export const GENESIS_B64: string = Buffer.from(GENESIS).toString('base64url');

/**
 * Terminality is a pure function of the sealed head: seq 0 / GENESIS ⇒ the chain
 * was empty. SINGLE-SOURCED here so the signer that bakes the kind into the
 * SIGNED message and any verifier that reconstructs it can never derive it
 * differently — a divergence would fail every genuine terminal seal.
 */
export function terminalKindForHead(seq: number, headHashB64: string): TerminalDescriptor['kind'] {
    return seq === 0 && headHashB64 === GENESIS_B64 ? 'empty_chain' : 'sealed';
}

/**
 * The fields a checkpoint signature covers. Hashes are carried as base64url
 * strings so the canonical message is plain JSON (no binary). Single-sourced
 * here so the checkpoint signer and `verifyChain` (this package) build the
 * identical signed message.
 *
 * `schema_version` / `terminal` are OPTIONAL: a periodic (V1) checkpoint omits
 * both — `buildCheckpointMessage` then produces the exact shipped bytes — while
 * a terminal (V2) checkpoint sets `schema_version = CHECKPOINT_SCHEMA_VERSION_SEAL`
 * and a `terminal` descriptor, both signature-covered.
 */
export interface CheckpointSignable {
    readonly tenant_name: string;
    readonly log_name: string;
    readonly seq: number;
    readonly head_hash_b64: string;
    readonly prev_checkpoint_hash_b64: string | null;
    readonly window_id: string;
    readonly signed_at: string;
    readonly kid: string;
    readonly schema_version?: number;
    readonly terminal?: TerminalDescriptor;
}

/** The canonical bytes that get Ed25519-signed for a checkpoint. */
export function buildCheckpointMessage(record: CheckpointSignable): Uint8Array {
    return utf8Bytes(canonicalJson(record));
}

/**
 * `checkpoint_hash` — links the checkpoint-chain (`prev_checkpoint_hash` of the
 * next checkpoint). Computed over the signed message so a dropped intermediate
 * checkpoint breaks the chain.
 */
export function checkpointHash(record: CheckpointSignable): Uint8Array {
    return createHash('sha256').update(buildCheckpointMessage(record)).digest();
}

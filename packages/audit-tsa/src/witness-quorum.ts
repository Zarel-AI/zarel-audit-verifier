// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Witness quorum + independence-floor evaluation.
 *
 * The non-equivocation HALF of the property: a self-operated log can prove
 * append-only completeness (the consistency proof), but a SINGLE GLOBAL VIEW needs
 * INDEPENDENT witnesses cosigning the checkpoint. This module verifies the
 * cosignatures over a checkpoint body against a DEPENDENCY-INJECTED named policy,
 * counts only DISTINCT policy-matching valid witnesses, and evaluates the
 * independence floor. Pure; fail-closed; reuses the cosignature primitive. The honest LABEL
 * (rendered in the CLI verifier) is gated on `floorMet`.
 */

import { cosignatureMessage } from './cosignature.js';
import { ed25519Verify } from './ed25519.js';

export interface WitnessVerifierEntry {
    readonly keyName: string;
    /** Raw 32-byte Ed25519 public key (the trusted, out-of-band policy identity). */
    readonly publicKey: Uint8Array;
    /** Operated by a party OTHER than the deployment operator (the floor's external leg). */
    readonly isExternal: boolean;
    /** ISO-style region/country tag; null ⇒ cannot satisfy the EU/EEA leg. */
    readonly jurisdiction: string | null;
}

export interface WitnessVerifierPolicy {
    readonly name: string;
    /** The expected checkpoint origin; the caller MUST reject a mismatch (fail-closed). */
    readonly origin: string;
    /** Named N-of-M quorum threshold. */
    readonly threshold: number;
    readonly witnesses: ReadonlyArray<WitnessVerifierEntry>;
}

/** A cosignature as carried by the evidence bundle (witness name + timestamp + 64-byte sig). */
export interface CheckpointCosignature {
    readonly keyName: string;
    readonly timestamp: bigint;
    readonly signature: Uint8Array;
}

export interface QuorumVerdict {
    /** Distinct policy witnesses with at least one cryptographically valid cosignature. */
    readonly matchedKeyNames: ReadonlyArray<string>;
    /** matched ≥ threshold. */
    readonly quorumMet: boolean;
    readonly externalCount: number;
    readonly euEeaCount: number;
    /** Independence floor: matched ≥ 3 ∧ external ≥ 1 ∧ EU/EEA ≥ 1. */
    readonly floorMet: boolean;
}

/** Independence floor: minimum reputational units that must cosign. */
export const D21_MIN_UNITS = 3;

/**
 * EU/EEA jurisdictions accepted for the floor's EU/EEA leg: ISO 3166-1 alpha-2 codes
 * for EU member states + EEA (IS/LI/NO), plus the explicit region labels EU/EEA.
 * Tags are matched case-insensitively (normalised to upper case).
 */
export const EU_EEA_REGIONS: ReadonlySet<string> = new Set([
    // EU member states
    'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU',
    'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE',
    // EEA (non-EU)
    'IS', 'LI', 'NO',
    // 'EL' is the code the EU itself uses for Greece (Eurostat) alongside ISO 'GR'
    'EL',
    // explicit region labels
    'EU', 'EEA',
]);

function isEuEea(jurisdiction: string | null): boolean {
    return jurisdiction !== null && EU_EEA_REGIONS.has(jurisdiction.toUpperCase());
}

/**
 * Evaluate the cosignatures over `checkpointBody` against `policy`. A cosignature
 * counts ONLY when its keyName matches a policy witness AND the Ed25519 signature
 * verifies under that witness's trusted public key over the timestamped message —
 * never on the cosignature's self-asserted identity. Distinct by policy witness, so
 * duplicates/replays collapse. The independence floor is computed over the matched set.
 */
export function evaluateWitnessQuorum(
    checkpointBody: string,
    cosignatures: ReadonlyArray<CheckpointCosignature>,
    policy: WitnessVerifierPolicy,
): QuorumVerdict {
    const byKeyName = new Map(policy.witnesses.map((w) => [w.keyName, w]));
    // Distinct by raw PUBLIC KEY, not keyName: the cosignature binds the body +
    // timestamp but NOT the keyName, so a single physical key listed under several
    // policy keyNames could otherwise fill several "independent units". One
    // physical key = at most one reputational unit.
    const matchedPubkeys = new Set<string>();
    const matchedEntries: WitnessVerifierEntry[] = [];

    for (const cosig of cosignatures) {
        const witness = byKeyName.get(cosig.keyName);
        if (witness === undefined) {
            continue; // not in policy
        }
        const pkHex = Buffer.from(witness.publicKey).toString('hex');
        if (matchedPubkeys.has(pkHex)) {
            continue; // this physical key already counted (duplicate / replay / alias)
        }
        if (cosig.signature.length !== 64) {
            continue; // malformed → fail-closed
        }
        const message = cosignatureMessage(checkpointBody, cosig.timestamp);
        if (ed25519Verify(message, cosig.signature, witness.publicKey)) {
            matchedPubkeys.add(pkHex);
            matchedEntries.push(witness);
        }
    }

    const externalCount = matchedEntries.filter((w) => w.isExternal).length;
    const euEeaCount = matchedEntries.filter((w) => isEuEea(w.jurisdiction)).length;
    const quorumMet = matchedEntries.length >= policy.threshold;
    const floorMet = matchedEntries.length >= D21_MIN_UNITS && externalCount >= 1 && euEeaCount >= 1;

    return {
        matchedKeyNames: matchedEntries.map((w) => w.keyName),
        quorumMet,
        externalCount,
        euEeaCount,
        floorMet,
    };
}

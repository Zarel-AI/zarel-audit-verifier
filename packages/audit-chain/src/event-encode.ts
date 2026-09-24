// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Canonical event content encoder.
 *
 * Encodes the application-authored, immutable fields of an event into a
 * deterministic, language-neutral byte sequence. The rule is simple and
 * divergence-proof: the hash covers EXACTLY the fields the application itself
 * supplies when it writes the event. Every field the storage layer stamps on its
 * own is EXCLUDED — `id` (random), `created_*`/`updated_*`/`deleted_*` (stamped at
 * write time, so the application cannot know them before hashing), and
 * `trace_id`/`parent_trace_id` (taken from the request's tracing context, not from
 * the event). The chain still binds every domain-semantic field + the
 * `seq`/`prev_hash` ordering — soft-delete leaves the chain verifiable while the
 * verifier flags the soft-deleted event as an anomaly separately.
 *
 * `canonicalJson` recursively sorts every key (including inside the nested JSON
 * sub-values `payload` / `rule_evaluations`), so the byte output is
 * order-independent of how the object was constructed — the write-path and the
 * offline verifier produce identical bytes for the same logical content.
 */

import { canonicalJson, utf8Bytes } from './canonical-json.js';

/**
 * The immutable content of a chained event. Events come from one of two logs:
 * `state_machine` (a record moving between states) populates the transition
 * fields; `flows` (the steps of a multi-step flow) populates the flow fields. Absent
 * fields are simply omitted (never serialized) so each log has a stable shape.
 */
export interface ChainedEventContent {
    readonly tenant_name: string;
    readonly instance_id: string;
    // state_machine log
    readonly field_name?: string | null;
    readonly from_state?: string | null;
    readonly to_state?: string | null;
    // flows log
    readonly event_type?: string | null;
    readonly step_name?: string | null;
    readonly output_key?: string | null;
    readonly duration_ms?: number | null;
    /**
     * Which run of the flow instance wrote the event. Hashed like every other application-set
     * field: readers scope a compliance verdict by it, so it has to be as tamper-evident as the
     * step name it qualifies.
     */
    readonly attempt?: number | null;
    // common (state_machine only sets actor/actor_role)
    readonly actor?: string | null;
    readonly actor_role?: string | null;
    readonly payload?: unknown;
    readonly policy_version?: string | null;
    readonly rule_evaluations?: unknown;
    // EXCLUDED (stamped by the storage layer): id, created_*, updated_*, deleted_*,
    // trace_id, parent_trace_id. See the module doc.
}

/** Drop keys whose value is `undefined` (an absent field) while preserving explicit `null`. */
function definedOnly(content: ChainedEventContent): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(content)) {
        if (value !== undefined) {
            out[key] = value;
        }
    }
    return out;
}

export function canonicalEventEncode(content: ChainedEventContent): Uint8Array {
    return utf8Bytes(canonicalJson(definedOnly(content)));
}

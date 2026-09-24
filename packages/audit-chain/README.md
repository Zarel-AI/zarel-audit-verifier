# @zarel-ai/audit-chain

**Offline, dependency-free verifier for Zarel audit tamper-evidence.**

Zarel emits a cryptographic, append-only audit chain: every event is hash-linked
to its predecessor, and the chain head is periodically sealed into a signed
checkpoint. This package is the **independent verifier** for that
chain. It is pure `node:crypto` — **zero runtime dependencies** — so you can read
exactly what it checks and run it anywhere, without trusting Zarel.

> What it proves: the event log was **not altered, reordered, dropped, or
> soft-deleted** between checkpoints, and the checkpoints were signed by a key you
> trust. What it does *not* prove: the *content* of an event is true, or that the
> log is *complete*. Tamper-**evidence**, not tamper-prevention.

## Install

```bash
npm install @zarel-ai/audit-chain
```

Ships dual ESM + CommonJS with type declarations. Node ≥ 18.

```ts
import { verifyChain } from '@zarel-ai/audit-chain'; // ESM
// const { verifyChain } = require('@zarel-ai/audit-chain'); // CommonJS
```

## Verify a chain

`verifyChain` is synchronous and offline. You give it the events, the signed
checkpoints, and the **trust keys** you decided to trust (fetch them out-of-band
from the deployment's `/.well-known/zarel-trust-keys.json`, never from the bundle
itself). It returns a fail-closed verdict.

```ts
import { verifyChain, type TrustKey } from '@zarel-ai/audit-chain';

// Trust keys fetched out-of-band — NOT from the evidence bundle.
const keys: TrustKey[] = [
    { kid: 'deploy-2026', publicKeyB64: '<base64url raw 32-byte Ed25519 key>' },
];

const verdict = verifyChain({
    events,        // VerifierEventRow[]   — raw event rows from the bundle
    checkpoints,   // VerifierCheckpoint[] — signed checkpoints from the bundle
    keys,
});

if (verdict.ok) {
    console.log(
        `✓ chain intact for seq ${verdict.coveredRange?.from}..${verdict.coveredRange?.to}`,
        `(${verdict.checkpointsVerified} checkpoints, signed by ${verdict.keyKid})`,
    );
} else {
    for (const f of verdict.failures) {
        console.error(`✗ seq ${f.seq}: ${f.reason}`);
    }
    process.exitCode = 1;
}
```

A failure `reason` is one of `event_hash_mismatch`, `prev_hash_mismatch`,
`seq_gap`, `seq_duplicate`, `soft_deleted_event`, `checkpoint_chain_broken`,
`checkpoint_signature_invalid`, `checkpoint_anchor_mismatch`, `unknown_kid`,
`kid_not_yet_valid`, `kid_expired`, `kid_revoked`, or `no_verified_checkpoint` —
each names exactly what broke. `no_verified_checkpoint` is reported at `seq: -1`:
a chain with no signature-verified checkpoint is self-consistent at best, never
authentic, so it never verifies.

## Beyond the chain

To additionally check that a chain was **anchored to an independent RFC 3161
timestamp authority** (proving it existed before a third-party-attested time), pair
this with [`@zarel-ai/audit-tsa`](https://www.npmjs.com/package/@zarel-ai/audit-tsa).
The `zarel` CLI (`zarel verify`) wraps both for whole-bundle verification.

## License

Apache-2.0 © 2026 Nicolas Moreno. See [LICENSE](LICENSE).

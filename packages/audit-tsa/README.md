# @zarel-ai/audit-tsa

**Offline RFC 3161 timestamp-token verifier + Merkle inclusion proofs** for
Zarel's external audit anchoring.

Zarel anchors each window of audit checkpoints to an **independent RFC 3161
Timestamp Authority (TSA)**: it builds a Merkle tree over the window's checkpoints
and gets the TSA to sign a timestamp token over the root. A third-party-attested
`genTime` then replaces the operator's self-asserted clock. This package verifies
those tokens and the per-checkpoint inclusion proofs, **synchronously and
offline**.

> What it proves: a specific hash (the Merkle root) **existed before the TSA's
> attested `genTime`**, witnessed by a third party — i.e. anti-backdating. What it
> does *not* prove: content veracity, completeness, or non-equivocation.
> `verifyTimestampToken` does **structural** validation (token + the chain embedded
> via `certReq=true`) and does **not** check revocation (CRL/OCSP), so a single
> token is not "valid for years" on its own. Long-term validity and revocation are
> checked by `verifyEvidenceRecord`, over an RFC 4998 evidence record that carries
> the renewal timestamps and the captured CRL/OCSP responses. Pair it with [`@zarel-ai/audit-chain`](https://www.npmjs.com/package/@zarel-ai/audit-chain)
> for chain integrity.

## Install

```bash
npm install @zarel-ai/audit-tsa
```

Dual ESM + CommonJS with type declarations. Node ≥ 18. The only runtime
dependencies are the ASN.1/CMS parsers (`asn1js`, `pkijs`) — `node:crypto` has the
signature primitives but not a CMS envelope parser.

## Verify a timestamp token

`verifyTimestampToken` is offline and fail-closed. It takes the DER token, the
Merkle root **you recomputed** from the bundle, and an **explicit set of pinned TSA
root certificates** — never the OS trust store, never the bundle itself (the bundle
cannot be its own trust anchor).

```ts
import { verifyTimestampToken } from '@zarel-ai/audit-tsa';

const verdict = verifyTimestampToken({
    token,         // Uint8Array — DER TimeStampToken from the bundle
    expectedRoot,  // Uint8Array — the Merkle root you recomputed yourself
    pinnedRoots,   // Uint8Array[] — TSA root certs (DER) you trust, supplied out-of-band
});

if (verdict.ok) {
    console.log(`✓ root attested at ${verdict.genTime}`);
} else {
    console.error(`✗ token verification failed: ${verdict.failure}`);
    process.exitCode = 1;
}
```

`failure` names the first failing check: `no_pinned_root`, `malformed_token`,
`cms_signature`, `chain_to_pinned_root`, `eku_timestamping`,
`gentime_outside_validity`, or `imprint_mismatch`.

## Verify a checkpoint's inclusion in the anchored root

Each checkpoint ships a Merkle **inclusion path** (sibling hashes only — no other
checkpoint's content). Recompute the root from the leaf and confirm it equals the
anchored root before trusting the token over it.

```ts
import { verifyInclusion } from '@zarel-ai/audit-tsa';

const included = verifyInclusion(
    leaf,   // Uint8Array — this checkpoint's hash
    path,   // InclusionPath — sibling hashes + side ('L' | 'R')
    root,   // Uint8Array — the anchored Merkle root
);
```

## License

Apache-2.0 © 2026 Nicolas Moreno. See [LICENSE](LICENSE).

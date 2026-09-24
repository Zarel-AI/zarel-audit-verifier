# zarel-audit-verifier

Offline verifiers for Zarel's audit evidence. They let you check an evidence bundle
yourself, with code you can read, instead of trusting the system that produced it.

| package | what it verifies |
|---|---|
| [`@zarel-ai/audit-chain`](packages/audit-chain) | The hash chain and its signed checkpoints: no event was altered, reordered, dropped or soft-deleted between checkpoints, and each checkpoint was signed by a key you trust. `node:crypto` only, with zero runtime dependencies. |
| [`@zarel-ai/audit-tsa`](packages/audit-tsa) | External anchoring: RFC 3161 timestamp tokens against TSA roots you pin, Merkle inclusion proofs, RFC 4998 evidence records with renewal and revocation, and C2SP transparency-log checkpoints with witness cosignatures. |

Each package's README shows how to use it. The two are independent, so you can install either
one on its own.

## Building and testing

Each package builds and tests on its own, on Node 18 or later:

```bash
cd packages/audit-chain   # or packages/audit-tsa
npm install
npm test
npm run build
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every commit needs a `Signed-off-by:` line, under the
[Developer Certificate of Origin](DCO).

## License

Apache-2.0 © 2026 Nicolas Moreno. See [LICENSE](LICENSE).


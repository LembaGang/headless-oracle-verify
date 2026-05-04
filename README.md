# @headlessoracle/verify

Verify cryptographically signed market-state receipts from [Headless Oracle](https://headlessoracle.com).

**Zero production dependencies.** Uses the Web Crypto API built into Node.js 18+, Cloudflare Workers, and all modern browsers.

## Install

```bash
npm install @headlessoracle/verify
```

## Quickstart

```javascript
import { verify } from '@headlessoracle/verify';

// Fetch a receipt from the Oracle
const receipt = await fetch('https://api.headlessoracle.com/v5/demo?mic=XNYS')
  .then(r => r.json());

// Verify the Ed25519 signature and TTL
const { valid, reason } = await verify(receipt);
if (!valid) {
  console.error('Invalid receipt:', reason); // 'EXPIRED', 'INVALID_SIGNATURE', etc.
  halt();
}

// Check market status — HALTED and UNKNOWN must be treated as CLOSED
if (receipt.status !== 'OPEN') halt();
```

Three lines. No configuration required.

## API

### `verify(receipt, options?)`

Returns `Promise<{ valid: boolean; reason?: VerifyFailureReason }>`.

```typescript
// Fetch public key automatically (one network call per verification)
await verify(receipt);

// Pass public key directly — no network call
await verify(receipt, { publicKey: '03dc2799...' });

// Override current time in tests
await verify(receipt, { publicKey: '03dc2799...', now: new Date('2026-03-01') });
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `publicKey` | `string` | — | Ed25519 public key (64-char hex). Skips key registry fetch. |
| `canonicalFields` | `string[]` | — | Skip `/v5/keys` fetch entirely by passing the canonical signed-payload field allowlist directly. Tests and offline-only environments only. |
| `keysUrl` | `string` | `https://headlessoracle.com/v5/keys` | Endpoint to fetch keys + `canonical_payload_spec` from. Custom URLs MUST return both. |
| `now` | `Date` | `new Date()` | Current time override. Useful in tests. |

**Failure reasons:**

| Reason | Meaning |
|--------|---------|
| `MISSING_FIELDS` | Receipt is missing `signature`, `public_key_id`, `expires_at`, or `issued_at`. |
| `EXPIRED` | `expires_at` has passed. Fetch a fresh receipt before acting. |
| `UNKNOWN_KEY` | `public_key_id` not in the key registry. Key may have rotated. |
| `INVALID_SIGNATURE` | Ed25519 signature does not match. Receipt may have been tampered with. |
| `KEY_FETCH_FAILED` | Network error fetching the key registry / canonical spec. |
| `INVALID_KEY_FORMAT` | Public key or signature is not valid hex. |
| `SPEC_UNAVAILABLE` | `/v5/keys` returned no `canonical_payload_spec`. The verifier refuses to guess. |

## Receipt TTL

Oracle receipts expire **60 seconds** after `issued_at`. `verify` rejects any receipt where `expires_at ≤ now`. Always fetch a fresh receipt before acting — never reuse a cached receipt.

## Status semantics

After successful verification, check `receipt.status`:

| Status | Meaning | Action |
|--------|---------|--------|
| `OPEN` | Market is open for trading | Proceed |
| `CLOSED` | Market is closed | Do not trade |
| `HALTED` | Circuit breaker active | Halt execution |
| `UNKNOWN` | Oracle safe-state | **Halt all execution** |

`UNKNOWN` means the Oracle cannot determine market state. Always treat it as `CLOSED`.

## Caching the public key

For high-throughput use, fetch the public key once and pass it on every call:

```javascript
// At startup — fetch once. /v5/keys carries both the public keys and the
// canonical_payload_spec the SDK needs to reconstruct the signed message.
const { keys, canonical_payload_spec } = await fetch('https://headlessoracle.com/v5/keys')
  .then(r => r.json());
const publicKey = keys[0].public_key;
const canonicalFields = Array.from(new Set([
  ...(canonical_payload_spec.receipt_fields  ?? []),
  ...(canonical_payload_spec.override_fields ?? []),
  ...(canonical_payload_spec.health_fields   ?? []),
]));

// On every receipt — no network call
const { valid } = await verify(receipt, { publicKey, canonicalFields });
```

## Authenticated receipts

The `/v5/demo` endpoint is public. For production use, `/v5/status` requires an API key and returns the same signed receipt format — `verify` works identically for both:

```javascript
const receipt = await fetch('https://api.headlessoracle.com/v5/status?mic=XNYS', {
  headers: { 'X-Oracle-Key': process.env.ORACLE_API_KEY },
}).then(r => r.json());

const { valid } = await verify(receipt, { publicKey });
```

## Batch receipts

`/v5/batch` returns an array of independently signed receipts. Verify each one individually:

```javascript
const { receipts } = await fetch('https://api.headlessoracle.com/v5/batch?mics=XNYS,XLON', {
  headers: { 'X-Oracle-Key': process.env.ORACLE_API_KEY },
}).then(r => r.json());

for (const receipt of receipts) {
  const { valid } = await verify(receipt, { publicKey });
  if (!valid || receipt.status !== 'OPEN') halt(receipt.mic);
}
```

## Verification spec

Receipts are signed with **Ed25519**. The canonical payload is the receipt filtered to the field allowlist published at [/v5/keys → canonical_payload_spec](https://headlessoracle.com/v5/keys), keys sorted alphabetically, `JSON.stringify`'d with no whitespace, UTF-8 encoded. The worker decorates `/v5/demo` and `/v5/status` responses with non-signed metadata (`receipt`, `discovery_url`, `extensions.bazaar`); the SDK filters these out before reconstructing the message bytes.

## Runtime requirements

- **Node.js** 18+ (`crypto.subtle` with Ed25519)
- **Cloudflare Workers** — supported
- **Browsers** — Chrome 113+, Firefox 126+, Safari 17+

## License

MIT

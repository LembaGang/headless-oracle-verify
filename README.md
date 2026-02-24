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
| `keysUrl` | `string` | `https://api.headlessoracle.com/.well-known/oracle-keys.json` | Key registry URL. |
| `now` | `Date` | `new Date()` | Current time override. Useful in tests. |

**Failure reasons:**

| Reason | Meaning |
|--------|---------|
| `MISSING_FIELDS` | Receipt is missing `signature`, `public_key_id`, `expires_at`, or `issued_at`. |
| `EXPIRED` | `expires_at` has passed. Fetch a fresh receipt before acting. |
| `UNKNOWN_KEY` | `public_key_id` not in the key registry. Key may have rotated. |
| `INVALID_SIGNATURE` | Ed25519 signature does not match. Receipt may have been tampered with. |
| `KEY_FETCH_FAILED` | Network error fetching the key registry. |
| `INVALID_KEY_FORMAT` | Public key or signature is not valid hex. |

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
// At startup — fetch once
const { keys } = await fetch('https://api.headlessoracle.com/.well-known/oracle-keys.json')
  .then(r => r.json());
const publicKey = keys[0].public_key;

// On every receipt — no network call
const { valid } = await verify(receipt, { publicKey });
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

Receipts are signed with **Ed25519**. The canonical payload is all receipt fields except `signature`, keys sorted alphabetically, `JSON.stringify`'d with no whitespace, UTF-8 encoded. The field list for each receipt type is published at [/v5/keys → canonical_payload_spec](https://api.headlessoracle.com/v5/keys).

## Runtime requirements

- **Node.js** 18+ (`crypto.subtle` with Ed25519)
- **Cloudflare Workers** — supported
- **Browsers** — Chrome 113+, Firefox 126+, Safari 17+

## License

MIT

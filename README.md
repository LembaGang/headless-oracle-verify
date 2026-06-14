# @headlessoracle/verify

Fail-closed pre-trade guard + Ed25519 verifier for signed market-state attestations from [Headless Oracle](https://headlessoracle.com).

**Zero production dependencies.** Uses the Web Crypto API built into Node.js 18+, Cloudflare Workers, and all modern browsers.

The headline export is [`safeToExecute(mic, opts)`](#safetoexecutemic-opts) — the drop-in guard that lets an autonomous agent answer "is the market open?" with a single call. It fetches a signed attestation from the free `/v1/status` endpoint, enforces the relying party's freshness policy, verifies the Ed25519 signature against HO's published public key, and returns `safe: false` on every fail-closed branch. The lower-level [`verify(receipt, options?)`](#verifyreceipt-options) primitive is kept for callers that fetch receipts themselves.

## Install

```bash
npm install @headlessoracle/verify
```

## Quickstart — the fail-closed guard

```javascript
import { safeToExecute } from '@headlessoracle/verify';

const { safe, reason, receipt } = await safeToExecute('XNYS', {
  max_attestation_age: 30,   // seconds — YOUR freshness policy. No default. Required.
});

// Log the artifact whichever way the decision went — receipt IS the audit trail.
logEvent({ kind: 'pretrade-gate', safe, reason, receipt });

if (!safe) return;           // fail-closed: do nothing
await placeOrder(/* ... */);
```

That's it. The guard hits `https://headlessoracle.com/v1/status/XNYS` (free, unauthenticated, signed), reconstructs the canonical bytes, verifies the Ed25519 signature against HO's published key, enforces your `max_attestation_age` policy, and refuses unless the venue reports `OPEN`. Any failure mode — network unreachable, stale receipt, bad signature, wrong MIC, status `CLOSED` / `HALTED` / `UNKNOWN` — returns `safe: false` with a machine-readable `reason`.

## What the receipt is, and isn't

* **What it is.** A cryptographically signed attestation of the venue's session-state as **observed by HO** at `issued_at`. Verifiable offline against the published Ed25519 key. The bytes that justified your decision — log them, replay them, prove them later. That artifact IS the audit trail.
* **What it isn't.** Ground truth. The receipt attests HO's observation at a specific instant, not the venue's state at action-time. Freshness is enforced by **the relying party** at action-time via `max_attestation_age`, not by HO. A receipt with `status: OPEN` at `issued_at = T` does not promise the market is open at `T+Δ`.
* **Per-symbol vs per-venue.** Status is at the MIC level (`XNYS`, `XLON`, …). Single-name halts (T1, T2, LULD pauses) do not flip a whole-venue status. For per-symbol detail, see the [halt archive](https://headlessoracle.com/halt-gate#further-reading).
* **Trust model.** This SDK trusts exactly one thing: HO's signing key, fetched from `/v5/keys` (or supplied via `opts.publicKey`). A response advertising a different `public_key_id` is rejected as `UNKNOWN_KEY` unless that key is in the registry. The SDK does not trust the receipt to vouch for its own provenance.

## API

### `safeToExecute(mic, opts)`

The fail-closed drop-in guard. Returns `Promise<SafeToExecuteResult>`.

```typescript
interface SafeToExecuteResult {
  safe: boolean;                          // true only on fresh + valid + correct MIC + OPEN
  reason?: SafeToExecuteReason;           // machine-readable, present when safe === false
  status?: string;                        // receipt.status — absent if no receipt was retrieved
  receipt?: Record<string, unknown>;      // the audit artifact — present whenever a receipt was retrieved
}
```

The receipt is included on **every** failure branch where one was retrieved. Log it whichever way the decision goes. That artifact is your audit trail.

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_attestation_age` | `number` | **none — required** | Maximum age, in seconds, between the receipt's `issued_at` and the caller's `now`. **Throws** if missing, 0, negative, NaN, or Infinity. No default is intentional: the IETF [`environment.*` constraint family](https://datatracker.ietf.org/doc/draft-borthwick-msebenzi-environment-state/) requires the relying party to declare its own freshness policy. |
| `endpoint` | `string` | `https://headlessoracle.com/v1/status` | Base URL of the free signed-status endpoint. The MIC is appended. |
| `publicKey` | `string` | — | Ed25519 public key (64-char hex). When supplied, the SDK skips the `/v5/keys` key-registry fetch. |
| `canonicalFields` | `string[]` | — | When supplied, the SDK skips the `canonical_payload_spec` fetch entirely. Tests and offline-only environments only. |
| `keysUrl` | `string` | `https://headlessoracle.com/v5/keys` | Override the key-registry URL. |
| `now` | `Date` | `new Date()` | Override the clock. Useful in tests. |

**Failure reasons** — match on this enum, do not parse free text:

| Reason | Meaning |
|--------|---------|
| `NETWORK_ERROR` | `fetch` to `/v1/status` threw — network or DNS failure. |
| `BAD_RESPONSE` | Non-2xx status or unparseable JSON body. |
| `MISSING_FIELDS` | Receipt missing `signature`, `public_key_id`, `issued_at`, or `expires_at`. |
| `STALE_RECEIPT` | `(now − issued_at) > max_attestation_age`. Your freshness policy refused it. |
| `EXPIRED` | Receipt's own `expires_at` has passed (HO's 60-s TTL). |
| `INVALID_SIGNATURE` | Ed25519 signature does not match the canonical payload. |
| `INVALID_KEY_FORMAT` | Public key or signature is not valid hex — Web Crypto rejected the bytes. |
| `UNKNOWN_KEY` | `public_key_id` not in HO's published key registry. |
| `KEY_FETCH_FAILED` | `/v5/keys` request failed. |
| `SPEC_UNAVAILABLE` | `/v5/keys` returned no `canonical_payload_spec` — cannot determine the signed-field allowlist. The verifier refuses to guess. |
| `WRONG_MIC` | Receipt MIC does not match what you asked for (proxy / CDN misroute). |
| `NOT_OPEN` | Venue status is `CLOSED`, `HALTED`, or `UNKNOWN`. UNKNOWN is treated as CLOSED — the fail-closed contract. |

**Throws** — only one case, always a caller bug: `opts.max_attestation_age` is missing or not a finite positive number.

### `verify(receipt, options?)`

The lower-level primitive. Use this when you fetch the receipt yourself (e.g. authenticated `/v5/status`, batch `/v5/batch`, or a receipt received over a webhook / message bus).

Returns `Promise<{ valid: boolean; reason?: VerifyFailureReason }>`.

```typescript
import { verify } from '@headlessoracle/verify';

// 1. Fetch the receipt however you fetch it.
const receipt = await fetch('https://headlessoracle.com/v5/status?mic=XNYS', {
  headers: { 'X-Oracle-Key': process.env.ORACLE_API_KEY },
}).then(r => r.json());

// 2. Verify Ed25519 signature + TTL.
const { valid, reason } = await verify(receipt);
if (!valid) return halt(reason);

// 3. Check status yourself. HALTED / UNKNOWN must be treated as CLOSED.
if (receipt.status !== 'OPEN') return halt(receipt.status);
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `publicKey` | `string` | — | Ed25519 public key (64-char hex). Skips key-registry fetch. |
| `canonicalFields` | `string[]` | — | Canonical signed-payload field allowlist. Skips `/v5/keys` fetch entirely. Tests and offline-only environments only. |
| `keysUrl` | `string` | `https://headlessoracle.com/v5/keys` | Override the key-registry URL. |
| `now` | `Date` | `new Date()` | Clock override. |

**Failure reasons:**

| Reason | Meaning |
|--------|---------|
| `MISSING_FIELDS` | Receipt missing `signature`, `public_key_id`, `expires_at`, or `issued_at`. |
| `EXPIRED` | `expires_at` has passed. Fetch a fresh receipt before acting. |
| `INVALID_SIGNATURE` | Ed25519 signature does not match. Receipt may have been tampered. |
| `INVALID_KEY_FORMAT` | Public key or signature is not valid hex. |
| `UNKNOWN_KEY` | `public_key_id` not in the key registry. Key may have rotated. |
| `KEY_FETCH_FAILED` | Network error fetching the key registry / canonical spec. |
| `SPEC_UNAVAILABLE` | `/v5/keys` returned no `canonical_payload_spec`. The verifier refuses to guess. |

## Caching the public key

For high-throughput use, fetch the public key + canonical spec once and pass them on every call. Eliminates the per-verification `/v5/keys` round-trip.

```javascript
// At startup — fetch once.
const { keys, canonical_payload_spec } = await fetch('https://headlessoracle.com/v5/keys')
  .then(r => r.json());
const publicKey = keys[0].public_key;
const canonicalFields = Array.from(new Set([
  ...(canonical_payload_spec.receipt_fields  ?? []),
  ...(canonical_payload_spec.override_fields ?? []),
  ...(canonical_payload_spec.health_fields   ?? []),
]));

// On every call — no network call.
const result = await safeToExecute('XNYS', {
  max_attestation_age: 30,
  publicKey,
  canonicalFields,
});

// Or for verify():
const { valid } = await verify(receipt, { publicKey, canonicalFields });
```

`override_fields` is a superset of `receipt_fields` — it includes the `reason` field that appears on `HALTED` receipts driven by a manual override. The union of all three sets is the safe allowlist to pass to either `safeToExecute` or `verify`.

## Receipt TTL

HO receipts expire **60 seconds** after `issued_at`. Both `safeToExecute` and `verify` reject any receipt where `expires_at ≤ now`. Always fetch a fresh receipt before acting — never reuse a cached receipt.

`safeToExecute` additionally enforces **your** `max_attestation_age` policy, which should be tighter than HO's 60-s TTL for any action whose decision could meaningfully race a venue state change.

## Status semantics

After successful verification, check `receipt.status`:

| Status | Meaning | Action |
|--------|---------|--------|
| `OPEN` | Market is open for trading | Proceed |
| `CLOSED` | Market is closed | Do not trade |
| `HALTED` | Circuit breaker or operator override active | Do not trade |
| `UNKNOWN` | HO cannot determine the state — safe-state response | **Do not trade — UNKNOWN is treated as CLOSED, the fail-closed contract.** |

## Verification spec

Receipts are signed with **Ed25519**. The canonical signed payload is the receipt filtered to the field allowlist published at [`/v5/keys → canonical_payload_spec`](https://headlessoracle.com/v5/keys), keys sorted alphabetically, `JSON.stringify`'d with no whitespace, UTF-8 encoded. The Oracle decorates `/v1/status` and `/v5/status` responses with two non-signed wrapper fields (`receipt` — a flat-copy mirror, and `discovery_url` — a pointer to the MCP server card). The SDK ignores them automatically via the canonical-fields allowlist; you do not need to strip them yourself. Including either of them in the canonical bytes you verify against will produce `INVALID_SIGNATURE`.

## Endpoints worth knowing

* `GET https://headlessoracle.com/v1/status/{MIC}` — free, unauthenticated, rate-limited, signed. The endpoint `safeToExecute` uses by default. Returns the same authoritative signed receipt as the paid `/v5/status` — byte-equivalent canonical bytes for the same MIC at the same instant.
* `GET https://headlessoracle.com/v5/status?mic={MIC}` — authenticated (`X-Oracle-Key`). Use when you want per-key rate limits, usage analytics, or paid-tier guarantees.
* `GET https://headlessoracle.com/v5/batch?mics={MIC,MIC,…}` — authenticated. Returns independently signed receipts; verify each individually.
* `GET https://headlessoracle.com/v5/keys` — public key registry + `canonical_payload_spec`.
* `GET https://headlessoracle.com/halt-gate` — adoption-first walkthrough: curl → `safeToExecute()` → on-chain `HaltGuard.sol` reference.

## Runtime requirements

* **Node.js** 18+ (`crypto.subtle` with Ed25519)
* **Cloudflare Workers** — supported
* **Browsers** — Chrome 113+, Firefox 126+, Safari 17+

## License

MIT

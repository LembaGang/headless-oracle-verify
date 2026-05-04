/**
 * @headlessoracle/verify
 *
 * Verify cryptographically signed market-state receipts from Headless Oracle.
 * Zero production dependencies — uses the Web Crypto API (crypto.subtle).
 *
 * Requires: Node.js 18+, Cloudflare Workers, Chrome 113+, Firefox 126+, Safari 17+.
 */

// ── Types ─────────────────────────────────────────────────────────────────────

/** Machine-readable failure reason. Safe to switch/match on. */
export type VerifyFailureReason =
  | 'MISSING_FIELDS'    // receipt is missing signature, public_key_id, expires_at, or issued_at
  | 'EXPIRED'           // expires_at has passed — fetch a fresh receipt
  | 'UNKNOWN_KEY'       // public_key_id not found in the key registry
  | 'INVALID_SIGNATURE' // Ed25519 signature does not match the canonical payload
  | 'KEY_FETCH_FAILED'  // network error fetching the key registry / canonical spec
  | 'INVALID_KEY_FORMAT' // public key or signature is not valid hex
  | 'SPEC_UNAVAILABLE'; // /v5/keys returned no canonical_payload_spec

export interface VerifyResult {
  valid: boolean;
  reason?: VerifyFailureReason;
}

export interface VerifyOptions {
  /**
   * Ed25519 public key as a 64-character hex string.
   * When provided, skips the public-key registry lookup but DOES NOT
   * skip the canonical_payload_spec fetch unless `canonicalFields` is
   * also provided. Obtain from /v5/keys or /.well-known/oracle-keys.json.
   */
  publicKey?: string;

  /**
   * Explicit list of canonical signed-payload fields. When provided,
   * skips the /v5/keys fetch entirely. Use this in tests or when the
   * verifier is running in an offline environment with a known spec.
   * The list MUST match the union of receipt_fields, override_fields,
   * and health_fields published at /v5/keys → canonical_payload_spec.
   */
  canonicalFields?: string[];

  /**
   * URL to fetch keys + canonical_payload_spec from.
   * Default: https://headlessoracle.com/v5/keys
   *
   * The endpoint MUST return:
   *   { keys: [{ key_id, public_key, ... }, ...],
   *     canonical_payload_spec: { receipt_fields, override_fields, health_fields } }
   */
  keysUrl?: string;

  /**
   * Override the current time used for TTL checks.
   * Useful in tests. Default: new Date()
   */
  now?: Date;
}

interface KeysResponse {
  keys?: Array<{ key_id: string; public_key: string }>;
  canonical_payload_spec?: {
    receipt_fields?: string[];
    override_fields?: string[];
    health_fields?: string[];
  };
}

// ── Constants ─────────────────────────────────────────────────────────────────

const DEFAULT_KEYS_URL = 'https://headlessoracle.com/v5/keys';

// Module-level memoization keyed by keysUrl. Within one process, /v5/keys
// is fetched at most once per unique URL. Each new process starts fresh.
// Tests that need to drive different fetch responses should use different
// URLs (or call resetSpecCache() in afterEach).
const specCache = new Map<string, Promise<KeysResponse>>();

/**
 * Reset the in-process /v5/keys cache. Intended for test suites that
 * need to drive different mock responses across cases.
 */
export function resetSpecCache(): void {
  specCache.clear();
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Verify a signed receipt from Headless Oracle.
 *
 * Checks, in order:
 *   1. Required fields are present (signature, public_key_id, expires_at, issued_at)
 *   2. Receipt has not expired (expires_at > now)
 *   3. Canonical signed-payload field list (from /v5/keys → canonical_payload_spec
 *      unless `canonicalFields` is supplied)
 *   4. Public key (from /v5/keys → keys unless `publicKey` is supplied)
 *   5. Ed25519 signature matches the canonical payload built by filtering the
 *      receipt to the allowlist, sorting alphabetically, and JSON.stringify
 *      with no whitespace
 *
 * Endpoints like /v5/demo and /v5/status decorate the response with metadata
 * (`receipt` wrapper, `discovery_url`, `extensions.bazaar`) that is NOT
 * part of the signed bytes. The allowlist filter excludes them.
 *
 * @example
 * const receipt = await fetch('https://headlessoracle.com/v5/demo?mic=XNYS').then(r => r.json());
 * const { valid, reason } = await verify(receipt);
 * if (!valid || receipt.status !== 'OPEN') halt();
 */
export async function verify(
  receipt: Record<string, unknown>,
  options: VerifyOptions = {},
): Promise<VerifyResult> {

  // ── 1. Required fields ────────────────────────────────────────────────────
  if (
    typeof receipt.signature     !== 'string' ||
    typeof receipt.public_key_id !== 'string' ||
    typeof receipt.expires_at    !== 'string' ||
    typeof receipt.issued_at     !== 'string'
  ) {
    return { valid: false, reason: 'MISSING_FIELDS' };
  }

  // ── 2. TTL check — reject before any network call ─────────────────────────
  const now       = options.now ?? new Date();
  const expiresAt = new Date(receipt.expires_at);
  if (isNaN(expiresAt.getTime()) || expiresAt <= now) {
    return { valid: false, reason: 'EXPIRED' };
  }

  // ── 3. Determine whether we need to fetch /v5/keys ────────────────────────
  const needsSpecFetch = !options.canonicalFields;
  const needsKeyFetch  = !options.publicKey;
  const keysUrl        = options.keysUrl ?? DEFAULT_KEYS_URL;

  let fetched: KeysResponse | null = null;
  if (needsSpecFetch || needsKeyFetch) {
    try {
      fetched = await fetchKeys(keysUrl);
    } catch {
      return { valid: false, reason: 'KEY_FETCH_FAILED' };
    }
  }

  // ── 4. Resolve canonical field list ───────────────────────────────────────
  let canonicalFields: string[];
  if (options.canonicalFields) {
    canonicalFields = options.canonicalFields;
  } else {
    const spec = fetched?.canonical_payload_spec;
    const union = new Set<string>([
      ...(spec?.receipt_fields  ?? []),
      ...(spec?.override_fields ?? []),
      ...(spec?.health_fields   ?? []),
    ]);
    if (union.size === 0) return { valid: false, reason: 'SPEC_UNAVAILABLE' };
    canonicalFields = Array.from(union);
  }

  // ── 5. Resolve public key ─────────────────────────────────────────────────
  let publicKeyHex: string;
  if (options.publicKey) {
    publicKeyHex = options.publicKey;
  } else {
    const keys = fetched?.keys ?? [];
    const entry = keys.find((k) => k.key_id === receipt.public_key_id);
    if (!entry) return { valid: false, reason: 'UNKNOWN_KEY' };
    publicKeyHex = entry.public_key;
  }

  // ── 6. Build canonical payload from the allowlist ─────────────────────────
  // Only fields the worker actually signs go into the message bytes.
  // Keys sorted alphabetically, JSON.stringify with no whitespace.
  const sorted: Record<string, unknown> = {};
  for (const key of canonicalFields.slice().sort()) {
    if (key in receipt) sorted[key] = receipt[key];
  }
  const canonical = JSON.stringify(sorted);

  // ── 7. Ed25519 verification via Web Crypto ────────────────────────────────
  try {
    const pubKeyBytes = hexToBytes(publicKeyHex);
    const sigBytes    = hexToBytes(receipt.signature);
    const msgBytes    = new TextEncoder().encode(canonical);

    // Cast .buffer to ArrayBuffer — hexToBytes always allocates fresh Uint8Array
    // with byteOffset === 0, so this cast is always safe.
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      pubKeyBytes.buffer as ArrayBuffer,
      { name: 'Ed25519' } as AlgorithmIdentifier,
      false,
      ['verify'],
    );

    const ok = await crypto.subtle.verify(
      { name: 'Ed25519' } as AlgorithmIdentifier,
      cryptoKey,
      sigBytes.buffer as ArrayBuffer,
      msgBytes.buffer as ArrayBuffer,
    );

    return ok ? { valid: true } : { valid: false, reason: 'INVALID_SIGNATURE' };

  } catch {
    // importKey throws on bad key format; verify throws on bad sig bytes
    return { valid: false, reason: 'INVALID_KEY_FORMAT' };
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async function fetchKeys(url: string): Promise<KeysResponse> {
  const cached = specCache.get(url);
  if (cached) return cached;

  // Insert the in-flight promise so concurrent calls share one fetch.
  const promise = (async () => {
    const res  = await fetch(url);
    const data = await res.json() as KeysResponse;
    return data;
  })();

  specCache.set(url, promise);
  try {
    return await promise;
  } catch (err) {
    // Don't pin a failed fetch in the cache.
    specCache.delete(url);
    throw err;
  }
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Odd-length hex string');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

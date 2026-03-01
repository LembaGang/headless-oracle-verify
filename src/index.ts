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
  | 'KEY_FETCH_FAILED'  // network error fetching the key registry
  | 'INVALID_KEY_FORMAT'; // public key or signature is not valid hex

export interface VerifyResult {
  valid: boolean;
  reason?: VerifyFailureReason;
}

export interface VerifyOptions {
  /**
   * Ed25519 public key as a 64-character hex string.
   * When provided, skips the key registry network fetch.
   * Obtain from: https://headlessoracle.com/.well-known/oracle-keys.json
   */
  publicKey?: string;

  /**
   * Key registry URL to fetch the public key from.
   * Default: https://headlessoracle.com/.well-known/oracle-keys.json
   */
  keysUrl?: string;

  /**
   * Override the current time used for TTL checks.
   * Useful in tests. Default: new Date()
   */
  now?: Date;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const DEFAULT_KEYS_URL =
  'https://headlessoracle.com/.well-known/oracle-keys.json';

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Verify a signed receipt from Headless Oracle.
 *
 * Checks, in order:
 *   1. Required fields are present (signature, public_key_id, expires_at, issued_at)
 *   2. Receipt has not expired (expires_at > now)
 *   3. Ed25519 signature matches the canonical payload
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

  // ── 3. Resolve the public key ─────────────────────────────────────────────
  let publicKeyHex: string;

  if (options.publicKey) {
    publicKeyHex = options.publicKey;
  } else {
    const keysUrl = options.keysUrl ?? DEFAULT_KEYS_URL;
    let keys: Array<{ key_id: string; public_key: string }>;
    try {
      const res  = await fetch(keysUrl);
      const data = await res.json() as { keys: typeof keys };
      keys = data.keys;
    } catch {
      return { valid: false, reason: 'KEY_FETCH_FAILED' };
    }
    const entry = keys.find((k) => k.key_id === receipt.public_key_id);
    if (!entry) {
      return { valid: false, reason: 'UNKNOWN_KEY' };
    }
    publicKeyHex = entry.public_key;
  }

  // ── 4. Reconstruct canonical payload ──────────────────────────────────────
  // All fields except `signature`, sorted alphabetically, JSON.stringify with no whitespace.
  // Must match the Oracle's signPayload() exactly. See /v5/keys → canonical_payload_spec.
  const { signature, ...payloadFields } = receipt;
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(payloadFields).sort()) {
    sorted[key] = payloadFields[key];
  }
  const canonical = JSON.stringify(sorted);

  // ── 5. Ed25519 verification via Web Crypto ────────────────────────────────
  try {
    const pubKeyBytes = hexToBytes(publicKeyHex);
    const sigBytes    = hexToBytes(signature);
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

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Odd-length hex string');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

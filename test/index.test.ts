import { describe, it, expect, vi, afterEach } from 'vitest';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { verify, resetSpecCache } from '../src/index.js';

// Configure noble sha512 for test key generation and signing
ed.hashes.sha512 = sha512;

// ── Helpers ───────────────────────────────────────────────────────────────────

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

async function makeKeypair() {
  const privBytes = new Uint8Array(32);
  crypto.getRandomValues(privBytes);
  const pub = await ed.getPublicKeyAsync(privBytes);
  return { priv: toHex(privBytes), pub: toHex(pub) };
}

/**
 * The canonical field allowlist used in unit tests. Matches the union
 * of receipt_fields, override_fields, and health_fields published by
 * the live worker at /v5/keys → canonical_payload_spec. Passing this
 * via VerifyOptions.canonicalFields lets unit tests exercise the
 * cryptographic path without mocking /v5/keys.
 */
const TEST_CANONICAL_FIELDS = [
  'expires_at', 'halt_detection', 'issued_at', 'issuer', 'mic',
  'public_key_id', 'reason', 'receipt_id', 'receipt_mode',
  'schema_version', 'source', 'status',
];

/**
 * Sign a payload exactly as the Oracle server does:
 * sort keys alphabetically, JSON.stringify, sign with Ed25519.
 */
async function oracleSign(
  payload: Record<string, string>,
  privHex: string,
): Promise<string> {
  const sorted: Record<string, string> = {};
  for (const key of Object.keys(payload).sort()) sorted[key] = payload[key];
  const msg = new TextEncoder().encode(JSON.stringify(sorted));
  const sig = await ed.sign(msg, fromHex(privHex));
  return toHex(sig);
}

const FUTURE = new Date(Date.now() + 120_000).toISOString(); // 2 min from now
const PAST   = new Date(Date.now() -   1_000).toISOString(); // 1 sec ago

/**
 * Build a realistic Oracle receipt, signed with a fresh keypair.
 * Use `fieldOverrides` to test specific field variations.
 */
async function makeReceipt(
  fieldOverrides: Partial<Record<string, string>> = {},
  keypair?: Awaited<ReturnType<typeof makeKeypair>>,
) {
  const kp = keypair ?? await makeKeypair();
  const payload: Record<string, string> = {
    receipt_id:     'test-receipt-00000001',
    issued_at:      new Date().toISOString(),
    expires_at:     FUTURE,
    mic:            'XNYS',
    status:         'CLOSED',
    source:         'SCHEDULE',
    schema_version: 'v5.0',
    public_key_id:  'test_key_v1',
    ...fieldOverrides,
  };
  const signature = await oracleSign(payload, kp.priv);
  return { receipt: { ...payload, signature }, kp };
}

afterEach(() => {
  vi.restoreAllMocks();
  resetSpecCache();
});

// ── Valid receipts ─────────────────────────────────────────────────────────────

describe('verify() — valid receipts', () => {
  it('returns { valid: true } for a correctly signed SCHEDULE receipt', async () => {
    const { receipt, kp } = await makeReceipt();
    const result = await verify(receipt, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it('returns { valid: true } for an OVERRIDE receipt containing a reason field', async () => {
    // reason field changes the canonical payload — verifier must include it
    const { receipt, kp } = await makeReceipt({
      status: 'HALTED',
      source: 'OVERRIDE',
      reason: 'NYSE L1 circuit breaker',
    });
    const result = await verify(receipt, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(true);
  });

  it('returns { valid: true } for a health receipt (no mic, no schema_version)', async () => {
    // Health receipts have a reduced field set
    const kp = await makeKeypair();
    const payload: Record<string, string> = {
      receipt_id:    'health-uuid-00000001',
      issued_at:     new Date().toISOString(),
      expires_at:    FUTURE,
      status:        'OK',
      source:        'SYSTEM',
      public_key_id: 'test_key_v1',
    };
    const signature = await oracleSign(payload, kp.priv);
    const result = await verify({ ...payload, signature }, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(true);
  });

  it('handles a receipt with OPEN status correctly', async () => {
    const { receipt, kp } = await makeReceipt({ status: 'OPEN' });
    const result = await verify(receipt, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(true);
  });

  it('handles a receipt with UNKNOWN status correctly (fail-closed scenario)', async () => {
    const { receipt, kp } = await makeReceipt({ status: 'UNKNOWN', source: 'SYSTEM' });
    const result = await verify(receipt, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    // Signature is valid — it's a legitimate signed UNKNOWN receipt
    expect(result.valid).toBe(true);
  });
});

// ── Decoration handling ───────────────────────────────────────────────────────

describe('verify() — wrapper decoration', () => {
  it('ignores top-level decoration the worker adds after signing', async () => {
    // Real /v5/demo receipts include `receipt` (duplicate wrapper),
    // `discovery_url`, and `extensions.bazaar`. None of these are signed.
    // The verifier MUST exclude them from the canonical message bytes.
    const { receipt, kp } = await makeReceipt();
    const decorated = {
      ...receipt,
      receipt: { ...receipt },
      discovery_url: 'https://headlessoracle.com/.well-known/mcp/server-card.json',
      extensions: { bazaar: { discoverable: true, category: 'financial-data' } },
    };
    const result = await verify(decorated, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(true);
  });

  it('still detects tampering of signed fields when decoration is present', async () => {
    const { receipt, kp } = await makeReceipt({ status: 'CLOSED' });
    const tampered = {
      ...receipt,
      status: 'OPEN', // tamper a signed field
      receipt: { ...receipt },
      discovery_url: 'https://example.com',
      extensions: { foo: 'bar' },
    };
    const result = await verify(tampered, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });
});

// ── Expiry ────────────────────────────────────────────────────────────────────

describe('verify() — TTL / expiry', () => {
  it('returns EXPIRED when expires_at is in the past', async () => {
    const { receipt, kp } = await makeReceipt({ expires_at: PAST });
    const result = await verify(receipt, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('EXPIRED');
  });

  it('returns EXPIRED when now is passed beyond expires_at (time-travel test)', async () => {
    const { receipt, kp } = await makeReceipt();
    const futureNow = new Date(Date.now() + 200_000); // 200s from now, past 2-min expiry
    const result = await verify(receipt, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
      now: futureNow,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('EXPIRED');
  });

  it('rejects a receipt with an unparseable expires_at value', async () => {
    const { receipt, kp } = await makeReceipt();
    const tampered = { ...receipt, expires_at: 'not-a-date' };
    const result = await verify(tampered, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('EXPIRED');
  });

  it('checks expiry before hitting the network (no fetch when expired)', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const { receipt } = await makeReceipt({ expires_at: PAST });
    // No publicKey + no canonicalFields → would normally fetch, but expiry check fires first
    const result = await verify(receipt);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('EXPIRED');
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

// ── Signature tampering ───────────────────────────────────────────────────────

describe('verify() — signature failures', () => {
  it('returns INVALID_SIGNATURE when the signature hex is wrong', async () => {
    const { receipt, kp } = await makeReceipt();
    const tampered = { ...receipt, signature: 'a'.repeat(128) };
    const result = await verify(tampered, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  it('returns INVALID_SIGNATURE when a payload field is tampered after signing', async () => {
    const { receipt, kp } = await makeReceipt();
    // Attacker changes status from CLOSED to OPEN without re-signing
    const tampered = { ...receipt, status: 'OPEN' };
    const result = await verify(tampered, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  it('returns INVALID_SIGNATURE when mic is changed after signing', async () => {
    const { receipt, kp } = await makeReceipt({ mic: 'XNYS' });
    const tampered = { ...receipt, mic: 'XLON' };
    const result = await verify(tampered, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  it('returns INVALID_SIGNATURE when the wrong public key is used for verification', async () => {
    const { receipt } = await makeReceipt();
    const wrongKp = await makeKeypair();
    const result  = await verify(receipt, {
      publicKey: wrongKp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  it('rejects a receipt signed by a different keypair for a different MIC', async () => {
    const kp1 = await makeKeypair();
    const kp2 = await makeKeypair();
    // Sign with kp1, verify with kp2's public key
    const { receipt } = await makeReceipt({ mic: 'XNYS' }, kp1);
    const result = await verify(receipt, {
      publicKey: kp2.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });
});

// ── Missing fields ────────────────────────────────────────────────────────────

describe('verify() — missing fields', () => {
  it('returns MISSING_FIELDS when signature is absent', async () => {
    const { receipt, kp } = await makeReceipt();
    const { signature: _s, ...noSig } = receipt as Record<string, unknown>;
    const result = await verify(noSig, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('MISSING_FIELDS');
  });

  it('returns MISSING_FIELDS when expires_at is absent', async () => {
    const { receipt, kp } = await makeReceipt();
    const { expires_at: _ea, ...noExpiry } = receipt as Record<string, unknown>;
    const result = await verify(noExpiry, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('MISSING_FIELDS');
  });

  it('returns MISSING_FIELDS when public_key_id is absent', async () => {
    const { receipt, kp } = await makeReceipt();
    const { public_key_id: _pk, ...noKeyId } = receipt as Record<string, unknown>;
    const result = await verify(noKeyId, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('MISSING_FIELDS');
  });

  it('returns MISSING_FIELDS when issued_at is absent', async () => {
    const { receipt, kp } = await makeReceipt();
    const { issued_at: _ia, ...noIssuedAt } = receipt as Record<string, unknown>;
    const result = await verify(noIssuedAt, {
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('MISSING_FIELDS');
  });

  it('returns MISSING_FIELDS for an empty object', async () => {
    const result = await verify({});
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('MISSING_FIELDS');
  });
});

// ── Key format errors ─────────────────────────────────────────────────────────

describe('verify() — key format errors', () => {
  it('returns INVALID_KEY_FORMAT when publicKey is not valid hex', async () => {
    const { receipt } = await makeReceipt();
    const result = await verify(receipt, {
      publicKey: 'not-hex-at-all!!!!',
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.valid).toBe(false);
    // importKey will throw on a bad key — we map that to INVALID_KEY_FORMAT
    expect(['INVALID_KEY_FORMAT', 'INVALID_SIGNATURE']).toContain(result.reason);
  });
});

// ── Key registry / spec fetch ─────────────────────────────────────────────────

describe('verify() — /v5/keys fetch', () => {
  it('returns UNKNOWN_KEY when public_key_id is not in the registry response', async () => {
    const { receipt } = await makeReceipt({ public_key_id: 'rotated_old_key' });

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      json: async () => ({
        keys: [{ key_id: 'current_key_2026', public_key: 'deadbeef'.repeat(8) }],
        canonical_payload_spec: {
          receipt_fields:  TEST_CANONICAL_FIELDS,
          override_fields: TEST_CANONICAL_FIELDS,
          health_fields:   TEST_CANONICAL_FIELDS,
        },
      }),
    } as unknown as Response);

    const result = await verify(receipt); // no publicKey → triggers fetch
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('UNKNOWN_KEY');
  });

  it('returns KEY_FETCH_FAILED when fetch throws (network error)', async () => {
    const { receipt } = await makeReceipt();

    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('Network error'));

    const result = await verify(receipt);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('KEY_FETCH_FAILED');
  });

  it('returns SPEC_UNAVAILABLE when /v5/keys returns no canonical_payload_spec', async () => {
    const { receipt, kp } = await makeReceipt();

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      json: async () => ({
        keys: [{ key_id: 'test_key_v1', public_key: kp.pub }],
        // no canonical_payload_spec
      }),
    } as unknown as Response);

    const result = await verify(receipt);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('SPEC_UNAVAILABLE');
  });

  it('uses the key + spec from /v5/keys when public_key_id matches', async () => {
    const kp = await makeKeypair();
    const { receipt } = await makeReceipt({ public_key_id: 'live_key_v1' }, kp);

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      json: async () => ({
        keys: [{ key_id: 'live_key_v1', public_key: kp.pub }],
        canonical_payload_spec: {
          receipt_fields:  TEST_CANONICAL_FIELDS,
          override_fields: TEST_CANONICAL_FIELDS,
          health_fields:   TEST_CANONICAL_FIELDS,
        },
      }),
    } as unknown as Response);

    const result = await verify(receipt); // no publicKey → fetches and matches
    expect(result.valid).toBe(true);
  });

  it('uses custom keysUrl when provided', async () => {
    const { receipt, kp } = await makeReceipt({ public_key_id: 'staging_key' });

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      json: async () => ({
        keys: [{ key_id: 'staging_key', public_key: kp.pub }],
        canonical_payload_spec: {
          receipt_fields:  TEST_CANONICAL_FIELDS,
          override_fields: TEST_CANONICAL_FIELDS,
          health_fields:   TEST_CANONICAL_FIELDS,
        },
      }),
    } as unknown as Response);

    const result = await verify(receipt, {
      keysUrl: 'https://staging.headlessoracle.com/v5/keys',
    });

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://staging.headlessoracle.com/v5/keys',
    );
    expect(result.valid).toBe(true);
  });

  it('memoizes /v5/keys across verify() calls within a process', async () => {
    const kp = await makeKeypair();
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      json: async () => ({
        keys: [{ key_id: 'memo_key', public_key: kp.pub }],
        canonical_payload_spec: {
          receipt_fields:  TEST_CANONICAL_FIELDS,
          override_fields: TEST_CANONICAL_FIELDS,
          health_fields:   TEST_CANONICAL_FIELDS,
        },
      }),
    } as unknown as Response);

    const url = 'https://memo.example.com/v5/keys';
    const { receipt: r1 } = await makeReceipt({ public_key_id: 'memo_key' }, kp);
    const { receipt: r2 } = await makeReceipt({ public_key_id: 'memo_key' }, kp);

    const res1 = await verify(r1, { keysUrl: url });
    const res2 = await verify(r2, { keysUrl: url });

    expect(res1.valid).toBe(true);
    expect(res2.valid).toBe(true);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});

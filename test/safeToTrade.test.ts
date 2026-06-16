// ══════════════════════════════════════════════════════════════════════════
// safeToTrade — circuit-breaker SDK tests.
//
// Same test-discipline as safeToExecute: round-trip sign with noble + verify
// with Web Crypto, fail-closed on every documented failure mode.
//
// Critically: the receipt's `cross_venue` and `reasons` are JSON-encoded
// strings in the signed bytes (matching the /v5/batch precedent). The SDK
// JSON.parses them back AFTER signature verification and surfaces typed
// values on the result. Round-trip the signature with the JSON-as-string
// shape so any change to that encoding fails the test loudly.
// ══════════════════════════════════════════════════════════════════════════

import { describe, it, expect, vi, afterEach } from 'vitest';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { safeToTrade, verify, resetSpecCache } from '../src/index.js';

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

// Mirror the worker's safe_to_trade_fields entry at /v5/keys.
// If this list ever drifts from the worker's published spec, the
// round-trip will produce INVALID_SIGNATURE.
const SAFE_TO_TRADE_FIELDS = [
  'cross_venue', 'expires_at', 'instrument', 'issued_at', 'issuer',
  'max_age', 'public_key_id', 'reasons', 'receipt_id', 'receipt_mode',
  'safe', 'schema_version', 'venue', 'venue_source', 'venue_status',
];

async function oracleSign(payload: Record<string, string>, privHex: string): Promise<string> {
  const sorted: Record<string, string> = {};
  for (const key of Object.keys(payload).sort()) sorted[key] = payload[key];
  const msg = new TextEncoder().encode(JSON.stringify(sorted));
  const sig = await ed.sign(msg, fromHex(privHex));
  return toHex(sig);
}

interface MakeOpts {
  venue?:             string;
  venue_status?:      string;
  venue_source?:      string;
  safe?:              'true' | 'false';
  instrument?:        string;
  max_age?:           string;
  reasons?:           string[];
  cross_venue?:       { realtime_overrides: string[]; scan_ok: boolean };
  issuedAtOffsetSec?: number; // default 5 (fresh by 5s)
  ttlSec?:            number; // default 60
  keypair?:           Awaited<ReturnType<typeof makeKeypair>>;
  publicKeyId?:       string;
}

/** Build a /v1/safe-to-trade response body. */
async function makeSafeToTradeBody(opts: MakeOpts = {}) {
  const kp = opts.keypair ?? await makeKeypair();
  const now = new Date();
  const issuedAt = new Date(now.getTime() - 1000 * (opts.issuedAtOffsetSec ?? 5));
  const expiresAt = new Date(issuedAt.getTime() + 1000 * (opts.ttlSec ?? 60));

  const payload: Record<string, string> = {
    cross_venue:    JSON.stringify(opts.cross_venue ?? { realtime_overrides: [], scan_ok: true }),
    expires_at:     expiresAt.toISOString(),
    instrument:     opts.instrument ?? '',
    issued_at:      issuedAt.toISOString(),
    issuer:         'headlessoracle.com',
    max_age:        opts.max_age ?? '30',
    public_key_id:  opts.publicKeyId ?? 'test_key_v1',
    reasons:        JSON.stringify(opts.reasons ?? []),
    receipt_id:     'safe-to-trade-test-00000001',
    receipt_mode:   'live',
    safe:           opts.safe ?? 'true',
    schema_version: 'v5.0',
    venue:          opts.venue ?? 'XNYS',
    venue_source:   opts.venue_source ?? 'SCHEDULE',
    venue_status:   opts.venue_status ?? 'OPEN',
  };
  const signature = await oracleSign(payload, kp.priv);
  const receipt = { ...payload, signature };
  const body = { ...receipt, receipt, discovery_url: 'https://headlessoracle.com/.well-known/mcp/server-card.json' };
  return { body, kp, receipt };
}

function mockFetchOnce(body: unknown, status = 200) {
  return vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
    ok:     status >= 200 && status < 300,
    status,
    json:   async () => body,
  } as unknown as Response);
}

afterEach(() => {
  vi.restoreAllMocks();
  resetSpecCache();
});

// ══════════════════════════════════════════════════════════════════════════
// Caller-bug guard
// ══════════════════════════════════════════════════════════════════════════

describe('safeToTrade() — opts.max_attestation_age guard', () => {
  it('throws when opts is missing entirely', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await expect((safeToTrade as any)('XNYS')).rejects.toThrow(/max_attestation_age/);
  });

  it('throws when max_attestation_age is absent', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await expect(safeToTrade('XNYS', {} as any)).rejects.toThrow(/max_attestation_age/);
  });

  it('throws when max_attestation_age is zero or negative', async () => {
    await expect(safeToTrade('XNYS', { max_attestation_age: 0 })).rejects.toThrow();
    await expect(safeToTrade('XNYS', { max_attestation_age: -5 })).rejects.toThrow();
  });
});

// ══════════════════════════════════════════════════════════════════════════
// verify() works on the new receipt shape via canonical_payload_spec union
// ══════════════════════════════════════════════════════════════════════════

describe('verify() — supports safe_to_trade receipts via spec union', () => {
  it('returns valid:true for a correctly signed safe-to-trade receipt', async () => {
    const { receipt, kp } = await makeSafeToTradeBody();
    const result = await verify(receipt, {
      publicKey: kp.pub,
      canonicalFields: SAFE_TO_TRADE_FIELDS,
    });
    expect(result.valid).toBe(true);
  });

  it('returns INVALID_SIGNATURE when the cross_venue JSON string is tampered post-sign', async () => {
    const { receipt, kp } = await makeSafeToTradeBody();
    const tampered = { ...receipt, cross_venue: JSON.stringify({ realtime_overrides: ['XNAS'], scan_ok: true }) };
    const result = await verify(tampered, {
      publicKey: kp.pub,
      canonicalFields: SAFE_TO_TRADE_FIELDS,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  it('returns EXPIRED on a receipt past expires_at', async () => {
    const { receipt, kp } = await makeSafeToTradeBody({
      issuedAtOffsetSec: 120, ttlSec: 60, // expires_at = now - 60s
    });
    const result = await verify(receipt, {
      publicKey: kp.pub,
      canonicalFields: SAFE_TO_TRADE_FIELDS,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('EXPIRED');
  });

  it('fetches and unions safe_to_trade_fields from /v5/keys when not supplied', async () => {
    const { receipt, kp } = await makeSafeToTradeBody();
    // Mock /v5/keys returning a spec with ONLY safe_to_trade_fields populated
    mockFetchOnce({
      keys: [{ key_id: 'test_key_v1', public_key: kp.pub }],
      canonical_payload_spec: {
        receipt_fields:       [],
        override_fields:      [],
        health_fields:        [],
        safe_to_trade_fields: SAFE_TO_TRADE_FIELDS,
      },
    });
    const result = await verify(receipt); // No options — exercises the fetch path
    expect(result.valid).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// safeToTrade() — happy path
// ══════════════════════════════════════════════════════════════════════════

describe('safeToTrade() — happy path', () => {
  it('returns safe:true with parsed reasons + cross_venue when venue is OPEN', async () => {
    const { body, kp } = await makeSafeToTradeBody();
    mockFetchOnce(body);
    const result = await safeToTrade('XNYS', {
      max_attestation_age: 30,
      publicKey: kp.pub,
      canonicalFields: SAFE_TO_TRADE_FIELDS,
    });
    expect(result.safe).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.reasons).toEqual([]);
    expect(result.cross_venue).toEqual({ realtime_overrides: [], scan_ok: true });
    expect(result.receipt).toBeDefined();
  });

  it('parses cross_venue.realtime_overrides into a typed string array', async () => {
    const { body, kp } = await makeSafeToTradeBody({
      cross_venue: { realtime_overrides: ['XNAS', 'XLON'], scan_ok: true },
    });
    mockFetchOnce(body);
    const result = await safeToTrade('XNYS', {
      max_attestation_age: 30,
      publicKey: kp.pub,
      canonicalFields: SAFE_TO_TRADE_FIELDS,
    });
    expect(result.safe).toBe(true);
    expect(result.cross_venue?.realtime_overrides).toEqual(['XNAS', 'XLON']);
    expect(result.cross_venue?.scan_ok).toBe(true);
  });

  it('sends max_age, venue, and instrument as query params', async () => {
    const { body, kp } = await makeSafeToTradeBody({ instrument: 'AAPL' });
    const spy = mockFetchOnce(body);
    await safeToTrade('XNYS', {
      max_attestation_age: 30,
      instrument: 'AAPL',
      publicKey: kp.pub,
      canonicalFields: SAFE_TO_TRADE_FIELDS,
    });
    const callArgs = spy.mock.calls[0]!;
    const url = String(callArgs[0]);
    expect(url).toContain('venue=XNYS');
    expect(url).toContain('max_age=30');
    expect(url).toContain('instrument=AAPL');
  });

  it('forwards apiKey as X-Oracle-Key header', async () => {
    const { body, kp } = await makeSafeToTradeBody();
    const spy = mockFetchOnce(body);
    await safeToTrade('XNYS', {
      max_attestation_age: 30,
      apiKey: 'ho_live_testkey',
      publicKey: kp.pub,
      canonicalFields: SAFE_TO_TRADE_FIELDS,
    });
    const callArgs = spy.mock.calls[0]!;
    const init = callArgs[1] as RequestInit;
    expect((init.headers as Record<string, string>)['X-Oracle-Key']).toBe('ho_live_testkey');
  });
});

// ══════════════════════════════════════════════════════════════════════════
// safeToTrade() — fail-closed paths
// ══════════════════════════════════════════════════════════════════════════

describe('safeToTrade() — fail-closed paths', () => {
  it('returns NOT_SAFE when server reports safe=false', async () => {
    const { body, kp } = await makeSafeToTradeBody({
      safe: 'false',
      venue_status: 'HALTED',
      venue_source: 'OVERRIDE',
      reasons: ['VENUE_NOT_OPEN', 'VENUE_REALTIME_HALT'],
      cross_venue: { realtime_overrides: ['XNYS'], scan_ok: true },
    });
    mockFetchOnce(body);
    const result = await safeToTrade('XNYS', {
      max_attestation_age: 30,
      publicKey: kp.pub,
      canonicalFields: SAFE_TO_TRADE_FIELDS,
    });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('NOT_SAFE');
    expect(result.reasons).toEqual(['VENUE_NOT_OPEN', 'VENUE_REALTIME_HALT']);
    expect(result.cross_venue?.realtime_overrides).toEqual(['XNYS']);
    expect(result.receipt).toBeDefined();
  });

  it('returns WRONG_VENUE when receipt venue does not match request', async () => {
    const { body, kp } = await makeSafeToTradeBody({ venue: 'XNAS' });
    mockFetchOnce(body);
    const result = await safeToTrade('XNYS', {
      max_attestation_age: 30,
      publicKey: kp.pub,
      canonicalFields: SAFE_TO_TRADE_FIELDS,
    });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('WRONG_VENUE');
  });

  it('returns STALE_RECEIPT when receipt is older than max_attestation_age', async () => {
    const { body, kp } = await makeSafeToTradeBody({ issuedAtOffsetSec: 45 });
    mockFetchOnce(body);
    const result = await safeToTrade('XNYS', {
      max_attestation_age: 30, // receipt is 45s old, policy says max 30s
      publicKey: kp.pub,
      canonicalFields: SAFE_TO_TRADE_FIELDS,
    });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('STALE_RECEIPT');
    expect(result.reasons).toEqual([]);
  });

  it('returns INVALID_SIGNATURE when receipt is tampered after signing', async () => {
    const { body, kp } = await makeSafeToTradeBody();
    // Tamper with `safe` after signing — change "true" to "false"
    body.safe = 'false';
    body.receipt.safe = 'false';
    mockFetchOnce(body);
    const result = await safeToTrade('XNYS', {
      max_attestation_age: 30,
      publicKey: kp.pub,
      canonicalFields: SAFE_TO_TRADE_FIELDS,
    });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  it('returns MALFORMED_RECEIPT when cross_venue is not valid JSON', async () => {
    const { body } = await makeSafeToTradeBody();
    body.cross_venue = 'not-json-at-all';
    mockFetchOnce(body);
    const result = await safeToTrade('XNYS', { max_attestation_age: 30 });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('MALFORMED_RECEIPT');
  });

  it('returns MALFORMED_RECEIPT when reasons is not a string array', async () => {
    const { body } = await makeSafeToTradeBody();
    body.reasons = JSON.stringify({ not_an_array: true });
    body.receipt.reasons = body.reasons;
    mockFetchOnce(body);
    const result = await safeToTrade('XNYS', { max_attestation_age: 30 });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('MALFORMED_RECEIPT');
  });

  it('returns MISSING_FIELDS when signature is absent', async () => {
    const { body } = await makeSafeToTradeBody();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    delete (body as any).signature;
    mockFetchOnce(body);
    const result = await safeToTrade('XNYS', { max_attestation_age: 30 });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('MISSING_FIELDS');
  });

  it('returns BAD_RESPONSE on non-2xx status (402, 400, 500)', async () => {
    for (const status of [400, 402, 500]) {
      mockFetchOnce({ error: 'PAYMENT_REQUIRED' }, status);
      const result = await safeToTrade('XNYS', { max_attestation_age: 30 });
      expect(result.safe).toBe(false);
      expect(result.reason).toBe('BAD_RESPONSE');
      expect(result.receipt).toBeDefined(); // body included for audit
    }
  });

  it('returns NETWORK_ERROR when fetch throws', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('network down'));
    const result = await safeToTrade('XNYS', { max_attestation_age: 30 });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('NETWORK_ERROR');
  });
});

// ══════════════════════════════════════════════════════════════════════════
// Edge-case: cross-venue REALTIME override on a DIFFERENT venue does NOT
// trip safe=false (the server is the source of truth — agent trusts its
// decision). This is the v1 design: cross_venue is reported, not gating
// without the cross-listed-venue map.
// ══════════════════════════════════════════════════════════════════════════

describe('safeToTrade() — cross-venue is informational, not gating (v1)', () => {
  it('safe:true even when cross_venue.realtime_overrides has a non-target venue', async () => {
    const { body, kp } = await makeSafeToTradeBody({
      // XNAS has a halt; XNYS itself is OPEN. Server signed safe="true".
      cross_venue: { realtime_overrides: ['XNAS'], scan_ok: true },
      safe: 'true',
    });
    mockFetchOnce(body);
    const result = await safeToTrade('XNYS', {
      max_attestation_age: 30,
      publicKey: kp.pub,
      canonicalFields: SAFE_TO_TRADE_FIELDS,
    });
    expect(result.safe).toBe(true);
    expect(result.cross_venue?.realtime_overrides).toEqual(['XNAS']);
  });

  it('surfaces scan_ok=false through to the caller (informational)', async () => {
    const { body, kp } = await makeSafeToTradeBody({
      cross_venue: { realtime_overrides: [], scan_ok: false },
      reasons: ['CROSS_VENUE_SCAN_UNAVAILABLE'],
    });
    mockFetchOnce(body);
    const result = await safeToTrade('XNYS', {
      max_attestation_age: 30,
      publicKey: kp.pub,
      canonicalFields: SAFE_TO_TRADE_FIELDS,
    });
    expect(result.safe).toBe(true); // CROSS_VENUE_SCAN_UNAVAILABLE alone does not trip safe
    expect(result.cross_venue?.scan_ok).toBe(false);
    expect(result.reasons).toContain('CROSS_VENUE_SCAN_UNAVAILABLE');
  });
});

import { describe, it, expect, vi, afterEach } from 'vitest';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { safeToExecute, resetSpecCache } from '../src/index.js';

// Configure noble sha512 for test key generation and signing.
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

const TEST_CANONICAL_FIELDS = [
  'expires_at', 'halt_detection', 'issued_at', 'issuer', 'mic',
  'public_key_id', 'reason', 'receipt_id', 'receipt_mode',
  'schema_version', 'source', 'status',
];

async function oracleSign(payload: Record<string, string>, privHex: string): Promise<string> {
  const sorted: Record<string, string> = {};
  for (const key of Object.keys(payload).sort()) sorted[key] = payload[key];
  const msg = new TextEncoder().encode(JSON.stringify(sorted));
  const sig = await ed.sign(msg, fromHex(privHex));
  return toHex(sig);
}

/** Build a /v1/status response body. By default — OPEN, fresh, valid sig. */
async function makeStatusBody(opts: {
  mic?: string;
  status?: string;
  issuedAtOffsetSec?: number; // seconds before now; default 5
  ttlSec?: number;            // default 60
  keypair?: Awaited<ReturnType<typeof makeKeypair>>;
  publicKeyId?: string;
} = {}) {
  const kp = opts.keypair ?? await makeKeypair();
  const now = new Date();
  const issuedAt = new Date(now.getTime() - 1000 * (opts.issuedAtOffsetSec ?? 5));
  const expiresAt = new Date(issuedAt.getTime() + 1000 * (opts.ttlSec ?? 60));
  const payload: Record<string, string> = {
    receipt_id:     'test-receipt-00000001',
    issued_at:      issuedAt.toISOString(),
    expires_at:     expiresAt.toISOString(),
    issuer:         'headlessoracle.com',
    mic:            opts.mic ?? 'XNYS',
    status:         opts.status ?? 'OPEN',
    source:         'SCHEDULE',
    halt_detection: 'schedule_only',
    receipt_mode:   'live',
    schema_version: 'v5.0',
    public_key_id:  opts.publicKeyId ?? 'test_key_v1',
  };
  const signature = await oracleSign(payload, kp.priv);
  // Mirror the production wrapper: top-level fields, nested `receipt`, discovery_url.
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

// ── Caller-bug guard (throws, does NOT return) ────────────────────────────────

describe('safeToExecute() — opts.max_attestation_age guard', () => {
  it('throws when opts is missing entirely', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await expect((safeToExecute as any)('XNYS')).rejects.toThrow(/max_attestation_age/);
  });

  it('throws when max_attestation_age is absent', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await expect(safeToExecute('XNYS', {} as any)).rejects.toThrow(/max_attestation_age/);
  });

  it('throws when max_attestation_age is 0', async () => {
    await expect(safeToExecute('XNYS', { max_attestation_age: 0 })).rejects.toThrow(/max_attestation_age/);
  });

  it('throws when max_attestation_age is negative', async () => {
    await expect(safeToExecute('XNYS', { max_attestation_age: -1 })).rejects.toThrow(/max_attestation_age/);
  });

  it('throws when max_attestation_age is NaN', async () => {
    await expect(safeToExecute('XNYS', { max_attestation_age: NaN })).rejects.toThrow(/max_attestation_age/);
  });

  it('throws when max_attestation_age is Infinity', async () => {
    await expect(safeToExecute('XNYS', { max_attestation_age: Infinity })).rejects.toThrow(/max_attestation_age/);
  });
});

// ── Network / response failures ───────────────────────────────────────────────

describe('safeToExecute() — network and response failures', () => {
  it('returns NETWORK_ERROR when fetch throws', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('Network down'));
    const result = await safeToExecute('XNYS', { max_attestation_age: 60 });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('NETWORK_ERROR');
    expect(result.receipt).toBeUndefined();
  });

  it('returns BAD_RESPONSE on non-2xx status', async () => {
    mockFetchOnce({ error: 'UNKNOWN_MIC' }, 400);
    const result = await safeToExecute('XNYS', { max_attestation_age: 60 });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('BAD_RESPONSE');
    expect(result.receipt).toEqual({ error: 'UNKNOWN_MIC' });
  });

  it('returns BAD_RESPONSE on unparseable JSON', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok:    true,
      status: 200,
      json:  async () => { throw new Error('bad json'); },
    } as unknown as Response);
    const result = await safeToExecute('XNYS', { max_attestation_age: 60 });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('BAD_RESPONSE');
  });

  it('returns MISSING_FIELDS when response is missing signature', async () => {
    mockFetchOnce({ mic: 'XNYS', status: 'OPEN' });
    const result = await safeToExecute('XNYS', { max_attestation_age: 60 });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('MISSING_FIELDS');
  });
});

// ── Freshness (caller-policy bound) ──────────────────────────────────────────

describe('safeToExecute() — freshness gate', () => {
  it('returns STALE_RECEIPT when issued_at is older than max_attestation_age', async () => {
    const { body, kp } = await makeStatusBody({ issuedAtOffsetSec: 120 });
    mockFetchOnce(body);
    const result = await safeToExecute('XNYS', {
      max_attestation_age: 30,
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('STALE_RECEIPT');
    expect(result.receipt).toBeDefined();
    expect(result.status).toBe('OPEN'); // surfaces the receipt's reported status even on stale-fail
  });

  it('freshness check runs BEFORE signature verification — no key fetch on stale receipt', async () => {
    // If freshness short-circuits before verify(), the /v5/keys fetch should NEVER fire.
    const { body } = await makeStatusBody({ issuedAtOffsetSec: 600 });
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true, status: 200, json: async () => body,
    } as unknown as Response);
    const result = await safeToExecute('XNYS', { max_attestation_age: 5 });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('STALE_RECEIPT');
    expect(fetchSpy).toHaveBeenCalledTimes(1); // only /v1/status, never /v5/keys
  });

  it('returns EXPIRED when receipt.expires_at has passed (delegated to verify())', async () => {
    // Fresh issued_at, but expires_at already past.
    const { body, kp } = await makeStatusBody({ issuedAtOffsetSec: 5, ttlSec: 1 });
    // Advance now past expires_at.
    const now = new Date(Date.now() + 60_000);
    mockFetchOnce(body);
    const result = await safeToExecute('XNYS', {
      max_attestation_age: 300,  // very loose so it can't catch this
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
      now,
    });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('EXPIRED');
  });
});

// ── Signature failures ───────────────────────────────────────────────────────

describe('safeToExecute() — signature verification', () => {
  it('returns INVALID_SIGNATURE when payload was tampered after signing', async () => {
    const { body, kp } = await makeStatusBody();
    // Tamper top-level status. The nested `receipt` still has the original.
    // verify() runs against top-level fields, so this should fail signature.
    const tampered = { ...body, status: 'CLOSED' };
    mockFetchOnce(tampered);
    const result = await safeToExecute('XNYS', {
      max_attestation_age: 60,
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
    expect(result.receipt).toBeDefined();
  });

  it('returns INVALID_SIGNATURE when wrong public key is used', async () => {
    const { body } = await makeStatusBody();
    const wrongKp = await makeKeypair();
    mockFetchOnce(body);
    const result = await safeToExecute('XNYS', {
      max_attestation_age: 60,
      publicKey: wrongKp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });
});

// ── MIC mismatch and status failures ─────────────────────────────────────────

describe('safeToExecute() — MIC and status gates', () => {
  it('returns WRONG_MIC when receipt mic does not match requested mic', async () => {
    const { body, kp } = await makeStatusBody({ mic: 'XLON' });
    mockFetchOnce(body);
    const result = await safeToExecute('XNYS', {
      max_attestation_age: 60,
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('WRONG_MIC');
    expect(result.receipt).toBeDefined();
  });

  it('returns NOT_OPEN when status is CLOSED', async () => {
    const { body, kp } = await makeStatusBody({ status: 'CLOSED' });
    mockFetchOnce(body);
    const result = await safeToExecute('XNYS', {
      max_attestation_age: 60,
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('NOT_OPEN');
    expect(result.status).toBe('CLOSED');
    expect(result.receipt).toBeDefined();
  });

  it('returns NOT_OPEN when status is HALTED (does NOT fail open)', async () => {
    const { body, kp } = await makeStatusBody({ status: 'HALTED' });
    mockFetchOnce(body);
    const result = await safeToExecute('XNYS', {
      max_attestation_age: 60,
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('NOT_OPEN');
    expect(result.status).toBe('HALTED');
  });

  it('returns NOT_OPEN when status is UNKNOWN (the fail-closed invariant)', async () => {
    const { body, kp } = await makeStatusBody({ status: 'UNKNOWN' });
    mockFetchOnce(body);
    const result = await safeToExecute('XNYS', {
      max_attestation_age: 60,
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('NOT_OPEN');
    expect(result.status).toBe('UNKNOWN');
  });
});

// ── Happy path ────────────────────────────────────────────────────────────────

describe('safeToExecute() — the one happy path', () => {
  it('returns safe: true on fresh + valid + OPEN + correct MIC', async () => {
    const { body, kp } = await makeStatusBody();
    mockFetchOnce(body);
    const result = await safeToExecute('XNYS', {
      max_attestation_age: 60,
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.safe).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.status).toBe('OPEN');
    expect(result.receipt).toBeDefined();
    expect((result.receipt as Record<string, unknown>).mic).toBe('XNYS');
  });

  it('normalizes lowercase mic to uppercase in the URL and MIC check', async () => {
    const { body, kp } = await makeStatusBody();
    const fetchSpy = mockFetchOnce(body);
    const result = await safeToExecute('xnys', {
      max_attestation_age: 60,
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.safe).toBe(true);
    expect(fetchSpy).toHaveBeenCalledWith('https://headlessoracle.com/v1/status/XNYS');
  });

  it('uses custom endpoint when opts.endpoint is provided', async () => {
    const { body, kp } = await makeStatusBody();
    const fetchSpy = mockFetchOnce(body);
    await safeToExecute('XNYS', {
      max_attestation_age: 60,
      endpoint: 'https://staging.headlessoracle.com/v1/status',
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(fetchSpy).toHaveBeenCalledWith('https://staging.headlessoracle.com/v1/status/XNYS');
  });

  it('handles trailing slash on custom endpoint', async () => {
    const { body, kp } = await makeStatusBody();
    const fetchSpy = mockFetchOnce(body);
    await safeToExecute('XNYS', {
      max_attestation_age: 60,
      endpoint: 'https://staging.headlessoracle.com/v1/status/',
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(fetchSpy).toHaveBeenCalledWith('https://staging.headlessoracle.com/v1/status/XNYS');
  });
});

// ── Audit trail (receipt returned on failure) ────────────────────────────────

describe('safeToExecute() — receipt always returned for audit', () => {
  it('returns the receipt body even on NOT_OPEN — caller logs the artifact', async () => {
    const { body, kp } = await makeStatusBody({ status: 'CLOSED' });
    mockFetchOnce(body);
    const result = await safeToExecute('XNYS', {
      max_attestation_age: 60,
      publicKey: kp.pub,
      canonicalFields: TEST_CANONICAL_FIELDS,
    });
    expect(result.safe).toBe(false);
    expect(result.receipt).toBeDefined();
    // The full wrapper is preserved — caller can log the signed artifact and
    // the discovery_url that came with it.
    const r = result.receipt as Record<string, unknown>;
    expect(r).toHaveProperty('signature');
    expect(r).toHaveProperty('discovery_url');
  });
});

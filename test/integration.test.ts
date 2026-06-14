/**
 * Integration tests — round-trip against the live Oracle.
 *
 * Fetches real /v5/demo and /v5/health responses from headlessoracle.com
 * and verifies them with the SDK. This is the regression gate for the
 * canonicalization-decoration bug fixed in 1.0.2: the worker decorates
 * receipts with `receipt`, `discovery_url`, and `extensions` after
 * signing, and the SDK must filter them out before reconstructing the
 * canonical message bytes.
 *
 * Skips entirely when SDK_OFFLINE=1 is set (CI on disconnected runners).
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { verify, resetSpecCache } from '../src/index.js';

const ORACLE_BASE   = process.env.ORACLE_BASE_URL ?? 'https://headlessoracle.com';
const OFFLINE       = process.env.SDK_OFFLINE === '1';
const ALL_MICS      = ['XNYS', 'XNAS', 'XLON', 'XJPX', 'XPAR', 'XHKG', 'XSES'];

const describeIfOnline = OFFLINE ? describe.skip : describe;

beforeEach(() => {
  // Each test starts with a fresh /v5/keys fetch — keeps the suite hermetic
  // even though spec almost never changes.
  resetSpecCache();
});

describeIfOnline('integration — live /v5/demo round-trip', () => {
  it('verifies a real /v5/demo receipt for XNYS', async () => {
    const res     = await fetch(`${ORACLE_BASE}/v5/demo?mic=XNYS`);
    const receipt = await res.json();

    // Sanity: the worker decorates the response with non-signed metadata.
    // If any of these go away, the bug being regressed against has changed
    // shape and the test is no longer measuring what it claims to measure.
    //
    // NOTE — 2026-06-14: extensions.bazaar was deliberately removed from
    // /v5/demo and /v5/status trial 200 bodies (CDP Bazaar now indexes from
    // the dedicated /v5/status/x402 402 resource, not from trial 200s). The
    // `extensions` field is no longer present on this response and is no
    // longer asserted here. `receipt` + `discovery_url` remain.
    expect(receipt).toHaveProperty('receipt');
    expect(receipt).toHaveProperty('discovery_url');

    const result = await verify(receipt);
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it.each(ALL_MICS)('verifies a real /v5/demo receipt for %s', async (mic) => {
    const res     = await fetch(`${ORACLE_BASE}/v5/demo?mic=${mic}`);
    const receipt = await res.json();
    const result  = await verify(receipt);
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it('rejects a tampered signature on a real receipt', async () => {
    const res     = await fetch(`${ORACLE_BASE}/v5/demo?mic=XNYS`);
    const receipt = await res.json() as Record<string, unknown>;

    const tampered = { ...receipt, signature: 'a'.repeat(128) };
    const result   = await verify(tampered);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  it('rejects tampering of a signed field on a real receipt', async () => {
    const res     = await fetch(`${ORACLE_BASE}/v5/demo?mic=XNYS`);
    const receipt = await res.json() as Record<string, unknown>;

    // Flip the status — this is signed, so the signature must no longer verify.
    const flipped = receipt.status === 'OPEN' ? 'CLOSED' : 'OPEN';
    const tampered = { ...receipt, status: flipped };
    const result   = await verify(tampered);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });
});

describeIfOnline('integration — live /v5/health round-trip', () => {
  it('verifies a real /v5/health receipt', async () => {
    const res     = await fetch(`${ORACLE_BASE}/v5/health`);
    const receipt = await res.json();

    const result = await verify(receipt);
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });
});

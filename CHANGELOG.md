# Changelog

All notable changes to `@headlessoracle/verify` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] — 2026-05-04

### Fixed
- **Canonical-payload reconstruction now matches the worker.** Previous
  releases stripped only the `signature` field from the receipt and signed
  every other top-level key. The worker decorates `/v5/demo` and `/v5/status`
  responses after signing with `receipt` (duplicate wrapper), `discovery_url`,
  and `extensions.bazaar`. Including those in the canonical message bytes
  produced `INVALID_SIGNATURE` against every real production receipt.
- `verify()` now fetches `canonical_payload_spec` from `/v5/keys` and
  filters the receipt to the union of `receipt_fields`, `override_fields`,
  and `health_fields` before constructing the canonical JSON. Decoration
  fields the worker adds to the response after signing are excluded.

### Changed
- Default `keysUrl` changed from `https://headlessoracle.com/.well-known/oracle-keys.json`
  to `https://headlessoracle.com/v5/keys`. The `.well-known` endpoint does
  not publish `canonical_payload_spec`, so the SDK can no longer rely on
  it. Consumers passing `publicKey` explicitly are unaffected only if they
  also pass `canonicalFields`; otherwise the SDK still fetches `/v5/keys`
  for the spec.
- Custom `keysUrl` overrides MUST now point at an endpoint returning both
  `keys` and `canonical_payload_spec`.

### Added
- `canonicalFields?: string[]` option on `VerifyOptions` lets callers
  bypass the network fetch entirely (used by tests and by offline-only
  environments with a frozen spec).
- `SPEC_UNAVAILABLE` failure reason for the case where `/v5/keys` returns
  no `canonical_payload_spec`.
- `resetSpecCache()` named export — clears the in-process memoized
  `/v5/keys` response. Intended for test suites that need to drive
  different mock responses across cases.
- New unit tests covering wrapper-decoration handling and `/v5/keys`
  caching semantics.
- New `test/integration.test.ts` runs the SDK against live
  `headlessoracle.com` (skip with `SDK_OFFLINE=1`).

### Internal
- In-process memoization of `/v5/keys` keyed by URL. Each unique URL is
  fetched at most once per process; failed fetches are not cached.

## [1.0.1] — 2026-03-01

- Initial published release.

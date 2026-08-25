# Changelog

All notable changes to ldapact v1 are tracked here, one entry per implementation
unit (see `docs/plans/2026-08-24-001-feat-ldapact-v1-implementation-plan.md`).

## U1 — Project skeleton, config, secret resolver, slog, security headers, CSRF

- Go module `github.com/liut/ldapact` with `cmd/ldapact` single-binary entry
  point (CGO_ENABLED=0 build via Makefile).
- Strict YAML server profile (`pkg/config`) with R12 validation: TLS floor
  TLSv1.2, verify mandatory, StartTLS defaults on for `ldap://`, session
  timeout ranges, pool size, tree filter.
- Secret resolver chain env → 0600 file → TTY prompt; plaintext YAML never
  accepted; truncated fingerprints for logs.
- `log/slog` JSON logger with `userPassword`/`*_password` redaction at the
  handler boundary plus `logging.SafeAttr` belt-and-suspenders.
- Security headers middleware (CSP-Report-Only, HSTS over TLS, nosniff, DENY,
  Referrer-Policy, Permissions-Policy, cache policy), CSRF Origin-header check,
  per-IP rate limiter, request ID and panic recovery middleware.
- `//go:embed` assets package with dev-mode `os.DirFS` override; `static/` and
  `templates/` placeholders.

## U2 — LDAP abstraction layer (pool, schema, CRUD)

- `pkg/ldapx` wrapping go-ldap/ldap v3.4.14 with an admin-tool-specific
  surface (not exported as a general library):
  - Channel-based connection pool (KTD 5): validate-on-Put base-scope search,
    health-check ping every 30s, refill on drop, retry-once on
    ErrorNetwork/ServerDown with 50ms→2s backoff.
  - Dial layer with KeepAlive 30s/Timeout 5s, ldaps:// and ldap://+StartTLS,
    TLS 1.2 floor, mandatory verify, fail-closed certificate expiry (warn at
    <30 days).
  - Paged search (R2) with paging-cookie loop, stateless page re-run, context
    cancellation between pages.
  - RFC 4512 schema description parser + process-lifetime subschema cache
    (R14), attribute-name canonicalization, fail-fast load.
  - CRUD wrappers (R3): Add/Modify/Delete/ModifyDN with newSuperior support,
    RFC 3062 PasswordModify, SASL EXTERNAL helper.
  - `LDAPError` with `slog.LogValuer` carrying result code + DN (never
    passwords) for HTTP status mapping.
- Unit tests via a fake connection interface (no Docker required); integration
  tests against testcontainers-go OpenLDAP 2.6 that skip cleanly when Docker is
  unavailable.

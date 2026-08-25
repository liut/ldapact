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

## U4 — HTML template infrastructure, embed, ARIA helpers, static assets

- `pkg/web`: html/template parsing from an embedded FS (panic-on-parse-failure
  at startup), base FuncMap (dict/join/safeHTML), Renderer for full pages and
  HTMX fragments; layout shell with skip link, `role="main"`, `role="contentinfo"`,
  WCAG 2.1 AA CSS primitives (focus-visible rings, prefers-reduced-motion,
  24px touch targets).
- `static/`: HTMX 2.0.4, main/tree/forms CSS, `tree-keys.js` (full ARIA tree
  keyboard navigation with a transport-agnostic loader hook for U5),
  `autofill.js` (`%var|start-end/modifier%` runtime for R8 autoFill).
- Root `templates/`: `template.dtd` + creation/modification XML corpus copied
  verbatim from the phpLDAPadmin oracle (plan invariant; verified byte-identical).
- `/static/` served from the embedded FS (`Cache-Control: public, max-age=300`);
  XML templates are embedded but never exposed over HTTP.
- JS unit tests run under Node (`make test-js`): autofill token grammar and
  tree keyboard behavior via a minimal DOM shim.

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

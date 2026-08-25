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

## U3 — Session store, cookie security, rotation, auth middleware

- `pkg/session`: bbolt-backed store (0600-enforced, KTD 7) with opaque 256-bit
  base64url IDs, idle + absolute timeouts, `__Host-LDAPADM_SID` cookie
  (Secure/HttpOnly/SameSite=Strict/Path=/, no Domain), rotation, per-form data
  for the F2 wizard, and a 5-minute sweeper.
- `pkg/authn`: session middleware implementing AE1 auto-login (first request
  mints a session; no login page), AE7 expiry actions
  (`retry_bind` re-mints; `redirect_to_login` → `/login?next=...`), malformed
  cookie rejection (400), store-failure 503, and conservative session rotation
  before state-changing handlers (documented deviation: header commit order
  makes post-handler cookie rotation unreliable).
- `main.go`: fail-fast startup LDAP bind via `ldapx.New` (R14/AE1), session
  store + sweep loop, signal-aware shutdown; `/healthz` and `/static/` skip
  session minting; minimal `/login` landing page.

## U5 — Tree browse (F1) + schema browser (R5)

- `pkg/tree`: paged `GET /api/tree/{dn...}/children` HTMX fragments with the
  ARIA tree pattern (aria-level/setsize/posinset/expanded, aria-disabled empty
  and inaccessible states, `role="alert"` errors distinguishing
  size-limit-exceeded from network failure, "Load more" pagination).
  Leaf detection mirrors phpLDAPadmin's `hassubordinates` operational
  attribute; breadcrumb trails stop at the base DN and collapse deep trails to
  3 + ellipsis + 2.
- Schema browser (R5/R5.x): objectClass + attributeType lists and detail pages
  with MUST/MAY and SUP cross-navigation, syntax/matching/single-value
  rendering, from the U2 subschema cache.
- Full-page render pipeline upgraded to content-template + layout wrapper
  (html/template cannot dispatch dynamic template names); home page becomes
  the tree scaffold rooted at the base DN (AE1).
- `tree-keys.js` htmx integration: expand → hx-get children, aria-busy
  lifecycle, "N children loaded" announcement, and `X-Mutated-Subtree` refresh
  hook for F2/F5/F6 cross-flow consistency.
- Integration test against testcontainers-go OpenLDAP (skips without Docker).

## U6 — Template engine + entry flows (F2/F3/F5/F6/F-Detail)

- `pkg/tplengine`: phpLDAPadmin template.dtd-compatible XML parser (strict:
  unknown elements/duplicate ids/missing title/rdn fail at load), typed model
  with pages/orders/kinds, and the full R8 server-macro allowlist
  (PickList/GetNextNumber search+pool/PASSWORDEncrypt/PasswordEncryptionTypes/
  HashPassword/RandomPassword/Join/Default/DN/Encoded/Escape/Binary/
  HasMultiples/MultiList) with unknown functions rejected at parse time.
  autoFill client macros compile to JS fragments consumed by autofill.js
  (multi-source bindings). Regression corpus: all 9 phpLDAPadmin creation
  templates parse unmodified (plan's key quality gate); parser.go coverage
  95%, macros_server.go 93%.
- `pkg/tplengine/password.go`: RFC 2307 hashing with KTD 6 write whitelist
  (SSHA512/SSHA256/SSHA/SHA512/SHA256/ARGON2ID/MD4-UTF16LE), read-only
  verification for legacy MD5/SMD5/SHA/BLOWFISH/crypt family, {PLAIN} rejected
  unless `password_plain_override` is set (structured warn).
- `pkg/entry`: F-Detail page with breadcrumbs + action links; F2 wizard
  (single-page multi-section form with step indicator — server-side per-page
  session state deferred, see notes) evaluating PickList/GetNextNumber at
  render, server-side required-field revalidation, post-hook password hashing,
  inline schema-violation errors with rollback link, `X-Mutated-Subtree`
  header; F3 password change (detect scheme, SSHA512 default, ppolicy error
  mapping, AE4 bind verification); F5 delete confirmation with typed-DN for
  non-leaf entries and ceiling-gated recursive delete; F6 rename/move with
  target-parent existence check.
- R15 audit lines emitted for every mutation (event/actor/dn/op_type; user
  password values never logged).
- Integration test (testcontainers-go OpenLDAP, Docker-gated) exercising
  F2→bind→F3→F6→F5 against a live directory (AE3/AE4).

## U7 — LDIF import/export (F4/F7) + search (F8)

- `pkg/ldif`: streaming RFC 2849 parser (bounded memory, no ReadAll) with
  R11 caps (100k entries, 1000 attrs/entry, 10MiB values), strict validation
  (dn required, UTF-8 values, URL references rejected, base64/continuation
  support), per-record error continuation (AE5); RFC 2849 writer with
  automatic base64 for binary/unsafe values and long-line folding.
- F4 import: multipart upload capped at 100MB (413 without disk buffering),
  per-entry try/continue, dry-run mode, result page with success/failure
  counts + inline rows (line/reason/raw LDIF), and a downloadable
  `import-errors-<timestamp>.txt` report served from an in-memory store.
- F7 export: entry or subtree scope; subtree streams page-by-page via the
  paging cookie with `http.Flusher`; `userPassword` redacted by default,
  `include_secrets=1` emits a warn; binary attributes base64.
- F8 search: `GET /api/search` with LDAP filter validation (inline
  "filter syntax error at position N" + `aria-invalid`), subtree/global scope,
  DN-sorted results (objectClass + modifyTimestamp), 50/page pagination,
  "0 results" state.
- Toolbar links on the tree page; integration test (Docker-gated) covering
  F4 partial success + F7 subtree export against live OpenLDAP.

## U8 — Build, integration harness, deployment, operations

- `internal/app`: handler assembly extracted from the CLI so the end-to-end
  harness exercises the real middleware/routing stack.
- `test/integration`: testcontainers-go OpenLDAP harness (TestMain starts and
  seeds 5 OUs, 1210 users, 3 groups) with F1-F8 flow tests — paged tree,
  template create + audit redaction (AE3/AE6), password change + bind (AE4),
  partial-success import (AE5), rename/delete, subtree export, search.
  Skips cleanly when Docker is unavailable.
- `Dockerfile`: distroless static image; `-healthcheck` flag for container
  probes; systemd unit with `LoadCredential`; k8s Deployment/Service with
  projected config+secret and probes.
- `Makefile`: `test-integration` target; `govulncheck` in `lint` (with
  install hint).
- README (install/config/deployment/security/API surface) and OPERATIONS
  (secret resolver examples, sessions.db lifecycle, log shipping, TLS
  rotation, cutover playbook, error-code mapping, v1 pre-launch checklist).

## v1 review pass (Tier 2, ce-code-review 20260825-153915)

- LDIF parser: bounded line reads (R11 constant-memory guarantee).
- LDIF import: oversized bodies return 413; export: entry lookup before
  response headers (clean 404/5xx).
- Entry detail: `userPassword` values redacted in the UI (scheme shown).
- Create/password errors mapped via LDAP result codes (no brittle string
  matching).
- `GetNextNumber` runs on the independent auto-number pool when configured
  (R8 rebind).
- F8 global scope searches from the root DSE; `page_size` honored.
- Rename success links to the new DN.
- Accepted residuals recorded in
  `docs/residual-review-findings/feat-ldapact-v1.md` (F2 single-page wizard,
  O(n²) subtree export, pre-handler session rotation).

## Non-containerized integration tests (internal/testldap)

- New `internal/testldap` backend detection: `LDAPADM_TEST_LDAP_URL` →
  Docker (testcontainers) → local ephemeral `slapd` → skip. The local backend
  generates an isolated `slapd.conf` + temp data dir, binds a random loopback
  port, runs slapd in the foreground as the current user, seeds the base
  entry, and tears everything down on Stop — never touching system configs,
  data dirs, pidfiles, or launchd/systemd services (safety contract).
- All four package integration suites + the F1-F8 harness now use the shared
  backend; the harness runs for real against the local MacPorts OpenLDAP on
  this machine (12s).
- Fixed two latent defects the local runs exposed: Go ServeMux rejects
  `{dn...}` followed by literals (route registration would panic at startup),
  and LDAP paged-result sessions are connection-scoped (Page now pins one
  connection for the whole multi-page loop).
- New `password_scheme` config option (KTD 6 default SSHA512); the harness
  probes `{SSHA512}` bind support and downgrades to `{SSHA}` for builds that
  lack SHA-2 password schemes (verified: MacPorts OpenLDAP 2.6.13 rejects
  SSHA512).

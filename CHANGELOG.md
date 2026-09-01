# Changelog

All notable changes to ldapact v1 are tracked here, one entry per implementation
unit (see `docs/plans/2026-08-24-001-feat-ldapact-v1-implementation-plan.md`).

## Logout control and identity in the header (2026-09-01)

- `feat(web)` — authenticated pages now render a "Log out" button in the
  header (POST /logout, protected by the same CSRF/rate-limit chain) plus the
  logged-in bind DN as small "Logged in as <DN>" text; the public login page
  keeps the plain header. The renderer gains `PageAuth(..., actor)`, and the
  authn middleware attaches the bind DN to the request context for page
  rendering (`web.WithActor`/`ActorFrom`).

## Redis-to-memory fallback + Makefile sync (2026-09-01)

- `feat(config)` — when `LDAPADM_SESSION_STORE` is left at the default and
  Redis is not configured (empty URL) or only a loopback Redis
  (`localhost`/`127.*`/`::1`) is unreachable, the store falls back to
  `memory` (logged as `event=session.redis_fallback_memory`). An explicitly
  configured `redis` store or a remote Redis URL stays fail-fast. Config
  gains `SessionStoreExplicit` to distinguish defaulted vs explicit choice.
- `chore(Makefile)` — `make test-integration` now runs the gated integration
  tests in `internal/app`, `pkg/authn`, `pkg/entry`, `pkg/ldapx`, `pkg/ldif`,
  `pkg/session`, and `pkg/tree` in addition to the F1-F8 flows; `make run`
  documents the memory fallback. README/OPERATIONS/.env.example/AGENTS.md
  synced.

## Secret resolution without TTY prompt (2026-09-01)

- `refactor(config)` — ldapact is a server process, so secret resolution no
  longer falls back to an interactive TTY prompt. Secrets come from env vars
  or 0600 files only; a missing secret fails fast at startup with an error
  naming the variable and its `_FILE` reference. `golang.org/x/term` is no
  longer a dependency. README/OPERATIONS/.env.example/AGENTS.md updated.

## External session store and login gate (2026-08-31)

One entry per implementation unit of
`docs/plans/2026-08-31-001-feat-session-store-login-gate-plan.md`:

- `refactor(session)` — the bbolt store becomes the `Store` interface
  (Create/Get/Rotate/Delete/Sweep/Close); `Value` gains `ServerRef` and
  `Credential` (encrypted bind credential) fields; a memory backend with the
  same timeout/rotation semantics is added (bbolt persists, memory clears on
  restart).
- `feat(config)` — `LDAPADM_SESSION_STORE` (default `redis`),
  `LDAPADM_REDIS_URL`/`LDAPADM_REDIS_DB`/`LDAPADM_REDIS_PASSWORD`,
  `LDAPADM_SESSION_KEY` (required secret), and `LDAPADM_SERVERS` (replica
  list, mutually exclusive with `LDAPADM_URL`); `expired_action` defaults to
  `redirect_to_login` and `retry_bind` is rejected; `LDAPADM_BIND_PASSWORD`
  is deprecated and no longer resolved.
- `feat(session)` — Redis session backend: JSON records under
  `ldapa_sess:<id>`, sliding TTL via `GETEX`, atomic `RENAME` rotation, lazy
  absolute expiry; shared across instances (unit tests use miniredis, gated
  integration tests use a real Redis backend).
- `feat(session)` — AES-256-GCM credential cipher: versioned envelope with a
  per-record nonce; corrupt vs key-mismatch error classes; key comes from
  `LDAPADM_SESSION_KEY`.
- `feat(ldapx)` — the main pool is unbound: every operation binds with the
  request-scoped credential from the context; the schema cache loads lazily
  on the first authenticated operation; `VerifyBind` (dial + bind + close)
  backs the login gate; invalidCredentials is typed and never retried.
- `feat(authn)` — login gate: `/healthz`, `/static/*`, and `/login` are
  public, everything else requires a session and redirects to `/login`;
  login verifies the bind DN + password and stores the encrypted credential;
  logout deletes the session and clears the cookie; invalidCredentials
  invalidates the session and redirects to login (entry/tree/search/ldif
  error paths wired).
- `feat(ldapx)` — replica failover: one unbound pool per `LDAPADM_SERVERS`
  URL, rotating start points, bounded failover on network errors only,
  aggregate error naming each replica when all are down.
- `feat(main)` — session store factory wiring (redis/bbolt/memory), cipher
  construction, replica-aware client, and the startup probe no longer binds;
  README/OPERATIONS/.env.example updated and CHANGELOG entries kept in sync.

## LDAP server troubleshooting docs (2026-08-31)

- OPERATIONS.md gains a directory-server troubleshooting section: diagnosing
  a wedged slapd via the macOS unified log (`log show --predicate
  'process == "slapd"'`) and restarting it (SIGKILL + `launchctl kickstart`),
  including the MacPorts daemondo `--pid=none` trap.

## Envconfig unified prefix + config reference (2026-08-31)

- envconfig now parses with the `LDAPADM` prefix and short `envconfig` tags;
  the documented `LDAPADM_*` names are unchanged. The flat envFields view is
  kept (nested-struct parsing would produce `LDAPADM_LDAP_URL`-style names),
  and defaults stay in `Validate()` as the single source of truth.
- Unknown `LDAPADM_*` variables are ignored (the strict allowlist is gone);
  envconfig's bare-name fallback is accepted: when `LDAPADM_URL` is absent a
  bare `URL` variable would be read, so set the prefixed key to be explicit.
- A set-but-empty variable is parsed as-is instead of treated as unset:
  numeric/boolean fields fail at parse time naming the variable, string
  fields fall through to validation.
- The non-secret `LDAPADM_*` env-name constants moved to `config_test.go`
  (test-only); runtime code no longer references them — the two secret
  constants remain in `pkg/config` for the resolver chain.
- `LDAPADM_PASSWORD_SCHEME` is normalized (trim + upper) at parse time via an
  envconfig `Decoder`; the RFC 2307 write-allowlist check stays in
  `Validate()`.
- New `-config-help` flag prints the `LDAPADM_*` reference (key, type,
  description) generated from the struct tags.

## Default listen port 8389 (2026-08-31)

- Default `LDAPADM_LISTEN` moved from 8080 to 127.0.0.1:8389 (IANA-unassigned,
  LDAP-flavored, low collision). README, `.env.example`, Dockerfile EXPOSE,
  the `-healthcheck` default URL, and the systemd/Kubernetes deployment
  artifacts follow.

## Dockerfile builder improvements (2026-08-31)

- Builder base switched to `golang:1.27-alpine` and module downloads go
  through a commented-out GOPROXY line (goproxy.cn/goproxy.io/direct — enable
  for CN networks); runtime stage is gcr.io/distroless/static-debian13.

## Test LDAP image switch (2026-08-31)

- The Docker integration backend now uses `liut7/staffio-ldap` (Alpine
  OpenLDAP, port 389, `LDAP_ADMIN_NAME`/`LDAP_BASE_DN` env) instead of the
  removed `bitnami/openldap:2.6` tag; the image is overridable via
  `LDAPADM_TEST_LDAP_IMAGE`.

## Lint unified on golangci-lint (2026-08-31)

- `make lint` now runs gofmt + vet + golangci-lint (v2.13.2) + govulncheck;
  standalone staticcheck is gone. `.golangci.yml` enables govet/ineffassign/
  staticcheck/unused (errcheck off — its findings were idiomatic ignored
  `Close`/`Write` errors).
- Workflows no longer depend on make: lint uses the golangci-lint action (v9)
  and the official govulncheck action plus direct go commands; test and
  release steps run go/node directly.
- Fixed the md4 nolint directive for golangci-lint and the reported
  staticcheck/ineffassign findings.

## Dependency security bumps (2026-08-31)

- `govulncheck` in CI flagged the testcontainers tar path (moby/go-archive).
  Bumped `github.com/moby/go-archive` v0.2.0 → v0.3.3 and
  `golang.org/x/crypto` v0.54.0 → v0.55.0; `make lint` is green again.

## Lint tool management (2026-08-31)

- `make lint`'s tool prerequisites (staticcheck, govulncheck) are installed
  via a new `make tools` target with overridable versions; CI calls it
  instead of repeating `go install` in each workflow. `make lint` now hints
  at `make tools` when staticcheck is missing.

## CI workflow consolidation (2026-08-31)

- Merged the lint and test workflows into a single `ci.yml` with parallel
  lint/test jobs; `release.yml` stays separate.

## GitHub Actions CI (2026-08-31)

- Added `.github/workflows`: `lint` (gofmt/vet/staticcheck/govulncheck),
  `test` (build, unit + Docker-backed integration, JS), and `release`
  (tag `v*` → multi-platform binaries + GitHub Release).
- Makefile gains `dist/<os>_<arch>/ldapact` targets and stamps `main.commit`
  in builds.

## License (2026-08-31)

- Added `LICENSE` (GPL-2.0-or-later), matching phpLDAPadmin whose template
  artifacts (`template.dtd`, creation templates) this repo builds on; README
  and AGENTS.md now state the license and the constraint on those artifacts.

## Docs split: README vs AGENTS.md (2026-08-31)

- README is now user-facing only: intro, features, quick start, configuration,
  deployment, security model, routes, and the make-target summary.
- Developer/agent guidance moved to the new `AGENTS.md`: repository layout,
  the integration-test backend contract, commit/routing/rendering conventions,
  config and secret handling, security invariants, known gotchas, and the
  docs index. README links to it from the Development section.

## Route prefix cleanup (2026-08-31)

- `/api` is now reserved for endpoints that return data or HTMX fragments:
  `/api/tree/{dn...}` (tree children fragment), `/api/entry/{dn...}/photo`
  (image data), `/api/export` (LDIF data), `/api/import/report/{id}` (plain
  text report). Page routes lost the prefix and live under plain paths:
  `/entry/...` (detail, edit, password, delete, rename), `/template/...`
  (create), `/schema/...`, `/search`, and `/import`.

## Schema browser detail pages (2026-08-30)

- R5.x — schema detail pages now match the phpLDAPadmin layout.
  - objectClass detail: dedicated "Inherits from" (SUP) and "Parent to"
    (direct children) rows, plus a two-column Required/Optional attributes
    table. MUST/MAY are resolved through the SUP chain, and attributes
    inherited from an ancestor are annotated with the defining objectClass as
    a cross-navigation link; `top` renders its children as the "all"
    objectClasses list.
  - attributeType detail: a label/value table covering Description, Obsolete,
    Inherits from, Equality/Ordering/Substring, Syntax (resolved to its
    ldapSyntaxes description plus OID), Single Valued, Collective, User
    Modification, Usage, Maximum Length (from the SYNTAX `{N}` suffix),
    Aliases, "Used by objectClasses" (direct MUST/MAY references), and Force
    as MAY by config. The RFC 4512 parser now captures OBSOLETE, COLLECTIVE,
    NO-USER-MODIFICATION and the syntax `{length}` suffix.

## Schema-driven edit form controls (2026-08-27)

- U1 — Schema control classification: `pkg/ldapx` now derives the edit-form
  control kind from the attributeType RFC 4517 syntax (boolean → select,
  DN syntaxes → DN field, binary syntaxes → read-only, Postal Address →
  textarea), reports operational attributes from the schema USAGE
  declaration, and resolves effective objectClass MUST/MAY sets through the
  SUP chain.
- U2 — Edit form schema-driven rendering: both the template-driven and
  generic edit paths classify controls from the schema; boolean attributes
  render as TRUE/FALSE selects (with a "(not set)" option when empty),
  DN attributes carry a "Distinguished Name" hint, binary values are
  read-only, Postal Address values render as textareas, schema-MUST
  attributes show a visible "Required (schema)" marker (informational only),
  and operational attributes are excluded via schema USAGE with the
  hardcoded list retained as fallback. Template-declared presentation
  (textarea, picklists, display names) is preserved where it does not
  conflict with schema semantics.
- U3 — Integration: the edit round trip now covers the generic editor path
  with a Postal Address textarea against a real LDAP backend, the
  schema-MUST marker on a template-driven form, and the unchanged-submit
  short-circuit.
- U4 — Docs: README features/API rows describe schema-driven control
  rendering.
- U6 — Clear/delete semantics + no-fabrication selects: removing every
  multi-value row now deletes the attribute (previously a silent no-op);
  booleans and picklist selects always offer "(not set)" so untouched submits
  cannot browser-default a value into existence; schema-MUST attributes can
  never be cleared (server-enforced with an inline error).
- U5 — Add/delete attributes: the edit form offers an "Add attribute" picker
  fed by the entry's effective objectClass MUST/MAY set and a per-attribute
  "Delete attribute" action (MAY/schema-unknown only), both round-tripping
  through review → apply.
- U9 — ObjectClass add/remove: edit forms list the entry's object classes;
  AUXILIARY classes can be added, value-less auxiliary classes can be
  removed, and STRUCTURAL/ABSTRACT classes are protected; changes apply as a
  full-set Replace through review → apply.
- U7 — Binary upload replace: binary-syntax attributes keep their read-only
  display (photo previews preserved) and gain a file upload that replaces the
  value set, staged server-side between review and apply (size-capped,
  token-scoped, cleaned up after apply).
- U10 — Leaf-only delete: entries with children cannot be deleted (the
  recursive/typed-DN paths are removed); children must be removed first.
- U11 — Password gating: the Change password action and `/password` route are
  only available for entries that have a `userPassword` attribute.

## Entry edit + search completion (2026-08-26)

- U1 — Entry edit form: `GET /api/entry/{dn...}/edit` renders a prefilled
  form from the best-matching `templates/modification/*.xml` template
  (custom `templates_dir` first, most-specific objectClass match, `?template=`
  override) with a generic attribute editor fallback. Multi-value attributes
  render one input per value with add/remove controls; `userPassword` renders
  `[redacted]` with an F3 link; RDN attributes and `objectClass` render
  read-only; operational attributes are excluded.
- U2 — Edit diff + apply: `POST /edit` with `stage=review` renders an
  old→new table (phpLDAPadmin parity, stateless hidden-input round trip);
  `stage=apply` builds `Replace`/`Delete` changes (full value sets, cleared
  attributes deleted, unchanged skipped — no LDAP call on a no-op), audits
  `event=ldap.modify` with `op_type=modify`, emits `X-Mutated-Subtree`, and
  re-renders the form with inline errors on LDAP rejection.
- U3 — Detail-page entry points: the actions list gains "Edit attributes"
  naming the matched template or the generic editor; the `userPassword` row
  keeps its F3 link.
- U4 — Search R4 completion: `scope=base|one|subtree|global` (unknown → 400),
  sortable columns (`sort=dn|objectclass|modified`, `dir=asc|desc`) via an
  RFC 2891 server-side sort control with per-page client-sort fallback,
  `size_limit`/`time_limit`, and comma-separated `attrs` rendered as extra
  result columns. `SearchOptions` gains optional `Sort`; tree/export paths are
  unchanged when it is unset.
- U5 — Integration: package-level edit round trip (form → review → apply →
  re-fetch) and an F1–F8 harness flow covering detail→edit→review→apply,
  base/one-level scopes, DN-desc sort, and the modified-sort fallback against
  a real directory.
- Media rendering: `jpegPhoto` renders as an inline image via a new
  `GET /api/entry/{dn...}/photo?idx=N` endpoint (raw octets or base64 text,
  JPEG/PNG/GIF/WebP sniffed by magic bytes; never echoed as raw page text)
  and `avatarPath` renders directly as an `<img>`; the edit form shows
  thumbnails for both, with `jpegPhoto` kept read-only. Tree labels now link
  to the entry detail page, and search column headers are visibly clickable.
- Review pass (Tier 2, ce-code-review 20260827-004931): the template-path
  edit fields now exclude `userPassword` and operational attributes (custom
  templates cannot leak a stored hash) and render binary values read-only;
  the chosen modification template round-trips through review/apply as a
  hidden field so a forced `?template=` survives the two-step flow;
  duplicated submitted values are deduped; sort-fallback pages state that
  ordering applies within the page; size/time limits are documented as
  per-request.

## Session DB path fallback (2026-08-26)

- When `LDAPADM_DB_PATH` is unset and the default `/var/lib/ldapact`
  directory does not exist, the session store now falls back to
  `~/.local/state/ldapact/sessions.db` (XDG-style per-user path) so
  unprivileged, dev, and container runs need no pre-created system directory.
  The same fallback applies when the variable is explicitly set to the
  default value (e.g. sample env files); other explicit paths are unchanged.
- `session.NewStore` creates the parent directory (mode 0700) only when it is
  missing; an existing (even unstat-able) directory is never re-created, so
  deployments with an explicit `LDAPADM_DB_PATH` are unchanged.
- The resolved path is logged at startup (`db_path`).

## Env-driven configuration migration (2026-08-26)

- `pkg/config` now loads the full profile from `LDAPADM_*` environment
  variables via kelseyhightower/envconfig v1.4.0; the YAML config file and the
  `-config` flag are removed (**breaking** for anything that scripts startup).
- Flat env naming for every non-secret field (see the README reference
  table); the four previously shipped names — `LDAPADM_LISTEN`,
  `LDAPADM_URL`, `LDAPADM_BASE_DN`, `LDAPADM_BIND_DN` — are unchanged.
- Unknown `LDAPADM_*` variables fail fast at startup (typo guard); set-but-
  empty variables are treated as unset so defaults still apply.
- Secrets unchanged: env → 0600 file → TTY resolver; never parsed from the
  environment and never logged.
- Docker, k8s, and systemd artifacts plus `make run` are env-driven; systemd
  reads non-secret config from `/etc/default/ldapact` via
  `EnvironmentFile`, and the bind Secret / `LoadCredential` mounts plus
  `LDAPADM_BIND_PASSWORD_FILE` stay.
- Added `.env.example` with the full variable set for local development.

## U1 — Project skeleton, config, secret resolver, slog, security headers, CSRF

- Go module `github.com/liut/ldapact` with `cmd/ldapact` single-binary entry
  point (CGO_ENABLED=0 build via Makefile).
- Strict YAML server profile (`pkg/config`) with R12 validation: TLS floor
  TLSv1.2, verify mandatory, StartTLS defaults on for `ldap://`, session
  timeout ranges, pool size, tree filter.
- Environment variable overrides for the runtime profile fields:
  `LDAPADM_LISTEN`, `LDAPADM_URL`, `LDAPADM_BASE_DN`, `LDAPADM_BIND_DN`
  (non-empty env wins over YAML; empty env is ignored).
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

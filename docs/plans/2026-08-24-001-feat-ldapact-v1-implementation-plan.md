---
title: ldapact v1 — Go reimplementation of phpLDAPadmin
type: feat
status: active
date: 2026-08-24
origin: docs/brainstorms/ldapact-go-reimplementation.md
---

# ldapact v1 — Go reimplementation of phpLDAPadmin

## Summary

Plan implements the v1 scope from the brainstorm doc (Hybrid Spine architecture: Go-idiomatic core + retained XML template parsing) at 8 implementation units in dependency order. The plan commits to specific Go libraries (go-ldap/ldap v3, stdlib net/http, HTMX 2, html/template, bbolt, slog, yaml.v3, x/crypto + GehirnInc/crypt, embed) and resolves every "Deferred to Planning" item rather than re-bouncing them to the user.

## Problem Frame

Enterprise IT teams running phpLDAPadmin 1.2.5 hit a deployment blocker in new environments that lack PHP runtimes. The current target audience cannot move forward with the existing PHP tool, but replacing it with a from-scratch Go tool risks losing daily-admin workflow parity. This plan delivers the parity replacement on a Go-native spine while preserving the XML template engine so existing custom templates keep working. (See origin doc for the full situational narrative.)

## Requirements

This plan implements the v1 requirements from the origin doc. R-IDs are carried over verbatim from origin so traceability is preserved.

**Origin actors:** A1 (LDAP admin), A2 (LDAP application owner), A3 (ops/platform engineer), A4 (future auditor, v2).
**Origin flows:** F1 (browse tree), F2 (create POSIX account), F3 (change password), F4 (LDIF import), F5 (delete entry), F6 (rename/move), F7 (export LDIF), F8 (search).
**Origin acceptance examples:** AE1 (auto-bind + tree render), AE2 (5000-child paged tree), AE3 (posixAccount form parity), AE4 (SSHA password change), AE5 (LDIF partial-success), AE6 (slog redaction), AE7 (30-min session expiry).

The plan satisfies:
- All eighteen main requirements (LDAP/Schema/Password/LDIF/Config/Architecture) including sub-items R5.x, R8.x, R8.y and the new R18 (WCAG).
- All eight flows above with the explicit UX states enumerated in the origin doc.
- The seven acceptance examples with their explicit setup-action-outcome structure.

## Scope Boundaries

**v1 in scope** (origin doc carried verbatim):
- Single-server configuration; one admin bind DN with server-side session model.
- LDAP simple bind + SASL bind; StartTLS only; TLS 1.2 floor.
- Tree browse, schema browse, template-driven create, password change, LDIF import/export, search, delete, rename/move.
- Smoke test of all F1-F8 with assertions matching AE1-AE7.
- XML template parser compatible with phpLDAPadmin `templates/template.dtd` for v1 templates (inetOrgPerson, posixAccount, posixGroup) and custom loads from a server-profile directory.
- Structured logging via slog JSON to stdout, with `userPassword` redaction at the handler.

### Deferred to Follow-Up Work

- **Plan-level work split to a separate future plan:** A2 actor flows (template visibility configuration, bind credential rotation, BaseDN change UI) — origin doc carries these as an outstanding question. The current plan includes A2's bind profile as a server-side config but no UI.
- **Plan-level work split to a separate future plan:** A4 audit log read UI — origin defers this to v2 audit product. The current plan instruments all write operations per R15 but does not surface an A4-readable UI.
- **Plan-level work split to a separate future plan:** XML→YAML template migration tooling for v2 — origin defers this. The current plan reads XML only.
- **Plan-level work split to a separate future plan:** Microsoft Active Directory `unicodePwd` attribute support — origin keeps this out of R9. The current plan supports `userPassword` only (RFC 2307 scheme prefix), and the AD MD4 hash works for `userPassword` only.

### Outside this product's identity

Origin doc carries these; reproduced here for reviewer convenience. The plan does not build:
- A general-purpose LDAP client library (the LDAP layer in this plan is admin-tool-specific and not exported).
- An LDAP server implementation.
- A user-facing self-service password reset portal (this is an admin tool).
- Samba templates, batch ops, multi-server profile UI, SSO, audit product, i18n, schema extension tools, CLI/TUI, gRPC proxy.

## Context & Research

### Relevant Code and Patterns

The Go repository at `/Users/liutao/gocode/src/github.com/liut/ldapact/` is empty except for `.git` and `.claude/settings.local.json`. No Go conventions exist yet; this plan establishes them:

- `gofmt` + `go vet` + `staticcheck` for formatting/static analysis.
- Wrapped errors via `fmt.Errorf("...: %w", err)`; sentinel errors declared in each package.
- `testing` (stdlib) for unit tests; `testify/require` reserved for assertion clarity in integration tests.
- `log/slog` for structured logging; JSON handler.
- Conventional commits (no `Co-Authored-By` trailer per global CLAUDE.md).

The PHP reference source at `~/Sites/phpLDAPadmin/` is the compatibility oracle for template engine parity. The plan reads but does not modify it. Key PHP files referenced by this plan (not modified, only studied):

- `lib/Tree.php`, `lib/TreeItem.php` — informs the on-demand tree browse decision (no cache).
- `lib/ds_ldap.php`, `lib/ds.php` — informs the LDAP abstraction surface.
- `lib/Template.php`, `lib/TemplateRender.php`, `lib/xmlTemplates.php`, `lib/xml2array.php` — the template engine being ported.
- `lib/template_functions.php` (referenced via `lib/TemplateRender.php` calls) — the macro function registry.
- `lib/functions.php` — `get_next_number` (search/pool modes), `password_types()` (the 13-scheme list), `auto_number.dn/auto_number.pass` rebind.
- `lib/createlm.php`, `lib/blowfish.php` — explicitly NOT ported (Samba deferred).
- `htdocs/cmd.php` and `htdocs/*.php` — the 60+ entry points being collapsed to ~12 REST routes.
- `templates/template.dtd` and `templates/creation/*.xml` — the template corpus.

The plan's per-unit **Patterns to follow** sections name specific PHP files when behavior must be preserved.

### Institutional Learnings

None — this is a greenfield repo with no `docs/solutions/`, `MEMORY.md`, `STRATEGY.md`, or `AGENTS.md`. The plan treats the origin brainstorm as the single source of truth. Future work should populate `docs/solutions/` from the post-implementation review.

### External References

- OWASP Password Storage Cheat Sheet (2026) — drove the password floor decision (Key Technical Decisions #3).
- OWASP Session Management Cheat Sheet (2026) — drove the absolute-timeout and `__Host-` cookie prefix additions (Key Technical Decisions #4).
- OWASP HTTP Headers Cheat Sheet / Secure Headers Project — drove the security response headers default (Key Technical Decisions #6).
- W3C ARIA Authoring Practices — Tree View pattern — drove the tree browser ARIA attribute set (Key Technical Decisions #7).
- go-ldap/ldap v3.4.14 documentation (pkg.go.dev, GitHub release notes) — drove the LDAP layer API choices (Unit U2).

## Key Technical Decisions

The origin doc carries the product-level decisions. This section records the plan-level architectural choices — most of them driven by Phase 1 research and surfaced as defaults for items the doc still flagged as "Deferred to Planning".

1. **Go module path: `github.com/liut/ldapact`.** Repository name on disk matches; module path canonicalized to the user's GitHub handle.

2. **Single binary with `CGO_ENABLED=0`.** All native deps are pure Go or self-rolled; no cgo needed. Static binary deploys via container, systemd, or bare metal.

3. **HTTP routing: stdlib `net/http.ServeMux` (Go 1.22+) with `PathValue` + method-based patterns.** ~12 routes total; no middleware chain idiom needed at this size. If routes exceed ~30 in a future iteration, migrate to `chi` (mechanical).

4. **LDAP library: `github.com/go-ldap/ldap/v3` v3.4.14.** The only actively maintained option in 2026. `nmcclain/ldap` is unmaintained. The plan wraps the library with a hand-rolled `chan *ldap.Conn` pool (~80 LOC) since the library ships no native pool.

5. **Connection pool design (driven by best-practices research):**
   - `DialWithDialer{Dialer: net.Dialer{KeepAlive: 30*time.Second, Timeout: 5*time.Second}}` + `DialWithTLSConfig(...)`.
   - Validate-on-Put: `Search(ScopeBaseObject, "(objectClass=*)", limit=1, timeLimit=5s)`; drop on error.
   - Retry policy: any op retryable once on `ErrorNetwork`/`ErrorServerDown` with exponential backoff (50ms, 200ms, cap 2s).
   - Health-check goroutine pings each conn every 30s.
   - Honor `r.Context()` and call `conn.Abandon(msgID)` on cancel.
   - **Independent auto-number bind pool:** a second small pool (size 1-2) using the server profile's `auto_number_dn/auto_number_password` so the admin bind is not interrupted by `GetNextNumber` operations.

6. **Password algorithm floor (driven by OWASP 2026 + LDAP RFC 2307):**
   - **Write whitelist (preferred):** `{SSHA512}`, `{SSHA256}`, `{SSHA}`, `{SHA512}`, `{SHA256}`, `{ARGON2}$argon2id$…` for OpenLDAP/389-DS, `{MD4}` (UTF-16LE) for AD-mode only.
   - **Read support:** all of the above plus `{MD5}`, `{SHA}`, `{CRYPT}`, `{BLOWFISH}` (read-only verification of legacy entries).
   - **Reject:** `{PLAIN}` from new writes unless explicit server-profile override is set, in which case a structured `warn` log line is emitted.
   - **Implementation:**
     - SSHA family: self-rolled with `crypto/sha1|sha256|sha512` + 16-byte random salt + base64. ~30 LOC per scheme.
     - `GehirnInc/crypt` for `{SHA256CRYPT}`, `{SHA512CRYPT}`, `{MD5CRYPT}` (pin commit hash in `go.sum`; pre-1.0 module).
     - `golang.org/x/crypto/bcrypt` for `{BLOWFISH}` ($2a$ — note LDAP server must support `{CRYPT}` scheme to bind on).
     - `golang.org/x/crypto/md4` for `{MD4}`.
     - `github.com/alexedwards/argon2id` for `{ARGON2ID}`.
   - **Defer to v2:** `{EXT_DES}` (no clean third-party Go implementation; rare in modern deployments).
   - This supersedes the origin doc's R9 list. The plan applies the demotion in code; the origin doc remains the v1 contract and will be updated at v1 close to reflect the final write whitelist.

7. **Session store: `go.etcd.io/bbolt` v1.5.0 at `/var/lib/ldapact/sessions.db` (mode 0600).** Single file, ACID, survives restart. Sweep goroutine removes expired entries every 5 minutes. Pinned to 0600 by the same secret resolver used for bind passwords.

8. **Cookie & session security (driven by OWASP 2026):**
   - Cookie name: `__Host-LDAPADM_SID` (the `__Host-` prefix forces `Secure=true; Path=/; no Domain attribute`).
   - Session ID: 32 bytes from `crypto/rand`, base64url-encoded (≥ 256 bits entropy).
   - **Rotation:** on every bind success and on every state-changing operation completed.
   - **Idle timeout:** 30 min default, configurable 5 min – 4 h.
   - **Absolute timeout: 8 h default, configurable** (NEW — not in origin doc R13; added per OWASP "renew session ID on privilege change" guidance).
   - **Storage:** server-side keyed map in bbolt; cookie holds only the random opaque ID.

9. **CSRF defense: `SameSite=Strict` + Origin-header check on state-changing methods.** Per OWASP 2026, `SameSite=Strict` alone is acceptable when the deployment model is loopback / internal VPN / mTLS-fronted (origin doc's C1 current decision). The Origin-header check is a 1-line middleware that rejects POST/PUT/PATCH/DELETE on `Origin` mismatch — belt-and-suspenders for older browsers without `SameSite` enforcement. No synchronizer tokens, no double-submit cookies, no JWT.

10. **TLS for LDAP (driven by RFC 4513 + OWASP):**
    - `MinVersion: tls.VersionTLS12`; StartTLS via `ldaps://` URL treated as StartTLS-by-default.
    - StartTLS failures are **fatal** (no silent fallback to plaintext).
    - Hostname verification via SAN (Go does this by default if `ServerName` matches).
    - On startup: verify cert chain, parse `NotAfter`, log warning if expiry < 30 days, refuse to start if expired.
    - Cipher policy: don't set `CipherSuites` (defaults are ECDHE-only on Go ≥1.22).
    - No certificate pinning (rely on chain + hostname verification).
    - Reject `verify=off` in config (parse-time fatal).

11. **Web UI: HTMX 2.0.x served from embedded `static/htmx.min.js`** + small CSS for tree/form/error states. Stdlib `html/template` for the Go-rendered shell (layout, tree scaffold, entry detail, error pages). XML template layer keeps its own parser. ~14 KB HTMX overhead; no build step.

12. **Structured logging via `log/slog` + JSONHandler + ReplaceAttr redaction.** Redaction runs at the handler boundary so every code path that calls `slog.Info(..., "userPassword", val)` is scrubbed. Belt-and-suspenders: also wrap call sites with a typed helper `audit.Attr(name, val)` that constructs a `slog.Attr` named-`userPassword` is silently dropped.

13. **Security response headers middleware (driven by OWASP Secure Headers Project):**
    - `Strict-Transport-Security: max-age=63072000; includeSubDomains` (only sent when HTTPS).
    - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'`. Ship initially as `Content-Security-Policy-Report-Only` for one week of observation, then enforce.
    - `X-Frame-Options: DENY` (legacy browser defense in depth).
    - `X-Content-Type-Options: nosniff`.
    - `Referrer-Policy: no-referrer`.
    - `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`.
    - `Cache-Control: no-store` on session-authenticated responses; `public, max-age=300` on `/static/*` assets.

14. **WCAG 2.1 AA accessibility for tree (driven by W3C ARIA APG):** Full `role="tree"` / `role="treeitem"` / `role="group"` structure with `aria-expanded`, `aria-level`, `aria-setsize`, `aria-posinset`, `aria-selected`; roving `tabindex` (only focused item is `tabindex="0"`); `aria-busy="true"` while children are loading; `aria-live="polite"` status region announces "N children loaded" after paged search returns; left/right/up/down/home/end/enter keys all wired. Multi-page form (F2): `role="region"` per step with `aria-labelledby`, `aria-current="step"` on the active step. Confirmation modals (F5 delete): focus trap, `role="dialog"` with `aria-labelledby` + `aria-describedby`, ESC closes, focus restored to trigger on close. Skip link to main content; visible `:focus-visible` rings. Honors `prefers-reduced-motion`. Touch targets ≥ 24×24 CSS px.

15. **Template parser regression corpus (origin doc outstanding question):** The plan uses phpLDAPadmin's 3 built-in templates (`posixAccount`, `inetOrgPerson`, `posixGroup`) plus 5-10 templates from `~/Sites/phpLDAPadmin/templates/creation/*.xml`. Broader corpus requires user-supplied fixtures post-v1.

16. **Embed strategy:** `//go:embed all:static all:templates` in an `assets.go` file at the package root; `fs.Sub(assetsFS, "static")` exposes the static dir; `http.FileServerFS(subFS)` mounts at `/static/`. Dev mode (`//go:build dev`) uses `os.DirFS("static")` for live reload during development.

17. **GOTRACEBACK=none + RLIMIT_CORE=0 in `main()`.** Disable core dumps so secrets don't leak via crash artifacts. Document in deployment guide.

## Open Questions

### Resolved During Planning

All "Deferred to Planning" items from the origin doc are resolved into Key Technical Decisions above. Specifically:

- LDAP library (origin deferred): `go-ldap/ldap/v3` v3.4.14. (KTD #4)
- HTTP router (origin deferred): stdlib `net/http.ServeMux`. (KTD #3)
- Session store (origin deferred): `go.etcd.io/bbolt`. (KTD #7)
- Web UI (origin outstanding question): HTMX 2.0.x + stdlib `html/template`. (KTD #11)
- Config format (origin gave YAML/TOML choice): YAML via `gopkg.in/yaml.v3` with strict `KnownFields`. (KTD implied)
- Tree pagination default (origin suggested 100): 100 per paged search; UI shows "Load more" or virtualizes after threshold (deferred to implementation in U5).
- Schema UX (origin outstanding question): R5.x navigation is in v1; R5 schema filter UI is v2.
- Template macro full set (origin outstanding question): all R8-enumerated macros are in v1 with PHP parity.
- Web UI tech stack (origin outstanding question "Lock HTMX?"): locked to HTMX 2.0.x. (KTD #11)
- R15 actor field semantics (origin outstanding question): `actor = bind DN used for the operation`. Matches AE6.

### Deferred to Implementation

- **Exact method signatures** for `ServerProfile` struct fields and LDAP layer interface methods — settled during U1 (config) and U2 (LDAP) implementation.
- **Specific Go function signatures** for the macro functions (`PickList`, `GetNextNumber`, etc.) — settled during U6 implementation.
- **`autoFill` JS emitter output format** — the per-attribute JS fragment shape is decided during U6 implementation; only the documented `%var|substart-end/modifier%` token grammar is fixed.
- **gzip pre-compression for static assets** — `klauspost/compress` middleware or build-time `gzip -9`; decided during U8 implementation.

## Output Structure

The plan creates a new Go module from scratch. Expected directory tree at v1 completion (~100 files across 8 units):

```
ldapact/
├── go.mod
├── go.sum
├── README.md
├── OPERATIONS.md
├── Makefile
├── cmd/
│   └── ldapact/
│       └── main.go                      (U1)
├── pkg/
│   ├── config/
│   │   ├── config.go                   (U1)
│   │   ├── secret.go                   (U1: secret resolver)
│   │   └── config_test.go
│   ├── logging/
│   │   ├── logger.go                   (U1: slog + redaction)
│   │   └── logger_test.go
│   ├── ldapx/                          (U2: LDAP abstraction layer)
│   │   ├── conn.go                     (DialWithDialer/TLSConfig)
│   │   ├── pool.go                     (chan-based pool)
│   │   ├── bind.go                     (simple + SASL + rebind)
│   │   ├── search.go                   (paged search wrapper)
│   │   ├── schema.go                   (subschema fetch + cache)
│   │   ├── crud.go                     (Add/Modify/Delete/ModifyDN)
│   │   ├── modify_password.go          (PasswordModify)
│   │   ├── errors.go                   (LDAPError type with LogValuer)
│   │   └── *_test.go
│   ├── session/                        (U3)
│   │   ├── store.go                    (bbolt-backed)
│   │   ├── cookie.go                   (cookie read/write)
│   │   ├── rotation.go                 (session ID rotation)
│   │   ├── sweep.go                    (TTL sweeper goroutine)
│   │   └── *_test.go
│   ├── authn/                          (U3)
│   │   ├── middleware.go               (session bind check)
│   │   ├── csrf.go                     (Origin-header check)
│   │   └── *_test.go
│   ├── secheaders/                     (U1)
│   │   ├── middleware.go
│   │   └── middleware_test.go
│   ├── web/                            (U4: HTML template infrastructure)
│   │   ├── templates.go                (html/template ParseFS)
│   │   ├── funcs.go                    (FuncMap registration)
│   │   ├── render.go                   (partial render helpers)
│   │   └── *_test.go
│   ├── tree/                           (U5)
│   │   ├── browse.go                   (F1 handlers)
│   │   ├── schema.go                   (R5 handlers)
│   │   ├── fragments.go                (HTMX template fragments)
│   │   └── *_test.go
│   ├── entry/                          (U6)
│   │   ├── detail.go                   (F-Detail handler)
│   │   ├── create.go                   (F2 handler)
│   │   ├── password.go                 (F3 handler)
│   │   ├── delete.go                   (F5 handler)
│   │   ├── rename.go                   (F6 handler)
│   │   └── *_test.go
│   ├── ldif/                           (U7)
│   │   ├── parser.go                   (RFC 2849 streaming)
│   │   ├── writer.go                   (RFC 2849 with base64)
│   │   ├── import.go                   (F4 handler)
│   │   ├── export.go                   (F7 handler)
│   │   └── *_test.go
│   ├── search/                         (U7)
│   │   ├── handler.go                  (F8)
│   │   └── handler_test.go
│   ├── tplengine/                      (U6: XML template parser + macros)
│   │   ├── parser.go                   (encoding/xml + DTD walker)
│   │   ├── model.go                    (typed Template struct)
│   │   ├── macros_server.go            (PickList, GetNextNumber, ...)
│   │   ├── macros_client.go            (autoFill → JS emitter)
│   │   ├── password.go                 (PasswordEncrypt dispatcher)
│   │   ├── fixtures/                   (parser regression corpus)
│   │   │   ├── posixAccount.xml
│   │   │   ├── inetOrgPerson.xml
│   │   │   ├── posixGroup.xml
│   │   │   ├── alias.xml
│   │   │   ├── customAccount.xml
│   │   │   ├── dNSDomain.xml
│   │   │   ├── organizationalRole.xml
│   │   │   ├── ou.xml
│   │   │   └── simpleSecurityObject.xml
│   │   └── *_test.go
│   └── assets/
│       ├── assets.go                   (//go:embed)
│       ├── assets_dev.go               (//go:build dev → os.DirFS)
│       └── static/
│           ├── htmx.min.js              (HTMX 2.0.x)
│           ├── css/
│           │   ├── main.css
│           │   ├── tree.css
│           │   └── forms.css
│           └── js/
│               ├── tree-keys.js         (ARIA tree keyboard nav)
│               └── autofill.js          (client-side macro runtime)
├── templates/                          (XML template corpus, also embed)
│   ├── template.dtd
│   ├── creation/
│   │   ├── posixAccount.xml
│   │   ├── inetOrgPerson.xml
│   │   └── posixGroup.xml
│   └── modification/
│       ├── inetOrgPerson.xml
│       └── posixGroup.xml
├── config/
│   └── example.yaml                    (sample server profile)
├── test/
│   └── integration/                    (testcontainers-go OpenLDAP)
│       ├── setup_test.go
│       └── flows_test.go               (end-to-end F1-F8)
└── docs/
    ├── brainstorms/
    │   └── ldapact-go-reimplementation.md
    └── plans/
        └── 2026-08-24-001-feat-ldapact-v1-implementation-plan.md
```

This tree is a scope declaration. The implementer may adjust if implementation reveals a better layout.

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

### Request lifecycle (single request, all flows)

```
HTTP request
  ↓
[recover middleware] → panic → slog error + 500
  ↓
[requestID middleware] → assign X-Request-Id
  ↓
[secheaders middleware] → set HSTS / CSP / X-Content-Type-Options / ...
  ↓
[session middleware]
  - read __Host-LDAPADM_SID cookie
  - look up session in bbolt
  - on hit: check idle timeout, check absolute timeout
  - on miss/expired: clear cookie + set session expired action
  - attach session to request context
  ↓
[authn middleware] — bind has been done at startup, so this is a no-op for v1 single-bind
  ↓
[csrf middleware]
  - if POST/PUT/PATCH/DELETE: check Origin header matches Host
  - on mismatch: 403 Forbidden
  ↓
[rate-limit middleware] (U1, simple per-IP cap)
  ↓
[route handler]
  - F1-F8 specific logic
  - emit HTMX fragment or full HTML page
  - on state-changing op: rotate session ID, emit audit slog line with event/dn/op_type/actor
  ↓
HTTP response with security headers + Cache-Control + Content-Type
```

### Paged search state machine (R2, F1, F8)

```
Start search with (base DN, scope, filter, attrs, page size)
  ↓
[Acquire conn from pool]
  ↓
Loop:
  - Build ControlPaging(size)
  - Send Search
  - Collect results + paging cookie
  - If cookie is empty → done
  - If size-limited → page = page + 1, render "Load more" affordance
  - If ErrorNetwork/ErrorServerDown → reconnect + restart from page 1 (best-effort)
  - If context canceled → call conn.Abandon, return partial
  ↓
[Release conn to pool; pool validates on Put]
```

### Session rotation on state-changing operation

```
POST/PUT/PATCH/DELETE handler completes
  ↓
[middleware] — after handler returns 2xx:
  - mint new session ID via crypto/rand 32 bytes
  - copy session value to new ID in bbolt
  - delete old session entry
  - set new cookie with new ID + __Host- prefix
  - emit audit slog with new session ID, op, dn
  ↓
[response sent]
```

This rotation is automatic for any state-changing route; the handler does not call it explicitly.

### XML template parser (R7)

The parser uses `encoding/xml` for structure and a small DTD-aware walker to enforce the typed model. It is **not** a PHP runtime: macro references like `=php.PasswordEncrypt(%enc%;%userPassword%)` are parsed into an AST node referencing a `FuncRef` from the allowlist; unknown functions produce a parse-time error (not a runtime fallback).

```
XML file
  ↓
encoding/xml → raw tree
  ↓
DTD-aware walker:
  - <attribute id="..."> → Attribute{ ID, Kind, ... }
  - <value id="...">X</value> → Value{ ID, Display }
  - <post>=php.Foo(args)</post> → PostHook{ Ref, Args }
  - <onchange>=autoFill(target;template)</onchange> → OnChangeJS{ Target, Template }
  ↓
Typed Template{ ObjectClasses, RDN, Pages, Attributes, ... }
  ↓
Schema validator:
  - drop attributes absent from subschema
  - canonicalize attribute names
  - validate RDN
  - sort attributes by order
  ↓
Render:
  - For each page, html/template.Execute("page-N")
  - macro funcs registered via FuncMap
  - OnChange fragments emitted into per-attribute <script>
```

### Cross-flow tree consistency (per U5 F1 + U6 F2/F5/F6 mutation responses)

After F2/F5/F6 mutation, the response carries `X-Mutated-Subtree: <base DN>` header. The client-side JS (in `static/js/tree-keys.js`) reads this header and triggers a re-fetch of that subtree on the next focus. No SSE/WebSocket in v1.

## Implementation Units

### U1. Project skeleton, config, secret resolver, slog, security headers, CSRF middleware

**Goal:** Establish the Go module, CLI entry point, config loader, secret resolver, structured logging with redaction, security response headers middleware, CSRF Origin-header middleware. The app starts and responds with a "hello" page; it has no functional LDAP or session yet.

**Requirements:** R12 (config skeleton + secret resolver), R17 (single binary + embedded resources placeholder), R15 (slog with redaction).

**Dependencies:** None.

**Files:**
- Create: `go.mod`, `go.sum`
- Create: `cmd/ldapact/main.go`
- Create: `pkg/config/config.go`
- Create: `pkg/config/secret.go`
- Create: `pkg/config/config_test.go`
- Create: `pkg/logging/logger.go`
- Create: `pkg/logging/logger_test.go`
- Create: `pkg/secheaders/middleware.go`
- Create: `pkg/secheaders/middleware_test.go`
- Create: `pkg/authn/csrf.go`
- Create: `pkg/authn/csrf_test.go`
- Create: `pkg/assets/assets.go` (with `//go:embed` stubs that point at placeholder dirs)
- Create: `config/example.yaml`

**Approach:**
- `gofmt` + `go vet` + `staticcheck` wired into `Makefile` as the `make lint` target.
- Config struct uses `yaml:"..."` tags with `yaml.KnownFields(true)` strict mode; unmarshal fails on unknown keys.
- Secret resolver implements `func ResolveSecret(name string) (string, error)` with chain order: env var `<NAME>` → file path env var `<NAME>_FILE` (verify mode 0600) → TTY prompt. Returns errors that include the chain attempted but never the secret value.
- `main.go` calls `os.Setenv("GOTRACEBACK", "none")` and `syscall.Setrlimit(RLIMIT_CORE, ...)` early.
- Logger uses `slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: levelVar, ReplaceAttr: redactFn})`; level var initialized from `LDAPADM_LOG_LEVEL` env.
- Redaction `ReplaceAttr` drops `slog.Attr` whose key is `userPassword` or ends in `_password`/`Password`.
- Security headers middleware emits the headers listed in KTD #13. CSP is initially `Content-Security-Policy-Report-Only` until KTD review date.
- CSRF middleware inspects `r.Header.Get("Origin")` for state-changing methods and compares to `r.Host`; reject on mismatch with 403.

**Execution note:** Implement test-first for the secret resolver — its chain semantics are easy to get wrong.

**Patterns to follow:** Secret resolver chain mirrors `~/Sites/phpLDAPadmin/lib/session_functions.php` lines 76-174 conceptually, but replaces file/TTY transport with Go-native.

**Test scenarios:**
- Happy path: `LDAPADM_BIND_PASSWORD=foo` env var resolves; `LDAPADM_BIND_PASSWORD_FILE=/tmp/pwd` with mode 0600 resolves; TTY prompt returns entered string.
- Edge case: env var unset + file env var unset → TTY prompt fallback; TTY unavailable returns error.
- Edge case: file mode 0644 → startup aborts with explicit error message naming the file path.
- Edge case: missing secret (no env, no file, no TTY) → startup aborts; CI run fails fast.
- Error path: secret resolver log line uses truncated fingerprint only (first 4 + last 2 chars or SHA-256 hex first 8 bytes); assert log output never contains the full secret.
- Integration: app starts with config file, responds with `200 OK` on `/healthz`; response carries `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` headers.
- Integration: `POST /test-state-changing` with `Origin: http://attacker.com` returns `403 Forbidden`; with `Origin: http://localhost:8080` (matching Host) returns `200 OK`.

**Verification:**
- `go build ./...` produces a single binary at `bin/ldapact` with `CGO_ENABLED=0`.
- `bin/ldapact --version` prints the version string.
- `bin/ldapact -config config/example.yaml` starts and listens on `:8080`; `curl -i http://localhost:8080/healthz` returns 200 with the security headers.
- `make test` passes; coverage on the secret resolver package ≥ 90%.

---

### U2. LDAP abstraction layer (pool, schema, CRUD)

**Goal:** Implement the LDAP abstraction layer with a hand-rolled connection pool, paged search, subschema fetch with process-wide cache, and all write operations. The layer is testable via testcontainers-go OpenLDAP and via a mock backend for unit tests.

**Requirements:** R1 (bind + pool + reconnect), R2 (paged search), R3 (CRUD + modrdn), R5 (subschema), R8 (server macros need LDAP search), R14 (subschema canonicalization at startup, fail-fast).

**Dependencies:** U1.

**Files:**
- Create: `pkg/ldapx/conn.go`
- Create: `pkg/ldapx/pool.go`
- Create: `pkg/ldapx/bind.go`
- Create: `pkg/ldapx/search.go`
- Create: `pkg/ldapx/schema.go`
- Create: `pkg/ldapx/crud.go`
- Create: `pkg/ldapx/modify_password.go`
- Create: `pkg/ldapx/errors.go`
- Create: `pkg/ldapx/conn_test.go`
- Create: `pkg/ldapx/pool_test.go`
- Create: `pkg/ldapx/search_test.go`
- Create: `pkg/ldapx/schema_test.go`
- Create: `pkg/ldapx/crud_test.go`
- Create: `pkg/ldapx/integration_test.go` (testcontainers-go OpenLDAP)

**Approach:**
- `Pool` is a struct holding `chan *ldap.Conn` with capacity `maxOpen` (default 8); `Get()` blocks if empty; `Put()` validates via base-scope search and drops on error.
- Health-check goroutine pings each conn every 30s; drops dead conns.
- Retry policy: any operation that returns `ldap.ErrorNetwork`/`ldap.ErrorServerDown` retries once with backoff (50ms, 200ms).
- Paged search: `SearchWithPaging` or manual `ControlPaging` loop with cookie state; honors `r.Context()` for cancellation via `Abandon`.
- Subschema fetch: at startup, connect, fetch subschema subentry DSN, fetch objectClasses/attributeTypes/ldapSyntaxes/matchingRules, cache in process-wide `sync.Map`. Schema is stable for the process lifetime.
- Auto-number pool: a separate `chan *ldap.Conn` (capacity 1-2) using `auto_number_dn/auto_number_password` from the server profile.
- LDAPError type implements `slog.LogValuer` so structured logs surface LDAP result codes without dumping the full error chain.
- Bind credential memory: store in `*ServerProfile` struct field; zero out after each `Bind` operation if reusing is not needed (per-request bind). For long-lived pool model, keep in struct field; document exposure via `/proc/PID/mem` in OPERATIONS doc.

**Execution note:** Add characterization tests against a real OpenLDAP container first; then refine pool semantics.

**Patterns to follow:** PHP `~/Sites/phpLDAPadmin/lib/ds_ldap.php:121-239` (bind cache keyed by server+method); `lib/ds_ldap.php:1022-1050` (one-level search for tree children).

**Test scenarios:**
- Happy path: simple bind succeeds with correct credentials; subschema fetch returns objectClasses and attributeTypes; paged search returns N pages and stops at empty cookie; Add/Modify/Delete/ModifyDN round-trip an entry.
- Edge case: LDAP server restarts mid-search → pool reconnects and retries once; page 1 restarts.
- Edge case: pool acquires with all conns busy → `Get()` blocks; concurrent caller times out via `r.Context()`.
- Edge case: StartTLS handshake failure → fatal error on startup (no plaintext fallback).
- Error path: invalid credentials → bind returns LDAP error code 49 (invalidCredentials); slog emits `ldap.bind.failed` with masked DN.
- Error path: TLS cert expired → startup aborts with explicit error naming the cert subject.
- Integration (testcontainers-go): connect to a real OpenLDAP 2.6 instance; run all CRUD ops; verify via subsequent search.

**Verification:**
- `make test` passes; integration test suite runs against testcontainers-go OpenLDAP and produces a fresh container per test run.
- Subschema cache is populated on startup (verify via inspection log).
- Pool validation on Put drops ~1% of conns in a chaos test where the LDAP server is killed mid-validation.

---

### U3. Session + authentication middleware

**Goal:** Implement the session store (bbolt-backed), cookie management, session ID rotation, idle + absolute timeout, the auth middleware that enforces session on protected routes. Bind at startup (per AE1) so protected routes don't re-bind.

**Requirements:** R1 (admin bind at startup), R13 (cookie + store + rotation + timeout + session_expired_action).

**Dependencies:** U1, U2.

**Files:**
- Create: `pkg/session/store.go`
- Create: `pkg/session/cookie.go`
- Create: `pkg/session/rotation.go`
- Create: `pkg/session/sweep.go`
- Create: `pkg/session/store_test.go`
- Create: `pkg/session/cookie_test.go`
- Create: `pkg/authn/middleware.go`
- Create: `pkg/authn/middleware_test.go`

**Approach:**
- bbolt schema: bucket `sessions` keyed by session ID; value is JSON `{created_at, last_seen_at, expires_at, profile_ref}`.
- Sweep goroutine runs every 5 minutes; deletes entries where `expires_at < now`.
- Cookie read: parse `__Host-LDAPADM_SID` from `r.Cookie(...)`; reject if missing `Secure` or `Domain` or path != `/`.
- Cookie write: `http.SetCookie(w, &http.Cookie{Name: "__Host-LDAPADM_SID", Value: newID, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 0})` (session cookie, no MaxAge — expires on browser close).
- Session ID rotation: after any state-changing handler returns 2xx, the auth middleware (as a deferred action in the request lifecycle) mints a new ID, copies the session value, deletes the old entry, sets the new cookie.
- Absolute timeout: separate field `absolute_expires_at = created_at + 8h`; checked on every session load.
- Session expired action: `redirect_to_login` (HTTP 302 to `/login?next=...`) or `retry_bind` (try the cached bind DN; on failure redirect to `/login`).
- Bind at startup: in `main.go`, after config load, attempt bind via U2's pool; if bind fails, exit with structured error log. Successful bind populates the pool with one healthy conn.

**Execution note:** Add table-driven tests for cookie security attributes (presence of `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Strict`, absence of `Domain`).

**Patterns to follow:** PHP `~/Sites/phpLDAPadmin/lib/session_functions.php:120-153` (session storage), `lib/session_functions.php:174-200` (cookie handling).

**Test scenarios:**
- Happy path: bind at startup succeeds; session middleware attaches session to request context; protected route handler accesses session via `ctx.Session`.
- Edge case: session ID rotated mid-request — old ID is invalidated, new ID is in the response cookie.
- Edge case: idle timeout 30 min — request after 31 min idle → session cleared, `redirect_to_login` action triggers 302 to `/login?next=/protected`.
- Edge case: absolute timeout 8 h — request after 8.5 h even with recent activity → session cleared.
- Edge case: cookie missing `Secure` attribute → middleware rejects with 400 Bad Request.
- Edge case: cookie has `Domain` attribute → middleware rejects (defeats `__Host-` prefix).
- Error path: bbolt file locked or corrupted → startup aborts; subsequent requests return 503 Service Unavailable (don't crash on transient).
- Integration: full session lifecycle — login → idle reset → rotation → expiry → re-login, all logged with audit events.

**Verification:**
- bbolt file created at `/var/lib/ldapact/sessions.db` with mode 0600; startup fails if mode is wrong.
- Session creation → rotation → deletion all visible in bbolt (`bolt pages` CLI or programmatic check).
- 1000 concurrent sessions don't degrade `Get`/`Put` performance below 1ms p99.
- Sweep goroutine removes expired entries within 5 minutes of expiry.

---

### U4. HTML template infrastructure + embed + ARIA helpers

**Goal:** Establish the Go-side HTML rendering surface (separate from XML templates). Stdlib `html/template` parses from embed.FS; custom FuncMap registers; partial render helpers for HTMX; static assets embedded; CSS/JS for ARIA tree and forms shipped.

**Requirements:** R17 (embed + single binary), R18 (WCAG 2.1 AA — initial accessibility primitives live here).

**Dependencies:** U1.

**Files:**
- Create: `pkg/web/templates.go`
- Create: `pkg/web/funcs.go`
- Create: `pkg/web/render.go`
- Create: `pkg/web/templates_test.go`
- Create: `pkg/web/render_test.go`
- Create: `pkg/assets/assets.go` (extend U1 stub)
- Create: `pkg/assets/assets_dev.go`
- Create: `static/css/main.css`
- Create: `static/css/tree.css`
- Create: `static/css/forms.css`
- Create: `static/js/tree-keys.js`
- Create: `static/js/autofill.js`
- Create: `static/htmx.min.js` (HTMX 2.0.x)
- Create: `templates/template.dtd` (copied from phpLDAPadmin reference)
- Create: `templates/creation/posixAccount.xml` (copied from phpLDAPadmin)
- Create: `templates/creation/inetOrgPerson.xml` (copied from phpLDAPadmin)
- Create: `templates/creation/posixGroup.xml` (copied from phpLDAPadmin)
- Create: `templates/modification/inetOrgPerson.xml`
- Create: `templates/modification/posixGroup.xml`

**Approach:**
- `templates.go` parses named HTML template files (`layout.html`, `tree.html`, `entry-detail.html`, `import-result.html`, etc.) at startup; templates are cached for process lifetime.
- `funcs.go` registers the FuncMap. The FuncMap is initially empty (no macros yet); U6 fills it with the macro registry.
- `render.go` provides `func RenderFragment(w io.Writer, name string, data any) error` that calls `ExecuteTemplate` for partial renders used by HTMX swaps.
- `assets.go` uses `//go:embed all:static all:templates` to embed both static assets and XML templates.
- `tree-keys.js` implements the full ARIA tree keyboard navigation (left/right/up/down/home/end/enter) and roving tabindex.
- `autofill.js` is the runtime for compiled `autoFill` JS fragments (U6 emits these server-side; the JS reads source field changes and updates target fields).
- Skip link, `:focus-visible` rings, `prefers-reduced-motion` honored in CSS.

**Execution note:** Write the ARIA tree keyboard navigation test as a Playwright/integration test against a real browser if feasible; otherwise write a thorough unit test that simulates the keyboard event handlers.

**Patterns to follow:** W3C ARIA APG Tree View pattern; OWASP Secure Headers Project (CSP).

**Test scenarios:**
- Happy path: `RenderFragment(w, "tree-row", data)` writes a `<li role="treeitem">` to `w`.
- Edge case: HTMX fragment with `role="alert"` triggers `aria-live="assertive"` announcement.
- Edge case: focus moves into a freshly-rendered modal and is trapped; ESC closes.
- Error path: missing template name → handler returns 500 Internal Server Error (logged with template name).
- Integration: full page render includes skip link, main content with `role="main"`, footer with `role="contentinfo"`.

**Verification:**
- All named templates parse without error at startup (panic on parse failure with template name).
- Rendered HTML passes `go-html-check` if available, or `html5lib`/`validator` via W3C nu HTML checker in CI.
- axe-core scan on rendered pages finds zero serious or critical violations.
- `go vet ./...` clean; `staticcheck ./...` clean.

---

### U5. Tree browse (F1) + Schema browser (R5)

**Goal:** Implement the tree browser with paged search, full ARIA tree pattern, the four states (loading/empty/deep/error); and the schema browser with objectClass + attribute type list/detail and cross-navigation.

**Requirements:** R2 (paged search), R5 (schema list), R5.x (schema navigation), R18 (WCAG tree).

**Dependencies:** U2 (LDAP), U4 (templates).

**Files:**
- Create: `pkg/tree/browse.go`
- Create: `pkg/tree/schema.go`
- Create: `pkg/tree/fragments.go` (HTMX templates for tree nodes)
- Create: `pkg/tree/breadcrumb.go`
- Create: `pkg/tree/states.go` (loading/empty/deep/error state helpers)
- Create: `pkg/tree/browse_test.go`
- Create: `pkg/tree/schema_test.go`
- Create: `pkg/tree/integration_test.go`

**Approach:**
- Routes:
  - `GET /api/tree/{dn...}/children?page=N` → returns HTMX fragment with child entries (F1).
  - `GET /api/schema/objectclass` → objectClass list page.
  - `GET /api/schema/objectclass/{name}` → objectClass detail page.
  - `GET /api/schema/attribute` → attribute type list page.
  - `GET /api/schema/attribute/{name}` → attribute type detail page.
- Paged search per page request: page size 100 (per deferred question default).
- Tree fragment template uses `role="treeitem"` + `aria-level` + `aria-setsize` + `aria-posinset`; parent nodes have `aria-expanded`.
- Empty branch shows muted `<li>(no children)</li>`; ACL-filtered branches (server returns an empty result with permission hint) show `(inaccessible)` instead.
- Deep state: breadcrumb trail with clickable ancestors; 6+ level collapses middle with ellipsis (click to expand).
- Error state: distinguishes size-limit-exceeded from network failure in inline error.
- Schema detail page renders MUST/MAY attributes (for objectClass) or syntax/matching rule/single-vs-multi (for attribute); both link to the other type's detail page.
- On F2/F5/F6 mutation responses, `X-Mutated-Subtree: <dn>` header; client-side JS reads this and invalidates that subtree on next focus.

**Execution note:** Add a Playwright integration test that loads the tree, expands 3 levels, and asserts ARIA attributes via DOM queries.

**Patterns to follow:** PHP `~/Sites/phpLDAPadmin/htdocs/draw_tree_node.php` (tree rendering), `htdocs/expand.php` (child fetch), `htdocs/schema.php` (schema browser).

**Test scenarios:**
- Happy path: `GET /api/tree/dc=example,dc=com/children?page=1` returns HTMX fragment with up to 100 child entries; response includes `HX-Trigger: subtree-loaded` for OOB swap.
- Edge case: empty branch (DN with no children) → fragment contains `<li role="treeitem">(no children)</li>`.
- Edge case: ACL-filtered branch → fragment contains `<li role="treeitem">(inaccessible)</li>` with `aria-disabled="true"`.
- Edge case: deep tree (10+ level) → breadcrumb shows first 3 ancestors + ellipsis + last 2 ancestors.
- Error path: size-limit-exceeded → fragment contains inline error with `role="alert"` and recovery hint "narrow the filter".
- Error path: LDAP server disconnect mid-fetch → fragment contains retry button; auto-retry once via the pool.
- Integration: schema objectClass detail for `inetOrgPerson` lists `cn`, `sn`, `mail` as MUST; `telephoneNumber` as MAY.

**Verification:**
- End-to-end test against testcontainers-go OpenLDAP: load tree, expand 5 levels, verify ARIA tree pattern via axe-core.
- Schema browser lists all 30+ objectClasses from a default OpenLDAP schema.
- Lighthouse accessibility audit scores ≥ 95 on the tree page.

---

### U6. Template-driven flows (F2 create + F3 password + F5 delete + F6 rename + F-Detail)

**Goal:** Implement the XML template parser + typed Template model, all server macros (PickList, GetNextNumber, MultiList, Join, RandomPassword, HashPassword, Default, DN, Encoded, Escape, Binary, HasMultiples, PasswordEncrypt, PasswordEncryptionTypes), the `autoFill` JS emitter (server-side compilation to per-attribute JS), and the four flows (create, password, delete, rename) plus the implicit F-Detail entry view.

**Requirements:** R6 (template-driven create), R7 (XML template parser compatible with phpLDAPadmin DTD), R8 + R8.x + R8.y (server macros + failure UX), R3 (delete + modrdn), R9 (password encryption whitelist), R10 (export triggers from entry detail — only the trigger lives here, the export logic is U7), R11 (error handling), R15 (audit log on every mutation).

**Dependencies:** U2 (LDAP), U4 (templates).

**Files:**
- Create: `pkg/tplengine/parser.go`
- Create: `pkg/tplengine/model.go`
- Create: `pkg/tplengine/macros_server.go`
- Create: `pkg/tplengine/macros_client.go`
- Create: `pkg/tplengine/password.go`
- Create: `pkg/tplengine/parser_test.go`
- Create: `pkg/tplengine/fixtures/posixAccount.xml`
- Create: `pkg/tplengine/fixtures/inetOrgPerson.xml`
- Create: `pkg/tplengine/fixtures/posixGroup.xml`
- Create: `pkg/tplengine/fixtures/alias.xml`
- Create: `pkg/tplengine/fixtures/customAccount.xml`
- Create: `pkg/tplengine/fixtures/dNSDomain.xml`
- Create: `pkg/tplengine/fixtures/organizationalRole.xml`
- Create: `pkg/tplengine/fixtures/ou.xml`
- Create: `pkg/tplengine/fixtures/simpleSecurityObject.xml`
- Create: `pkg/entry/detail.go`
- Create: `pkg/entry/create.go`
- Create: `pkg/entry/password.go`
- Create: `pkg/entry/delete.go`
- Create: `pkg/entry/rename.go`
- Create: `pkg/entry/detail_test.go`
- Create: `pkg/entry/create_test.go`
- Create: `pkg/entry/password_test.go`
- Create: `pkg/entry/delete_test.go`
- Create: `pkg/entry/rename_test.go`
- Create: `pkg/entry/integration_test.go`

**Approach:**
- XML parser uses `encoding/xml` for the structural walk; a separate validator applies the DTD-aware rules from R7's element list.
- `Template` struct: `ObjectClasses []string`, `RDN string`, `Pages []Page`, `Attributes []Attribute`.
- `Attribute` struct: `ID string`, `Kind AttributeKind`, `Display string`, `HelpText string`, `Order int`, `Page int`, `Readonly bool`, `Hidden bool`, `PostHooks []PostHook`, `OnChangeJS string`, `Helper *Helper`, `Values []Value`.
- Server macros evaluated server-side at template-render time, return typed values plugged into template data.
- `autoFill` macro compiles to a small JS function stored in `OnChangeJS`; the rendered HTML includes `<script>document.addEventListener('change', ...)</script>` that wires up the source→target field updates.
- `GetNextNumber` mode `search`: queries all values under the configured DN, sorts, fills the first gap, honors startmin. Mode `pool`: requires filter to match at most one entry (else error); increments per template config.
- `PickList` with 0 results → renders free-text input with notice; both surface to slog.
- `PasswordEncrypt` is a thin dispatcher into the password package (U2-adjacent or its own).
- F2 multi-page form: server-side state stored in session under a per-form UUID; back button preserves state via session lookup; per-page validation hook (`helper`) + server-side revalidation on Next.
- F3 password change: detect current hash scheme by parsing the existing value's `{SCHEME}` prefix; hash new password per template config; replace via `ModifyRequest.Replace("userPassword", ...)`; check LDAP ppolicy overlay response codes if configured.
- F5 delete: confirmation page echoes DN/RDN/child count; non-leaf deletion requires typed DN confirmation; recursive subtree delete gated by configurable ceiling (default 1000 entries).
- F6 rename: modrdn with new RDN + optional new superior DN (cross-naming-context support per RFC 4511 §4.9 modrdn semantics); validation of target parent existence.
- F-Detail: entry detail view from tree click / search result click → renders attribute table with values; "edit" affordance opens modify form per attribute.
- All state-changing operations emit audit log line per R15; userPassword value NEVER appears in any log field.

**Execution note:** The XML parser regression corpus test is the single most important quality gate for this unit — it must pass against all 8 built-in templates unmodified.

**Patterns to follow:** PHP `~/Sites/phpLDAPadmin/lib/Template.php:140-220` (template storage + schema validation), `lib/TemplateRender.php:155-228` (GetNextNumber), `:231-391` (PickList/MultiList), `lib/functions.php:1445-1453` (auto_number rebind).

**Test scenarios:**
- Happy path: parse `posixAccount.xml`, render form HTML, verify field order matches template's `order` attribute.
- Edge case: template with unknown macro reference (`=php.UnknownFunc(...)`) → parser fails at template-load time with named error.
- Happy path: F2 form submit with all required fields → server hashes password with `SSHA512` per template config → LDAP add succeeds → entry created with `objectClass` = `[posixAccount, inetOrgPerson]`.
- Edge case: PickList returns 0 results → form renders the gidNumber field as free-text input with "未找到候选" notice; submission succeeds.
- Edge case: GetNextNumber hits configured max (uidNumber ceiling 65535) → form shows blocking notice; manual override allowed.
- Happy path: F3 password change with current `SSHA` hash → new password `NewPass#2026` hashed with `SSHA512` per template → `LDAP bind as user with NewPass#2026` succeeds.
- Edge case: ppolicy reject (password too short) → form shows inline error citing LDAP result code 53 (insufficientQuality).
- Happy path: F5 delete leaf entry → confirmation page → submit → entry removed from LDAP; tree refreshes.
- Edge case: F5 delete non-leaf entry without recursive flag → confirmation page shows child count; submit blocked unless user types the DN.
- Happy path: F6 rename within same parent (RDN change only) → modrdn succeeds; tree refreshes.
- Happy path: F6 rename with new superior DN (cross-OA move) → modrdn with `newSuperior` succeeds; entry now under new parent.
- Error path: F2 LDAP add fails due to schema violation → form re-renders with inline errors + "rollback" link.
- Error path: F6 target parent DN does not exist → handler returns 400 with explanation.
- Audit log verification: every F2/F3/F5/F6 success emits exactly one slog JSON line with `event` ∈ {`ldap.create`, `ldap.modify`, `ldap.delete`, `ldap.rename`}; no log line contains the string `userPassword`.
- Regression: XML parser passes for all 9 fixture templates (posixAccount, inetOrgPerson, posixGroup, alias, customAccount, dNSDomain, organizationalRole, ou, simpleSecurityObject) without modification.

**Verification:**
- All 9 fixture templates (PHP-built-in + custom) parse and render without error.
- End-to-end F2/F3/F5/F6 against testcontainers-go OpenLDAP with sample data; assertions match AE3 and AE4.
- Static analysis: `staticcheck ./...` reports zero issues for the `tplengine` and `entry` packages.
- Code coverage on `tplengine/parser.go` ≥ 85%; on `tplengine/macros_server.go` ≥ 90% (macros are testable in isolation).

---

### U7. LDIF import/export (F4 + F7) + Search (F8)

**Goal:** Implement the LDIF parser (streaming with size/charset/attribute-count limits), LDIF writer (RFC 2849 base64 for binary attrs), LDIF import handler with per-entry error collection, LDIF export handler with default userPassword redaction and streaming for huge subtrees, and the search handler with scope/filter/sort/pagination.

**Requirements:** R4 (search), R10 (LDIF export), R11 (LDIF import + size/charset limits + error report format).

**Dependencies:** U2 (LDAP), U4 (templates).

**Files:**
- Create: `pkg/ldif/parser.go`
- Create: `pkg/ldif/writer.go`
- Create: `pkg/ldif/import.go`
- Create: `pkg/ldif/export.go`
- Create: `pkg/ldif/parser_test.go`
- Create: `pkg/ldif/writer_test.go`
- Create: `pkg/ldif/import_test.go`
- Create: `pkg/ldif/export_test.go`
- Create: `pkg/search/handler.go`
- Create: `pkg/search/handler_test.go`
- Create: `pkg/ldif/integration_test.go`

**Approach:**
- LDIF parser: streaming line reader; bounded buffer (no `ReadAll` of full file); validates `dn:` and attribute value charsets per RFC 2849.
- LDIF writer: emits RFC 2849 form; binary attributes auto-base64 with `:&lt;&lt;` syntax; line-folding for long values.
- Import handler: `POST /api/import` (multipart upload, max 100MB body); per-entry try/continue; error report at `import-errors-&lt;timestamp&gt;.txt`.
- Import result page: inline summary (success count, failure count) + download link for the error report.
- Optional dry-run mode: checkbox on the import page; on dry-run, no LDAP writes happen, only validation; result page reports which entries would fail.
- Export handler: `GET /api/export?dn=&lt;dn&gt;&amp;scope=entry|subtree`; subtree export streams via `http.Flusher` chunked response; binary attrs base64.
- Default redaction: `userPassword` excluded from export unless explicit `?include_secrets=true` flag is set; emit `warn` slog line when flag is used.
- Search handler: `GET /api/search?q=&lt;filter&gt;&amp;scope=subtree|global&amp;base=&lt;dn&gt;&amp;page=N&amp;page_size=50`; results paginated; sortable columns.
- Search UI: built in U4's template infra; filter input + scope toggle + result table.

**Execution note:** LDIF parser must handle a 100MB file with constant memory; add a chaos test that pipes a 100MB random LDIF and asserts memory stays bounded.

**Patterns to follow:** PHP `~/Sites/phpLDAPadmin/htdocs/import.php:52-87` (per-entry continue), `htdocs/export.php:23-32` (download stream).

**Test scenarios:**
- Happy path: LDIF import of 100 entries → 98 succeed, 2 fail (schema violations); result page shows 98/2 + download link.
- Edge case: 100MB LDIF import → parser stays under 50MB RSS; succeeds within 30s.
- Edge case: malformed LDIF (line 12 missing `:`) → that entry fails; subsequent entries continue processing.
- Edge case: LDAP server rejects schema-violating entry → that entry fails; report row contains LDAP result code + line number + raw LDIF chunk + remediation hint.
- Edge case: binary attribute in export (e.g., `userCertificate;binary`) → encoded as base64 per RFC 2849.
- Error path: LDIF body exceeds 100MB → server returns `413 Payload Too Large` without buffering to disk.
- Happy path: search `?q=(uid=alice)&scope=subtree&base=ou=People,dc=example,dc=com` returns DN + objectClass + last-modified columns; results sorted by DN ascending; pagination at 50/page.
- Edge case: search with no results → "0 results" inline message; no pagination shown.
- Error path: search with invalid LDAP filter syntax → inline error "filter syntax error at position N"; field highlighted with `aria-invalid="true"`.

**Verification:**
- Import 100k-entry LDIF in &lt; 5 min against testcontainers-go OpenLDAP.
- Export 50k-entry subtree streams to disk at &gt; 100MB/s.
- Memory profile under LDIF import shows bounded growth (heap stays under 100MB).

---

### U8. Build, integration tests, deployment, operations

**Goal:** Wire everything into a buildable, testable, deployable single binary. Provide Makefile, integration test harness using testcontainers-go, deployment documentation.

**Requirements:** R17 (single binary delivery).

**Dependencies:** U1-U7.

**Files:**
- Create: `Makefile`
- Create: `README.md`
- Create: `OPERATIONS.md`
- Create: `test/integration/setup_test.go`
- Create: `test/integration/flows_test.go`
- Create: `Dockerfile`
- Create: `deploy/systemd/ldapact.service`
- Create: `deploy/k8s/deployment.yaml`

**Approach:**
- Makefile targets: `build` (single binary, `CGO_ENABLED=0`), `test` (unit tests), `test-integration` (testcontainers-go OpenLDAP), `lint` (`gofmt -l` + `go vet` + `staticcheck`), `run` (local dev).
- Dockerfile: multi-stage with `golang:1.27` builder and `gcr.io/distroless/static-debian12` runtime; final image size &lt; 30MB.
- README: installation, configuration (YAML schema reference), deployment models (loopback, internal VPN, mTLS-fronted).
- OPERATIONS: secret resolver examples (env, file, systemd LoadCredential, k8s Secret); sessions.db backup procedure; log shipping; TLS cert rotation; sessions.db cleanup; common error codes.
- Integration test harness: `test/integration/setup_test.go` starts an OpenLDAP container, populates with test data (10 users, 3 groups, 5 OUs), exposes `127.0.0.1:<port>`. Each flow test runs against this.
- End-to-end smoke test: full F1-F8 sequence against the test container; assertions match AE1-AE7.

**Execution note:** End-to-end integration tests use `testcontainers-go`; CI must have Docker. If Docker is unavailable in CI, fall back to unit tests only (degraded coverage).

**Patterns to follow:** Standard Go project layout (https://github.com/golang-standards/project-layout); `kelseyhightower/envconfig` patterns for env var binding (we use yaml.v3 + named env vars instead).

**Test scenarios:**
- Makefile target `make build` produces `bin/ldapact` with `CGO_ENABLED=0`.
- Makefile target `make test-integration` passes locally and in CI.
- Dockerfile builds an image &lt; 30MB.
- `bin/ldapact --help` prints all flags.
- `bin/ldapact -config test/config/sample.yaml` starts and serves F1-F8 against the test container.

**Verification:**
- `make build && make test && make test-integration && make lint` all green on a fresh checkout.
- Docker image builds and runs; container healthcheck passes; F1-F8 exercisable via the running container.
- README and OPERATIONS are reviewed by a second reader for clarity.

## System-Wide Impact

- **Interaction graph:** U2 (LDAP pool) is the bottleneck for all write flows. U3 (session middleware) wraps every request. U6 (template engine) is consumed by U5 (tree) for entry-detail rendering and by F2/F3/F5/F6 directly. U7 (LDIF) interacts with U2 for entry fetch/export. U1 (slog redaction) is on the write path for every mutation; a misconfiguration could leak `userPassword`.
- **Error propagation:** LDAP errors bubble up as `*ldapx.LDAPError` carrying LDAP result code + masked DN. Handler maps LDAPError to HTTP status (e.g., code 19 → 409, code 49 → 401 with retry). All errors logged via slog with `event=ldap.error` and request ID.
- **State lifecycle risks:**
  - **bbolt file corruption:** bbolt's free-list validation surfaces corruption on open; startup aborts; OPERATIONS doc covers `bolt pages` inspection and `db.View(tx.Copy(...))` backup.
  - **Partial-write on F2/F5/F6:** LDAP write is atomic at the entry level; multi-step modifications (e.g., modify RDN + update memberOf) are sequenced within a single `ModifyRequest` per the LDAP protocol. If interrupted, LDAP server may have applied partial changes; recovery requires manual reconciliation.
  - **Session rotation race:** if a request handler emits a response after the session middleware has rotated the ID, the client receives the new cookie but stale server-side state. Mitigation: rotation happens in the auth middleware's deferred phase, after the handler returns; this is the standard pattern.
  - **Tree cache staleness (mitigated):** plan does NOT use server-side tree cache; tree state is read on every expand.
- **API surface parity:** The 60+ PHP entry points are collapsed to ~12 REST routes:
  - `GET /api/tree/{dn...}/children?page=N` — F1
  - `GET /api/entry/{dn...}` — F-Detail
  - `GET /api/template/{name}` — F2 template fetch
  - `POST /api/template/{name}/create` — F2 submit
  - `POST /api/entry/{dn...}/password` — F3
  - `POST /api/entry/{dn...}/delete` — F5
  - `POST /api/entry/{dn...}/rename` — F6
  - `POST /api/import` — F4
  - `GET /api/export` — F7
  - `GET /api/search` — F8
  - `GET /api/schema/objectclass[/{name}]` — R5 schema
  - `GET /api/schema/attribute[/{name}]` — R5 schema
  - `GET /healthz` — health check
- **Integration coverage:** Test scenarios in U8's integration test suite exercise F1-F8 end-to-end against testcontainers-go OpenLDAP. Unit tests use mocks for the LDAP layer (so failures don't require Docker for `make test`). Per-unit integration tests in U2/U5/U6/U7 spin up their own containers.
- **Unchanged invariants:**
  - PHP `~/Sites/phpLDAPadmin/` is **not modified**. It remains the compatibility oracle. Plan reads but never writes.
  - The XML template corpus `templates/creation/*.xml` is copied unchanged from phpLDAPadmin reference into the Go module's `templates/` directory.
  - The `slog` JSON log format is the **only** audit output path; no legacy syslog/CSV formats.

## Risks & Dependencies

| Risk | Mitigation |
|---|---|
| `go-ldap/ldap/v3` doesn't ship a native connection pool; U2 must build one from scratch. | Hand-rolled `chan *ldap.Conn` pool (~80 LOC) is the documented community pattern; reference implementations exist in `glauth` and other Go projects. Validation-on-Put + retry-on-ErrorNetwork pattern from best-practices research. |
| `GehirnInc/crypt` is pre-1.0 (no semver). A force-push to upstream could break the build. | Pin commit hash in `go.sum`; add `govulncheck` to `make lint`. |
| LDAP servers in production may be AD (Active Directory), which uses `unicodePwd` not `userPassword` for password writes. | Plan defers AD `unicodePwd` to v2 (Deferred to Follow-Up Work). OpenLDAP and 389-DS use `userPassword` and are fully covered. |
| The Hybrid Spine XML compatibility bet depends on the production template inventory (origin C3 outstanding question). | U6 includes the regression corpus of 8 phpLDAPadmin built-in templates; broader coverage requires user-supplied fixtures post-v1. |
| Long-running LDAP connections may be silently killed by middleboxes. | U2 sets `KeepAlive=30s` on the dialer and runs a health-check ping every 30s. |
| `GetNextNumber` mode `pool` is racy (phpLDAPadmin source explicitly warns). | Document the race in the macro's `// Note:` comment; test that the macro is best-effort and never the sole source of uniqueness. |
| Migration playbook for cutover is undefined (origin C4 outstanding question). | Plan's `OPERATIONS.md` documents cutover options: parallel-run (phpLDAPadmin + ldapact against same LDAP) for verification window, then traffic switch. The plan does NOT ship a migration tool (origin doc deferred this to "if user picks option (b)"). |
| The 23 "Resolve Before Planning" + 16 "Deferred to Planning" items in the origin doc are mostly carried as planning-time assumptions (with explicit "current decision" notes in the origin doc). If any of these defaults are wrong, the plan must be amended. | Origin doc lists each current decision; U8's OPERATIONS doc includes a "v1 pre-launch checklist" pointing to each default and asking "still valid?" |

## Documentation / Operational Notes

- **README.md** is required at v1 ship: installation, configuration reference, deployment models, security model summary.
- **OPERATIONS.md** is required at v1 ship: secret resolver examples, sessions.db lifecycle, log shipping, TLS rotation, cutover playbook (parallel-run then switch), common LDAP error codes mapping to HTTP status, monitoring hooks (metrics endpoint not in v1 scope but slog lines are metrics-ready).
- **CHANGELOG.md** tracks v1 milestones (one entry per U1-U8 landing).
- **docs/solutions/** is created post-v1 with entries for: LDAP pool validation pattern; XML template parser regression strategy; bbolt schema migration; web UI SSR with HTMX.

## Sources & References

- **Origin document:** [`docs/brainstorms/ldapact-go-reimplementation.md`](../brainstorms/ldapact-go-reimplementation.md)
- **PHP compatibility oracle:** `~/Sites/phpLDAPadmin/` (read-only)
- **Library docs:**
  - go-ldap/ldap v3.4.14: https://pkg.go.dev/github.com/go-ldap/ldap/v3
  - bbolt v1.5.0: https://pkg.go.dev/go.etcd.io/bbolt
  - HTMX 2.0.x: https://htmx.org
  - log/slog: https://pkg.go.dev/log/slog
  - embed: https://pkg.go.dev/embed
  - yaml.v3: https://pkg.go.dev/gopkg.in/yaml.v3
- **Standards / best practices:**
  - OWASP Password Storage Cheat Sheet (2026)
  - OWASP Session Management Cheat Sheet (2026)
  - OWASP HTTP Headers Cheat Sheet / Secure Headers Project
  - W3C ARIA Authoring Practices — Tree View pattern
  - RFC 2307 (LDAP password schemes), RFC 2849 (LDIF), RFC 3062 (PasswordModify), RFC 4512 (LDAP subschema), RFC 4513 (LDAP auth + StartTLS)

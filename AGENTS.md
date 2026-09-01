# AGENTS.md

Guidance for AI agents and developers working in this repository. README is
the user-facing product/ops document; this file covers how to work on the
code. Product goals and scope live in `docs/brainstorms/` and the v1 feature
plan (`docs/plans/2026-08-24-001-feat-ldapact-v1-implementation-plan.md`).

## Project

ldapact is a single-binary Go reimplementation of phpLDAPadmin for daily LDAP
administration. It keeps the phpLDAPadmin XML template engine so existing
custom creation templates keep working, and renders the UI with Go
`html/template` + HTMX (no JS framework).

## Repository layout

- `cmd/ldapact` — CLI entry point.
- `internal/app` — the only place routes are registered; HTTP middleware chain.
- `internal/testldap` — integration-test LDAP backend harness (never touches a real LDAP service).
- `pkg/authn` — session middleware + CSRF.
- `pkg/config` — `LDAPADM_*` envconfig profile, secret resolution.
- `pkg/entry` — entry flows: detail, create (F2), edit, password (F3), delete (F5), rename (F6), photo.
- `pkg/ldapx` — LDAP client, connection pool, paged search, schema parse/cache, CRUD.
- `pkg/ldif` — LDIF parser/writer, streaming import/export (F4/F7).
- `pkg/logging` — slog setup, request ID + recover middleware, redaction.
- `pkg/ratelimit` — in-memory rate limiter middleware.
- `pkg/search` — search page handler (F8).
- `pkg/secheaders` — security headers middleware.
- `pkg/session` — bbolt session store, `__Host-` cookie, rotation, sweeper.
- `pkg/tplengine` — phpLDAPadmin XML template engine, macros, password hashing.
- `pkg/tree` — tree browse (F1) + schema browser (R5) handlers.
- `pkg/web` — Go-side HTML rendering (Page vs Fragment), embedded templates and static assets.
- `templates/` — creation/modification XML templates (phpLDAPadmin-compatible).
- `static/` — CSS/JS/HTMX assets (embedded by `assets.go`; dev mode uses `assets_dev.go`).
- `docs/` — brainstorms, plans, residual-review findings (historical records).

## Development commands

```sh
make build            # CGO_ENABLED=0 single binary -> bin/ldapact
make dist             # cross-platform release binaries under dist/
make test             # unit + integration tests (integration skips when no backend detected)
make test-integration # unit + gated integration tests (LDAP/Redis backends, incl. F1-F8)
make test-js          # node test/js/*_test.js
make lint             # gofmt + go vet + golangci-lint + govulncheck
make tools            # install golangci-lint + govulncheck (lint prerequisites)
make run              # go run ./cmd/ldapact (needs LDAPADM_* env; see README "Configuration")

CI in `.github/workflows` does not invoke make: `ci` runs lint via the
golangci-lint and govulncheck GitHub Actions plus direct go/node commands, and
tests (Docker-backed integration on ubuntu runners); `release` builds
multi-platform binaries and publishes on tag `v*`.
```

The Makefile exports `GOWORK=off` because this repo is not listed in the
parent `go.work` — build standalone. For a single package, use
`go test -count=1 ./pkg/<pkg>/` (same for `go vet`).

Local dev env: copy `.env.example` to your own file and source it; never edit
or source the example directly. Unset `LDAPADM_TEST_*` variables before
running the server (unknown `LDAPADM_*` variables are ignored).

## Integration-test backends

`internal/testldap` detects a backend in order and never touches a real LDAP
service:

1. `LDAPADM_TEST_LDAP_URL` — caller-provisioned dedicated test server.
2. Docker — ephemeral `liut7/staffio-ldap` container (testcontainers-go);
   override the image with `LDAPADM_TEST_LDAP_IMAGE`.
3. Local `slapd` — ephemeral foreground instance with a generated config and
   temp data directory on a random `127.0.0.1` port. System configs, data
   directories, pidfiles, and launchd/systemd services are never read or
   modified.

When no backend exists, integration tests skip (`testldap.ErrUnavailable`).
The harness probes whether the server verifies `{SSHA512}` binds and
downgrades the write scheme to `{SSHA}` for directory builds without SHA-2
support; the product default remains SSHA512.

## Conventions

### Commits

Conventional commits with scopes, one commit per implementation unit:
`feat(entry):`, `fix(authn):`, `refactor(web):`, `test(...)`, `docs(...)`,
`chore(...)`. CHANGELOG keeps one entry per implementation unit — keep them in
sync.

### Routing

Routes are registered only in `internal/app`. The `/api` prefix is reserved
for endpoints that return data or HTMX fragments (tree children, photo image,
export LDIF, import report). Full-page routes use plain paths (`/entry/...`,
`/template/...`, `/schema/...`, `/search`, `/import`). New endpoints: page →
plain path; data/fragment → `/api`.

Go's ServeMux requires multi-segment `{dn...}` wildcards to end the pattern,
so suffix actions (`/children`, `/edit`, `/password`, `/delete`, `/rename`)
are parsed manually in `internal/app` (`treeDispatch`, `entryDispatch`,
`apiEntryDispatch`). DNs containing `/` are not supported.

### Rendering

`pkg/web.Renderer` has two modes: `Page` renders a full page (content template
wrapped in `layout.html`); `Fragment` renders an HTMX partial. Pick the mode
that matches the endpoint kind (see Routing). HTML templates live in
`pkg/web/templates` (embedded); XML creation/modification templates live in
`templates/` and are parsed by `pkg/tplengine`. `MustParse` panics on template
parse failure at startup — don't weaken that.

### Config and secrets

- All runtime config comes from `LDAPADM_*` env vars via envconfig; no config file.
- Secrets (`LDAPADM_SESSION_KEY`, Redis / auto-number passwords) resolve:
  env var → file (mode must be `0600`) only. There is no interactive TTY
  prompt — this is a server process, and a missing secret fails fast at
  startup. Never put secrets in config structs or logs.
- Unknown `LDAPADM_*` variables are ignored; a set-but-empty value is parsed
  as-is (numeric/boolean fields fail at parse time naming the variable).

### Security invariants (do not weaken)

- Fail-fast startup: refuses to start when every LDAP replica is
  unreachable, a replica certificate is expired (fail-closed), or the
  configured session store is unreachable. At least one reachable replica is
  sufficient to start; replicas down at startup are retried in the
  background.
- TLS 1.2 floor, mandatory verification, StartTLS-only for `ldap://`.
- Sessions: 256-bit opaque IDs, `__Host-LDAPADM_SID` (Secure/HttpOnly/
  SameSite=Strict), bbolt store, idle + absolute timeouts, rotation on state
  change, 5-minute sweeper.
- CSRF: SameSite=Strict + Origin-header check on state-changing methods.
- Passwords: RFC 2307 write whitelist; `{PLAIN}` rejected unless explicitly
  overridden; hashes redacted at the logger boundary and never echoed in the
  UI (detail pages show `[redacted]`).
- Audit: JSON `slog` events (`ldap.create/modify/delete/rename`) on every mutation.

## Known gotchas

- LDAP paged-result sessions are connection-scoped: `ldapx.Page` pins one
  pooled connection for the whole multi-page loop.
- Session-ID rotation happens before state-changing handlers (header commit
  order makes post-handler rotation unreliable).
- The F2 wizard renders all pages in one form with a step indicator; per-page
  server-side session state is deferred.
- Paging scale: the AE2 5000-child case is exercised at 1210 children in the
  harness; Docker-gated tests cover the AE3/AE4/partial-AE5 gates.

## License

GPL-2.0-or-later (see `LICENSE`), matching phpLDAPadmin — the repo contains
verbatim phpLDAPadmin template artifacts (`templates/template.dtd`, creation
templates). Do not relicense or replace them with non-GPL copies; keep the
upstream copyright headers intact.

## Docs

- Product goals and scope: `docs/brainstorms/ldapact-go-reimplementation.md`
  and `docs/plans/2026-08-24-001-feat-ldapact-v1-implementation-plan.md`.
- Ops runbook: `OPERATIONS.md` (secret resolver examples, sessions.db
  lifecycle, log shipping, TLS rotation, cutover, v1 pre-launch checklist).
- `docs/plans/*` and `docs/residual-review-findings/*` are historical records —
  record new decisions in CHANGELOG, don't rewrite past plans.
- User-facing behavior, configuration, routes, and security: README.

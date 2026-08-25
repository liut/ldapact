# ldapact

ldapact is a single-binary Go reimplementation of phpLDAPadmin for daily LDAP
administration. It keeps the phpLDAPadmin XML template engine so existing
custom creation templates keep working, while replacing the PHP runtime with a
static, embeddable binary (R17).

## Features (v1)

- **F1 Browse** — paged, ARIA-compliant directory tree (`role="tree"`,
  keyboard navigation, screen-reader announcements).
- **F2 Create** — template-driven entry creation (built-in `posixAccount`,
  `inetOrgPerson`, `posixGroup` + custom XML templates) with `GetNextNumber`
  auto-numbering, `PickList` group selection, client-side `autoFill`, and
  server-side password hashing.
- **F3 Password** — change passwords with RFC 2307 hashing (SSHA512 default),
  LDAP ppolicy error surfacing, and bind verification.
- **F4/F7 LDIF** — streaming import (per-entry continue + downloadable error
  report) and export (subtree streaming, `userPassword` redacted by default).
- **F5/F6 Delete/Rename** — confirmation flows with typed-DN protection and
  ceiling-gated recursive subtree delete; rename/move across parents.
- **F8 Search** — scoped, filtered, paginated search with inline filter
  errors.
- **R5 Schema browser** — objectClass and attributeType lists/detail with
  MUST/MAY cross-navigation from the cached subschema.
- Structured `slog` JSON audit of every mutation (`ldap.create/modify/delete/
  rename`) — passwords are redacted at the logger boundary (R15/AE6).

## Quick start

```sh
make build
export LDAPADM_BIND_PASSWORD='your-secret'      # or LDAPADM_BIND_PASSWORD_FILE=/path/to/0600-file
./bin/ldapact -config config/example.yaml
open http://127.0.0.1:8080
```

`bin/ldapact --version` prints the version; `-healthcheck` supports container
health probes.

## Configuration

The server profile is a strict YAML file (unknown keys fail the parse):

```yaml
server:
  listen: "127.0.0.1:8080"
ldap:
  url: "ldap://127.0.0.1:389"       # or ldaps://host:636
  base_dn: "dc=example,dc=com"
  bind_dn: "cn=admin,dc=example,dc=com"
  tls:
    min_version: "TLSv1.2"           # TLSv1.2 | TLSv1.3 (floor enforced)
    verify: true                     # false is rejected at parse time
    start_tls: true                  # ldap:// + StartTLS (failures are fatal)
    cert_expiry_fail_closed: true    # refuse to start on expired certs
  schema_compat: "openldap"
  tree_filter: "(objectClass=*)"
  pool_size: 8
  password_plain_override: false     # {PLAIN} writes emit a warn when enabled
session:
  timeout_minutes: 30                # idle, 5..240
  absolute_timeout_minutes: 480      # absolute, 30..1440
  expired_action: "retry_bind"       # retry_bind | redirect_to_login
  db_path: "/var/lib/ldapact/sessions.db"
log_level: "info"                    # debug|info|warn|error (LDAPADM_LOG_LEVEL overrides)
templates_dir: ""                    # optional custom XML template directory
```

**Secrets are never stored in the YAML.** The bind password (and the optional
`auto_number` password) resolve through the chain:

1. env var `LDAPADM_BIND_PASSWORD` (or `LDAPADM_AUTO_NUMBER_PASSWORD`)
2. file referenced by `LDAPADM_BIND_PASSWORD_FILE` — mode must be `0600`
3. interactive TTY prompt (fails fast when no TTY is available)

## Deployment models

ldapact is designed for loopback, internal-VPN, or mTLS-fronted deployments
(single admin bind + server-side sessions; no public multi-tenant exposure).

- **Bare metal/systemd**: `deploy/systemd/ldapact.service` (uses
  `LoadCredential` for secret files).
- **Kubernetes**: `deploy/k8s/deployment.yaml` (ConfigMap + Secret + probes).
- **Container**: `Dockerfile` produces a distroless static image; run with
  `-config /etc/ldapact/ldapact.yaml` and `LDAPADM_BIND_PASSWORD_FILE`.

See [OPERATIONS.md](OPERATIONS.md) for the runbook: secret resolver examples,
sessions.db lifecycle, log shipping, TLS rotation, cutover playbook, and the
v1 pre-launch checklist.

## Security model

- Fail-fast LDAP startup bind (R14): the process refuses to start when the
  directory is unreachable or the certificate is expired.
- TLS 1.2 floor, mandatory verification, StartTLS-only (no plaintext
  fallback).
- Sessions: 256-bit opaque IDs in a `__Host-LDAPADM_SID` cookie
  (Secure/HttpOnly/SameSite=Strict), bbolt store with idle + absolute
  timeouts, rotation on every state change, 5-minute sweeper.
- CSRF: SameSite=Strict + Origin-header check on state-changing methods.
- Security headers: CSP (Report-Only initially), HSTS over TLS, nosniff,
  `X-Frame-Options: DENY`, Referrer-Policy, Permissions-Policy.
- Passwords: RFC 2307 write whitelist (SSHA512/SSHA256/SSHA/SHA512/SHA256/
  ARGON2ID/MD4); legacy schemes read-only; `{PLAIN}` rejected unless explicitly
  overridden; values never appear in logs.
- Core dumps disabled (`GOTRACEBACK=none`, `RLIMIT_CORE=0`).

## Development

```sh
make build            # CGO_ENABLED=0 single binary -> bin/ldapact
make test             # unit tests (no Docker required)
make test-js          # JS unit tests (Node)
make test-integration # end-to-end F1-F8 vs testcontainers-go OpenLDAP (Docker)
make lint             # gofmt + go vet + staticcheck + govulncheck
make run              # local dev with config/example.yaml
```

Integration tests skip automatically when Docker is unavailable.

## API surface

The phpLDAPadmin 60+ PHP entry points collapse to ~13 REST routes:

| Method + path | Flow |
|---|---|
| `GET /api/tree/{dn...}/children?page=N` | F1 |
| `GET /api/entry/{dn...}` | F-Detail |
| `GET /api/template/{name}` · `POST /api/template/{name}/create` | F2 |
| `POST /api/entry/{dn...}/password` | F3 |
| `POST /api/entry/{dn...}/delete` | F5 |
| `POST /api/entry/{dn...}/rename` | F6 |
| `POST /api/import` · `GET /api/import/report/{id}` | F4 |
| `GET /api/export?dn=...&scope=entry\|subtree` | F7 |
| `GET /api/search?q=...&scope=...&page=N` | F8 |
| `GET /api/schema/objectclass[/{name}]` · `GET /api/schema/attribute[/{name}]` | R5 |
| `GET /healthz` | health |

State-changing responses carry `X-Mutated-Subtree: <dn>` so the tree refreshes
the affected branch.

## Known scope notes (v1)

- The F2 wizard renders all pages in one form with a step indicator;
  per-page server-side session state is deferred (see
  `docs/plans/2026-08-24-001-...md` "Deferred to Implementation").
- Session-ID rotation happens before state-changing handlers (header commit
  order makes post-handler cookie rotation unreliable).
- Docker-gated integration tests cover the AE3/AE4/partial-AE5 gates; the
  exact 5000-child paging scale (AE2) is exercised at 1210 children in the
  harness.

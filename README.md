# ldapact

ldapact is a single-binary Go reimplementation of phpLDAPadmin for daily LDAP
administration. It keeps the phpLDAPadmin XML template engine so existing
custom creation templates keep working, while replacing the PHP runtime with a
static, embeddable binary.

## Features

- **Browse** — paged, keyboard-navigable directory tree with
  screen-reader announcements.
- **Create** — template-driven entry creation (built-in `posixAccount`,
  `inetOrgPerson`, `posixGroup` + custom XML templates) with automatic
  numbering, group pick-lists, client-side auto-fill, and server-side
  password hashing.
- **Password** — change passwords with standard LDAP hashing (SSHA512 default),
  LDAP ppolicy error surfacing, and bind verification; the change-password
  affordance is only available on entries that have a `userPassword`
  attribute.
- **Edit attributes** — modification-template-driven entry editing with a
  generic-editor fallback, review-then-apply, multi-value support, and
  schema-driven controls (the attribute's syntax picks the control kind;
  required/optional markers; operational attributes excluded). Attributes can
  be added from the objectClass schema, optional/unknown ones cleared or
  deleted (required ones cannot), binary attributes replaced via file upload,
  and auxiliary object classes added/removed. `userPassword` and RDN changes
  stay in Password / Rename.
- **Import/Export (LDIF)** — streaming import (per-entry continue +
  downloadable error report) and export (subtree streaming, passwords
  redacted by default).
- **Delete/Rename** — leaf-only deletion (entries with children are
  blocked — delete children first); rename/move across parents.
- **Search** — scoped (base/one/subtree/global), filtered, sortable,
  paginated search with size/time limits, attribute selection, and inline
  filter errors. Size/time limits apply per LDAP request; when the directory
  doesn't support server-side sorting, ordering is applied within each page.
- **Schema browser** — objectClass and attributeType lists/detail with
  required/optional cross-navigation from the cached subschema.
- Structured JSON audit log of every mutation (create, modify, delete,
  rename) — passwords are redacted at the logger boundary.

## Quick start

```sh
make build
export LDAPADM_URL='ldap://127.0.0.1:389'
export LDAPADM_BASE_DN='dc=example,dc=com'
export LDAPADM_BIND_DN='cn=admin,dc=example,dc=com'
export LDAPADM_SESSION_KEY="$(openssl rand -base64 32)"   # AES-256-GCM session-key
export LDAPADM_REDIS_URL='redis://127.0.0.1:6379'
./bin/ldapact
open http://127.0.0.1:8389/login   # log in with the admin bind DN + password
```

`bin/ldapact --version` prints the version; `-config-help` prints the
`LDAPADM_*` configuration reference; `-healthcheck` supports container health
probes.

## Configuration

There is no config file — the server is configured entirely by `LDAPADM_*`
environment variables. Unknown `LDAPADM_*` variables are ignored; a variable
set without the `LDAPADM_` prefix (for example `URL`) is read only when the
prefixed key is absent (envconfig fallback), so set the prefixed key to be
explicit. A variable set to an empty value is parsed as-is: numeric and
boolean fields fail startup with a parse error naming the variable, string
fields fall through to validation (defaulted or rejected); leave optional
variables unset rather than empty. `ldapact -config-help` prints this
reference (with descriptions) from the struct tags.

| env var | default | notes |
|---|---|---|
| `LDAPADM_LISTEN` | `127.0.0.1:8389` | |
| `LDAPADM_URL` | — (required unless `SERVERS` set) | `ldap://host:port` or `ldaps://host:port`; mutually exclusive with `LDAPADM_SERVERS` |
| `LDAPADM_SERVERS` | empty | comma-separated replica URLs; overrides `LDAPADM_URL` (replica failover) |
| `LDAPADM_BASE_DN` | — (required) | |
| `LDAPADM_BIND_DN` | — (required) | shared admin bind DN, prefilled on the login page (editable) |
| `LDAPADM_AUTO_NUMBER_DN` | empty | enables auto-numbering; also resolves `LDAPADM_AUTO_NUMBER_PASSWORD` |
| `LDAPADM_MIN_VERSION` | `TLSv1.2` | `TLSv1.2` \| `TLSv1.3` (floor enforced) |
| `LDAPADM_VERIFY` | `true` | `false` is rejected at startup |
| `LDAPADM_START_TLS` | `true` for `ldap://` | failures are fatal; must be off with `ldaps://` |
| `LDAPADM_CERT_EXPIRY_FAIL_CLOSED` | `true` | refuse to start on expired certs |
| `LDAPADM_SCHEMA_COMPAT` | `openldap` | |
| `LDAPADM_TREE_FILTER` | `(objectClass=*)` | |
| `LDAPADM_POOL_SIZE` | `8` | 1..100 |
| `LDAPADM_PASSWORD_PLAIN_OVERRIDE` | `false` | `{PLAIN}` writes emit a warn when enabled |
| `LDAPADM_PASSWORD_SCHEME` | empty | password write scheme (default SSHA512; `SSHA` for legacy directories) |
| `LDAPADM_TIMEOUT_MINUTES` | `30` | idle, 5..240 |
| `LDAPADM_ABSOLUTE_TIMEOUT_MINUTES` | `480` | absolute, 30..1440 |
| `LDAPADM_EXPIRED_ACTION` | `redirect_to_login` | expired sessions redirect to `/login` (`retry_bind` was removed) |
| `LDAPADM_SESSION_STORE` | `redis` | `redis` \| `bbolt` \| `memory`; redis is shared across instances, bbolt/memory are single-instance |
| `LDAPADM_REDIS_URL` | — (required when store=redis) | `redis://host:port` or `rediss://host:port` (TLS verification mandatory) |
| `LDAPADM_REDIS_DB` | `0` | Redis logical database |
| `LDAPADM_DB_PATH` | `/var/lib/ldapact/sessions.db` | bbolt only: unset or set to the default: falls back to `~/.local/state/ldapact/sessions.db` when `/var/lib/ldapact` does not exist |
| `LDAPADM_SESSION_KEY` | — (required secret) | base64 of 32 bytes; AES-256-GCM key for session bind credentials; changing it invalidates all sessions |
| `LDAPADM_LOG_LEVEL` | `info` | `debug`\|`info`\|`warn`\|`error` |
| `LDAPADM_TEMPLATES_DIR` | empty | optional custom XML template directory |

**Secrets are never parsed from the environment or stored in any config
file.** `LDAPADM_SESSION_KEY` (required) and the optional
`LDAPADM_REDIS_PASSWORD`/`LDAPADM_AUTO_NUMBER_PASSWORD` resolve through the
chain:

1. env var (`LDAPADM_SESSION_KEY`, `LDAPADM_REDIS_PASSWORD`,
   `LDAPADM_AUTO_NUMBER_PASSWORD`)
2. a 0600 file referenced by the `_FILE` variant

`LDAPADM_BIND_PASSWORD` is deprecated and ignored: the bind credential is
entered on the login page, verified against the directory, and stored
encrypted in the session. There is no interactive fallback: missing secrets
fail fast at startup, as a server process should.

## Deployment models

ldapact is designed for loopback, internal-VPN, or mTLS-fronted deployments
(single admin bind + server-side sessions; no public multi-tenant exposure).

- **Bare metal/systemd**: `deploy/systemd/ldapact.service` reads non-secret
  config from `/etc/default/ldapact` (`EnvironmentFile`; see
  `deploy/systemd/ldapact.default.example`) and uses `LoadCredential` for
  secret files.
- **Kubernetes**: `deploy/k8s/deployment.yaml` (ConfigMap + Secret + probes).
- **Container**: `Dockerfile` produces a distroless static image; run with
  only environment variables and secret files (no mounted config file).
- **Multi-instance**: point every instance at the same Redis and the same
  `LDAPADM_SESSION_KEY`; sessions (and their encrypted credentials) are then
  usable from any instance without session affinity (R14).

See [OPERATIONS.md](OPERATIONS.md) for the runbook: secret resolver examples,
sessions.db lifecycle, log shipping, TLS rotation, cutover playbook, and the
v1 pre-launch checklist.

## Security model

- Fail-fast startup probe: the process refuses to start when the directory is
  unreachable or the certificate is expired; credential validation happens at
  login instead of startup.
- TLS 1.2 floor, mandatory verification, StartTLS-only (no plaintext
  fallback).
- Login gate: every page (except `/healthz`, `/static/*`, `/login`) requires
  a session minted by `/login`; expired or invalidated sessions redirect to
  `/login`.
- Sessions: 256-bit opaque IDs in a `__Host-LDAPADM_SID` cookie
  (Secure/HttpOnly/SameSite=Strict); Redis store by default (bbolt/memory for
  single instances) with idle + absolute timeouts and rotation on every state
  change; the bind credential rides along encrypted (AES-256-GCM) and is
  never written to cookies, logs, or pages.
- Operations bind per request with the session credential (no shared
  configured password); replica failover on network errors with rotating
  start points, never on `invalidCredentials` (that invalidates the session
  and redirects to login).
- CSRF: SameSite=Strict + Origin-header check on state-changing methods.
- Security headers: CSP (Report-Only initially), HSTS over TLS, nosniff,
  `X-Frame-Options: DENY`, Referrer-Policy, Permissions-Policy.
- Passwords: write whitelist (SSHA512/SSHA256/SSHA/SHA512/SHA256/
  ARGON2ID/MD4); legacy schemes read-only; `{PLAIN}` rejected unless explicitly
  overridden; values never appear in logs.
- Core dumps disabled.

## Development

```sh
make build            # CGO_ENABLED=0 single binary -> bin/ldapact
make test             # unit tests + integration tests (backend auto-detected)
make test-js          # JS unit tests (Node)
make test-integration # end-to-end vs the detected backend
make lint             # format + vet + static analysis + vuln check
make run              # local dev (export the required env vars; see Configuration)
```

`.env.example` holds a starter set of variables — copy it to your own file and
override the secrets; never edit or source the example directly.

Repository layout, the integration-test backend contract, conventions, and
known gotchas: see [AGENTS.md](AGENTS.md).

## Routes

The phpLDAPadmin 60+ PHP entry points collapse to a small route set. Full
pages render under their plain path; the `/api` prefix is reserved for
endpoints that return data (images, LDIF, report files) or HTML fragments:

### Pages

| Method + path | Purpose |
|---|---|
| `GET /` | tree home |
| `GET /search?q=...&scope=base\|one\|subtree\|global&sort=dn\|objectclass\|modified&dir=asc\|desc&size_limit=&time_limit=&attrs=cn,mail&page=N` | search |
| `GET /schema/objectclass[/{name}]` · `GET /schema/attribute[/{name}]` | schema browser |
| `GET /template/{name}` · `POST /template/{name}/create` | create wizard |
| `GET /entry/{dn...}` | entry detail |
| `GET/POST /entry/{dn...}/edit` | edit attributes (stage=review\|apply); controls render per the LDAP schema |
| `GET/POST /entry/{dn...}/password` | change password |
| `GET/POST /entry/{dn...}/delete` | delete entry |
| `GET/POST /entry/{dn...}/rename` | rename / move |
| `GET /import` · `POST /import` | import LDIF |

### API (data / fragments)

| Method + path | Purpose |
|---|---|
| `GET /api/tree/{dn...}/children?page=N` | tree children fragment |
| `GET /api/entry/{dn...}/photo?idx=N` | jpegPhoto image data |
| `GET /api/export?dn=...&scope=entry\|subtree` | LDIF data |
| `GET /api/import/report/{id}` | error report (plain text) |
| `GET /healthz` | health |

State-changing responses carry `X-Mutated-Subtree: <dn>` so the tree refreshes
the affected branch.

## License

GPL-2.0-or-later — the same license as phpLDAPadmin, whose template engine and
template artifacts this project builds on (`templates/` retains the upstream
copyright headers). See [LICENSE](LICENSE).

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
  LDAP ppolicy error surfacing, and bind verification; the change-password
  affordance is only available on entries that have a `userPassword`
  attribute.
- **Edit attributes** — modification-template-driven entry editing with a
  generic-editor fallback, review-then-apply, multi-value support, and
  schema-driven controls (attributeType syntax picks the control kind;
  MUST/MAY markers; operational attributes excluded). Attributes can be added
  from the objectClass schema, MAY/unknown ones cleared or deleted (MUST
  cannot), binary attributes replaced via file upload, and auxiliary object
  classes added/removed. `userPassword` and RDN changes stay in Password (F3)
  / Rename (F6).
- **F4/F7 LDIF** — streaming import (per-entry continue + downloadable error
  report) and export (subtree streaming, `userPassword` redacted by default).
- **F5/F6 Delete/Rename** — leaf-only deletion (entries with children are
  blocked — delete children first); rename/move across parents.
- **F8 Search** — scoped (base/one/subtree/global), filtered, sortable,
  paginated search with size/time limits, attribute selection, and inline
  filter errors. Size/time limits apply per LDAP request; when the directory
  rejects the RFC 2891 sort control, ordering is applied within each page.
- **R5 Schema browser** — objectClass and attributeType lists/detail with
  MUST/MAY cross-navigation from the cached subschema.
- Structured `slog` JSON audit of every mutation (`ldap.create/modify/delete/
  rename`) — passwords are redacted at the logger boundary (R15/AE6).

## Quick start

```sh
make build
export LDAPADM_URL='ldap://127.0.0.1:389'
export LDAPADM_BASE_DN='dc=example,dc=com'
export LDAPADM_BIND_DN='cn=admin,dc=example,dc=com'
export LDAPADM_BIND_PASSWORD='your-secret'      # or LDAPADM_BIND_PASSWORD_FILE=/path/to/0600-file
./bin/ldapact
open http://127.0.0.1:8080
```

`bin/ldapact --version` prints the version; `-healthcheck` supports container
health probes.

## Configuration

The server profile is configured entirely by `LDAPADM_*` environment
variables parsed by
[kelseyhightower/envconfig](https://github.com/kelseyhightower/envconfig);
there is no config file. Unknown `LDAPADM_*` variables fail startup (typo
guard), and set-but-empty variables are treated as unset, so an empty value
never overrides a default. Code defaults apply when a variable is absent.

| env var | config key | default | notes |
|---|---|---|---|
| `LDAPADM_LISTEN` | `server.listen` | `127.0.0.1:8080` | |
| `LDAPADM_URL` | `ldap.url` | — (required) | `ldap://host:port` or `ldaps://host:port` |
| `LDAPADM_BASE_DN` | `ldap.base_dn` | — (required) | |
| `LDAPADM_BIND_DN` | `ldap.bind_dn` | — (required) | |
| `LDAPADM_AUTO_NUMBER_DN` | `ldap.auto_number_dn` | empty | enables auto-numbering; also resolves `LDAPADM_AUTO_NUMBER_PASSWORD` |
| `LDAPADM_MIN_VERSION` | `ldap.tls.min_version` | `TLSv1.2` | `TLSv1.2` \| `TLSv1.3` (floor enforced) |
| `LDAPADM_VERIFY` | `ldap.tls.verify` | `true` | `false` is rejected at startup |
| `LDAPADM_START_TLS` | `ldap.tls.start_tls` | `true` for `ldap://` | failures are fatal; must be off with `ldaps://` |
| `LDAPADM_CERT_EXPIRY_FAIL_CLOSED` | `ldap.tls.cert_expiry_fail_closed` | `true` | refuse to start on expired certs |
| `LDAPADM_SCHEMA_COMPAT` | `ldap.schema_compat` | `openldap` | |
| `LDAPADM_TREE_FILTER` | `ldap.tree_filter` | `(objectClass=*)` | |
| `LDAPADM_POOL_SIZE` | `ldap.pool_size` | `8` | 1..100 |
| `LDAPADM_PASSWORD_PLAIN_OVERRIDE` | `ldap.password_plain_override` | `false` | `{PLAIN}` writes emit a warn when enabled |
| `LDAPADM_PASSWORD_SCHEME` | `ldap.password_scheme` | empty | RFC 2307 write scheme (engine default SSHA512; `SSHA` for legacy dirs) |
| `LDAPADM_TIMEOUT_MINUTES` | `session.timeout_minutes` | `30` | idle, 5..240 |
| `LDAPADM_ABSOLUTE_TIMEOUT_MINUTES` | `session.absolute_timeout_minutes` | `480` | absolute, 30..1440 |
| `LDAPADM_EXPIRED_ACTION` | `session.expired_action` | `retry_bind` | `retry_bind` \| `redirect_to_login` |
| `LDAPADM_DB_PATH` | `session.db_path` | `/var/lib/ldapact/sessions.db` | unset or set to the default: falls back to `~/.local/state/ldapact/sessions.db` when `/var/lib/ldapact` does not exist |
| `LDAPADM_LOG_LEVEL` | `log_level` | `info` | `debug`\|`info`\|`warn`\|`error` |
| `LDAPADM_TEMPLATES_DIR` | `templates_dir` | empty | optional custom XML template directory |

**Secrets are never parsed from the environment or stored in any config
file.** The bind password (and the optional `auto_number` password) resolve
through the chain:

1. env var `LDAPADM_BIND_PASSWORD` (or `LDAPADM_AUTO_NUMBER_PASSWORD`)
2. file referenced by `LDAPADM_BIND_PASSWORD_FILE` — mode must be `0600`
3. interactive TTY prompt (fails fast when no TTY is available)

## Deployment models

ldapact is designed for loopback, internal-VPN, or mTLS-fronted deployments
(single admin bind + server-side sessions; no public multi-tenant exposure).

- **Bare metal/systemd**: `deploy/systemd/ldapact.service` reads non-secret
  config from `/etc/default/ldapact` (`EnvironmentFile`; see
  `deploy/systemd/ldapact.default.example`) and uses `LoadCredential` for
  secret files.
- **Kubernetes**: `deploy/k8s/deployment.yaml` (ConfigMap + Secret + probes).
- **Container**: `Dockerfile` produces a distroless static image; run with
  only environment variables and `LDAPADM_BIND_PASSWORD_FILE` (no mounted
  config file).

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
make test             # unit tests + integration tests (backend auto-detected)
make test-js          # JS unit tests (Node)
make test-integration # end-to-end F1-F8 vs the detected backend
make lint             # gofmt + go vet + staticcheck + govulncheck
make run              # local dev (export the required env vars; see Configuration)
```

`.env.example` holds a starter set of variables — copy it to your own file and
override the secrets; never edit or source the example directly.

Repository layout, the integration-test backend contract, conventions, and
known gotchas: see [AGENTS.md](AGENTS.md).

## Routes

The phpLDAPadmin 60+ PHP entry points collapse to a small route set. Full
pages render under their plain path; the `/api` prefix is reserved for
endpoints that return data (images, LDIF, report files) or HTMX fragments:

### Pages

| Method + path | Flow |
|---|---|
| `GET /` | F1 tree home |
| `GET /search?q=...&scope=base\|one\|subtree\|global&sort=dn\|objectclass\|modified&dir=asc\|desc&size_limit=&time_limit=&attrs=cn,mail&page=N` | F8 |
| `GET /schema/objectclass[/{name}]` · `GET /schema/attribute[/{name}]` | R5 |
| `GET /template/{name}` · `POST /template/{name}/create` | F2 |
| `GET /entry/{dn...}` | F-Detail |
| `GET/POST /entry/{dn...}/edit` | edit attributes (stage=review\|apply); controls render per the LDAP schema |
| `GET/POST /entry/{dn...}/password` | F3 |
| `GET/POST /entry/{dn...}/delete` | F5 |
| `GET/POST /entry/{dn...}/rename` | F6 |
| `GET /import` · `POST /import` | F4 |

### API (data / fragments)

| Method + path | Flow |
|---|---|
| `GET /api/tree/{dn...}/children?page=N` | F1 HTMX fragment |
| `GET /api/entry/{dn...}/photo?idx=N` | jpegPhoto image data |
| `GET /api/export?dn=...&scope=entry\|subtree` | F7 LDIF data |
| `GET /api/import/report/{id}` | F4 error report (plain text) |
| `GET /healthz` | health |

State-changing responses carry `X-Mutated-Subtree: <dn>` so the tree refreshes
the affected branch.

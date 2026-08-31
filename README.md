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
export LDAPADM_BIND_PASSWORD='your-secret'      # or LDAPADM_BIND_PASSWORD_FILE=/path/to/0600-file
./bin/ldapact
open http://127.0.0.1:8389
```

`bin/ldapact --version` prints the version; `-healthcheck` supports container
health probes.

## Configuration

There is no config file — the server is configured entirely by `LDAPADM_*`
environment variables. Unknown `LDAPADM_*` variables fail startup (typo
guard), and set-but-empty variables are treated as unset, so an empty value
never overrides a default; defaults apply when a variable is absent.

| env var | default | notes |
|---|---|---|
| `LDAPADM_LISTEN` | `127.0.0.1:8389` | |
| `LDAPADM_URL` | — (required) | `ldap://host:port` or `ldaps://host:port` |
| `LDAPADM_BASE_DN` | — (required) | |
| `LDAPADM_BIND_DN` | — (required) | |
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
| `LDAPADM_EXPIRED_ACTION` | `retry_bind` | `retry_bind` \| `redirect_to_login` |
| `LDAPADM_DB_PATH` | `/var/lib/ldapact/sessions.db` | unset or set to the default: falls back to `~/.local/state/ldapact/sessions.db` when `/var/lib/ldapact` does not exist |
| `LDAPADM_LOG_LEVEL` | `info` | `debug`\|`info`\|`warn`\|`error` |
| `LDAPADM_TEMPLATES_DIR` | empty | optional custom XML template directory |

**Secrets are never parsed from the environment or stored in any config
file.** The bind password (and the optional `auto_number` password) resolve
through the chain:

1. env var `LDAPADM_BIND_PASSWORD` (or `LDAPADM_AUTO_NUMBER_PASSWORD`)
2. a 0600 file referenced by `LDAPADM_BIND_PASSWORD_FILE` (or
   `LDAPADM_AUTO_NUMBER_PASSWORD_FILE`)
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

- Fail-fast startup bind: the process refuses to start when the directory is
  unreachable or the certificate is expired.
- TLS 1.2 floor, mandatory verification, StartTLS-only (no plaintext
  fallback).
- Sessions: 256-bit opaque IDs in a `__Host-LDAPADM_SID` cookie
  (Secure/HttpOnly/SameSite=Strict), on-disk store with idle + absolute
  timeouts, rotation on every state change, 5-minute sweeper.
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

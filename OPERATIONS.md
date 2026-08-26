# ldapact operations runbook

## Secrets

The resolver chain (env → 0600 file → TTY) applies to `LDAPADM_BIND_PASSWORD`
and `LDAPADM_AUTO_NUMBER_PASSWORD`. No secret ever appears in config files, in
`/proc/PID/environ`, or in logs (truncated fingerprints only).

Examples:

- **env**: `LDAPADM_BIND_PASSWORD='...' systemctl start ldapact`
- **file**: `LDAPADM_BIND_PASSWORD_FILE=/run/credentials/ldapact.service/bind-password`
- **systemd**: `LoadCredential=bind-password:/etc/ldapact/bind-password`
- **k8s**: Secret mounted at `mode: 0600` (see `deploy/k8s/deployment.yaml`)

Rotate by replacing the file/env value and restarting. Startup fails fast when
the secret is missing or the file mode is wrong.

### Moving from YAML to env

This release replaced the YAML profile and the `-config` flag with `LDAPADM_*`
environment variables (see the reference table in README). If you scripted
startup with `-config /path/ldapact.yaml`, export the same values as env vars
instead and drop the flag; the required variables are `LDAPADM_URL`,
`LDAPADM_BASE_DN`, and `LDAPADM_BIND_DN`, with secrets injected exactly as
before (`LoadCredential`/mounted Secret + `LDAPADM_BIND_PASSWORD_FILE`).
Under systemd, edit `/etc/default/ldapact` (see
`deploy/systemd/ldapact.default.example`) — the unit file only references it via
`EnvironmentFile`, so configuration changes never require editing the unit.

## Sessions database

`LDAPADM_DB_PATH` (default `/var/lib/ldapact/sessions.db`, mode 0600) holds
the bbolt session store. When the variable is unset (or explicitly set to the
default value) and `/var/lib/ldapact` does not exist, the store falls back to
`~/.local/state/ldapact/sessions.db` (XDG-style per-user path) so
unprivileged, dev, and container runs need no pre-created system directory;
the parent directory is created with mode 0700 on first open. Lifecycle:

- **Backup**: stop the service, `cp sessions.db sessions.db.bak-$(date +%F)`,
  restart. (bbolt writes are atomic, but copy the file offline for a clean
  snapshot.)
- **Corruption**: bbolt free-list validation aborts startup; the process exits
  with a structured error rather than serving 503s. Restore from the latest
  backup; expired-session loss only forces an automatic re-login.
- **Cleanup**: the built-in sweeper removes expired entries every 5 minutes;
  no manual cleanup is required.

## Logging and audit (R15/AE6)

Logs are JSON on stdout. Every mutation emits one line:

```json
{"time":"...","level":"INFO","msg":"ldap mutation","event":"ldap.create","actor":"cn=admin,dc=example,dc=com","dn":"uid=alice,ou=People,dc=example,dc=com","op_type":"add"}
```

`userPassword` values are dropped at the logger boundary — grep your log
shipper for `userPassword` periodically as a regression check. Level is
controlled by `LDAPADM_LOG_LEVEL` (`error` silences audit lines for
storage-constrained deployments, but note the audit-loss tradeoff).

## TLS certificate rotation (LDAP)

`LDAPADM_CERT_EXPIRY_FAIL_CLOSED` (default `true`) refuses startup on expired
certificates and warns at < 30 days (`event=ldap.cert_expiring`). Rotate the
directory server certificate, then restart ldapact. Hostname verification uses
the SAN from the `LDAPADM_URL` host.

## Cutover playbook (phpLDAPadmin → ldapact)

1. **Parallel run**: deploy ldapact against the same directory with a read-only
   admin DN first (or the same bind DN); verify tree/schema/search render.
2. **Template inventory**: copy production custom templates into
   `templates_dir`; run `make test-integration`'s fixture gate or a smoke
   create for each template. The parser rejects unknown macros at load time —
   a failing template fails loudly, never silently.
3. **Switch traffic**: point users/DNS/proxy at ldapact. Keep phpLDAPadmin
   running read-only for one verification window (30 days recommended).
4. **Rollback**: flip back to phpLDAPadmin; session stores are independent, so
   no data migration is involved.

## LDAP error → HTTP mapping

| LDAP result | HTTP | Notes |
|---|---|---|
| 32 noSuchObject | 404 | entry missing |
| 49 invalidCredentials | 401/startup failure | fail-fast at boot (R14) |
| 65/19/20 schema/constraint | form inline error | create/password pages |
| 68 entryAlreadyExists | form inline error | create page |
| 4 sizeLimitExceeded | tree inline error | "narrow the filter" |
| 50 insufficientAccessRights | tree "(inaccessible)" | aria-disabled |
| network/ServerDown | retry-once, then inline retry | pool reconnect |

## v1 pre-launch checklist

Review each default from the plan (docs/plans/2026-08-24-001-...) and confirm
it still matches your deployment:

- Deployment model is loopback / internal VPN / mTLS-fronted (single admin
  bind + server-side session, AE1).
- LDAP server supports `userPassword` writes (OpenLDAP/389-DS); AD
  `unicodePwd` is v2.
- No Samba/batch/multi-profile needs in the near term (v2 scope).
- Custom template inventory is non-empty and covered by the parser corpus
  (plan C3 assumption).
- `LDAPADM_PASSWORD_PLAIN_OVERRIDE` stays `false` (unset).
- Sessions DB path is writable by the service user and backed up.
- Log shipper preserves JSON lines; `event=ldap.*` filters wired for audit
  queries.

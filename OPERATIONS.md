# ldapact operations runbook

## Secrets

The resolver chain (env → 0600 file) applies to `LDAPADM_SESSION_KEY`
(required), and optionally `LDAPADM_REDIS_PASSWORD` and
`LDAPADM_AUTO_NUMBER_PASSWORD`. `LDAPADM_BIND_PASSWORD` is deprecated and
ignored — the bind credential is entered on the login page and stored
encrypted in the session. No secret ever appears in config files, in
`/proc/PID/environ`, or in logs (truncated fingerprints only). There is no
interactive TTY prompt: ldapact is a server process, so a missing secret
fails fast at startup with an error naming the variable and its `_FILE`
reference.

Examples:

- **env**: `LDAPADM_SESSION_KEY="$(openssl rand -base64 32)" systemctl start ldapact`
- **file**: `LDAPADM_SESSION_KEY_FILE=/run/credentials/ldapact.service/session-key`
- **systemd**: `LoadCredential=session-key:/etc/ldapact/session-key`
- **k8s**: Secret mounted at `mode: 0600` (see `deploy/k8s/deployment.yaml`)

Rotate by replacing the file/env value and restarting. Startup fails fast when
the secret is missing or the file mode is wrong. **Rotating
`LDAPADM_SESSION_KEY` invalidates every stored session** (their encrypted
credentials can no longer be decrypted): users simply re-login — this is an
accepted tradeoff for short-lived admin sessions.

`LDAPADM_REDIS_PASSWORD` is optional: Redis without auth is allowed, and the
resolver returns empty when the variable and file reference are both absent.

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

## Session storage

`LDAPADM_SESSION_STORE` selects the backend: `redis` (default, shared across
instances), `bbolt` (single instance, on-disk), or `memory` (single instance,
cleared on restart). Sessions hold the bind DN plus the bind password
encrypted with AES-256-GCM under `LDAPADM_SESSION_KEY`; idle + absolute
timeouts, rotation on state changes, and invalidation on logout work the same
on every backend.

**Dev fallback:** when `LDAPADM_SESSION_STORE` is left at the default and
Redis is not configured at all (no `LDAPADM_REDIS_URL`), or the configured
Redis is loopback-only (`localhost`, `127.*`, `::1`) and unreachable, the
server starts with the in-memory store and logs
`event=session.redis_fallback_memory`. This keeps dev startup friction-free;
it does not apply to an explicitly configured `redis` store or a remote
Redis URL — those stay fail-fast, because silently degrading multi-instance
session sharing hides real configuration problems.

### Redis (default, multi-instance)

- Keys are `ldapa_sess:<id>`; the value is the JSON session record. A sliding
  TTL implements the idle timeout (refreshed atomically via `GETEX`); the
  absolute deadline is enforced from the value's timestamp (lazy deletion).
  Expired keys are reaped by Redis itself — no sweeper.
- Point every instance at the same Redis URL/database and the same
  `LDAPADM_SESSION_KEY`; sessions are then usable from any instance with no
  session affinity. Rotation, expiry, and logout take effect on every instance
  immediately.
- Startup fails fast when Redis is unreachable; runtime store failures render
  503 (monitor for `session.store_error` events).

### bbolt (single instance)

`LDAPADM_DB_PATH` (default `/var/lib/ldapact/sessions.db`, mode 0600) holds
the bbolt store. When the variable is unset (or explicitly set to the default
value) and `/var/lib/ldapact` does not exist, the store falls back to
`~/.local/state/ldapact/sessions.db` (XDG-style per-user path); the parent
directory is created with mode 0700 on first open. The file now contains
**encrypted credentials**, so backups and file permissions must cover it.
Lifecycle:

- **Backup**: stop the service, `cp sessions.db sessions.db.bak-$(date +%F)`,
  restart. (bbolt writes are atomic, but copy the file offline for a clean
  snapshot.)
- **Corruption**: bbolt free-list validation aborts startup; the process exits
  with a structured error rather than serving 503s. Restore from the latest
  backup; expired-session loss only forces a re-login.
- **Cleanup**: the built-in sweeper removes expired entries every 5 minutes;
  no manual cleanup is required.

### memory (single instance, dev)

In-process map with the same timeouts/rotation semantics; everything clears on
restart. Useful for dev and ephemeral containers only.

### Replica failover

`LDAPADM_SERVERS` (comma-separated URLs, mutually exclusive with
`LDAPADM_URL`) gives each replica its own unbound connection pool. Operations
rotate their starting replica and fail over to the next on network-level
errors (bounded at 2 attempts per replica); `invalidCredentials` (49) never
failovers — the identity is shared across replicas, so a rejected bind means
the credential is stale and the session is invalidated (redirect to login).
When every replica is unreachable, the error names each replica's reason
(look for `ldapx: all replicas failed`).

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

## LDAP server troubleshooting

If ldapact starts silently — no `LDAP bound` and no error — the directory
server may have wedged: it still accepts TCP connections but never processes
them (sessions hang before the first log line). Check the directory's own
log first. A MacPorts slapd configured with `loglevel conns stats` writes to
syslog LOG_LOCAL4, i.e. the macOS unified log:

```sh
log show --predicate 'process == "slapd"' --last 1h
```

Quick confirmation of a wedged server: `netstat -an | grep .389` shows
ESTABLISHED connections with a stuck Recv-Q, and even
`ldapsearch -x -H ldap://127.0.0.1:389 -b '' -s base` hangs.

Restart a wedged slapd with SIGKILL (SIGTERM is ineffective once it is
stuck), then let launchd start a fresh instance:

```sh
ps -eo pid,lstart,command | grep libexec/slapd   # note the old PID
sudo kill -9 <old-slapd-pid>
sudo launchctl kickstart -k system/org.macports.slapd
```

The MacPorts daemondo job runs with `--pid=none`, so `kickstart -k` only
restarts daemondo itself — kill the old slapd first or the fresh instance
fails to bind :389. Note that slapd's `logfile` directive only captures `-d`
debug messages, not `loglevel` output; `loglevel` always goes to syslog.

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

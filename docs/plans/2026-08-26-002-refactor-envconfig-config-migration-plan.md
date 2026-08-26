---
title: "refactor: migrate server config from YAML file to envconfig"
type: refactor
status: completed
date: 2026-08-26
---

# Migrate server config from YAML file to envconfig

## Summary

Replace the strict-YAML server profile and the `-config` flag with environment-variable configuration parsed by `github.com/kelseyhightower/envconfig` (flat `LDAPADM_*` namespace). Startup requires no config file: envconfig populates the existing `Config` struct, the existing `Validate()` and secret resolver chain run unchanged, and all deployment artifacts and docs move to env-driven configuration.

---

## Problem Frame

The server profile is currently a strict YAML file loaded by `config.Load(path)`, with the `-config` flag defaulting to `config/example.yaml`. That couples every deployment (Dockerfile CMD, k8s ConfigMap plus projected volume, systemd ExecStart, `make run`) to a mounted config file and forces operators to maintain a duplicate YAML artifact — even though the project already treats secrets as env/file-only and validates everything in code. The goal is a 12-factor, file-free configuration surface: environment variables with code defaults are the single source, matching the existing `LDAPADM_BIND_PASSWORD` / `LDAPADM_LOG_LEVEL` conventions.

---

## Requirements

- R1. All non-secret config fields are sourced from `LDAPADM_*` environment variables parsed by kelseyhightower/envconfig; no config file is read at startup.
- R2. Defaults and validation behavior are preserved: same default values, same policy checks (TLS floor, verify mandatory, StartTLS default-on for `ldap://`, session/pool ranges), same fail-fast startup.
- R3. Secrets keep the env → 0600 file → TTY resolver; they are never parsed by envconfig and never appear in logs.
- R4. Env semantics are explicit: set-but-empty vars are treated as unset (the shipped "empty is ignored" behavior), and unknown `LDAPADM_*` vars fail fast (preserving R12's unknown-key strictness in env form).
- R5. The `-config` flag and the YAML example are removed; Docker/k8s/systemd artifacts and operator docs become env-driven.
- R6. The four env names shipped previously stay valid: `LDAPADM_LISTEN`, `LDAPADM_URL`, `LDAPADM_BASE_DN`, `LDAPADM_BIND_DN`.

---

## Scope Boundaries

- No change to secret resolution, session, auth, LDAP, or web behavior.
- No TOML or other config formats, no multi-profile support, no config hot-reload or config subcommand.
- No changes to the `Config` struct shape or its consumers' APIs (`internal/app`, `pkg/ldapx`, `pkg/entry` compile unchanged).
- No other CLI flag changes: `-version`, `-healthcheck`, `-health-url` stay.
- Historical planning docs (`docs/brainstorms/`, `docs/plans/2026-08-24-001-...`) are not rewritten; they remain the record of the original design.

### Deferred to Follow-Up Work

- A `.env.example` for local dev and a generated env-reference tool: not needed for the migration; the README carries the reference table.
- Removing now-unused logging helpers (`NewFromEnv`/`LevelFromEnv`): left in place because they are exported and tested; cleanup is optional follow-up.

---

## Context & Research

### Relevant Code and Patterns

- `pkg/config/config.go`: `Config`/`LDAPConfig`/`TLSConfig`/`SessionConfig`/`ServerConfig` structs, defaults constants, `Validate()` (defaults + policy), `Load(path)`, `ApplyEnv()`, env constants (config.go:19-29).
- `pkg/config/secret.go`: `ResolveSecret`/`ResolveSecrets` chain (env → `_FILE` 0600 → TTY) and `SecretFingerprint`.
- `cmd/ldapact/main.go`: `-config` flag (main.go:46), `Load` → `ResolveSecrets` → `logging.LevelFromEnv` fallback (main.go:71-90) → `ldapx.New` → `app.NewHandler`.
- Config consumers: `internal/app/app.go` (`TemplatesDir`, `Session.ExpiredAction`, `LDAP.BindDN`), `pkg/ldapx/client.go` (`URL`/`BaseDN`/`BindDN`/`TreeFilter`/`AutoNumberDN` plus passwords), `pkg/entry/handlers.go` (`PasswordPlainOverride`, `PasswordScheme`, `AutoNumberDN`).
- Deployment surface: `Dockerfile` (CMD `-config`), `deploy/k8s/deployment.yaml` (ConfigMap `ldapact-config`, container args, projected volume, bind Secret), `deploy/systemd/ldapact.service` (ExecStart `-config`, `LoadCredential`), `Makefile` (`run` target).

### Institutional Learnings

- `docs/solutions/` does not exist in this repo; no prior solution docs apply.
- `docs/brainstorms/ldapact-go-reimplementation.md` R12: strict single-profile config, secrets never plaintext (env/file/TTY only), `LDAPADM_` prefix convention. The YAML-file choice is superseded by this plan per user direction; the secret-handling and naming constraints are carried forward.

### External References

- kelseyhightower/envconfig v1.4.0 README and source: tag vocabulary, nested-struct prefixing, pointer handling, empty-vs-unset semantics, `ParseError` format, `CheckDisallowed`.
- 12factor.net/config: env-var configuration, code defaults, fail-fast startup.

---

## Key Technical Decisions

- **Pinned library, empty prefix, full-name tags**: envconfig v1.4.0, invoked with an empty prefix and explicit `envconfig:"LDAPADM_..."` tags on every parsed field. Rationale: with a prefix plus short tags, envconfig falls back to the bare tag name when the prefixed key is missing (e.g. `LDAPADM_URL` unset but `URL` set), which would silently read generic vars like `URL`/`VERIFY`; full-name tags make that fallback a no-op.
- **Flat namespace**: `LDAPADM_` + leaf config key (`LDAPADM_URL`, `LDAPADM_MIN_VERSION`, `LDAPADM_START_TLS`, `LDAPADM_TIMEOUT_MINUTES`, ...). Rationale: consistent with the four shipped names and `LDAPADM_LOG_LEVEL`; nested-section prefixes (`LDAPADM_LDAP_*`, `LDAPADM_TLS_*`) would contradict what already shipped.
- **Defaults stay in `Validate()`**: envconfig is parsing-only; no `default` tags. Rationale: single source of truth for defaults, including conditional logic (StartTLS default-on only for `ldap://`, `Verify`/`CertExpiryFailClosed` default true) that tags cannot express.
- **Required enforcement stays in `Validate()`**: no `required` tags; missing `url`/`base_dn`/`bind_dn` keep the existing messages. Rationale: preserve error wording; envconfig still produces parse errors naming the env var for invalid values.
- **"Empty env is ignored" preserved via pre-pass**: before parsing, unset any `LDAPADM_*` var whose value is empty. Rationale: keeps the semantic already shipped and tested (an empty var never overrides or clears), and makes `LDAPADM_BIND_PASSWORD=""` fall through the resolver chain exactly as today.
- **Strict unknown-var check (custom)**: reject any `LDAPADM_*` var not in a known allowlist (all config names + `LDAPADM_LOG_LEVEL` + `LDAPADM_BIND_PASSWORD`/`LDAPADM_AUTO_NUMBER_PASSWORD` and their `_FILE` variants). Rationale: preserves R12's unknown-key rejection as a typo guard; envconfig's own `CheckDisallowed` is unusable here (empty prefix would flag the whole environment; a prefix would flag secret/`_FILE`/test vars).
- **Secrets excluded from envconfig**: `BindPassword`/`AutoNumberPassword` tagged ignored; the resolver chain is unchanged. Rationale: file/TTY fallbacks and 0600 enforcement are security behavior, not config parsing.
- **Clean break**: `-config` removed entirely (no compat shim); log level comes from `cfg.LogLevel` only (`LDAPADM_LOG_LEVEL` parsed by envconfig), dropping main's dual `LevelFromEnv`/fallback logic. Rationale: user-confirmed scope; single source of truth; the app is pre-1.0.

---

## Open Questions

### Resolved During Planning

- `-config` fate: removed entirely (clean break).
- YAML example artifact: deleted; the README gets the env reference table.
- Empty-env semantics: "empty is ignored" preserved via pre-pass.
- Unknown-env strictness: preserved via allowlist check.
- TLS/session env naming: flat leaf names (`LDAPADM_MIN_VERSION`, `LDAPADM_TIMEOUT_MINUTES`).

### Deferred to Implementation

- k8s manifest layout (inline env list vs `envFrom` ConfigMap): implementer picks the style that keeps the manifest readable; both are valid.
- systemd env wiring (`Environment=` lines vs `EnvironmentFile=`): implementer picks per deployment convention.
- Whether the strict allowlist should ever include test-harness vars (`LDAPADM_TEST_*`): default is no — a prod environment carrying test vars is misconfigured.

---

## Implementation Units

### U1. Env-driven config loading in pkg/config

**Goal:** Replace YAML parsing with envconfig; keep the `Config` struct shape, `Validate()`, and `ResolveSecrets()`; preserve all documented semantics.

**Requirements:** R1, R2, R3, R4, R6

**Dependencies:** None

**Files:**
- Modify: `pkg/config/config.go`
- Test: `pkg/config/config_test.go`
- Modify (dependency only): `go.mod`, `go.sum` (add envconfig v1.4.0)

**Approach:**
- Re-tag struct fields: YAML tags → explicit full-name envconfig tags per the mapping below; runtime secret fields → `ignored:"true"`.
- Replace `Load(path)` with `Load()` (no argument): pre-pass that unsets empty `LDAPADM_*` vars → envconfig parse → strict unknown-var allowlist check → `Validate()`. `ApplyEnv()` is removed (superseded).
- Keep the exported env name constants (`ListenEnv`/`URLEnv`/`BaseDNEnv`/`BindDNEnv` and the secret constants) as the single source of truth for tags, the allowlist, and tests.
- Remove the yaml.v3 import from `pkg/config/config.go`.

**Env var mapping (contract for this unit):**

| Config key | Env var | Notes |
|---|---|---|
| `server.listen` | `LDAPADM_LISTEN` | default `127.0.0.1:8080` |
| `ldap.url` | `LDAPADM_URL` | required; `ldap://` or `ldaps://` |
| `ldap.base_dn` | `LDAPADM_BASE_DN` | required |
| `ldap.bind_dn` | `LDAPADM_BIND_DN` | required |
| `ldap.auto_number_dn` | `LDAPADM_AUTO_NUMBER_DN` | optional |
| `ldap.tls.min_version` | `LDAPADM_MIN_VERSION` | default `TLSv1.2` |
| `ldap.tls.verify` | `LDAPADM_VERIFY` | bool; `false` rejected |
| `ldap.tls.start_tls` | `LDAPADM_START_TLS` | bool; default on for `ldap://` |
| `ldap.tls.cert_expiry_fail_closed` | `LDAPADM_CERT_EXPIRY_FAIL_CLOSED` | bool; default true |
| `ldap.schema_compat` | `LDAPADM_SCHEMA_COMPAT` | default `openldap` |
| `ldap.tree_filter` | `LDAPADM_TREE_FILTER` | default `(objectClass=*)` |
| `ldap.pool_size` | `LDAPADM_POOL_SIZE` | int; default 8, 1..100 |
| `ldap.password_plain_override` | `LDAPADM_PASSWORD_PLAIN_OVERRIDE` | bool; default false |
| `ldap.password_scheme` | `LDAPADM_PASSWORD_SCHEME` | optional; empty = engine default |
| `session.timeout_minutes` | `LDAPADM_TIMEOUT_MINUTES` | int; default 30, 5..240 |
| `session.absolute_timeout_minutes` | `LDAPADM_ABSOLUTE_TIMEOUT_MINUTES` | int; default 480, 30..1440 |
| `session.expired_action` | `LDAPADM_EXPIRED_ACTION` | default `retry_bind` |
| `session.db_path` | `LDAPADM_DB_PATH` | default `/var/lib/ldapact/sessions.db` |
| `log_level` | `LDAPADM_LOG_LEVEL` | default `info` |
| `templates_dir` | `LDAPADM_TEMPLATES_DIR` | optional |
| secrets | `LDAPADM_BIND_PASSWORD`, `LDAPADM_AUTO_NUMBER_PASSWORD` (+ `_FILE`) | resolver chain; not parsed by envconfig |

**Patterns to follow:**
- Existing `Validate()` structure and error messages in `pkg/config/config.go`.
- Existing `t.Setenv` test style in `pkg/config/config_test.go`.

**Test scenarios:**
- Happy path: full config via env vars populates every section, including TLS pointers (`LDAPADM_VERIFY=true`, `LDAPADM_START_TLS=true`, `LDAPADM_CERT_EXPIRY_FAIL_CLOSED=false`) and session fields.
- Happy path: minimal config (`LDAPADM_URL`/`LDAPADM_BASE_DN`/`LDAPADM_BIND_DN` only) yields all existing defaults (listen, log_level, schema_compat, tree_filter, pool_size, TLS, session).
- Happy path: R6 regression — the four shipped env names still work.
- Happy path: `LDAPADM_START_TLS=false` is preserved as explicit false (plaintext dev mode), matching the existing `TestValidateStartTLSExplicitFalse` expectation.
- Edge case: set-but-empty vars for string, int, and bool-pointer fields are treated as unset (defaults apply), matching the shipped "empty is ignored" tests.
- Edge case: unset bool pointers stay nil before `Validate()`; `Validate()` fills the true defaults.
- Error path: `LDAPADM_URL` with a non-ldap scheme → existing `ldap.url` validation error.
- Error path: missing `LDAPADM_BASE_DN` / `LDAPADM_BIND_DN` → existing required errors.
- Error path: `LDAPADM_POOL_SIZE=abc` and `LDAPADM_START_TLS=maybe` → envconfig parse error naming the env var.
- Error path: `LDAPADM_VERIFY=false`, `ldaps://` + `LDAPADM_START_TLS=true`, `LDAPADM_MIN_VERSION=TLSv1.1`, `LDAPADM_LOG_LEVEL=loud`, session range violations, bad `LDAPADM_PASSWORD_SCHEME` → existing validation errors.
- Error path: unknown var such as `LDAPADM_LITSEN` → strict allowlist error naming the var.
- Edge case: a stray unprefixed `URL=...` in the environment is ignored (full-name-tag footgun guard).
- Regression: secret resolver tests (env / `_FILE` 0600 / TTY) pass unchanged; `LDAPADM_BIND_PASSWORD=""` falls through to `_FILE`/TTY.

**Verification:**
- The `pkg/config` test suite passes with the rewritten env-based tests; the package no longer references yaml.v3; formatting and vet checks are clean.

### U2. Remove config-file path from CLI and tree

**Goal:** Startup consumes env only; the `-config` flag is gone; the YAML example and yaml.v3 dependency are removed.

**Requirements:** R1, R5

**Dependencies:** U1

**Files:**
- Modify: `cmd/ldapact/main.go`
- Delete: `config/example.yaml` (and the `config/` directory if empty)
- Modify: `go.mod`, `go.sum` (drop `gopkg.in/yaml.v3` via module tidy)

**Approach:**
- Remove the `-config` flag and the `configPath` variable; call `config.Load()` with no argument.
- Simplify log level: derive it from `cfg.LogLevel` only (`LDAPADM_LOG_LEVEL` is parsed by envconfig in U1); drop the `LevelFromEnv`/fallback dance. Leave the `pkg/logging` helpers in place (exported and tested; cleanup deferred).
- Keep `-version`/`-healthcheck`/`-health-url` behavior unchanged.

**Test expectation:** none — `cmd/ldapact` has no unit-test seam for flag plumbing; coverage is build and smoke below.

**Verification:**
- The `cmd/ldapact` binary builds and vets cleanly; the module tidy leaves yaml.v3 out of `go.mod`.
- The binary's help output lists no `-config` flag.
- Smoke: with only `LDAPADM_URL`/`LDAPADM_BASE_DN`/`LDAPADM_BIND_DN` set, the binary reaches the same bind/serve startup path as today — no file involved.

### U3. Env-driven deployment artifacts

**Goal:** Docker, k8s, systemd, and the Makefile run without any config file or `-config` argument.

**Requirements:** R5

**Dependencies:** U2

**Files:**
- Modify: `Dockerfile`
- Modify: `deploy/k8s/deployment.yaml`
- Modify: `deploy/systemd/ldapact.service`
- Modify: `Makefile`

**Approach:**
- Dockerfile: remove the CMD `-config`; the ENTRYPOINT runs the binary with no args (env injected at runtime).
- k8s: the ConfigMap data becomes env-var key/value pairs (inline or `envFrom`) covering the non-secret fields; container args and the projected config volume are removed; the bind Secret mount plus `LDAPADM_BIND_PASSWORD_FILE` stay.
- systemd: ExecStart drops `-config`; add `Environment=` (or `EnvironmentFile=`) entries for non-secret fields; `LoadCredential` plus `LDAPADM_BIND_PASSWORD_FILE` stay.
- Makefile: the `run` target drops `-config`; the README documents the required exports for local dev (U4).

**Test expectation:** none — manifests and service files have no unit-test seam; they are validated by parsing and smoke runs.

**Verification:**
- The container image builds with the new CMD; a container started with env vars only (no mounted config) reaches the same startup path.
- The k8s manifest parses under a client-side dry-run and contains no `-config`/config-volume reference.
- The systemd unit parses under `systemd-analyze verify` (where available) and contains no `-config` reference.

### U4. Documentation update

**Goal:** README/OPERATIONS/CHANGELOG describe the env-driven config with the full env reference; no stale `-config`/YAML claims remain.

**Requirements:** R5

**Dependencies:** U1 (env names final), U2 (flag/artifact removal)

**Files:**
- Modify: `README.md`
- Modify: `OPERATIONS.md`
- Modify: `CHANGELOG.md`

**Approach:**
- README: rewrite the Configuration section into the env reference table from U1 (with defaults and required markers); the quick start becomes env exports plus `./bin/ldapact`; deployment-models and `make run` notes updated.
- OPERATIONS.md: the secrets section wording drops the YAML claim ("never stored in config files"/"never plaintext"); session and TLS sections name the env vars (`LDAPADM_DB_PATH`, `LDAPADM_CERT_EXPIRY_FAIL_CLOSED`); add a short "moving from YAML to env" note for operators.
- CHANGELOG.md: record the migration, the removed flag (breaking for anyone scripting startup), and the env reference.

**Test expectation:** none — docs; covered by the grep verification below.

**Verification:**
- README/OPERATIONS contain no live references to `-config`, `config/example.yaml`, or `ldapact.yaml` (historical docs may mention them).
- Every env var in the reference table matches a tag implemented in U1 (spot-check against the config package constants).

---

## System-Wide Impact

- **Interaction graph:** startup only — main → `config.Load()` → `ResolveSecrets` → logger → `ldapx.New` → `app.NewHandler`. No middleware, handler, or store changes.
- **Error propagation:** config failures stay fail-fast — envconfig parse errors name the env var; strict allowlist errors name the var; `Validate()` errors keep existing wording; secret errors are unchanged. All exit non-zero via main.
- **State lifecycle risks:** none — config is read once at boot; no reload, partial-write, or shared-state concerns.
- **API surface parity:** the `Config` struct and all consumer code compile unchanged; the CLI surface loses `-config` (intentional); the env surface becomes the full config contract (additive relative to the four shipped names; secrets unchanged).
- **Integration coverage:** `test/integration` uses `internal/testldap`'s in-memory config (`inst.Config()`), so it is unaffected; a container/env smoke proves the file-free path.
- **Unchanged invariants:** secret resolver chain, validation policy, defaults, `-version`/`-healthcheck` flags, and all LDAP/session/web behavior.

---

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| envconfig v1.4.0 is effectively unmaintained | Pin the exact version; the library is tiny and `pkg/config` wraps it thinly, so replacement is cheap if maintenance becomes a problem |
| Behavior drift in edge semantics (empty vars, unknown vars, pointer defaults) | Pre-pass + strict allowlist + the full U1 test matrix preserve shipped semantics |
| Bare-name fallback reads unprefixed vars (`URL`, `VERIFY`, `DEBUG`) | Full-name tags with empty prefix plus a dedicated regression test |
| Deployment breakage if only some artifacts are updated | U3 updates every `-config` reference in the same change; U4 grep-verifies docs |
| Breaking CLI change | Intentional per confirmed scope; CHANGELOG and README document it |

---

## Documentation / Operational Notes

- Operators move from `-config /path/ldapact.yaml` to exported `LDAPADM_*` vars (U4 table); the secrets workflow is unchanged (`LoadCredential`/k8s Secret still work).
- The CHANGELOG records the flag removal as breaking for anyone scripting startup.
- No monitoring or rollout changes beyond the env contract.

---

## Sources & References

- Related code: `pkg/config/config.go`, `pkg/config/secret.go`, `cmd/ldapact/main.go`, `deploy/k8s/deployment.yaml`, `deploy/systemd/ldapact.service`, `Dockerfile`, `Makefile`
- Related prior commit: `43ee2b9` (env overrides for the core profile fields — the R6 names)
- External docs: github.com/kelseyhightower/envconfig (v1.4.0 source and README), 12factor.net/config

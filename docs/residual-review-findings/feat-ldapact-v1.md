# Known Residuals — ldapact v1 (feat/ldapact-v1)

Source review run: `ce-code-review` run `20260825-153915` (inline execution;
sub-agent dispatch is non-functional in this harness). Run artifact:
`/tmp/compound-engineering/ce-code-review/20260825-153915/`.
Decision: **Accept and proceed** (user-approved) — findings recorded here and
shipped with the v1 implementation.

## 1. F2 multi-page wizard is single-page (P2)

`pkg/entry/create.go` renders all template pages in one form with a client-side
step indicator (`aria-current="step"`), instead of the plan's server-side
per-page session state with back-button preservation.

Why accepted: AE3 (posixAccount form parity + create) is satisfied; per-page
server-side state adds a session-backed POST flow with no functional gain for
the v1 acceptance examples. Revisit if multi-page UX fidelity is required.

## 2. Subtree export re-runs paging from page 1 per page (P2)

`pkg/ldif/export.go` streams pages through the stateless `ldapx.Page` API,
which re-runs the paged search from the start for each page — correct output,
but O(n²) server searches for very large subtrees (the 50k-entry export
verification target).

Why accepted: v1 trees are admin-scale; a sequential cookie cursor or
`SearchAsync` stream is the follow-up when large-scale exports are measured.

## 3. Session rotation precedes state-changing handlers (P2)

`pkg/authn/middleware.go` rotates the session ID before state-changing
handlers run because a post-handler `Set-Cookie` cannot be committed reliably
after the body is written. Failed mutations also rotate (conservative; no
session-fixation risk).

Why accepted: OWASP direction is satisfied (renewal on state change); exact
success-only rotation would require buffered responses and was judged
not-worth-the-complexity for v1.

## Implementation notes (resolved during execution)

- **gzip pre-compression for static assets** (plan "Deferred to
  Implementation"): resolved as *not implemented* for v1 — embedded assets are
  small (htmx 50 KB, CSS/JS ~10 KB total) and the tool is network-local; revisit
  if assets grow or remote deployments need it.
- **F2 form state** (plan: session-backed per-form UUID): superseded by
  finding 1 above.
- **Cookie Secure=true unconditionally** (advisory): local plain-HTTP browsers
  will not retain sessions; production deployments are HTTPS by design
  (`__Host-` prefix requires it).
- **Rate limiter** keys on `RemoteAddr` (advisory): shared reverse proxies
  share the per-IP budget.
- **AE2 scale** (advisory): the integration harness exercises paging with 1210
  children (Docker-gated); the exact 5000-child scenario is a CI-scale test.

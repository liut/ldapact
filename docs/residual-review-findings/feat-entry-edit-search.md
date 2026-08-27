# Accepted review residuals: entry edit + search completion

Source review run: `ce-code-review` (autofix), run ID `20260827-004931-7704bea6`,
2026-08-27, on branch `feat/ldapact-v1` (base `9025306`).

Plan: `docs/plans/2026-08-26-003-feat-entry-edit-search-plan.md` (completed).

## Findings and disposition

The review surfaced six findings. Four code fixes were applied in this change:
the template-path edit fields exclude `userPassword`/operational attributes and
mark binary values read-only; the chosen modification template round-trips
through review/apply as a hidden field; duplicated submitted values are
deduped; and the search results page states when ordering applies only within
the page. The remaining items below are accepted as documented follow-ups,
not blocking defects:

## Accepted residuals

- **Strict server-side sort without client fallback.** When the directory
  rejects the RFC 2891 sort control, ordering is applied within each returned
  page, so multi-page sorted results may be inconsistent across page
  boundaries. The results page states this, and the plan defers strict sort
  to follow-up ("a later pass can make sort strict").
- **`size_limit`/`time_limit` are per LDAP request.** Paged sessions grant a
  fresh per-request budget, so pagination may exceed a requested size limit.
  Documented in the README; per-session limit accounting is follow-up.
- **Agent-native surface.** The edit/search surfaces are HTML-form/query
  interfaces consistent with the rest of the product (create/delete/rename);
  there is no JSON API by design.

No pre-existing issues were flagged; no learnings existed (`docs/solutions/`
has no entries).

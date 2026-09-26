# Row Level Security Access Matrix

Audited 2026-09-19 as part of Member 3's Stage 7 (RLS and privacy hardening) work.
This reflects the database as it actually exists, not an aspirational design. Update
this file whenever a table or policy changes.

## How this system enforces access, in one paragraph

The `service_role` Postgres role bypasses Row Level Security entirely regardless of
policies (this is Supabase's default behavior). `services/api` is the only holder of
the service-role key, so in practice the API is the trust boundary, not the database
role system. Moderator and admin access is checked in application code
(`services/api/src/http/auth.mjs`, via the caller's Supabase Auth JWT and its
`app_metadata.role` claim), then the API itself uses the service-role key to read or
write. This means the `anon` and `authenticated` Postgres roles below only matter for
someone bypassing the API and talking to Supabase's REST API directly with a plain key
or a non-moderator user's JWT. The policies exist to make sure that path is safe.

## Matrix

| Table | anon | authenticated | service_role (via API only) |
|---|---|---|---|
| `submissions` | no access | no access | full access |
| `extracted_entities` | no access | no access | full access |
| `findings` | no access | no access | full access |
| `approved_organizations` | read active rows only | read active rows only | full access (bypasses RLS; no explicit policy needed) |
| `user_reports` | insert only, forced to `status = 'PENDING'` | insert only, forced to `status = 'PENDING'` | full access |
| `verified_intelligence` | read active rows only | read active rows only | full access |
| `moderation_audit_logs` | no access | no access | full access |

Verified live for `approved_organizations` in `services/api/test/domainDirectoryRls.test.mjs`
(anon can read active rows, cannot insert or update; service role can do both).

## Findings from this audit

- **No gaps found in table-level access control.** Every table either has no
  anon/authenticated policy at all (full implicit deny, correct for private pipeline
  data) or a narrowly scoped read/insert policy matching its intended public use.
- **`submissions` has no `user_id` ownership column and no end-user login flow.**
  "Users cannot view another user's private data" is currently satisfied trivially,
  since no one, including the original submitter, can read a past submission back via
  direct Supabase access; it only ever appears in that request's own API response.
  This is worth knowing if end-user accounts are added later, since ownership-based
  RLS policies would need to be introduced at that point, not assumed to already exist.
- **Retention (`expires_at`) was a real gap and has been fixed**: the column existed
  since the first migration but was never set on insert and nothing ever purged
  expired rows. `persistIfConsented` now sets a 90-day `expires_at`, and
  `purgeExpiredSubmissions` runs on a daily timer inside the API process (see
  `services/api/src/services/persistence.mjs` and the retention purge wiring in
  `server.mjs`). `extracted_entities` and `findings` cascade-delete with their parent
  submission, so purging `submissions` alone is sufficient.
- **No Supabase Storage bucket exists yet.** Screenshots are processed client-side via
  Tesseract.js per the project proposal, so there is nothing to harden here right now.
  Flagged for whoever adds server-side screenshot storage later, not fixed here.
- **No Gemini/LLM integration exists yet in this codebase.** Redaction of phone
  numbers, emails, and account details before an external model call cannot be built
  or tested against code that does not exist. Flagged as a requirement for whoever
  builds the AI adapter, not fixed here.
- **Logging reviewed**: `console.log`/`console.error` calls in `services/api/src`
  contain only operational messages (startup, shutdown, scanner failures by generic
  reason), no secrets or raw submission content.

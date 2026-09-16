# Open Architecture Decisions

This file tracks decisions that affect shared code but have not yet been confirmed by
the team or the team leader. Each entry should be updated with the outcome once it is
settled, rather than deleted, so there is a record of what was decided and why.

## 1. Domain-directory table name

**Status:** Pending confirmation.

The existing migration (`supabase/migrations/202609140001_initial_schema.sql`) created
a table named `approved_organizations`. The Full Development Plan document refers to
the same concept as `official_domains`.

**Recommendation:** keep `approved_organizations`, since it already exists, is seeded,
and other branches may already depend on it. Renaming later is a breaking change for
anyone with local data or in-progress work against the current name.

## 2. Shared contracts versus hand-written validation

**Status:** Pending confirmation.

`packages/contracts` holds Zod schemas meant to be the shared source of truth for
submission, entity, and finding shapes. `services/api/src/services/analysis.mjs`
currently has its own hand-written `validateSubmission` function that duplicates part
of this validation logic in plain JavaScript.

**Recommendation:** migrate `services/api` to import and use the Zod schemas directly,
so there is exactly one definition of what a valid submission looks like. This affects
every endpoint the API exposes, so it should happen before more endpoints are added.

## 3. Split of URL-related work between Member 2 and Member 3

**Status:** Pending confirmation.

The two planning documents describe this differently:
- `TrustLens_LK_Five_Member_Equal_Work_Division.pdf` gives Member 3 the full "URL and
  Domain Verification" vertical slice, with no URL-related work listed for Member 2.
- `TrustLens_LK_Full_Development_Plan.pdf`'s ordered task list gives Member 2 both
  "Entity extraction" (which includes URL and domain extraction) and "suspicious-link
  rules" as part of "Core scam rules".

**Recommendation (proposed to the team, not yet agreed):**
- Member 2 owns extracting URLs and domains that appear inside free-text message
  submissions, plus generic keyword-style suspicious-link rules (shorteners, raw IP
  hosts, and similar signals treated as one rule among many).
- Member 3 owns everything downstream of a direct URL submission: normalization,
  scheme validation, registrable-domain extraction, and matching against the
  official-domain directory for a match, mismatch, or unknown verdict.

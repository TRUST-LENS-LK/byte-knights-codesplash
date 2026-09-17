# Open Architecture Decisions

This file tracks decisions that affect shared code but have not yet been confirmed by
the team or the team leader. Each entry should be updated with the outcome once it is
settled, rather than deleted, so there is a record of what was decided and why.

## 1. Domain-directory table name

**Status:** Pending confirmation. The leader referenced example names
(`official_domains` or `verified_organizations`) when confirming decision 4 below,
but this may just be illustrative wording rather than a decision to rename the
existing table. Needs one more explicit check.

The existing migration (`supabase/migrations/202609140001_initial_schema.sql`) created
a table named `approved_organizations`, and it is already wired into
`services/api/src/services/domainVerification.mjs`. The Full Development Plan document
refers to the same concept as `official_domains`.

**Recommendation:** keep `approved_organizations` and extend it with governance columns
(reviewer, status, review dates), since it already exists, is seeded, and is already
used by working code. Renaming later is a breaking change for anyone depending on the
current name.

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

**Status:** Confirmed by the leader (2026-09-17).

The two planning documents originally described this differently:
- `TrustLens_LK_Five_Member_Equal_Work_Division.pdf` gives Member 3 the full "URL and
  Domain Verification" vertical slice, with no URL-related work listed for Member 2.
- `TrustLens_LK_Full_Development_Plan.pdf`'s ordered task list gives Member 2 both
  "Entity extraction" (which includes URL and domain extraction) and "suspicious-link
  rules" as part of "Core scam rules".

**Confirmed split:**
- Member 2 owns extracting URLs and domains that appear inside free-text message
  submissions and screenshots, plus generic structural suspicious-link rules
  (shorteners, raw IP hosts, and similar signals treated as one rule among many).
- Member 3 owns everything downstream once a URL or domain is handed off:
  registrable-domain extraction, normalization, and cross-referencing against the
  official-domain directory to verify the claimed organization.

## 4. Database foundation ownership: Member 3 versus Member 5

**Status:** Confirmed by the leader (2026-09-17).

Member 4's clarification message initially said Member 3 owns "database foundation,"
which conflicted with the Full Development Plan's task #4 ("Database foundation":
initial migrations, roles, users, submissions tables), assigned to Member 5.

**Confirmed split:**
- Member 5 owns the core schema (`submissions`, `extracted_entities`, `findings`,
  `user_reports`, and related pipeline tables) so the base pipeline functions.
  Member 3 does not rebuild or duplicate this schema.
- Member 3's database scope is strictly: (a) the tables specific to the
  domain-directory slice, and (b) a later pass to harden Row Level Security policies
  across the entire database once the core tables are stable.

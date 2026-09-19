# Member 3 Implementation Notes: URL and Domain Verification

What this slice does, how to demo it, and its known limitations, per the project's
Definition of Done requirement to document setup, assumptions, limitations, and
demonstration steps for each vertical slice.

## What this slice answers

Given a message or a submitted URL, this slice answers one question: **does the
domain actually belong to the organization it claims to represent?** It never visits
the destination page (that is Member 4's scanner); it works purely on the URL/domain
string and the official-domain directory.

## What was built

- **Official domain directory** (`approved_organizations` table): reviewed
  organizations with a reviewer, verification date, next review date, and status
  (`ACTIVE` / `STALE` / `RETIRED`). Entries older than their review date stop
  contributing positive evidence automatically (`isDirectoryEntryStale` in
  `packages/domain`).
- **Domain matching** (`matchesOfficialDomain`): a submitted domain matches an
  official entry if it is that domain or a subdomain of it, not a substring
  lookalike (`boc.lk.evil.com` does not match `boc.lk`).
- **Claimed-organization mismatch detection** (`checkOrganizationDomainMatch`, wired
  into `/api/analyze` via `checkClaimedOrganizationDomain`): compares the organization
  name extracted from a message against the actual destination domain. Produces one
  of `MATCHED`, `MISMATCH`, `UNKNOWN`, or `STALE`. A `MISMATCH` is a critical override:
  it forces `HIGH` risk and `STOP_AND_AVOID` regardless of what the text-only rules
  alone would have produced (`applyDomainMismatchRisk`).
- **Dedicated URL submissions**: `POST /api/analyze` accepts `{ type: 'url', url }`
  directly, not just a URL embedded in free text.
- **Directory read API**: `GET /api/domain-directory` (list, optional `category`
  filter) and `GET /api/domain-directory/lookup?domain=` (single lookup).
- **Frontend**: a "Domain identity check" evidence card showing the claimed
  organization, the actual (defanged) destination domain, and the evidence sentence,
  distinct from the generic findings list.
- **Retention and RLS**: consented submissions now expire after 90 days and are
  purged automatically; the full access matrix is documented in
  `docs/rls-access-matrix.md`.

## How to demonstrate it

1. Paste this into the checker: *"Congratulations! You have been selected for a
   remote job at Virtusa Pvt Ltd. Please pay Rs. 5000 registration fee today at
   https://virtusa-careers-login.com to confirm your position."*
2. Point out the extracted claimed organization (Virtusa Pvt Ltd) and destination
   domain (virtusa-careers-login.com) in the "Domain identity check" card.
3. Show the result: `HIGH` risk, `STOP_AND_AVOID`, with `domain_mismatch` as one of
   the listed findings and evidence quoting the real official domain (`virtusa.com`).
4. Contrast with a legitimate example: a message mentioning Bank of Ceylon linking to
   `https://boc.lk` produces `LOW` risk with an `approved_domain` finding instead.
5. Contrast again with an organization not in the directory (any small/unlisted
   company): no domain-related finding appears at all, demonstrating that an unlisted
   organization is treated as "Unable to Verify," never as proof of fraud.

## Known limitations

- **Abbreviations are not resolved.** The extraction package recognizes bare
  abbreviations like "BOC" or "HNB" as organization entities, but the directory
  matcher only does exact and substring name matching, not abbreviation expansion. A
  message using only "BOC" (never spelling out "Bank of Ceylon") will currently
  produce `UNKNOWN`, not `MATCHED` or `MISMATCH`. Fixing this needs an alias list per
  directory entry, tracked as a follow-up rather than built now.
- **Only the first organization and first domain in a submission are compared.** A
  message naming multiple organizations or containing multiple links only checks the
  first pair found. This matches the project's single fake-job demo scenario but is a
  simplification for messages with more complex structure.
- **The domain-directory dataset is small and seeded from general knowledge, not a
  live lookup.** `supabase/seed/002_expand_domain_directory.sql` explicitly flags that
  each `source_url` should be spot-checked before being relied on for a real
  deployment; it is adequate for a hackathon demo directory of about a dozen
  organizations.
- **Redirect evidence display (originally planned Stage 6.5) was not built.** It
  depends on agreeing a data shape with Member 4's scanner output, which did not
  happen in this development window.
- **No registrable-domain/public-suffix utility was built for general use** (planned
  Stage 4.3), since Member 4's scanner already independently implemented most of the
  equivalent structural URL heuristics (embedded credentials, non-standard ports,
  punycode hostnames, subdomain depth) before this slice reached that stage. This
  does mean Member 4's subdomain-depth heuristic has no public-suffix awareness and
  may false-positive on legitimate multi-label Sri Lankan domains (see
  `docs/decisions.md`, decision 5); this was flagged, not fixed, since it lives in
  another member's file.

## Setup

Requires `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` in `services/api/.env` (see
`.env.example`). No additional configuration specific to this slice; the domain
directory and its governance columns are created by
`supabase/migrations/202609190001_domain_directory_governance.sql`.

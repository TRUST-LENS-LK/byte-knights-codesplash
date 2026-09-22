# Member 3 Implementation Notes: URL and Domain Verification

What this slice does, how to demo it, and its known limitations, per the project's
Definition of Done requirement to document setup, assumptions, limitations, and
demonstration steps for each vertical slice.

## What this slice answers

Given a message or a submitted URL, this slice answers two questions: **does the
domain actually belong to the organization it claims to represent?**, and, more
generally, **is this domain itself trustworthy at all** — known-good, known-malicious,
or brand new and unproven? It never visits the destination page (that is Member 4's
scanner); it works purely on the URL/domain string, the official-domain directory, and
external domain-reputation signals.

## What was built

A five-tier verification cascade runs inside `/api/analyze` for every URL, from most
specific/authoritative to most general, each tier only running when a faster, more
specific tier hasn't already resolved the domain:

1. **Official domain directory** (`approved_organizations` table, Tier 1): reviewed
   Sri Lankan organizations with a reviewer, verification date, next review date, and
   status (`ACTIVE` / `STALE` / `RETIRED`). Entries older than their review date stop
   contributing positive evidence automatically (`isDirectoryEntryStale` in
   `packages/domain`). Matching (`matchesOfficialDomain`) treats a domain or its
   subdomain as a match, never a substring lookalike (`boc.lk.evil.com` does not match
   `boc.lk`).
2. **Community intelligence** (existing reconciliation engine): prior moderator-
   verified reports about the same domain.
3. **Global domain trust** (`checkGlobalDomainTrust` in `services/api`, backed by
   `packages/domain`'s `isTopGlobalDomain`): is this one of the world's ~1,000,000
   most-visited domains, per the Tranco research ranking? Checked via an in-memory
   top-20,000 set first (microsecond lookups, embedded at build time), falling back to
   a Supabase-held `global_trusted_domains` table (the full 1M-row list) only on a
   miss. This is weaker evidence than Tier 1 (a lower `strength`), since global
   popularity isn't the same as being verified for a Sri Lankan audience.
4. **Google Safe Browsing** (`checkSafeBrowsing`/`applyKnownMaliciousRisk`): a live
   reputation check against Google's malware/phishing/unwanted-software threat lists.
   A hit is a critical override — it forces `HIGH` risk and `STOP_AND_AVOID`
   regardless of any other signal.
5. **Domain age** (`checkDomainAge`): RDAP registration-date lookup, falling back to
   the domain's earliest known TLS certificate (via crt.sh, then Certspotter's
   certificate-transparency-log APIs) when RDAP is unavailable — which it is for every
   `.lk` domain, since the LK Domain Registry runs neither RDAP nor traditional WHOIS.
   A domain first seen in the last 14 days is flagged as a `new_domain_risk`, with
   lower confidence when the evidence is the CT-log proxy rather than an authoritative
   RDAP record. Only runs when no faster tier has already resolved the domain, to
   bound worst-case latency (this tier can make up to three sequential network calls).

Plus, unchanged from before:

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

And new for this expansion:

- **Suffix-aware domain extraction** (`packages/domain/src/extraction.ts`, using
  `tldts`): replaced the earlier naive `.split('.')` domain/subdomain-depth logic with
  public-suffix-aware parsing, correctly handling multi-level Sri Lankan TLDs like
  `gov.lk` and `ac.lk`. This closes the limitation the original version of this
  document flagged as not built.
- **Moderator domain directory management UI** (`ModeratorDashboard.tsx`, "Domains"
  tab): moderators can add, activate, mark stale, or retire directory entries directly
  from the dashboard, backed by `GET/POST /api/moderation/domains` and
  `PATCH /api/moderation/domains/:id` (see `docs/api-conventions.md`).
- **Customer-facing "Check a URL" tab** (`App.tsx`): a dedicated single-line URL input
  next to the existing "Text / URL" and "Upload Screenshot (OCR)" tabs, for a user who
  just wants to paste a bare link rather than a full message.
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
6. Use the "Check a URL" tab to paste a well-known global domain not in the local
   directory (e.g. `https://github.com`): it resolves via Tier 3 (global domain trust)
   with a `known_global_domain` finding, weaker than a Tier 1 `approved_domain` hit but
   still positive evidence.
7. Paste one of Google's official Safe Browsing test URLs (from
   `testsafebrowsing.appspot.com`) to demonstrate Tier 4: `HIGH` risk,
   `STOP_AND_AVOID`, with a `known_malicious_domain` finding and the
   `known_malicious_domain_override` in `overridesApplied`.
8. Paste a freshly registered domain to demonstrate Tier 5: a `new_domain_risk`
   finding appears, with the evidence noting whether it came from an authoritative
   RDAP record or a certificate-transparency-log proxy (relevant for `.lk` domains,
   which have neither RDAP nor WHOIS).
9. As a moderator, open the "Domains" tab in the dashboard to add, activate, mark
   stale, or retire a directory entry, demonstrating the management UI behind Tier 1.

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
- **Redirect evidence display (originally planned Stage 6.5) was not built.** It
  depends on agreeing a data shape with Member 4's scanner output, which did not
  happen in this development window.
- **`.lk` domains have no authoritative age source.** The LK Domain Registry runs
  neither RDAP nor traditional port-43 WHOIS (confirmed against IANA's own root
  registry record, which lists a blank `whois:` field for `.lk`). Tier 5 falls back to
  a certificate-transparency-log-derived "first known SSL certificate" date as a
  proxy, recorded with lower confidence than a real RDAP registration date, and is
  fully fail-open (an honest "age could not be determined" limitation, not an error)
  when even that is unavailable — crt.sh in particular is a free community service
  that is intermittently overloaded.
- **The global domain trust list (Tier 3) is a static snapshot, not a live feed.** It
  was loaded once from the Tranco top-1M ranking via
  `services/api/scripts/loadGlobalDomains.mjs` and does not automatically refresh; a
  newly-popular legitimate domain won't appear until the list is reloaded.
- **Google Safe Browsing (Tier 4) requires a configured API key.**
  `GOOGLE_SAFE_BROWSING_API_KEY` must be set in `services/api/.env`; if it is not, the
  tier is skipped entirely (fail-open) rather than blocking analysis.
- **The domain-directory dataset is small and seeded from general knowledge, not a
  live lookup.** `supabase/seed/002_expand_domain_directory.sql` explicitly flags that
  each `source_url` should be spot-checked before being relied on for a real
  deployment; it is adequate for a hackathon demo directory of about a dozen
  organizations, now supplemented by moderator-added entries via the management UI.

## Setup

Requires `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` in `services/api/.env` (see
`.env.example`). The domain directory and its governance columns are created by
`supabase/migrations/202609190001_domain_directory_governance.sql`.

For the full five-tier cascade:

- Run `supabase/migrations/202609220001_global_trusted_domains.sql`, then populate it
  with `node services/api/scripts/loadGlobalDomains.mjs` (downloads the live Tranco
  top-1M list; pass `--file <path>` to load from a local CSV instead, or `--limit N`
  for a quick test load).
- Set `GOOGLE_SAFE_BROWSING_API_KEY` in `services/api/.env` (see `.env.example`) to
  enable Tier 4. Without it, Tier 4 is skipped, not treated as an error.
- Tier 5 (domain age) needs no configuration; it calls RDAP and the public
  certificate-transparency-log APIs directly and fails open on any network issue.

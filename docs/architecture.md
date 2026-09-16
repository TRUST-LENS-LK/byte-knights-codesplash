# TrustLens LK Architecture

This document describes the system as it actually exists in the codebase today. It is
written from the URL and Domain Verification slice (Member 3), as the first step of that
slice's work, so that later changes can be measured against a known starting point.

## 1. Repository layout

```text
apps/web              React + TypeScript + Vite frontend (single checker page today)
packages/contracts     Shared Zod schemas and TypeScript types for the whole team
packages/extraction    Standalone entity extraction helpers, used by the frontend
packages/rules         Standalone rule engine, used by the frontend
services/api           Local Node HTTP API (Supabase-backed), used when the frontend
                        calls the live analyze endpoint instead of running rules locally
supabase/migrations    SQL schema for the shared Supabase project
supabase/seed          Seed data for the shared Supabase project
```

Note that the frontend can run two ways right now: purely offline (calling
`packages/extraction` and `packages/rules` directly in the browser), or through
`services/api` when it is running locally. Both code paths currently duplicate similar
logic; see the open decisions log for the plan to reconcile this.

## 2. Request flow through services/api

A request to `POST /api/analyze` currently flows through these modules in order:

1. `server.mjs` accepts the connection, assigns a `requestId`, and applies security
   headers, CORS, and a per-IP rate limit (`services/rateLimit.mjs`).
2. `services/analysis.mjs` validates the submitted body shape (`validateSubmission`),
   then extracts entities from the text (`extractEntities`) and runs the deterministic
   keyword rules (`analyze`).
3. `services/domainVerification.mjs` takes any `domain` entities found in step 2 and
   looks them up against the `approved_organizations` table in Supabase. Matches are
   appended to the decision's findings as `DOMAIN_DIRECTORY` evidence.
4. `services/persistence.mjs` writes the submission, its entities, and its findings to
   Supabase, but only when `retentionConsent: true` was sent. If the entity or finding
   insert fails partway through, the submission row is rolled back with a delete.
5. `http/response.mjs` sends the final JSON response with security headers and the
   `requestId` for tracing.

## 3. Data flow (current, not the full target design)

```text
Client (browser)
   |  POST /api/analyze { type, text, languageHint, retentionConsent }
   v
services/api (Node HTTP server)
   |  extract entities -> run keyword rules -> check domain directory -> merge findings
   |  optionally persist to Supabase if consent given
   v
Supabase (Postgres + RLS)
   tables: submissions, extracted_entities, findings, approved_organizations, user_reports
```

What exists today only covers the message/keyword-rule path plus a basic domain lookup.
The following pieces described in the project proposal are not yet built:

- A dedicated URL submission mode (today, URLs are only found incidentally inside
  free-text message submissions).
- Screenshot upload and OCR (Member 2).
- The isolated Playwright/Chromium link scanner (Member 4).
- Gemini/LLM context findings (Member 4, per the ordered task list).
- Report moderation and approval workflow (Member 5).
- Authentication and role-based access (Member 5).

## 4. Trust boundaries

- **Client boundary**: the browser is untrusted. All input is revalidated server-side;
  nothing from the client is trusted just because the UI already checked it.
- **API boundary**: `services/api` holds the Supabase service-role key, which bypasses
  Row Level Security. This key must never be sent to the client and must never appear
  in logs or error messages.
- **Data boundary**: Supabase enforces Row Level Security on every table. The service
  role can read and write everything; anonymous and authenticated users can only read
  active `approved_organizations` rows and insert `user_reports` rows in `PENDING`
  status. No other public write paths exist today.
- **Scanner boundary** (not yet built): per the proposal, the isolated link scanner will
  run in a disposable, non-root Docker container with no application secrets, on its own
  trust boundary, separate from the main API.

## 5. Current API conventions (see docs/api-conventions.md for the full reference)

- Every response includes an `x-request-id` header and a `requestId` field in the body,
  for tracing a single request end to end.
- Every response carries a fixed set of security headers (no caching, no framing,
  restricted permissions policy, explicit CORS origin).
- Errors are returned as `{ code, message, requestId }` with an appropriate HTTP status.
- Successful analysis responses are returned as `{ decision, entities, inputType,
  requestId, submissionId? }`.

## 6. Open decisions

See the pending items tracked separately so they are not lost before the team confirms
them. As of this writing, three decisions are still open:

1. Whether the domain-directory table keeps its current name, `approved_organizations`,
   or is renamed to `official_domains` as named in the development plan.
2. Whether `services/api` adopts the shared Zod schemas in `packages/contracts` as its
   single source of validation truth, instead of the current hand-written checks in
   `services/analysis.mjs`.
3. How URL-related work is split between Member 2 (generic entity extraction and
   suspicious-link keyword rules) and Member 3 (dedicated URL submission and
   official-domain verification), since the two planning documents describe this
   differently.

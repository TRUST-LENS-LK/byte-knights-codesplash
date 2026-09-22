# TrustLens LK API Conventions

This documents the conventions `services/api` already follows in practice, so new
endpoints stay consistent instead of each member inventing their own response shape.
If a new endpoint cannot follow one of these rules, raise it with the team before
merging, rather than quietly diverging. Refreshed 2026-09-22 against the actual
current route list in `server.mjs`, adding the moderator domain directory management
routes and the multi-tier domain verification work that now runs inside
`/api/analyze` (global domain trust, Google Safe Browsing, domain age).

## Request handling

- Every incoming request is assigned a random `requestId` (a UUID) before anything
  else happens. This id is used for tracing and is always echoed back to the caller.
- Only `application/json` request bodies are accepted for `POST` endpoints. Anything
  else returns `415 UNSUPPORTED_MEDIA_TYPE`.
- Request bodies are size-limited (`MAX_BODY_BYTES`, currently 15,000 bytes) and are
  rejected early with `413 PAYLOAD_TOO_LARGE` if the `content-length` header or the
  actual streamed size exceeds the limit. Do not buffer unbounded input.
- `POST` requests are rate-limited per client IP (`services/rateLimit.mjs`). Every
  such response carries `ratelimit-limit`, `ratelimit-remaining`, and
  `ratelimit-reset` headers, and a limited request returns `429 RATE_LIMITED` with a
  `retry-after` header. `GET` endpoints (health, docs, directory, moderation reads)
  are not currently rate-limited.
- Protected endpoints (moderator-only) check authorization via
  `authorizeModerator(req)` in `http/auth.mjs`, which validates the caller's Supabase
  Auth JWT and requires an `app_metadata.role` (or `user_metadata.role`) of
  `moderator` or `admin`. An unauthorized call returns `401 UNAUTHORIZED`.

## Response shape

Every response is JSON and includes these security headers, set centrally in
`http/response.mjs`:

- `cache-control: no-store`
- `access-control-allow-origin` (the configured frontend origin, not a wildcard)
- `x-content-type-options: nosniff`
- `x-frame-options: DENY`
- `permissions-policy` (camera, microphone, and geolocation all disabled)
- `referrer-policy: no-referrer`
- `x-request-id` (matches the `requestId` in the body)

### Success responses

Success responses are a plain JSON object specific to the endpoint, but always
include `requestId`.

### Error responses

Errors always follow this exact shape:

```text
{ code, message, requestId }
```

- `code` is a short, stable, uppercase-with-underscores identifier.
- `message` is a short, human-readable sentence, safe to display to a developer. It
  must never include raw user input, stack traces, or internal details.
- New error codes should be added to the table below, not invented ad hoc per
  endpoint, so the full set of possible errors stays discoverable in one place.

## Route inventory

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | Liveness check |
| GET | `/docs` | none | Swagger UI (HTML) |
| GET | `/openapi.json` | none | OpenAPI 3.0 spec |
| GET | `/api/domain-directory` | none | List directory entries; `category`, `includeStale` query params |
| GET | `/api/domain-directory/lookup` | none | Look up one domain; `domain` query param required |
| GET | `/api/moderation/stats` | moderator | Aggregate moderation queue stats |
| GET | `/api/moderation/queue` | moderator | Paginated report queue; `status`, `page`, `limit` query params |
| GET | `/api/moderation/domains` | moderator | List every domain directory entry, including retired ones, for the management screen |
| POST | `/api/scanner/preview` | none, rate-limited | Structural URL safety check without fetching the page |
| POST | `/api/reports` | none, rate-limited | Submit a report into the private moderation queue |
| POST | `/api/moderation/login` | none | Exchange moderator email/password for a session token |
| POST | `/api/moderation/review` | moderator | Approve, reject, or retire a report |
| POST | `/api/moderation/seed-demo` | moderator | Populate demo fixtures for a rehearsal |
| POST | `/api/moderation/domains` | moderator | Add a new domain directory entry; requires `name` and `officialDomain` |
| PATCH | `/api/moderation/domains/:id` | moderator | Update a domain directory entry's `status`, `category`, `sourceUrl`, `reviewNotes`, or `active` |
| POST | `/api/analyze` | none, rate-limited | Main pipeline: message or dedicated URL submission to a full decision |

`/api/analyze` runs the full domain verification cascade for URL submissions: a
curated directory match (Tier 1), community intelligence, global domain trust via
the Tranco-derived allowlist (Tier 3, in-memory top 20k then a Supabase-backed full
list), Google Safe Browsing reputation (Tier 4), a claimed-organization domain
mismatch check, and, only when no faster tier has already resolved the domain,
a domain age check via RDAP with a certificate-transparency-log fallback for TLDs
(such as `.lk`) that run neither RDAP nor WHOIS (Tier 5). Every external/live-network
tier fails open: a timeout or missing upstream config degrades to an honest
limitation rather than blocking analysis or fabricating a result.

`/api/domain-directory*` and `/api/moderation/stats|queue` intentionally require no
extra auth beyond what RLS already grants (see `docs/rls-access-matrix.md`): the
directory ones because anon/authenticated can already read that data directly from
Supabase, so the endpoint is a validated, camelCase convenience rather than a new
trust boundary; the moderation reads because `authorizeModerator` is the actual gate.

## Error codes

| Code | Status | Meaning |
|---|---|---|
| `NOT_FOUND` | 404 | Unknown route or method, or (domain directory PATCH) an unknown entry id |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | Body was not `application/json` |
| `RATE_LIMITED` | 429 | Too many requests from this client |
| `PAYLOAD_TOO_LARGE` | 413 | Body exceeded the size limit |
| `INVALID_JSON` | 400 | Body was not parseable JSON |
| `INVALID_SUBMISSION` | 400 | Body failed schema validation (analyze, scanner preview, unknown report type) |
| `INVALID_REPORT` | 400 | A known report type failed its own field validation |
| `INVALID_ACTION` | 400 | A moderation review action failed validation |
| `UNSAFE_URL` | 400 | Scanner preview rejected the URL (SSRF/scheme guard) |
| `UNAUTHORIZED` | 401 | Missing or non-moderator token on a protected route |
| `AUTH_FAILED` | 401 (or upstream status) | Moderator login failed |
| `REPORT_NOT_FOUND` | 404 | Moderation review referenced a report that does not exist |
| `REPORTING_UNAVAILABLE` | 503 | Supabase is not configured, so reporting cannot accept writes |
| `REPORT_CREATION_FAILED` | 502 | Report validated but the Supabase write failed |
| `REVIEW_FAILED` | 502 | Moderation review action failed for a reason other than not-found |
| `SEED_FAILED` | 502 | Demo fixture seeding failed |
| `STATS_FETCH_ERROR` | 502 | Moderation stats query failed |
| `QUEUE_FETCH_ERROR` | 502 | Moderation queue query failed |
| `DIRECTORY_FETCH_ERROR` | 502 | Domain directory list query failed |
| `DIRECTORY_LOOKUP_ERROR` | 502 | Domain directory lookup query failed |
| `DIRECTORY_CREATE_ERROR` | 502 | Creating a domain directory entry failed |
| `INVALID_ID` | 400 | Domain directory update was missing its `:id` path segment |
| `INVALID_PAYLOAD` | 400 | Domain directory update had no recognized fields, or an invalid `status` |
| `UPDATE_FAILED` | 502 | Domain directory update failed for a reason other than not-found |
| `PERSISTENCE_ERROR` | 502 | Analysis succeeded, but the Supabase write failed |

## What must never appear in a response or a log line

- The Supabase service-role key, or any other secret from `config/env.mjs`.
- Raw OTPs, passwords, or full banking details submitted by a user.
- Full stack traces or internal file paths.
- A moderator's password or raw session token (only the issued access token is ever
  returned, and only to the authenticated caller who just logged in).

## Adding a new endpoint

1. Add the route to `server.mjs`. There is currently no shared route table; routes
   are a sequence of `if` checks against `pathname`/`method`. A refactor to a route
   table was considered (see `docs/decisions.md`) but deliberately not done given the
   number of people actively editing this file during the hackathon window; keep
   following the existing if-chain style rather than introducing a second pattern
   partway through.
2. Validate the request body before doing any work with it. `submissionSchema` from
   `packages/contracts` is already the validation source of truth for `/api/analyze`;
   reuse it or extend it rather than hand-rolling a new checker.
3. Reuse `consumeRateLimit`, `send`, and the existing header/error conventions above.
   Do not write a new response helper for a single endpoint.
4. If the endpoint should be moderator-only, gate it with `authorizeModerator`, the
   same way the existing `/api/moderation/*` routes do.
5. Add its error codes to the table above.
6. Add a test in `services/api/test` covering at least: a valid request, a validation
   failure, and (for `POST` routes) the rate-limit boundary.

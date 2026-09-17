# TrustLens LK API Conventions

This documents the conventions `services/api` already follows in practice, so new
endpoints stay consistent instead of each member inventing their own response shape.
If a new endpoint cannot follow one of these rules, raise it with the team before
merging, rather than quietly diverging.

## Request handling

- Every incoming request is assigned a random `requestId` (a UUID) before anything
  else happens. This id is used for tracing and is always echoed back to the caller.
- Only `application/json` request bodies are accepted for endpoints that take a body.
  Anything else returns `415 UNSUPPORTED_MEDIA_TYPE`.
- Request bodies are size-limited (`MAX_BODY_BYTES`, currently 15,000 bytes) and are
  rejected early with `413 PAYLOAD_TOO_LARGE` if the `content-length` header or the
  actual streamed size exceeds the limit. Do not buffer unbounded input.
- Requests are rate-limited per client IP (`services/rateLimit.mjs`). Every response
  carries `ratelimit-limit`, `ratelimit-remaining`, and `ratelimit-reset` headers, and
  a limited request returns `429 RATE_LIMITED` with a `retry-after` header.

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

Success responses are a plain JSON object specific to the endpoint, but always include
`requestId`. For example, `/api/analyze` returns:

```text
{ decision, entities, inputType, requestId, submissionId? }
```

`submissionId` is only present when the caller consented to retention and the write to
Supabase succeeded.

### Error responses

Errors always follow this exact shape:

```text
{ code, message, requestId }
```

- `code` is a short, stable, uppercase-with-underscores identifier
  (for example `INVALID_SUBMISSION`, `RATE_LIMITED`, `NOT_FOUND`).
- `message` is a short, human-readable sentence, safe to display to a developer. It
  must never include raw user input, stack traces, or internal details.
- New error codes should be added to this list, not invented ad hoc per endpoint:

| Code | Status | Meaning |
|---|---|---|
| `NOT_FOUND` | 404 | Unknown route or method |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | Body was not `application/json` |
| `RATE_LIMITED` | 429 | Too many requests from this client |
| `PAYLOAD_TOO_LARGE` | 413 | Body exceeded the size limit |
| `INVALID_SUBMISSION` | 400 | Body failed validation |
| `INVALID_JSON` | 400 | Body was not parseable JSON |
| `PERSISTENCE_ERROR` | 502 | Analysis succeeded, but the Supabase write failed |

## What must never appear in a response or a log line

- The Supabase service-role key, or any other secret from `config/env.mjs`.
- Raw OTPs, passwords, or full banking details submitted by a user.
- Full stack traces or internal file paths.

## Adding a new endpoint

1. Add the route to `server.mjs` (or, once the route table refactor lands, to the route
   table it replaces this with).
2. Validate the request body before doing any work with it. Once the shared-contracts
   decision in `docs/decisions.md` is confirmed, validation should call into
   `packages/contracts`, not a hand-written checker.
3. Reuse `consumeRateLimit`, `send`, and the existing header/error conventions above.
   Do not write a new response helper for a single endpoint.
4. Add a test in `services/api/test` covering at least: a valid request, a validation
   failure, and the rate-limit boundary.

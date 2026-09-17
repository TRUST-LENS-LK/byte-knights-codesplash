# TrustLens LK — Threat Model

**Author:** Member 4 (Safe Scanner & Security Controls)
**Last updated:** 2026-09-16
**Status:** Draft

---

## 1. Scope

This document covers the attack surface of the TrustLens LK backend API (`services/api`) and the planned isolated URL scanner (`services/scanner`). The frontend (`apps/web`) is treated as an untrusted client; no secrets or privileged logic reside there.

---

## 2. System Overview

```
[User Browser]
      │  HTTPS
      ▼
[API — services/api]   ─── Supabase REST API (postgres + storage)
      │
      │  HTTP (internal only, planned)
      ▼
[Scanner — services/scanner]   ─── Chromium / Playwright (isolated)
```

The API is a stateless Node.js HTTP server. It accepts text or URL submissions, runs deterministic rules and domain lookups, optionally calls the scanner, and returns a verdict. The scanner is a planned separate service that fetches URLs in a sandboxed Chromium instance.

---

## 3. Trust Boundaries

| Boundary | Direction | Trust Level |
|---|---|---|
| User browser → API | Inbound | **Untrusted** — all input validated and bounded |
| API → Supabase | Outbound | Trusted channel — service-role key never exposed to client |
| API → Scanner | Outbound (internal) | Semi-trusted — scanner only reachable from API, not public internet |
| Scanner → External URLs | Outbound | **Untrusted** — sandboxed Chromium, SSRF-protected |

---

## 4. Identified Threats and Mitigations

### 4.1 Server-Side Request Forgery (SSRF)

**Threat:** A user submits a URL pointing to an internal resource (e.g., `http://169.254.169.254/latest/meta-data/`) and the scanner fetches it, leaking cloud metadata or hitting internal services.

**Current Mitigations (implemented):**
- `validateScannerUrl()` in [`urlSafety.mjs`](../services/api/src/services/urlSafety.mjs) blocks all of:
  - `localhost` and `.localhost`
  - IPv4 private ranges: `10.x`, `172.16-31.x`, `192.168.x`, `169.254.x` (link-local), `0.x`, `100.64-127.x` (CGNAT), `198.18-19.x`, `224-239.x` (multicast)
  - IPv6 private: `::1`, `::`, `fc00::/7`, `fe80::/10`
  - IPv4-mapped IPv6 (`::ffff:` prefix) pointing to private ranges
  - Only `http:` and `https:` protocols allowed — blocks `file:`, `ftp:`, `javascript:` etc.

**Remaining Gap:**
- DNS rebinding: A hostname like `public.attacker.com` resolves to a public IP at validation time but rebinds to `192.168.1.1` at fetch time. The Playwright scanner must re-verify the resolved IP after DNS lookup, before connecting.

**Planned Mitigation (scanner service):**
- Use Playwright's `page.route()` or a custom DNS resolver to intercept the resolved IP and block private addresses before any connection is made.

---

### 4.2 DNS Rebinding

**Threat:** A DNS record for a public-looking hostname has a short TTL and flips to a private IP between the API's hostname check and the scanner's actual fetch. This bypasses the syntactic SSRF check.

**Current Mitigations:**
- None — the current SSRF check is purely syntactic (hostname string analysis).

**Planned Mitigation:**
- The scanner service will use Playwright's network interception (`page.route()`) to resolve the actual IP of each request before connecting and apply the same private-range blocklist.
- Use a short DNS cache (no external resolver caching) so rebinding windows are minimized.

---

### 4.3 Prompt Injection / Rule Bypass

**Threat:** A user crafts a message that uses Unicode homoglyphs, zero-width characters, or unusual whitespace to bypass keyword rules (e.g., `0TP` instead of `OTP`).

**Current Mitigations:**
- Rules use case-insensitive regex (`/i` flag).
- Some Unicode Sinhala terms are matched directly.

**Remaining Gap:**
- No normalization of Unicode lookalike characters or zero-width joiners before matching.
- No AI/LLM layer to catch semantic evasion.

**Planned Mitigation:**
- AI context analysis (Gemini) is planned as an additional layer for semantic detection without replacing deterministic rules.

---

### 4.4 Malicious File Downloads via Scanner

**Threat:** A URL the scanner visits triggers an automatic download of a malicious file (e.g., a `.exe` or `.apk`). This file lands on the scanner host.

**Planned Mitigations (scanner service):**
- Block MIME types other than `text/html` and `application/xhtml+xml` at the network intercept layer.
- Set `--disable-downloads` Chromium flag.
- Chromium runs as a non-root user inside a disposable Docker container.
- Container is destroyed after each scan.

---

### 4.5 Credential Leakage via Supabase Key

**Threat:** The Supabase service-role key is a secret that grants full database access. If it is exposed in source code, logs, or Postman collections, the database is fully compromised.

**Current Mitigations:**
- `services/api/.env` is in `.gitignore`.
- The env file was actively removed from Git tracking during setup.
- The key is never returned in API responses.
- The key is used server-side only via `fetch` to Supabase's REST API.

**Remaining Action:**
- Rotate the Supabase service-role key before any production or competition deployment.
- Confirm `.env` never appeared in any commit in the repository history.

---

### 4.6 Request Size and Denial of Service

**Threat:** A large request body or extremely long text exhausts memory or CPU in the API process.

**Current Mitigations:**
- `MAX_BODY_BYTES = 15,000` enforced via `Content-Length` header check and streaming byte counter.
- `MAX_TEXT = 10,000` characters checked after parsing.
- In-memory rate limiter: 60 requests per IP per minute (configurable).
- `429 RATE_LIMITED` response with `Retry-After` header.
- In-memory rate store capped at 1,000 IP entries.

**Remaining Gap:**
- Rate limiting is in-memory and resets on restart. A distributed deployment would need Redis or similar.
- No per-IP blocking for sustained abuse.

---

### 4.7 Information Disclosure via Error Messages

**Threat:** Detailed error messages leak internal stack traces or file paths to the client.

**Current Mitigations:**
- API returns structured error codes (`INVALID_JSON`, `RATE_LIMITED`, `PERSISTENCE_ERROR`) without stack traces.
- No internal paths or service names are exposed in responses.
- `X-Content-Type-Options: nosniff` prevents MIME-type sniffing attacks.
- `X-Frame-Options: DENY` prevents clickjacking.
- `Cache-Control: no-store` prevents sensitive response caching.
- `Referrer-Policy: no-referrer` prevents leaking the submission URL to third parties.

---

### 4.8 Cross-Origin Requests

**Threat:** A malicious website makes cross-origin requests to the API, piggy-backing on an authenticated user session.

**Current Mitigations:**
- CORS origin is restricted to a single configured origin (`CORS_ORIGIN` env var, defaults to `http://localhost:5173`).
- Only `POST` and `GET` methods are allowed via CORS.
- Allowed headers are explicitly listed.

---

### 4.9 Scanner Container Escape

**Threat (future):** A malicious webpage exploits a Chromium vulnerability to escape the browser sandbox and execute code on the scanner host.

**Planned Mitigations:**
- Chromium runs with `--no-sandbox` disabled — the full sandbox is enabled.
- Scanner runs as a non-root user inside a Docker container with a read-only root filesystem (planned).
- No persistent state in the scanner container — destroyed after each scan.
- Scanner container has no access to the host network beyond what is needed to fetch the target URL.
- The scanner is not reachable from the public internet — only from the API.

---

## 5. Security Controls Summary

| Control | Status |
|---|---|
| Syntactic SSRF protection | ✅ Implemented |
| Protocol allowlist (http/https only) | ✅ Implemented |
| Private IPv4 range blocklist | ✅ Implemented |
| Private IPv6 range blocklist | ✅ Implemented |
| IPv4-mapped IPv6 blocklist | ✅ Implemented |
| Request size limits | ✅ Implemented |
| In-memory rate limiting | ✅ Implemented |
| Security headers | ✅ Implemented |
| CORS restriction | ✅ Implemented |
| Supabase key server-side only | ✅ Implemented |
| DNS rebinding protection | ❌ Planned (scanner service) |
| Playwright sandboxed fetch | ❌ Planned (scanner service) |
| MIME-type blocking in scanner | ❌ Planned (scanner service) |
| Docker container isolation | ❌ Planned (scanner service) |
| Non-root scanner process | ❌ Planned (scanner service) |
| Post-DNS IP re-verification | ❌ Planned (scanner service) |

---

## 6. Out of Scope

- Authentication and user accounts (not implemented for this phase)
- DDoS mitigation beyond in-process rate limiting
- TLS certificate management (handled by the hosting provider)
- Frontend XSS (mitigated by React's JSX escaping by default)

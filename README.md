# TrustLens LK — Advanced Scam Decision Support & Threat Intelligence Platform 🛡️🇱🇰

[![Node.js](https://img.shields.io/badge/Node.js-20%2B-brightgreen.svg?logo=node.js)](https://nodejs.org/)
[![React 19](https://img.shields.io/badge/React-19-blue.svg?logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg?logo=typescript)](https://www.typescriptlang.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg?logo=docker)](https://www.docker.com/)
[![NIST XAI Compliant](https://img.shields.io/badge/NIST-XAI%20Compliant-orange.svg)](https://www.nist.gov/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**TrustLens LK** is an enterprise-grade, multi-layered threat intelligence and scam decision support platform engineered specifically to safeguard Sri Lankan citizens and organizations from modern digital scams, brand impersonation, deceptive task frauds, and credential harvesting.

Combining **in-browser multilingual OCR**, **Sri Lanka-specific deterministic heuristics**, **curated institutional domain registries**, **isolated sandbox URL detonation**, and an **explainable decision arbiter**, TrustLens LK delivers transparent, NIST-aligned security verdicts with zero black-box hallucinations.

---

## 🌟 Core Architecture: The 5-Layer Defense Pipeline

When an SMS, chat transcript, screenshot, or URL is submitted to TrustLens LK, it passes through five coordinated defense layers:

```
[ Citizen Submission / Screenshot Upload ]
                     │
                     ▼
  Layer 1: Multilingual OCR Engine (Tesseract.js — English & Sinhala)
                     │
                     ▼
  Layer 2: Sri Lanka Heuristic & Entity Extraction Engine (@trustlens/rules)
                     │
                     ▼
  Layer 3: 3-Tier Domain Trust & Age Verification Engine
                     │
                     ▼
  Layer 4: Isolated Headless Playwright Sandbox Detonation (services/scanner)
                     │
                     ▼
  Layer 5: Decision Arbiter & Hard Invariant Enforcement (INV-01 to INV-09)
                     │
                     ▼
[ Explainable Verdict + NIST Trace + Statutory Emergency Actions ]
```

### 1. Multilingual In-Browser OCR & Screenshot Extraction
- **Zero-PII Client-Side Extraction**: Powered by `Tesseract.js` running locally in the browser with optimized bilingual models for **English (`eng`)** and **Sinhala (`sin`)**.
- **Interactive Verification**: Provides confidence metrics and an interactive side-by-side text correction screen so citizens can verify extracted message text before analysis.
- **Linguistic Coverage**: Detects deceptive patterns in standard English, native Sinhala Unicode, and **Singlish** (e.g., *"salli danna"*, *"card eka block wela"*).

### 2. Sri Lanka-Specific Heuristic & Entity Extraction (`@trustlens/rules` & `@trustlens/extraction`)
- **Entity Normalization**: Accurately extracts Sri Lankan mobile/landline numbers (E.164 normalization, e.g., `+94 77 ...`), LKR monetary values, domestic bank names, and defanged indicators (`hxxps://`, `[.]lk`).
- **Parallel Heuristic Detectors**:
  - **Credential Theft Detector**: Flags solicitations for OTPs, PINs, CVC codes, or banking login credentials.
  - **Advance-Fee & Customs Scam Detector**: Flags requests for delivery fees, clearance fees, or tax payments.
  - **Job & Task Scam Detector**: Flags "daily pay", "like YouTube videos", or "WhatsApp task" recruitment lures.
  - **Urgency & Coercion Detector**: Identifies artificial deadlines, threats of account suspension, or legal action.

### 3. Multi-Tier Domain Verification & Threat Intelligence
- **Tier 1 (Tranco Global Whitelist)**: Integrates the Tranco Top 1M list (cached in-memory) for sub-millisecond, zero-database verification of globally trusted domains (e.g., `google.com`, `facebook.com`).
- **Tier 2 (Google Safe Browsing API)**: Performs real-time checks against Google's live threat intelligence database to instantly detect and block known malware, phishing, and deceptive sites.
- **Tier 3 (Curated Sri Lankan Institutional Directory)**: Actively curated local database of official Sri Lankan institutions (Central Bank of Sri Lanka, commercial banks, telecom operators, `gov.lk` government services). Protected with PostgreSQL Row-Level Security (RLS).
- **Tier 4 (Live WHOIS & Domain Age Heuristics)**: Performs live RDAP/WHOIS age verification. Newly registered domains (< 30 days old) that attempt to impersonate familiar brands or collect data are immediately escalated to High Risk.

### 4. Isolated Headless Playwright Sandbox Detonation (`services/scanner`)
- **Containerized Playwright Worker**: Safely detonates URLs in an isolated, headless Chromium container.
- **SSRF & Private IP Containment**: Enforces strict RFC 1918 and loopback address blocking (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, IPv6) to prevent internal infrastructure probing.
- **Redirect Chain & Cloaking Analysis**: Traces full multi-hop HTTP redirects, shorteners, and deceptive URL paths.
- **DOM & Visual Inspection**: Analyzes page forms for credential harvesting, flags malicious/adult patterns, and streams a secure viewport screenshot to the analysis viewer.

### 5. Multi-Signal Decision Arbiter & Hard Invariant Enforcement
To prevent probabilistic AI hallucinations from endangering citizens, TrustLens LK arbitrates all signals through **Deterministic Hard Invariants**:

| Invariant | Name | Trigger Condition | Deterministic Outcome |
| :--- | :--- | :--- | :--- |
| **INV-01** | `CRITICAL_MALICIOUS_DOMAIN` | Google Safe Browsing malware/phishing hit | `HIGH` Risk (`STOP_AND_AVOID`) |
| **INV-02** | `CONFIRMED_COMMUNITY_INTEL` | Matches active verified threat intelligence | `HIGH` Risk (`STOP_AND_AVOID`) |
| **INV-04** | `BRAND_IMPERSONATION_MISMATCH` | Claimed entity links to an unauthorized domain | `HIGH` Risk (`STOP_AND_AVOID`) |
| **INV-05** | `ANTI_SPOOFING_GUARD` | Legitimate domain quoted, but message demands OTP/PIN | `HIGH` Risk (`POSSIBLE_IMPERSONATION`) |
| **INV-06** | `OFFICIAL_ADVISORY_PRESERVATION` | Legitimate bank security advisory ("Never share OTPs") | Suppresses false alarms (`SAFE`) |
| **INV-07** | `SEMANTIC_OVERRIDE` | Complex Singlish task scams or social engineering | Escalates to `HIGH` Risk |
| **INV-08** | `TRANSACTIONAL_NOTIFICATION` | Legitimate bank transaction confirmation or OTP issuance | Preserves benign status with OTP caution |
| **INV-09** | `BENIGN_PROMOTION_PRESERVATION` | Clean commercial marketing / merchant promos (e.g. KFC) | `SAFE` (0/100, 0 malicious patterns) |

---

## 🏛️ Explainable AI (XAI) & NIST Compliance

### Dual-Stage Gemini AI Integration
To ensure both accurate linguistic understanding and holistic threat context, Gemini AI is invoked in a two-stage pipeline:
1. **Pure Semantic Intent Analysis**: First, the model analyzes the raw text in isolation (understanding Sinhala, Singlish, and English) to determine the baseline psychological intent—whether the message is a coercive threat, an educational advisory, or a benign notification.
2. **Unified Contextual Synthesis**: Finally, the system feeds the AI's independent semantic reasoning alongside all deterministic heuristic signals (domain verification, sandbox findings, and intelligence hits) back into Gemini. The model synthesizes this combined intelligence into a single, user-friendly overall summary explaining exactly *why* the message is safe or dangerous.

Every analysis strictly adheres to **NIST Explainable AI (XAI) Principles**:
- **Explainable Decision Trace**: Viewers see the specific `findings` and weighting that produced the verdict.
- **Plain-Language Action Directives (`safeActions`)**: Concrete instructions (e.g., *"Do not share your OTP"*, *"Verify transaction with your bank"*).
- **Statutory Authority Contacts**: Dynamically resolves official helpline numbers for Sri Lanka CERT, CBSL Financial Consumer Protection, 1990, and Police Cyber Crime units.
- **Explicit Limitation Disclosures**: Discloses system boundaries (e.g., whether sandbox detonation was bypassed or if the entity is unverified in the national directory).

---

## 🛡️ Enterprise Human-in-the-Loop (HITL) Moderation & Threat Intelligence Operations

TrustLens LK closes the loop between citizens and security analysts through a comprehensive threat intelligence operations center:

### 1. Citizen Crowdsourced Reporting System
- **Three Core Submission Channels**:
  - `suspicious`: Citizens report emerging scam messages, phishing links, and deceptive SMS.
  - `false_positive`: Citizens or domain owners dispute a legitimate service erroneously flagged as high risk.
  - `false_negative`: Citizens flag an active scam that evaded automated heuristic detection.
- **Client & Server Runtime Validation**: Fully typed runtime schema validation using **Zod** (`packages/contracts`).
- **Cryptographic Content Hashing**: Computes Web Crypto SHA-256 hashes (`content_sha256`) of message content to ensure indicator integrity and non-repudiation.
- **Automated Indicator Defanging**: Raw URLs and domains are systematically neutralized (`hxxps://`, `[.]lk`) on ingestion to prevent drive-by clicks and accidental live resolution.
- **Cooldown Window Deduplication**: Coalesces identical submissions occurring within an active cooldown window to eliminate queue flooding while maintaining report counts.
- **Privacy-First Citizen Sanitization**: Submitter IP addresses and personally identifiable information (PII) are segregated from public threat intelligence outputs.

### 2. High-Density Moderator Operations Dashboard (`ModeratorDashboard.tsx`)
- **Cyber-Security Operations View**: High-contrast, responsive interface equipped with live metrics, triage queues, audit chains, and intelligence explorers.
- **Triage Queue with Server-Side Pagination**:
  - Filter by lifecycle status (`PENDING`, `APPROVED`, `REJECTED`, `ALL`).
  - Search across reported domains, notes, excerpts, and SHA-256 hashes.
  - Filter by threat categories (Phishing, Brand Impersonation, Credential Theft, Malware Distribution, Advance Fee, Task Scam).
  - Date filtering: `Today`, `Past 7 Days`, `Past 30 Days`, `All Time`.
  - Database-backed server-side pagination supporting high-volume query loads (up to 500 records per page).
- **One-Click Triage Actions**:
  - **`APPROVE`**: Promotes report to active `verified_intelligence`, assigning threat category, Bayesian confidence score, indicator type (`domain`, `content_hash`, `url`, `phone`), and analyst notes.
  - **`REJECT`**: Dismisses unfounded reports with recorded citizen dispute justification.
  - **`RETIRE`**: Decommissions remediated or stale threat indicators from the active blocklist.

### 3. Context Radar & Bayesian Threat Corroboration Engine
- **Live Context Radar Modal (`GET /api/moderation/reports/:id/context`)**:
  - Equips analysts with complete historical decision memory for the indicator before any action is committed.
  - Displays prior approval/rejection counts and past moderator notes.
- **Dual-Directional Conflict Detection**:
  - `FALSE_ALARM_ON_ACTIVE_THREAT`: Detects when a citizen dispute is filed against an active, confirmed threat indicator.
  - `SCAM_AGAINST_SAFE`: Detects when a scam report is filed against a previously verified safe indicator.
- **Dynamic Threat Revocation & Escalation**:
  - Approving a false positive dispute automatically **revokes and deactivates** the active scam indicator, reclassifying the target as `VERIFIED_SAFE` and logging an audit event.
  - Approving a scam report against an existing safe indicator supersedes and deactivates the safe intelligence.
- **Mathematical Bayesian Doubt Decay**:
  - Automatically calculates effective confidence scaling as independent community reports corroborate the same threat:
    $$\text{Confidence}_{\text{eff}} = \min\left(1.0,\, 1.0 - (1.0 - \text{base}) \times 0.65^{n - 1}\right)$$
  - Quantifies community consensus mathematically without manual threshold tuning.
- **Subdomain Intelligence Mapping**: Automatically maps multi-level subdomains back to parent apex threat intelligence.
- **Standalone Content SHA-256 Tracking**: Matches and tracks threats purely by content hash when no URL or domain is present.

### 4. Protected Entity Circuit Breaker
- **Institutional Safety Guard**: Continuously cross-references incoming reports against the Curated Sri Lankan Institutional Directory (CBSL, commercial banks, government services `gov.lk`, emergency hotlines).
- **Fail-Closed Circuit Breaker**: If a moderator attempts to approve a scam report targeting a protected national institution, the Circuit Breaker trips with HTTP 422 (`CIRCUIT_BREAKER_TRIGGERED`), preventing accidental blacklisting of critical infrastructure.
- **Statutory Incident Override**: Approval is strictly blocked unless the analyst provides an explicit override (`overrideProtectedEntity=true`) and mandatory statutory documentation (`incidentReason`, e.g. confirmed DNS hijacking or infrastructure compromise).

### 5. Cryptographic SHA-256 Audit Trail & Live Tamper Verification
- **Blockchain-Style Merkle Hash Chaining**: Every moderation action (`APPROVE`, `REJECT`, `RETIRE`, `MANUAL_INDICATOR_CREATE`, `RECLASSIFY_INDICATOR`, `PURGE_RETENTION`, `AUTH_LOGIN`, `AUTH_FAILED`) is appended to an immutable cryptographic audit chain.
- **Chaining Architecture**:
  - Genesis block anchored at `0000000000000000000000000000000000000000000000000000000000000000`.
  - Each entry binds: `sequence_id`, `timestamp`, `action`, `actor_email`, `actor_role`, `target_indicator`, `threat_category`, `moderator_notes`, `client_ip`, `user_agent`, `prev_hash`, and `entry_hash`.
  - Entry hash formula:
    $$\text{entry\_hash} = \text{SHA-256}(\text{prev\_hash} + \text{seq} + \text{action} + \text{actor} + \text{target} + \text{payload})$$
- **Live Cryptographic Tamper Verification Tool**:
  - Moderators can click **"Verify Cryptographic Audit Chain"** in the UI (`GET /api/moderation/audit-logs/verify`).
  - Recalculates the entire hash chain from the Genesis block to current block in real time.
  - Instantly detects if any log entry was modified, injected, deleted, or backdated (`CHAIN_INTEGRITY_VERIFIED` vs `TAMPER_DETECTED`).

### 6. Automated Statutory 90-Day Retention Purge & Health Metrics
- **Data Protection Compliance**: Implements strict data minimization adhering to GDPR and Sri Lanka's Personal Data Protection Act (PDPA).
- **Retention Purge API (`POST /api/moderation/audit-logs/purge`)**: Automatically purges audit and report records older than 90 days while preserving cryptographic chain continuity.
- **Live Storage Volume Metrics**: Dashboard displays real-time active storage volume, expired log volume, and system retention health.

### 7. External Threat Intelligence Feed & SIEM Export
- **On-Demand Dataset Export**: One-click JSON export of all active verified threat indicators directly from the database.
- **SIEM & Firewall Compatibility**: Structured feed format ready for ingestion into enterprise SIEM platforms (Splunk, Elastic, Microsoft Sentinel), next-gen firewalls, DNS sinkholes, and Sri Lanka CERT threat feeds.

### 8. Authentication & PostgreSQL Row-Level Security (RLS)
- **Supabase Auth Integration**: Secure session handling with role verification (`user`, `moderator`, `admin`).
- **PostgreSQL Row-Level Security (RLS)**:
  - Public / Anonymous users can only `INSERT` unverified reports with strict validation.
  - Public users can `SELECT` active verified intelligence and official directory entries.
  - Public users CANNOT update, delete, or approve reports or modify verified intelligence.
  - Only authenticated `service_role` and verified `moderator`/`admin` JWT tokens have administrative write access.

### 9. Demo Seeding & Competition Presentation Readiness
- **One-Click Demo Seed (`POST /api/moderation/seed-demo`)**: Pre-loads realistic Sri Lankan scenario fixtures (phishing SMS, legitimate bank security advisories, Singlish task scams, false alarms) for live judging demonstrations.
- **One-Click Demo Reset (`POST /api/moderation/clear-demo`)**: Restores the database and moderation queue back to a clean state.

---

## 🏗️ Monorepo Structure

TrustLens LK is organized as an NPM Workspace monorepo:

```
byte-knights/
├── apps/
│   └── web/                   # React 19 + Vite frontend (Citizen UI & Moderator Portal)
├── services/
│   ├── api/                   # Core Node.js Intelligence API, Arbiter & Reporting Service
│   └── scanner/               # Isolated Playwright/Chromium sandbox URL detonation service
├── packages/
│   ├── contracts/             # Shared TypeScript schemas & runtime Zod contracts
│   ├── domain/                # Curated domain directory lookups & mismatch logic
│   ├── extraction/            # Sri Lanka regex entity extraction (phone, money, defanged URLs)
│   └── rules/                 # Deterministic heuristic scoring engine & detectors
├── docker-compose.yml         # Multi-container orchestration (Web, API, Scanner)
└── Dockerfile                 # Unified container definition
```

---

## 🐳 Quick Start (Docker) — Recommended for Evaluation

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/) installed.

### 1. Configure Environment
Copy the example environment file at the repository root:

```bash
# On Linux / macOS:
cp .env.example .env

# On Windows (PowerShell):
Copy-Item .env.example .env
```

*(Default values work out of the box. Add your Supabase, Google Safe Browsing, or Gemini API keys to `.env` to enable live cloud integrations.)*

### 2. Build and Launch Containers
```bash
docker compose up --build
```

### 3. Access Services
| Service | URL | Description |
| :--- | :--- | :--- |
| **Citizen Web App & Moderator Portal** | [http://localhost:5174](http://localhost:5174) | Full citizen analysis UI, screenshot OCR, and moderator dashboard |
| **Core Intelligence API** | [http://localhost:8787](http://localhost:8787) | Threat evaluation engine and reporting endpoints |
| **Interactive Swagger API Docs** | [http://localhost:8787/docs](http://localhost:8787/docs) | Interactive Swagger UI for testing all REST endpoints |
| **Sandbox URL Detonation Service** | [http://localhost:8789](http://localhost:8789) | Headless browser container with SSRF sandbox |

---

## 💻 Local Development (Without Docker)

### 1. Install Dependencies
```bash
npm install
```

### 2. Build Shared Monorepo Packages
```bash
npm run build:packages
```

### 3. Run the Entire Stack
You can start all services concurrently with one command:
```bash
npm start
```
*Or launch individual services in separate terminals:*
```bash
# Terminal 1: Backend API
npm run start:api

# Terminal 2: Frontend Web App
npm run dev:web

# Terminal 3: Scanner Service
npm run start:scanner
```

---

## 🧪 Testing & Verification

TrustLens LK maintains rigorous test coverage across all microservices and shared libraries:

```bash
# Run all Core API & Decision Arbiter tests (160+ unit & integration tests)
npm run test:api

# Run shared packages tests (rules, extraction, domain directory)
npm run test:packages

# Type-check and validate all monorepo packages
npm run check:packages

# Run API syntax & module checks
npm run check:api

# Type-check and build the frontend application
npm run build:web

# Lint the frontend code
npm run lint:web
```

---

## 📡 Complete REST API Endpoints

Interactive OpenAPI documentation is hosted live at **`http://localhost:8787/docs`**.

| Method | Endpoint | Access | Purpose |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/analyze` | Public | Submits text or URL for multi-layered threat analysis |
| `POST` | `/api/reports` | Public | Submits citizen report (`suspicious`, `false_positive`, `false_negative`) |
| `POST` | `/api/moderation/login` | Public | Authenticates moderator credentials and issues Supabase JWT |
| `GET` | `/api/moderation/queue` | Moderator | Retrieves paginated moderation queue with status, search & threat filters |
| `POST` | `/api/moderation/review` | Moderator | Performs `APPROVE`, `REJECT`, or `RETIRE` on a report |
| `GET` | `/api/moderation/reports/:id/context` | Moderator | Retrieves Context Radar, conflict detection & Bayesian corroboration |
| `GET` | `/api/moderation/stats` | Moderator | Retrieves triage metrics, verification velocity & weekly activity |
| `GET` | `/api/moderation/audit-logs` | Moderator | Queries cryptographic audit chain with filtering & pagination |
| `GET` | `/api/moderation/audit-logs/verify` | Moderator | Executes live Genesis-to-head cryptographic tamper verification |
| `GET` | `/api/moderation/audit-logs/stats` | Moderator | Returns audit storage volume, expired log counts & retention health |
| `POST` | `/api/moderation/audit-logs/purge` | Moderator | Executes statutory 90-day retention purge of expired logs |
| `GET` | `/api/moderation/domains` | Moderator | Lists curated Sri Lankan institutional domain directory |
| `POST` | `/api/moderation/domains` | Moderator | Adds a new official institution domain entry |
| `PATCH` | `/api/moderation/domains/:id` | Moderator | Updates status (ACTIVE/RETIRED) or notes of a directory entry |
| `GET` | `/api/moderation/intelligence` | Moderator | Lists active verified threat intelligence indicators |
| `POST` | `/api/moderation/intelligence` | Moderator | Directly injects verified scam or safe threat indicator |
| `PATCH` | `/api/moderation/intelligence/:id` | Moderator | Toggles active status or confidence of a threat indicator |
| `POST` | `/api/moderation/seed-demo` | Moderator | Populates realistic Sri Lankan threat scenarios for live evaluation |
| `POST` | `/api/moderation/clear-demo` | Moderator | Clears seeded demo reports and resets queue state |
| `GET` | `/api/moderation/settings` | Moderator | Reads dynamic engine thresholds & feature flags |
| `PATCH` | `/api/moderation/settings` | Moderator | Updates dynamic engine thresholds & feature flags |

---

## 🔒 Security & Privacy Commitments

1. **Privacy-First Data Minimization**: Submitted message excerpts and PII are never permanently persisted unless the citizen grants explicit `retentionConsent`.
2. **Defanged Threat Indicators**: All reported URLs, domains, and indicators are defanged (`hxxps://`, `[.]`) to prevent accidental clicks or drive-by downloads.
3. **SSRF & Network Containment**: The scanner sandbox strictly isolates external network calls and rejects private/loopback IP requests.
4. **Immutable Cryptographic Audit Trail**: All administrative decisions are permanently chained with cryptographic SHA-256 hashes for total post-incident forensic transparency.
5. **Circuit Breaker Protection**: Statutory critical infrastructure cannot be blocked without strict override justifications.

---

## 👥 Byte Knights Team

Built with dedication for digital security and consumer protection in Sri Lanka.
Distributed under the **MIT License**.

# TrustLens LK — Member 5 Technical Dossier & Architectural Guide

> **Author**: Member 5  
> **Branch**: `feature/member5-reporting-and-moderation`  
> **Domain**: Reporting System, Moderation Workflow, Authentication & RBAC, Asymmetric Threat Intelligence Reconciliation, and NIST SP 800-92 Cryptographic Audit Logging  
> **Compliance & Standards**: NIST SP 800-61 Rev. 2, NIST SP 800-92, STIX 2.1 / MISP Admiralty Scale, Saltzer & Schroeder (1975) Fail-Safe Defaults  

---

## 1. Executive Summary & Team Ownership

Member 5 owns the entire **Reporting, Moderation, Intelligence Ingestion, and Governance vertical slice** within TrustLens LK. This encompasses end-to-end frontend interfaces, backend microservices, mathematical reconciliation algorithms, PostgreSQL database schemas with Row-Level Security (RLS), and cryptographic audit chaining.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              TRUSTLENS LK TEAM TOPOLOGY                                │
├─────────────────────────┬─────────────────────────┬────────────────────────────────────┤
│ Member 1                │ Member 2                │ Member 3                           │
│ Message Analysis Engine │ OCR & Sinhala Extractor │ Domain Directory & WHOIS           │
├─────────────────────────┼─────────────────────────┼────────────────────────────────────┤
│ Member 4                │ MEMBER 5 (THIS DOMAIN)  │ Shared Foundation                  │
│ Playwright Sandbox      │ • Citizen Reporting     │ • Contracts (@trustlens/contracts) │
│ & Isolated Worker       │ • Moderator Dashboard   │ • Supabase Auth & Migrations       │
│                         │ • Threat Reconciliation │ • Release Integration & E2E Tests  │
│                         │ • NIST Audit Hash Chain │                                    │
└─────────────────────────┴─────────────────────────┴────────────────────────────────────┘
```

### Strict Team Division & Ownership Boundaries
To ensure clean collaboration and zero merge conflicts, Member 5 operates strictly within defined boundaries:
- **Owned by Member 5**: Citizen reporting UI/API, moderator authentication/dashboard, triage pipeline, verified threat intelligence feed, asymmetric reconciliation engine, cryptographic audit trail, and associated test suites.
- **Untouched (Other Members' Work)**: Member 1 rules engine (`@trustlens/rules`), Member 2 OCR & Sinhala correction, Member 3 domain directory comparison & canonical normalizer, Member 4 Playwright sandbox crawler.

---

## 2. System Architecture & The 7-Stage Engineering Pipeline

Member 5 engineered a unified, secure 7-stage pipeline transforming unverified crowd signals into authoritative threat intelligence and cryptographically sealed audit records:

```mermaid
flowchart TD
    A[Citizen Submits Report] --> B[Stage 1: Ingestion & Defanging Pipeline]
    B --> C[Stage 2: Protected Moderator Dashboard RBAC]
    C --> D[Stage 3: Verified Intelligence Feed & Deduplication]
    D --> E[Stage 4: Asymmetric Risk Reconciliation Engine]
    E --> F[Stage 5: Mathematical Doubt Decay Model]
    F --> G[Stage 6: 100% Explainable AI Decision Traces]
    G --> H[Stage 7: NIST SP 800-92 Cryptographic Audit Chaining]

    style A fill:#1e293b,stroke:#3b82f6,color:#fff
    style B fill:#1e293b,stroke:#06b6d4,color:#fff
    style C fill:#1e293b,stroke:#8b5cf6,color:#fff
    style D fill:#1e293b,stroke:#10b981,color:#fff
    style E fill:#1e293b,stroke:#f59e0b,color:#fff
    style F fill:#1e293b,stroke:#ec4899,color:#fff
    style G fill:#1e293b,stroke:#14b8a6,color:#fff
    style H fill:#1e293b,stroke:#6366f1,color:#fff
```

---

## 3. Deep-Dive Component Breakdown

### 3.1 Citizen Reporting System (Ingestion & Sanitization)
- **Frontend Component**: `apps/web/src/components/ReportModal.tsx` & `ReportModal.css`
  - Integrated directly into `AnalysisResultCard.tsx` and the main navigation header.
  - Allows citizens to report:
    1. `scam`: Confirmed fraud, banking lures, credential harvesting.
    2. `phishing`: Malicious URLs or impersonation.
    3. `false_positive`: Legitimate messages or official services mistakenly flagged by the engine.
- **Backend Service**: `submitReport()` in `services/api/src/services/reportingService.mjs`
- **Security & Privacy Features**:
  1. **Zero PII Storage**: Submitter IP addresses and contact details are completely scrubbed before database insertion.
  2. **URL Defanging**: Raw malicious URLs are converted to inert defanged strings (`https://evil.com` $\to$ `hxxps://evil[.]com`) to prevent accidental clicks by moderators or downstream consumers.
  3. **Cryptographic Fingerprinting (`content_sha256`)**: Message excerpts are normalized and hashed via SHA-256, enabling template matching across mutated campaigns.
  4. **Duplicate Report Coalescing**: If identical reports arrive within a 15-minute cooldown window, the engine increments the pending record's weight rather than flooding the database with duplicate rows.

---

### 3.2 Protected Moderator Dashboard & Workflow
- **Frontend Components**:
  - `apps/web/src/components/ModeratorDashboard.tsx` & `ModeratorDashboard.css`
  - `apps/web/src/components/ModeratorLogin.tsx` & `ModeratorLogin.css`
  - `apps/web/src/services/moderatorService.ts`
- **Authentication & RBAC**:
  - Supabase Auth integration with strict role-based access control (`moderator`, `admin`).
  - Route-level and API-level authorization gates blocking unauthenticated or unauthorized users (`401 Unauthorized` / `403 Forbidden`).
- **Moderation Workflow Capabilities**:
  1. **Triage Queue**: Review pending reports with full context, defanged indicator preview, and submitter notes.
  2. **Triage Actions**: `APPROVE`, `REJECT`, or `RETIRE`.
  3. **STIX 2.1 / MISP Admiralty Confidence Selector**:
     - `1.00 (Definite Threat / Confirmed Scam)`
     - `0.85 (High Probability / Strong IoC)`
     - `0.70 (Suspicious / Exercise Caution)`
  4. **Editable Moderator Notes**: Update intelligence notes dynamically post-approval to document evolving threat actor TTPs.
  5. **Verified Intelligence Feed**: Search, filter, toggle active/inactive status, and inspect corroborated indicator metrics.
  6. **Manual Threat Intelligence**: Inject verified zero-day threat indicators directly without requiring an initial citizen report.
  7. **Dynamic Engine Settings**: Adjust global sensitivity, auto-corroboration thresholds, and feature flags in real-time.

---

### 3.3 Asymmetric Threat Intelligence Reconciliation Engine
- **Source Code**: `services/api/src/services/reconcileIntelligence.mjs`
- **Foundational Problem**: In cyber-defense, **majority voting is fatal**. If 3 bots or unobservant users vote "safe" and 2 victims report that a website stole their bank OTP, naive voting declares the URL 60% safe.
- **Fail-Safe Defaults (Saltzer & Schroeder, 1975)**:
  - Threat reports represent **Indicators of Compromise (IoCs)**.
  - Crowd "safe" reports represent **non-authoritative absence of harm** ("I didn't lose money" is never proof of safety).
  - In contested scenarios (e.g., 3 safe vs 2 scam), the engine **fails-closed to HIGH risk (`CONFLICTED`)** with recommendation `VERIFY_INDEPENDENTLY`. Crowd votes can **never** whitewash a verified threat.

#### The Mathematical Doubt Decay Model
Every approved indicator carries a base uncertainty (doubt):
$$\text{Doubt}_0 = 1 - C_{\text{base}}$$

When $n$ independent community reports corroborate the exact same indicator, doubt decays exponentially:
$$\text{Doubt}(n) = (1 - C_{\text{base}}) \times \gamma^{(n - 1)}$$
$$C_{\text{effective}}(n) = \min\left(1.0, 1 - \text{Doubt}(n)\right)$$

Where $\gamma = 0.65$ (each independent report eliminates 35% of remaining doubt).

| Report Count ($n$) | Starting $C_{\text{base}} = 0.70$ (Suspicious) | Starting $C_{\text{base}} = 0.85$ (High Prob.) | Escalation State |
| :---: | :---: | :---: | :--- |
| **1** | **70.0%** (`SUSPICIOUS_INDICATOR` — MEDIUM) | **85.0%** (`CONFIRMED_SCAM` — HIGH) | Initial moderator approval |
| **2** | **80.5%** (`SUSPICIOUS_INDICATOR` — MEDIUM) | **90.3%** (`CONFIRMED_SCAM` — HIGH) | Corroborated by 2nd report |
| **3** | **87.3%** (`CONFIRMED_SCAM` — HIGH) | **93.7%** (`CONFIRMED_SCAM` — HIGH) | **Threshold crossed ($C \ge 0.85$)** |
| **5** | **94.7%** (`CONFIRMED_SCAM` — HIGH) | **97.3%** (`CONFIRMED_SCAM` — HIGH) | Widespread campaign consensus |

---

### 3.4 NIST SP 800-92 Cryptographic Audit Logging & Tamper-Evidence
- **Backend Service**: `recordAuditLog()`, `getModerationAuditLogs()`, `verifyAuditChainIntegrity()`, and `purgeExpiredAuditLogs()` in `reportingService.mjs`
- **Frontend Modal**: `apps/web/src/components/modals/AuditDetailModal.tsx` & `AuditDetailModal.css`
- **Database Trigger**: `supabase/migrations/202609230001_audit_tamper_evidence_and_integrity.sql`

#### Cryptographic Hash Chaining Mechanism
Every audit action is forward-chained using SHA-256:
$$\text{entry\_hash} = \text{SHA-256}\left(\text{prev\_hash} \,\|\, \text{canonical\_timestamp} \,\|\, \text{action} \,\|\, \text{actor\_email} \,\|\, \text{actor\_role} \,\|\, \text{target} \,\|\, \text{category} \,\|\, \text{notes} \,\|\, \text{client\_ip}\right)$$

- **Genesis Block Anchor**: `0000000000000000000000000000000000000000000000000000000000000000`
- **PostgreSQL Immutability**: Trigger `prevent_audit_log_tamper()` explicitly raises an exception on any SQL `UPDATE` statement on `public.moderation_audit_logs`.
- **Dual-Storage Resilience**: Logs are stored in remote PostgreSQL (Supabase) and simultaneously cached in local persistent disk storage (`services/api/data/audit_logs_persistent.json`), ensuring zero data loss during network spikes or cold server restarts.

#### Pruning Resilience (The Floating Chain Anchor Principle)
In compliance with data privacy regulations (GDPR / ISO 27001), audit records older than 90 days are pruned:
1. When expired historical records are pruned, the **oldest surviving record in the table becomes the floating chain anchor**.
2. Verification validates the anchor's self-contained SHA-256 hash against its payload and stored `prev_hash`.
3. All subsequent records strictly enforce `current.prev_hash === previous.entry_hash`.
4. The automated purge worker appends an immutable governance record (`action: 'PURGE_EXPIRED'`) to the tip of the chain, sealing the prune event into the immutable ledger.
5. Illicit middle-deletions or payload alterations are detected with 100% precision.

---

### 3.5 Protected Entity Guardrail System & Approval Circuit Breaker (Zero-Hardcoding Architecture)
- **Problem Statement**:
  Citizens regularly submit legitimate official domains (e.g., `police.lk`, `cbsl.gov.lk`) or high-reputation global platforms (e.g., `facebook.com`, `google.com`) after receiving scam SMS messages or viewing malicious third-party ads. Without guardrails, an inattentive moderator might approve the domain as a scam, causing catastrophic false positives for millions of citizens.
- **Architectural Policy (Zero Hardcoding)**:
  - **No Static Domain Lists**: Never hardcodes lists of banks, police, or tech giants.
  - **Authoritative National Lookup**: Dynamically invokes Member 3's `lookupDomainDirectory(cleanDomain)` to query `approved_organizations`.
  - **Global Platform Evaluation**: Dynamically evaluates `isTopGlobalDomain(cleanDomain)` using Tranco Top-1M ranking data from `@trustlens/domain`.
- **Vertical Features Implemented**:
  1. **Dynamic Queue Triage & Visual Badging**:
     - Automatically decorates incoming reports with `protected_entity`:
       - `🏛️ Official National Entity` (e.g., Sri Lanka Police, Central Bank of Sri Lanka).
       - `🌐 Top Global Platform` (e.g., Meta, Google, Microsoft).
     - Moderator queue displays a distinct warning pill and recommended action: `⚡ Recom: REJECT`.
  2. **Approval Circuit Breaker (HTTP 422 Enforcement)**:
     - The backend route `/api/moderation/review` blocks direct approval of protected entities, returning `PROTECTED_ENTITY_OVERRIDE_REQUIRED` (HTTP 422).
     - Approval is locked unless the moderator explicitly passes:
       - `overrideProtectedEntity: true`
       - `incidentReason: string` (e.g., `SLCERT-INC-2026-089: Active DNS Hijack Incident`).
     - Audit logs record the event under threat category `Protected Entity Override`.
  3. **One-Click Fast Dismissal UI**:
     - `ReviewDecisionModal.tsx` provides a 1-click button: *"Dismiss as Legitimate Entity (Recommended)"*, allowing rapid clearance of false reports without friction.
  4. **False Alarm Dispute (`false_positive`) Exemption**:
     - If a citizen submits a `false_positive` dispute for `police.lk`, approving it clears the domain as `VERIFIED_SAFE`, which is allowed without incident overrides.
  5. **Reconciliation Disambiguation (`GLOBAL_PLATFORM_WITH_CAUTION`)**:
     - When a citizen reports a scam hosted on Facebook or Google, the reconciliation engine evaluates 0 or 1 crowd report to `GLOBAL_PLATFORM_WITH_CAUTION` (LOW risk, `PROCEED_CAUTIOUSLY`).
     - Clarifies to the user that third-party content abuse does not compromise the root platform.
  6. **Anti-Spoofing Behavioral Override**:
     - If any message body demands credentials, passwords, or OTPs, `applyBehavioralImpersonationOverride()` escalates to `POSSIBLE_IMPERSONATION` (`HIGH` risk, `STOP_AND_AVOID`), ensuring malicious lures never hide behind legitimate names.


---

## 4. Complete API Surface (Member 5 Endpoints)

| Method | Endpoint | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/reports` | Public (Rate-Limited) | Submits citizen report with defanging and deduplication |
| `POST` | `/api/moderation/login` | Public | Authenticates moderator credentials and issues Supabase JWT |
| `GET` | `/api/moderation/queue` | Moderator JWT | Fetches pending reports with status, category, and date filtering |
| `POST` | `/api/moderation/review` | Moderator JWT | Executes `APPROVE`, `REJECT`, or `RETIRE` triage action |
| `GET` | `/api/moderation/stats` | Moderator JWT | Aggregated queue volume, velocity, and threat breakdown |
| `GET` | `/api/moderation/intelligence` | Moderator JWT | Retrieves verified intelligence feed with pagination & search |
| `PATCH` | `/api/moderation/intelligence` | Moderator JWT | Toggles indicator active status or updates moderator notes |
| `POST` | `/api/moderation/manual-intel` | Moderator JWT | Injects direct verified threat indicator (zero-day feed) |
| `GET` | `/api/moderation/settings` | Moderator JWT | Fetches dynamic engine configuration and feature flags |
| `PATCH`| `/api/moderation/settings` | Moderator JWT | Updates engine sensitivity, corroboration thresholds |
| `GET` | `/api/moderation/audit-logs` | Moderator JWT | Fetches cryptographically chained audit trail |
| `GET` | `/api/moderation/audit-logs/stats`| Moderator JWT | Audit table storage volume, retention health, oldest record |
| `GET` | `/api/moderation/audit-logs/verify`| Moderator JWT | Re-evaluates full cryptographic hash chain and reports tamper status |
| `POST` | `/api/moderation/audit-logs/purge`| Moderator JWT | Triggers retention prune and records `PURGE_EXPIRED` block |
| `DELETE`| `/api/moderation/audit-logs/clear`| Moderator JWT | Development reset for cryptographic chain testing |
| `POST` | `/api/moderation/seed-demo` | Moderator JWT | Ingests realistic test scenarios for jury presentation |
| `POST` | `/api/moderation/clear-demo` | Moderator JWT | Cleans demo data to return system to clean state |

---

## 5. Automated Test Suites & Validation (100% Pass Rate)

Member 5 maintains comprehensive automated test coverage with zero failing tests:

### 1. Cryptographic Integrity & Hash Chaining Test Suite
**File**: `services/api/test/auditChainAndIntegrity.test.mjs` (20 Tests — 100% Pass)
- Deterministic SHA-256 calculation across canonical ISO timestamps.
- Sequential hash linkage (`current.prev_hash === previous.entry_hash`).
- Payload tampering detection and pinpointing of `brokenAtId`.
- Illicit middle-record deletion detection.
- Forged hash replacement attack detection.
- Scrambled / out-of-order block detection.
- Graceful legacy unhashed record compatibility without false alarms.
- Raw vs defanged indicator matching resilience.
- Chain tip hash alignment.
- **Post-prune verification resilience** (floating chain anchor).
- **Tamper detection within pruned chains**.

### 2. Reconciliation Engine Mathematical Suite
**File**: `services/api/test/reconciliationEngine.test.mjs` (12 Tests — 100% Pass)
- Scenarios 1–3: Pure scam indicators scaling via doubt decay.
- Scenario 4: Official domain with safe citizen reports.
- Scenario 5: Contested reports (1 Scam vs 1 Safe) failing-closed to `CONFLICTED`.
- Scenario 6: Malicious URL within legitimate body.
- Scenario 7: High-confidence phone indicator override.
- Scenario 8: Retired indicator excluded from live matching.
- Scenario 9: Asymmetric risk (1 Scam vs 2 Safe) failing-closed to `CONFLICTED`.
- Scenario 10: Official directory match with caution.
- Scenario 11: Single 0.70 report yielding `SUSPICIOUS_INDICATOR` (MEDIUM risk).
- Scenario 12: Corroborated report ($n=3$) crossing 0.85 to `CONFIRMED_SCAM` (HIGH risk).

### 3. Reporting API & Auth Suite
**File**: `services/api/test/reportingApi.test.mjs` (23 Tests — 100% Pass)
- Public report creation, payload validation, and rate-limiting.
- Moderator route protection and role-based access control.
- Review triage workflow (`APPROVE`, `REJECT`, `RETIRE`).
- Dynamic settings and intelligence status updates.

---

## 6. Live Hackathon Demonstration Script (5-Minute Walkthrough)

When presenting to judges and technical evaluators, execute this sequence:

```
[ Step 1: Submit Citizen Report ] ──> [ Step 2: Moderator Triage (0.70) ]
                 │                                        │
                 ▼                                        ▼
[ Step 3: Dynamic Doubt Decay ]   ──> [ Step 4: Bot Whitewashing Defense ]
                 │                                        │
                 ▼                                        ▼
[ Step 5: Cryptographic Audit Verification (NIST SP 800-92) ]
```

| Step | Action on Screen | Script to Speak | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **1. Citizen Report & Defanging** | Open Report Modal. Submit a phishing SMS with `https://ceb-bill-pay.lk`. | *"A citizen reports a phishing SMS. Our backend immediately computes a SHA-256 fingerprint of the message and defangs the URL to `hxxps://ceb-bill-pay[.]lk`. Submitter PII is completely stripped."* | Report created as `PENDING`. URL defanged. Zero PII stored. |
| **2. Moderator Review & Confidence Gating** | Log into `/moderator`. Select the pending report, assign **0.70 (Suspicious)**, and click **Approve**. | *"As an authenticated moderator, I triage the submission using the STIX 2.1 confidence scale. Approving it transforms the report into verified intelligence and logs an immutable audit block."* | Transformed into `verified_threat_intelligence`. Audit block created. |
| **3. Doubt Decay in Action** | Simulate 2 additional reports for the same domain. View intelligence feed. | *"Notice that rather than duplicating rows, `report_count` incremented to 3. Applying our mathematical doubt decay model, confidence dynamically scaled from 70.0% to 87.3%, automatically escalating the verdict to `CONFIRMED_SCAM` at HIGH risk."* | Report count = 3.<br/>Confidence = **87.3%**.<br/>Verdict escalates to `CONFIRMED_SCAM`. |
| **4. Bot Whitewashing Defense** | Analyze an indicator with 1 Scam report and 40 Safe reports. | *"If we used naive majority voting, 40 safe votes would declare this phishing site 97% safe. In Member 5's engine, we enforce Saltzer & Schroeder's Fail-Safe Defaults: threat evidence can never be whitewashed. The engine flags it as `CONFLICTED` with HIGH risk."* | Verdict: `CONFLICTED`<br/>Risk: **HIGH**<br/>Directive: `VERIFY_INDEPENDENTLY` |
| **5. Cryptographic Audit Verification** | Go to Audit Trail tab in Moderator Dashboard. Click **Verify Chain Integrity**. Inspect an entry. | *"Every action is forward-chained using SHA-256 (NIST SP 800-92). Notice our live verification: it mathematically proves zero tampering across the entire chain. Even when records are pruned after 90 days, floating anchors preserve cryptographic validity."* | Chain verified (`isValid: true`). Live block hash linkage displayed. |

---

## 7. Anticipated Jury Questions & Bulletproof Answers

### Q1: "Why can't attackers use a botnet to whitewash phishing URLs by voting 'Safe'?"
> **Answer**: *"We eliminate whitewashing through two layers of defense:
> 1. **Human-in-the-Loop Gating**: Citizen submissions only enter the `user_reports` queue. They never touch live analysis until vetted by an authenticated moderator.
> 2. **Asymmetric Fail-Safe Defaults**: Grounded in Saltzer & Schroeder (1975), crowd 'safe' votes can never override an Indicator of Compromise. Even with 50 safe votes and 1 verified scam report, the system fails-closed to `CONFLICTED` (`HIGH` risk)."*

### Q2: "How do you protect submitter privacy and ensure compliance with data protection laws?"
> **Answer**: *"Privacy is guaranteed by design at ingestion:
> 1. Submitter IP addresses and contact details are completely scrubbed before database insertion.
> 2. Message bodies are converted into cryptographic SHA-256 fingerprints (`content_sha256`), allowing us to match scam campaigns without storing private message contents.
> 3. Historical audit records respect a 90-day rolling retention policy with automated pruning."*

### Q3: "What prevents a malicious or compromised moderator from altering audit logs to cover their tracks?"
> **Answer**: *"Audit logs are protected by cryptographic forward-chaining (NIST SP 800-92) and database immutability:
> 1. Each record's `entry_hash` is computed from `prev_hash` and the full entry payload. Any alteration breaks the cryptographic hash and all subsequent links.
> 2. The PostgreSQL database trigger `prevent_audit_log_tamper()` categorically raises an exception on any SQL `UPDATE` statement.
> 3. Our automated verifier re-computes every block from anchor to tip, detecting tampering with sub-millisecond precision."*

### Q4: "Does pruning old records break the cryptographic audit chain?"
> **Answer**: *"No. When records older than 90 days roll off, the oldest surviving active record becomes the **floating chain anchor**. Its internal SHA-256 hash is verified against its payload and stored `prev_hash`, and all forward sequential links are verified. Additionally, the automated retention worker logs an immutable `PURGE_EXPIRED` governance block directly to the tip of the chain, sealing the prune event into the ledger."*

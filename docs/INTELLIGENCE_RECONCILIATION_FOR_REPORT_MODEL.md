# TrustLens LK — Reporting, Moderation & Threat Intelligence Reconciliation System

> **Author**: Member 5  
> **Domain**: Citizen Reporting System, Moderation Dashboard & Workflow, Verified Threat Intelligence Feed, and Asymmetric Risk Reconciliation Engine   
> **Standards Compliance**: NIST SP 800-61 Rev. 2, STIX 2.1 / MISP Admiralty Scale, Saltzer & Schroeder (1975) Fail-Safe Defaults  

---

## 1. Executive Overview & Problem Statement

In digital fraud detection and community cyber-defense, **treating crowd submissions like a standard democratic election (where majority vote wins) is catastrophic**.

### The Fatal Flaw of Naive Democratic Voting
Suppose an attacker launches an SMS phishing campaign impersonating a financial institution:
- 2 citizens realize they were asked for banking OTPs and submit scam reports.
- 3 other citizens visit the link, do not enter details, or assume it looks legitimate, and submit "false alarm / safe" reports (or the attacker coordinates 3 bot accounts to whitewash the URL).

Under naive democratic voting:
$$\text{Safe Ratio} = \frac{3}{3 + 2} = 60\% \implies \text{Verdict: SAFE}$$

If a security platform marks this content as "VERIFIED SAFE", citizens will trust the lure, click the link, and surrender their bank credentials or financial assets.

### Member 5's Solution: The Asymmetric Threat Intelligence Architecture
To eliminate this vulnerability, Member 5 engineered an end-to-end vertical slice comprising:
1. **Citizen Reporting Pipeline**: Secure, validated report submission interface capturing threat indicators, SHA-256 message hashes, and defanged URLs with zero PII leakage.
2. **Moderation Queue & Workflow**: Protected dashboard (Supabase Auth RBAC) where verified moderators review, triage, set STIX 2.1 confidence ratings, edit threat notes, and retire/reactivate indicators.
3. **Verified Threat Intelligence Feed**: An authoritative, deduplicated repository of vetted threat indicators that feeds directly into real-time analysis.
4. **Asymmetric Risk Reconciliation Engine**: A mathematical, fail-closed reconciliation engine grounded in **Saltzer & Schroeder's (1975) Fail-Safe Defaults**:
   - Threat reports represent **Indicators of Compromise (IoCs)**.
   - Crowd "safe" reports represent **non-authoritative absence of harm** ("I didn't lose money" is never proof of safety).
   - In contested scenarios (e.g. 3 safe vs 2 scam), the engine **fails-closed to HIGH risk (`CONFLICTED`)** with recommendation `VERIFY_INDEPENDENTLY`. Crowd votes can **never** whitewash a verified threat.
5. **Cryptographic Audit Trail & Tamper-Evidence (NIST SP 800-92)**:
   - Forward-secure SHA-256 hash chaining (`prev_hash` $\to$ `entry_hash`) linking every moderator action and governance event into an immutable ledger.
   - PostgreSQL trigger immutability (`prevent_audit_log_tamper()`) forbidding `UPDATE` operations.
   - Resilience across 90-day retention pruning using the **Floating Chain Anchor Principle** and `PURGE_EXPIRED` cryptographic governance blocks.
   - Live audit verification UI providing real-time mathematical proof of log integrity.

---

## 2. Mathematical Foundation & Dynamic Corroboration

### A. Human-in-the-Loop Base Confidence ($C_{\text{base}}$)
When a moderator approves an indicator in the Moderator Dashboard, they assign a **Base Confidence** ($C_{\text{base}}$) using the **STIX 2.1 / MISP Admiralty Scale**:
- **Definite Threat (1.00 / 100%)**: Confirmed phishing kit, active credential harvester, verified scam infrastructure.
- **High Probability (0.85 / 85%)**: Strong scam markers, unverified lookalike domain, urgent financial lure.
- **Suspicious / Caution (0.70 / 70%)**: Suspicious characteristics, unverified entity, moderate certainty.

### B. The Mathematical Doubt Decay Model
Every confidence score corresponds to an initial **Uncertainty (Doubt)**:
$$\text{Doubt}_0 = 1 - C_{\text{base}}$$

When $n$ independent community reports corroborate the exact same indicator, the remaining doubt decays exponentially with each corroboration:
$$\text{Doubt}(n) = (1 - C_{\text{base}}) \times \gamma^{(n - 1)}$$
$$C_{\text{effective}}(n) = \min\left(1.0, 1 - \text{Doubt}(n)\right)$$

Where:
- $\gamma = 0.65$ (Uncertainty decay rate: each corroboration eliminates 35% of the remaining doubt).
- $n = \text{report\_count} \ge 1$.

### C. Numerical Convergence Table

| Report Count ($n$) | Starting $C_{\text{base}} = 0.70$ (Suspicious) | Starting $C_{\text{base}} = 0.85$ (High Probability) | Starting $C_{\text{base}} = 1.00$ (Definite) | Security Significance |
| :---: | :---: | :---: | :---: | :--- |
| **1** | **70.0%** (`SUSPICIOUS_INDICATOR` — MEDIUM) | **85.0%** (`CONFIRMED_SCAM` — HIGH) | **100.0%** (`CONFIRMED_SCAM` — HIGH) | Initial moderator approval |
| **2** | **80.5%** (`SUSPICIOUS_INDICATOR` — MEDIUM) | **90.3%** (`CONFIRMED_SCAM` — HIGH) | **100.0%** (`CONFIRMED_SCAM` — HIGH) | Corroborated by 2nd independent report |
| **3** | **87.3%** (`CONFIRMED_SCAM` — HIGH) | **93.7%** (`CONFIRMED_SCAM` — HIGH) | **100.0%** (`CONFIRMED_SCAM` — HIGH) | **Escalation Threshold crossed** ($C \ge 0.85$) |
| **4** | **91.8%** (`CONFIRMED_SCAM` — HIGH) | **95.9%** (`CONFIRMED_SCAM` — HIGH) | **100.0%** (`CONFIRMED_SCAM` — HIGH) | High community consensus |
| **5** | **94.7%** (`CONFIRMED_SCAM` — HIGH) | **97.3%** (`CONFIRMED_SCAM` — HIGH) | **100.0%** (`CONFIRMED_SCAM` — HIGH) | Confirmed widespread campaign |
| **8+** | **99.0%+** (`CONFIRMED_SCAM` — HIGH) | **99.5%+** (`CONFIRMED_SCAM` — HIGH) | **100.0%** (`CONFIRMED_SCAM` — HIGH) | Near-absolute mathematical certainty |

> **Key Architectural Insight**: A single `0.70` (Suspicious) report begins at `MEDIUM` risk (`SUSPICIOUS_INDICATOR`, `VERIFY_INDEPENDENTLY`). When 2 more independent victims report it ($n=3$), confidence dynamically scales to **87.3%**, automatically crossing the **0.85 threshold** and escalating the indicator to `CONFIRMED_SCAM` (`HIGH` risk, `STOP_AND_AVOID`) — without requiring manual re-review by a moderator.

---

## 3. Asymmetric Decision Engine Architecture

```mermaid
flowchart TD
    A[Incoming Threat Indicator / Verified Feed Lookup] --> B{Contested Reports on File?<br/>Scam > 0 AND Safe > 0}
    
    B -- YES --> C[FAIL-SAFE ASYMMETRIC OVERRIDE<br/>Net Verdict: CONFLICTED<br/>Risk: HIGH | VERIFY_INDEPENDENTLY<br/>Trace: Crowd votes cannot whitewash IoCs]
    
    B -- NO --> D{Report Type?}
    
    D -- Pure Safe: Safe > 0, Scam == 0 --> E[VERIFIED_SAFE<br/>Risk: LOW | VERIFIED_SAFE<br/>Action: Safe Trust Badge]
    
    D -- Pure Scam: Scam > 0, Safe == 0 --> F{Effective Confidence<br/>C_effective >= 0.85?}
    
    F -- YES --> G[CONFIRMED_SCAM<br/>Risk: HIGH | STOP_AND_AVOID<br/>Action: Block & Warn Directive]
    
    F -- NO --> H[SUSPICIOUS_INDICATOR<br/>Risk: MEDIUM | VERIFY_INDEPENDENTLY<br/>Action: Exercise Caution Directive]
    
    D -- No Intelligence on File --> I[Preserve Base Analyzer Assessment]
```

---

## 4. Master Catalog of Scenarios & Edge Cases (Member 5 Domain)

### Category 1: Contested Crowd Reports & Fail-Safe Defaults
1. **The "3 Safe vs 2 Unsafe" Case**:
   - *Outcome*: `CONFLICTED` (Risk: HIGH, `VERIFY_INDEPENDENTLY`).
   - *Security Rationale*: Threat evidence represents an IoC. 3 unverified citizens claiming "safe" cannot negate 2 reports of financial loss.
   - *Trace*: *"Submissions contain conflicting assessments (2 threat vs 3 safe). Fail-Safe Defaults (Saltzer & Schroeder 1975): Verified threat evidence cannot be overridden by unverified crowd votes."*
2. **The "1 Scam vs 1 Safe" Case**:
   - *Outcome*: `CONFLICTED` (Risk: HIGH, `VERIFY_INDEPENDENTLY`).
3. **The "1 Scam vs 40 Safe" Case (The Bot Whitewashing Defense)**:
   - *Outcome*: `CONFLICTED` (Risk: HIGH, `VERIFY_INDEPENDENTLY`).
   - *Security Rationale*: In digital crime, an attacker can spin up 40 bot accounts to whitewash a phishing domain. Unverified crowd votes can **never** erase an IoC.

### Category 2: Adversarial & Fraudster Attack Vectors
4. **Sybil / Botnet Whitewashing Attack**:
   - Scammers generate 50 fake accounts to submit "Safe" reports for a phishing URL.
   - *Defense*: Crowd safe votes never override verified threat reports. The whitewashing fails.
5. **Denial-of-Reputation Attack on Legitimate Entities**:
   - A malicious actor reports a competitor or legitimate service as a scam.
   - *Defense*: Citizen reports are stored as `PENDING` in `user_reports`. They **never** affect real-time verdicts until an authenticated moderator examines the evidence and verifies the indicator.

### Category 3: Multi-Indicator Heterogeneous Evidence
6. **Throwaway Domain + Known Scam Content Hash**:
   - A scammer registers a brand-new domain, but the message body matches a verified scam template on file.
   - *Defense*: The `content_sha256` indicator matches the verified intelligence feed, flagging the message with 95%+ confidence regardless of the new URL.
7. **Clean Domain + Malicious Phone Number**:
   - A scam message references a known website, but lists a phone number flagged in the verified feed as an active OTP harvester.
   - *Defense*: The phone indicator independently escalates the threat to `CONFIRMED_SCAM` (Risk: HIGH).

### Category 4: Confidence Scaling & Lifecycle Management
8. **Single Suspicious Report ($C_{\text{base}} = 0.70$)**:
   - Evaluates to `SUSPICIOUS_INDICATOR` (Risk: MEDIUM, `VERIFY_INDEPENDENTLY`).
9. **Corroborated Report ($C_{\text{base}} = 0.70, n = 3 \implies C_{\text{effective}} = 0.873$)**:
   - Automatically crosses the $0.85$ threshold, escalating to `CONFIRMED_SCAM` (Risk: HIGH, `STOP_AND_AVOID`).
10. **Indicator Retirement & Reactivation**:
    - When a moderator marks `active = false` on an indicator, it is immediately excluded from live matching.
    - If a threat resurfaces, the moderator reactivates it, immediately restoring protection with an auditable log entry.

### Category 5: Cryptographic Chain Integrity & Pruning Resilience (NIST SP 800-92)
11. **Cryptographic Payload Tampering Detection**:
    - An attacker or rogue database admin modifies `moderator_notes`, `action`, or `confidence` on an existing audit record.
    - *Defense*: `verifyAuditChainIntegrity()` recomputes `SHA-256(prev_hash | payload)` for every block. Any payload alteration breaks the hash; the system reports `isValid: false` and pinpoints the exact record ID.
12. **Rogue Record Deletion / Sequence Breaking**:
    - An insider deletes a controversial audit entry from the middle of the active database table.
    - *Defense*: The subsequent block's `prev_hash` no longer points to the preceding block. The chain break is flagged with sub-millisecond precision.
13. **Retention Pruning with Floating Chain Anchors**:
    - Records older than the 90-day retention window are purged to comply with privacy regulations.
    - *Defense*: The oldest surviving record serves as the floating chain anchor. The audit verifier validates the anchor's self-contained SHA-256 hash and verifies all forward sequential links, eliminating false alarms without sacrificing tamper detection.
14. **Immutable Governance Prune Sealing (`PURGE_EXPIRED`)**:
    - Every automated retention purge generates a cryptographically hashed governance entry chained to the active chain tip, permanently recording the deletion timestamp and volume.

### Category 6: Protected Entity Guardrail System & Approval Circuit Breakers (Zero-Hardcoding Architecture)
15. **Citizen Reports Official National Domain (e.g. `police.lk`, `cbsl.gov.lk`)**:
    - *The Problem*: Citizens frequently submit legitimate official domains when receiving SMS lures that falsely claim to originate from police or banks. An unobservant moderator might mistakenly approve the domain as a scam.
    - *Dynamic Guardrail (Zero Hardcoding)*: Queries Member 3's authoritative `lookupDomainDirectory(cleanDomain)` dynamically against `approved_organizations`.
    - *Outcome*: Triage tags the item as `🏛️ Official National Entity` with recommended action `REJECT`. Direct approval is locked by the **Approval Circuit Breaker** (`PROTECTED_ENTITY_OVERRIDE_REQUIRED`, HTTP 422).
16. **Citizen Reports Global Platform Abused in Campaign (e.g. `facebook.com`, `google.com`)**:
    - *The Problem*: Fraudulent ads or phishing pages hosted on top global platforms lead users to report the root domain itself.
    - *Dynamic Guardrail (Zero Hardcoding)*: Dynamically evaluates `isTopGlobalDomain(cleanDomain)` using Tranco Top-1M ranking data from `@trustlens/domain`.
    - *Outcome*: Triage tags the item as `🌐 Top Global Platform` with recommended action `REJECT`. In the reconciliation engine, isolated crowd reports evaluate to `GLOBAL_PLATFORM_WITH_CAUTION` (Risk: LOW, `PROCEED_CAUTIOUSLY`), disambiguating third-party platform abuse from core domain compromise.
17. **Approval Circuit Breaker & Incident Override Workflow**:
    - If a moderator attempts to click `APPROVE` on a protected entity, the API and UI circuit breakers block execution unless:
      1. `overrideProtectedEntity === true` is explicitly checked.
      2. An `incidentReason` or CERT Ticket Reference (e.g. `SLCERT-INC-2026-089: Active DNS Hijack`) is provided.
    - The audit trail records the action under threat category `Protected Entity Override` with full operator accountability.
18. **Active Behavioral Impersonation Override on Protected Entities**:
    - If a message quotes a legitimate global platform (e.g. `facebook.com`) or official domain, but the body contains active credential or payment harvesting (demanding OTPs, bank passwords, or instant money transfers), the engine executes `applyBehavioralImpersonationOverride()`:
    - *Outcome*: Fails-closed to `POSSIBLE_IMPERSONATION` (`HIGH` risk, `STOP_AND_AVOID`). Safe intelligence and global reputation **never** excuse active credential theft.
19. **Citizen Disputes False Alarm on Protected Entity (`false_positive`)**:
    - If a user reports `police.lk` as a `false_positive` (disputing a false flag), the Circuit Breaker does **not** block approval. Approving a false positive marks the indicator as `VERIFIED_SAFE`, protecting the legitimate entity from future heuristic false alarms.

---

## 5. Judge & Evaluator Presentation Guide (Member 5 Vertical Slice)

This section is engineered specifically for hackathon presentations, technical evaluations, and jury defenses of **Member 5's contributions**.

---

### 5.1 The 30-Second Elevator Pitch
> *"In community-driven fraud defense, naive majority voting is fatal. If 3 bots vote 'safe' and 2 victims report that a site stole their bank OTP, standard voting declares that site 60% safe.
>
> As **Member 5**, I engineered the **Citizen Reporting, Moderation Workflow, and Verified Threat Intelligence Engine** for TrustLens LK. 
>
> Grounded in **NIST SP 800-61** and **Saltzer & Schroeder's Fail-Safe Defaults**, our engine treats threat indicators as asymmetric: a verified threat report can never be whitewashed by crowd votes. By coupling human-in-the-loop moderation with mathematical doubt decay and deduplicated indicator feeds, Member 5 delivered a 100% explainable, tamper-resistant threat intelligence vertical slice."*

---

### 5.2 How Member 5 Built It — The 6-Stage Engineering Pipeline

Member 5 engineered an end-to-end vertical slice spanning UI, API, Database/RLS, and Mathematical Modeling:

```
[ Citizen Report Submission ]
               │
               ▼
┌──────────────────────────────────────────────────────────┐
│ STAGE 1: Report Ingestion & Sanitization Pipeline         │
│ • Client/Server Zod schema validation                    │
│ • URL defanging (hxxps://, [.])                          │
│ • SHA-256 message body cryptographic hashing             │
│ • Submitter PII scrubbing (anonymized storage)           │
└──────────────────────────────┬───────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│ STAGE 2: Protected Moderator Dashboard & Workflow (RBAC) │
│ • Supabase Auth JWT verification & role gating           │
│ • Triage queue: APPROVE, REJECT, RETIRE                  │
│ • STIX 2.1 Base Confidence selector (1.00 / 0.85 / 0.70) │
│ • Editable moderator context notes                       │
└──────────────────────────────┬───────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│ STAGE 3: Verified Threat Intelligence Feed & Deduplication│
│ • Sanitized ingestion into verified_threat_intelligence  │
│ • Deduplication by canonical indicator & content hash    │
│ • Corroboration tracking (report_count incrementing)     │
└──────────────────────────────┬───────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│ STAGE 4: Asymmetric Risk Reconciliation Engine           │
│ • Fail-Closed Defaults (Saltzer & Schroeder 1975)        │
│ • Contested reports (Scam > 0 AND Safe > 0) -> CONFLICTED│
│ • Crowd safe votes cannot overturn verified IoCs         │
└──────────────────────────────┬───────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│ STAGE 5: Dynamic Doubt Decay Engine                      │
│ • Doubt(n) = (1 - C_base) * 0.65^(n - 1)                 │
│ • C_effective >= 0.85 -> CONFIRMED_SCAM (HIGH Risk)      │
│ • C_effective <  0.85 -> SUSPICIOUS_INDICATOR (MEDIUM)   │
└──────────────────────────────┬───────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│ STAGE 6: 100% Explainable AI Trace Chain & Safety Actions│
│ • Transparent, human-readable reasoning output           │
│ • Directives: STOP_AND_AVOID vs VERIFY_INDEPENDENTLY     │
└──────────────────────────────┬───────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│ STAGE 7: NIST SP 800-92 Cryptographic Audit & Tamper-Evid │
│ • Forward-secure SHA-256 hash chaining (prev -> entry)   │
│ • PostgreSQL trigger prevents UPDATE (immutability)      │
│ • Floating anchor verification survives 90d prune        │
│ • Real-time UI verification with zero false alarms       │
└──────────────────────────────────────────────────────────┘
```

#### Detailed Technical Breakdown of Member 5's Implementation:

1. **Stage 1: Citizen Report Ingestion & Sanitization (`reportingService.mjs`)**:
   - **Validation**: Enforces strict runtime data validation using Zod schemas for report type (`SCAM`, `SAFE`, `PHISHING`), indicators, and context.
   - **URL Defanging**: Malicious URLs are automatically defanged (`https://evil.com` $\to$ `hxxps://evil[.]com`) before database insertion to prevent accidental clicks.
   - **Cryptographic Hashing**: Computes SHA-256 hashes of reported message bodies to detect identical scam templates even if URLs change.
   - **PII Scrubbing**: Submitter IP addresses and personal identifiers are scrubbed; only sanitized threat indicators and hashed fingerprints are retained.

2. **Stage 2: Protected Moderator Dashboard & Workflow (`ModeratorDashboard.tsx`)**:
   - **Authentication & RBAC**: Powered by Supabase Auth with strict role-based access control (`moderator` and `admin` roles). Unauthorized users are blocked at both route and API levels.
   - **Triage Actions**: Moderators can `APPROVE`, `REJECT`, or `RETIRE` reported items.
   - **STIX 2.1 Confidence Selector**: When approving, the moderator assigns a base confidence tier: `1.00 Definite Threat`, `0.85 High Probability`, or `0.70 Suspicious`.
   - **Editable Moderator Notes**: Contextual notes can be updated dynamically after approval to provide updated intelligence without altering indicator integrity.

3. **Stage 3: Verified Intelligence Feed & Deduplication**:
   - Approved reports populate the `verified_threat_intelligence` table.
   - **Smart Deduplication**: If an approved indicator already exists in the feed, the system does not create redundant rows. Instead, it increments `report_count`, updates the timestamp, and feeds into the corroboration engine.

4. **Stage 4: Asymmetric Risk Reconciliation Engine (`reconcileIntelligence.mjs`)**:
   - Implements **Saltzer & Schroeder's 1975 Fail-Safe Defaults**:
     - If both Scam and Safe reports exist for an indicator, the system **refuses to average them**.
     - The verdict fails-closed to `CONFLICTED` (`HIGH` risk, `VERIFY_INDEPENDENTLY`).
     - Crowd safe votes can **never** erase an Indicator of Compromise (IoC).

5. **Stage 5: Dynamic Doubt Decay Engine**:
   - Implements the mathematical formula:
     $$\text{Doubt}(n) = (1 - C_{\text{base}}) \times 0.65^{(n - 1)}, \quad C_{\text{effective}} = 1 - \text{Doubt}(n)$$
   - When report count increases, confidence scales automatically:
     - $C_{\text{effective}} \ge 0.85 \implies \text{CONFIRMED\_SCAM}$ (`HIGH` risk, `STOP_AND_AVOID`).
     - $0.65 \le C_{\text{effective}} < 0.85 \implies \text{SUSPICIOUS\_INDICATOR}$ (`MEDIUM` risk, `VERIFY_INDEPENDENTLY`).

6. **Stage 6: Explainable AI Trace Chain**:
   - Rather than outputting an opaque risk score, Member 5's engine generates an auditable, step-by-step reasoning trace explaining the exact mathematical and security rationale.

7. **Stage 7: Cryptographic Audit Trail & Forward-Secure Tamper-Evidence (`AuditDetailModal.tsx`)**:
   - Complies with **NIST SP 800-92** (Guide to Computer Security Log Management).
   - Computes deterministic SHA-256 digests across canonical timestamps, action, actor role, email, indicator, threat category, notes, and client IP.
   - Each entry strictly points to `prev_hash` of the preceding entry.
   - Enforces database immutability via PostgreSQL trigger `prevent_audit_log_tamper()`.
   - Preserves chain verification through historical 90-day retention pruning using floating chain anchors and `PURGE_EXPIRED` cryptographic governance blocks.

---

### 5.3 Live Demonstration Script for Judges (3-Minute Walkthrough)

Follow this 5-step sequence to demonstrate Member 5's features live to the judging panel:

| Step | What to Show on Screen | What to Say to the Judges | Expected Result |
| :--- | :--- | :--- | :--- |
| **1. Citizen Report Submission & Defanging** | Open the Report Modal on the frontend. Submit a suspicious SMS with a phishing link (`https://pay-ceb-bill.com`). | *"Here, a citizen reports a phishing SMS. Notice that on submission, our backend automatically computes a SHA-256 content hash and defangs the URL to `hxxps://pay-ceb-bill[.]com` so it can never be accidentally triggered. Submitter PII is completely stripped."* | Report created in `PENDING` status. URL defanged. Zero PII stored. |
| **2. Moderator Dashboard & STIX Confidence Gating** | Log into `/moderator` with moderator credentials. Open the pending report, select **0.70 (Suspicious)**, add a moderator note, and click **Approve**. | *"As an authenticated moderator, I review the report in our protected dashboard. I assign a base confidence of 0.70 based on the STIX 2.1 scale and approve it. Notice that it immediately populates our Verified Threat Intelligence feed with an editable moderator note."* | Report approved. Transformed into `verified_threat_intelligence`. |
| **3. Dynamic Doubt Decay in Action** | Trigger/simulate a 2nd and 3rd citizen report for the same indicator. Show the indicator in the feed. | *"Notice what happened: rather than creating duplicate rows, our system incremented `report_count` to 3. Applying our exponential doubt decay formula, the confidence mathematically scaled from 70.0% to 87.3%, automatically crossing our 0.85 threshold and escalating the verdict to `CONFIRMED_SCAM` at HIGH risk."* | Report count = 3.<br/>Confidence = **87.3%**.<br/>Verdict escalates to `CONFIRMED_SCAM`. |
| **4. The Bot Whitewashing Defense (Fail-Safe Defaults)** | Show an indicator that has **1 Scam Report** and **40 Safe Reports** (or 3 Safe vs 2 Scam). Run analysis on it. | *"In a naive voting system, 40 safe votes would declare this site 97% safe, exposing citizens to fraud. In Member 5's reconciliation engine, we enforce Saltzer & Schroeder's Fail-Safe Defaults: threat evidence cannot be whitewashed. The system flags it as `CONFLICTED` with HIGH risk."* | Verdict: `CONFLICTED`<br/>Risk: **HIGH**<br/>Action: `VERIFY_INDEPENDENTLY` |
| **5. Cryptographic Audit Trail & Chain Verification** | Navigate to the Audit Trail tab in the Moderator Dashboard. Click **Verify Chain Integrity** or inspect a log entry. | *"Every action—approval, rejection, or policy edit—is cryptographically chained using SHA-256 (NIST SP 800-92). Notice our real-time audit verification: it evaluates the full cryptographic chain and mathematically proves zero tampering. Even if records are pruned after 90 days, floating anchors preserve proof of integrity."* | Chain verified (`isValid: true`). Live SHA-256 hash inspection displayed. |

---

### 5.4 Anticipated Questions & Bulletproof Answers (Member 5 Focus)

#### Q1: "How does Member 5's reporting system protect submitter privacy and prevent PII leaks?"
> **Answer**: *"Privacy is enforced at ingestion. When a citizen submits a report:
> 1. Submitter IP addresses and contact details are **scrubbed** before database insertion.
> 2. The report text is converted to a cryptographic SHA-256 hash (`content_sha256`), allowing us to identify identical scam templates without storing private message contents.
> 3. All URLs are defanged (`hxxps://`, `[.]`) to ensure safe storage and display."*

#### Q2: "How do you prevent attackers from using bot accounts to mark scam websites as safe (Sybil Whitewashing)?"
> **Answer**: *"Member 5's architecture prevents Sybil attacks through two strict controls:
> 1. **Moderator Gating**: Citizen submissions only enter the `user_reports` queue. They **never** become verified intelligence until an authenticated, vetted moderator inspects the evidence.
> 2. **Asymmetric Risk Priority**: In our reconciliation engine, crowd 'safe' reports **can never override a verified threat indicator**. Even with 50 bot 'safe' reports and 1 verified scam report, the system fails-closed to `CONFLICTED` (`HIGH` risk)."*

#### Q3: "What prevents malicious actors from filing false reports against legitimate businesses to destroy their reputation (Denial-of-Reputation)?"
> **Answer**: *"Denial-of-Reputation is prevented by our three-tier gating:
> 1. **Human-in-the-Loop Triage**: Reports do not affect analysis until vetted by a moderator.
> 2. **Confidence Gating**: A single low-confidence report ($C_{\text{base}} = 0.70$) only yields `SUSPICIOUS_INDICATOR` (`MEDIUM` risk, `VERIFY_INDEPENDENTLY`) and cannot escalate to `CONFIRMED_SCAM` (`HIGH` risk) without independent corroboration.
> 3. **Audited Moderator Actions**: All approvals, rejections, and retirements are logged with moderator IDs and timestamps for full accountability."*

#### Q4: "Why use exponential doubt decay $(1 - C_{\text{base}}) \times 0.65^{(n-1)}$ instead of a simple linear average or fixed score?"
> **Answer**: *"Linear averages fail at the extremes: they either scale too slowly or require arbitrary caps that break when report volume surges.
>
> Exponential doubt decay is an asymptotic model inspired by Bayesian belief updating:
> - The first corroboration provides the largest surge in certainty (eliminating 35% of uncertainty).
> - As reports accumulate, confidence approaches 100% asymptotically without ever overflowing.
> - It reflects real-world intelligence tradecraft: three independent reports in the wild provide exponential confirmation of a coordinated campaign."*

#### Q5: "How does your database handle duplicate reports without bloat?"
> **Answer**: *"When an approved report matches an existing indicator in `verified_threat_intelligence`, our backend does not insert a duplicate row. Instead, it increments `report_count`, recalculates `effective_confidence` via doubt decay, updates the timestamp, and preserves the moderator's context notes. This keeps the database lean, indexed, and optimized for sub-millisecond lookups."*

#### Q6: "How do you guarantee that a rogue moderator or database admin cannot alter historical audit records or whitewash actions?"
> **Answer**: *"We enforce tamper-evidence at both the cryptographic and database layers:
> 1. **NIST SP 800-92 SHA-256 Hash Chaining**: Every log entry computes `entry_hash = SHA-256(prev_hash | payload)`. Modifying any field (notes, action, timestamp) invalidates the hash and breaks all subsequent links.
> 2. **PostgreSQL Immutability Trigger**: The trigger `prevent_audit_log_tamper()` categorically raises an exception on any SQL `UPDATE` statement on `moderation_audit_logs`.
> 3. **Mathematical Verification**: Our verifier re-computes every block from the chain anchor to the chain tip, exposing any discrepancy immediately with the exact record ID."*

#### Q7: "Does the audit verification system break when historical logs are pruned after the 90-day retention window?"
> **Answer**: *"No. To comply with data privacy regulations (GDPR / ISO 27001), records older than 90 days are pruned. In our architecture:
> 1. The oldest surviving record in the database becomes the **floating chain anchor**, and its internal SHA-256 hash is verified against its payload and stored `prev_hash`.
> 2. All subsequent entries must strictly satisfy `current.prev_hash === previous.entry_hash`.
> 3. The retention purge worker itself appends a `PURGE_EXPIRED` cryptographic governance block to the tip of the chain, sealing the prune event into the immutable ledger."*

---

### 5.5 Key Takeaway for the Evaluation
Member 5 engineered a robust, secure, and mathematically sound **Reporting, Moderation, and Verified Threat Intelligence vertical slice** for TrustLens LK. By refusing to compromise on fail-closed security, we ensure that community reports empower citizens rather than exposing them to bot manipulation, whitewashing, or fraud.

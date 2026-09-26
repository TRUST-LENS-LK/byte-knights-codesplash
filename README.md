# TrustLens LK — Advanced Scam Decision Support & Threat Intelligence 🛡️

TrustLens LK is an enterprise-grade, multi-layered threat intelligence platform designed to protect Sri Lankan citizens from sophisticated digital scams, phishing, and fraudulent communications.

## 🌟 Core Architecture & Advanced Capabilities

TrustLens LK goes far beyond simple keyword matching. It utilizes a state-of-the-art **Multi-Layered Analysis Engine** to detect complex threats. 

### 🔍 The 4-Layer URL & Threat Analysis Pipeline
When a message or URL is submitted, it passes through four specialized defense layers:
1. **Heuristic & Entity Extraction Engine**: Uses a proprietary extraction engine to parse defanged URLs (e.g., `hxxp://`, `scam[.]lk`), extract phone numbers, emails, and LKR amounts, and evaluate grammatical/urgency heuristics.
2. **Organization & Domain Directory Validation**: Actively cross-references claimed organizations against an official trusted domain whitelist to instantly catch domain mismatches (e.g., claiming to be a major bank but using a `.top` domain).
3. **Global Threat Intelligence & Metadata Check**: Integrates with Google Safe Browsing APIs, global domain trust registries, and performs rigorous **Domain Age Verification** to flag newly registered, high-risk domains.
4. **Active Sandbox Detonation (URL Scanner)**: A dedicated, containerized headless Chromium scanner service safely detonates links in an isolated environment. It analyzes redirects, structural anomalies, adult content, and captures visual evidence (screenshots) without risking the user's device.

### 🧠 Additional Enterprise Features
* **AI-Assisted Context Validation**: Leverages the Gemini API for deep semantic analysis of the message context to resolve edge cases and highly sophisticated social engineering attacks.
* **Human-in-the-Loop (HITL) Moderation Dashboard**: A fully authenticated dashboard for threat analysts to review citizen reports, manage false positives, and manually inject verified intelligence indicators into the global blocklist.
* **Cryptographic Audit Chain**: Every moderation action is logged in an immutable, cryptographically verifiable audit chain, ensuring total accountability and integrity for threat intelligence changes.
* **Privacy-First Data Persistence**: Strict data minimization. No submitted PII or message content is stored on our servers unless explicit `retentionConsent` is granted by the user.

### 🔎 Advanced Heuristics & Entity Extraction Engine
The core of the offline analysis relies on highly specialized proprietary packages (`@trustlens/rules` and `@trustlens/extraction`):
* **Sri Lanka-Specific Entity Extraction:** Accurately extracts Sri Lankan mobile/landline numbers (E.164 normalization), LKR/USD monetary amounts, local organization names, and defanged URLs (e.g., `scam[.]lk`).
* **Deterministic Threat Detectors:** Runs 4 parallel heuristic detectors:
  * **Credential Request Detector:** Instantly triggers a `STOP_AND_AVOID` block if requests for OTPs, PINs, or passwords are found.
  * **Advance Payment Detector:** Identifies requests for "processing fees" or "customs clearance".
  * **Job Scam Detector:** Flags suspicious "work from home" or "daily income" schemes.
  * **Urgency Detector:** Analyzes language intended to cause panic or rush the victim.

### 🏛️ Explainable AI (XAI) & NIST Compliance
Every analysis result strictly adheres to **NIST Explainable AI (XAI) principles**. The system never just gives a "Safe" or "Unsafe" verdict; it provides specific `findings`, actionable `safeActions`, and explicitly discloses `limitations` (e.g., "This analysis uses deterministic keyword rules only") so citizens always understand *why* a decision was made.

### 🏗️ Monorepo Architecture
The project is built as a highly scalable **NPM Workspace Monorepo**, separating concerns for maximum reusability and maintainability:
* `apps/web`: The React + Vite frontend for citizens and moderators.
* `services/api`: The core Node.js intelligence and reporting API.
* `services/scanner`: The isolated Playwright/Chromium sandbox detonation environment.
* `packages/*`: Shared internal TypeScript libraries for Zod `contracts`, `rules`, `extraction`, and `domain` logic.

---

## 🐳 Quick Start (Docker) — Recommended for Evaluation

### Prerequisites
* Docker and Docker Compose must be installed on your system.

### Environment Configuration
Before starting the application, you must set up your environment variables:

```bash
# From the repository root, copy the example environment file:
cp .env.example .env
```
*(The `.env` file contains defaults that will work out of the box. If you have Supabase, Google Safe Browsing, or Gemini API keys, add them to the `.env` file before building to unlock full moderation and AI functionality.)*

### How to Build and Start
Run the following command from the repository root to build and start all microservices (Frontend, Core API, and URL Detonation Scanner):

```bash
docker compose up --build
```

### Accessing the Application
Once the containers are running, you can access the services at:
* **Frontend Web App (Citizen UI)**: [http://localhost:5174](http://localhost:5174)
* **Backend Core API**: [http://localhost:8787](http://localhost:8787) (Swagger OpenAPI Docs at `http://localhost:8787/docs`)
* **URL Detonation Scanner**: [http://localhost:8789](http://localhost:8789)

---

## 💻 Local Development (Without Docker)

Install dependencies from the repository root:

```powershell
npm install
```

Run the API and frontend in separate terminals:

```powershell
npm run start:api
npm run dev:web
```

Run the backend tests and formatting checks:

```powershell
npm run check:api
npm run test:api
npm run build:web
npm run lint:web
```

Build and type-check the shared monorepo packages with:

```powershell
npm run build:packages
npm run check:packages
```


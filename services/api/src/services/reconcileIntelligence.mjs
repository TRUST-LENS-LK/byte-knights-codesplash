/**
 * TrustLens LK — Intelligence Reconciliation Engine
 * ──────────────────────────────────────────────────
 * Confidence-weighted signal reconciliation that unifies rule-engine findings,
 * approved-domain lookups, and community-verified intelligence into a single,
 * explainable risk assessment.
 *
 * Design principles:
 *  1. Fail-Closed Security: Unresolved conflicts or critical threats default to HIGH risk.
 *  2. Anti-Spoofing / Impersonation Guard: Verified domains/safe reports CANNOT override
 *     active credential harvesting (OTP/PIN/password) or advance-fee payment demands.
 *  3. Explainable AI: Every adjustment produces an auditable, step-by-step trace chain.
 *  4. Democratic Consensus: Robust weighted consensus handling (e.g. 1 scam vs 40 safe,
 *     split disputes, or unanimous verification).
 *  5. Additive: Findings are never erased — only the final verdict is synthesized.
 */

// ─── Signal Classification ──────────────────────────────────────────────────

const SCAM_SIGNALS = new Set([
  'verified_scam_intelligence',
  'credential_request',
  'advance_payment',
])

const SAFE_SIGNALS = new Set([
  'verified_safe_intelligence',
  'approved_domain',
])

/**
 * Classify a finding into a signal bucket.
 * @param {{ canonicalSignal: string, strength: number, source: string }} finding
 * @returns {'SCAM' | 'SAFE' | 'NEUTRAL'}
 */
function classifySignal(finding) {
  if (SCAM_SIGNALS.has(finding.canonicalSignal) || finding.strength > 0.8) return 'SCAM'
  if (SAFE_SIGNALS.has(finding.canonicalSignal) || finding.strength === 0.0) return 'SAFE'
  return 'NEUTRAL'
}

// ─── Reconciliation Engine ──────────────────────────────────────────────────

/**
 * @typedef {Object} IntelligenceOverlay
 * @property {'CONFIRMED_SCAM' | 'VERIFIED_SAFE' | 'CONFLICTED' | 'OFFICIAL_ENTITY' | 'POSSIBLE_IMPERSONATION' | 'NO_INTEL'} netVerdict
 * @property {number} scamConfidence    – Weighted scam signal confidence [0..1]
 * @property {number} safeConfidence    – Weighted safe signal confidence [0..1]
 * @property {number} signalCount       – Total verified signals analyzed
 * @property {number} scamCount         – Number of verified scam reports
 * @property {number} safeCount         – Number of verified safe reports
 * @property {number} consensusRatio    – Dominant consensus ratio [0..1]
 * @property {string} consensusSummary  – Human-readable consensus breakdown
 * @property {boolean} hasDirectoryMatch – Whether domain is in official national registry
 * @property {string|null} officialOrganization – Name of the official organization if matched
 * @property {boolean} behavioralOverride – Whether critical rules overrode safe intelligence
 * @property {string[]} reconciliationTrace – Human-readable step-by-step reasoning chain
 */

/**
 * Reconcile all findings against the base decision from the rules engine.
 *
 * @param {Object} decision – The base decision produced by `analyze()`
 * @param {Array}  verifiedFindings – Findings from `checkVerifiedIntelligence()`
 * @returns {{ decision: Object, intelligenceOverlay: IntelligenceOverlay }}
 */
export function reconcileDecision(decision, verifiedFindings = []) {
  const trace = []
  const approvedDomainFindings = (decision.findings || []).filter((f) => f.canonicalSignal === 'approved_domain')
  const hasDirectoryMatch = approvedDomainFindings.length > 0
  const officialOrg = hasDirectoryMatch ? approvedDomainFindings[0].organization || approvedDomainFindings[0].evidence : null

  // 1. Bucket verified intelligence findings
  const scamFindings = []
  const safeFindings = []

  for (const finding of verifiedFindings) {
    const bucket = classifySignal(finding)
    if (bucket === 'SCAM') scamFindings.push(finding)
    else if (bucket === 'SAFE') safeFindings.push(finding)
  }

  const scamCount = scamFindings.length
  const safeCount = safeFindings.length
  const totalVerified = scamCount + safeCount

  // 2. Base confidence calculations
  let scamConfidence = scamCount
    ? Math.max(...scamFindings.map((f) => Number(f.confidence) || 0.9))
    : 0
  let safeConfidence = safeCount
    ? Math.max(...safeFindings.map((f) => Number(f.confidence) || 0.9))
    : 0

  if (hasDirectoryMatch) {
    const directoryConf = Math.max(...approvedDomainFindings.map((f) => Number(f.confidence) || 0.95))
    safeConfidence = Math.max(safeConfidence, directoryConf)
  }

  // Check for critical rule-engine threat signals (credential theft or advance payments)
  const criticalRuleFinding = (decision.findings || []).find(
    (f) => f.source === 'RULE' && (f.canonicalSignal === 'credential_request' || f.canonicalSignal === 'advance_payment')
  )
  const hasCriticalRuleThreat = Boolean(criticalRuleFinding)

  // Initialize overlay
  const overlay = {
    netVerdict: 'NO_INTEL',
    scamConfidence,
    safeConfidence,
    signalCount: totalVerified + (hasDirectoryMatch ? 1 : 0),
    scamCount,
    safeCount,
    consensusRatio: 1.0,
    consensusSummary: 'No verified intelligence on file.',
    hasDirectoryMatch,
    officialOrganization: officialOrg,
    behavioralOverride: false,
    reconciliationTrace: trace,
  }

  // ── CASE 1: No Verified Findings & No Official Directory Match ─────────────
  if (!totalVerified && !hasDirectoryMatch) {
    trace.push('No verified intelligence reports or official directory matches found.')
    trace.push(`Base rule engine assessment preserved (Risk: ${decision.riskBand}, Policy: ${decision.policyVersion || 'v1'}).`)
    return { decision, intelligenceOverlay: overlay }
  }

  // ── CASE 2: Official Directory Match (0 Community Reports) ─────────────────
  if (!totalVerified && hasDirectoryMatch) {
    trace.push(`🏛️ Official Directory Match: Domain is verified as the official digital property of "${officialOrg}".`)

    if (hasCriticalRuleThreat) {
      // Impersonation attack: official domain quoted in message asking for OTP/money
      overlay.netVerdict = 'POSSIBLE_IMPERSONATION'
      overlay.behavioralOverride = true
      overlay.scamConfidence = 0.95
      decision.riskBand = 'HIGH'
      decision.recommendation = 'STOP_AND_AVOID'
      decision.safeActions = [
        `Do not share OTPs, passwords, or send funds. Official organizations (${officialOrg}) never request credentials via SMS or unverified links.`,
        `Contact ${officialOrg} directly through verified public telephone channels to confirm this request.`,
      ]
      trace.push(
        `⚠ CRITICAL IMPERSONATION ALERT: Although the domain belongs to "${officialOrg}", the message contains high-risk threat indicators (${criticalRuleFinding.category}: ${criticalRuleFinding.canonicalSignal}).`,
        `Threat actors frequently reference legitimate institutions to trick victims into surrendering banking credentials.`,
        `Behavioral threat overrides domain reputation. Risk escalated to HIGH.`
      )
    } else {
      overlay.netVerdict = 'OFFICIAL_ENTITY'
      decision.riskBand = 'LOW'
      decision.recommendation = 'VERIFIED_SAFE'
      decision.safeActions = [
        `This domain is verified in the official Sri Lankan national registry for ${officialOrg}.`,
        `Always verify that your browser address bar shows the exact official domain before entering sensitive credentials.`,
      ]
      trace.push(
        `✅ Official registry confirmation: Identity verified as legitimate entity (${officialOrg}).`,
        `No critical threat signals detected. Risk set to LOW (VERIFIED_SAFE).`
      )
    }

    overlay.consensusSummary = `Official Registry (${officialOrg})`
    return { decision, intelligenceOverlay: overlay }
  }

  // ── CASE 3: Active Community Intelligence Reports Exist ───────────────────

  // Scenario 3A: Conflicting reports exist (Both Scam and Safe submitted)
  if (scamCount > 0 && safeCount > 0) {
    const scamRatio = scamCount / totalVerified
    const safeRatio = safeCount / totalVerified
    overlay.consensusRatio = Math.max(scamRatio, safeRatio)
    overlay.consensusSummary = `${safeCount} Safe vs ${scamCount} Scam (${(overlay.consensusRatio * 100).toFixed(1)}% ${scamRatio > safeRatio ? 'Scam' : 'Safe'})`

    trace.push(
      `📊 Community consensus analysis: ${scamCount} scam report(s) vs ${safeCount} safe report(s) (Total: ${totalVerified}).`
    )

    // Subcase 3A-1: Overwhelming Safe Consensus (e.g. 1 scam vs 40 safe -> scamRatio = 2.4% < 15%)
    if (scamRatio < 0.15 && safeCount >= 3) {
      if (hasCriticalRuleThreat) {
        // Even with 40 safe votes, if message currently asks for OTP, behavioral rule wins!
        applyBehavioralImpersonationOverride(decision, overlay, trace, criticalRuleFinding, officialOrg)
      } else {
        overlay.netVerdict = 'VERIFIED_SAFE'
        trace.push(
          `✅ Overwhelming community consensus: ${(safeRatio * 100).toFixed(1)}% of submissions confirm this is safe/legitimate.`,
          `The ${scamCount} minority threat report(s) are considered isolated disputes, resolved issues, or false alarms.`,
          `⚠ Minority notice: ${scamCount} historical report(s) flagged this indicator. Exercise standard digital caution.`
        )
        applyVerifiedSafeDeescalation(decision, overlay, trace, safeFindings, approvedDomainFindings)
      }

    // Subcase 3A-2: Clear Scam Majority (e.g. 40 scam vs 1 safe -> scamRatio = 97.6% > 55%)
    } else if (scamRatio > 0.55) {
      overlay.netVerdict = 'CONFIRMED_SCAM'
      trace.push(
        `🔴 Threat consensus established: ${(scamRatio * 100).toFixed(1)}% of reports confirm active scam/fraud.`,
        `The ${safeCount} safe report(s) are considered outdated, mistaken, or malicious attempts to whitewash the indicator.`,
        `Risk escalated to HIGH (STOP_AND_AVOID).`
      )
      applyScamEscalation(decision, overlay, trace, scamFindings)

    // Subcase 3A-3: Split / Contested Consensus (e.g. 5 vs 5, 2 vs 5, 1 vs 1)
    } else {
      overlay.netVerdict = 'CONFLICTED'
      trace.push(
        `⚠ SPLIT INTELLIGENCE DISPUTE: Submissions are divided (${scamCount} threat vs ${safeCount} safe). Neither side has sufficient consensus.`,
        `🛡️ Fail-Closed Security Policy: The indicator is treated as HIGH RISK until further independent verification.`,
        `Recommendation: Do not interact with this content until community moderators review recent reports.`
      )
      applyScamEscalation(decision, overlay, trace, scamFindings)
    }

  // Scenario 3B: Pure Scam Intelligence (1 or more scam reports, 0 safe reports)
  } else if (scamCount > 0) {
    overlay.netVerdict = 'CONFIRMED_SCAM'
    overlay.consensusRatio = 1.0
    overlay.consensusSummary = `${scamCount} Scam Report(s) (100% Threat Consensus)`
    trace.push(
      `🔴 Confirmed Threat Intelligence: ${scamCount} report(s) verified as malicious by community moderators (Confidence: ${(scamConfidence * 100).toFixed(0)}%).`
    )
    applyScamEscalation(decision, overlay, trace, scamFindings)

  // Scenario 3C: Pure Safe Intelligence (1 or more safe reports, 0 scam reports)
  } else if (safeCount > 0) {
    overlay.consensusRatio = 1.0
    overlay.consensusSummary = `${safeCount} Safe Report(s) (100% Safe Consensus)`
    trace.push(
      `✅ Verified Community Intelligence: ${safeCount} report(s) verified this content/domain as legitimate or a false alarm.`
    )

    if (hasCriticalRuleThreat) {
      applyBehavioralImpersonationOverride(decision, overlay, trace, criticalRuleFinding, officialOrg)
    } else {
      overlay.netVerdict = 'VERIFIED_SAFE'
      applyVerifiedSafeDeescalation(decision, overlay, trace, safeFindings, approvedDomainFindings)
    }
  }

  return { decision, intelligenceOverlay: overlay }
}

// ─── Reconciliation Action Helpers ───────────────────────────────────────────

function applyScamEscalation(decision, overlay, trace, scamFindings) {
  const previousBand = decision.riskBand
  decision.riskBand = 'HIGH'
  decision.recommendation = 'STOP_AND_AVOID'

  if (!decision.safeActions.some((a) => a.includes('Do not click, pay, reply, or share credentials.'))) {
    decision.safeActions.unshift('Do not click, pay, reply, or share credentials.')
  }

  const sampleCategories = [...new Set(scamFindings.map((f) => f.category))].filter(Boolean)
  if (sampleCategories.length) {
    trace.push(`Threat classification: ${sampleCategories.join(', ')}.`)
  }

  if (previousBand !== 'HIGH') {
    trace.push(`Risk band escalated from ${previousBand} to HIGH based on verified threat intelligence.`)
  }
}

function applyVerifiedSafeDeescalation(decision, overlay, trace, safeFindings, approvedDomainFindings) {
  const hasApprovedDomain = approvedDomainFindings.length > 0
  const sourceTypes = new Set(safeFindings.map((f) => f.source))

  if (hasApprovedDomain || sourceTypes.size > 1) {
    trace.push(`Multi-source validation: Cross-verified by both community report consensus and official registry.`)
    overlay.safeConfidence = Math.min(overlay.safeConfidence * 1.05, 1.0)
  }

  decision.riskBand = 'LOW'
  decision.recommendation = 'VERIFIED_SAFE'
  decision.safeActions = [
    'This content/domain has been verified as legitimate by community moderators and threat intelligence.',
    'Standard digital hygiene still applies — always verify critical financial or credential requests independently.',
  ]
  trace.push(
    `Risk de-escalated to LOW. Verdict set to VERIFIED_SAFE.`,
    `A verified trust badge will be presented to the user.`
  )
}

function applyBehavioralImpersonationOverride(decision, overlay, trace, criticalFinding, officialOrg) {
  overlay.netVerdict = 'POSSIBLE_IMPERSONATION'
  overlay.behavioralOverride = true
  overlay.scamConfidence = Math.max(overlay.scamConfidence, 0.95)
  decision.riskBand = 'HIGH'
  decision.recommendation = 'STOP_AND_AVOID'

  const entityLabel = officialOrg || 'the reported organization'
  decision.safeActions = [
    `CRITICAL WARNING: This message demands credentials or advance payment while referencing ${entityLabel}. Legitimate organizations will never ask for OTPs or instant cash transfers via text message.`,
    `Do not share your OTP, PIN, password, or send funds. Verify directly through official corporate telephone directories.`,
  ]

  trace.push(
    `⚠ CRITICAL BEHAVIORAL OVERRIDE: The message contains severe scam indicators (${criticalFinding.category}: ${criticalFinding.canonicalSignal}).`,
    `Even though community reports or directory entries exist for this indicator, safe intelligence CANNOT override active credential or payment harvesting.`,
    `This pattern matches domain impersonation and credential phishing campaigns. Risk escalated to HIGH.`
  )
}

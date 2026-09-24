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
 * @property {'CONFIRMED_SCAM' | 'SUSPICIOUS_INDICATOR' | 'VERIFIED_SAFE' | 'CONFLICTED' | 'OFFICIAL_ENTITY' | 'OFFICIAL_ENTITY_WITH_CAUTION' | 'GLOBAL_PLATFORM_WITH_CAUTION' | 'POSSIBLE_IMPERSONATION' | 'NO_INTEL'} netVerdict
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
export function reconcileDecision(decision, verifiedFindings = [], context = {}) {
  const trace = []
  const approvedDomainFindings = (decision.findings || []).filter((f) => f.canonicalSignal === 'approved_domain')
  const hasDirectoryMatch = approvedDomainFindings.length > 0
  const officialOrg = hasDirectoryMatch ? approvedDomainFindings[0].organization || approvedDomainFindings[0].evidence : null

  // 1. Bucket verified intelligence findings and aggregate report counts
  const scamFindings = []
  const safeFindings = []

  for (const finding of verifiedFindings) {
    const bucket = classifySignal(finding)
    if (bucket === 'SCAM') scamFindings.push(finding)
    else if (bucket === 'SAFE') safeFindings.push(finding)
  }

  const scamCount = scamFindings.reduce((acc, f) => acc + (Number(f.reportCount) || 1), 0)
  const safeCount = safeFindings.reduce((acc, f) => acc + (Number(f.reportCount) || 1), 0)
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
    (f) => f.canonicalSignal === 'credential_request' || 
           f.canonicalSignal === 'advance_payment' || 
           f.canonicalSignal === 'credential_harvesting_intent' ||
           f.canonicalSignal === 'payment_demand' ||
           f.canonicalSignal === 'otp_theft'
  ) || (context?.messageBody && /otp|pin|password|credential|credit card|cvv|bank account/i.test(context.messageBody) ? {
    canonicalSignal: 'credential_request',
    category: 'Social engineering',
    source: 'RULE',
    strength: 1.0,
  } : null)
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
    globalDomain: null,
    behavioralOverride: false,
    reconciliationTrace: trace,
  }

  // ── CASE 1: No Verified Findings & No Official Directory Match ─────────────
  if (!totalVerified && !hasDirectoryMatch) {
    trace.push('No verified intelligence reports or official directory matches found.')
    trace.push(`Base rule engine assessment preserved (Risk: ${decision.riskBand}, Policy: ${decision.policyVersion || 'v1'}).`)
    return { decision, intelligenceOverlay: overlay }
  }

  // ── CASE 2: Official Directory Match (Authoritative National Registry) ─────
  if (hasDirectoryMatch) {
    trace.push(`🏛️ Official Directory Match: Domain is verified as the official digital property of "${officialOrg}".`)

    if (hasCriticalRuleThreat) {
      // Impersonation attack: official domain quoted in message asking for OTP/money
      applyBehavioralImpersonationOverride(decision, overlay, trace, criticalRuleFinding, officialOrg)
      overlay.consensusSummary = `Official Registry (${officialOrg}) with Threat Override`
      return { decision, intelligenceOverlay: overlay }
    }

    if (scamCount === 0) {
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
      overlay.consensusSummary = `Official Registry (${officialOrg})`
      return { decision, intelligenceOverlay: overlay }
    }

    if (scamCount <= 1) {
      // 1 isolated citizen report against official government/bank directory
      overlay.netVerdict = 'OFFICIAL_ENTITY_WITH_CAUTION'
      decision.riskBand = 'LOW'
      decision.recommendation = 'PROCEED_CAUTIOUSLY'
      decision.safeActions = [
        `This domain is verified in the official Sri Lankan national registry for ${officialOrg}.`,
        `1 citizen report was filed against this domain, noted as a likely dispute or false report. Exercise standard digital caution.`,
      ]
      trace.push(
        `🏛️ Official National Registry Entity: Domain is verified as "${officialOrg}".`,
        `⚠ 1 citizen report flagged this domain. The official national registry possesses authoritative cryptographic and legal status.`,
        `Official identity preserved with caution note. Recommendation set to PROCEED_CAUTIOUSLY.`
      )
      overlay.consensusSummary = `Official Registry (${officialOrg}) with 1 Caution Report`
      return { decision, intelligenceOverlay: overlay }
    }

    // scamCount >= 2 on an official domain -> potential infrastructure compromise or severe dispute
    overlay.netVerdict = 'CONFLICTED'
    overlay.consensusSummary = `${scamCount} Scam Reports vs Official Registry (${officialOrg})`
    trace.push(
      `⚠ CRITICAL ALERT: Official domain "${officialOrg}" has ${scamCount} active threat reports on file.`,
      `Infrastructure may be experiencing an active breach, compromised subdomain, or spoofed campaign.`,
      `🛡️ Fail-Closed Security Policy: Risk escalated to HIGH (STOP_AND_AVOID) until verified by security analysts.`
    )
    applyScamEscalation(decision, overlay, trace, scamFindings)
    return { decision, intelligenceOverlay: overlay }
  }

  // ── CASE 2B: Global Trusted Domain Match (Tranco Top-1M Global Platforms) ────
  const globalDomainFindings = (decision.findings || []).filter((f) => f.canonicalSignal === 'known_global_domain')
  const hasGlobalDomainMatch = globalDomainFindings.length > 0

  if (hasGlobalDomainMatch) {
    const globalDomainName = globalDomainFindings[0]?.meta?.domain || globalDomainFindings[0]?.domain || null
    overlay.globalDomain = globalDomainName
    trace.push(`🌐 Global Domain Match: Domain is verified as a top global service provider (Tranco Top-1M).`)

    if (hasCriticalRuleThreat) {
      applyBehavioralImpersonationOverride(decision, overlay, trace, criticalRuleFinding, globalDomainName || 'Global Service Provider')
      overlay.consensusSummary = `Global Platform with Threat Override`
      return { decision, intelligenceOverlay: overlay }
    }

    if (scamCount <= 1) {
      // 0 or 1 crowd report against a top global domain (e.g. facebook.com, google.com)
      overlay.netVerdict = 'GLOBAL_PLATFORM_WITH_CAUTION'
      decision.riskBand = 'LOW'
      decision.recommendation = 'PROCEED_CAUTIOUSLY'
      decision.safeActions = [
        `This domain is a verified top global service provider.`,
        scamCount === 1
          ? `1 citizen report was logged against this domain. Citizens often report legitimate platforms when encountering scam posts, phishing ads, or third-party impersonators hosted on them. The domain itself is legitimate.`
          : `Always verify that you are interacting with authentic accounts or official pages on this platform.`,
      ]
      trace.push(
        `🌐 Global Platform Protection: Domain possesses verified global reputation.`,
        scamCount === 1
          ? `⚠ 1 citizen report is on file. Disambiguation applied: Flagged as likely third-party platform abuse rather than core domain compromise. Risk maintained at LOW (PROCEED_CAUTIOUSLY).`
          : `No threat reports or critical indicators detected. Global platform reputation preserved.`
      )
      overlay.consensusSummary = scamCount === 1 ? `Global Platform with 1 Caution Report` : `Global Platform (Verified)`
      return { decision, intelligenceOverlay: overlay }
    }

    // scamCount >= 2 on a global domain
    if (scamCount > 0 && safeCount > 0) {
      overlay.netVerdict = 'CONFLICTED'
      overlay.consensusSummary = `${scamCount} Scam vs ${safeCount} Safe on Global Platform`
      trace.push(
        `⚠ CONFLICTED THREAT INTELLIGENCE: Global platform has ${scamCount} scam reports and ${safeCount} safe reports.`,
        `🛡️ Fail-Safe Defaults: Risk set to HIGH (VERIFY_INDEPENDENTLY).`
      )
      decision.riskBand = 'HIGH'
      decision.recommendation = 'VERIFY_INDEPENDENTLY'
      return { decision, intelligenceOverlay: overlay }
    }
  }

  // ── CASE 3: Active Community Intelligence Reports Exist (No Directory Match) ───

  // Scenario 3A: Conflicting reports exist (Both Scam and Safe submitted)
  if (scamCount > 0 && safeCount > 0) {
    const scamRatio = scamCount / totalVerified
    const safeRatio = safeCount / totalVerified
    overlay.consensusRatio = Math.max(scamRatio, safeRatio)
    overlay.consensusSummary = `${safeCount} Safe vs ${scamCount} Scam (${(overlay.consensusRatio * 100).toFixed(1)}% ${scamRatio > safeRatio ? 'Scam' : 'Safe'})`

    trace.push(
      `📊 Community consensus analysis: ${scamCount} scam report(s) vs ${safeCount} safe report(s) (Total: ${totalVerified}).`
    )

    if (hasCriticalRuleThreat) {
      applyBehavioralImpersonationOverride(decision, overlay, trace, criticalRuleFinding, officialOrg)
      return { decision, intelligenceOverlay: overlay }
    }

    // A moderator-verified scam indicator can NEVER be overturned by crowd safe votes!
    overlay.netVerdict = 'CONFLICTED'
    decision.riskBand = 'HIGH'
    decision.recommendation = 'VERIFY_INDEPENDENTLY'
    if (!decision.safeActions.some((a) => a.includes('Verify independently before clicking, paying, or replying.'))) {
      decision.safeActions.unshift('Verify independently before clicking, paying, or replying.')
    }
    trace.push(
      `⚠ CONFLICTED THREAT INTELLIGENCE: Submissions contain conflicting assessments (${scamCount} threat vs ${safeCount} safe).`,
      `🛡️ Fail-Safe Defaults (Saltzer & Schroeder 1975): Verified threat evidence cannot be overridden by unverified crowd votes.`,
      `In digital fraud prevention, threat evidence takes precedence to prevent whitewashing attacks and protect citizens from financial loss.`,
      `Risk set to HIGH. Recommendation: VERIFY_INDEPENDENTLY (independent verification recommended).`
    )

  // Scenario 3B: Pure Scam Intelligence (1 or more scam reports, 0 safe reports)
  } else if (scamCount > 0) {
    overlay.consensusRatio = 1.0
    overlay.consensusSummary = `${scamCount} Threat Report(s) (${(scamConfidence * 100).toFixed(0)}% Confidence)`

    // Gated by effective confidence:
    // C_effective >= 0.85 -> CONFIRMED_SCAM (HIGH risk, STOP_AND_AVOID)
    // C_effective < 0.85  -> SUSPICIOUS_INDICATOR (MEDIUM risk, VERIFY_INDEPENDENTLY)
    if (scamConfidence >= 0.85) {
      overlay.netVerdict = 'CONFIRMED_SCAM'
      trace.push(
        `🔴 Confirmed Threat Intelligence: ${scamCount} report(s) verified as high-confidence threat (Confidence: ${(scamConfidence * 100).toFixed(0)}%).`
      )
      applyScamEscalation(decision, overlay, trace, scamFindings)
    } else {
      overlay.netVerdict = 'SUSPICIOUS_INDICATOR'
      decision.riskBand = 'MEDIUM'
      decision.recommendation = 'VERIFY_INDEPENDENTLY'
      if (!decision.safeActions.some((a) => a.includes('Verify the sender or domain through independent channels'))) {
        decision.safeActions.unshift('Verify the sender or domain through independent channels before engaging.')
      }
      trace.push(
        `⚠ Suspicious Threat Indicator: ${scamCount} report(s) flagged with moderate certainty (Confidence: ${(scamConfidence * 100).toFixed(0)}%).`,
        `Evidence meets suspicious threshold but requires further corroboration or moderator confirmation to escalate to HIGH.`,
        `Risk set to MEDIUM. Recommendation: VERIFY_INDEPENDENTLY.`
      )
    }

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
    `⚠ CRITICAL IMPERSONATION ALERT: Although the domain belongs to or references "${entityLabel}", the message contains high-risk threat indicators (${criticalFinding.category || 'High-Risk Threat'}: ${criticalFinding.canonicalSignal}).`,
    `Even though community reports or directory entries exist for this indicator, safe intelligence CANNOT override active credential or payment harvesting.`,
    `Behavioral override active: Safe intelligence cannot override active credential theft.`,
    `This pattern matches domain impersonation and credential phishing campaigns. Risk escalated to HIGH.`
  )
}

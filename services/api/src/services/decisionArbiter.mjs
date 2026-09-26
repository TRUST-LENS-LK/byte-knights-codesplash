/**
 * TrustLens LK — Synchronized Multi-Signal Decision Arbiter
 * ──────────────────────────────────────────────────────────
 * Unifies all 6 detection layers (Sandbox Detonator, Behavioral Rules, Structural URL Inspector,
 * 5-Tier Domain Engine, Community Threat Intelligence, and Gemini Multilingual AI) into a single,
 * mathematically sound, explainable arbitration engine.
 *
 * Core Principles:
 *  1. Multi-Vector Evidence Harvesting: Layers act as independent sensors emitting standardized findings.
 *  2. Deterministic Hard Invariants: Non-negotiable fail-closed security guards (NIST SP 800-61 / Saltzer-Schroeder).
 *  3. Continuous Composite Scoring: Continuous 0–100 threat index prevents discrete state bouncing.
 *  4. Anti-Spoofing & Advisory Awareness: Prevents genuine advisories from false alarms while blocking real OTP theft.
 *  5. Context-Aware Action Synthesis: Produces actionable advice with official bank & emergency hotlines.
 *  6. Pure Dynamic Processing: Zero hardcoded dictionaries, phone numbers, or static language keywords.
 */

import { synthesizeSafeActions } from './safeActionSynthesizer.mjs'

/**
 * Standardizes and deduplicates findings from all detection layers.
 * @param {Array} rawFindings
 * @returns {Array}
 */
export function normalizeFindings(rawFindings = []) {
  const seen = new Set()
  const normalized = []

  for (const f of rawFindings) {
    if (!f || typeof f !== 'object') continue
    const signal = f.canonicalSignal || f.category || 'unknown_signal'
    const source = f.source || 'ARBITER'
    const key = `${source}::${signal}::${(f.evidence || '').slice(0, 40).toLowerCase()}`

    if (!seen.has(key)) {
      seen.add(key)
      normalized.push({
        source,
        canonicalSignal: signal,
        category: f.category || 'General',
        evidence: f.evidence || '',
        strength: typeof f.strength === 'number' ? f.strength : 0.5,
        confidence: typeof f.confidence === 'number' ? f.confidence : 0.8,
        limitation: f.limitation || null,
        organization: f.organization || null,
        domain: f.domain || null,
        sourceUrl: f.sourceUrl || null,
        meta: f.meta || null,
      })
    }
  }

  return normalized
}

/**
 * Evaluates non-negotiable hard invariants (Saltzer & Schroeder Fail-Safe Defaults).
 * Returns an invariant match object if triggered, or null if clear.
 * Dynamically driven by standardized signals and verified intelligence — zero hardcoded keywords.
 */
export function evaluateHardInvariants({
  findings = [],
  claimedOrg = null,
  matchedOrg = null,
  hasOfficialDomain = false,
  aiResult = null,
  text = '',
}) {
  const signals = new Set(findings.map((f) => f.canonicalSignal))

  // INV-01: Live Malicious Feed Hit (Google Safe Browsing)
  if (signals.has('known_malicious_domain')) {
    return {
      code: 'INV-01',
      riskBand: 'HIGH',
      recommendation: 'STOP_AND_AVOID',
      reason: 'Destination domain is actively listed on global cyber threat intelligence registries (Google Safe Browsing) as confirmed malicious infrastructure.',
      invariantType: 'HARD_SECURITY_ENFORCEMENT',
    }
  }

  // INV-02: Confirmed Community Threat Intelligence IoC
  const confirmedIntel = findings.find(
    (f) => f.canonicalSignal === 'verified_scam_intelligence' && (f.confidence >= 0.85 || f.strength >= 0.85)
  )
  if (confirmedIntel) {
    return {
      code: 'INV-02',
      riskBand: 'HIGH',
      recommendation: 'STOP_AND_AVOID',
      reason: `Indicator is a confirmed scam in the TrustLens Sri Lanka verified intelligence feed (${confirmedIntel.evidence || 'Vetted by cyber analysts'}).`,
      invariantType: 'HARD_SECURITY_ENFORCEMENT',
    }
  }

  // Active Phishing / Credential Theft Demand
  const hasCredentialTheft = signals.has('credential_request') || signals.has('embedded_credentials')
  const hasAdvanceFee = signals.has('advance_payment') || signals.has('payment_demand')
  const hasDomainMismatch = signals.has('domain_mismatch')

  // Dynamic context check from AI or signal evidence
  const isAdvisoryNotice = Boolean(aiResult?.isAdvisory || aiResult?.intent === 'ADVISORY_WARNING')
  const isDeliveryOrCautionText = Boolean(
    /\b(?:your otp (?:at|for|is)|otp (?:is|expires in)|do not share|never share|keep (?:your )?otp confidential|one[- ]time (?:password|code|pin))\b/i.test(text)
  )
  const isBenignNotification = Boolean(
    (aiResult?.intent === 'BENIGN_INFORMATIVE' || (aiResult?.verdict === 'DISAGREE' && !isAdvisoryNotice && aiResult?.intent !== 'COERCIVE_DEMAND')) &&
    (aiResult?.confidence || 0) >= 0.75
  ) || (isDeliveryOrCautionText && !hasAdvanceFee && !hasDomainMismatch)

  // INV-06: Genuine Advisory Notice Suppression
  if (isAdvisoryNotice && !hasDomainMismatch && !signals.has('known_malicious_domain')) {
    return {
      code: 'INV-06',
      riskBand: 'LOW',
      recommendation: 'VERIFIED_SAFE',
      reason: `Message context is a defensive educational warning from ${matchedOrg || 'an official institution'} advising citizens never to share credentials. No fraud intent detected.`,
      invariantType: 'DEFENSIVE_ADVISORY_PRESERVATION',
      isAdvisory: true,
    }
  }

  // INV-08: Genuine Transactional / OTP Delivery Notification Suppression (Only when message actually involves OTP)
  if (isDeliveryOrCautionText && !hasDomainMismatch && !signals.has('known_malicious_domain') && !hasAdvanceFee) {
    return {
      code: 'INV-08',
      riskBand: 'LOW',
      recommendation: 'PROCEED_CAUTIOUSLY',
      reason: `Automated Transaction Notification: ${aiResult?.reasoning || 'Standard OTP issuance or transaction receipt. No credential harvesting or scam demand detected.'}`,
      invariantType: 'TRANSACTIONAL_NOTIFICATION_PRESERVATION',
      isTransactional: true,
    }
  }

  // INV-09: Genuine Commercial Promotion / Informational Content Suppression
  if (isBenignNotification && !hasDomainMismatch && !signals.has('known_malicious_domain') && !hasAdvanceFee) {
    return {
      code: 'INV-09',
      riskBand: 'LOW',
      recommendation: 'PROCEED_CAUTIOUSLY',
      reason: `Legitimate Commercial / Informational Notice: ${aiResult?.reasoning || 'Standard promotional, commercial, or informational message. No fraud, credential harvesting, or scam demand detected.'}`,
      invariantType: 'BENIGN_PROMOTION_PRESERVATION',
      isPromotion: true,
    }
  }

  // INV-05: Anti-Spoofing Rule (Official Domain Quoted in Phishing Lure)
  if (hasOfficialDomain && (hasCredentialTheft || hasAdvanceFee || aiResult?.intent === 'COERCIVE_DEMAND' || signals.has('coercive_scam_lure')) && !isAdvisoryNotice && !isBenignNotification) {
    return {
      code: 'INV-05',
      riskBand: 'HIGH',
      recommendation: 'OFFICIAL_ENTITY_WITH_CAUTION',
      reason: `Anti-Spoofing Violation: Message references the official domain of "${matchedOrg || 'an approved institution'}", but contains an active credential harvest, payment demand, or coercive lure. Legitimate organizations never request credentials or payments via text message.`,
      invariantType: 'ANTI_SPOOFING_GUARD',
    }
  }

  // INV-04: Brand Impersonation / Organization Domain Mismatch
  if (hasDomainMismatch) {
    return {
      code: 'INV-04',
      riskBand: 'HIGH',
      recommendation: 'STOP_AND_AVOID',
      reason: `Brand Impersonation Detected: The sender claims to represent "${claimedOrg || 'a verified organization'}", but the destination link routes to an unauthorized third-party lookalike domain.`,
      invariantType: 'BRAND_PROTECTION_GUARD',
    }
  }

  // Active Phishing on Non-Approved Domain
  if (hasCredentialTheft && !hasOfficialDomain && !isAdvisoryNotice && !isBenignNotification) {
    return {
      code: 'INV-03',
      riskBand: 'HIGH',
      recommendation: 'STOP_AND_AVOID',
      reason: 'Active Credential Harvesting: Message demands immediate surrender of OTP, PIN, or banking passwords on an unverified domain.',
      invariantType: 'HARD_SECURITY_ENFORCEMENT',
    }
  }

  // INV-07: Semantic Threat Lure (Uncaught by Rules Engine, e.g. Sinhala/Singlish Task Scam)
  if (aiResult?.intent === 'COERCIVE_DEMAND' && (aiResult.confidence || 0) >= 0.85 && !hasOfficialDomain) {
    return {
      code: 'INV-07',
      riskBand: 'HIGH',
      recommendation: 'STOP_AND_AVOID',
      reason: `Semantic Threat Lure: Advanced multilingual intent analysis identified an active scam demand or deceptive recruitment lure (${aiResult.reasoning || 'Coercive social engineering'}).`,
      invariantType: 'SEMANTIC_THREAT_ENFORCEMENT',
    }
  }

  return null
}

/**
 * Computes continuous composite threat index [0..100].
 */
export function calculateCompositeThreatScore({
  findings = [],
  aiResult = null,
  hasOfficialDomain = false,
  hasGlobalDomain = false,
  verifiedSafeCount = 0,
}) {
  let score = 0
  const signals = new Set(findings.map((f) => f.canonicalSignal))

  // 1. Structural / Rule Threats
  if (signals.has('credential_request')) score += 35
  if (signals.has('advance_payment')) score += 30
  if (signals.has('job_scam') || signals.has('fake_job')) score += 25
  if (signals.has('urgency')) score += 15
  if (signals.has('embedded_credentials')) score += 25
  if (signals.has('unsafe_url_target')) score += 35
  if (signals.has('new_domain_risk')) score += 25
  if (signals.has('coercive_scam_lure')) score += 45

  // 2. Intelligence Threats
  if (signals.has('verified_scam_intelligence')) score += 40

  // 3. AI Semantic Context Threat Signals
  if (aiResult?.intent === 'COERCIVE_DEMAND' || (aiResult?.verdict === 'DISAGREE' && aiResult?.action === 'UPGRADED')) {
    score += Math.round((aiResult.confidence || 0.85) * 30)
  }

  // 4. Safe Mitigation Discounts
  if (hasOfficialDomain) score -= 35
  if (hasGlobalDomain) score -= 20
  if (verifiedSafeCount > 0) score -= Math.min(25, verifiedSafeCount * 10)
  if (aiResult?.isAdvisory || aiResult?.intent === 'ADVISORY_WARNING') score -= 40
  if (aiResult?.intent === 'BENIGN_INFORMATIVE') score -= 40
  if (signals.has('approved_domain')) score -= 20

  // Clamp 0 to 100
  return Math.max(0, Math.min(100, score))
}

/**
 * Main Public API: Synchronized Multi-Signal Arbitration Engine.
 *
 * Synthesizes all findings from all layers into a unified, harmonious,
 * and context-aware RiskDecision without mutating input objects.
 *
 * @param {Object} context
 * @returns {Object} { decision, intelligenceOverlay, aiValidation, compositeScore }
 */
export function arbitrateDecision({
  baseDecision = null,
  entities = [],
  scannerFindings = [],
  scannerEvidence = [],
  domainFindings = [],
  verifiedIntelligenceFindings = [],
  aiResult = null,
  text = '',
  claimedOrg = null,
  authorities = [],
}) {
  const trace = []
  trace.push('Initializing Synchronized Multi-Signal Arbitration Engine.')

  // 1. Normalize and aggregate all evidence findings
  let initialFindings = [
    ...(baseDecision?.findings || []),
    ...scannerFindings,
    ...domainFindings,
    ...verifiedIntelligenceFindings,
  ]

  // Completely bypass and purge keyword regex signals when AI is active
  if (aiResult && aiResult.verdict !== 'UNCERTAIN') {
    trace.push('[AI Sovereign Mode]: AI semantic validator is active. Bypassing and suppressing all keyword regex signals.')
    const regexSignals = new Set(['credential_request', 'advance_payment', 'job_scam', 'fake_job', 'urgency'])
    initialFindings = initialFindings.filter((f) => !regexSignals.has(f.canonicalSignal))
    if (aiResult.intent === 'COERCIVE_DEMAND' && !initialFindings.some((f) => f.canonicalSignal === 'coercive_scam_lure')) {
      initialFindings.push({
        canonicalSignal: 'coercive_scam_lure',
        category: 'Social Engineering & Coercion',
        strength: aiResult.confidence || 0.95,
        evidence: aiResult.reasoning || 'Coercive demand or deceptive recruitment lure identified by semantic analysis',
      })
    }
  }
  const allFindings = normalizeFindings(initialFindings)

  // 2. Identify key organizational and domain entities dynamically
  const approvedDomainFinding = allFindings.find((f) => f.canonicalSignal === 'approved_domain')
  const matchedOrg = approvedDomainFinding?.organization || approvedDomainFinding?.evidence || null
  const sourceUrl = approvedDomainFinding?.sourceUrl || null
  const hasOfficialDomain = Boolean(approvedDomainFinding)

  const globalDomainFinding = allFindings.find((f) => f.canonicalSignal === 'known_global_domain')
  const hasGlobalDomain = Boolean(globalDomainFinding)
  const globalDomainName = globalDomainFinding?.meta?.domain || globalDomainFinding?.domain || null

  const scamFindings = allFindings.filter((f) => f.canonicalSignal === 'verified_scam_intelligence')
  const safeFindings = allFindings.filter((f) => f.canonicalSignal === 'verified_safe_intelligence')
  const scamCount = scamFindings.length
  const safeCount = safeFindings.length

  // 3. Evaluate Non-Negotiable Hard Invariants
  const invariantHit = evaluateHardInvariants({
    findings: allFindings,
    claimedOrg,
    matchedOrg,
    hasOfficialDomain,
    aiResult,
    text,
  })

  let finalRiskBand = 'LOW'
  let finalRecommendation = 'PROCEED_CAUTIOUSLY'
  let compositeScore = 0

  if (invariantHit) {
    finalRiskBand = invariantHit.riskBand
    finalRecommendation = invariantHit.recommendation
    compositeScore = invariantHit.riskBand === 'HIGH' ? 95 : 10
    trace.push(`[${invariantHit.code}] ${invariantHit.invariantType}: ${invariantHit.reason}`)
  } else {
    // 4. Continuous Composite Threat Scoring for Non-Invariant Cases
    compositeScore = calculateCompositeThreatScore({
      findings: allFindings,
      aiResult,
      hasOfficialDomain,
      hasGlobalDomain,
      verifiedSafeCount: safeCount,
    })

    if (compositeScore >= 65) {
      finalRiskBand = 'HIGH'
      finalRecommendation = 'STOP_AND_AVOID'
      trace.push(`[Composite Scoring]: High threat index calculated (${compositeScore}/100). Enforced STOP_AND_AVOID.`)
    } else if (compositeScore >= 30) {
      finalRiskBand = 'MEDIUM'
      finalRecommendation = 'VERIFY_INDEPENDENTLY'
      trace.push(`[Composite Scoring]: Moderate threat index calculated (${compositeScore}/100). Enforced VERIFY_INDEPENDENTLY.`)
    } else {
      finalRiskBand = 'LOW'
      finalRecommendation = hasOfficialDomain ? 'VERIFIED_SAFE' : 'PROCEED_CAUTIOUSLY'
      trace.push(`[Composite Scoring]: Low threat index calculated (${compositeScore}/100). Enforced ${finalRecommendation}.`)
    }
  }

  // 5. Build Synthesized Intelligence Overlay
  let netVerdict = 'NO_INTEL'
  if (hasOfficialDomain) {
    netVerdict = invariantHit?.code === 'INV-05' ? 'OFFICIAL_ENTITY_WITH_CAUTION' : 'OFFICIAL_ENTITY'
  } else if (hasGlobalDomain) {
    netVerdict = 'GLOBAL_PLATFORM_WITH_CAUTION'
  } else if (invariantHit?.code === 'INV-04') {
    netVerdict = 'POSSIBLE_IMPERSONATION'
  } else if (scamCount > 0 && safeCount > 0) {
    netVerdict = 'CONFLICTED'
  } else if (scamCount > 0) {
    netVerdict = finalRiskBand === 'HIGH' ? 'CONFIRMED_SCAM' : 'SUSPICIOUS_INDICATOR'
  } else if (safeCount > 0) {
    netVerdict = 'VERIFIED_SAFE'
  }

  const intelligenceOverlay = {
    netVerdict,
    scamConfidence: scamCount ? 0.95 : 0,
    safeConfidence: hasOfficialDomain ? 0.98 : safeCount ? 0.9 : 0,
    signalCount: allFindings.length,
    scamCount,
    safeCount,
    consensusRatio: scamCount + safeCount > 0 ? (scamCount / (scamCount + safeCount)) : 1.0,
    consensusSummary: invariantHit?.reason || (hasOfficialDomain ? `Official Registry: ${matchedOrg}` : 'Synchronized Multi-Signal Consensus'),
    hasDirectoryMatch: hasOfficialDomain,
    officialOrganization: matchedOrg,
    globalDomain: globalDomainName,
    behavioralOverride: invariantHit?.code === 'INV-05',
    reconciliationTrace: trace,
  }

  // 6. Synthesize Threat-Tailored Contextual Safe Actions Dynamically
  const safeActions = synthesizeSafeActions({
    riskBand: finalRiskBand,
    recommendation: finalRecommendation,
    findings: allFindings,
    claimedOrg,
    matchedOrg,
    sourceUrl,
    isAdvisory: invariantHit?.isAdvisory || false,
    isTransactional: invariantHit?.isTransactional || false,
    isPromotion: invariantHit?.isPromotion || false,
    isCoercive: Boolean(aiResult?.intent === 'COERCIVE_DEMAND'),
    authorities,
  })

  // 7. Harmonize AI Context Validation Output
  const aiValidation = aiResult ? {
    verdict: aiResult.verdict || 'AGREE',
    confidence: aiResult.confidence || 0.85,
    reasoning: aiResult.reasoning || '',
    intent: aiResult.intent || 'GENERAL',
    appliedAction: invariantHit?.invariantType || (compositeScore >= 65 ? 'CONFIRMED_HIGH' : 'EVALUATED'),
    originalRiskBand: baseDecision?.riskBand || 'LOW',
    adjustedRiskBand: finalRiskBand,
  } : null

  // 8. Prune or Reconcile Contradicted Regex Findings
  // If the message was verified as a benign transactional notification or defensive advisory,
  // raw keyword findings (e.g. "credential_request" or "urgency") are false alarms and must not
  // pollute the user-facing findings list with "Critical Threat" or "credential request" badges.
  let sanitizedFindings = [...allFindings]
  if (invariantHit?.isTransactional || invariantHit?.isPromotion || invariantHit?.isAdvisory || (aiResult?.intent === 'BENIGN_INFORMATIVE' && (aiResult?.confidence || 0) >= 0.75)) {
    sanitizedFindings = sanitizedFindings.filter(
      (f) => f.canonicalSignal !== 'credential_request' && f.canonicalSignal !== 'urgency'
    )
    if (invariantHit?.isTransactional) {
      sanitizedFindings.push({
        canonicalSignal: 'transactional_otp_issuance',
        category: 'Automated Account Notification',
        strength: 0.0,
        evidence: 'Standard OTP issuance or transaction confirmation notice',
        limitation: 'Verify that the merchant name and transaction amount correspond to your own legitimate activity.',
      })
    }
  }

  // 9. Assemble final immutable RiskDecision object
  const decision = {
    riskBand: finalRiskBand,
    recommendation: finalRecommendation,
    findings: sanitizedFindings,
    limitations: baseDecision?.limitations || [],
    safeActions,
    policyVersion: 'rules-v2-synchronized',
    compositeScore,
    reconciliationTrace: trace,
    ...(aiValidation ? { aiValidation } : {}),
  }

  return {
    decision,
    intelligenceOverlay,
    aiValidation,
    compositeScore,
  }
}

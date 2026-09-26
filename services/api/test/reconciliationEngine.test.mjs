import test from 'node:test'
import assert from 'node:assert/strict'
import { reconcileDecision } from '../src/services/reconcileIntelligence.mjs'
import {
  extractDomainVariants,
  getIndicatorIntelligenceContext,
  submitReport,
  processModerationReview,
} from '../src/services/reportingService.mjs'

test('reconcileDecision: Scenario 1 — Pure scam intelligence escalates to HIGH (CONFIRMED_SCAM)', () => {
  const baseDecision = {
    riskBand: 'LOW',
    recommendation: 'PROCEED_CAUTIOUSLY',
    findings: [],
    safeActions: ['Standard caution.'],
  }
  const verifiedFindings = [
    {
      canonicalSignal: 'verified_scam_intelligence',
      category: 'Banking Phishing',
      confidence: 1.0,
      source: 'APPROVED_REPORT',
      strength: 1.0,
    },
  ]

  const { decision, intelligenceOverlay } = reconcileDecision(baseDecision, verifiedFindings)
  assert.equal(decision.riskBand, 'HIGH')
  assert.equal(decision.recommendation, 'STOP_AND_AVOID')
  assert.equal(intelligenceOverlay.netVerdict, 'CONFIRMED_SCAM')
  assert.equal(intelligenceOverlay.scamCount, 1)
  assert.equal(intelligenceOverlay.safeCount, 0)
})

test('reconcileDecision: Scenario 2 — Pure safe intelligence de-escalates to LOW (VERIFIED_SAFE)', () => {
  const baseDecision = {
    riskBand: 'MEDIUM',
    recommendation: 'VERIFY_INDEPENDENTLY',
    findings: [
      { canonicalSignal: 'urgency', category: 'Social engineering', source: 'RULE', strength: 0.55 },
    ],
    safeActions: ['Verify sender.'],
  }
  const verifiedFindings = [
    {
      canonicalSignal: 'verified_safe_intelligence',
      category: 'False Alarm',
      confidence: 0.95,
      source: 'APPROVED_REPORT',
      strength: 0.0,
    },
  ]

  const { decision, intelligenceOverlay } = reconcileDecision(baseDecision, verifiedFindings)
  assert.equal(decision.riskBand, 'LOW')
  assert.equal(decision.recommendation, 'VERIFIED_SAFE')
  assert.equal(intelligenceOverlay.netVerdict, 'VERIFIED_SAFE')
  assert.equal(intelligenceOverlay.safeCount, 1)
  assert.equal(intelligenceOverlay.scamCount, 0)
})

test('reconcileDecision: Scenario 3 — 1 scam vs 40 safe reports yields CONFLICTED under fail-safe defaults', () => {
  const baseDecision = {
    riskBand: 'LOW',
    recommendation: 'PROCEED_CAUTIOUSLY',
    findings: [],
    safeActions: ['Verify independently.'],
  }
  const verifiedFindings = [
    { canonicalSignal: 'verified_scam_intelligence', confidence: 0.9, source: 'APPROVED_REPORT', strength: 1.0 },
    ...Array(40).fill(null).map(() => ({
      canonicalSignal: 'verified_safe_intelligence',
      confidence: 0.95,
      source: 'APPROVED_REPORT',
      strength: 0.0,
    })),
  ]

  const { decision, intelligenceOverlay } = reconcileDecision(baseDecision, verifiedFindings)
  assert.equal(decision.riskBand, 'HIGH')
  assert.equal(decision.recommendation, 'VERIFY_INDEPENDENTLY')
  assert.equal(intelligenceOverlay.netVerdict, 'CONFLICTED')
  assert.equal(intelligenceOverlay.scamCount, 1)
  assert.equal(intelligenceOverlay.safeCount, 40)
  assert.ok(intelligenceOverlay.consensusSummary.includes('40 Safe vs 1 Scam'))
  assert.ok(intelligenceOverlay.reconciliationTrace.some((line) => line.includes('Saltzer & Schroeder')))
})

test('reconcileDecision: Scenario 4 — 40 scam vs 1 safe report yields CONFLICTED (threat present)', () => {
  const baseDecision = {
    riskBand: 'LOW',
    recommendation: 'PROCEED_CAUTIOUSLY',
    findings: [],
    safeActions: ['Standard caution.'],
  }
  const verifiedFindings = [
    { canonicalSignal: 'verified_safe_intelligence', confidence: 0.9, source: 'APPROVED_REPORT', strength: 0.0 },
    ...Array(40).fill(null).map(() => ({
      canonicalSignal: 'verified_scam_intelligence',
      confidence: 1.0,
      source: 'APPROVED_REPORT',
      strength: 1.0,
    })),
  ]

  const { decision, intelligenceOverlay } = reconcileDecision(baseDecision, verifiedFindings)
  assert.equal(decision.riskBand, 'HIGH')
  assert.equal(decision.recommendation, 'VERIFY_INDEPENDENTLY')
  assert.equal(intelligenceOverlay.netVerdict, 'CONFLICTED')
  assert.equal(intelligenceOverlay.scamCount, 40)
  assert.equal(intelligenceOverlay.safeCount, 1)
})

test('reconcileDecision: Scenario 5 — 5 scam vs 5 safe reports triggers CONFLICTED (fail-closed to HIGH)', () => {
  const baseDecision = {
    riskBand: 'LOW',
    recommendation: 'PROCEED_CAUTIOUSLY',
    findings: [],
    safeActions: ['Verify independently.'],
  }
  const verifiedFindings = [
    ...Array(5).fill(null).map(() => ({
      canonicalSignal: 'verified_scam_intelligence',
      confidence: 0.9,
      source: 'APPROVED_REPORT',
      strength: 1.0,
    })),
    ...Array(5).fill(null).map(() => ({
      canonicalSignal: 'verified_safe_intelligence',
      confidence: 0.9,
      source: 'APPROVED_REPORT',
      strength: 0.0,
    })),
  ]

  const { decision, intelligenceOverlay } = reconcileDecision(baseDecision, verifiedFindings)
  assert.equal(decision.riskBand, 'HIGH')
  assert.equal(decision.recommendation, 'VERIFY_INDEPENDENTLY')
  assert.equal(intelligenceOverlay.netVerdict, 'CONFLICTED')
  assert.equal(intelligenceOverlay.scamCount, 5)
  assert.equal(intelligenceOverlay.safeCount, 5)
  assert.ok(intelligenceOverlay.reconciliationTrace.some((line) => line.includes('Saltzer & Schroeder')))
})

test('reconcileDecision: Scenario 6 — Anti-Spoofing Guard: Official domain + OTP credential theft triggers POSSIBLE_IMPERSONATION (HIGH)', () => {
  const baseDecision = {
    riskBand: 'HIGH',
    recommendation: 'STOP_AND_AVOID',
    findings: [
      {
        canonicalSignal: 'credential_request',
        category: 'Sensitive information',
        source: 'RULE',
        strength: 0.98,
      },
      {
        canonicalSignal: 'approved_domain',
        category: 'Domain verification',
        source: 'DOMAIN_DIRECTORY',
        organization: 'Central Bank of Sri Lanka',
        confidence: 0.95,
      },
    ],
    safeActions: ['Do not send credentials.'],
  }

  const { decision, intelligenceOverlay } = reconcileDecision(baseDecision, [])
  assert.equal(decision.riskBand, 'HIGH')
  assert.equal(decision.recommendation, 'STOP_AND_AVOID')
  assert.equal(intelligenceOverlay.netVerdict, 'POSSIBLE_IMPERSONATION')
  assert.equal(intelligenceOverlay.behavioralOverride, true)
  assert.ok(intelligenceOverlay.reconciliationTrace.some((line) => line.includes('CRITICAL IMPERSONATION ALERT')))
})

test('reconcileDecision: Scenario 7 — Official directory match with 0 reports gives OFFICIAL_ENTITY', () => {
  const baseDecision = {
    riskBand: 'LOW',
    recommendation: 'PROCEED_CAUTIOUSLY',
    findings: [
      {
        canonicalSignal: 'approved_domain',
        category: 'Domain verification',
        source: 'DOMAIN_DIRECTORY',
        organization: 'Commercial Bank of Ceylon',
        confidence: 0.95,
      },
    ],
    safeActions: ['Standard caution.'],
  }

  const { decision, intelligenceOverlay } = reconcileDecision(baseDecision, [])
  assert.equal(decision.riskBand, 'LOW')
  assert.equal(decision.recommendation, 'VERIFIED_SAFE')
  assert.equal(intelligenceOverlay.netVerdict, 'OFFICIAL_ENTITY')
  assert.equal(intelligenceOverlay.officialOrganization, 'Commercial Bank of Ceylon')
})

test('reconcileDecision: Scenario 8 — Asymmetric Risk: 3 safe vs 2 scam reports fails-closed to HIGH (CONFLICTED)', () => {
  const baseDecision = {
    riskBand: 'LOW',
    recommendation: 'PROCEED_CAUTIOUSLY',
    findings: [],
    safeActions: ['Verify independently.'],
  }
  const verifiedFindings = [
    { canonicalSignal: 'verified_scam_intelligence', confidence: 0.9, source: 'APPROVED_REPORT', strength: 1.0, reportCount: 1 },
    { canonicalSignal: 'verified_scam_intelligence', confidence: 0.9, source: 'APPROVED_REPORT', strength: 1.0, reportCount: 1 },
    { canonicalSignal: 'verified_safe_intelligence', confidence: 0.9, source: 'APPROVED_REPORT', strength: 0.0, reportCount: 1 },
    { canonicalSignal: 'verified_safe_intelligence', confidence: 0.9, source: 'APPROVED_REPORT', strength: 0.0, reportCount: 1 },
    { canonicalSignal: 'verified_safe_intelligence', confidence: 0.9, source: 'APPROVED_REPORT', strength: 0.0, reportCount: 1 },
  ]

  const { decision, intelligenceOverlay } = reconcileDecision(baseDecision, verifiedFindings)
  assert.equal(decision.riskBand, 'HIGH')
  assert.equal(decision.recommendation, 'VERIFY_INDEPENDENTLY')
  assert.equal(intelligenceOverlay.netVerdict, 'CONFLICTED')
  assert.equal(intelligenceOverlay.scamCount, 2)
  assert.equal(intelligenceOverlay.safeCount, 3)
  assert.ok(intelligenceOverlay.reconciliationTrace.some((line) => line.includes('Saltzer & Schroeder')))
})

test('reconcileDecision: Scenario 9 — Asymmetric Risk: 1 scam vs 2 safe reports fails-closed to HIGH (CONFLICTED)', () => {
  const baseDecision = {
    riskBand: 'LOW',
    recommendation: 'PROCEED_CAUTIOUSLY',
    findings: [],
    safeActions: ['Standard caution.'],
  }
  const verifiedFindings = [
    { canonicalSignal: 'verified_scam_intelligence', confidence: 0.85, source: 'APPROVED_REPORT', strength: 1.0, reportCount: 1 },
    { canonicalSignal: 'verified_safe_intelligence', confidence: 0.9, source: 'APPROVED_REPORT', strength: 0.0, reportCount: 2 },
  ]

  const { decision, intelligenceOverlay } = reconcileDecision(baseDecision, verifiedFindings)
  assert.equal(decision.riskBand, 'HIGH')
  assert.equal(decision.recommendation, 'VERIFY_INDEPENDENTLY')
  assert.equal(intelligenceOverlay.netVerdict, 'CONFLICTED')
  assert.equal(intelligenceOverlay.scamCount, 1)
  assert.equal(intelligenceOverlay.safeCount, 2)
})

test('reconcileDecision: Scenario 10 — Official Directory match with 1 citizen report preserves entity as OFFICIAL_ENTITY_WITH_CAUTION', () => {
  const baseDecision = {
    riskBand: 'LOW',
    recommendation: 'PROCEED_CAUTIOUSLY',
    findings: [
      {
        canonicalSignal: 'approved_domain',
        category: 'Domain verification',
        source: 'DOMAIN_DIRECTORY',
        organization: 'Ceylon Electricity Board',
        confidence: 0.98,
      },
    ],
    safeActions: ['Standard caution.'],
  }
  const verifiedFindings = [
    { canonicalSignal: 'verified_scam_intelligence', confidence: 0.70, source: 'APPROVED_REPORT', strength: 1.0, reportCount: 1 },
  ]

  const { decision, intelligenceOverlay } = reconcileDecision(baseDecision, verifiedFindings)
  assert.equal(decision.riskBand, 'LOW')
  assert.equal(decision.recommendation, 'PROCEED_CAUTIOUSLY')
  assert.equal(intelligenceOverlay.netVerdict, 'OFFICIAL_ENTITY_WITH_CAUTION')
  assert.equal(intelligenceOverlay.officialOrganization, 'Ceylon Electricity Board')
  assert.ok(intelligenceOverlay.reconciliationTrace.some((line) => line.includes('authoritative cryptographic and legal status')))
})

test('computeEffectiveConfidence: Mathematical Doubt Decay scales correctly', async () => {
  const { computeEffectiveConfidence } = await import('../src/services/reportingService.mjs')

  // 1 report starting at 70%
  assert.equal(computeEffectiveConfidence(0.70, 1), 0.70)
  // 2 reports: doubt 30% * 0.65 = 19.5% -> 80.5%
  assert.equal(computeEffectiveConfidence(0.70, 2), 0.805)
  // 3 reports: doubt 19.5% * 0.65 = 12.675% -> 87.3%
  assert.equal(computeEffectiveConfidence(0.70, 3), 0.873)
  // 5 reports: 94.6%
  assert.equal(computeEffectiveConfidence(0.70, 5), 0.946)

  // 1 report starting at 85%
  assert.equal(computeEffectiveConfidence(0.85, 1), 0.85)
  // 2 reports starting at 85%: doubt 15% * 0.65 = 9.75% -> 90.2%
  assert.equal(computeEffectiveConfidence(0.85, 2), 0.902)

  // Starting at 100% remains 100%
  assert.equal(computeEffectiveConfidence(1.0, 5), 1.0)
})

test('reconcileDecision: Scenario 11 — Single 0.70 Suspicious report yields SUSPICIOUS_INDICATOR (MEDIUM risk, VERIFY_INDEPENDENTLY)', () => {
  const baseDecision = {
    riskBand: 'LOW',
    recommendation: 'PROCEED_CAUTIOUSLY',
    findings: [],
    safeActions: ['Standard caution.'],
  }
  const verifiedFindings = [
    { canonicalSignal: 'verified_scam_intelligence', confidence: 0.70, source: 'APPROVED_REPORT', strength: 1.0, reportCount: 1 },
  ]

  const { decision, intelligenceOverlay } = reconcileDecision(baseDecision, verifiedFindings)
  assert.equal(decision.riskBand, 'MEDIUM')
  assert.equal(decision.recommendation, 'VERIFY_INDEPENDENTLY')
  assert.equal(intelligenceOverlay.netVerdict, 'SUSPICIOUS_INDICATOR')
  assert.equal(intelligenceOverlay.scamCount, 1)
  assert.ok(intelligenceOverlay.reconciliationTrace.some((line) => line.includes('Suspicious Threat Indicator')))
})

test('reconcileDecision: Scenario 12 — Corroborated report (0.873 >= 0.85) escalates to CONFIRMED_SCAM (HIGH risk, STOP_AND_AVOID)', () => {
  const baseDecision = {
    riskBand: 'LOW',
    recommendation: 'PROCEED_CAUTIOUSLY',
    findings: [],
    safeActions: ['Standard caution.'],
  }
  const verifiedFindings = [
    { canonicalSignal: 'verified_scam_intelligence', confidence: 0.873, source: 'APPROVED_REPORT', strength: 1.0, reportCount: 3 },
  ]

  const { decision, intelligenceOverlay } = reconcileDecision(baseDecision, verifiedFindings)
  assert.equal(decision.riskBand, 'HIGH')
  assert.equal(decision.recommendation, 'STOP_AND_AVOID')
  assert.equal(intelligenceOverlay.netVerdict, 'CONFIRMED_SCAM')
  assert.equal(intelligenceOverlay.scamCount, 3)
})

test('extractDomainVariants: Correctly resolves apex and stripped variants for Sri Lankan domains', () => {
  const variants1 = extractDomainVariants('login.scam.lk')
  assert.ok(variants1.includes('login.scam.lk'))
  assert.ok(variants1.includes('scam.lk'))

  const variants2 = extractDomainVariants('www.commercialbank.com.lk')
  assert.ok(variants2.includes('commercialbank.com.lk'))

  const variants3 = extractDomainVariants('ebanking.cbsl.gov.lk')
  assert.ok(variants3.includes('ebanking.cbsl.gov.lk'))
  assert.ok(variants3.includes('cbsl.gov.lk'))
})

test('reconcileDecision: Scenario 13 — Known global platform (facebook.com) with crowd report yields GLOBAL_PLATFORM_WITH_CAUTION', () => {
  const baseDecision = {
    riskBand: 'LOW',
    recommendation: 'PROCEED_CAUTIOUSLY',
    findings: [
      { canonicalSignal: 'known_global_domain', category: 'High-reputation global infrastructure', source: 'RULE', strength: 0.0, meta: { domain: 'facebook.com', trancoRank: 3 } }
    ],
    safeActions: ['Standard caution.'],
  }
  const verifiedFindings = [
    { canonicalSignal: 'verified_scam_intelligence', confidence: 0.70, source: 'APPROVED_REPORT', strength: 1.0, reportCount: 1 }
  ]

  const { decision, intelligenceOverlay } = reconcileDecision(baseDecision, verifiedFindings)
  assert.equal(decision.riskBand, 'LOW')
  assert.equal(decision.recommendation, 'PROCEED_CAUTIOUSLY')
  assert.equal(intelligenceOverlay.netVerdict, 'GLOBAL_PLATFORM_WITH_CAUTION')
  assert.equal(intelligenceOverlay.globalDomain, 'facebook.com')
  assert.ok(intelligenceOverlay.reconciliationTrace.some((line) => line.includes('Global Platform Protection')))
})

test('reconcileDecision: Scenario 14 — Global platform with critical behavioral credential theft overrides to HIGH risk', () => {
  const baseDecision = {
    riskBand: 'LOW',
    recommendation: 'PROCEED_CAUTIOUSLY',
    findings: [
      { canonicalSignal: 'known_global_domain', category: 'High-reputation global infrastructure', source: 'RULE', strength: 0.0, meta: { domain: 'facebook.com' } },
      { canonicalSignal: 'credential_harvesting_intent', category: 'Social engineering', source: 'RULE', strength: 0.95 }
    ],
    safeActions: ['Standard caution.'],
  }
  const verifiedFindings = [
    { canonicalSignal: 'verified_scam_intelligence', confidence: 0.85, source: 'APPROVED_REPORT', strength: 1.0, reportCount: 1 }
  ]

  const { decision, intelligenceOverlay } = reconcileDecision(baseDecision, verifiedFindings, {
    messageBody: 'Your account is suspended. Enter your OTP and debit card PIN immediately.'
  })
  assert.equal(decision.riskBand, 'HIGH')
  assert.equal(decision.recommendation, 'STOP_AND_AVOID')
  assert.ok(intelligenceOverlay.reconciliationTrace.some((line) => line.includes('Behavioral override active')))
})

test('Indicator Intelligence Context: Detects conflict when false alarm is submitted on active threat', async () => {
  // 1. Submit a suspicious report for test-bank-alert.xyz and approve as CONFIRMED_SCAM
  const scamReport = await submitReport({
    reportType: 'suspicious',
    text: 'Click here to update your account: http://test-bank-alert.xyz',
    reportedDomain: 'test-bank-alert.xyz',
    notes: 'Phishing domain sending fake alerts',
  })
  await processModerationReview({
    reportId: scamReport.id,
    action: 'APPROVE',
    confidence: 0.95,
    category: 'Banking Phishing',
    notes: 'Verified malicious indicator',
  })

  // 2. A user later submits a false_positive report for the same domain
  const disputeReport = await submitReport({
    reportType: 'false_positive',
    text: 'Legitimate portal: http://test-bank-alert.xyz',
    reportedDomain: 'test-bank-alert.xyz',
    notes: 'This is my business site, not a scam!',
  })

  // 3. Inspect intelligence context
  const context = await getIndicatorIntelligenceContext(disputeReport.id)
  assert.ok(context)
  assert.equal(context.hasActiveIntel, true)
  assert.equal(context.activeIntel.risk_level, 'CONFIRMED_SCAM')
  assert.equal(context.isConflict, true)
  assert.equal(context.conflictType, 'FALSE_ALARM_AGAINST_SCAM')
  assert.ok(context.conflictExplanation.includes('Active Intelligence already classifies this domain as a CONFIRMED SCAM'))
  assert.ok(context.revocationConsequence.includes('Approving this report will REVOKE'))
})

test('Dynamic Threat Revocation: Approving false positive supersedes and deactivates active scam indicator', async () => {
  // 1. Submit a false alarm on test-bank-alert.xyz (which was active as CONFIRMED_SCAM)
  const disputeReport = await submitReport({
    reportType: 'false_positive',
    text: 'Site verified clean: http://test-bank-alert.xyz',
    reportedDomain: 'test-bank-alert.xyz',
    notes: 'Security audit completed, cleaned up.',
  })

  // 2. Moderator approves the false positive report
  const reviewResult = await processModerationReview({
    reportId: disputeReport.id,
    action: 'APPROVE',
    confidence: 1.0,
    category: 'False Alarm',
    notes: 'Domain confirmed cleaned and legitimate.',
  })
  assert.equal(reviewResult.success, true)
  assert.equal(reviewResult.status, 'APPROVED')

  // 3. Inspect context now: active intel should now be VERIFIED_SAFE, not CONFIRMED_SCAM
  const updatedContext = await getIndicatorIntelligenceContext(disputeReport.id)
  assert.ok(updatedContext)
  assert.equal(updatedContext.activeIntel.risk_level, 'VERIFIED_SAFE')
  assert.equal(updatedContext.isConflict, false)
})

test('Historical Decision Memory: Reflects past rejections for an indicator', async () => {
  const domain = `clean-blog-${Date.now()}.lk`
  // 1. Submit a spammy report for domain and REJECT it
  const spamReport = await submitReport({
    reportType: 'suspicious',
    text: `Citizen claims this is suspicious: http://${domain}`,
    reportedDomain: domain,
    notes: 'Vexatious report',
  })
  await processModerationReview({
    reportId: spamReport.id,
    action: 'REJECT',
    notes: 'No phishing elements detected. Normal citizen blog.',
  })

  // 2. Another report comes in for the same domain
  const secondReport = await submitReport({
    reportType: 'suspicious',
    text: `Look at this: http://${domain}`,
    reportedDomain: domain,
    notes: 'Second submission',
  })

  // 3. Inspect context: should show 1 prior rejection with moderator notes
  const context = await getIndicatorIntelligenceContext(secondReport.id)
  assert.ok(context)
  assert.equal(context.priorDecisions.totalRejections, 1)
  assert.equal(context.priorDecisions.latestRejection.notes, 'No phishing elements detected. Normal citizen blog.')
})

test('Dynamic Threat Escalation: Reconciles SCAM_AGAINST_SAFE conflict when safe entity is later compromised', async () => {
  const domain = `initially-safe-${Date.now()}.lk`
  // 1. Establish an active VERIFIED_SAFE indicator
  const safeReport = await submitReport({
    reportType: 'false_positive',
    text: `Registered business portal: http://${domain}`,
    reportedDomain: domain,
    notes: 'Safe corporate portal',
  })
  await processModerationReview({
    reportId: safeReport.id,
    action: 'APPROVE',
    confidence: 1.0,
    category: 'False Alarm',
    notes: 'Verified clean business site',
  })

  // 2. Later, a citizen reports it as a scam because it got compromised
  const compromisedReport = await submitReport({
    reportType: 'suspicious',
    text: `Attacker injected credential stealer: http://${domain}`,
    reportedDomain: domain,
    notes: 'Injected banking form on home page',
  })

  // 3. Verify context flags SCAM_AGAINST_SAFE conflict
  const context = await getIndicatorIntelligenceContext(compromisedReport.id)
  assert.ok(context)
  assert.equal(context.hasActiveIntel, true)
  assert.equal(context.activeIntel.risk_level, 'VERIFIED_SAFE')
  assert.equal(context.isConflict, true)
  assert.equal(context.conflictType, 'SCAM_AGAINST_SAFE')
  assert.ok(context.conflictExplanation.includes('VERIFIED SAFE'))
  assert.ok(context.revocationConsequence.includes('REVOKE the VERIFIED_SAFE status'))

  // 4. Moderator approves threat: VERIFIED_SAFE revoked and replaced by CONFIRMED_SCAM
  const reviewResult = await processModerationReview({
    reportId: compromisedReport.id,
    action: 'APPROVE',
    confidence: 0.95,
    category: 'Compromised Website',
    notes: 'Confirmed DNS and file compromise, revoking safe status',
  })
  assert.equal(reviewResult.success, true)
  assert.equal(reviewResult.status, 'APPROVED')

  const updatedContext = await getIndicatorIntelligenceContext(compromisedReport.id)
  assert.ok(updatedContext)
  assert.equal(updatedContext.activeIntel.risk_level, 'CONFIRMED_SCAM')
  assert.equal(updatedContext.isConflict, false)
})

test('Threat Corroboration Engine: Calculates projected Bayesian confidence scaling for repeated threat submissions', async () => {
  const domain = `corrob-tracker-${Date.now()}.com`
  // 1. Establish initial confirmed scam with 0.80 base confidence
  const report1 = await submitReport({
    reportType: 'suspicious',
    text: `Phishing: http://${domain}`,
    reportedDomain: domain,
    notes: 'First submission',
  })
  await processModerationReview({
    reportId: report1.id,
    action: 'APPROVE',
    confidence: 0.80,
    category: 'Phishing',
    notes: 'Initial threat verification',
  })

  // 2. Submit second report for the same domain
  const report2 = await submitReport({
    reportType: 'suspicious',
    text: `Another complaint: http://${domain}`,
    reportedDomain: domain,
    notes: 'Second submission',
  })

  // 3. Context should project corroboration and Bayesian scaling
  const context = await getIndicatorIntelligenceContext(report2.id)
  assert.ok(context)
  assert.equal(context.isCorroborating, true)
  assert.equal(context.isConflict, false)
  assert.equal(context.projectedCount, 2)
  assert.ok(context.projectedConfidence > 0.80, 'Projected confidence should scale above 0.80')

  // 4. Moderator approves corroboration: report_count increases and confidence updates
  await processModerationReview({
    reportId: report2.id,
    action: 'APPROVE',
    confidence: 0.80,
    category: 'Phishing',
    notes: 'Corroborating evidence verified',
  })

  const updatedContext = await getIndicatorIntelligenceContext(report2.id)
  assert.ok(updatedContext)
  assert.equal(updatedContext.activeIntel.report_count, 2)
  assert.ok(updatedContext.activeIntel.confidence > 0.80)
})

test('Subdomain Intel Resolution: Maps multi-level subdomain reports to apex indicator intelligence', async () => {
  const apexDomain = `apex-scam-${Date.now()}.lk`
  const subDomain = `auth.verify.${apexDomain}`

  // 1. Establish active threat on apex domain
  const apexReport = await submitReport({
    reportType: 'suspicious',
    text: `Apex phishing: http://${apexDomain}`,
    reportedDomain: apexDomain,
    notes: 'Apex scam domain',
  })
  await processModerationReview({
    reportId: apexReport.id,
    action: 'APPROVE',
    confidence: 0.95,
    category: 'Credential Harvester',
    notes: 'Apex verified threat',
  })

  // 2. Subdomain report arrives
  const subReport = await submitReport({
    reportType: 'suspicious',
    text: `Subdomain lure: http://${subDomain}`,
    reportedDomain: subDomain,
    notes: 'Subdomain targeting login',
  })

  // 3. Intelligence context maps to apex intelligence
  const context = await getIndicatorIntelligenceContext(subReport.id)
  assert.ok(context)
  assert.equal(context.hasActiveIntel, true)
  assert.equal(context.activeIntel.indicator_value, apexDomain)
  assert.equal(context.isCorroborating, true)
})






import test from 'node:test'
import assert from 'node:assert/strict'
import { arbitrateDecision, evaluateHardInvariants, calculateCompositeThreatScore, normalizeFindings } from '../src/services/decisionArbiter.mjs'

test('normalizeFindings: deduplicates identical findings and preserves metadata', () => {
  const raw = [
    { canonicalSignal: 'approved_domain', source: 'DOMAIN_DIRECTORY', evidence: 'boc.lk is listed for Bank of Ceylon' },
    { canonicalSignal: 'approved_domain', source: 'DOMAIN_DIRECTORY', evidence: 'boc.lk is listed for Bank of Ceylon' },
    { canonicalSignal: 'credential_request', source: 'RULE', evidence: 'Demands OTP' },
  ]
  const normalized = normalizeFindings(raw)
  assert.equal(normalized.length, 2, 'Should deduplicate duplicate findings')
  assert.equal(normalized[0].canonicalSignal, 'approved_domain')
  assert.equal(normalized[1].canonicalSignal, 'credential_request')
})

test('Hard Invariants: INV-01 Google Safe Browsing malware hit forces HIGH / STOP_AND_AVOID', () => {
  const findings = [
    { canonicalSignal: 'known_malicious_domain', evidence: 'Google Safe Browsing match' },
  ]
  const result = evaluateHardInvariants({ findings })
  assert.ok(result, 'Invariant should trigger')
  assert.equal(result.code, 'INV-01')
  assert.equal(result.riskBand, 'HIGH')
  assert.equal(result.recommendation, 'STOP_AND_AVOID')
})

test('Hard Invariants: INV-02 Confirmed Community Threat Intel forces HIGH / STOP_AND_AVOID', () => {
  const findings = [
    { canonicalSignal: 'verified_scam_intelligence', confidence: 0.95, strength: 0.95, evidence: 'Verified phishing kit' },
  ]
  const result = evaluateHardInvariants({ findings })
  assert.ok(result, 'Invariant should trigger')
  assert.equal(result.code, 'INV-02')
  assert.equal(result.riskBand, 'HIGH')
  assert.equal(result.recommendation, 'STOP_AND_AVOID')
})

test('Hard Invariants: INV-04 Brand Impersonation / Domain Mismatch forces HIGH / STOP_AND_AVOID', () => {
  const findings = [
    { canonicalSignal: 'domain_mismatch', evidence: 'Claims Bank of Ceylon but links to scam-portal.xyz' },
  ]
  const result = evaluateHardInvariants({ findings, claimedOrg: 'Bank of Ceylon' })
  assert.ok(result, 'Invariant should trigger')
  assert.equal(result.code, 'INV-04')
  assert.equal(result.riskBand, 'HIGH')
  assert.equal(result.recommendation, 'STOP_AND_AVOID')
})

test('Hard Invariants: INV-05 Anti-Spoofing Guard blocks legitimate domain when message demands OTP', () => {
  const findings = [
    { canonicalSignal: 'approved_domain', organization: 'Commercial Bank of Ceylon' },
    { canonicalSignal: 'credential_request', evidence: 'Please send OTP' },
  ]
  const result = evaluateHardInvariants({
    findings,
    hasOfficialDomain: true,
    matchedOrg: 'Commercial Bank of Ceylon',
    aiResult: { intent: 'COERCIVE_DEMAND' },
  })
  assert.ok(result, 'Invariant should trigger')
  assert.equal(result.code, 'INV-05')
  assert.equal(result.riskBand, 'HIGH')
  assert.equal(result.recommendation, 'OFFICIAL_ENTITY_WITH_CAUTION')
})

test('Hard Invariants: INV-06 Genuine Advisory Warning suppresses false alarm on official notice', () => {
  const findings = [
    { canonicalSignal: 'approved_domain', organization: 'Bank of Ceylon' },
    { canonicalSignal: 'credential_request', evidence: 'Mentions OTP in warning context' },
  ]
  const result = evaluateHardInvariants({
    findings,
    hasOfficialDomain: true,
    matchedOrg: 'Bank of Ceylon',
    aiResult: { intent: 'ADVISORY_WARNING', isAdvisory: true },
  })
  assert.ok(result, 'Invariant should trigger')
  assert.equal(result.code, 'INV-06')
  assert.equal(result.riskBand, 'LOW')
  assert.equal(result.recommendation, 'VERIFIED_SAFE')
})

test('Composite Threat Scoring: Moderate threat triggers MEDIUM (VERIFY_INDEPENDENTLY)', () => {
  const findings = [
    { canonicalSignal: 'urgency' },
    { canonicalSignal: 'new_domain_risk' },
  ]
  const score = calculateCompositeThreatScore({ findings })
  assert.ok(score >= 30 && score < 65, `Expected score between 30 and 65, got ${score}`)
})

test('Composite Threat Scoring: Official domain with zero threats yields LOW score (< 30)', () => {
  const findings = [
    { canonicalSignal: 'approved_domain' },
  ]
  const score = calculateCompositeThreatScore({ findings, hasOfficialDomain: true })
  assert.equal(score, 0, `Expected 0 score, got ${score}`)
})

test('arbitrateDecision: Full pipeline harmonizes all signals with explainable trace and dynamic safe actions', () => {
  const arbitrated = arbitrateDecision({
    baseDecision: {
      riskBand: 'LOW',
      findings: [{ canonicalSignal: 'domain_mismatch', evidence: 'Mismatch detected' }],
      limitations: ['Test limitation'],
    },
    entities: [{ type: 'organization', value: 'CEB' }],
    claimedOrg: 'CEB',
  })

  assert.equal(arbitrated.decision.riskBand, 'HIGH')
  assert.equal(arbitrated.decision.recommendation, 'STOP_AND_AVOID')
  assert.ok(arbitrated.compositeScore >= 65)
  assert.ok(arbitrated.decision.safeActions.length > 0)
  assert.ok(arbitrated.decision.reconciliationTrace.length > 0)
  assert.equal(arbitrated.decision.limitations[0], 'Test limitation')
})

test('synthesizeSafeActions: Dynamically resolves statutory authorities from database directory without hardcoding', () => {
  const dynamicAuthorities = [
    { name: 'National Cybersecurity Center', officialDomain: 'cybercenter.gov.lk' },
  ]
  const arbitrated = arbitrateDecision({
    baseDecision: {
      riskBand: 'HIGH',
      findings: [{ canonicalSignal: 'credential_request' }],
    },
    authorities: dynamicAuthorities,
  })

  const actions = arbitrated.decision.safeActions
  const mentionsDynamicAuth = actions.some((a) => a.includes('National Cybersecurity Center') && a.includes('cybercenter.gov.lk'))
  assert.ok(mentionsDynamicAuth, 'Safe actions should dynamically incorporate directory authorities')

  // Verify zero hardcoded hotlines or emails in actions
  const hasHardcodedHotline = actions.some((a) => a.includes('1930') || a.includes('011 269 1692'))
  assert.equal(hasHardcodedHotline, false, 'Should not contain hardcoded phone numbers')
})

test('Scenario 1: Legitimate Bank Security Advisory SMS suppresses false alarm (INV-06)', () => {
  const arbitrated = arbitrateDecision({
    baseDecision: {
      riskBand: 'HIGH',
      findings: [
        { canonicalSignal: 'credential_request', evidence: 'Never share OTP' },
        { canonicalSignal: 'approved_domain', organization: 'Bank of Ceylon', domain: 'boc.lk' },
      ],
    },
    aiResult: {
      intent: 'ADVISORY_WARNING',
      isAdvisory: true,
      reasoning: 'Educational security notice warning customers never to share OTPs.',
    },
    claimedOrg: 'Bank of Ceylon',
  })

  assert.equal(arbitrated.decision.riskBand, 'LOW')
  assert.equal(arbitrated.decision.recommendation, 'VERIFIED_SAFE')
  assert.ok(arbitrated.decision.safeActions.some((a) => a.includes('defensive educational guidance')))
})

test('Scenario 2: Phishing SMS Quoting Real Bank URL triggers Anti-Spoofing Guard (INV-05)', () => {
  const arbitrated = arbitrateDecision({
    baseDecision: {
      riskBand: 'HIGH',
      findings: [
        { canonicalSignal: 'credential_request', evidence: 'Reply with your OTP' },
        { canonicalSignal: 'approved_domain', organization: 'Commercial Bank of Ceylon', domain: 'combank.lk' },
      ],
    },
    aiResult: {
      intent: 'COERCIVE_DEMAND',
      isAdvisory: false,
      reasoning: 'Coercive demand for OTP using official domain lure.',
    },
    claimedOrg: 'Commercial Bank of Ceylon',
  })

  assert.equal(arbitrated.decision.riskBand, 'HIGH')
  assert.equal(arbitrated.decision.recommendation, 'OFFICIAL_ENTITY_WITH_CAUTION')
  assert.ok(arbitrated.decision.safeActions.some((a) => a.includes('Never share your OTP')))
})

test('Scenario 3: Singlish Task Scam uncaught by rules engine triggers Semantic Enforcement (INV-07)', () => {
  const arbitrated = arbitrateDecision({
    baseDecision: {
      riskBand: 'LOW',
      findings: [], // 0 rule findings matched
    },
    aiResult: {
      intent: 'COERCIVE_DEMAND',
      confidence: 0.95,
      reasoning: 'Identified as a fraudulent daily salary recruitment task scam in Singlish.',
    },
    text: 'Gedara indan dawasata 5000k hoyanna kemathida? WhatsApp msg ekak danna me link ekata: bit.ly/lk-job',
  })

  assert.equal(arbitrated.decision.riskBand, 'HIGH')
  assert.equal(arbitrated.decision.recommendation, 'STOP_AND_AVOID')
  assert.ok(arbitrated.compositeScore >= 65)
  assert.ok(arbitrated.decision.safeActions.some((a) => a.includes('fraudulent job or task offers')))
})

test('Scenario 4: Legitimate Transactional OTP Notification suppresses false alarm (INV-08)', () => {
  const arbitrated = arbitrateDecision({
    baseDecision: {
      riskBand: 'HIGH',
      findings: [
        { canonicalSignal: 'credential_request', evidence: 'OTP or one-time verification code requested' },
      ],
    },
    aiResult: {
      verdict: 'DISAGREE',
      intent: 'BENIGN_INFORMATIVE',
      confidence: 0.95,
      reasoning: 'The message is a standard, legitimate automated OTP notification for a valid transaction rather than a coercive demand or phishing attempt.',
    },
    text: "Dear Cardholder, please verify the merchant name and transaction amount before entering the One Time Password (OTP). Keep your OTP confidential and do not share it with anyone. Your OTP at Merchant 'Bharthi Airtel Lanka -App' for LKR 168.00 is 594104",
  })

  assert.equal(arbitrated.decision.riskBand, 'LOW')
  assert.equal(arbitrated.decision.recommendation, 'PROCEED_CAUTIOUSLY')
  assert.ok(arbitrated.decision.safeActions.some((a) => a.includes('automated transaction verification notification')))
  assert.ok(arbitrated.decision.safeActions.some((a) => a.includes('Never disclose, forward, or speak this OTP')))
  // Verify that the false regex credential_request is pruned from user-facing findings
  assert.ok(!arbitrated.decision.findings.some((f) => f.canonicalSignal === 'credential_request'))
  assert.ok(arbitrated.decision.findings.some((f) => f.canonicalSignal === 'transactional_otp_issuance'))
})

test('Scenario 5: Legitimate Commercial / Promotional message (e.g. KFC promo) triggers INV-09 with zero OTP findings', () => {
  const arbitrated = arbitrateDecision({
    baseDecision: {
      riskBand: 'LOW',
      findings: [],
    },
    aiResult: {
      verdict: 'DISAGREE',
      intent: 'BENIGN_INFORMATIVE',
      confidence: 0.95,
      reasoning: 'The message is a standard, legitimate promotional offer for KFC meals with no credential theft, urgency coercion, or scam indicators.',
    },
    text: 'Craving crispy chicken? Order your favorite KFC meals online at www.kfc.lk! Get 20% off on all bucket meals this weekend only. T&C apply.',
  })

  assert.equal(arbitrated.decision.riskBand, 'LOW')
  assert.equal(arbitrated.decision.recommendation, 'PROCEED_CAUTIOUSLY')
  // Must NOT contain OTP issuance or transactional findings
  assert.ok(!arbitrated.decision.findings.some((f) => f.canonicalSignal === 'transactional_otp_issuance'))
  assert.ok(!arbitrated.decision.findings.some((f) => f.canonicalSignal === 'credential_request'))
  assert.equal(arbitrated.decision.findings.length, 0)
  // Must NOT give OTP safe actions or tell user to freeze card
  assert.ok(!arbitrated.decision.safeActions.some((a) => a.includes('OTP')))
  assert.ok(!arbitrated.decision.safeActions.some((a) => a.includes('freeze your card')))
  // Must provide commercial promotion safe guidance
  assert.ok(arbitrated.decision.safeActions.some((a) => a.includes('legitimate commercial promotion')))
})




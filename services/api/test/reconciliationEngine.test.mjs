import test from 'node:test'
import assert from 'node:assert/strict'
import { reconcileDecision } from '../src/services/reconcileIntelligence.mjs'
import { extractDomainVariants } from '../src/services/reportingService.mjs'

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

test('reconcileDecision: Scenario 3 — 1 scam vs 40 safe reports yields VERIFIED_SAFE with minority dissent trace', () => {
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
  assert.equal(decision.riskBand, 'LOW')
  assert.equal(decision.recommendation, 'VERIFIED_SAFE')
  assert.equal(intelligenceOverlay.netVerdict, 'VERIFIED_SAFE')
  assert.equal(intelligenceOverlay.scamCount, 1)
  assert.equal(intelligenceOverlay.safeCount, 40)
  assert.ok(intelligenceOverlay.consensusSummary.includes('40 Safe vs 1 Scam'))
  // Check that the trace contains the minority notice
  assert.ok(intelligenceOverlay.reconciliationTrace.some((line) => line.includes('Minority notice: 1 historical report(s)')))
})

test('reconcileDecision: Scenario 4 — 40 scam vs 1 safe report yields CONFIRMED_SCAM (threat consensus)', () => {
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
  assert.equal(decision.recommendation, 'STOP_AND_AVOID')
  assert.equal(intelligenceOverlay.netVerdict, 'CONFIRMED_SCAM')
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
  assert.equal(decision.recommendation, 'STOP_AND_AVOID')
  assert.equal(intelligenceOverlay.netVerdict, 'CONFLICTED')
  assert.equal(intelligenceOverlay.scamCount, 5)
  assert.equal(intelligenceOverlay.safeCount, 5)
  assert.ok(intelligenceOverlay.reconciliationTrace.some((line) => line.includes('Fail-Closed Security Policy')))
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

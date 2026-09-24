import test from 'node:test'
import assert from 'node:assert/strict'
import {
  isAiValidationConfigured,
  isHardBlockedFromAiDowngrade,
  applyAiVerdict,
  evaluateContextWithAi,
} from '../src/services/aiContextValidator.mjs'

test('AI Context Validation: isAiValidationConfigured returns true when GEMINI_API_KEY is present', () => {
  assert.equal(typeof isAiValidationConfigured(), 'boolean')
})

test('AI Context Validation: Hard Block — Credential theft + advance fee compound threat', () => {
  const decision = {
    riskBand: 'HIGH',
    findings: [
      { canonicalSignal: 'credential_request', strength: 0.95 },
      { canonicalSignal: 'advance_payment', strength: 0.9 },
    ],
  }
  assert.equal(isHardBlockedFromAiDowngrade(decision, null), true)
})

test('AI Context Validation: Hard Block — Domain mismatch / spoofing', () => {
  const decision = {
    riskBand: 'HIGH',
    findings: [{ canonicalSignal: 'domain_mismatch', strength: 0.99 }],
  }
  assert.equal(isHardBlockedFromAiDowngrade(decision, null), true)
})

test('AI Context Validation: Hard Block — Google Safe Browsing hit', () => {
  const decision = {
    riskBand: 'HIGH',
    findings: [{ canonicalSignal: 'known_malicious_domain', strength: 0.98 }],
  }
  assert.equal(isHardBlockedFromAiDowngrade(decision, null), true)
})

test('AI Context Validation: Hard Block — Verified community intelligence CONFIRMED_SCAM', () => {
  const decision = {
    riskBand: 'HIGH',
    findings: [{ canonicalSignal: 'urgency', strength: 0.7 }],
  }
  const overlay = { netVerdict: 'CONFIRMED_SCAM' }
  assert.equal(isHardBlockedFromAiDowngrade(decision, overlay), true)
})

test('AI Context Validation: Soft Downgrade — HIGH to MEDIUM for benign contextual message', () => {
  const decision = {
    riskBand: 'HIGH',
    recommendation: 'STOP_AND_AVOID',
    findings: [{ canonicalSignal: 'urgency', strength: 0.7, evidence: 'urgent action' }],
    reconciliationTrace: [],
  }

  const aiResult = {
    verdict: 'DISAGREE',
    confidence: 0.85,
    reasoning: 'Message is a routine internal corporate reminder.',
  }

  const updated = applyAiVerdict(decision, aiResult, null)

  assert.equal(updated.riskBand, 'MEDIUM')
  assert.equal(updated.recommendation, 'PROCEED_WITH_CAUTION')
  assert.equal(updated.aiValidation.appliedAction, 'DOWNGRADED')
  assert.ok(updated.reconciliationTrace.some((t) => t.includes('downgraded from HIGH to MEDIUM')))
})

test('AI Context Validation: Soft Downgrade — MEDIUM to LOW for benign contextual message', () => {
  const decision = {
    riskBand: 'MEDIUM',
    recommendation: 'VERIFY_INDEPENDENTLY',
    findings: [{ canonicalSignal: 'job_offer', strength: 0.65, evidence: 'part time work' }],
    reconciliationTrace: [],
  }

  const aiResult = {
    verdict: 'DISAGREE',
    confidence: 0.82,
    reasoning: 'Official recruitment post from a registered company.',
  }

  const updated = applyAiVerdict(decision, aiResult, null)

  assert.equal(updated.riskBand, 'LOW')
  assert.equal(updated.recommendation, 'SAFE_TO_PROCEED')
  assert.equal(updated.aiValidation.appliedAction, 'DOWNGRADED')
})

test('AI Context Validation: Retain verdict when AI AGREEs with rule engine', () => {
  const decision = {
    riskBand: 'HIGH',
    recommendation: 'STOP_AND_AVOID',
    findings: [{ canonicalSignal: 'credential_request', strength: 0.9 }],
    reconciliationTrace: [],
  }

  const aiResult = {
    verdict: 'AGREE',
    confidence: 0.92,
    reasoning: 'Active phishing attempt targeting personal credentials.',
  }

  const updated = applyAiVerdict(decision, aiResult, null)

  assert.equal(updated.riskBand, 'HIGH')
  assert.equal(updated.aiValidation.appliedAction, 'RETAINED')
  assert.ok(updated.reconciliationTrace.some((t) => t.includes('confirmed rule-engine verdict')))
})

test('AI Context Validation: Retain verdict on UNCERTAIN or low confidence', () => {
  const decision = {
    riskBand: 'HIGH',
    findings: [{ canonicalSignal: 'advance_payment', strength: 0.85 }],
    reconciliationTrace: [],
  }

  const aiResult = {
    verdict: 'UNCERTAIN',
    confidence: 0.5,
    reasoning: 'Ambiguous wording.',
  }

  const updated = applyAiVerdict(decision, aiResult, null)

  assert.equal(updated.riskBand, 'HIGH')
  assert.equal(updated.aiValidation.appliedAction, 'RETAINED')
})

test('AI Context Validation: Hard Block overrides AI DISAGREE verdict', () => {
  const decision = {
    riskBand: 'HIGH',
    findings: [
      { canonicalSignal: 'credential_request', strength: 0.9 },
      { canonicalSignal: 'advance_payment', strength: 0.9 },
    ],
    reconciliationTrace: [],
  }

  const aiResult = {
    verdict: 'DISAGREE',
    confidence: 0.9,
    reasoning: 'AI falsely claims this compound threat is benign.',
  }

  const updated = applyAiVerdict(decision, aiResult, null)

  assert.equal(updated.riskBand, 'HIGH')
  assert.equal(updated.aiValidation.appliedAction, 'HARD_BLOCKED')
  assert.ok(updated.reconciliationTrace.some((t) => t.includes('HARD BLOCKED')))
})

test('AI Context Validation: evaluateContextWithAi skips LOW risk messages', async () => {
  const decision = { riskBand: 'LOW', findings: [] }
  const res = await evaluateContextWithAi({ text: 'Hello', decision })
  assert.equal(res, null)
})

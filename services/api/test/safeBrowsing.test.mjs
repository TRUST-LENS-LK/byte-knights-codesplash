import test from 'node:test'
import assert from 'node:assert/strict'
import { applyKnownMaliciousRisk } from '../src/services/safeBrowsing.mjs'

// checkSafeBrowsing itself (the live Google API call) is verified manually
// against Google's own official test URLs (testsafebrowsing.appspot.com),
// which are specifically provided by Google for exactly this kind of
// integration testing, confirmed to correctly return MALWARE and
// SOCIAL_ENGINEERING respectively, and an empty result for a clean URL.
// Baking a real external API call requiring a live key into the automated
// suite would make it inapplicable for anyone without that key configured;
// applyKnownMaliciousRisk (the pure decision logic) is what's unit tested
// here instead.

test('a known_malicious_domain finding forces HIGH risk and STOP_AND_AVOID', () => {
  const decision = {
    riskBand: 'LOW',
    recommendation: 'PROCEED_CAUTIOUSLY',
    findings: [{ canonicalSignal: 'known_malicious_domain', evidence: 'test' }],
    safeActions: ['original action'],
  }
  applyKnownMaliciousRisk(decision)
  assert.equal(decision.riskBand, 'HIGH')
  assert.equal(decision.recommendation, 'STOP_AND_AVOID')
  assert.equal(decision.overridesApplied.includes('known_malicious_domain_override'), true)
})

test('no known_malicious_domain finding leaves the decision untouched', () => {
  const decision = {
    riskBand: 'LOW',
    recommendation: 'PROCEED_CAUTIOUSLY',
    findings: [{ canonicalSignal: 'approved_domain', evidence: 'test' }],
    safeActions: ['original action'],
  }
  applyKnownMaliciousRisk(decision)
  assert.equal(decision.riskBand, 'LOW')
  assert.equal(decision.recommendation, 'PROCEED_CAUTIOUSLY')
  assert.equal(decision.overridesApplied, undefined)
})

test('overridesApplied accumulates rather than overwriting an existing override', () => {
  const decision = {
    riskBand: 'HIGH',
    recommendation: 'STOP_AND_AVOID',
    findings: [{ canonicalSignal: 'known_malicious_domain', evidence: 'test' }],
    safeActions: [],
    overridesApplied: ['domain_mismatch_override'],
  }
  applyKnownMaliciousRisk(decision)
  assert.deepEqual(decision.overridesApplied, ['domain_mismatch_override', 'known_malicious_domain_override'])
})

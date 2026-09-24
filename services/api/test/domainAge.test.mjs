import test from 'node:test'
import assert from 'node:assert/strict'
import { buildDomainAgeOutcome } from '../src/services/domainAge.mjs'

// These tests cover the pure decision logic only (buildDomainAgeOutcome),
// deliberately not the live RDAP/CT-log network calls in domainAge.mjs.
// Those were verified manually against the real services (rdap.org, crt.sh,
// api.certspotter.com) during development; baking live third-party network
// calls into the automated suite would make it slow and flaky, since crt.sh
// in particular is a free community service known to be occasionally
// overloaded (observed directly while researching this feature).

const FIXED_NOW = new Date('2026-09-22T00:00:00Z')

test('a domain registered 2 days ago via RDAP produces a new_domain_risk finding', () => {
  const ageResult = { date: new Date('2026-09-20T00:00:00Z'), source: 'RDAP' }
  const outcome = buildDomainAgeOutcome('scam-site.com', ageResult, FIXED_NOW)
  assert.equal(outcome.findings.length, 1)
  assert.equal(outcome.findings[0].canonicalSignal, 'new_domain_risk')
  assert.match(outcome.findings[0].evidence, /2 day\(s\) ago/)
  assert.match(outcome.findings[0].evidence, /RDAP/)
  assert.equal(outcome.findings[0].confidence, 0.9, 'RDAP is authoritative, so confidence should be high')
})

test('a domain first certified 2 days ago via a CT log produces a lower-confidence finding', () => {
  const ageResult = { date: new Date('2026-09-20T00:00:00Z'), source: 'CT_LOG_CRTSH' }
  const outcome = buildDomainAgeOutcome('scam-site.lk', ageResult, FIXED_NOW)
  assert.equal(outcome.findings.length, 1)
  assert.match(outcome.findings[0].evidence, /first seen with an SSL certificate/)
  assert.equal(outcome.findings[0].confidence, 0.6, 'a CT-log first-cert date is a proxy, not an exact registration date, so confidence should be lower than RDAP')
})

test('a domain registered well over 14 days ago produces no finding', () => {
  const ageResult = { date: new Date('2020-01-01T00:00:00Z'), source: 'RDAP' }
  const outcome = buildDomainAgeOutcome('boc.lk', ageResult, FIXED_NOW)
  assert.equal(outcome.findings.length, 0)
  assert.equal(outcome.limitations.length, 0)
})

test('exactly at the 14-day boundary produces no finding (< 14, not <= 14)', () => {
  const ageResult = { date: new Date('2026-09-08T00:00:00Z'), source: 'RDAP' } // exactly 14 days before FIXED_NOW
  const outcome = buildDomainAgeOutcome('boundary-test.com', ageResult, FIXED_NOW)
  assert.equal(outcome.findings.length, 0)
})

test('13 days old is still inside the new-domain window', () => {
  const ageResult = { date: new Date('2026-09-09T00:00:00Z'), source: 'RDAP' } // 13 days before FIXED_NOW
  const outcome = buildDomainAgeOutcome('just-inside.com', ageResult, FIXED_NOW)
  assert.equal(outcome.findings.length, 1)
})

test('no age data available produces no finding, only a limitation, never a fabricated risk', () => {
  const outcome = buildDomainAgeOutcome('unknown-age.com', null, FIXED_NOW)
  assert.equal(outcome.findings.length, 0)
  assert.equal(outcome.limitations.length, 1)
  assert.match(outcome.limitations[0], /could not be determined/)
})

test('a future-dated registration event (clock skew or bad data) is treated as unknown, not negative age', () => {
  const ageResult = { date: new Date('2026-10-01T00:00:00Z'), source: 'RDAP' } // after FIXED_NOW
  const outcome = buildDomainAgeOutcome('future-dated.com', ageResult, FIXED_NOW)
  assert.equal(outcome.findings.length, 0)
})

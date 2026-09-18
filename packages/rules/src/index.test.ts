import { describe, expect, it } from 'vitest'
import { analyzeMessage } from './index'

describe('analyzeMessage', () => {
  // ── English baseline ──────────────────────────────────────────────────────
  it('flags a fake job with payment and credentials as high risk', () => {
    const result = analyzeMessage('You got a job. Pay Rs. 5,000 today and send your OTP immediately.')
    expect(result.riskBand).toBe('HIGH')
    expect(result.recommendation).toBe('STOP_AND_AVOID')
    expect(result.findings.map((f) => f.canonicalSignal)).toEqual(
      expect.arrayContaining(['advance_payment', 'credential_request', 'urgency', 'job_offer']),
    )
  })

  it('does not flag ordinary text as suspicious', () => {
    const result = analyzeMessage('The team meeting is scheduled for tomorrow at 10 AM.')
    expect(result.riskBand).toBe('LOW')
    expect(result.findings).toHaveLength(0)
  })

  it('flags only job_offer as medium risk', () => {
    const result = analyzeMessage('We have a vacancy for work from home. You have been selected.')
    expect(result.riskBand).toBe('MEDIUM')
    expect(result.recommendation).toBe('VERIFY_INDEPENDENTLY')
    expect(result.findings.some((f) => f.canonicalSignal === 'job_offer')).toBe(true)
  })

  it('escalates to HIGH when both critical signals appear', () => {
    const result = analyzeMessage('Send your bank account details and pay the deposit now.')
    expect(result.riskBand).toBe('HIGH')
  })

  // ── Sinhala Unicode ───────────────────────────────────────────────────────
  it('flags Sinhala credential request', () => {
    const result = analyzeMessage('ඔබගේ රහස් අංකය දෙන්න.')
    expect(result.findings.some((f) => f.canonicalSignal === 'credential_request')).toBe(true)
    expect(result.riskBand).toBe('HIGH')
  })

  it('flags Sinhala payment request', () => {
    const result = analyzeMessage('ගාස්තු ගෙවන්න. ඉක්මනින් කරන්න.')
    expect(result.findings.some((f) => f.canonicalSignal === 'advance_payment')).toBe(true)
  })

  it('flags Sinhala urgency language', () => {
    const result = analyzeMessage('වහාම දන්වන්න. අදම කරන්න.')
    expect(result.findings.some((f) => f.canonicalSignal === 'urgency')).toBe(true)
  })

  it('flags Sinhala job offer', () => {
    const result = analyzeMessage('ඔබ රැකියා අවස්ථාව සඳහා තෝරාගෙන ඇත.')
    expect(result.findings.some((f) => f.canonicalSignal === 'job_offer')).toBe(true)
  })

  // ── Singlish ──────────────────────────────────────────────────────────────
  it('flags OTP eka ewanna as credential request', () => {
    const result = analyzeMessage('Api OTP eka ewanna. Danma send karanna.')
    expect(result.findings.some((f) => f.canonicalSignal === 'credential_request')).toBe(true)
    expect(result.riskBand).toBe('HIGH')
  })

  it('flags salli ewanna as advance payment', () => {
    const result = analyzeMessage('Registration fee salli ewanna. Job offer ekak.')
    expect(result.findings.some((f) => f.canonicalSignal === 'advance_payment')).toBe(true)
  })

  it('flags ada pay as urgency', () => {
    const result = analyzeMessage('Ada pay karanna. Ikmanata.')
    expect(result.findings.some((f) => f.canonicalSignal === 'urgency')).toBe(true)
  })

  it('flags job ekak as job offer', () => {
    const result = analyzeMessage('Salary lassana job ekak. Work from home.')
    expect(result.findings.some((f) => f.canonicalSignal === 'job_offer')).toBe(true)
  })

  // ── False positives ───────────────────────────────────────────────────────
  it('does not flag the word "today" in a legitimate reminder', () => {
    // "today" triggers urgency, but no critical signals — should be MEDIUM not HIGH
    const result = analyzeMessage('Your order will arrive today between 2pm and 4pm.')
    expect(result.riskBand).not.toBe('HIGH')
    expect(result.findings.some((f) => f.canonicalSignal === 'credential_request')).toBe(false)
    expect(result.findings.some((f) => f.canonicalSignal === 'advance_payment')).toBe(false)
  })

  it('returns policyVersion rules-v2', () => {
    const result = analyzeMessage('hello')
    expect(result.policyVersion).toBe('rules-v2')
  })
})


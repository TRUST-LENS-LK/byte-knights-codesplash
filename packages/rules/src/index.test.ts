import { describe, expect, it } from 'vitest'
import { analyzeMessage } from './index'

describe('analyzeMessage', () => {
  it('flags a fake job with payment and credentials as high risk', () => {
    const result = analyzeMessage('You got a job. Pay Rs. 5,000 today and send your OTP immediately.')
    expect(result.riskBand).toBe('HIGH')
    expect(result.recommendation).toBe('STOP_AND_AVOID')
    expect(result.findings.map((finding) => finding.canonicalSignal)).toEqual(expect.arrayContaining(['advance_payment', 'credential_request', 'urgency', 'job_offer']))
  })

  it('does not flag ordinary text as suspicious', () => {
    const result = analyzeMessage('The team meeting is scheduled for tomorrow at 10 AM.')
    expect(result.riskBand).toBe('LOW')
    expect(result.findings).toHaveLength(0)
  })
})

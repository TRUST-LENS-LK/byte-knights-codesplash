import { findingSchema, type Finding, type RiskDecision } from '../../../packages/contracts/src/index'

type Rule = { signal: string; category: string; pattern: RegExp; evidence: string; strength: number; critical?: boolean }

const RULES: Rule[] = [
  { signal: 'credential_request', category: 'Sensitive information', pattern: /otp|one[- ]time password|pin|password|bank(?:ing)? details?/i, evidence: 'OTP, PIN, password, or banking details', strength: 0.98, critical: true },
  { signal: 'advance_payment', category: 'Financial request', pattern: /registration fee|upfront|deposit|send (?:rs\.?|lkr)|payment|pay today|transfer/i, evidence: 'Payment or upfront-fee language', strength: 0.95, critical: true },
  { signal: 'urgency', category: 'Social engineering', pattern: /urgent|immediately|today|expires|act now|last chance/i, evidence: 'Urgent timing language', strength: 0.55 },
  { signal: 'job_offer', category: 'Job scam', pattern: /job|salary|vacancy|work from home|hiring|selected/i, evidence: 'Recruitment or job-offer language', strength: 0.65 },
]

export function analyzeMessage(text: string): RiskDecision {
  const findings: Finding[] = RULES.filter((rule) => rule.pattern.test(text)).map((rule) => findingSchema.parse({ canonicalSignal: rule.signal, category: rule.category, evidence: rule.evidence, source: 'RULE', strength: rule.strength, confidence: rule.strength, limitation: 'Keyword rule; context should be verified independently.' }))
  const critical = findings.some((finding) => finding.canonicalSignal === 'credential_request' || finding.canonicalSignal === 'advance_payment')
  const riskBand = critical || findings.length >= 3 ? 'HIGH' : findings.length ? 'MEDIUM' : 'LOW'
  const recommendation = riskBand === 'HIGH' ? 'STOP_AND_AVOID' : riskBand === 'MEDIUM' ? 'VERIFY_INDEPENDENTLY' : 'PROCEED_CAUTIOUSLY'
  return { riskBand, recommendation, findings, limitations: ['This local prototype uses deterministic rules only.'], safeActions: riskBand === 'HIGH' ? ['Do not click, pay, reply, or share credentials.', 'Verify through the organisation’s official website.'] : ['Verify the sender and organisation independently.'], policyVersion: 'rules-v1' }
}

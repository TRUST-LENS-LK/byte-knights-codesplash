import { findingSchema, type Finding, type RiskDecision } from '@trustlens/contracts'

type Rule = { signal: string; category: string; pattern: RegExp; evidence: string; strength: number; critical?: boolean }

const RULES: Rule[] = [
  {
    signal: 'credential_request',
    category: 'Sensitive information',
    pattern: /otp|one[- ]time password|pin|password|bank(?:ing)? details?|otp\s+eka|otp\s+ewanna|otp\s+denna|රහස්\s*(?:කේතය|අංකය)|මුරපදය|ගිණුම්\s*විස්තර|bank\s*details|account\s*(?:number|details)/i,
    evidence: 'OTP, PIN, password, or banking details requested',
    strength: 0.98,
    critical: true,
  },
  {
    signal: 'advance_payment',
    category: 'Financial request',
    pattern: /registration fee|upfront|deposit|send (?:rs\.?|lkr)|payment|pay today|transfer|pay\s+(?:the\s+)?fee|salli\s+(?:ewanna|gewanna|denna)|gaasthu|ගාස්තු|මුදල්\s*(?:ගෙවන්න|දෙන්න)|ගෙවන්න|තැන්පතු|fee\s+(?:ewanna|denna)|rs\s*\./i,
    evidence: 'Payment or upfront-fee language',
    strength: 0.95,
    critical: true,
  },
  {
    signal: 'urgency',
    category: 'Social engineering',
    pattern: /urgent|immediately|today only|expires|act now|last chance|limited time|ada\s+(?:pay|denna|ewanna)|danma|ikmanata|වහාම|අදම|හදිසි|දැන්ම|ඉක්මනින්|කල\s*ඉකුත්/i,
    evidence: 'Urgent or pressure-based timing language',
    strength: 0.55,
  },
  {
    signal: 'job_offer',
    category: 'Job scam',
    pattern: /job|salary|vacancy|work from home|work\s*from\s*home|hiring|you(?:'ve| have) been selected|selected for|job\s+ekak|job\s+offer|රැකියාව|රැකියා\s*අවස්ථාව|වැටුප්|තෝරාගෙන|තෝරා\s*ගත්|ගෙදර\s*ඉඳන්\s*වැඩ/i,
    evidence: 'Recruitment or job-offer language',
    strength: 0.65,
  },
]

export function analyzeMessage(text: string): RiskDecision {
  const findings: Finding[] = RULES
    .filter((rule) => rule.pattern.test(text))
    .map((rule) =>
      findingSchema.parse({
        canonicalSignal: rule.signal,
        category: rule.category,
        evidence: rule.evidence,
        source: 'RULE',
        strength: rule.strength,
        confidence: rule.strength,
        limitation: 'Keyword rule; context should be verified independently.',
      }),
    )
  const critical = findings.some(
    (f) => f.canonicalSignal === 'credential_request' || f.canonicalSignal === 'advance_payment',
  )
  const riskBand = critical || findings.length >= 3 ? 'HIGH' : findings.length ? 'MEDIUM' : 'LOW'
  const recommendation =
    riskBand === 'HIGH' ? 'STOP_AND_AVOID' : riskBand === 'MEDIUM' ? 'VERIFY_INDEPENDENTLY' : 'PROCEED_CAUTIOUSLY'
  return {
    riskBand,
    recommendation,
    findings,
    limitations: ['Analysis uses deterministic keyword rules. Context and language nuance may affect accuracy.'],
    safeActions:
      riskBand === 'HIGH'
        ? ['Do not click, pay, reply, or share credentials.', "Verify through the organisation’s official website."]
        : ['Verify the sender and organisation independently.'],
    policyVersion: 'rules-v2',
  }
}

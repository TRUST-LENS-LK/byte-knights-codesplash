import { findingSchema, type Finding } from '@trustlens/contracts'

/**
 * ADVANCE PAYMENT DETECTOR
 *
 * Detects language that demands an upfront monetary payment before delivering
 * any promised service or employment — the defining characteristic of fee-fraud
 * and job-scam schemes prevalent in Sri Lanka.
 *
 * This is a CRITICAL signal: its presence alone is sufficient to trigger
 * the STOP_AND_AVOID critical override in the main rules engine.
 *
 * Examples:
 *   "Pay Rs. 2,500 registration fee to activate your account."
 *   "Send a refundable deposit of LKR 5,000 to secure your slot."
 *   "Processing fee Rs.1,000 required before your interview."
 *   "Transfer money to account 123456 at People's Bank."
 */

const PAYMENT_PATTERNS: { pattern: RegExp; evidence: string; strength: number }[] = [
  // Registration / joining fees — strongest signal for job scams
  {
    pattern: /\b(?:registration fee|joining fee|enrollment fee|sign(?:-|\s)?up fee|membership fee|activation fee)\b/i,
    evidence: 'Registration or joining fee demanded before service delivery',
    strength: 0.97,
  },
  // Deposit variants — "refundable" framing is classic social engineering
  {
    pattern: /\b(?:refundable\s+)?(?:security\s+)?deposit\b/i,
    evidence: 'Upfront deposit demanded (refundable framing often used to lower victim guard)',
    strength: 0.90,
  },
  // Processing / training / background-check fees
  {
    pattern: /\b(?:processing fee|training fee|background check fee|admin(?:istration)? fee|handling fee|application fee)\b/i,
    evidence: 'Processing or administrative fee demanded before service',
    strength: 0.93,
  },
  // Direct "send money / pay upfront" commands
  {
    pattern: /\b(?:pay upfront|pay (?:first|now|today|immediately)|send (?:money|cash|payment|the amount)|transfer (?:money|funds?|the amount|to (?:account|our)))\b/i,
    evidence: 'Explicit upfront payment instruction',
    strength: 0.92,
  },
  // Bank account transfer instructions
  {
    pattern: /\b(?:transfer (?:to|into)|deposit (?:to|into)|send (?:to|via)|pay (?:to|via)) (?:\w+\s+){0,4}(?:account|bank|wallet)\b/i,
    evidence: 'Direct bank account transfer instruction',
    strength: 0.88,
  },
  // "Pay to get started / to activate / to begin"
  {
    pattern: /\bpay(?:ment)?\s+(?:required|needed|necessary|must be made|to (?:start|begin|activate|unlock|access|claim|secure|confirm|proceed))\b/i,
    evidence: 'Payment required as a prerequisite to access opportunity',
    strength: 0.90,
  },
  // Singlish & informal variants: "denna" (give/pay in Sinhala)
  {
    pattern: /\b(?:fee\s+eka\s+(?:gewanna|denna|kathanawa)|reg(?:istration)?\s+fee\s+(?:pay|send|denna|gewanna))\b/i,
    evidence: 'Singlish/Sinhala payment demand detected (fee eka gewanna / denna)',
    strength: 0.95,
  },
  // Generic upfront / prepayment language
  {
    pattern: /\b(?:upfront|advance payment|prepayment|pay before|paid (?:first|in advance))\b/i,
    evidence: 'Generic advance payment language',
    strength: 0.88,
  },
]

/**
 * Detects advance payment demands in the given text.
 *
 * Returns the single strongest matching Finding, marked as critical.
 * A critical finding triggers STOP_AND_AVOID regardless of other signals.
 */
export function detectAdvancePayment(text: string): Finding[] {
  const matches: { evidence: string; strength: number }[] = []

  for (const { pattern, evidence, strength } of PAYMENT_PATTERNS) {
    if (pattern.test(text)) {
      matches.push({ evidence, strength })
    }
  }

  if (matches.length === 0) return []

  // Return the strongest match only — avoid flooding findings with duplicate payment signals
  matches.sort((a, b) => b.strength - a.strength)
  const best = matches[0]

  return [
    findingSchema.parse({
      canonicalSignal: 'advance_payment',
      category: 'Financial fraud',
      evidence: best.evidence,
      source: 'RULE',
      strength: best.strength,
      confidence: best.strength,
      limitation:
        'Keyword rule; legitimate payment requests (e.g. utility bills, official application fees) may also mention fees. Cross-verify with the official organisation website.',
    }),
  ]
}

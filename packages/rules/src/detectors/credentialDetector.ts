import { findingSchema, type Finding } from '@trustlens/contracts'

/**
 * CREDENTIAL REQUEST DETECTOR
 *
 * Detects demands for sensitive personal or financial authentication data.
 * This is the HIGHEST PRIORITY critical signal in TrustLens LK — no legitimate
 * bank, government body, or employer ever asks for OTPs, PINs, or passwords
 * via SMS, WhatsApp, or Telegram.
 *
 * NIST XAI Principle applied: any credential request is a hard override trigger.
 * Even if every other signal is absent, a single credential request
 * forces STOP_AND_AVOID.
 *
 * Examples:
 *   "Please share the OTP sent to your phone to verify your identity."
 *   "Provide your bank account PIN and password to cancel the transaction."
 *   "Send us your CVV number to confirm your card."
 *   "ඔබගේ OTP අංකය ලබා දෙන්න." (Sinhala: Please give your OTP)
 */

const CREDENTIAL_PATTERNS: { pattern: RegExp; evidence: string; strength: number }[] = [
  // OTP — One-Time Password (exact term or common abbreviations)
  {
    pattern: /\b(?:otp|one[- ]time\s+(?:password|pin|code)|verification\s+code|auth(?:entication)?\s+code)\b/i,
    evidence: 'OTP or one-time verification code requested',
    strength: 0.99,
  },
  // PIN — Personal Identification Number
  {
    pattern: /\b(?:your\s+)?(?:atm\s+)?pin(?:\s+number|\s+code)?\b(?!\s*eka\s+(?:hadanawa|type))/i,
    evidence: 'PIN or ATM PIN number requested',
    strength: 0.98,
  },
  // Password demands
  {
    pattern: /\b(?:your\s+)?(?:internet|online|mobile|e-?banking)?\s+password\b/i,
    evidence: 'Account password requested',
    strength: 0.99,
  },
  // Banking credentials — account numbers, card details
  {
    pattern: /\b(?:bank(?:ing)?\s+(?:details?|credentials?|information)|account\s+(?:number|details?|credentials?)|card\s+(?:number|details?|cvv|cvc|expiry))\b/i,
    evidence: 'Banking details or card information requested',
    strength: 0.97,
  },
  // CVV / CVC (card security code)
  {
    pattern: /\b(?:cvv|cvc|security\s+code|card\s+verification)\b/i,
    evidence: 'Card CVV or security code requested',
    strength: 0.99,
  },
  // Sharing / sending credential actions
  {
    pattern: /\b(?:share|send|provide|give|enter|type|submit|forward)\s+(?:your\s+)?(?:otp|pin|password|code|credentials?|details?)\b/i,
    evidence: 'Explicit instruction to share sensitive credentials',
    strength: 0.98,
  },
  // Sinhala language credential requests
  {
    pattern: /(?:otp|pin)\s+(?:eka\s+)?(?:denna|gewanna|liyanna|kathanawa|share\s+karanna)/i,
    evidence: 'Sinhala-language OTP or PIN sharing instruction detected',
    strength: 0.99,
  },
  // Singlish credential requests
  {
    pattern: /\b(?:otp|pin)\s+eka\s+(?:denna|send\s+karanna|share\s+karanna|kathanawa)\b/i,
    evidence: 'Singlish OTP or PIN demand detected',
    strength: 0.99,
  },
  // "Verify identity" via sensitive data
  {
    pattern: /\bverify\s+(?:your\s+)?(?:identity|account|card|details?)\s+(?:by\s+)?(?:sending|sharing|providing|entering)\b/i,
    evidence: 'Identity verification requested via credential sharing',
    strength: 0.95,
  },
  // Username + password combination
  {
    pattern: /\b(?:username|user\s+id|user\s+name)\s+(?:and|&|\+)\s+password\b/i,
    evidence: 'Username and password combination requested',
    strength: 0.99,
  },
]

/**
 * Detects credential and sensitive data requests in the given text.
 *
 * This is the highest-priority critical signal.
 * Returns the single strongest matching Finding.
 * Presence forces STOP_AND_AVOID in the main rules engine via critical override.
 */
export function detectCredentialRequest(text: string): Finding[] {
  const matches: { evidence: string; strength: number }[] = []

  for (const { pattern, evidence, strength } of CREDENTIAL_PATTERNS) {
    if (pattern.test(text)) {
      matches.push({ evidence, strength })
    }
  }

  if (matches.length === 0) return []

  // Return the single strongest credential finding
  matches.sort((a, b) => b.strength - a.strength)
  const best = matches[0]

  return [
    findingSchema.parse({
      canonicalSignal: 'credential_request',
      category: 'Sensitive information theft',
      evidence: best.evidence,
      source: 'RULE',
      strength: best.strength,
      confidence: best.strength,
      limitation:
        'No legitimate bank, employer, or government body requests OTPs, PINs, or passwords via SMS, WhatsApp, or Telegram. This signal has near-zero false positive rate.',
    }),
  ]
}

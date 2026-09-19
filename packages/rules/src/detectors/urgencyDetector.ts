import { findingSchema, type Finding } from '@trustlens/contracts'

/**
 * URGENCY DETECTOR
 *
 * Detects high-pressure, time-limited language commonly used in scam messages
 * to prevent the victim from thinking critically before acting.
 *
 * Examples:
 *   "Act now — offer expires today!"
 *   "Limited slots remaining, hurry!"
 *   "You must respond immediately or lose your opportunity."
 *   "Last chance — only 2 hours left!"
 */

const URGENCY_PATTERNS: { pattern: RegExp; evidence: string; strength: number }[] = [
  // Hard deadlines
  {
    pattern: /\b(?:expires?|expiring|expiry)\b/i,
    evidence: 'Expiry deadline language to pressure immediate action',
    strength: 0.60,
  },
  // Temporal pressure
  {
    pattern: /\b(?:act now|respond now|reply now|hurry|rush|fast|quickly|immediately|instant(?:ly)?)\b/i,
    evidence: 'Immediate action demand language',
    strength: 0.65,
  },
  // Today / time-bound urgency
  {
    pattern: /\b(?:today only|by today|before (?:\d+\s*(?:am|pm|hours?)|tonight|midnight)|within \d+\s*(?:minutes?|hours?|days?))\b/i,
    evidence: 'Time-bound urgency with specific deadline',
    strength: 0.70,
  },
  // Scarcity and last-chance
  {
    pattern: /\b(?:last chance|final (?:offer|call|notice)|limited (?:time|slots?|spots?|offer|seats?)|only \d+ (?:slot|spot|seat|place)s? (?:left|remaining|available))\b/i,
    evidence: 'Artificial scarcity language to create fear of missing out',
    strength: 0.70,
  },
  // Threat-based urgency
  {
    pattern: /\b(?:or (?:else|lose|miss|forfeit)|if you (?:don'?t|fail|ignore)|account (?:will be |will get )?(?:suspended|blocked|closed|deactivated))\b/i,
    evidence: 'Threat of loss or account suspension to force action',
    strength: 0.75,
  },
  // General urgency markers
  {
    pattern: /\burgent\b/i,
    evidence: 'Urgent marker in message',
    strength: 0.55,
  },
]

/**
 * Detects urgency and high-pressure language in the given text.
 * Returns a deduplicated list of Findings, one per distinct pattern matched.
 */
export function detectUrgency(text: string): Finding[] {
  const findings: Finding[] = []
  const seenEvidences = new Set<string>()

  for (const { pattern, evidence, strength } of URGENCY_PATTERNS) {
    if (pattern.test(text) && !seenEvidences.has(evidence)) {
      seenEvidences.add(evidence)
      findings.push(
        findingSchema.parse({
          canonicalSignal: 'urgency',
          category: 'Social engineering',
          evidence,
          source: 'RULE',
          strength,
          confidence: strength,
          limitation:
            'Keyword rule; legitimate urgent notices (e.g. bill reminders) may also trigger this signal. Context should be verified independently.',
        })
      )
    }
  }

  // Return the single strongest urgency finding to avoid noise
  if (findings.length === 0) return []
  findings.sort((a, b) => b.strength - a.strength)
  return [findings[0]]
}

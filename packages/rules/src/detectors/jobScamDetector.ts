import { findingSchema, type Finding } from '../../../../packages/contracts/src/index'

/**
 * JOB SCAM DETECTOR
 *
 * Detects fake job offer patterns — the primary scam type in Sri Lanka and
 * the core demonstration case for the CodeSplash hackathon.
 *
 * Job scams operate on a composite signal model:
 *   1. An attractive income promise (high salary, daily earnings, passive income)
 *   2. A zero-barrier entry claim (no experience / qualifications needed)
 *   3. A private-channel referral (WhatsApp / Telegram group, not an official site)
 *
 * Each sub-signal contributes independently, but the strength is weighted
 * higher when multiple sub-signals co-occur in the same message.
 *
 * Examples:
 *   "Earn Rs. 15,000 daily! No experience required. WhatsApp 0771234567."
 *   "Work from home, LKR 50,000 per month, anyone can apply. Call now."
 *   "Gedara idan salli hadana job. Reg fee 2500. WhatsApp karanna."
 */

// ---------------------------------------------------------------------------
// Sub-signal 1: Attractive income / financial reward promise
// ---------------------------------------------------------------------------
const INCOME_PROMISE_PATTERN =
  /\b(?:earn(?:ing)?s?|income|salary|wage|pay(?:out)?|profit|reward|bonus|daily|per\s+(?:day|week|month)|(?:lkr|rs\.?)\s*[\d,]+\s*(?:per|a|\/)\s*(?:day|week|month|hr|hour))\b/i

// ---------------------------------------------------------------------------
// Sub-signal 2: Zero-barrier entry (no experience / qualifications)
// ---------------------------------------------------------------------------
const NO_EXPERIENCE_PATTERN =
  /\b(?:no\s+(?:experience|qualification|degree|education|skills?|interview|exam)|anyone\s+can|all\s+are\s+welcome|freshers?\s+(?:welcome|eligible|can apply)|open\s+to\s+all|no\s+age\s+(?:limit|bar)|no\s+requirement)\b/i

// ---------------------------------------------------------------------------
// Sub-signal 3: Private channel referral (WhatsApp / Telegram / DM)
// ---------------------------------------------------------------------------
const PRIVATE_CHANNEL_PATTERN =
  /\b(?:whatsapp|telegram|viber|signal|inbox|dm\s+us|message\s+us|contact\s+(?:on|via|through)\s+(?:whatsapp|telegram|viber))\b/i

// ---------------------------------------------------------------------------
// Sub-signal 4: Remote / work-from-home framing
// ---------------------------------------------------------------------------
const REMOTE_WORK_PATTERN =
  /\b(?:work\s+from\s+home|remote\s+(?:job|work|position)|online\s+(?:job|work|earning)|home\s+based|gedara\s+idan|gharwale\s+kaam)\b/i

// ---------------------------------------------------------------------------
// Sub-signal 5: Job-specific vocabulary (hiring language)
// ---------------------------------------------------------------------------
const JOB_VOCAB_PATTERN =
  /\b(?:job\s+(?:offer|opportunity|vacancy|opening|available)|vacancy|hiring|recruitment|we(?:'re|\s+are)\s+hiring|position\s+(?:available|open|filled)|selected|shortlisted|chosen\s+for)\b/i

// ---------------------------------------------------------------------------
// Singlish composite job scam pattern
// ---------------------------------------------------------------------------
const SINGLISH_JOB_PATTERN =
  /\b(?:job\s+ekak|salary\s+eka|salli\s+hadanawa|work\s+ekak|vacancy\s+thiyanawa|earning\s+karanawa)\b/i

interface SubSignal {
  name: string
  matched: boolean
  strength: number
}

/**
 * Detects job scam patterns in the given text using a composite signal model.
 *
 * The final strength is derived from the number and quality of sub-signals matched:
 *   - 1 sub-signal alone: LOW contribution (0.40) — not enough alone
 *   - 2 sub-signals:      MEDIUM (0.60)
 *   - 3+ sub-signals:     HIGH (0.75) — classic job scam profile
 *
 * Returns one Finding if any job-scam sub-signal is detected, with strength
 * reflecting how many signals co-occurred.
 */
export function detectJobScam(text: string): Finding[] {
  const subSignals: SubSignal[] = [
    { name: 'income_promise', matched: INCOME_PROMISE_PATTERN.test(text), strength: 0.50 },
    { name: 'no_experience', matched: NO_EXPERIENCE_PATTERN.test(text), strength: 0.60 },
    { name: 'private_channel', matched: PRIVATE_CHANNEL_PATTERN.test(text), strength: 0.55 },
    { name: 'remote_work', matched: REMOTE_WORK_PATTERN.test(text), strength: 0.45 },
    { name: 'job_vocabulary', matched: JOB_VOCAB_PATTERN.test(text), strength: 0.50 },
    { name: 'singlish_job', matched: SINGLISH_JOB_PATTERN.test(text), strength: 0.60 },
  ]

  const matched = subSignals.filter((s) => s.matched)

  if (matched.length === 0) return []

  // Composite strength: increases with number of co-occurring signals
  let compositeStrength: number
  const matchCount = matched.length

  if (matchCount >= 3) {
    compositeStrength = 0.75 // Full job scam profile
  } else if (matchCount === 2) {
    compositeStrength = 0.60 // Suspicious but not conclusive alone
  } else {
    compositeStrength = 0.40 // Weak signal — requires other detectors to confirm
  }

  // Build evidence string listing matched sub-signals
  const signalNames = matched.map((s) => s.name.replace(/_/g, ' ')).join(', ')
  const evidence = `Job scam sub-signals matched: ${signalNames}`

  return [
    findingSchema.parse({
      canonicalSignal: 'job_offer',
      category: 'Fake employment offer',
      evidence,
      source: 'RULE',
      strength: compositeStrength,
      confidence: compositeStrength,
      limitation:
        'Composite keyword rule. Legitimate job postings may also mention WhatsApp contact or remote work. This signal is most meaningful when combined with advance_payment or credential_request findings.',
    }),
  ]
}

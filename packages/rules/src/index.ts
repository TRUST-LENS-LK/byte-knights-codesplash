import { type RiskDecision } from '../../../packages/contracts/src/index'
import { detectUrgency } from './detectors/urgencyDetector'
import { detectAdvancePayment } from './detectors/paymentDetector'
import { detectCredentialRequest } from './detectors/credentialDetector'
import { detectJobScam } from './detectors/jobScamDetector'

// ---------------------------------------------------------------------------
// Policy version — increment when rule logic changes significantly
// ---------------------------------------------------------------------------
const POLICY_VERSION = 'rules-v2'

// ---------------------------------------------------------------------------
// Critical signal names — their presence alone forces STOP_AND_AVOID
// ---------------------------------------------------------------------------
const CRITICAL_SIGNALS = new Set(['credential_request', 'advance_payment'])

// ---------------------------------------------------------------------------
// Safe action guidance by risk band
// ---------------------------------------------------------------------------
const SAFE_ACTIONS: Record<string, string[]> = {
  HIGH: [
    'Do not click any links, make any payments, or share any personal information.',
    'Verify directly through the organisation\'s official website or hotline.',
    'Report this message to Sri Lanka Police Cybercrime Division: 1930 or cybercrime@police.lk',
  ],
  MEDIUM: [
    'Do not act on this message until you have independently verified the sender.',
    'Search for the organisation\'s official contact details separately — do not use links in this message.',
    'If in doubt, call the organisation\'s official hotline directly.',
  ],
  LOW: [
    'No significant warning signs were detected, but always verify important requests independently.',
    'Never share OTPs, PINs, or passwords — no legitimate organisation will ask for them.',
  ],
  UNKNOWN: [
    'Insufficient information to make a determination. Treat with caution.',
    'Verify the sender through official channels before taking any action.',
  ],
}

// ---------------------------------------------------------------------------
// System limitations — always disclosed per NIST XAI principles
// ---------------------------------------------------------------------------
const SYSTEM_LIMITATIONS = [
  'This analysis uses deterministic keyword rules only. It does not have access to real-time domain verification or AI context analysis in offline mode.',
  'Legitimate messages may occasionally trigger false positives. Always apply independent judgement.',
  'Sinhala script (Unicode) detection is limited in the offline rules engine. Use the full analysis pipeline for Sinhala screenshots.',
]

// ---------------------------------------------------------------------------
// Main public API
// ---------------------------------------------------------------------------

/**
 * Analyses a text message for scam indicators using the deterministic rules engine.
 *
 * Decision logic:
 *   1. Run all 4 detectors in parallel (urgency, payment, credential, job).
 *   2. CRITICAL OVERRIDE: if credential_request OR advance_payment is detected,
 *      force riskBand=HIGH and recommendation=STOP_AND_AVOID regardless of
 *      other signals. This is the most important safety guarantee.
 *   3. Otherwise: riskBand is derived from the number and strength of findings:
 *      - 0 findings    → LOW  / PROCEED_CAUTIOUSLY
 *      - 1–2 findings  → MEDIUM / VERIFY_INDEPENDENTLY
 *      - 3+ findings   → HIGH  / STOP_AND_AVOID
 *
 * Returns a fully structured RiskDecision conforming to the shared contracts schema.
 */
export function analyzeMessage(text: string): RiskDecision {
  if (!text || text.trim().length === 0) {
    return {
      riskBand: 'UNKNOWN',
      recommendation: 'UNABLE_TO_VERIFY',
      findings: [],
      limitations: SYSTEM_LIMITATIONS,
      safeActions: SAFE_ACTIONS.UNKNOWN,
      policyVersion: POLICY_VERSION,
    }
  }

  // Run all detectors
  const allFindings = [
    ...detectCredentialRequest(text),  // Run first — highest priority
    ...detectAdvancePayment(text),
    ...detectUrgency(text),
    ...detectJobScam(text),
  ]

  // -------------------------------------------------------------------------
  // CRITICAL OVERRIDE: credential or payment demand → always STOP_AND_AVOID
  // -------------------------------------------------------------------------
  const hasCriticalSignal = allFindings.some((f) =>
    CRITICAL_SIGNALS.has(f.canonicalSignal)
  )

  if (hasCriticalSignal) {
    return {
      riskBand: 'HIGH',
      recommendation: 'STOP_AND_AVOID',
      findings: allFindings,
      limitations: SYSTEM_LIMITATIONS,
      safeActions: SAFE_ACTIONS.HIGH,
      policyVersion: POLICY_VERSION,
    }
  }

  // -------------------------------------------------------------------------
  // Standard risk banding (no critical signals present)
  // -------------------------------------------------------------------------
  const findingCount = allFindings.length
  const maxStrength = findingCount > 0
    ? Math.max(...allFindings.map((f) => f.strength))
    : 0

  let riskBand: RiskDecision['riskBand']
  let recommendation: RiskDecision['recommendation']

  if (findingCount === 0) {
    riskBand = 'LOW'
    recommendation = 'PROCEED_CAUTIOUSLY'
  } else if (findingCount >= 3 || maxStrength >= 0.75) {
    riskBand = 'HIGH'
    recommendation = 'STOP_AND_AVOID'
  } else {
    riskBand = 'MEDIUM'
    recommendation = 'VERIFY_INDEPENDENTLY'
  }

  return {
    riskBand,
    recommendation,
    findings: allFindings,
    limitations: SYSTEM_LIMITATIONS,
    safeActions: SAFE_ACTIONS[riskBand],
    policyVersion: POLICY_VERSION,
  }
}


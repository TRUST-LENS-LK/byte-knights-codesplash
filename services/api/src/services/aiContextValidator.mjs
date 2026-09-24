import { GEMINI_API_KEY } from '../config/env.mjs'

const GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent'
const REQUEST_TIMEOUT_MS = 8_000
const MAX_TEXT_LENGTH = 2_000

// In-memory rate limit / failure cooldown guard (60 seconds)
let lastFailureTimestamp = 0
const COOLDOWN_MS = 60_000

/**
 * Checks whether Layer 5 AI context validation is configured and healthy.
 */
export function isAiValidationConfigured() {
  return Boolean(GEMINI_API_KEY)
}

/**
 * Checks if compound critical signals exist that must HARD BLOCK any AI downgrade.
 * Anti-spoofing rule: AI can never override confirmed active credential harvesting
 * combined with payment demands, domain mismatches, or known malicious domains.
 */
export function isHardBlockedFromAiDowngrade(decision, intelligenceOverlay) {
  if (!decision || !Array.isArray(decision.findings)) return false

  const signals = new Set(decision.findings.map((f) => f.canonicalSignal))

  // Hard Block 1: Both credential request AND advance payment present
  if (signals.has('credential_request') && signals.has('advance_payment')) {
    return true
  }

  // Hard Block 2: Domain mismatch / spoofing detected
  if (signals.has('domain_mismatch')) {
    return true
  }

  // Hard Block 3: Known malicious domain (Google Safe Browsing hit)
  if (signals.has('known_malicious_domain')) {
    return true
  }

  // Hard Block 4: Verified community intelligence confirmed scam
  if (intelligenceOverlay?.netVerdict === 'CONFIRMED_SCAM') {
    return true
  }

  return false
}

/**
 * Formats a clean prompt for Gemini API focusing on context evaluation.
 */
function buildGeminiPrompt(text, findings, languageHint) {
  const truncatedText = text.slice(0, MAX_TEXT_LENGTH)
  const findingsSummary = findings.map((f) => `- ${f.canonicalSignal || f.category} (strength: ${f.strength || 0.5}): ${f.evidence || 'detected'}`).join('\n')

  return `You are a Sri Lankan cyber threat and scam detection expert for TrustLens LK.
A deterministic rule engine analyzed a user message and flagged threat signals.

MESSAGE TO ANALYZE:
"""
${truncatedText}
"""
Language Hint: ${languageHint || 'Auto-detect (Sinhala, Singlish, Tamil, or English)'}

RULE ENGINE FINDINGS:
${findingsSummary || '- General high-risk pattern detected'}

TASK:
Analyze the full context of the message. Is this message genuinely a scam, phishing attempt, or social engineering attack targeting the reader?
Or is this high-risk vocabulary (e.g. "OTP", "payment", "fee", "verify", "account") being used in a benign, official, informational, or internal business context where the reader is NOT being tricked into losing money or credentials?

Respond STRICTLY in valid JSON matching this exact structure (no Markdown block wrappers, no preamble):
{
  "verdict": "AGREE" | "DISAGREE" | "UNCERTAIN",
  "confidence": 0.85,
  "reasoning": "One concise sentence explaining why the message context is benign or malicious."
}`
}

/**
 * Calls the Google Gemini API to evaluate context.
 * Fails open: Returns null on timeout, missing key, or API errors.
 */
export async function evaluateContextWithAi({ text, decision, languageHint = null }) {
  if (!isAiValidationConfigured()) return null

  // Skip AI evaluation for LOW risk messages to minimize latency and API cost
  if (!decision || decision.riskBand === 'LOW') return null

  // Cooldown check if recent call failed
  if (Date.now() - lastFailureTimestamp < COOLDOWN_MS) {
    return null
  }

  try {
    const prompt = buildGeminiPrompt(text, decision.findings || [], languageHint)
    const url = `${GEMINI_API_URL}?key=${encodeURIComponent(GEMINI_API_KEY)}`

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        contents: [
          {
            parts: [{ text: prompt }],
          },
        ],
        generationConfig: {
          temperature: 0.1,
          responseMimeType: 'application/json',
        },
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    })

    if (!response.ok) {
      lastFailureTimestamp = Date.now()
      return null
    }

    const data = await response.json()
    const contentText = data?.candidates?.[0]?.content?.parts?.[0]?.text
    if (!contentText) {
      return null
    }

    const parsed = JSON.parse(contentText)
    const validVerdicts = ['AGREE', 'DISAGREE', 'UNCERTAIN']
    const verdict = validVerdicts.includes(parsed.verdict) ? parsed.verdict : 'UNCERTAIN'
    const confidence = typeof parsed.confidence === 'number' ? Math.min(1, Math.max(0, parsed.confidence)) : 0.5
    const reasoning = parsed.reasoning || 'AI context evaluation complete.'

    return {
      verdict,
      confidence,
      reasoning,
      evaluatedAt: new Date().toISOString(),
    }
  } catch (error) {
    lastFailureTimestamp = Date.now()
    return null
  }
}

/**
 * Applies the AI context validation verdict to the decision object.
 * Enforces one-step maximum downgrades and fail-closed hard blocks.
 */
export function applyAiVerdict(decision, aiResult, intelligenceOverlay = null) {
  if (!decision || !aiResult) return decision

  const originalRiskBand = decision.riskBand
  const trace = decision.reconciliationTrace || []

  // Check hard block
  const hardBlocked = isHardBlockedFromAiDowngrade(decision, intelligenceOverlay)

  if (hardBlocked) {
    trace.push(`[AI Context Layer]: AI returned '${aiResult.verdict}' (${Math.round(aiResult.confidence * 100)}% confidence), but downgrade was HARD BLOCKED due to compound critical threat signals. Original verdict ${originalRiskBand} retained.`)
    return {
      ...decision,
      reconciliationTrace: trace,
      aiValidation: {
        ...aiResult,
        originalRiskBand,
        adjustedRiskBand: originalRiskBand,
        appliedAction: 'HARD_BLOCKED',
      },
    }
  }

  // Handle DISAGREE (Soft Downgrade)
  if (aiResult.verdict === 'DISAGREE' && aiResult.confidence >= 0.75) {
    let newRiskBand = originalRiskBand
    if (originalRiskBand === 'HIGH') {
      newRiskBand = 'MEDIUM'
    } else if (originalRiskBand === 'MEDIUM') {
      newRiskBand = 'LOW'
    }

    if (newRiskBand !== originalRiskBand) {
      trace.push(`[AI Context Layer]: AI context analysis detected benign language usage ("${aiResult.reasoning}"). Risk band downgraded from ${originalRiskBand} to ${newRiskBand}.`)

      decision.riskBand = newRiskBand
      decision.overridesApplied = [...(decision.overridesApplied || []), 'ai_context_downgrade']

      if (newRiskBand === 'MEDIUM') {
        decision.recommendation = 'PROCEED_WITH_CAUTION'
      } else if (newRiskBand === 'LOW') {
        decision.recommendation = 'SAFE_TO_PROCEED'
      }

      return {
        ...decision,
        reconciliationTrace: trace,
        aiValidation: {
          ...aiResult,
          originalRiskBand,
          adjustedRiskBand: newRiskBand,
          appliedAction: 'DOWNGRADED',
        },
      }
    }
  }

  // Handle AGREE or UNCERTAIN
  if (aiResult.verdict === 'AGREE') {
    trace.push(`[AI Context Layer]: AI context analysis confirmed rule-engine verdict as genuine threat (${aiResult.reasoning}).`)
  } else {
    trace.push(`[AI Context Layer]: AI context evaluation uncertain (${aiResult.reasoning}). Original verdict retained.`)
  }

  return {
    ...decision,
    reconciliationTrace: trace,
    aiValidation: {
      ...aiResult,
      originalRiskBand,
      adjustedRiskBand: originalRiskBand,
      appliedAction: 'RETAINED',
    },
  }
}

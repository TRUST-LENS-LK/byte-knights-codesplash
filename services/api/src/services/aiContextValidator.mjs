import { GEMINI_API_KEY } from '../config/env.mjs'

const GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent'
const REQUEST_TIMEOUT_MS = 12_000
const MAX_TEXT_LENGTH = 2_000

// In-memory failure cooldown guard (5 seconds)
let lastFailureTimestamp = 0
const COOLDOWN_MS = 5_000

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
function buildGeminiPrompt(text = '', findings = [], languageHint = '', riskBand = 'LOW') {
  const safeText = String(text || '')
  const truncatedText = safeText.slice(0, MAX_TEXT_LENGTH)
  const safeFindings = Array.isArray(findings) ? findings : []
  const findingsSummary = safeFindings.length > 0
    ? safeFindings.map((f) => `- ${f?.canonicalSignal || f?.category || 'signal'} (strength: ${f?.strength || 0.5}): ${f?.evidence || 'detected'}`).join('\n')
    : '- No high-risk threat signals flagged by deterministic rule engine.'

  return `You are a Sri Lankan cyber threat and scam detection expert for TrustLens LK.
A deterministic rule engine analyzed a user message and reached a preliminary risk level of: ${riskBand}

MESSAGE TO ANALYZE:
"""
${truncatedText}
"""
Language Hint: ${languageHint || 'Auto-detect (Sinhala, Singlish, Tamil, or English)'}

RULE ENGINE FINDINGS:
${findingsSummary}

TASK:
Analyze the full context of the message. The rule engine assigned it a risk level of ${riskBand}. Do you AGREE or DISAGREE with this overall risk level?
- If the rule engine evaluated it as HIGH/MEDIUM risk, but you determine the context is actually safe/benign (e.g. an official bank warning), output "DISAGREE".
- If the rule engine evaluated it as LOW risk, but you determine the message is actually a dangerous scam/phishing attempt, output "DISAGREE".
- Otherwise, if your assessment aligns with the rule engine's risk level, output "AGREE".

Respond STRICTLY in valid JSON matching this exact structure (no Markdown block wrappers, no preamble):
{
  "verdict": "AGREE" | "DISAGREE" | "UNCERTAIN",
  "confidence": 0.85,
  "reasoning": "One concise sentence explaining why the message context is benign or malicious."
}`
}

const GEMINI_MODELS = [
  'gemini-flash-lite-latest',
  'gemini-3.5-flash-lite',
  'gemini-3.6-flash',
  'gemini-3.1-flash-lite',
  'gemini-3.5-flash',
]

/**
 * Calls the Google Gemini API to evaluate context for all inputs.
 * Fails open: Returns null on timeout, missing key, or API errors.
 */
async function fetchModel(modelName, prompt) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.1,
        responseMimeType: 'application/json',
      },
    }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  })

  if (!response.ok) {
    throw new Error(`Model ${modelName} returned status ${response.status}`)
  }

  const data = await response.json()
  const contentText = data?.candidates?.[0]?.content?.parts?.[0]?.text
  if (!contentText) {
    throw new Error(`Model ${modelName} returned empty candidate text`)
  }

  let cleanJsonText = contentText.trim()
  if (cleanJsonText.startsWith('```')) {
    cleanJsonText = cleanJsonText.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim()
  }
  if (!cleanJsonText.startsWith('{')) {
    const match = contentText.match(/\{[\s\S]*\}/)
    if (match) cleanJsonText = match[0]
  }

  const parsed = JSON.parse(cleanJsonText)
  const validVerdicts = ['AGREE', 'DISAGREE', 'UNCERTAIN']
  const verdict = validVerdicts.includes(parsed.verdict) ? parsed.verdict : 'UNCERTAIN'
  const confidence = typeof parsed.confidence === 'number' ? Math.min(1, Math.max(0, parsed.confidence)) : 0.5
  const reasoning = parsed.reasoning || 'AI context evaluation complete.'

  lastFailureTimestamp = 0
  return {
    verdict,
    confidence,
    reasoning,
    evaluatedAt: new Date().toISOString(),
  }
}

export async function evaluateContextWithAi({ text = '', decision, languageHint = null }) {
  if (!isAiValidationConfigured()) return null
  if (!decision) return null

  const safeText = String(text || '').trim()
  if (!safeText) return null

  const prompt = buildGeminiPrompt(safeText, decision.findings || [], languageHint, decision.riskBand)

  // Use Promise.any to race the top 3 models concurrently to reduce latency
  const modelsToRace = GEMINI_MODELS.slice(0, 3)
  
  try {
    return await Promise.any(
      modelsToRace.map(modelName => fetchModel(modelName, prompt))
    )
  } catch (aggregateError) {
    console.error(`[AI Validator Exception] All concurrent models failed:`, aggregateError)
    
    // Fallback if all models fail
    return {
      verdict: 'UNCERTAIN',
      confidence: 0,
      reasoning: `AI context evaluation temporarily unavailable (Concurrent requests failed).`,
      evaluatedAt: new Date().toISOString(),
    }
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

  // Handle DISAGREE (Soft Downgrade or Upgrade)
  if (aiResult.verdict === 'DISAGREE' && aiResult.confidence >= 0.75) {
    let newRiskBand = originalRiskBand
    let action = 'DOWNGRADED'
    
    // Downgrade logic
    if (originalRiskBand === 'HIGH') {
      newRiskBand = 'MEDIUM'
    } else if (originalRiskBand === 'MEDIUM') {
      newRiskBand = 'LOW'
    } 
    // Upgrade logic
    else if (originalRiskBand === 'LOW') {
      newRiskBand = 'HIGH'
      action = 'UPGRADED'
    }

    if (newRiskBand !== originalRiskBand) {
      if (action === 'UPGRADED') {
        trace.push(`[AI Context Layer]: AI context analysis detected hidden threat not caught by rules ("${aiResult.reasoning}"). Risk band UPGRADED from ${originalRiskBand} to ${newRiskBand}.`)
        decision.recommendation = 'STOP_AND_AVOID'
        decision.overridesApplied = [...(decision.overridesApplied || []), 'ai_context_upgrade']
      } else {
        trace.push(`[AI Context Layer]: AI context analysis detected benign language usage ("${aiResult.reasoning}"). Risk band DOWNGRADED from ${originalRiskBand} to ${newRiskBand}.`)
        if (newRiskBand === 'MEDIUM') {
          decision.recommendation = 'PROCEED_WITH_CAUTION'
        } else if (newRiskBand === 'LOW') {
          decision.recommendation = 'SAFE_TO_PROCEED'
        }
        decision.overridesApplied = [...(decision.overridesApplied || []), 'ai_context_downgrade']
      }

      decision.riskBand = newRiskBand

      return {
        ...decision,
        reconciliationTrace: trace,
        aiValidation: {
          ...aiResult,
          originalRiskBand,
          adjustedRiskBand: newRiskBand,
          appliedAction: action,
        },
      }
    }
  }

  // Handle AGREE, UNCERTAIN, or LOW risk band
  if (aiResult.verdict === 'AGREE') {
    if (originalRiskBand === 'LOW') {
      trace.push(`[AI Context Layer]: AI context evaluation confirmed message is safe and benign ("${aiResult.reasoning}").`)
    } else {
      trace.push(`[AI Context Layer]: AI context analysis confirmed rule-engine verdict as genuine threat ("${aiResult.reasoning}").`)
    }
  } else if (originalRiskBand === 'LOW') {
    trace.push(`[AI Context Layer]: AI context evaluation evaluated message ("${aiResult.reasoning}").`)
  } else {
    trace.push(`[AI Context Layer]: AI context evaluation complete ("${aiResult.reasoning}"). Original verdict retained.`)
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

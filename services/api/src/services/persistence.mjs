import { createHash } from 'node:crypto'
import { SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL } from '../config/env.mjs'

const PERSISTENCE_TIMEOUT_MS = 8_000

function requestOptions(headers, body) {
  return { method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(PERSISTENCE_TIMEOUT_MS) }
}

export async function persistIfConsented(body, decision, entities) {
  if (body.retentionConsent !== true || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return null
  const headers = { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`, 'content-type': 'application/json', Prefer: 'return=representation' }
  const hash = createHash('sha256').update(body.text).digest('hex')
  const response = await fetch(`${SUPABASE_URL}/rest/v1/submissions`, requestOptions(headers, { submission_type: body.type || 'message', content_sha256: hash, raw_text: body.text, language_hint: body.languageHint || null, retention_consent: true, risk_band: decision.riskBand, recommendation: decision.recommendation, policy_version: decision.policyVersion }))
  if (!response.ok) throw new Error('Supabase persistence failed')
  const [submission] = await response.json()
  if (submission?.id) {
    try {
      if (entities.length) {
        const entityResponse = await fetch(`${SUPABASE_URL}/rest/v1/extracted_entities`, requestOptions(headers, entities.map((entity) => ({ submission_id: submission.id, entity_type: entity.type, value: entity.value, normalized_value: entity.normalizedValue || null, confidence: entity.confidence || null }))))
        if (!entityResponse.ok) throw new Error('Supabase entity persistence failed')
      }
      if (decision.findings.length) {
        const findingResponse = await fetch(`${SUPABASE_URL}/rest/v1/findings`, requestOptions(headers, decision.findings.map((finding) => ({ submission_id: submission.id, canonical_signal: finding.canonicalSignal, category: finding.category, evidence: finding.evidence, source: finding.source, strength: finding.strength, confidence: finding.confidence, limitation: finding.limitation }))))
        if (!findingResponse.ok) throw new Error('Supabase finding persistence failed')
      }
    } catch (error) {
      await fetch(`${SUPABASE_URL}/rest/v1/submissions?id=eq.${encodeURIComponent(submission.id)}`, { method: 'DELETE', headers, signal: AbortSignal.timeout(PERSISTENCE_TIMEOUT_MS) })
      throw error
    }
  }
  return submission?.id || null
}

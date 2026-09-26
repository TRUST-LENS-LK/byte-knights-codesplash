import { createHash } from 'node:crypto'
import { SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL } from '../config/env.mjs'

const PERSISTENCE_TIMEOUT_MS = 8_000

// Default retention window for a consented submission. Matches the 90-day
// cadence already used for domain-directory review, kept here rather than in
// the schema so the policy can be adjusted without a migration.
const SUBMISSION_RETENTION_DAYS = 90

function requestOptions(headers, body) {
  return { method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(PERSISTENCE_TIMEOUT_MS) }
}

function defaultExpiryDate() {
  return new Date(Date.now() + SUBMISSION_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString()
}

export async function persistIfConsented(body, decision, entities) {
  if (body.retentionConsent !== true || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return null
  const headers = { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`, 'content-type': 'application/json', Prefer: 'return=representation' }
  const hash = createHash('sha256').update(body.text).digest('hex')
  const response = await fetch(`${SUPABASE_URL}/rest/v1/submissions`, requestOptions(headers, { submission_type: body.type || 'message', content_sha256: hash, raw_text: body.text, language_hint: body.languageHint || null, retention_consent: true, risk_band: decision.riskBand, recommendation: decision.recommendation, policy_version: decision.policyVersion, expires_at: defaultExpiryDate() }))
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

/**
 * Deletes submissions whose expires_at has passed. extracted_entities and
 * findings cascade-delete with their parent submission (see the foreign key
 * definitions in the initial schema migration), so this alone is enough to
 * remove a submission's full trace. Returns the number of rows deleted, or
 * null when Supabase is not configured, so callers can log or test the
 * outcome without needing to inspect Supabase directly.
 */
export async function purgeExpiredSubmissions(now = new Date()) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return null
  const headers = { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`, Prefer: 'return=representation' }
  const params = new URLSearchParams({ expires_at: `lt.${now.toISOString()}` })
  const response = await fetch(`${SUPABASE_URL}/rest/v1/submissions?${params}`, {
    method: 'DELETE',
    headers,
    signal: AbortSignal.timeout(PERSISTENCE_TIMEOUT_MS),
  })
  if (!response.ok) throw new Error('Supabase retention purge failed')
  const deleted = await response.json()
  return Array.isArray(deleted) ? deleted.length : 0
}

export async function persistReport(body) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return null
  const headers = { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`, 'content-type': 'application/json', Prefer: 'return=representation' }
  const response = await fetch(`${SUPABASE_URL}/rest/v1/user_reports`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ report_type: body.reportType, content_sha256: createHash('sha256').update(body.text).digest('hex'), reported_domain: body.reportedDomain?.trim().toLowerCase() || null, notes: body.notes?.trim() || null, status: 'PENDING' }),
    signal: AbortSignal.timeout(PERSISTENCE_TIMEOUT_MS),
  })
  if (!response.ok) throw new Error('Supabase report persistence failed')
  const [report] = await response.json()
  return report?.id || null
}

import { createServer } from 'node:http'
import { randomUUID, createHash } from 'node:crypto'
import { readFileSync, existsSync } from 'node:fs'

if (existsSync(new URL('../.env', import.meta.url))) {
  for (const line of readFileSync(new URL('../.env', import.meta.url), 'utf8').split(/\r?\n/)) {
    const match = line.match(/^([A-Z0-9_]+)=(.*)$/)
    if (match && !process.env[match[1]]) process.env[match[1]] = match[2].trim().replace(/^['"]|['"]$/g, '')
  }
}

const PORT = Number(process.env.PORT || 8787)
const MAX_TEXT = 10000
const patterns = [
  ['credential_request', 'Sensitive information', /otp|one[- ]time password|pin|password|bank(?:ing)? details?/i, 'OTP, PIN, password, or banking details', 0.98],
  ['advance_payment', 'Financial request', /registration fee|upfront|deposit|send (?:rs\.?|lkr)|payment|pay today|transfer/i, 'Payment or upfront-fee language', 0.95],
  ['urgency', 'Social engineering', /urgent|immediately|today|expires|act now|last chance/i, 'Urgent timing language', 0.55],
  ['job_offer', 'Job scam', /job|salary|vacancy|work from home|hiring|selected/i, 'Recruitment or job-offer language', 0.65],
]

function extractEntities(text) {
  const entities = []
  for (const match of text.matchAll(/https?:\/\/[^\s]+/gi)) entities.push({ type: 'url', value: match[0].replace(/[),.!?]+$/, ''), confidence: 0.99 })
  for (const match of text.matchAll(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g)) entities.push({ type: 'email', value: match[0], confidence: 0.99 })
  for (const match of text.matchAll(/(?:\+94|0)\s*\d{2}\s*\d{3}\s*\d{4}/g)) entities.push({ type: 'phone', value: match[0], normalizedValue: match[0].replace(/\s+/g, '').replace(/^0/, '+94'), confidence: 0.95 })
  for (const match of text.matchAll(/(?:Rs\.?|LKR)\s?[\d,]+(?:\.\d{1,2})?/gi)) entities.push({ type: 'amount', value: match[0], confidence: 0.94 })
  return entities
}

function analyze(text) {
  const findings = patterns.filter(([, , pattern]) => pattern.test(text)).map(([canonicalSignal, category, , evidence, strength]) => ({ canonicalSignal, category, evidence, source: 'RULE', strength, confidence: strength, limitation: 'Keyword rule; context should be verified independently.' }))
  const critical = findings.some((item) => ['credential_request', 'advance_payment'].includes(item.canonicalSignal))
  const riskBand = critical || findings.length >= 3 ? 'HIGH' : findings.length ? 'MEDIUM' : 'LOW'
  return { riskBand, recommendation: riskBand === 'HIGH' ? 'STOP_AND_AVOID' : riskBand === 'MEDIUM' ? 'VERIFY_INDEPENDENTLY' : 'PROCEED_CAUTIOUSLY', findings, limitations: ['This local prototype uses deterministic rules only.'], safeActions: riskBand === 'HIGH' ? ['Do not click, pay, reply, or share credentials.', 'Verify through the organisation’s official website.'] : ['Verify the sender and organisation independently.'], policyVersion: 'rules-v1' }
}

async function persistIfConsented(body, decision, entities) {
  if (body.retentionConsent !== true || !process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) return null
  const headers = { apikey: process.env.SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`, 'content-type': 'application/json', Prefer: 'return=representation' }
  const hash = createHash('sha256').update(body.text).digest('hex')
  const response = await fetch(`${process.env.SUPABASE_URL}/rest/v1/submissions`, { method: 'POST', headers, body: JSON.stringify({ submission_type: body.type || 'message', content_sha256: hash, raw_text: body.text, language_hint: body.languageHint || null, retention_consent: true, risk_band: decision.riskBand, recommendation: decision.recommendation, policy_version: decision.policyVersion }) })
  if (!response.ok) throw new Error('Supabase persistence failed')
  const [submission] = await response.json()
  if (submission?.id) {
    if (entities.length) await fetch(`${process.env.SUPABASE_URL}/rest/v1/extracted_entities`, { method: 'POST', headers, body: JSON.stringify(entities.map((entity) => ({ submission_id: submission.id, entity_type: entity.type, value: entity.value, normalized_value: entity.normalizedValue || null, confidence: entity.confidence || null }))) })
    if (decision.findings.length) await fetch(`${process.env.SUPABASE_URL}/rest/v1/findings`, { method: 'POST', headers, body: JSON.stringify(decision.findings.map((finding) => ({ submission_id: submission.id, canonical_signal: finding.canonicalSignal, category: finding.category, evidence: finding.evidence, source: finding.source, strength: finding.strength, confidence: finding.confidence, limitation: finding.limitation }))) })
  }
  return submission?.id || null
}

function send(res, status, body) { res.writeHead(status, { 'content-type': 'application/json', 'access-control-allow-origin': 'http://localhost:5173' }); res.end(JSON.stringify(body)) }
const server = createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return send(res, 204, {})
  if (req.method === 'GET' && req.url === '/health') return send(res, 200, { status: 'ok', service: 'trustlens-functions' })
  if (req.method !== 'POST' || req.url !== '/api/analyze') return send(res, 404, { code: 'NOT_FOUND', message: 'Route not found.' })
  let raw = ''; for await (const chunk of req) { raw += chunk; if (raw.length > 15000) return send(res, 413, { code: 'PAYLOAD_TOO_LARGE', message: 'Request body is too large.' }) }
  try {
    const body = JSON.parse(raw || '{}'); const text = typeof body.text === 'string' ? body.text.trim() : ''
    if (!text || text.length > MAX_TEXT) return send(res, 400, { code: 'INVALID_SUBMISSION', message: 'text is required and must be at most 10,000 characters.' })
    const decision = analyze(text); const entities = extractEntities(text); const submissionId = await persistIfConsented({ ...body, text }, decision, entities)
    return send(res, 200, { decision, entities, inputType: entities.some((item) => item.type === 'url') ? 'url' : 'message', requestId: randomUUID(), ...(submissionId ? { submissionId } : {}) })
  } catch (error) { return send(res, error instanceof SyntaxError ? 400 : 502, { code: error instanceof SyntaxError ? 'INVALID_JSON' : 'PERSISTENCE_ERROR', message: error instanceof SyntaxError ? 'Request body must be valid JSON.' : 'Analysis completed, but persistence is temporarily unavailable.' }) }
})
server.listen(PORT, () => console.log(`TrustLens API listening on http://localhost:${PORT}`))

import { createServer } from 'node:http'
import { randomUUID } from 'node:crypto'
import { MAX_BODY_BYTES, MAX_TEXT, PORT } from './config/env.mjs'
import { send } from './http/response.mjs'
import { analyze, extractEntities, validateSubmission } from './services/analysis.mjs'
import { persistIfConsented } from './services/persistence.mjs'
import { consumeRateLimit } from './services/rateLimit.mjs'
import { verifyApprovedDomains } from './services/domainVerification.mjs'

const server = createServer(async (req, res) => {
  const requestId = randomUUID()
  if (req.method === 'OPTIONS') return send(res, 204, {}, requestId)
  if (req.method === 'GET' && req.url === '/health') return send(res, 200, { status: 'ok', service: 'trustlens-api', requestId }, requestId)
  if (req.method !== 'POST' || req.url !== '/api/analyze') return send(res, 404, { code: 'NOT_FOUND', message: 'Route not found.', requestId }, requestId)
  if (!String(req.headers['content-type'] || '').toLowerCase().includes('application/json')) return send(res, 415, { code: 'UNSUPPORTED_MEDIA_TYPE', message: 'Content-Type must be application/json.', requestId }, requestId)

  const rateLimit = consumeRateLimit(req)
  res.setHeader('ratelimit-limit', String(rateLimit.limit))
  res.setHeader('ratelimit-remaining', String(rateLimit.remaining))
  res.setHeader('ratelimit-reset', String(Math.ceil(rateLimit.resetAt / 1000)))
  if (!rateLimit.allowed) {
    res.setHeader('retry-after', String(rateLimit.retryAfter))
    return send(res, 429, { code: 'RATE_LIMITED', message: 'Too many analysis requests. Try again later.', requestId }, requestId)
  }

  const contentLength = Number(req.headers['content-length'] || 0)
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) return send(res, 413, { code: 'PAYLOAD_TOO_LARGE', message: 'Request body is too large.', requestId }, requestId)
  let raw = ''
  let receivedBytes = 0
  for await (const chunk of req) {
    receivedBytes += Buffer.byteLength(chunk)
    if (receivedBytes > MAX_BODY_BYTES) return send(res, 413, { code: 'PAYLOAD_TOO_LARGE', message: 'Request body is too large.', requestId }, requestId)
    raw += chunk
  }

  try {
    const body = JSON.parse(raw || '{}')
    const validationError = validateSubmission(body)
    if (validationError) return send(res, 400, { code: 'INVALID_SUBMISSION', message: validationError, requestId }, requestId)
    const text = typeof body.text === 'string' ? body.text.trim() : ''
    if (!text || text.length > MAX_TEXT) return send(res, 400, { code: 'INVALID_SUBMISSION', message: 'text is required and must be at most 10,000 characters.', requestId }, requestId)
    const entities = extractEntities(text)
    const decision = analyze(text)
    const approvedDomainFindings = await verifyApprovedDomains(entities)
    if (approvedDomainFindings.length) decision.findings.push(...approvedDomainFindings)
    const submissionId = await persistIfConsented({ ...body, text }, decision, entities)
    return send(res, 200, { decision, entities, inputType: body.type === 'url' || entities.some((item) => item.type === 'url') ? 'url' : 'message', requestId, ...(submissionId ? { submissionId } : {}) }, requestId)
  } catch (error) {
    return send(res, error instanceof SyntaxError ? 400 : 502, { code: error instanceof SyntaxError ? 'INVALID_JSON' : 'PERSISTENCE_ERROR', message: error instanceof SyntaxError ? 'Request body must be valid JSON.' : 'Analysis completed, but persistence is temporarily unavailable.', requestId }, requestId)
  }
})

server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`TrustLens API cannot start: port ${PORT} is already in use.`)
    process.exitCode = 1
    return
  }
  console.error('TrustLens API server error:', error)
  process.exitCode = 1
})

function shutdown(signal) {
  console.log(`${signal} received; shutting down TrustLens API.`)
  server.close(() => process.exit(0))
}

process.once('SIGINT', () => shutdown('SIGINT'))
process.once('SIGTERM', () => shutdown('SIGTERM'))
server.listen(PORT, () => console.log(`TrustLens API listening on http://localhost:${PORT}`))

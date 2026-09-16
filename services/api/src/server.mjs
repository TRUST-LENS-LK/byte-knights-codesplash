import { createServer } from 'node:http'
import { randomUUID, createHash } from 'node:crypto'
import { MAX_BODY_BYTES, MAX_TEXT, PORT } from './config/env.mjs'
import { send } from './http/response.mjs'
import { authorizeModerator } from './http/auth.mjs'
import { analyze, extractEntities, validateSubmission } from './services/analysis.mjs'
import { persistIfConsented } from './services/persistence.mjs'
import { consumeRateLimit } from './services/rateLimit.mjs'
import { verifyApprovedDomains } from './services/domainVerification.mjs'
import {
  checkVerifiedIntelligence,
  getModerationQueue,
  processModerationReview,
  submitReport,
  validateCreateReport,
  validateModerationAction,
} from './services/reportingService.mjs'
import { getOpenApiSpec, getSwaggerHtml } from './http/swagger.mjs'

const server = createServer(async (req, res) => {
  const requestId = randomUUID()
  const parsedUrl = new URL(req.url, 'http://localhost')
  const pathname = parsedUrl.pathname

  if (req.method === 'OPTIONS') return send(res, 204, {}, requestId)
  if (req.method === 'GET' && pathname === '/health') return send(res, 200, { status: 'ok', service: 'trustlens-api', requestId }, requestId)
  if (req.method === 'GET' && pathname === '/docs') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    return res.end(getSwaggerHtml())
  }
  if (req.method === 'GET' && pathname === '/openapi.json') {
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' })
    return res.end(JSON.stringify(getOpenApiSpec(), null, 2))
  }


  // Moderation Queue (Protected GET)
  if (req.method === 'GET' && pathname === '/api/moderation/queue') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    try {
      const statusParam = parsedUrl.searchParams.get('status') || 'PENDING'
      const reports = await getModerationQueue(statusParam)
      return send(res, 200, { reports, count: reports.length, status: statusParam, requestId }, requestId)
    } catch (error) {
      return send(res, 502, { code: 'QUEUE_FETCH_ERROR', message: error.message, requestId }, requestId)
    }
  }

  // Routes below require POST
  const validPostRoutes = ['/api/analyze', '/api/reports', '/api/moderation/review']
  if (req.method !== 'POST' || !validPostRoutes.includes(pathname)) {
    return send(res, 404, { code: 'NOT_FOUND', message: 'Route not found.', requestId }, requestId)
  }

  if (!String(req.headers['content-type'] || '').toLowerCase().includes('application/json')) {
    return send(res, 415, { code: 'UNSUPPORTED_MEDIA_TYPE', message: 'Content-Type must be application/json.', requestId }, requestId)
  }

  const rateLimit = consumeRateLimit(req)
  res.setHeader('ratelimit-limit', String(rateLimit.limit))
  res.setHeader('ratelimit-remaining', String(rateLimit.remaining))
  res.setHeader('ratelimit-reset', String(Math.ceil(rateLimit.resetAt / 1000)))
  if (!rateLimit.allowed) {
    res.setHeader('retry-after', String(rateLimit.retryAfter))
    return send(res, 429, { code: 'RATE_LIMITED', message: 'Too many analysis requests. Try again later.', requestId }, requestId)
  }

  const contentLength = Number(req.headers['content-length'] || 0)
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    return send(res, 413, { code: 'PAYLOAD_TOO_LARGE', message: 'Request body is too large.', requestId }, requestId)
  }

  let raw = ''
  let receivedBytes = 0
  for await (const chunk of req) {
    receivedBytes += Buffer.byteLength(chunk)
    if (receivedBytes > MAX_BODY_BYTES) {
      return send(res, 413, { code: 'PAYLOAD_TOO_LARGE', message: 'Request body is too large.', requestId }, requestId)
    }
    raw += chunk
  }

  let body
  try {
    body = JSON.parse(raw || '{}')
  } catch {
    return send(res, 400, { code: 'INVALID_JSON', message: 'Request body must be valid JSON.', requestId }, requestId)
  }

  // Route: POST /api/reports (Public / Rate-limited)
  if (pathname === '/api/reports') {
    const validationError = validateCreateReport(body)
    if (validationError) {
      return send(res, 400, { code: 'INVALID_REPORT', message: validationError, requestId }, requestId)
    }
    try {
      const created = await submitReport(body)
      return send(res, 201, { report: created, requestId }, requestId)
    } catch (error) {
      return send(res, 502, { code: 'REPORT_CREATION_FAILED', message: error.message, requestId }, requestId)
    }
  }

  // Route: POST /api/moderation/review (Protected)
  if (pathname === '/api/moderation/review') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    const validationError = validateModerationAction(body)
    if (validationError) {
      return send(res, 400, { code: 'INVALID_ACTION', message: validationError, requestId }, requestId)
    }
    try {
      const result = await processModerationReview(body, auth.actorRole)
      return send(res, 200, { result, requestId }, requestId)
    } catch (error) {
      return send(res, error.message === 'Report not found.' ? 404 : 502, { code: error.message === 'Report not found.' ? 'REPORT_NOT_FOUND' : 'REVIEW_FAILED', message: error.message, requestId }, requestId)
    }
  }

  // Route: POST /api/analyze
  try {
    const validationError = validateSubmission(body)
    if (validationError) return send(res, 400, { code: 'INVALID_SUBMISSION', message: validationError, requestId }, requestId)
    const text = typeof body.text === 'string' ? body.text.trim() : ''
    if (!text || text.length > MAX_TEXT) return send(res, 400, { code: 'INVALID_SUBMISSION', message: 'text is required and must be at most 10,000 characters.', requestId }, requestId)
    const entities = extractEntities(text)
    const decision = analyze(text)
    const contentSha256 = createHash('sha256').update(text).digest('hex')

    const approvedDomainFindings = await verifyApprovedDomains(entities)
    if (approvedDomainFindings.length) decision.findings.push(...approvedDomainFindings)

    // Check Verified Intelligence (Feedback loop)
    if (process.env.ENABLE_VERIFIED_INTEL === 'true') {
      const verifiedFindings = await checkVerifiedIntelligence(entities, contentSha256)
      if (verifiedFindings.length) {
        decision.findings.push(...verifiedFindings)
        if (verifiedFindings.some((f) => f.canonicalSignal === 'verified_scam_intelligence')) {
          decision.riskBand = 'HIGH'
          decision.recommendation = 'STOP_AND_AVOID'
          if (!decision.safeActions.includes('Do not click, pay, reply, or share credentials.')) {
            decision.safeActions.unshift('Do not click, pay, reply, or share credentials.')
          }
        }
      }
    }


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

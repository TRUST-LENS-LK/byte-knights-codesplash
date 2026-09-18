import { createServer } from 'node:http'
import { randomUUID, createHash } from 'node:crypto'
import { MAX_BODY_BYTES, MAX_TEXT, PORT } from './config/env.mjs'
import { send } from './http/response.mjs'
import { authorizeModerator, loginModeratorWithPassword } from './http/auth.mjs'
import { analyze, applyScannerRisk, extractEntities, validateSubmission } from './services/analysis.mjs'
import { persistIfConsented } from './services/persistence.mjs'
import { consumeRateLimit } from './services/rateLimit.mjs'
import { verifyApprovedDomains } from './services/domainVerification.mjs'
import { inspectScannerUrl, scannerFindings } from './services/urlSafety.mjs'
import {
  checkVerifiedIntelligence,
  getModerationQueue,
  getModerationStats,
  isSupabaseConfigured,
  processModerationReview,
  submitReport,
  validateCreateReport,
  validateModerationAction,
  seedDemoQueue,
} from './services/reportingService.mjs'
import { reconcileDecision } from './services/reconcileIntelligence.mjs'
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

  // Moderation Stats & High-Level Aggregations (Protected GET)
  if (req.method === 'GET' && pathname === '/api/moderation/stats') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    try {
      const stats = await getModerationStats()
      return send(res, 200, { ...stats, requestId }, requestId)
    } catch (error) {
      return send(res, 502, { code: 'STATS_FETCH_ERROR', message: error.message, requestId }, requestId)
    }
  }

  // Moderation Queue (Protected GET) with Pagination Support
  if (req.method === 'GET' && pathname === '/api/moderation/queue') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    try {
      const statusParam = parsedUrl.searchParams.get('status') || 'PENDING'
      const pageParam = parseInt(parsedUrl.searchParams.get('page') || '1', 10)
      const limitParam = parseInt(parsedUrl.searchParams.get('limit') || '20', 10)
      const page = Number.isFinite(pageParam) && pageParam > 0 ? pageParam : 1
      const limit = Number.isFinite(limitParam) && limitParam > 0 && limitParam <= 100 ? limitParam : 20
      const offset = (page - 1) * limit

      const { reports, total } = await getModerationQueue({ status: statusParam, limit, offset })
      const totalPages = Math.ceil(total / limit) || 1

      return send(
        res,
        200,
        {
          reports,
          count: reports.length,
          total,
          page,
          limit,
          totalPages,
          status: statusParam,
          requestId,
        },
        requestId
      )
    } catch (error) {
      return send(res, 502, { code: 'QUEUE_FETCH_ERROR', message: error.message, requestId }, requestId)
    }
  }

  // Routes below require POST
  const validPostRoutes = ['/api/analyze', '/api/reports', '/api/scanner/preview', '/api/moderation/review', '/api/moderation/login', '/api/moderation/seed-demo']
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

  // Route: POST /api/scanner/preview
  if (pathname === '/api/scanner/preview') {
    if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.url !== 'string' || !body.url.trim()) {
      return send(res, 400, { code: 'INVALID_SUBMISSION', message: 'url is required.', requestId }, requestId)
    }
    const result = inspectScannerUrl(body.url)
    return send(res, result.allowed ? 200 : 400, result.allowed
      ? { safeToFetch: true, hostname: result.hostname, url: result.url, requestId }
      : { code: 'UNSAFE_URL', message: result.reason, safeToFetch: false, requestId }, requestId)
  }

  // Route: POST /api/reports (Public / Rate-limited)
  if (pathname === '/api/reports') {
    const validationError = validateCreateReport(body)
    if (validationError) {
      const code = body?.reportType === 'unknown' ? 'INVALID_SUBMISSION' : 'INVALID_REPORT'
      return send(res, 400, { code, message: validationError, requestId }, requestId)
    }
    if (!isSupabaseConfigured()) {
      return send(res, 503, { code: 'REPORTING_UNAVAILABLE', message: 'Reporting storage is currently unavailable.', requestId }, requestId)
    }
    try {
      const created = await submitReport(body)
      return send(res, 201, {
        report: created,
        reportId: created.id,
        status: created.status,
        requestId,
      }, requestId)
    } catch (error) {
      return send(res, 502, { code: 'REPORT_CREATION_FAILED', message: error.message, requestId }, requestId)
    }
  }

  // Route: POST /api/moderation/login (Moderator Auth)
  if (pathname === '/api/moderation/login') {
    const { email, password } = body || {}
    const result = await loginModeratorWithPassword(email, password)
    if (!result.success) {
      return send(res, result.status || 401, { code: 'AUTH_FAILED', message: result.error, requestId }, requestId)
    }
    return send(res, 200, { accessToken: result.accessToken, user: result.user, requestId }, requestId)
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

  // Route: POST /api/moderation/seed-demo (Protected Demo Seed)
  if (pathname === '/api/moderation/seed-demo') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    try {
      const seeded = await seedDemoQueue()
      return send(res, 200, { seeded, count: seeded.length, requestId }, requestId)
    } catch (error) {
      return send(res, 502, { code: 'SEED_FAILED', message: error.message, requestId }, requestId)
    }
  }

  // Route: POST /api/analyze
  try {
    const validationError = validateSubmission(body)
    if (validationError) return send(res, 400, { code: 'INVALID_SUBMISSION', message: validationError, requestId }, requestId)

    const text = typeof body.text === 'string' ? body.text.trim() : ''
    if (!text || text.length > MAX_TEXT) return send(res, 400, { code: 'INVALID_SUBMISSION', message: 'text is required and must be at most 10,000 characters.', requestId }, requestId)

    const entities = extractEntities(text)

    // ── Remote URL Scanner ─────────────────────────────────────────────
    let finalScanText = text
    let scannerFailed = false
    const urlEntities = entities.filter(e => e.type === 'url').slice(0, 3) // Scan up to 3 URLs max
    
    if (urlEntities.length > 0 && process.env.SCANNER_URL) {
      const scanPromises = urlEntities.map(async (urlEntity) => {
        const scanRes = await fetch(`${process.env.SCANNER_URL}/scan`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: urlEntity.value }),
          signal: AbortSignal.timeout(10000)
        })
        if (!scanRes.ok) throw new Error(`Scanner returned ${scanRes.status}`)
        return scanRes.json()
      })

      const results = await Promise.allSettled(scanPromises)

      for (const result of results) {
        if (result.status === 'fulfilled' && result.value.textContent) {
          finalScanText += '\n\n' + result.value.textContent
        } else if (result.status === 'rejected') {
          console.error('Remote scanner failed:', result.reason)
          scannerFailed = true
        }
      }
    }

    const decision = analyze(finalScanText)
    
    if (scannerFailed) {
      decision.limitations.push('The remote URL scanner was unavailable or timed out. The URL content could not be verified.')
    }

    const localScannerFindings = scannerFindings(entities)
    if (localScannerFindings.length) decision.findings.push(...localScannerFindings)
    applyScannerRisk(decision)

    const normalizedText = text.replace(/\r\n/g, '\n').trim()
    const contentSha256 = createHash('sha256').update(normalizedText).digest('hex')

    const approvedDomainFindings = await verifyApprovedDomains(entities).catch(() => {
      decision.limitations.push('Approved-domain verification was unavailable for this request.')
      return []
    })
    if (approvedDomainFindings.length) decision.findings.push(...approvedDomainFindings)

    // ── Intelligence Reconciliation Engine ─────────────────────────────
    let verifiedFindings = []
    if (process.env.ENABLE_VERIFIED_INTEL === 'true' && process.env.SUPABASE_SERVICE_ROLE_KEY !== 'test-service-key') {
      verifiedFindings = await checkVerifiedIntelligence(entities, contentSha256).catch(() => [])
      if (verifiedFindings.length) decision.findings.push(...verifiedFindings)
    }
    const reconciled = reconcileDecision(decision, verifiedFindings)
    const intelligenceOverlay = reconciled.intelligenceOverlay

    const submissionId = await persistIfConsented({ ...body, text }, decision, entities)
    return send(res, 200, {
      decision,
      entities,
      inputType: body.type === 'url' || entities.some((item) => item.type === 'url') ? 'url' : 'message',
      requestId,
      ...(intelligenceOverlay ? { intelligenceOverlay } : {}),
      ...(submissionId ? { submissionId } : {}),
    }, requestId)
  } catch (error) {
    return send(res, error instanceof SyntaxError ? 400 : 502, {
      code: error instanceof SyntaxError ? 'INVALID_JSON' : 'PERSISTENCE_ERROR',
      message: error instanceof SyntaxError ? 'Request body must be valid JSON.' : 'Analysis completed, but persistence is temporarily unavailable.',
      requestId,
    }, requestId)
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

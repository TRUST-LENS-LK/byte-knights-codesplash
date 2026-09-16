import { createServer } from 'node:http'
import { randomUUID } from 'node:crypto'
import { MAX_BODY_BYTES, MAX_TEXT, PORT } from './config/env.mjs'
import { send } from './http/response.mjs'
import { analyze, applyScannerRisk, extractEntities, validateReport, validateSubmission } from './services/analysis.mjs'
import { persistIfConsented, persistReport } from './services/persistence.mjs'
import { consumeRateLimit } from './services/rateLimit.mjs'
import { verifyApprovedDomains } from './services/domainVerification.mjs'
import { inspectScannerUrl, scannerFindings } from './services/urlSafety.mjs'

const server = createServer(async (req, res) => {
  const requestId = randomUUID()
  if (req.method === 'OPTIONS') return send(res, 204, {}, requestId)
  if (req.method === 'GET' && req.url === '/health') return send(res, 200, { status: 'ok', service: 'trustlens-api', requestId }, requestId)
  const isAnalyze = req.method === 'POST' && req.url === '/api/analyze'
  const isReport = req.method === 'POST' && req.url === '/api/reports'
  const isScanPreview = req.method === 'POST' && req.url === '/api/scanner/preview'
  if (!isAnalyze && !isReport && !isScanPreview) return send(res, 404, { code: 'NOT_FOUND', message: 'Route not found.', requestId }, requestId)
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
    if (isScanPreview) {
      if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.url !== 'string' || !body.url.trim()) return send(res, 400, { code: 'INVALID_SUBMISSION', message: 'url is required.', requestId }, requestId)
      const result = inspectScannerUrl(body.url)
      return send(res, result.allowed ? 200 : 400, result.allowed ? { safeToFetch: true, hostname: result.hostname, url: result.url, requestId } : { code: 'UNSAFE_URL', message: result.reason, safeToFetch: false, requestId }, requestId)
    }
    const validationError = isReport ? validateReport(body) : validateSubmission(body)
    if (validationError) return send(res, 400, { code: 'INVALID_SUBMISSION', message: validationError, requestId }, requestId)
    if (isReport) {
      const reportId = await persistReport(body)
      if (!reportId) return send(res, 503, { code: 'REPORTING_UNAVAILABLE', message: 'Reporting storage is temporarily unavailable.', requestId }, requestId)
      return send(res, 201, { reportId, status: 'PENDING', requestId }, requestId)
    }
    const text = typeof body.text === 'string' ? body.text.trim() : ''
    if (!text || text.length > MAX_TEXT) return send(res, 400, { code: 'INVALID_SUBMISSION', message: 'text is required and must be at most 10,000 characters.', requestId }, requestId)
    const entities = extractEntities(text)
    let finalScanText = text
    const urlEntities = entities.filter(e => e.type === 'url')
    if (urlEntities.length > 0 && process.env.SCANNER_URL) {
      try {
        const scanRes = await fetch(`${process.env.SCANNER_URL}/scan`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: urlEntities[0].value }),
          signal: AbortSignal.timeout(10000)
        })
        if (scanRes.ok) {
          const scanBody = await scanRes.json()
          if (scanBody.textContent) {
            finalScanText += '\n\n' + scanBody.textContent
          }
        }
      } catch (err) {
        console.error('Remote scanner failed:', err)
      }
    }
    const decision = analyze(finalScanText)
    const localScannerFindings = scannerFindings(entities)
    if (localScannerFindings.length) decision.findings.push(...localScannerFindings)
    applyScannerRisk(decision)
    try {
      const approvedDomainFindings = await verifyApprovedDomains(entities)
      if (approvedDomainFindings.length) decision.findings.push(...approvedDomainFindings)
    } catch {
      decision.limitations.push('Approved-domain verification was unavailable for this request.')
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

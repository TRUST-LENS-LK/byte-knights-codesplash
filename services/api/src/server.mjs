import { createServer } from 'node:http'
import { randomUUID, createHash } from 'node:crypto'
import { MAX_BODY_BYTES, MAX_TEXT, PORT } from './config/env.mjs'
import { send } from './http/response.mjs'
import { authorizeModerator, loginModeratorWithPassword } from './http/auth.mjs'
import { analyze, applyScannerRisk, extractEntities, validateSubmission } from './services/analysis.mjs'
import { persistIfConsented, purgeExpiredSubmissions } from './services/persistence.mjs'
import { consumeRateLimit } from './services/rateLimit.mjs'
import { applyDomainMismatchRisk, checkClaimedOrganizationDomain, verifyApprovedDomains } from './services/domainVerification.mjs'
import { checkGlobalDomainTrust } from './services/globalDomains.mjs'
import { checkDomainAge } from './services/domainAge.mjs'
import { applyKnownMaliciousRisk, checkSafeBrowsing } from './services/safeBrowsing.mjs'
import { createDomainDirectoryEntry, listAllDomainDirectoryEntries, listDomainDirectory, lookupDomainDirectory, updateDomainDirectoryEntry } from './services/domainDirectory.mjs'
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
  clearDemoQueue,
  getVerifiedIntelligenceList,
  updateIntelligenceStatus,
  createManualIntelligenceEntry,
  getEngineSettings,
  updateEngineSettings,
  isVerifiedIntelEnabled,
  AUDIT_RETENTION_DAYS,
  getModerationAuditLogs,
  purgeExpiredAuditLogs,
  getAuditStorageStats,
  verifyAuditChainIntegrity,
  recordAuditLog,
} from './services/reportingService.mjs'
import { reconcileDecision } from './services/reconcileIntelligence.mjs'
import { getOpenApiSpec, getSwaggerHtml } from './http/swagger.mjs'

const server = createServer(async (req, res) => {
  res.req = req
  const requestId = randomUUID()
  const parsedUrl = new URL(req.url, 'http://localhost')
  const pathname = parsedUrl.pathname
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || null
  const userAgent = req.headers['user-agent'] || null

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

  // Domain Directory (Public GET) — matches the RLS policy, which already
  // lets anon/authenticated callers read active organizations directly, so
  // this endpoint requires no auth. It exists so the frontend and other
  // members can get a validated, camelCase response instead of talking to
  // Supabase's REST API directly.
  if (req.method === 'GET' && pathname === '/api/domain-directory') {
    try {
      const category = parsedUrl.searchParams.get('category') || undefined
      const includeStale = parsedUrl.searchParams.get('includeStale') === 'true'
      const entries = await listDomainDirectory({ category, includeStale })
      return send(res, 200, { entries, count: entries.length, requestId }, requestId)
    } catch (error) {
      return send(res, 502, { code: 'DIRECTORY_FETCH_ERROR', message: error.message, requestId }, requestId)
    }
  }

  // Domain Directory Lookup (Public GET)
  if (req.method === 'GET' && pathname === '/api/domain-directory/lookup') {
    const domain = parsedUrl.searchParams.get('domain')
    if (!domain || !domain.trim()) {
      return send(res, 400, { code: 'INVALID_SUBMISSION', message: 'domain query parameter is required.', requestId }, requestId)
    }
    try {
      const result = await lookupDomainDirectory(domain)
      return send(res, 200, { ...result, submittedDomain: domain.trim().toLowerCase(), requestId }, requestId)
    } catch (error) {
      return send(res, 502, { code: 'DIRECTORY_LOOKUP_ERROR', message: error.message, requestId }, requestId)
    }
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
          success: true,
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

  // Moderation Settings (Protected GET)
  if (req.method === 'GET' && pathname === '/api/moderation/settings') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    const settings = getEngineSettings()
    return send(res, 200, { success: true, settings, requestId }, requestId)
  }

  // Verified Intelligence Query (Protected GET)
  if (req.method === 'GET' && pathname === '/api/moderation/intelligence') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    try {
      const statusParam = parsedUrl.searchParams.get('status') || 'all'
      const typeParam = parsedUrl.searchParams.get('type') || 'all'
      const riskLevelParam = parsedUrl.searchParams.get('riskLevel') || 'all'
      const searchParam = parsedUrl.searchParams.get('search') || ''
      const pageParam = parseInt(parsedUrl.searchParams.get('page') || '1', 10)
      const limitParam = parseInt(parsedUrl.searchParams.get('limit') || '20', 10)

      const result = await getVerifiedIntelligenceList({
        status: statusParam,
        type: typeParam,
        riskLevel: riskLevelParam,
        search: searchParam,
        page: pageParam,
        limit: limitParam,
      })

      return send(res, 200, { success: true, ...result, requestId }, requestId)
    } catch (error) {
      return send(res, 502, { code: 'INTELLIGENCE_FETCH_ERROR', message: error.message, requestId }, requestId)
    }
  }

  // Moderation Audit Logs Query (Protected GET)
  if (req.method === 'GET' && pathname === '/api/moderation/audit-logs') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    try {
      const action = parsedUrl.searchParams.get('action') || 'ALL'
      const search = parsedUrl.searchParams.get('search') || ''
      const actor = parsedUrl.searchParams.get('actor') || ''
      const fromDate = parsedUrl.searchParams.get('fromDate') || ''
      const toDate = parsedUrl.searchParams.get('toDate') || ''
      const page = parseInt(parsedUrl.searchParams.get('page') || '1', 10)
      const limit = parseInt(parsedUrl.searchParams.get('limit') || '20', 10)
      const result = await getModerationAuditLogs({ action, search, actor, fromDate, toDate, page, limit })
      return send(res, 200, { success: true, ...result, requestId }, requestId)
    } catch (error) {
      return send(res, 502, { code: 'AUDIT_FETCH_ERROR', message: error.message, requestId }, requestId)
    }
  }

  // Moderation Audit Chain Integrity Verification (Protected GET)
  if (req.method === 'GET' && pathname === '/api/moderation/audit-logs/verify') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    try {
      const verification = await verifyAuditChainIntegrity()
      return send(res, 200, {
        success: true,
        verified: Boolean(verification.isValid),
        totalEntriesChecked: verification.verifiedCount || 0,
        brokenAtId: verification.brokenAtId || null,
        reason: verification.reason || null,
        message: verification.message,
        latestHash: verification.latestHash || null,
        verification,
        requestId,
      }, requestId)
    } catch (error) {
      return send(res, 502, { code: 'AUDIT_VERIFY_ERROR', message: error.message, requestId }, requestId)
    }
  }

  // Moderation Audit Storage & Retention Stats (Protected GET)
  if (req.method === 'GET' && pathname === '/api/moderation/audit-logs/stats') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    try {
      const stats = await getAuditStorageStats()
      return send(res, 200, { success: true, stats, requestId }, requestId)
    } catch (error) {
      return send(res, 502, { code: 'AUDIT_STATS_ERROR', message: error.message, requestId }, requestId)
    }
  }

  // Domain Directory Management List (Protected GET)
  if (req.method === 'GET' && pathname === '/api/moderation/domains') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    try {
      const entries = await listAllDomainDirectoryEntries()
      return send(res, 200, { success: true, entries, count: entries.length, requestId }, requestId)
    } catch (error) {
      return send(res, 502, { code: 'DIRECTORY_FETCH_ERROR', message: error.message, requestId }, requestId)
    }
  }

  // Routes below require POST or PATCH with a JSON body
  const validPostRoutes = [
    '/api/analyze',
    '/api/reports',
    '/api/scanner/preview',
    '/api/moderation/review',
    '/api/moderation/login',
    '/api/moderation/seed-demo',
    '/api/moderation/clear-demo',
    '/api/moderation/audit-logs/purge',
    '/api/moderation/domains',
    '/api/moderation/intelligence',
  ]
  const isPatchSettings = req.method === 'PATCH' && pathname === '/api/moderation/settings'
  const isPatchIntel = req.method === 'PATCH' && pathname.startsWith('/api/moderation/intelligence/')
  const isPatchDomains = req.method === 'PATCH' && pathname.startsWith('/api/moderation/domains/')
  const isValidPost = req.method === 'POST' && validPostRoutes.includes(pathname)

  if (!isValidPost && !isPatchSettings && !isPatchIntel && !isPatchDomains) {
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
      void recordAuditLog({
        action: 'AUTH_FAILED',
        actorEmail: email || null,
        actorRole: 'anonymous',
        targetIndicator: 'auth.login',
        threatCategory: 'Authentication',
        moderatorNotes: `Failed login attempt: ${result.error || 'Invalid credentials'}.`,
        clientIp,
        userAgent,
      })
      return send(res, result.status || 401, { code: 'AUTH_FAILED', message: result.error, requestId }, requestId)
    }

    void recordAuditLog({
      action: 'AUTH_LOGIN',
      actorEmail: result.user?.email || email,
      actorRole: result.user?.role || 'moderator',
      targetIndicator: 'auth.login',
      threatCategory: 'Authentication',
      moderatorNotes: `Moderator session established successfully. Role: ${result.user?.role || 'moderator'}.`,
      clientIp,
      userAgent,
    })

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
      const result = await processModerationReview(
        body,
        auth.actorRole,
        auth.userEmail || auth.user?.email,
        clientIp,
        userAgent,
      )
      return send(res, 200, { result, requestId }, requestId)
    } catch (error) {
      const status = error.statusCode || (error.message === 'Report not found.' ? 404 : 502)
      return send(res, status, {
        code: error.code || (error.message === 'Report not found.' ? 'REPORT_NOT_FOUND' : 'REVIEW_FAILED'),
        message: error.message,
        protectedEntity: error.protectedEntity || null,
        requestId,
      }, requestId)
    }
  }

  // Route: POST /api/moderation/audit-logs/purge (Protected Retention Purge)
  if (pathname === '/api/moderation/audit-logs/purge') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    try {
      const { retentionDays, graceDays } = body || {}
      const result = await purgeExpiredAuditLogs(retentionDays, graceDays)
      return send(res, 200, { success: true, ...result, requestId }, requestId)
    } catch (error) {
      return send(res, 502, { code: 'PURGE_FAILED', message: error.message, requestId }, requestId)
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

  // Route: POST /api/moderation/clear-demo (Protected Demo Clear)
  if (pathname === '/api/moderation/clear-demo' && req.method === 'POST') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    try {
      const result = await clearDemoQueue()
      return send(res, 200, { success: true, count: result.count, requestId }, requestId)
    } catch (error) {
      return send(res, 502, { code: 'CLEAR_FAILED', message: error.message, requestId }, requestId)
    }
  }

  // Route: PATCH /api/moderation/settings (Protected)
  if (pathname === '/api/moderation/settings' && req.method === 'PATCH') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    if (typeof body.enableVerifiedIntel !== 'boolean' && typeof body.auditRetentionDays !== 'number') {
      return send(res, 400, { code: 'INVALID_SETTINGS', message: 'At least one of enableVerifiedIntel (boolean) or auditRetentionDays (number) must be provided.', requestId }, requestId)
    }
  const settings = updateEngineSettings(body, auth.actorRole || auth.email || 'moderator', auth.userEmail || auth.user?.email)
    return send(res, 200, { success: true, settings, requestId }, requestId)
  }

  // Route: POST /api/moderation/intelligence (Protected — add a scam/safe
  // indicator directly, without requiring a prior citizen report)
  if (pathname === '/api/moderation/intelligence' && req.method === 'POST') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    if (typeof body.indicatorValue !== 'string' || !body.indicatorValue.trim()) {
      return send(res, 400, { code: 'INVALID_SUBMISSION', message: 'indicatorValue is required.', requestId }, requestId)
    }
    if (body.riskLevel !== undefined && !['CONFIRMED_SCAM', 'VERIFIED_SAFE'].includes(body.riskLevel)) {
      return send(res, 400, { code: 'INVALID_SUBMISSION', message: 'riskLevel must be CONFIRMED_SCAM or VERIFIED_SAFE.', requestId }, requestId)
    }
    try {
      const entry = await createManualIntelligenceEntry(
        {
          indicatorValue: body.indicatorValue,
          indicatorType: body.indicatorType,
          riskLevel: body.riskLevel,
          category: body.category,
          notes: body.notes,
          confidence: body.confidence,
        },
        auth.actorRole || 'moderator',
        auth.userEmail || auth.user?.email || auth.email,
        clientIp,
        userAgent,
      )
      return send(res, 201, { success: true, entry, requestId }, requestId)
    } catch (error) {
      if (error.message === 'DUPLICATE_INDICATOR') {
        return send(res, 409, { code: 'DUPLICATE_INDICATOR', message: 'An intelligence entry for this indicator already exists.', requestId }, requestId)
      }
      return send(res, 502, { code: 'INTELLIGENCE_CREATE_ERROR', message: error.message, requestId }, requestId)
    }
  }

  // Route: PATCH /api/moderation/intelligence/:id (Protected)
  if (pathname.startsWith('/api/moderation/intelligence/') && req.method === 'PATCH') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    const intelId = pathname.slice('/api/moderation/intelligence/'.length)
    if (!intelId) {
      return send(res, 400, { code: 'INVALID_ID', message: 'Intelligence ID is required.', requestId }, requestId)
    }
    if (typeof body.active !== 'boolean' && typeof body.notes !== 'string' && typeof body.category !== 'string') {
      return send(res, 400, { code: 'INVALID_PAYLOAD', message: 'At least one of active, notes, or category must be provided.', requestId }, requestId)
    }
    try {
      const updated = await updateIntelligenceStatus(intelId, {
        active: body.active,
        notes: body.notes,
        category: body.category,
        actorRole: auth.actorRole,
        actorEmail: auth.userEmail || auth.user?.email,
        clientIp,
        userAgent,
      })
      return send(res, 200, { success: true, updated, requestId }, requestId)
    } catch (error) {
      return send(res, error.message === 'Intelligence item not found.' ? 404 : 502, {
        code: error.message === 'Intelligence item not found.' ? 'NOT_FOUND' : 'UPDATE_FAILED',
        message: error.message,
        requestId,
      }, requestId)
    }
  }

  // Route: POST /api/moderation/domains (Protected — add a directory entry)
  if (pathname === '/api/moderation/domains' && req.method === 'POST') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    if (typeof body.name !== 'string' || !body.name.trim() || typeof body.officialDomain !== 'string' || !body.officialDomain.trim()) {
      return send(res, 400, { code: 'INVALID_SUBMISSION', message: 'name and officialDomain are required.', requestId }, requestId)
    }
    try {
      const reviewer = auth.email || auth.actorRole || 'moderator'
      const created = await createDomainDirectoryEntry(
        { name: body.name.trim(), officialDomain: body.officialDomain.trim().toLowerCase(), category: body.category, sourceUrl: body.sourceUrl },
        reviewer,
      )
      void recordAuditLog({
        action: 'DOMAIN_CREATE',
        targetIndicator: created.officialDomain,
        threatCategory: 'Official Whitelist',
        actorEmail: auth.userEmail || auth.user?.email || (reviewer.includes('@') ? reviewer : 'moderator@trustlens.lk'),
        actorRole: auth.actorRole || 'moderator',
        confidence: 1.0,
        moderatorNotes: `Added official directory entry: "${created.name}" (${created.officialDomain}) under category: ${created.category || 'General'}.`,
        clientIp,
        userAgent,
      })
      return send(res, 201, { success: true, entry: created, requestId }, requestId)
    } catch (error) {
      return send(res, 502, { code: 'DIRECTORY_CREATE_ERROR', message: error.message, requestId }, requestId)
    }
  }

  // Route: PATCH /api/moderation/domains/:id (Protected — update a directory entry)
  if (pathname.startsWith('/api/moderation/domains/') && req.method === 'PATCH') {
    const auth = await authorizeModerator(req)
    if (!auth.authorized) {
      return send(res, 401, { code: 'UNAUTHORIZED', message: auth.error || 'Moderator access required.', requestId }, requestId)
    }
    const domainId = pathname.slice('/api/moderation/domains/'.length)
    if (!domainId) {
      return send(res, 400, { code: 'INVALID_ID', message: 'Domain directory ID is required.', requestId }, requestId)
    }
    const allowedKeys = ['status', 'category', 'sourceUrl', 'reviewNotes', 'active']
    if (!allowedKeys.some((key) => body[key] !== undefined)) {
      return send(res, 400, { code: 'INVALID_PAYLOAD', message: `At least one of ${allowedKeys.join(', ')} must be provided.`, requestId }, requestId)
    }
    if (body.status !== undefined && !['ACTIVE', 'STALE', 'RETIRED'].includes(body.status)) {
      return send(res, 400, { code: 'INVALID_PAYLOAD', message: 'status must be ACTIVE, STALE, or RETIRED.', requestId }, requestId)
    }
    try {
      const reviewer = auth.email || auth.actorRole || 'moderator'
      const updated = await updateDomainDirectoryEntry(domainId, body, reviewer)
      void recordAuditLog({
        action: 'DOMAIN_UPDATE',
        targetIndicator: updated.officialDomain,
        threatCategory: 'Official Whitelist',
        actorEmail: auth.userEmail || auth.user?.email || (reviewer.includes('@') ? reviewer : 'moderator@trustlens.lk'),
        actorRole: auth.actorRole || 'moderator',
        confidence: 1.0,
        moderatorNotes: `Updated directory record for "${updated.name}" (${updated.officialDomain}). Status: ${updated.status}. Active: ${updated.active}.`,
        clientIp,
        userAgent,
      })
      return send(res, 200, { success: true, updated, requestId }, requestId)
    } catch (error) {
      return send(res, error.message === 'Domain directory entry not found.' ? 404 : 502, {
        code: error.message === 'Domain directory entry not found.' ? 'NOT_FOUND' : 'UPDATE_FAILED',
        message: error.message,
        requestId,
      }, requestId)
    }
  }

  // Route: POST /api/analyze
  try {
    // The `url` field (and the URL entity extractor downstream) only
    // recognizes an absolute http(s) URL. A dedicated URL submission's type
    // already tells us the whole value is meant as a link, so a bare domain
    // like "boc.lk" is normalized here rather than rejected or silently
    // producing zero entities.
    if (body && body.type === 'url' && typeof body.url === 'string' && body.url.trim() && !/^https?:\/\//i.test(body.url.trim())) {
      body.url = `https://${body.url.trim()}`
    }

    const validationError = validateSubmission(body)
    if (validationError) return send(res, 400, { code: 'INVALID_SUBMISSION', message: validationError, requestId }, requestId)

    // A dedicated URL submission (type: 'url') sends `url`, not `text`. Treat
    // the URL itself as the analysis input so it flows through the same
    // extraction, rules, and domain-verification pipeline as a message that
    // happens to contain a link, rather than duplicating that pipeline behind
    // a second endpoint. A bare URL naturally cannot trigger keyword-based
    // scam rules or the organization-mismatch check, since there is no
    // surrounding claim of identity to compare against, only message-mode
    // submissions can do that, but directory and structural URL checks still
    // apply.
    const text = typeof body.text === 'string' && body.text.trim()
      ? body.text.trim()
      : typeof body.url === 'string'
        ? body.url.trim()
        : ''
    if (!text || text.length > MAX_TEXT) return send(res, 400, { code: 'INVALID_SUBMISSION', message: 'text or url is required and must be at most 10,000 characters.', requestId }, requestId)

    const entities = extractEntities(text)

    // ── Remote URL Scanner ─────────────────────────────────────────────
    let finalScanText = text
    let scannerFailed = false
    const scannerEvidence = []
    const urlEntities = entities.filter(e => e.type === 'url').slice(0, 3) // Scan up to 3 URLs max

    if (urlEntities.length > 0 && process.env.SCANNER_URL) {
      const scanPromises = urlEntities.map(async (urlEntity) => {
        const scanRes = await fetch(`${process.env.SCANNER_URL}/scan`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            // Matches the optional shared-secret check in the scanner
            // service. Sending an empty string when unset is harmless: the
            // scanner only enforces the header when it has its own secret
            // configured.
            'x-scanner-secret': process.env.SCANNER_SHARED_SECRET || '',
          },
          body: JSON.stringify({ url: urlEntity.value }),
          signal: AbortSignal.timeout(20000)
        })
        if (!scanRes.ok) throw new Error(`Scanner returned ${scanRes.status}`)
        return scanRes.json()
      })

      const results = await Promise.allSettled(scanPromises)

      for (const result of results) {
        if (result.status === 'fulfilled') {
          if (result.value.textContent) {
            finalScanText += '\n\n' + result.value.textContent
          }
          if (result.value.evidence) {
            scannerEvidence.push({ url: result.value.requestedUrl, ...result.value.evidence })
          }
          if (result.value.limitations && result.value.limitations.length > 0) {
            // We'll push these into decision.limitations after analyze()
            result.value.limitations.forEach(l => urlEntities._pendingLimitations = (urlEntities._pendingLimitations || []).concat(l))
          }
        } else if (result.status === 'rejected') {
          console.error('Remote scanner failed:', result.reason)
          scannerFailed = true
        }
      }
    }

    const decision = analyze(finalScanText)
    if (urlEntities._pendingLimitations) {
      decision.limitations.push(...urlEntities._pendingLimitations)
    }

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

    // Tier 3: only check global popularity when the curated directory
    // (Tier 1) did not already find a match, so the same domain never gets
    // both an approved_domain and a known_global_domain finding at once.
    if (!approvedDomainFindings.length) {
      const globalDomainCheck = await checkGlobalDomainTrust(entities).catch(() => ({ findings: [] }))
      if (globalDomainCheck.findings.length) decision.findings.push(...globalDomainCheck.findings)
    }

    // Tier 4: a single, fast live call to Google Safe Browsing, checked
    // regardless of Tier 1/3 results, since it evaluates the URL's current
    // live threat status, a genuinely independent signal from domain
    // ownership (even a directory-matched domain could theoretically be
    // compromised). Fails open silently when no API key is configured.
    const safeBrowsingCheck = await checkSafeBrowsing(entities).catch(() => ({ findings: [] }))
    if (safeBrowsingCheck.findings.length) decision.findings.push(...safeBrowsingCheck.findings)
    applyKnownMaliciousRisk(decision)

    const organizationDomainCheck = await checkClaimedOrganizationDomain(entities).catch(() => ({ findings: [], limitations: [] }))
    if (organizationDomainCheck.findings.length) decision.findings.push(...organizationDomainCheck.findings)
    if (organizationDomainCheck.limitations.length) decision.limitations.push(...organizationDomainCheck.limitations)
    applyDomainMismatchRisk(decision)

    // Tier 5 (domain age): the slowest tier, since it makes live external
    // network calls (RDAP, then CT-log fallbacks). Only worth running when
    // the domain is not already resolved by a faster, cheaper tier: skip it
    // when Tier 1 already confirmed the domain (age adds nothing useful to
    // a known-good match) or when a mismatch was already found (the verdict
    // is already HIGH/STOP_AND_AVOID; waiting on slow external calls for
    // evidence that cannot change that outcome would only hurt latency).
    const alreadyResolved = approvedDomainFindings.length > 0
      || organizationDomainCheck.findings.some((f) => f.canonicalSignal === 'domain_mismatch')
      || safeBrowsingCheck.findings.some((f) => f.canonicalSignal === 'known_malicious_domain')
    if (!alreadyResolved) {
      const domainAgeCheck = await checkDomainAge(entities).catch(() => ({ findings: [], limitations: [] }))
      if (domainAgeCheck.findings.length) decision.findings.push(...domainAgeCheck.findings)
      if (domainAgeCheck.limitations.length) decision.limitations.push(...domainAgeCheck.limitations)
    }

    // ── Intelligence Reconciliation Engine ─────────────────────────────
    let verifiedFindings = []
    let intelligenceOverlay = undefined
    if (isVerifiedIntelEnabled()) {
      verifiedFindings = await checkVerifiedIntelligence(entities, contentSha256).catch(() => [])
      if (verifiedFindings.length) decision.findings.push(...verifiedFindings)
      const reconciled = reconcileDecision(decision, verifiedFindings)
      intelligenceOverlay = reconciled.intelligenceOverlay
    }

    const submissionId = await persistIfConsented({ ...body, text }, decision, entities)
    return send(res, 200, {
      decision,
      entities,
      scannerEvidence,
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

// Retention enforcement: this project has no separate cron infrastructure,
// so the running API process itself purges submissions past their
// expires_at once a day, plus once shortly after startup. A failure here is
// Retention enforcement for citizen submissions:
const PURGE_INTERVAL_MS = 24 * 60 * 60 * 1000
async function runRetentionPurge() {
  try {
    const deleted = await purgeExpiredSubmissions()
    if (deleted) console.log(`Retention purge removed ${deleted} expired submission(s).`)
  } catch (error) {
    console.error('Retention purge failed:', error.message)
  }
}
const purgeTimer = setInterval(runRetentionPurge, PURGE_INTERVAL_MS)
purgeTimer.unref?.()

function shutdown(signal) {
  console.log(`${signal} received; shutting down TrustLens API.`)
  clearInterval(purgeTimer)
  server.close(() => process.exit(0))
}

process.once('SIGINT', () => shutdown('SIGINT'))
process.once('SIGTERM', () => shutdown('SIGTERM'))
server.listen(PORT, () => console.log(`TrustLens API listening on http://localhost:${PORT}`))

import { randomUUID } from 'node:crypto'
import { SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL } from '../config/env.mjs'

const REQUEST_TIMEOUT_MS = 8_000

// In-memory store fallback for offline dev/tests when Supabase credentials are not supplied
const inMemoryReports = new Map()
const inMemoryIntel = new Map()
const inMemoryAuditLogs = []

function isSupabaseConfigured() {
  return Boolean(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY)
}

function getHeaders() {
  return {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    'content-type': 'application/json',
    Prefer: 'return=representation',
  }
}

export function defang(indicator) {
  if (!indicator || typeof indicator !== 'string') return ''
  return indicator
    .replace(/^https?:\/\//i, 'hxxps://')
    .replace(/\./g, '[.]')
}

export function validateCreateReport(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return 'Request body must be a JSON object.'
  }
  const validTypes = ['suspicious', 'false_positive', 'false_negative']
  if (!body.reportType || !validTypes.includes(body.reportType)) {
    return `reportType is required and must be one of: ${validTypes.join(', ')}.`
  }
  if (!body.contentSha256 || typeof body.contentSha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(body.contentSha256)) {
    return 'contentSha256 is required and must be a 64-character hex string.'
  }
  if (body.reportedDomain !== undefined && body.reportedDomain !== null) {
    if (typeof body.reportedDomain !== 'string' || body.reportedDomain.length > 255) {
      return 'reportedDomain must be a string up to 255 characters.'
    }
  }
  if (body.notes !== undefined && body.notes !== null) {
    if (typeof body.notes !== 'string' || body.notes.length > 2000) {
      return 'notes must be a string up to 2,000 characters.'
    }
  }
  if (body.submissionId !== undefined && body.submissionId !== null) {
    if (typeof body.submissionId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(body.submissionId)) {
      return 'submissionId must be a valid UUID.'
    }
  }
  return null
}

export function validateModerationAction(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return 'Request body must be a JSON object.'
  }
  if (!body.reportId || typeof body.reportId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(body.reportId)) {
    return 'reportId is required and must be a valid UUID.'
  }
  const validActions = ['APPROVE', 'REJECT', 'RETIRE']
  if (!body.action || !validActions.includes(body.action)) {
    return `action is required and must be one of: ${validActions.join(', ')}.`
  }
  if (body.notes !== undefined && body.notes !== null) {
    if (typeof body.notes !== 'string' || body.notes.length > 1000) {
      return 'notes must be a string up to 1,000 characters.'
    }
  }
  const validIndicators = ['domain', 'content_hash', 'phone', 'url']
  if (body.indicatorType !== undefined && body.indicatorType !== null && !validIndicators.includes(body.indicatorType)) {
    return `indicatorType must be one of: ${validIndicators.join(', ')}.`
  }
  return null
}

export async function submitReport(payload) {
  const report = {
    id: randomUUID(),
    report_type: payload.reportType,
    content_sha256: payload.contentSha256.toLowerCase(),
    reported_domain: payload.reportedDomain?.trim().toLowerCase() || null,
    notes: payload.notes?.trim() || null,
    status: 'PENDING',
    created_at: new Date().toISOString(),
  }

  if (isSupabaseConfigured()) {
    const response = await fetch(`${SUPABASE_URL}/rest/v1/user_reports`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(report),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    })
    if (!response.ok) {
      throw new Error(`Failed to persist report to Supabase: ${response.statusText}`)
    }
    const [saved] = await response.json()
    return saved || report
  }

  inMemoryReports.set(report.id, report)
  return report
}

export async function getModerationQueue(status = 'PENDING') {
  if (isSupabaseConfigured()) {
    let url = `${SUPABASE_URL}/rest/v1/user_reports?select=*&order=created_at.desc`
    if (status && status !== 'ALL') {
      url += `&status=eq.${encodeURIComponent(status)}`
    }
    const response = await fetch(url, {
      headers: getHeaders(),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    })
    if (!response.ok) {
      throw new Error(`Failed to fetch moderation queue: ${response.statusText}`)
    }
    return await response.json()
  }

  const list = Array.from(inMemoryReports.values())
  return status && status !== 'ALL' ? list.filter((r) => r.status === status) : list
}

export async function getReportById(reportId) {
  if (isSupabaseConfigured()) {
    const response = await fetch(`${SUPABASE_URL}/rest/v1/user_reports?id=eq.${encodeURIComponent(reportId)}`, {
      headers: getHeaders(),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    })
    if (!response.ok) return null
    const [report] = await response.json()
    return report || null
  }
  return inMemoryReports.get(reportId) || null
}

export async function processModerationReview(reviewPayload, actorRole = 'moderator') {
  const { reportId, action, notes, indicatorType, category } = reviewPayload

  const report = await getReportById(reportId)
  if (!report) {
    throw new Error('Report not found.')
  }

  const updatedStatus = action === 'APPROVE' ? 'APPROVED' : action === 'REJECT' ? 'REJECTED' : 'RETIRED'

  // 1. Update report status
  if (isSupabaseConfigured()) {
    const updateRes = await fetch(`${SUPABASE_URL}/rest/v1/user_reports?id=eq.${encodeURIComponent(reportId)}`, {
      method: 'PATCH',
      headers: getHeaders(),
      body: JSON.stringify({ status: updatedStatus }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    })
    if (!updateRes.ok) throw new Error('Failed to update report status.')
  } else {
    report.status = updatedStatus
    inMemoryReports.set(reportId, report)
  }

  // 2. Add audit log
  const auditLog = {
    report_id: reportId,
    action,
    moderator_notes: notes || null,
    actor_role: actorRole,
    created_at: new Date().toISOString(),
  }

  if (isSupabaseConfigured()) {
    try {
      await fetch(`${SUPABASE_URL}/rest/v1/moderation_audit_logs`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(auditLog),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      })
    } catch {
      // Non-blocking if audit table is still pending migration
    }
  } else {
    inMemoryAuditLogs.push(auditLog)
  }

  // 3. Sanitization Pipeline for APPROVE action
  let verifiedIntelligenceId = null
  if (action === 'APPROVE') {
    const rawVal = report.reported_domain || report.content_sha256
    const indType = indicatorType || (report.reported_domain ? 'domain' : 'content_hash')
    const intelRecord = {
      id: randomUUID(),
      source_report_id: reportId,
      indicator_type: indType,
      indicator_value: rawVal,
      defanged_value: defang(rawVal),
      risk_level: report.report_type === 'false_positive' ? 'VERIFIED_SAFE' : 'CONFIRMED_SCAM',
      category: category || 'Reported Scam',
      confidence: 1.0,
      notes: notes || 'Verified by moderator approval',
      active: true,
      created_at: new Date().toISOString(),
    }

    if (isSupabaseConfigured()) {
      try {
        const intelRes = await fetch(`${SUPABASE_URL}/rest/v1/verified_intelligence`, {
          method: 'POST',
          headers: getHeaders(),
          body: JSON.stringify(intelRecord),
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        })
        if (intelRes.ok) {
          const [savedIntel] = await intelRes.json()
          verifiedIntelligenceId = savedIntel?.id || intelRecord.id
        }
      } catch {
        // Non-blocking if table migration pending
      }
    } else {
      inMemoryIntel.set(intelRecord.id, intelRecord)
      verifiedIntelligenceId = intelRecord.id
    }
  }

  return {
    success: true,
    reportId,
    status: updatedStatus,
    action,
    verifiedIntelligenceId,
  }
}

export async function checkVerifiedIntelligence(entities = [], contentSha256 = null) {
  const domains = entities.filter((e) => e.type === 'domain').map((e) => e.normalizedValue || e.value)
  const findings = []

  if (!domains.length && !contentSha256) return findings

  if (isSupabaseConfigured()) {
    try {
      const filters = []
      if (domains.length) {
        filters.push(`indicator_value=in.(${domains.map(encodeURIComponent).join(',')})`)
      }
      if (contentSha256) {
        filters.push(`indicator_value=eq.${encodeURIComponent(contentSha256)}`)
      }

      const query = `${SUPABASE_URL}/rest/v1/verified_intelligence?active=eq.true&or=(${filters.join(',')})`
      const res = await fetch(query, {
        headers: getHeaders(),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      })
      if (res.ok) {
        const matches = await res.json()
        for (const match of matches) {
          findings.push({
            canonicalSignal: match.risk_level === 'CONFIRMED_SCAM' ? 'verified_scam_intelligence' : 'verified_safe_intelligence',
            category: match.category || 'Threat Intelligence',
            evidence: `Indicator ${match.defanged_value} confirmed by moderator review.`,
            source: 'APPROVED_REPORT',
            strength: match.risk_level === 'CONFIRMED_SCAM' ? 1.0 : 0.0,
            confidence: Number(match.confidence) || 1.0,
            limitation: 'Verified via community intelligence reports.',
          })
        }
      }
    } catch {
      // Fail closed / gracefully return empty findings on connection error
    }
  } else {
    for (const intel of inMemoryIntel.values()) {
      if (!intel.active) continue
      if (domains.includes(intel.indicator_value) || contentSha256 === intel.indicator_value) {
        findings.push({
          canonicalSignal: intel.risk_level === 'CONFIRMED_SCAM' ? 'verified_scam_intelligence' : 'verified_safe_intelligence',
          category: intel.category || 'Threat Intelligence',
          evidence: `Indicator ${intel.defanged_value} confirmed by moderator review.`,
          source: 'APPROVED_REPORT',
          strength: intel.risk_level === 'CONFIRMED_SCAM' ? 1.0 : 0.0,
          confidence: intel.confidence,
          limitation: 'Verified via community intelligence reports.',
        })
      }
    }
  }

  return findings
}

export function resetInMemoryStores() {
  inMemoryReports.clear()
  inMemoryIntel.clear()
  inMemoryAuditLogs.length = 0
}

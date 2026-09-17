import { randomUUID } from 'node:crypto'
import { SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL } from '../config/env.mjs'
import { DEMO_REPORTS } from '../fixtures/demoReports.mjs'

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
  const clean = indicator
    .replace(/hxxps?:\/\//gi, 'https://')
    .replace(/\[+\]+/g, '.')
    .replace(/\[\.\]/g, '.')
    .replace(/\[@\]/g, '@')

  return clean
    .replace(/^https?:\/\//i, 'hxxps://')
    .replace(/\./g, '[.]')
    .replace(/@/g, '[@]')
}

/** Reverse defanging so we can recover the raw indicator from stored reports */
export function rehydrate(defanged) {
  if (!defanged || typeof defanged !== 'string') return ''
  return defanged
    .replace(/hxxps?:\/\//gi, 'https://')
    .replace(/\[\.\]/g, '.')
    .replace(/\[@\]/g, '@')
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
  let finalNotes = payload.notes?.trim() || null
  if (payload.rawExcerpt && (!finalNotes || !finalNotes.includes(payload.rawExcerpt))) {
    finalNotes = `[Reported Message Excerpt]: "${payload.rawExcerpt}"${finalNotes ? `\n\n[Submitter Context]: ${finalNotes}` : ''}`
  }

  const report = {
    id: randomUUID(),
    report_type: payload.reportType,
    content_sha256: payload.contentSha256.toLowerCase(),
    reported_domain: payload.reportedDomain?.trim().toLowerCase() || null,
    notes: finalNotes,
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

export async function getModerationQueue(statusOrOptions = 'PENDING') {
  let status = 'PENDING'
  let limit = null
  let offset = 0

  if (typeof statusOrOptions === 'object' && statusOrOptions !== null) {
    status = statusOrOptions.status || 'PENDING'
    limit = Number.isFinite(Number(statusOrOptions.limit)) ? Number(statusOrOptions.limit) : null
    offset = Number.isFinite(Number(statusOrOptions.offset)) ? Number(statusOrOptions.offset) : 0
  } else if (typeof statusOrOptions === 'string') {
    status = statusOrOptions
  }

  if (isSupabaseConfigured()) {
    let url = `${SUPABASE_URL}/rest/v1/user_reports?select=*&order=created_at.desc`
    if (status && status !== 'ALL') {
      url += `&status=eq.${encodeURIComponent(status)}`
    }
    if (limit !== null && limit > 0) {
      url += `&limit=${limit}&offset=${offset}`
    }
    const headers = {
      ...getHeaders(),
      Prefer: 'count=exact',
    }
    const response = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    })
    if (!response.ok) {
      throw new Error(`Failed to fetch moderation queue: ${response.statusText}`)
    }
    const reports = await response.json()
    const contentRange = response.headers.get('content-range') || ''
    const match = contentRange.match(/\/(\d+|\*)$/)
    const total = match && match[1] !== '*' ? parseInt(match[1], 10) : reports.length
    return { reports, total }
  }

  const list = Array.from(inMemoryReports.values()).sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  )
  const filtered = status && status !== 'ALL' ? list.filter((r) => r.status === status) : list
  const total = filtered.length
  const reports = limit !== null && limit > 0 ? filtered.slice(offset, offset + limit) : filtered
  return { reports, total }
}

function computeStatsFromReports(reports) {
  let pendingCount = 0
  let approvedCount = 0
  let rejectedCount = 0
  let confirmedThreatCount = 0
  let clearedSafeCount = 0

  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
  const weeklyMap = new Map(days.map((d) => [d, { threats: 0, resolved: 0 }]))

  const categoryCounts = new Map([
    ['Banking Phishing', 0],
    ['Telecom / Utility Scam', 0],
    ['Job Scam', 0],
    ['Lottery / Prize Fraud', 0],
    ['OTP Theft', 0],
    ['Malicious Link / APK', 0],
    ['False Alarm', 0],
  ])

  let priorityIncident = null

  reports.forEach((report) => {
    if (report.status === 'PENDING') {
      pendingCount++
      if (!priorityIncident) {
        priorityIncident = {
          id: report.id,
          reported_domain: report.reported_domain || null,
          raw_excerpt: report.raw_excerpt || null,
          notes: report.notes || null,
          report_type: report.report_type,
          created_at: report.created_at,
        }
      }
    } else if (report.status === 'APPROVED') {
      approvedCount++
      if (report.report_type === 'false_positive') {
        clearedSafeCount++
      } else {
        confirmedThreatCount++
      }
    } else if (report.status === 'REJECTED') {
      rejectedCount++
    }

    // Weekly activity
    if (report.created_at) {
      try {
        const d = new Date(report.created_at)
        if (!isNaN(d.getTime())) {
          const dayName = days[d.getDay()]
          const entry = weeklyMap.get(dayName)
          if (entry) {
            if (report.report_type === 'suspicious') entry.threats++
            if (report.status === 'APPROVED' || report.status === 'REJECTED') entry.resolved++
          }
        }
      } catch (_) {}
    }

    // Categorization
    if (report.report_type === 'false_positive') {
      categoryCounts.set('False Alarm', (categoryCounts.get('False Alarm') || 0) + 1)
    } else {
      const text = `${report.reported_domain || ''} ${report.notes || ''} ${report.raw_excerpt || ''}`.toLowerCase()
      if (/boc|combank|bank|hnb|sampath|card|debit|credit|fund/.test(text)) {
        categoryCounts.set('Banking Phishing', (categoryCounts.get('Banking Phishing') || 0) + 1)
      } else if (/ceb|electricity|utility|water|bill|telecom|dialog|mobitel/.test(text)) {
        categoryCounts.set('Telecom / Utility Scam', (categoryCounts.get('Telecom / Utility Scam') || 0) + 1)
      } else if (/job|earn|part-time|salary|advance|bonus|hiring/.test(text)) {
        categoryCounts.set('Job Scam', (categoryCounts.get('Job Scam') || 0) + 1)
      } else if (/lottery|prize|won|lucky|cash|gift|reward/.test(text)) {
        categoryCounts.set('Lottery / Prize Fraud', (categoryCounts.get('Lottery / Prize Fraud') || 0) + 1)
      } else if (/otp|code|pin|password|credential|security/.test(text)) {
        categoryCounts.set('OTP Theft', (categoryCounts.get('OTP Theft') || 0) + 1)
      } else if (/\.apk|download|install|app/.test(text)) {
        categoryCounts.set('Malicious Link / APK', (categoryCounts.get('Malicious Link / APK') || 0) + 1)
      } else {
        categoryCounts.set('Banking Phishing', (categoryCounts.get('Banking Phishing') || 0) + 1)
      }
    }
  })

  const totalReports = reports.length
  const reviewedCount = approvedCount + rejectedCount
  const verificationVelocity = totalReports > 0 ? Number(((reviewedCount / totalReports) * 100).toFixed(1)) : 100

  const weeklyActivity = days.map((day) => ({
    day,
    threats: weeklyMap.get(day)?.threats || 0,
    resolved: weeklyMap.get(day)?.resolved || 0,
  }))

  const nonZeroCategories = Array.from(categoryCounts.entries())
    .map(([category, count]) => ({
      category,
      count,
      percentage: totalReports > 0 ? Number(((count / totalReports) * 100).toFixed(1)) : 0,
    }))
    .sort((a, b) => b.count - a.count)

  return {
    metrics: {
      totalReports,
      pendingCount,
      approvedCount,
      rejectedCount,
      confirmedThreatCount,
      clearedSafeCount,
      verificationVelocity,
    },
    weeklyActivity,
    threatCategories: nonZeroCategories,
    priorityIncident,
  }
}

export async function getModerationStats() {
  if (isSupabaseConfigured()) {
    const url = `${SUPABASE_URL}/rest/v1/user_reports?select=id,status,report_type,reported_domain,notes,created_at&order=created_at.desc`
    const response = await fetch(url, {
      headers: getHeaders(),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    })
    if (!response.ok) {
      throw new Error(`Failed to fetch moderation stats: ${response.statusText}`)
    }
    const reports = await response.json()
    return computeStatsFromReports(reports)
  }

  const reports = Array.from(inMemoryReports.values()).sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  )
  return computeStatsFromReports(reports)
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

const SRI_LANKA_2ND_LEVEL_TLDS = new Set(['gov.lk', 'com.lk', 'org.lk', 'edu.lk', 'hotel.lk', 'ac.lk', 'sch.lk', 'net.lk', 'web.lk'])

export function extractDomainVariants(domain) {
  if (!domain || typeof domain !== 'string') return []
  const clean = domain.toLowerCase().trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]
  const variants = new Set([clean])

  if (clean.startsWith('www.')) {
    variants.add(clean.replace(/^www\./, ''))
  }

  const parts = clean.split('.')
  if (parts.length > 2) {
    const lastTwo = parts.slice(-2).join('.')
    if (SRI_LANKA_2ND_LEVEL_TLDS.has(lastTwo) && parts.length >= 3) {
      variants.add(parts.slice(-3).join('.'))
    } else {
      variants.add(parts.slice(-2).join('.'))
    }
  }

  return Array.from(variants).filter(Boolean)
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
    const storedDomain = report.reported_domain || ''
    const rawDomain = rehydrate(storedDomain)
    const primaryVal = rawDomain || report.content_sha256
    const indType = indicatorType || (rawDomain ? 'domain' : 'content_hash')
    const intelRecords = []

    // Primary indicator record
    intelRecords.push({
      id: randomUUID(),
      source_report_id: reportId,
      indicator_type: indType,
      indicator_value: primaryVal.toLowerCase(),
      defanged_value: defang(primaryVal),
      risk_level: report.report_type === 'false_positive' ? 'VERIFIED_SAFE' : 'CONFIRMED_SCAM',
      category: category || (report.report_type === 'false_positive' ? 'False Alarm' : 'Reported Scam'),
      confidence: 1.0,
      notes: notes || 'Verified by moderator approval',
      active: true,
      created_at: new Date().toISOString(),
    })

    // Dual-index content SHA256 if distinct from primaryVal
    if (rawDomain && report.content_sha256 && /^[a-f0-9]{64}$/i.test(report.content_sha256)) {
      intelRecords.push({
        id: randomUUID(),
        source_report_id: reportId,
        indicator_type: 'content_hash',
        indicator_value: report.content_sha256.toLowerCase(),
        defanged_value: report.content_sha256.toLowerCase(),
        risk_level: report.report_type === 'false_positive' ? 'VERIFIED_SAFE' : 'CONFIRMED_SCAM',
        category: category || (report.report_type === 'false_positive' ? 'False Alarm' : 'Reported Scam'),
        confidence: 0.95,
        notes: `Cryptographic fingerprint for verified report ${reportId.slice(0, 8)}`,
        active: true,
        created_at: new Date().toISOString(),
      })
    }

    for (const intelRecord of intelRecords) {
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
            if (!verifiedIntelligenceId) verifiedIntelligenceId = savedIntel?.id || intelRecord.id
          }
        } catch {
          // Non-blocking if table migration pending
        }
      } else {
        inMemoryIntel.set(intelRecord.id, intelRecord)
        if (!verifiedIntelligenceId) verifiedIntelligenceId = intelRecord.id
      }
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
  const rawDomains = entities.filter((e) => e.type === 'domain').map((e) => (e.normalizedValue || e.value || '').toLowerCase())
  const urls = entities.filter((e) => e.type === 'url').map((e) => (e.value || '').toLowerCase())
  const phones = entities.filter((e) => e.type === 'phone').map((e) => (e.normalizedValue || e.value || '').toLowerCase())
  const emails = entities.filter((e) => e.type === 'email').map((e) => (e.value || '').toLowerCase())

  // Expand domains with apex variants and www. stripping
  const expandedDomains = []
  for (const d of rawDomains) {
    expandedDomains.push(...extractDomainVariants(d))
  }
  for (const u of urls) {
    try {
      const hostname = new URL(u.startsWith('http') ? u : `https://${u}`).hostname
      if (hostname) expandedDomains.push(...extractDomainVariants(hostname))
    } catch {}
  }

  const rawIndicators = [...new Set([...rawDomains, ...expandedDomains, ...urls, ...phones, ...emails])].filter(Boolean)
  const allVariants = new Set()
  for (const ind of rawIndicators) {
    allVariants.add(ind)
    allVariants.add(defang(ind))
    allVariants.add(rehydrate(ind))
  }
  const indicators = [...allVariants].filter(Boolean)
  const findings = []

  if (!indicators.length && !contentSha256) return findings

  if (isSupabaseConfigured()) {
    try {
      const filters = []
      if (indicators.length) {
        const quoted = indicators.map((ind) => `"${ind.replace(/"/g, '')}"`).join(',')
        filters.push(`indicator_value.in.(${quoted})`)
      }
      if (contentSha256) {
        filters.push(`indicator_value.eq.${contentSha256}`)
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
      // Gracefully return empty findings on connection error
    }
  } else {
    for (const intel of inMemoryIntel.values()) {
      if (!intel.active) continue
      if (indicators.includes(intel.indicator_value) || contentSha256 === intel.indicator_value) {
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

export async function seedDemoQueue() {
  const seeded = []
  for (const demo of DEMO_REPORTS) {
    const dbPayload = {
      id: demo.id,
      report_type: demo.report_type,
      content_sha256: demo.content_sha256,
      reported_domain: demo.reported_domain,
      notes: `[Reported Message Excerpt]: "${demo.raw_excerpt}"\n\n[Submitter Context]: ${demo.notes}`,
      status: demo.status,
      created_at: demo.created_at,
    }
    if (isSupabaseConfigured()) {
      try {
        const res = await fetch(`${SUPABASE_URL}/rest/v1/user_reports`, {
          method: 'POST',
          headers: { ...getHeaders(), Prefer: 'resolution=ignore-duplicates' },
          body: JSON.stringify(dbPayload),
        })
        if (res.ok) seeded.push(dbPayload)
      } catch {
        inMemoryReports.set(dbPayload.id, dbPayload)
        seeded.push(dbPayload)
      }
    } else {
      inMemoryReports.set(dbPayload.id, dbPayload)
      seeded.push(dbPayload)
    }
  }
  return seeded
}

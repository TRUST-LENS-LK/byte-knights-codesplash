import { randomUUID, createHash } from 'node:crypto'
import { SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL } from '../config/env.mjs'
import { DEMO_REPORTS } from '../fixtures/demoReports.mjs'
import { analyzeMessage } from '@trustlens/rules'

const REQUEST_TIMEOUT_MS = 8_000

export let AUDIT_RETENTION_DAYS = parseInt(process.env.AUDIT_RETENTION_DAYS || '90', 10)

// In-memory store fallback for offline dev/tests when Supabase credentials are not supplied
const inMemoryReports = new Map()
const inMemoryIntel = new Map()

const initialDemoAuditLogs = [
  {
    id: 'audit-demo-001',
    report_id: 'report-demo-001',
    action: 'APPROVE',
    target_indicator: 'hxxps://ceb-bill-payment[.]top',
    threat_category: 'Utility Bill Scam',
    actor_email: 'moderator2@trustlens.lk',
    actor_role: 'moderator',
    confidence: 1.0,
    moderator_notes: 'Confirmed phishing page harvesting CEB electricity account credentials and debit cards.',
    created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
    expires_at: new Date(Date.now() + (AUDIT_RETENTION_DAYS - 2) * 86400000).toISOString(),
  },
  {
    id: 'audit-demo-002',
    report_id: 'report-demo-002',
    action: 'APPROVE',
    target_indicator: 'hxxps://srilanka-telecom-rewards[.]xyz',
    threat_category: 'Telecom Impersonation',
    actor_email: 'moderator1@trustlens.lk',
    actor_role: 'moderator',
    confidence: 0.95,
    moderator_notes: 'Approved threat intelligence after verifying SMS campaign demanding OTP.',
    created_at: new Date(Date.now() - 86400000 * 4).toISOString(),
    expires_at: new Date(Date.now() + (AUDIT_RETENTION_DAYS - 4) * 86400000).toISOString(),
  },
  {
    id: 'audit-demo-003',
    report_id: 'report-demo-003',
    action: 'REJECT',
    target_indicator: 'hxxps://dialog[.]lk/myaccount',
    threat_category: 'False Alarm',
    actor_email: 'moderator2@trustlens.lk',
    actor_role: 'moderator',
    confidence: 1.0,
    moderator_notes: 'Dismissed report. Legitimate official portal matching Sri Lanka national directory.',
    created_at: new Date(Date.now() - 86400000 * 6).toISOString(),
    expires_at: new Date(Date.now() + (AUDIT_RETENTION_DAYS - 6) * 86400000).toISOString(),
  },
  {
    id: 'audit-demo-004',
    report_id: null,
    action: 'UPDATE_SETTINGS',
    target_indicator: 'engine.enableVerifiedIntel',
    threat_category: null,
    actor_email: 'admin@trustlens.lk',
    actor_role: 'admin',
    confidence: 1.0,
    moderator_notes: 'Threat feedback loop active with real-time community intelligence reconciliation.',
    created_at: new Date(Date.now() - 86400000 * 8).toISOString(),
    expires_at: new Date(Date.now() + (AUDIT_RETENTION_DAYS - 8) * 86400000).toISOString(),
  },
]

const inMemoryAuditLogs = [...initialDemoAuditLogs]

/**
 * Extracts normalized plain text from a report for deep deterministic rules analysis.
 */
export function extractCleanTextForAnalysis(report) {
  if (!report) return ''
  const parts = []
  if (report.raw_excerpt) parts.push(report.raw_excerpt)
  if (report.notes) {
    const match = report.notes.match(/\[Reported Message Excerpt\]:\s*"([^"]+)"/i)
    if (match) {
      parts.push(match[1])
    }
    const userMatch = report.notes.match(/\[Submitter Context\]:\s*([\s\S]+)$/i)
    if (userMatch) {
      parts.push(userMatch[1])
    } else if (!match) {
      parts.push(report.notes)
    }
  }
  return parts.join(' ').trim()
}

/**
 * Automates deterministic threat triage and risk signal evaluation using @trustlens/rules
 * and verified threat intelligence matching.
 */
export function enrichReportWithTriage(report) {
  if (!report) return report

  // 1. False positive: Submitter reporting legitimate message incorrectly flagged
  if (report.report_type === 'false_positive') {
    return {
      ...report,
      threat: { title: 'False Alarm', subtitle: 'User Dispute', type: 'safe' },
      risk_signal: { level: 'LOW', color: '#10B981' },
      detected_signals: ['user_dispute'],
    }
  }

  const rawDomain = report.reported_domain || ''
  const domain = rawDomain.toLowerCase().replace(/hxxps?:\/\//i, '').replace(/\[\.\]/g, '.').replace(/\[@\]/g, '@').trim()

  // 2. Check known verified intelligence
  if (domain) {
    const knownIntel = Array.from(inMemoryIntel.values()).find(
      (item) => item.active && item.indicator_value?.toLowerCase() === domain
    )
    if (knownIntel) {
      if (knownIntel.risk_level === 'CONFIRMED_SCAM') {
        return {
          ...report,
          threat: { title: 'Confirmed Threat', subtitle: knownIntel.category || 'Verified Malicious Indicator', type: 'phishing' },
          risk_signal: { level: 'HIGH', color: '#EF4444' },
          detected_signals: ['verified_threat_intelligence_match'],
        }
      }
      if (knownIntel.risk_level === 'VERIFIED_SAFE') {
        return {
          ...report,
          threat: { title: 'Official Domain', subtitle: knownIntel.category || 'Verified Entity', type: 'safe' },
          risk_signal: { level: 'LOW', color: '#10B981' },
          detected_signals: ['verified_safe_match'],
        }
      }
    }
  }

  // 3. Check for explicit user-selected threat category
  const threatCategoryMatch = report.notes?.match(/\[Threat Category\]:\s*([^\n]+)/i)
  const explicitCategory = (report.threat_category || (threatCategoryMatch ? threatCategoryMatch[1].trim() : null))?.toLowerCase()

  if (explicitCategory) {
    if (explicitCategory.includes('phish')) {
      return {
        ...report,
        threat: { title: 'Phishing', subtitle: 'Credential Theft (User Reported)', type: 'phishing' },
        risk_signal: { level: 'HIGH', color: '#EF4444' },
        detected_signals: ['user_selected_phishing'],
      }
    }
    if (explicitCategory.includes('job')) {
      return {
        ...report,
        threat: { title: 'Scam', subtitle: 'Fake Job Offer (User Reported)', type: 'scam' },
        risk_signal: { level: 'HIGH', color: '#EF4444' },
        detected_signals: ['user_selected_job_scam'],
      }
    }
    if (explicitCategory.includes('malware') || explicitCategory.includes('apk')) {
      return {
        ...report,
        threat: { title: 'Malware', subtitle: 'Malicious Link / APK (User Reported)', type: 'malware' },
        risk_signal: { level: 'HIGH', color: '#8B5CF6' },
        detected_signals: ['user_selected_malware'],
      }
    }
    if (explicitCategory.includes('impersonat')) {
      return {
        ...report,
        threat: { title: 'Impersonation', subtitle: 'Brand / Entity Spoofing (User Reported)', type: 'phishing' },
        risk_signal: { level: 'HIGH', color: '#EF4444' },
        detected_signals: ['user_selected_impersonation'],
      }
    }
    if (explicitCategory.includes('scam') || explicitCategory.includes('financial')) {
      return {
        ...report,
        threat: { title: 'Scam', subtitle: 'Financial & Utility Fraud (User Reported)', type: 'scam' },
        risk_signal: { level: 'HIGH', color: '#EF4444' },
        detected_signals: ['user_selected_financial_scam'],
      }
    }
    if (explicitCategory.includes('official') || explicitCategory.includes('legitimate') || explicitCategory.includes('personal')) {
      return {
        ...report,
        threat: { title: 'False Alarm', subtitle: 'Legitimate Content (User Dispute)', type: 'safe' },
        risk_signal: { level: 'LOW', color: '#10B981' },
        detected_signals: ['user_selected_safe_dispute'],
      }
    }
  }

  // 4. Check for raw IP address infrastructure (e.g. 192.168.21.144)
  if (domain && /^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/.test(domain)) {
    return {
      ...report,
      threat: { title: 'Suspicious Domain', subtitle: 'Raw IP Infrastructure', type: 'phishing' },
      risk_signal: { level: 'HIGH', color: '#EF4444' },
      detected_signals: ['raw_ip_host'],
    }
  }

  // 4. Run deterministic rules engine on content (notes + excerpt)
  const textToAnalyze = extractCleanTextForAnalysis(report)
  const decision = textToAnalyze ? analyzeMessage(textToAnalyze) : null

  let title = domain ? 'Suspicious Domain' : 'Suspicious Message'
  let subtitle = domain ? 'Unverified Web Target' : 'Citizen Submission'
  let type = domain ? 'phishing' : 'scam'
  let riskLevel = 'MEDIUM'
  const detectedSignals = decision?.findings?.map((f) => f.canonicalSignal) || []
  const lowerText = (textToAnalyze || '').toLowerCase()

  if (decision && decision.findings.length > 0) {
    const findingCategories = new Set(decision.findings.map((f) => f.category))

    if (findingCategories.has('CREDENTIAL_THEFT')) {
      title = 'Phishing'
      subtitle = 'Credential Harvesting'
      type = 'phishing'
    } else if (findingCategories.has('ADVANCE_FEE_FRAUD')) {
      title = 'Scam'
      subtitle = 'Advance Fee Fraud'
      type = 'scam'
    } else if (findingCategories.has('EMPLOYMENT_FRAUD')) {
      title = 'Scam'
      subtitle = 'Fake Job Offer'
      type = 'scam'
    } else if (findingCategories.has('URGENCY_MANIPULATION')) {
      title = 'Social Engineering'
      subtitle = 'Urgency Pressure'
      type = 'scam'
    } else if (!domain) {
      if (/subscription|invoice|refund|renew|charge|geek squad|norton|mcafee|paypal|apple/.test(lowerText)) {
        title = 'Scam'
        subtitle = 'Subscription / Invoice Fraud'
        type = 'scam'
      } else {
        title = 'Suspicious Message'
        subtitle = 'Citizen Submission'
        type = 'scam'
      }
    }

    riskLevel = decision.riskBand === 'HIGH' ? 'HIGH' : decision.riskBand === 'LOW' ? 'LOW' : 'MEDIUM'
  } else if (!domain) {
    if (/subscription|invoice|refund|renew|charge|geek squad|norton|mcafee|paypal|apple/.test(lowerText)) {
      title = 'Scam'
      subtitle = 'Subscription / Invoice Fraud'
      type = 'scam'
    } else if (/job|salary|part-time|hiring|earn|bonus/.test(lowerText)) {
      title = 'Scam'
      subtitle = 'Fake Job Offer'
      type = 'scam'
    } else if (/lottery|prize|won|lucky|cash|gift|reward/.test(lowerText)) {
      title = 'Scam'
      subtitle = 'Lottery / Prize Fraud'
      type = 'scam'
    } else if (/boc|combank|bank|hnb|sampath|card|debit|credit|fund|login|verify|otp|pin|password|credential|security/.test(lowerText)) {
      title = 'Phishing'
      subtitle = 'Credential Harvesting'
      type = 'phishing'
    } else {
      title = 'Suspicious Message'
      subtitle = 'Citizen Submission'
      type = 'scam'
    }
  }

  // If report_type === 'false_negative', user reported an evasion that bypassed automated filters
  if (report.report_type === 'false_negative' && riskLevel === 'LOW') {
    riskLevel = 'MEDIUM'
  }

  const colorMap = {
    HIGH: '#EF4444',
    MEDIUM: '#F59E0B',
    LOW: '#10B981',
  }

  return {
    ...report,
    threat: { title, subtitle, type },
    risk_signal: { level: riskLevel, color: colorMap[riskLevel] || '#F59E0B' },
    detected_signals: detectedSignals,
  }
}

const initialDemoIntel = [
  {
    id: 'intel-demo-001',
    source_report_id: 'report-demo-001',
    indicator_type: 'domain',
    indicator_value: 'ceb-bill-pay.top',
    defanged_value: 'hxxps://ceb-bill-pay[.]top',
    risk_level: 'CONFIRMED_SCAM',
    category: 'Utility Phishing',
    confidence: 0.98,
    notes: 'Impersonates Ceylon Electricity Board payment portal with fake bill settlement gateway.',
    report_count: 3,
    active: true,
    created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
    updated_at: new Date(Date.now() - 86400000 * 2).toISOString(),
  },
  {
    id: 'intel-demo-002',
    source_report_id: 'report-demo-002',
    indicator_type: 'domain',
    indicator_value: 'srilanka-telecom-rewards.xyz',
    defanged_value: 'hxxps://srilanka-telecom-rewards[.]xyz',
    risk_level: 'CONFIRMED_SCAM',
    category: 'Telecom Impersonation',
    confidence: 0.95,
    notes: 'Fraudulent SMS campaign offering fake data packages requiring OTP entry.',
    report_count: 5,
    active: true,
    created_at: new Date(Date.now() - 86400000 * 4).toISOString(),
    updated_at: new Date(Date.now() - 86400000 * 4).toISOString(),
  },
  {
    id: 'intel-demo-003',
    source_report_id: null,
    indicator_type: 'domain',
    indicator_value: 'gov.lk',
    defanged_value: 'hxxps://gov[.]lk',
    risk_level: 'VERIFIED_SAFE',
    category: 'Government Portal',
    confidence: 1.0,
    notes: 'Official Sri Lanka Government Web Portal top-level domain.',
    report_count: 1,
    active: true,
    created_at: new Date(Date.now() - 86400000 * 10).toISOString(),
    updated_at: new Date(Date.now() - 86400000 * 10).toISOString(),
  },
]

for (const item of initialDemoIntel) {
  inMemoryIntel.set(item.id, { ...item })
}

let engineSettings = {
  enableVerifiedIntel: process.env.ENABLE_VERIFIED_INTEL !== 'false',
  auditRetentionDays: AUDIT_RETENTION_DAYS,
  lastUpdated: new Date().toISOString(),
  updatedBy: 'system',
}

export function isVerifiedIntelEnabled() {
  return engineSettings.enableVerifiedIntel
}

export function getEngineSettings() {
  return { ...engineSettings, auditRetentionDays: AUDIT_RETENTION_DAYS }
}

export function updateEngineSettings(newSettings = {}, actor = 'moderator', actorEmail = null) {
  if (typeof newSettings.enableVerifiedIntel === 'boolean') {
    engineSettings.enableVerifiedIntel = newSettings.enableVerifiedIntel
    engineSettings.lastUpdated = new Date().toISOString()
    engineSettings.updatedBy = actorEmail || actor
    void recordAuditLog({
      reportId: null,
      action: 'UPDATE_SETTINGS',
      targetIndicator: 'engine.enableVerifiedIntel',
      threatCategory: null,
      actorEmail: actorEmail || (actor.includes('@') ? actor : null),
      actorRole: actor.includes('@') ? 'moderator' : actor,
      confidence: 1.0,
      moderatorNotes: newSettings.enableVerifiedIntel
        ? 'Threat feedback loop active with real-time community intelligence.'
        : 'Threat feedback loop paused by moderator.',
    })
  }

  if (
    typeof newSettings.auditRetentionDays === 'number' &&
    Number.isFinite(newSettings.auditRetentionDays) &&
    newSettings.auditRetentionDays > 0
  ) {
    const oldDays = AUDIT_RETENTION_DAYS
    AUDIT_RETENTION_DAYS = Math.round(newSettings.auditRetentionDays)
    engineSettings.auditRetentionDays = AUDIT_RETENTION_DAYS
    engineSettings.lastUpdated = new Date().toISOString()
    engineSettings.updatedBy = actorEmail || actor
    void recordAuditLog({
      reportId: null,
      action: 'UPDATE_SETTINGS',
      targetIndicator: 'policy.auditRetentionDays',
      threatCategory: null,
      actorEmail: actorEmail || (actor.includes('@') ? actor : null),
      actorRole: actor.includes('@') ? 'moderator' : actor,
      confidence: 1.0,
      moderatorNotes: `Audit data retention policy manually updated from ${oldDays} days to ${AUDIT_RETENTION_DAYS} days by moderator.`,
    })
  }

  return { ...engineSettings, auditRetentionDays: AUDIT_RETENTION_DAYS }
}

export function isSupabaseConfigured() {
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
  if (!body.contentSha256 && typeof body.text === 'string' && body.text.trim()) {
    body.contentSha256 = createHash('sha256').update(body.text.trim()).digest('hex')
  }
  if (!body.contentSha256 || typeof body.contentSha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(body.contentSha256)) {
    return 'contentSha256 is required and must be a 64-character hex string.'
  }
  if (body.reportedDomain !== undefined && body.reportedDomain !== null) {
    if (typeof body.reportedDomain !== 'string' || body.reportedDomain.length > 255) {
      return 'reportedDomain must be a string up to 255 characters.'
    }
  }
  if (body.threatCategory !== undefined && body.threatCategory !== null) {
    if (typeof body.threatCategory !== 'string' || body.threatCategory.length > 100) {
      return 'threatCategory must be a string up to 100 characters.'
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

/**
 * Compute dynamically scaled confidence incorporating corroboration count.
 * Formula: Doubt(n) = (1 - C_base) * (0.65)^(n - 1)
 *          C_effective = 1 - Doubt(n)
 * @param {number} baseConfidence - Initial moderator confidence (e.g. 0.70, 0.85, 1.0)
 * @param {number} reportCount - Number of independent corroborating reports (>= 1)
 * @returns {number} Effective confidence between 0.5 and 1.0 (rounded to 3 decimals)
 */
export function computeEffectiveConfidence(baseConfidence = 1.0, reportCount = 1) {
  const base = Math.max(0.1, Math.min(1.0, Number(baseConfidence) || 1.0))
  const n = Math.max(1, Number(reportCount) || 1)
  if (base >= 0.999 || n === 1) return Number(base.toFixed(3))
  const doubt = (1.0 - base) * Math.pow(0.65, n - 1)
  const effective = Math.min(1.0, 1.0 - doubt)
  return Number(effective.toFixed(3))
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
  if (body.confidence !== undefined && body.confidence !== null) {
    const conf = Number(body.confidence)
    if (isNaN(conf) || conf < 0.1 || conf > 1.0) {
      return 'confidence must be a number between 0.1 and 1.0.'
    }
  }
  return null
}

export const DEDUPLICATION_WINDOW_MS = 15 * 60 * 1000 // 15-minute coalescing cooldown window

/**
 * Looks up an existing pending report submitted within the cooldown window with matching hash and type.
 */
export async function findDuplicatePendingReport(contentSha256, reportType, reportedDomain = null) {
  const cutoff = new Date(Date.now() - DEDUPLICATION_WINDOW_MS).toISOString()

  if (isSupabaseConfigured()) {
    try {
      const url = `${SUPABASE_URL}/rest/v1/user_reports?status=eq.PENDING&report_type=eq.${encodeURIComponent(reportType)}&content_sha256=eq.${encodeURIComponent(contentSha256)}&created_at=gte.${encodeURIComponent(cutoff)}&order=created_at.desc&limit=1`
      const res = await fetch(url, {
        headers: getHeaders(),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      })
      if (res.ok) {
        const items = await res.json()
        if (items.length > 0) return items[0]
      }
    } catch {
      // Fall through to in-memory check
    }
  }

  const cutoffMs = Date.now() - DEDUPLICATION_WINDOW_MS
  for (const report of inMemoryReports.values()) {
    if (
      report.status === 'PENDING' &&
      report.report_type === reportType &&
      report.content_sha256 === contentSha256 &&
      new Date(report.created_at).getTime() >= cutoffMs
    ) {
      return report
    }
  }

  return null
}

export async function submitReport(payload) {
  const contentSha256 = payload.contentSha256.toLowerCase()
  const reportType = payload.reportType
  const reportedDomain = payload.reportedDomain?.trim().toLowerCase() || null

  // ── Ingestion Deduplication (15-Minute Cooldown Window) ────────────
  const existingPending = await findDuplicatePendingReport(contentSha256, reportType, reportedDomain)

  if (existingPending) {
    const countMatch = existingPending.notes?.match(/\[Corroborated Submissions:\s*(\d+)\]/i)
    const currentCount = countMatch ? parseInt(countMatch[1], 10) : 1
    const newCount = currentCount + 1

    let updatedNotes = existingPending.notes || ''
    if (countMatch) {
      updatedNotes = updatedNotes.replace(/\[Corroborated Submissions:\s*\d+\]/i, `[Corroborated Submissions: ${newCount}]`)
    } else {
      updatedNotes = `[Corroborated Submissions: ${newCount}]\n${updatedNotes}`.trim()
    }

    const newContext = payload.notes?.trim()
    if (newContext && !updatedNotes.includes(newContext)) {
      const addition = `\n[Additional Context]: ${newContext}`
      if ((updatedNotes + addition).length <= 2000) {
        updatedNotes += addition
      }
    }

    if (isSupabaseConfigured()) {
      try {
        const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/user_reports?id=eq.${encodeURIComponent(existingPending.id)}`, {
          method: 'PATCH',
          headers: getHeaders(),
          body: JSON.stringify({ notes: updatedNotes }),
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        })
        if (patchRes.ok) {
          return {
            ...existingPending,
            notes: updatedNotes,
            coalesced: true,
            submission_count: newCount,
          }
        }
      } catch {
        // Fall back to in-memory update
      }
    }

    existingPending.notes = updatedNotes
    existingPending.submission_count = newCount
    existingPending.coalesced = true
    inMemoryReports.set(existingPending.id, existingPending)
    return {
      ...existingPending,
      notes: updatedNotes,
      coalesced: true,
      submission_count: newCount,
    }
  }

  // ── No Duplicate Found: Create New Pending Report ─────────────────
  let finalNotes = payload.notes?.trim() || null
  if (payload.rawExcerpt && (!finalNotes || !finalNotes.includes(payload.rawExcerpt))) {
    finalNotes = `[Reported Message Excerpt]: "${payload.rawExcerpt}"${finalNotes ? `\n\n[Submitter Context]: ${finalNotes}` : ''}`
  }
  if (payload.threatCategory) {
    finalNotes = `[Threat Category]: ${payload.threatCategory}\n${finalNotes || ''}`.trim()
  }

  const report = {
    id: randomUUID(),
    report_type: reportType,
    threat_category: payload.threatCategory || null,
    content_sha256: contentSha256,
    reported_domain: reportedDomain,
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
    return { ...report, ...(saved || {}) }
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
    return { reports: reports.map(enrichReportWithTriage), total }
  }

  const list = Array.from(inMemoryReports.values()).sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  )
  const filtered = status && status !== 'ALL' ? list.filter((r) => r.status === status) : list
  const total = filtered.length
  const reports = limit !== null && limit > 0 ? filtered.slice(offset, offset + limit) : filtered
  return { reports: reports.map(enrichReportWithTriage), total }
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
      } catch (_) { }
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

export async function processModerationReview(reviewPayload, actorRole = 'moderator', actorEmail = null) {
  const { reportId, action, notes, indicatorType, category, confidence } = reviewPayload

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

  const storedDomain = report.reported_domain || ''
  const rawDomain = rehydrate(storedDomain)
  const primaryVal = rawDomain || report.content_sha256
  const chosenConfidence = typeof confidence === 'number' && confidence >= 0.1 && confidence <= 1.0
    ? Number(confidence.toFixed(3))
    : 1.0

  // 2. Add enriched audit log with 90-day retention
  await recordAuditLog({
    reportId,
    action,
    targetIndicator: defang(primaryVal),
    threatCategory: category || (report.report_type === 'false_positive' ? 'False Alarm' : 'Reported Scam'),
    actorEmail,
    actorRole,
    confidence: chosenConfidence,
    moderatorNotes: notes || (action === 'APPROVE' ? 'Approved by moderator and sanitized for threat intelligence.' : 'Dismissed by moderator.'),
  })

  // 3. Sanitization Pipeline for APPROVE action
  let verifiedIntelligenceId = null
  if (action === 'APPROVE') {
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
      confidence: chosenConfidence,
      notes: notes || report.notes || 'Verified by moderator approval',
      report_count: 1,
      active: true,
      created_at: new Date().toISOString(),
    })

    // Option A: Only create content_hash if NO rawDomain exists (pure text/phone scam)
    if (!rawDomain && report.content_sha256 && /^[a-f0-9]{64}$/i.test(report.content_sha256)) {
      if (primaryVal.toLowerCase() !== report.content_sha256.toLowerCase()) {
        intelRecords.push({
          id: randomUUID(),
          source_report_id: reportId,
          indicator_type: 'content_hash',
          indicator_value: report.content_sha256.toLowerCase(),
          defanged_value: report.content_sha256.toLowerCase(),
          risk_level: report.report_type === 'false_positive' ? 'VERIFIED_SAFE' : 'CONFIRMED_SCAM',
          category: category || (report.report_type === 'false_positive' ? 'False Alarm' : 'Reported Scam'),
          confidence: chosenConfidence < 1.0 ? chosenConfidence : 0.95,
          notes: notes || report.notes || `Cryptographic fingerprint for verified report ${reportId.slice(0, 8)}`,
          report_count: 1,
          active: true,
          created_at: new Date().toISOString(),
        })
      }
    }

    for (const intelRecord of intelRecords) {
      if (isSupabaseConfigured()) {
        try {
          // Check if an indicator with the exact same indicator_value already exists (Deduplication)
          const checkQuery = `${SUPABASE_URL}/rest/v1/verified_intelligence?indicator_value=eq.${encodeURIComponent(intelRecord.indicator_value)}&limit=1`
          const checkRes = await fetch(checkQuery, {
            headers: getHeaders(),
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          })
          if (checkRes.ok) {
            const [existing] = await checkRes.json()
            if (existing) {
              const updatedCount = (existing.report_count || 1) + 1
              const baseConf = Math.max(Number(existing.confidence) || 0.85, chosenConfidence)
              const updatedConfidence = computeEffectiveConfidence(baseConf, updatedCount)
              const updatedNotes = notes && !existing.notes?.includes(notes) ? `${existing.notes} | ${notes}` : existing.notes
              const updatePayload = {
                report_count: updatedCount,
                confidence: updatedConfidence,
                updated_at: new Date().toISOString(),
                ...(updatedNotes ? { notes: updatedNotes } : {}),
              }
              const updateRes = await fetch(`${SUPABASE_URL}/rest/v1/verified_intelligence?id=eq.${existing.id}`, {
                method: 'PATCH',
                headers: getHeaders(),
                body: JSON.stringify(updatePayload),
                signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
              })
              if (updateRes.ok) {
                if (!verifiedIntelligenceId) verifiedIntelligenceId = existing.id
                continue
              }
            }
          }

          // Not found, insert new indicator
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
        // In-memory Deduplication & Frequency Counter
        let existing = null
        for (const item of inMemoryIntel.values()) {
          if (item.indicator_value === intelRecord.indicator_value) {
            existing = item
            break
          }
        }

        if (existing) {
          existing.report_count = (existing.report_count || 1) + 1
          const baseConf = Math.max(Number(existing.confidence) || 0.85, chosenConfidence)
          existing.confidence = computeEffectiveConfidence(baseConf, existing.report_count)
          existing.updated_at = new Date().toISOString()
          if (notes && !existing.notes?.includes(notes)) {
            existing.notes = `${existing.notes} | ${notes}`
          }
          inMemoryIntel.set(existing.id, existing)
          if (!verifiedIntelligenceId) verifiedIntelligenceId = existing.id
        } else {
          intelRecord.report_count = 1
          intelRecord.confidence = chosenConfidence
          inMemoryIntel.set(intelRecord.id, intelRecord)
          if (!verifiedIntelligenceId) verifiedIntelligenceId = intelRecord.id
        }
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
    } catch { }
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
        filters.push(`defanged_value.in.(${quoted})`)
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
            reportCount: Number(match.report_count) || 1,
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
      if (indicators.includes(intel.indicator_value) || indicators.includes(intel.defanged_value) || contentSha256 === intel.indicator_value) {
        findings.push({
          canonicalSignal: intel.risk_level === 'CONFIRMED_SCAM' ? 'verified_scam_intelligence' : 'verified_safe_intelligence',
          category: intel.category || 'Threat Intelligence',
          evidence: `Indicator ${intel.defanged_value} confirmed by moderator review.`,
          source: 'APPROVED_REPORT',
          strength: intel.risk_level === 'CONFIRMED_SCAM' ? 1.0 : 0.0,
          confidence: Number(intel.confidence) || 1.0,
          reportCount: Number(intel.report_count) || 1,
          limitation: 'Verified via community intelligence reports.',
        })
      }
    }
  }

  return findings
}

/**
 * Records an immutable audit log entry for moderator actions or governance events.
 * Enforces 90-day rolling retention TTL (expires_at).
 */
export async function recordAuditLog({
  reportId = null,
  action,
  targetIndicator = null,
  threatCategory = null,
  actorEmail = null,
  actorRole = 'moderator',
  confidence = null,
  moderatorNotes = null,
}) {
  const expiresAt = new Date(Date.now() + AUDIT_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString()
  const logEntry = {
    id: randomUUID(),
    report_id: reportId,
    action,
    target_indicator: targetIndicator,
    threat_category: threatCategory,
    actor_email: actorEmail || null,
    actor_role: actorRole || 'moderator',
    confidence: typeof confidence === 'number' ? Number(confidence.toFixed(3)) : null,
    moderator_notes: moderatorNotes || null,
    created_at: new Date().toISOString(),
    expires_at: expiresAt,
  }

  if (isSupabaseConfigured()) {
    try {
      // Attempt 1: Full insert with all enriched columns (requires migration 202609220001)
      const res = await fetch(`${SUPABASE_URL}/rest/v1/moderation_audit_logs`, {
        method: 'POST',
        headers: { ...getHeaders(), Prefer: 'return=representation' },
        body: JSON.stringify(logEntry),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      })
      if (res.ok) {
        const body = await res.json()
        const saved = Array.isArray(body) ? body[0] : body
        if (saved) {
          inMemoryAuditLogs.unshift({ ...logEntry, ...saved })
          return { ...logEntry, ...saved }
        }
        inMemoryAuditLogs.unshift(logEntry)
        return logEntry
      }

      // Attempt 2: Graceful schema-compat fallback — use only columns guaranteed in older schema.
      // Encodes extra data into moderator_notes so nothing is lost.
      const notesParts = []
      if (targetIndicator) notesParts.push(`[Target]: ${targetIndicator}`)
      if (threatCategory) notesParts.push(`[Category]: ${threatCategory}`)
      if (actorEmail) notesParts.push(`[Actor]: ${actorEmail}`)
      if (moderatorNotes) notesParts.push(moderatorNotes)
      const compactNotes = notesParts.join(' | ')

      const compatPayload = {
        action,
        actor_role: actorRole || 'moderator',
        moderator_notes: compactNotes || null,
        // report_id: only include if non-null (avoids NOT NULL violation)
        ...(reportId ? { report_id: reportId } : {}),
      }
      const res2 = await fetch(`${SUPABASE_URL}/rest/v1/moderation_audit_logs`, {
        method: 'POST',
        headers: { ...getHeaders(), Prefer: 'return=representation' },
        body: JSON.stringify(compatPayload),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      })
      if (res2.ok) {
        const body2 = await res2.json()
        const saved2 = Array.isArray(body2) ? body2[0] : body2
        // Always keep in-memory with full detail so UI shows the enriched data
        inMemoryAuditLogs.unshift(logEntry)
        return saved2 ? { ...logEntry, id: saved2.id } : logEntry
      }
    } catch {
      // Non-blocking fallback to in-memory store
    }
  }

  inMemoryAuditLogs.unshift(logEntry)
  return logEntry
}


/**
 * Queries moderation audit logs with filtering, search, and pagination.
 */
export async function getModerationAuditLogs({
  action = 'ALL',
  search = '',
  page = 1,
  limit = 20,
} = {}) {
  const pageNum = Number.isFinite(Number(page)) && Number(page) > 0 ? Number(page) : 1
  const limitNum = Number.isFinite(Number(limit)) && Number(limit) > 0 && Number(limit) <= 100 ? Number(limit) : 20
  const offset = (pageNum - 1) * limitNum
  const searchTrim = typeof search === 'string' ? search.trim().toLowerCase() : ''

  if (isSupabaseConfigured()) {
    try {
      let query = `${SUPABASE_URL}/rest/v1/moderation_audit_logs?select=*,user_reports(reported_domain,notes,report_type)&order=created_at.desc`
      if (action && action !== 'ALL') {
        query += `&action=eq.${encodeURIComponent(action)}`
      }
      if (!searchTrim) {
        query += `&limit=${limitNum}&offset=${offset}`
      }
      const headers = { ...getHeaders(), Prefer: 'count=exact' }
      const res = await fetch(query, { headers, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) })
      if (res.ok) {
        const rawRows = await res.json()
        let rows = rawRows.map((row) => {
          const rep = row.user_reports
          let target = row.target_indicator
          if (!target && rep?.reported_domain) {
            target = rep.reported_domain
          }
          if (target && !target.startsWith('Report #') && !target.startsWith('policy.') && !target.startsWith('engine.')) {
            target = target.replace(/^https?:\/\//i, (m) => m.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://')
            if (!target.includes('[.]')) {
              target = target.replace(/\.(?=[a-zA-Z0-9])/g, '[.]')
            }
          }

          let category = row.threat_category
          if (!category && rep?.notes) {
            const catMatch = rep.notes.match(/\[Threat Category\]:\s*([^\n\r]+)/)
            if (catMatch) category = catMatch[1].trim()
          }
          if (!category) {
            const combinedText = `${rep?.reported_domain || ''} ${rep?.notes || ''} ${row.moderator_notes || ''}`.toLowerCase()
            if (rep?.report_type === 'false_positive' || combinedText.includes('false alarm') || combinedText.includes('official') || combinedText.includes('legitimate')) {
              category = 'False Alarm'
            } else if (combinedText.includes('ceb') || combinedText.includes('electricity') || combinedText.includes('utility') || combinedText.includes('bill')) {
              category = 'Utility Bill Scam'
            } else if (combinedText.includes('bank') || combinedText.includes('boc') || combinedText.includes('combank') || combinedText.includes('otp')) {
              category = 'Banking Phishing'
            } else if (combinedText.includes('telecom') || combinedText.includes('dialog') || combinedText.includes('mobitel')) {
              category = 'Telecom Scam'
            } else if (combinedText.includes('job') || combinedText.includes('salary') || combinedText.includes('hiring')) {
              category = 'Fake Job Scam'
            } else if (combinedText.includes('apk') || combinedText.includes('malware') || combinedText.includes('trojan')) {
              category = 'Malware / APK'
            } else if (row.action === 'APPROVE') {
              category = 'Confirmed Threat'
            } else if (row.action === 'REJECT') {
              category = 'Dismissed Report'
            } else if (row.action === 'RETIRE') {
              category = 'Retired Indicator'
            } else if (row.action === 'UPDATE_SETTINGS' || row.action === 'TOGGLE_STATUS') {
              category = 'Engine Policy'
            }
          }

          const expiresAt = row.expires_at || new Date(new Date(row.created_at).getTime() + AUDIT_RETENTION_DAYS * 86400000).toISOString()

          return {
            ...row,
            target_indicator: target || (row.report_id ? `Report #${row.report_id.slice(0, 8)}` : 'System Policy'),
            threat_category: category,
            actor_email: row.actor_email || 'moderator@trustlens.lk',
            actor_role: row.actor_role || 'moderator',
            expires_at: expiresAt,
          }
        })

        // Merge in-memory audit entries not already in the Supabase result.
        // This ensures actions recorded this session (even if Supabase write failed) appear immediately.
        const dbIds = new Set(rows.map((r) => String(r.id)))
        const tenMinAgo = Date.now() - 10 * 60 * 1000
        const recentMemOnly = inMemoryAuditLogs.filter(
          (m) => !dbIds.has(String(m.id)) && new Date(m.created_at).getTime() > tenMinAgo
        )
        if (recentMemOnly.length > 0) {
          let merged = [...recentMemOnly, ...rows]
          merged.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
          if (searchTrim) {
            merged = merged.filter((item) => {
              return item.target_indicator?.toLowerCase().includes(searchTrim)
                || item.actor_email?.toLowerCase().includes(searchTrim)
                || item.moderator_notes?.toLowerCase().includes(searchTrim)
                || item.threat_category?.toLowerCase().includes(searchTrim)
                || item.report_id?.toString().toLowerCase().includes(searchTrim)
            })
          }
          const mergedTotal = total + recentMemOnly.length
          const mergedTotalPages = Math.ceil(mergedTotal / limitNum) || 1
          return {
            auditLogs: merged.slice(offset, offset + limitNum),
            total: mergedTotal,
            page: pageNum,
            limit: limitNum,
            totalPages: mergedTotalPages,
            retentionDays: AUDIT_RETENTION_DAYS,
          }
        }


        if (searchTrim) {
          rows = rows.filter((item) => {
            const matchTarget = item.target_indicator?.toLowerCase().includes(searchTrim)
            const matchEmail = item.actor_email?.toLowerCase().includes(searchTrim)
            const matchNotes = item.moderator_notes?.toLowerCase().includes(searchTrim)
            const matchCat = item.threat_category?.toLowerCase().includes(searchTrim)
            const matchReportId = item.report_id?.toString().toLowerCase().includes(searchTrim)
            return matchTarget || matchEmail || matchNotes || matchCat || matchReportId
          })
          const total = rows.length
          const totalPages = Math.ceil(total / limitNum) || 1
          const pagedRows = rows.slice(offset, offset + limitNum)
          return {
            auditLogs: pagedRows,
            total,
            page: pageNum,
            limit: limitNum,
            totalPages,
            retentionDays: AUDIT_RETENTION_DAYS,
          }
        }

        const contentRange = res.headers.get('content-range') || ''
        const match = contentRange.match(/\/(\d+|\*)$/)
        const total = match && match[1] !== '*' ? parseInt(match[1], 10) : rows.length
        const totalPages = Math.ceil(total / limitNum) || 1
        return {
          auditLogs: rows,
          total,
          page: pageNum,
          limit: limitNum,
          totalPages,
          retentionDays: AUDIT_RETENTION_DAYS,
        }
      }
    } catch {
      // Fallback to in-memory on network error
    }
  }

  let filtered = [...inMemoryAuditLogs]
  if (action && action !== 'ALL') {
    filtered = filtered.filter((item) => item.action === action)
  }
  if (searchTrim) {
    filtered = filtered.filter((item) => {
      const matchIndicator = item.target_indicator?.toLowerCase().includes(searchTrim)
      const matchEmail = item.actor_email?.toLowerCase().includes(searchTrim)
      const matchNotes = item.moderator_notes?.toLowerCase().includes(searchTrim)
      const matchCategory = item.threat_category?.toLowerCase().includes(searchTrim)
      const matchReportId = item.report_id?.toLowerCase().includes(searchTrim)
      return matchIndicator || matchEmail || matchNotes || matchCategory || matchReportId
    })
  }

  filtered.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
  const total = filtered.length
  const totalPages = Math.ceil(total / limitNum) || 1
  const auditLogs = filtered.slice(offset, offset + limitNum)

  return {
    auditLogs,
    total,
    page: pageNum,
    limit: limitNum,
    totalPages,
    retentionDays: AUDIT_RETENTION_DAYS,
  }
}

/**
 * Purges audit logs whose retention window has passed.
 * Supports retentionDays limit and an optional safety grace window.
 * Uses created_at cutoff for guaranteed compatibility across database schemas.
 */
export async function purgeExpiredAuditLogs(retentionDays = AUDIT_RETENTION_DAYS, graceDays = 0) {
  const days = Number(retentionDays) > 0 ? Number(retentionDays) : AUDIT_RETENTION_DAYS
  const grace = Number(graceDays) >= 0 ? Number(graceDays) : 0
  const cutoffMs = Date.now() - (days + grace) * 86400000
  const cutoffIso = new Date(cutoffMs).toISOString()
  let purgedCount = 0

  if (isSupabaseConfigured()) {
    try {
      const deleteUrl = `${SUPABASE_URL}/rest/v1/moderation_audit_logs?created_at=lt.${encodeURIComponent(cutoffIso)}`
      const res = await fetch(deleteUrl, {
        method: 'DELETE',
        headers: { ...getHeaders(), Prefer: 'return=representation' },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      })
      if (res.ok) {
        const deleted = await res.json()
        if (Array.isArray(deleted)) {
          purgedCount = deleted.length
        }
      }
    } catch {
      // Non-fatal error during purge
    }
  }

  const beforeLen = inMemoryAuditLogs.length
  for (let i = inMemoryAuditLogs.length - 1; i >= 0; i--) {
    const item = inMemoryAuditLogs[i]
    const createdMs = new Date(item.created_at).getTime()
    if (createdMs && createdMs < cutoffMs) {
      inMemoryAuditLogs.splice(i, 1)
    }
  }
  const memoryPurged = beforeLen - inMemoryAuditLogs.length
  purgedCount = Math.max(purgedCount, memoryPurged)

  return {
    purgedCount,
    timestamp: cutoffIso,
    retentionDays: days,
    graceDays: grace,
  }
}

let retentionSchedulerInterval = null

/**
 * Initializes a background cron-like interval that runs every 24 hours to automatically
 * purge audit records that have passed the retention policy plus a 7-day safety grace window.
 */
export function startAuditRetentionScheduler(intervalMs = 24 * 60 * 60 * 1000) {
  if (retentionSchedulerInterval) {
    clearInterval(retentionSchedulerInterval)
  }

  // Quick initial audit sweep 10 seconds after server startup
  setTimeout(async () => {
    try {
      const result = await purgeExpiredAuditLogs(AUDIT_RETENTION_DAYS, 7)
      if (result.purgedCount > 0) {
        console.log(`[AuditRetentionScheduler] Auto-purged ${result.purgedCount} expired audit records older than ${result.retentionDays + result.graceDays} days.`)
      }
    } catch (e) {
      console.warn('[AuditRetentionScheduler] Initial purge warning:', e.message)
    }
  }, 10000)

  retentionSchedulerInterval = setInterval(async () => {
    try {
      const result = await purgeExpiredAuditLogs(AUDIT_RETENTION_DAYS, 7)
      if (result.purgedCount > 0) {
        console.log(`[AuditRetentionScheduler] Auto-purged ${result.purgedCount} expired audit records.`)
      }
    } catch (e) {
      console.warn('[AuditRetentionScheduler] Background purge warning:', e.message)
    }
  }, intervalMs)

  return retentionSchedulerInterval
}

export function stopAuditRetentionScheduler() {
  if (retentionSchedulerInterval) {
    clearInterval(retentionSchedulerInterval)
    retentionSchedulerInterval = null
  }
}

/**
 * Returns metrics on audit storage volume, retention policy, and health status.
 */
export async function getAuditStorageStats() {
  const nowMs = Date.now()
  const retentionMs = AUDIT_RETENTION_DAYS * 86400000
  const warningWindowMs = 7 * 86400000

  if (isSupabaseConfigured()) {
    try {
      const res = await fetch(`${SUPABASE_URL}/rest/v1/moderation_audit_logs?select=id,action,created_at&order=created_at.desc`, {
        headers: getHeaders(),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      })
      if (res.ok) {
        const rows = await res.json()
        const total = rows.length
        const sorted = [...rows].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())

        let expiredRecordsCount = 0
        let expiringSoonCount = 0
        for (const r of rows) {
          const createdMs = new Date(r.created_at).getTime()
          if (isNaN(createdMs)) continue
          const expiresMs = createdMs + retentionMs
          if (expiresMs <= nowMs) {
            expiredRecordsCount++
          } else if (expiresMs <= nowMs + warningWindowMs) {
            expiringSoonCount++
          }
        }

        const actionBreakdown = {
          approve: rows.filter((r) => r.action === 'APPROVE').length,
          reject: rows.filter((r) => r.action === 'REJECT').length,
          retire: rows.filter((r) => r.action === 'RETIRE').length,
          settings: rows.filter((r) => r.action === 'UPDATE_SETTINGS').length,
          toggle: rows.filter((r) => r.action === 'TOGGLE_STATUS').length,
          purge: rows.filter((r) => r.action === 'PURGE_EXPIRED').length,
        }
        return {
          totalRecords: total,
          retentionDays: AUDIT_RETENTION_DAYS,
          oldestRecordAt: sorted[0]?.created_at || null,
          newestRecordAt: sorted[sorted.length - 1]?.created_at || null,
          storageStatus: total >= 100000 ? 'CAPACITY_REACHED' : total >= 50000 ? 'WARNING' : 'OPTIMAL',
          actionBreakdown,
          expiredRecordsCount,
          expiringSoonCount,
        }
      }
    } catch {
      // Fallback to in-memory on connection error
    }
  }

  const total = inMemoryAuditLogs.length
  let oldestRecordAt = null
  let newestRecordAt = null
  let expiredRecordsCount = 0
  let expiringSoonCount = 0

  if (total > 0) {
    const sorted = [...inMemoryAuditLogs].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
    oldestRecordAt = sorted[0]?.created_at || null
    newestRecordAt = sorted[sorted.length - 1]?.created_at || null

    for (const a of inMemoryAuditLogs) {
      const createdMs = new Date(a.created_at).getTime()
      if (isNaN(createdMs)) continue
      const expiresMs = createdMs + retentionMs
      if (expiresMs <= nowMs) {
        expiredRecordsCount++
      } else if (expiresMs <= nowMs + warningWindowMs) {
        expiringSoonCount++
      }
    }
  }

  return {
    totalRecords: total,
    retentionDays: AUDIT_RETENTION_DAYS,
    oldestRecordAt,
    newestRecordAt,
    storageStatus: total >= 100000 ? 'CAPACITY_REACHED' : total >= 50000 ? 'WARNING' : 'OPTIMAL',
    actionBreakdown: {
      approve: inMemoryAuditLogs.filter((a) => a.action === 'APPROVE').length,
      reject: inMemoryAuditLogs.filter((a) => a.action === 'REJECT').length,
      retire: inMemoryAuditLogs.filter((a) => a.action === 'RETIRE').length,
      settings: inMemoryAuditLogs.filter((a) => a.action === 'UPDATE_SETTINGS').length,
      toggle: inMemoryAuditLogs.filter((a) => a.action === 'TOGGLE_STATUS').length,
      purge: inMemoryAuditLogs.filter((a) => a.action === 'PURGE_EXPIRED').length,
    },
    expiredRecordsCount,
    expiringSoonCount,
  }
}

export function resetInMemoryStores() {
  inMemoryReports.clear()
  inMemoryIntel.clear()
  inMemoryAuditLogs.length = 0
}

export async function getVerifiedIntelligenceList(options = {}) {
  const {
    status = 'all',
    type = 'all',
    riskLevel = 'all',
    search = '',
    page = 1,
    limit = 20,
  } = options

  const parsedPage = Math.max(1, parseInt(page, 10) || 1)
  const parsedLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 20))
  const offset = (parsedPage - 1) * parsedLimit

  if (isSupabaseConfigured()) {
    try {
      const filters = []
      if (status === 'active') filters.push('active=eq.true')
      if (status === 'retired') filters.push('active=eq.false')
      if (type && type !== 'all') filters.push(`indicator_type=eq.${type}`)
      if (riskLevel && riskLevel !== 'all') filters.push(`risk_level=eq.${riskLevel}`)
      if (search && search.trim()) {
        const cleanSearch = search.trim().replace(/"/g, '')
        filters.push(`or=(indicator_value.ilike.*${cleanSearch}*,defanged_value.ilike.*${cleanSearch}*,notes.ilike.*${cleanSearch}*,category.ilike.*${cleanSearch}*)`)
      }

      const queryString = filters.length ? `?${filters.join('&')}` : ''
      const url = `${SUPABASE_URL}/rest/v1/verified_intelligence${queryString}${queryString ? '&' : '?'}order=created_at.desc&limit=${parsedLimit}&offset=${offset}`

      const res = await fetch(url, {
        headers: {
          ...getHeaders(),
          Prefer: 'count=exact',
        },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      })

      if (res.ok) {
        const rawIntelligence = await res.json()
        const intelligence = rawIntelligence.map((item) => ({
          ...item,
          report_count: item.report_count || 1,
        }))
        const contentRange = res.headers.get('content-range')
        let total = intelligence.length
        if (contentRange) {
          const match = contentRange.match(/\/(\d+|\*)$/)
          if (match && match[1] !== '*') total = parseInt(match[1], 10)
        }
        return {
          intelligence,
          total,
          page: parsedPage,
          limit: parsedLimit,
          totalPages: Math.ceil(total / parsedLimit) || 1,
        }
      }
    } catch {
      // Fallback to in-memory on connection or query error
    }
  }

  // In-memory fallback
  let items = Array.from(inMemoryIntel.values())
  if (status === 'active') items = items.filter((item) => item.active === true)
  if (status === 'retired') items = items.filter((item) => item.active === false)
  if (type && type !== 'all') items = items.filter((item) => item.indicator_type === type)
  if (riskLevel && riskLevel !== 'all') items = items.filter((item) => item.risk_level === riskLevel)
  if (search && search.trim()) {
    const s = search.trim().toLowerCase()
    items = items.filter(
      (item) =>
        (item.indicator_value && item.indicator_value.toLowerCase().includes(s)) ||
        (item.defanged_value && item.defanged_value.toLowerCase().includes(s)) ||
        (item.notes && item.notes.toLowerCase().includes(s)) ||
        (item.category && item.category.toLowerCase().includes(s))
    )
  }

  items.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())

  const total = items.length
  const paginated = items.slice(offset, offset + parsedLimit).map((item) => ({
    ...item,
    report_count: item.report_count || 1,
  }))

  return {
    intelligence: paginated,
    total,
    page: parsedPage,
    limit: parsedLimit,
    totalPages: Math.ceil(total / parsedLimit) || 1,
  }
}

export async function updateIntelligenceStatus(id, { active, notes, category, actorRole = 'moderator', actorEmail = null } = {}) {
  const updatedAt = new Date().toISOString()

  if (isSupabaseConfigured()) {
    try {
      const updatePayload = {
        updated_at: updatedAt,
      }
      if (typeof active === 'boolean') {
        updatePayload.active = active
      }
      if (typeof notes === 'string') {
        updatePayload.notes = notes.trim()
      }
      if (typeof category === 'string' && category.trim()) {
        updatePayload.category = category.trim()
      }

      const res = await fetch(`${SUPABASE_URL}/rest/v1/verified_intelligence?id=eq.${id}`, {
        method: 'PATCH',
        headers: getHeaders(),
        body: JSON.stringify(updatePayload),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      })

      if (res.ok) {
        const [updated] = await res.json()
        if (updated) {
          const actionType = typeof active === 'boolean'
            ? (active ? 'TOGGLE_STATUS' : 'RETIRE')
            : 'TOGGLE_STATUS'
          await recordAuditLog({
            reportId: updated.source_report_id || null,
            action: actionType,
            targetIndicator: updated.defanged_value || id,
            threatCategory: updated.category || null,
            actorEmail,
            actorRole,
            confidence: Number(updated.confidence || 1.0),
            moderatorNotes: notes || `Indicator ${active ? 'reactivated' : 'retired'} by moderator.`,
          })
          return { ...updated, report_count: updated.report_count || 1 }
        }
      }
    } catch {
      // Fallback to in-memory on error
    }
  }

  const existing = inMemoryIntel.get(id)
  if (!existing) {
    throw new Error('Intelligence item not found.')
  }

  if (typeof active === 'boolean') {
    existing.active = active
  }
  if (typeof notes === 'string') {
    existing.notes = notes.trim()
  }
  if (typeof category === 'string' && category.trim()) {
    existing.category = category.trim()
  }
  existing.updated_at = updatedAt
  inMemoryIntel.set(id, existing)

  const actionType = typeof active === 'boolean'
    ? (active ? 'TOGGLE_STATUS' : 'RETIRE')
    : 'TOGGLE_STATUS'

  await recordAuditLog({
    reportId: existing.source_report_id || null,
    action: actionType,
    targetIndicator: existing.defanged_value || id,
    threatCategory: existing.category || null,
    actorEmail,
    actorRole,
    confidence: Number(existing.confidence || 1.0),
    moderatorNotes: notes || `Indicator ${active ? 'reactivated' : 'retired'} by moderator.`,
  })

  return { ...existing, report_count: existing.report_count || 1 }
}

/**
 * Lets a moderator add a known-scam (or known-safe) indicator directly to
 * the verified intelligence feed, without waiting for a citizen report to
 * arrive and be reviewed first. Writes to the same verified_intelligence
 * table and shape that processModerationReview's approval path writes to,
 * so both paths are picked up identically by checkVerifiedIntelligence.
 */
export async function createManualIntelligenceEntry(data, actorRole = 'moderator') {
  const rawValue = (data.indicatorValue || '').toLowerCase().trim()
  if (!rawValue) {
    throw new Error('indicatorValue is required.')
  }
  const indicatorType = data.indicatorType || 'domain'
  const riskLevel = data.riskLevel === 'VERIFIED_SAFE' ? 'VERIFIED_SAFE' : 'CONFIRMED_SCAM'
  const confidence = typeof data.confidence === 'number' && data.confidence >= 0.1 && data.confidence <= 1.0
    ? Number(data.confidence.toFixed(3))
    : 1.0
  const createdAt = new Date().toISOString()

  const record = {
    id: randomUUID(),
    source_report_id: null,
    indicator_type: indicatorType,
    indicator_value: rawValue,
    defanged_value: defang(rawValue),
    risk_level: riskLevel,
    category: data.category?.trim() || (riskLevel === 'CONFIRMED_SCAM' ? 'Moderator-Reported Scam' : 'Moderator-Verified Safe'),
    confidence,
    notes: data.notes?.trim() || 'Added directly by a moderator, not from a citizen report.',
    report_count: 1,
    active: true,
    created_at: createdAt,
  }

  const auditLog = {
    id: randomUUID(),
    report_id: null,
    actor_role: actorRole,
    action: riskLevel === 'CONFIRMED_SCAM' ? 'MANUAL_ADD_SCAM_INTEL' : 'MANUAL_ADD_SAFE_INTEL',
    notes: record.notes,
    created_at: createdAt,
  }

  if (isSupabaseConfigured()) {
    try {
      const checkQuery = `${SUPABASE_URL}/rest/v1/verified_intelligence?indicator_value=eq.${encodeURIComponent(rawValue)}&limit=1`
      const checkRes = await fetch(checkQuery, { headers: getHeaders(), signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) })
      if (checkRes.ok) {
        const [existing] = await checkRes.json().catch(() => [])
        if (existing) {
          throw new Error('DUPLICATE_INDICATOR')
        }
      }

      const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/verified_intelligence`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(record),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      })
      if (!insertRes.ok) {
        const text = await insertRes.text().catch(() => '')
        throw new Error(`Failed to create intelligence entry: ${text.slice(0, 300)}`)
      }
      const [saved] = await insertRes.json().catch(() => [])
      const finalRecord = saved || record

      try {
        await fetch(`${SUPABASE_URL}/rest/v1/moderation_audit_logs`, {
          method: 'POST',
          headers: getHeaders(),
          body: JSON.stringify(auditLog),
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        })
      } catch {
        // Non-blocking if the audit table is still pending migration
      }

      return { ...finalRecord, report_count: finalRecord.report_count || 1 }
    } catch (error) {
      if (error.message === 'DUPLICATE_INDICATOR') throw error
      // Fall through to in-memory on connection error, matching this file's other write paths
    }
  }

  for (const item of inMemoryIntel.values()) {
    if (item.indicator_value === rawValue) {
      throw new Error('DUPLICATE_INDICATOR')
    }
  }
  inMemoryIntel.set(record.id, record)
  inMemoryAuditLogs.push(auditLog)

  return { ...record }
}

export async function seedDemoQueue() {
  const seeded = []
  for (const demo of DEMO_REPORTS) {
    const freshId = randomUUID()
    const dbPayload = {
      id: freshId,
      report_type: demo.report_type,
      content_sha256: demo.content_sha256,
      reported_domain: demo.reported_domain,
      notes: `[Reported Message Excerpt]: "${demo.raw_excerpt}"\n\n[Submitter Context]: ${demo.notes} [DEMO_FIXTURE]`,
      status: demo.status,
      created_at: new Date().toISOString(),
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

  // Ensure demo intelligence items are seeded as well
  for (const item of initialDemoIntel) {
    if (isSupabaseConfigured()) {
      try {
        await fetch(`${SUPABASE_URL}/rest/v1/verified_intelligence`, {
          method: 'POST',
          headers: { ...getHeaders(), Prefer: 'resolution=ignore-duplicates' },
          body: JSON.stringify(item),
        })
      } catch {}
    }
    if (!inMemoryIntel.has(item.id)) {
      inMemoryIntel.set(item.id, { ...item })
    }
  }

  return seeded
}

export async function clearDemoQueue() {
  const demoDomains = [
    'ceb-billpay-portal.xyz',
    'combank-secure-update.online',
    'mohe.gov.lk',
    'phishing-scam.lk',
    'srilanka-telecom-rewards.xyz',
    'fake-prize.lk',
    'news-alert.lk',
    'bank-login.lk',
    'lottery-win.lk',
    'update-security.lk',
    'election-result.lk',
    'health-offer.lk',
    'boc-ebank-login.info',
    'dialog-mega-cash-win.top',
  ]

  let deletedCount = 0

  if (isSupabaseConfigured()) {
    try {
      // 1. Delete reports matching [DEMO_FIXTURE]
      const resFixture = await fetch(
        `${SUPABASE_URL}/rest/v1/user_reports?notes=ilike.*DEMO_FIXTURE*`,
        {
          method: 'DELETE',
          headers: { ...getHeaders(), Prefer: 'return=representation' },
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        }
      )
      if (resFixture.ok) {
        const deleted = await resFixture.json()
        deletedCount += Array.isArray(deleted) ? deleted.length : 0
      }

      // 2. Delete reports matching demo domains
      for (const domain of demoDomains) {
        const res = await fetch(
          `${SUPABASE_URL}/rest/v1/user_reports?reported_domain=eq.${encodeURIComponent(domain)}`,
          {
            method: 'DELETE',
            headers: { ...getHeaders(), Prefer: 'return=representation' },
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          }
        )
        if (res.ok) {
          const deleted = await res.json()
          deletedCount += Array.isArray(deleted) ? deleted.length : 0
        }
      }
    } catch {
      // Fallback
    }
  }

  // Clear from in-memory fallback store
  for (const [id, report] of inMemoryReports.entries()) {
    if (
      report.notes?.includes('DEMO_FIXTURE') ||
      demoDomains.includes(report.reported_domain)
    ) {
      inMemoryReports.delete(id)
      deletedCount++
    }
  }

  return { count: deletedCount }
}


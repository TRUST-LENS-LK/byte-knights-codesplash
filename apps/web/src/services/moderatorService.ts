import { moderationActionSchema } from '@trustlens/contracts'

export interface ModeratorUser {
  id: string
  email: string
  role: 'moderator' | 'admin'
}

export interface ModerationQueueItem {
  id: string
  submission_id: string | null
  report_type: 'suspicious' | 'false_positive' | 'false_negative'
  content_sha256: string
  reported_domain: string | null
  raw_excerpt: string | null
  notes: string | null
  status: 'PENDING' | 'REVIEWED' | 'REJECTED' | 'APPROVED'
  created_at: string
  updated_at: string
  threat?: {
    title: string
    subtitle: string
    type: 'phishing' | 'scam' | 'malware' | 'safe'
  }
  risk_signal?: {
    level: 'HIGH' | 'MEDIUM' | 'LOW'
    color: string
  }
  detected_signals?: string[]
  protected_entity?: {
    isProtected: boolean
    type: 'OFFICIAL_NATIONAL' | 'TOP_GLOBAL'
    name: string
    domain: string
    badge: string
    warning: string
    recommendedAction: 'REJECT' | 'INVESTIGATE_CAREFULLY'
  }
}

export interface ModerationReviewPayload {
  reportId: string
  action: 'APPROVE' | 'REJECT' | 'RETIRE'
  notes?: string
  indicatorType?: 'domain' | 'url' | 'content_hash'
  category?: string
  confidence?: number
  overrideProtectedEntity?: boolean
  incidentReason?: string
}

export interface ModerationReviewResult {
  success: boolean
  status: 'APPROVED' | 'REJECTED' | 'RETIRED'
  verifiedIntelId?: string
  auditId?: string
  message: string
}

export interface ModerationStatsMetrics {
  totalReports: number
  pendingCount: number
  approvedCount: number
  rejectedCount: number
  confirmedThreatCount: number
  clearedSafeCount: number
  verificationVelocity: number
}

export interface ModerationWeeklyActivityItem {
  day: string
  threats: number
  resolved: number
}

export interface ModerationThreatCategoryItem {
  category: string
  count: number
  percentage: number
}

export interface PriorityIncidentSummary {
  id: string
  reported_domain: string | null
  raw_excerpt: string | null
  notes: string | null
  report_type: 'suspicious' | 'false_positive' | 'false_negative'
  created_at: string
}

export interface ModerationStats {
  metrics: ModerationStatsMetrics
  weeklyActivity: ModerationWeeklyActivityItem[]
  threatCategories: ModerationThreatCategoryItem[]
  priorityIncident: PriorityIncidentSummary | null
}

export interface ModerationQueueResponse {
  success: boolean
  reports?: ModerationQueueItem[]
  total?: number
  page?: number
  limit?: number
  totalPages?: number
  error?: string
}

export interface IndicatorHistoryContext {
  reportId: string
  targetIndicator: string
  hasActiveIntel: boolean
  activeIntel: {
    id: string
    risk_level: 'CONFIRMED_SCAM' | 'VERIFIED_SAFE'
    category: string
    confidence: number
    report_count: number
    notes: string | null
    created_at: string
    updated_at: string
  } | null
  isConflict: boolean
  conflictType: 'FALSE_ALARM_AGAINST_SCAM' | 'SCAM_AGAINST_SAFE' | 'NONE'
  conflictExplanation: string | null
  revocationConsequence: string | null
  isCorroborating: boolean
  corroborationSummary: string | null
  projectedConfidence: number | null
  projectedCount: number | null
  priorDecisions: {
    totalRejections: number
    totalApprovals: number
    totalRetirements: number
    totalPriorEvents: number
    latestRejection: {
      actorEmail: string | null
      actorRole: string
      notes: string | null
      createdAt: string
    } | null
    latestAction: {
      action: string
      actorEmail: string | null
      notes: string | null
      createdAt: string
    } | null
  }
}

export interface ModerationStatsResponse {
  success: boolean
  stats?: ModerationStats
  error?: string
}

const TOKEN_KEY = 'trustlens_mod_token'
const USER_KEY = 'trustlens_mod_user'
const API_BASE = 'http://localhost:8787'

export async function fetchIndicatorIntelligenceContext(
  token: string,
  reportId: string
): Promise<{ success: boolean; context?: IndicatorHistoryContext; error?: string }> {
  try {
    const response = await fetch(`${API_BASE}/api/moderation/reports/${encodeURIComponent(reportId)}/context`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
    const data = await response.json()
    if (!response.ok) {
      return { success: false, error: data.message || 'Failed to fetch intelligence context' }
    }
    return { success: true, context: data.context }
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Network error fetching indicator context',
    }
  }
}

export function getStoredSession(): { token: string | null; user: ModeratorUser | null } {
  try {
    const token = sessionStorage.getItem(TOKEN_KEY)
    const userStr = sessionStorage.getItem(USER_KEY)
    const user = userStr ? JSON.parse(userStr) : null
    return { token, user }
  } catch {
    return { token: null, user: null }
  }
}

export function saveSession(token: string, user: ModeratorUser): void {
  try {
    sessionStorage.setItem(TOKEN_KEY, token)
    sessionStorage.setItem(USER_KEY, JSON.stringify(user))
  } catch {
    // SessionStorage unavailable
  }
}

export function clearSession(): void {
  try {
    sessionStorage.removeItem(TOKEN_KEY)
    sessionStorage.removeItem(USER_KEY)
  } catch {
    // Ignore
  }
}

export async function loginModerator(
  email: string,
  password: string
): Promise<{ success: boolean; token?: string; user?: ModeratorUser; error?: string }> {
  try {
    const response = await fetch(`${API_BASE}/api/moderation/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })

    const data = await response.json()

    if (!response.ok) {
      return {
        success: false,
        error: data.message || `Login failed (${response.status})`,
      }
    }

    saveSession(data.accessToken, data.user)
    return {
      success: true,
      token: data.accessToken,
      user: data.user,
    }
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Network error connecting to auth service.',
    }
  }
}

export async function fetchModerationQueue(
  token: string,
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'ALL' = 'PENDING',
  page = 1,
  limit = 20
): Promise<ModerationQueueResponse> {
  try {
    const response = await fetch(
      `${API_BASE}/api/moderation/queue?status=${status}&page=${page}&limit=${limit}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    )

    const data = await response.json()

    if (!response.ok) {
      return {
        success: false,
        error: data.message || `Failed to fetch queue (${response.status})`,
      }
    }

    return {
      success: true,
      reports: data.reports || [],
      total: data.total ?? (data.reports ? data.reports.length : 0),
      page: data.page ?? page,
      limit: data.limit ?? limit,
      totalPages: data.totalPages ?? 1,
    }
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to connect to moderation API.',
    }
  }
}

export async function fetchModerationStats(token: string): Promise<ModerationStatsResponse> {
  try {
    const response = await fetch(`${API_BASE}/api/moderation/stats`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })

    const data = await response.json()

    if (!response.ok) {
      return {
        success: false,
        error: data.message || `Failed to fetch stats (${response.status})`,
      }
    }

    return {
      success: true,
      stats: {
        metrics: data.metrics,
        weeklyActivity: data.weeklyActivity || [],
        threatCategories: data.threatCategories || [],
        priorityIncident: data.priorityIncident || null,
      },
    }
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to connect to moderation stats API.',
    }
  }
}

export async function reviewModerationItem(
  token: string,
  payload: ModerationReviewPayload
): Promise<{
  success: boolean
  result?: ModerationReviewResult
  error?: string
  code?: string
  protectedEntity?: any
}> {
  // Client-side contract validation
  const validation = moderationActionSchema.safeParse(payload)
  if (!validation.success) {
    const errorMessages = validation.error.issues.map((i) => i.message).join('; ')
    return {
      success: false,
      error: `Client validation error: ${errorMessages}`,
    }
  }

  try {
    const response = await fetch(`${API_BASE}/api/moderation/review`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(validation.data),
    })

    const data = await response.json()

    if (!response.ok) {
      return {
        success: false,
        error: data.message || `Review action failed (${response.status})`,
        code: data.code,
        protectedEntity: data.protectedEntity,
      }
    }

    return {
      success: true,
      result: data.result,
    }
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Network error submitting review.',
    }
  }
}

export async function seedDemoReports(
  token: string
): Promise<{ success: boolean; count?: number; error?: string }> {
  try {
    const response = await fetch(`${API_BASE}/api/moderation/seed-demo`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({}),
    })

    const data = await response.json()

    if (!response.ok) {
      return {
        success: false,
        error: data.message || `Seeding failed (${response.status})`,
      }
    }

    return {
      success: true,
      count: data.count,
    }
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Network error seeding demo reports.',
    }
  }
}

export async function clearDemoReports(
  token: string
): Promise<{ success: boolean; count?: number; error?: string }> {
  try {
    const response = await fetch(`${API_BASE}/api/moderation/clear-demo`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({}),
    })

    const data = await response.json()

    if (!response.ok) {
      return {
        success: false,
        error: data.message || `Clear failed (${response.status})`,
      }
    }

    return {
      success: true,
      count: data.count,
    }
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Network error clearing demo reports.',
    }
  }
}

export interface EngineSettings {
  enableVerifiedIntel?: boolean
  auditRetentionDays?: number
  lastUpdated?: string
  updatedBy?: string
}

export async function fetchEngineSettings(
  token: string
): Promise<{ success: boolean; settings?: EngineSettings; error?: string }> {
  try {
    const res = await fetch(`${API_BASE}/api/moderation/settings`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
    const data = await res.json()
    if (!res.ok) {
      return { success: false, error: data.message || `Failed to fetch engine settings (${res.status})` }
    }
    return { success: true, settings: data.settings }
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : 'Network error' }
  }
}

export async function updateEngineSettings(
  token: string,
  settings: { enableVerifiedIntel?: boolean; auditRetentionDays?: number }
): Promise<{ success: boolean; settings?: EngineSettings; error?: string }> {
  try {
    const res = await fetch(`${API_BASE}/api/moderation/settings`, {
      method: 'PATCH',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(settings),
    })
    const data = await res.json()
    if (!res.ok) {
      return { success: false, error: data.message || `Failed to update engine settings (${res.status})` }
    }
    return { success: true, settings: data.settings }
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : 'Network error' }
  }
}

export interface VerifiedIntelligenceItem {
  id: string
  source_report_id: string | null
  indicator_type: 'domain' | 'content_hash' | 'phone' | 'url'
  indicator_value: string
  defanged_value: string
  risk_level: 'CONFIRMED_SCAM' | 'VERIFIED_SAFE'
  category: string | null
  confidence: number
  notes: string | null
  report_count?: number
  active: boolean
  created_at: string
  updated_at?: string
}

export interface VerifiedIntelligenceResponse {
  success: boolean
  intelligence?: VerifiedIntelligenceItem[]
  total?: number
  page?: number
  limit?: number
  totalPages?: number
  error?: string
}

export async function fetchVerifiedIntelligence(
  token: string,
  options: {
    status?: 'active' | 'retired' | 'all'
    type?: 'domain' | 'content_hash' | 'phone' | 'url' | 'all'
    riskLevel?: 'CONFIRMED_SCAM' | 'VERIFIED_SAFE' | 'all'
    search?: string
    page?: number
    limit?: number
  } = {}
): Promise<VerifiedIntelligenceResponse> {
  const { status = 'all', type = 'all', riskLevel = 'all', search = '', page = 1, limit = 20 } = options
  const queryParams = new URLSearchParams()
  if (status) queryParams.set('status', status)
  if (type) queryParams.set('type', type)
  if (riskLevel) queryParams.set('riskLevel', riskLevel)
  if (search.trim()) queryParams.set('search', search.trim())
  queryParams.set('page', String(page))
  queryParams.set('limit', String(limit))

  try {
    const res = await fetch(`${API_BASE}/api/moderation/intelligence?${queryParams.toString()}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
    const data = await res.json()
    if (!res.ok) {
      return { success: false, error: data.message || `Failed to fetch intelligence (${res.status})` }
    }
    return {
      success: true,
      intelligence: data.intelligence || [],
      total: data.total || 0,
      page: data.page || 1,
      limit: data.limit || 20,
      totalPages: data.totalPages || 1,
    }
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : 'Network error' }
  }
}

export async function updateIntelligenceItem(
  token: string,
  id: string,
  updates: { active?: boolean; notes?: string; category?: string }
): Promise<{ success: boolean; updated?: VerifiedIntelligenceItem; error?: string }> {
  try {
    const res = await fetch(`${API_BASE}/api/moderation/intelligence/${id}`, {
      method: 'PATCH',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(updates),
    })
    const data = await res.json()
    if (!res.ok) {
      return { success: false, error: data.message || `Failed to update intelligence (${res.status})` }
    }
    return { success: true, updated: data.updated }
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : 'Network error' }
  }
}

export async function toggleIntelligenceStatus(
  token: string,
  id: string,
  active: boolean,
  notes?: string
): Promise<{ success: boolean; updated?: VerifiedIntelligenceItem; error?: string }> {
  return updateIntelligenceItem(token, id, { active, notes })
}

export interface ModerationAuditLogItem {
  id: string | number
  report_id: string | null
  action:
    | 'APPROVE'
    | 'REJECT'
    | 'RETIRE'
    | 'TOGGLE_STATUS'
    | 'UPDATE_SETTINGS'
    | 'PURGE_EXPIRED'
    | 'AUTH_LOGIN'
    | 'AUTH_FAILED'
    | 'DOMAIN_CREATE'
    | 'DOMAIN_UPDATE'
    | 'DOMAIN_DELETE'
    | 'MANUAL_INTEL'
  target_indicator: string | null
  threat_category: string | null
  actor_email: string | null
  actor_role: string
  confidence: number | null
  moderator_notes: string | null
  entry_hash?: string
  prev_hash?: string | null
  client_ip?: string | null
  user_agent?: string | null
  created_at: string
  expires_at?: string
}

export interface AuditStorageStats {
  totalRecords: number
  retentionDays: number
  oldestRecordAt: string | null
  newestRecordAt: string | null
  storageStatus: 'OPTIMAL' | 'WARNING' | 'CAPACITY_REACHED'
  actionBreakdown?: {
    approve: number
    reject: number
    retire: number
    settings: number
    toggle: number
    purge: number
  }
  expiredRecordsCount?: number
  expiringSoonCount?: number
}

export interface ModerationAuditLogsResponse {
  success: boolean
  auditLogs?: ModerationAuditLogItem[]
  total?: number
  page?: number
  limit?: number
  totalPages?: number
  retentionDays?: number
  error?: string
}

export async function fetchModerationAuditLogs(
  token: string,
  options: {
    page?: number
    limit?: number
    action?: string
    actor?: string
    search?: string
    fromDate?: string
    toDate?: string
  } = {}
): Promise<ModerationAuditLogsResponse> {
  try {
    const params = new URLSearchParams()
    if (options.page) params.set('page', String(options.page))
    if (options.limit) params.set('limit', String(options.limit))
    if (options.action && options.action !== 'ALL') params.set('action', options.action)
    if (options.actor) params.set('actor', options.actor)
    if (options.search) params.set('search', options.search)
    if (options.fromDate) params.set('fromDate', options.fromDate)
    if (options.toDate) params.set('toDate', options.toDate)

    const res = await fetch(`${API_BASE}/api/moderation/audit-logs?${params.toString()}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    const data = await res.json()
    if (!res.ok) {
      return { success: false, error: data.message || `Failed to fetch audit logs (${res.status})` }
    }
    return {
      success: true,
      auditLogs: data.auditLogs || [],
      total: data.total || 0,
      page: data.page || 1,
      limit: data.limit || 20,
      totalPages: data.totalPages || 1,
      retentionDays: data.retentionDays || 90,
    }
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : 'Network error' }
  }
}

export interface AuditChainVerifyResult {
  success: boolean
  verified: boolean
  totalEntriesChecked: number
  brokenAtId?: string | number | null
  reason?: string
  error?: string
}

export async function verifyAuditChainIntegrity(
  token: string
): Promise<AuditChainVerifyResult> {
  try {
    const res = await fetch(`${API_BASE}/api/moderation/audit-logs/verify`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    const data = await res.json()
    if (!res.ok) {
      return {
        success: false,
        verified: false,
        totalEntriesChecked: 0,
        error: data.message || `Failed to verify chain (${res.status})`,
      }
    }
    const verification = data.verification || {}
    const isVerified = Boolean(data.verified ?? verification.isValid)
    return {
      success: true,
      verified: isVerified,
      totalEntriesChecked: data.totalEntriesChecked ?? verification.verifiedCount ?? 0,
      brokenAtId: data.brokenAtId ?? verification.brokenAtId ?? null,
      reason: data.reason ?? verification.reason ?? null,
      error: data.error,
    }
  } catch (err) {
    return {
      success: false,
      verified: false,
      totalEntriesChecked: 0,
      error: err instanceof Error ? err.message : 'Network error during chain verification',
    }
  }
}

export async function fetchAuditStorageStats(
  token: string
): Promise<{ success: boolean; stats?: AuditStorageStats; error?: string }> {
  try {
    const res = await fetch(`${API_BASE}/api/moderation/audit-logs/stats`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
    const data = await res.json()
    if (!res.ok) {
      return { success: false, error: data.message || `Failed to fetch audit stats (${res.status})` }
    }
    return { success: true, stats: data.stats }
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : 'Network error' }
  }
}

export async function triggerAuditPurge(
  token: string,
  options: { retentionDays?: number; graceDays?: number } = {}
): Promise<{ success: boolean; purgedCount?: number; remainingCount?: number; timestamp?: string; error?: string }> {
  try {
    const res = await fetch(`${API_BASE}/api/moderation/audit-logs/purge`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(options),
    })
    const data = await res.json()
    if (!res.ok) {
      return { success: false, error: data.message || `Failed to execute retention purge (${res.status})` }
    }
    return {
      success: true,
      purgedCount: data.purgedCount,
      remainingCount: data.remainingCount,
      timestamp: data.timestamp,
    }
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : 'Network error' }
  }
}

export function exportAuditLogsToCsv(logs: ModerationAuditLogItem[]): void {
  if (!logs || !logs.length) return
  const headers = [
    'ID',
    'Action',
    'Target Indicator',
    'Threat Category',
    'Actor Email',
    'Actor Role',
    'Confidence',
    'Notes',
    'Entry Hash (SHA-256)',
    'Prev Hash',
    'Client IP',
    'Created At',
    'Expires At',
  ]
  const escapeCsv = (val: unknown) => {
    if (val === null || val === undefined) return '""'
    const str = String(val).replace(/"/g, '""')
    return `"${str}"`
  }
  const rows = logs.map((log) => [
    escapeCsv(log.id),
    escapeCsv(log.action),
    escapeCsv(log.target_indicator),
    escapeCsv(log.threat_category),
    escapeCsv(log.actor_email),
    escapeCsv(log.actor_role),
    escapeCsv(log.confidence !== null ? log.confidence : ''),
    escapeCsv(log.moderator_notes),
    escapeCsv(log.entry_hash || ''),
    escapeCsv(log.prev_hash || ''),
    escapeCsv(log.client_ip || ''),
    escapeCsv(log.created_at),
    escapeCsv(log.expires_at),
  ])

  const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\r\n')
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.setAttribute('href', url)
  a.setAttribute('download', `trustlens_audit_trail_${new Date().toISOString().slice(0, 10)}.csv`)
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}


export async function createIntelligenceEntry(
  token: string,
  data: {
    indicatorValue: string
    indicatorType?: 'domain' | 'content_hash' | 'phone' | 'url'
    riskLevel?: 'CONFIRMED_SCAM' | 'VERIFIED_SAFE'
    category?: string
    notes?: string
  }
): Promise<{ success: boolean; entry?: VerifiedIntelligenceItem; error?: string }> {
  try {
    const res = await fetch(`${API_BASE}/api/moderation/intelligence`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(data),
    })
    const body = await res.json()
    if (!res.ok) {
      return { success: false, error: body.message || `Failed to add indicator (${res.status})` }
    }
    return { success: true, entry: body.entry }
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : 'Network error' }
  }
}




// ============================================================================
// Member 3: Domain Directory Management
// ============================================================================

export interface DomainDirectoryEntry {
  id: number
  name: string
  officialDomain: string
  category: string | null
  sourceUrl: string | null
  reviewer: string | null
  verifiedAt: string | null
  nextReviewDate: string | null
  status: 'ACTIVE' | 'STALE' | 'RETIRED'
  active: boolean
}

export interface DomainDirectoryListResponse {
  success: boolean
  entries?: DomainDirectoryEntry[]
  count?: number
  error?: string
}

export async function fetchDomainDirectoryEntries(token: string): Promise<DomainDirectoryListResponse> {
  try {
    const res = await fetch(`${API_BASE}/api/moderation/domains`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    const data = await res.json()
    if (!res.ok) {
      return { success: false, error: data.message || `Failed to fetch domain directory (${res.status})` }
    }
    return { success: true, entries: data.entries || [], count: data.count || 0 }
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : 'Network error' }
  }
}

export async function createDomainDirectoryEntry(
  token: string,
  data: { name: string; officialDomain: string; category?: string; sourceUrl?: string }
): Promise<{ success: boolean; entry?: DomainDirectoryEntry; error?: string }> {
  try {
    const res = await fetch(`${API_BASE}/api/moderation/domains`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(data),
    })
    const body = await res.json()
    if (!res.ok) {
      return { success: false, error: body.message || `Failed to create domain entry (${res.status})` }
    }
    return { success: true, entry: body.entry }
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : 'Network error' }
  }
}

export async function updateDomainDirectoryEntry(
  token: string,
  id: number,
  updates: { status?: 'ACTIVE' | 'STALE' | 'RETIRED'; category?: string; sourceUrl?: string; reviewNotes?: string; active?: boolean }
): Promise<{ success: boolean; updated?: DomainDirectoryEntry; error?: string }> {
  try {
    const res = await fetch(`${API_BASE}/api/moderation/domains/${id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(updates),
    })
    const body = await res.json()
    if (!res.ok) {
      return { success: false, error: body.message || `Failed to update domain entry (${res.status})` }
    }
    return { success: true, updated: body.updated }
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : 'Network error' }
  }
}

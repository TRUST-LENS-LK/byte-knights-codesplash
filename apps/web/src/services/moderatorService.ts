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
}

export interface ModerationReviewPayload {
  reportId: string
  action: 'APPROVE' | 'REJECT' | 'RETIRE'
  notes?: string
  indicatorType?: 'domain' | 'url' | 'content_hash'
  category?: string
  confidence?: number
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

export interface ModerationStatsResponse {
  success: boolean
  stats?: ModerationStats
  error?: string
}

const TOKEN_KEY = 'trustlens_mod_token'
const USER_KEY = 'trustlens_mod_user'
const API_BASE = 'http://localhost:8787'

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
): Promise<{ success: boolean; result?: ModerationReviewResult; error?: string }> {
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
  action: 'APPROVE' | 'REJECT' | 'RETIRE' | 'TOGGLE_STATUS' | 'UPDATE_SETTINGS' | 'PURGE_EXPIRED'
  target_indicator: string | null
  threat_category: string | null
  actor_email: string | null
  actor_role: string
  confidence: number | null
  moderator_notes: string | null
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
    search?: string
  } = {}
): Promise<ModerationAuditLogsResponse> {
  try {
    const params = new URLSearchParams()
    if (options.page) params.set('page', String(options.page))
    if (options.limit) params.set('limit', String(options.limit))
    if (options.action && options.action !== 'ALL') params.set('action', options.action)
    if (options.search) params.set('search', options.search)

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
  const headers = ['ID', 'Action', 'Target Indicator', 'Threat Category', 'Actor Email', 'Actor Role', 'Confidence', 'Notes', 'Created At', 'Expires At']
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




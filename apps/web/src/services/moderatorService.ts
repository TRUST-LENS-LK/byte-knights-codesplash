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
}

export interface ModerationReviewPayload {
  reportId: string
  action: 'APPROVE' | 'REJECT' | 'RETIRE'
  notes?: string
  indicatorType?: 'domain' | 'url' | 'content_hash'
  category?: string
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

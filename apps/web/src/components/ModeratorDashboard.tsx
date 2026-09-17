import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  LayoutDashboard,
  ShieldCheck,
  ShieldAlert,
  Clock,
  CheckCircle2,
  RefreshCw,
  LogOut,
  ArrowLeft,
  Globe,
  Sparkles,
  ChevronRight,
  Activity,
  FileText,
  Eye,
  EyeOff,
  Lock,
  Mail,
  AlertCircle,
  PanelLeftClose,
  PanelLeftOpen,
} from 'lucide-react'
import {
  type ModerationQueueItem,
  type ModeratorUser,
  type ModerationStats,
  clearSession,
  fetchModerationQueue,
  fetchModerationStats,
  getStoredSession,
  loginModerator,
  reviewModerationItem,
  seedDemoReports,
} from '../services/moderatorService'
import { defangIndicator } from '../services/reportingService'
import { formatRelativeTime } from '../utils/formatTime'
import { ReportDetailModal } from './modals/ReportDetailModal'
import { ReviewDecisionModal } from './modals/ReviewDecisionModal'
import './ModeratorDashboard.css'

export interface ModeratorDashboardProps {
  onBackToScanner: () => void
}

/**
 * Normalizes any pre-existing brackets so indicators never show [[.]]
 */
function formatCleanIndicator(raw: string | null | undefined): string {
  if (!raw) return 'Message-only text'
  const stripped = raw.replace(/\[+/g, '').replace(/\]+/g, '').trim()
  return defangIndicator(stripped)
}

function parseReportNotes(rawNotes: string | null) {
  if (!rawNotes) return { excerpt: null, userNotes: null }
  const excerptMatch = rawNotes.match(/\[Reported Message Excerpt\]:\s*"([\s\S]*?)"(?:\n\n|$)/)
  const userNotesMatch = rawNotes.match(/\[Submitter Context\]:\s*([\s\S]*)$/)

  if (excerptMatch || userNotesMatch) {
    return {
      excerpt: excerptMatch ? excerptMatch[1] : null,
      userNotes: userNotesMatch ? userNotesMatch[1] : null,
    }
  }
  return { excerpt: null, userNotes: rawNotes }
}

/**
 * Categorize report dynamically based on real content
 */
function classifyReportCategory(item: ModerationQueueItem): string {
  if (item.report_type === 'false_positive') return 'False Alarm'
  const text = `${item.reported_domain || ''} ${item.notes || ''} ${item.raw_excerpt || ''}`.toLowerCase()
  if (/boc|combank|bank|hnb|sampath|card|debit|credit|fund/.test(text)) return 'Banking Phishing'
  if (/ceb|electricity|utility|water|bill|telecom|dialog|mobitel/.test(text)) return 'Utility Bill Scam'
  if (/job|earn|part-time|salary|advance|bonus|hiring/.test(text)) return 'Job Scam'
  if (/lottery|prize|won|lucky|cash|gift|reward/.test(text)) return 'Lottery / Prize Fraud'
  if (/otp|code|pin|password|credential|security/.test(text)) return 'OTP Theft'
  if (/\.apk|download|install|app/.test(text)) return 'Malicious Link / APK'
  return 'Suspicious Indicator'
}

/**
 * Interactive Mascot Robot
 * - Eyes dynamically track mouse cursor coordinates across the screen in real-time
 * - Eyes instantly close with a cute bashful expression when password field is focused
 */
interface CuteRobotAvatarProps {
  isPasswordFocused: boolean
  isError?: boolean
}

const CuteRobotAvatar: React.FC<CuteRobotAvatarProps> = ({ isPasswordFocused, isError }) => {
  const containerRef = useRef<HTMLDivElement>(null)
  const [pupilOffset, setPupilOffset] = useState({ x: 0, y: 0 })

  useEffect(() => {
    let animFrame: number

    const handleMouseMove = (e: MouseEvent) => {
      if (isPasswordFocused || !containerRef.current) return

      animFrame = requestAnimationFrame(() => {
        if (!containerRef.current) return
        const rect = containerRef.current.getBoundingClientRect()
        const centerX = rect.left + rect.width / 2
        const centerY = rect.top + rect.height / 2

        const dx = e.clientX - centerX
        const dy = e.clientY - centerY
        const angle = Math.atan2(dy, dx)
        // Max travel range of pupils inside eye sockets: 3.5px
        const dist = Math.min(Math.hypot(dx, dy) / 36, 3.5)
        const x = Math.cos(angle) * dist
        const y = Math.sin(angle) * dist

        setPupilOffset({ x, y })
      })
    }

    window.addEventListener('mousemove', handleMouseMove)
    return () => {
      window.removeEventListener('mousemove', handleMouseMove)
      cancelAnimationFrame(animFrame)
    }
  }, [isPasswordFocused])

  return (
    <div ref={containerRef} className={`neo-robot-wrapper ${isPasswordFocused ? 'shy' : ''}`}>
      <svg
        viewBox="0 0 96 96"
        width="88"
        height="88"
        className="neo-robot-svg"
      >
        <defs>
          <linearGradient id="sentinelChassisGrad" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#1e293b" />
            <stop offset="100%" stopColor="#0f172a" />
          </linearGradient>
          <linearGradient id="sentinelVisorGrad" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#080d1a" />
            <stop offset="100%" stopColor="#030712" />
          </linearGradient>
        </defs>

        {/* Tactical Sensor Mast / Antenna */}
        <line
          x1="48"
          y1="16"
          x2="48"
          y2="7"
          stroke="#475569"
          strokeWidth="2.5"
          strokeLinecap="round"
        />
        <circle
          cx="48"
          cy="6.5"
          r="4"
          fill={isError ? '#ef4444' : isPasswordFocused ? '#38bdf8' : '#d4ff32'}
          className={isPasswordFocused ? 'neo-antenna-pulse' : ''}
        />

        {/* Side Audio/Comm Sensor Pods (Tactical Ears) */}
        <rect x="9" y="36" width="6" height="24" rx="3" fill="#1e293b" stroke="#334155" strokeWidth="1.2" />
        <line x1="10.5" y1="44" x2="13.5" y2="44" stroke="#64748b" strokeWidth="1" />
        <line x1="10.5" y1="48" x2="13.5" y2="48" stroke="#64748b" strokeWidth="1" />
        <line x1="10.5" y1="52" x2="13.5" y2="52" stroke="#64748b" strokeWidth="1" />

        <rect x="81" y="36" width="6" height="24" rx="3" fill="#1e293b" stroke="#334155" strokeWidth="1.2" />
        <line x1="82.5" y1="44" x2="85.5" y2="44" stroke="#64748b" strokeWidth="1" />
        <line x1="82.5" y1="48" x2="85.5" y2="48" stroke="#64748b" strokeWidth="1" />
        <line x1="82.5" y1="52" x2="85.5" y2="52" stroke="#64748b" strokeWidth="1" />

        {/* Tactical Chassis Armor */}
        <rect
          x="14"
          y="16"
          width="68"
          height="64"
          rx="18"
          fill="url(#sentinelChassisGrad)"
          stroke="#334155"
          strokeWidth="2"
        />

        {/* Security Shield Crest on Forehead Armor Plate */}
        <path
          d="M 48 20.5 L 51.5 22.5 V 25.5 C 51.5 27.6 48 29 48 29 C 48 29 44.5 27.6 44.5 25.5 V 22.5 Z"
          fill="rgba(212, 255, 50, 0.12)"
          stroke="#d4ff32"
          strokeWidth="1.2"
        />

        {/* HUD Visor Screen */}
        <rect
          x="19"
          y="31"
          width="58"
          height="43"
          rx="13"
          fill="url(#sentinelVisorGrad)"
          stroke="#1e293b"
          strokeWidth="1.5"
        />

        {/* Subtle HUD Reticle Tech Brackets */}
        <path d="M 23 37 L 23 35 L 26 35" stroke="rgba(148, 163, 184, 0.25)" strokeWidth="1" fill="none" />
        <path d="M 73 37 L 73 35 L 70 35" stroke="rgba(148, 163, 184, 0.25)" strokeWidth="1" fill="none" />
        <path d="M 23 67 L 23 69 L 26 69" stroke="rgba(148, 163, 184, 0.25)" strokeWidth="1" fill="none" />
        <path d="M 73 67 L 73 69 L 70 69" stroke="rgba(148, 163, 184, 0.25)" strokeWidth="1" fill="none" />

        {/* Horizontal HUD Scanline Glow */}
        <line
          x1="22"
          y1="34"
          x2="74"
          y2="34"
          stroke="rgba(255, 255, 255, 0.08)"
          strokeWidth="1"
          strokeLinecap="round"
        />

        {/* ── Dynamic Ocular Sensors vs Privacy Lockdown Mode ── */}
        {!isPasswordFocused ? (
          <>
            {/* Left Eye Socket: Stationary, High-Contrast Clearly Visible Boundary */}
            <circle cx="36" cy="46" r="11" fill="#1e293b" stroke="#d4ff32" strokeWidth="1.2" />
            <circle cx="36" cy="46" r="9.2" fill="#ffffff" />
            
            {/* Left Black Dot Pupil (ONLY THIS MOVES) */}
            <circle
              cx={36 + pupilOffset.x}
              cy={46 + pupilOffset.y}
              r="4.4"
              fill="#0f172a"
            />
            {/* Left Pupil Cyber Iris Accent */}
            <circle
              cx={36 + pupilOffset.x}
              cy={46 + pupilOffset.y}
              r="4.4"
              fill="none"
              stroke="#d4ff32"
              strokeWidth="0.8"
            />
            {/* Left Specular Glint Reflection */}
            <circle
              cx={34.6 + pupilOffset.x * 0.75}
              cy={44.2 + pupilOffset.y * 0.75}
              r="1.4"
              fill="#ffffff"
            />
            {/* Left Mini Twinkle */}
            <circle
              cx={37.4 + pupilOffset.x * 0.75}
              cy={47.4 + pupilOffset.y * 0.75}
              r="0.7"
              fill="#ffffff"
            />

            {/* Right Eye Socket: Stationary, High-Contrast Clearly Visible Boundary */}
            <circle cx="60" cy="46" r="11" fill="#1e293b" stroke="#d4ff32" strokeWidth="1.2" />
            <circle cx="60" cy="46" r="9.2" fill="#ffffff" />

            {/* Right Black Dot Pupil (ONLY THIS MOVES) */}
            <circle
              cx={60 + pupilOffset.x}
              cy={46 + pupilOffset.y}
              r="4.4"
              fill="#0f172a"
            />
            {/* Right Pupil Cyber Iris Accent */}
            <circle
              cx={60 + pupilOffset.x}
              cy={46 + pupilOffset.y}
              r="4.4"
              fill="none"
              stroke="#d4ff32"
              strokeWidth="0.8"
            />
            {/* Right Specular Glint Reflection */}
            <circle
              cx={58.6 + pupilOffset.x * 0.75}
              cy={44.2 + pupilOffset.y * 0.75}
              r="1.4"
              fill="#ffffff"
            />
            {/* Right Mini Twinkle */}
            <circle
              cx={61.4 + pupilOffset.x * 0.75}
              cy={47.4 + pupilOffset.y * 0.75}
              r="0.7"
              fill="#ffffff"
            />

            {/* Lower Visor: Cyber Frequency Analyzer Equalizer Bars */}
            <g opacity="0.85">
              <rect x="41" y="62.5" width="2" height="4" rx="1" fill="#38bdf8" />
              <rect x="44.5" y="60.5" width="2" height="6" rx="1" fill="#d4ff32" />
              <rect x="48" y="59.5" width="2" height="7" rx="1" fill="#d4ff32" />
              <rect x="51.5" y="60.5" width="2" height="6" rx="1" fill="#d4ff32" />
              <rect x="55" y="62.5" width="2" height="4" rx="1" fill="#38bdf8" />
            </g>
          </>
        ) : (
          /* ── Privacy Lockdown Shutter Mode (Password Focused) ── */
          <g className="neo-closed-eyes">
            {/* Left Tactical Privacy Shutter */}
            <path
              d="M 28 46 L 44 46"
              stroke="#d4ff32"
              strokeWidth="3.2"
              strokeLinecap="round"
            />
            {/* Left Shutter Tech Brackets */}
            <line x1="26.5" y1="43" x2="26.5" y2="49" stroke="#64748b" strokeWidth="1.4" />
            <line x1="45.5" y1="43" x2="45.5" y2="49" stroke="#64748b" strokeWidth="1.4" />

            {/* Right Tactical Privacy Shutter */}
            <path
              d="M 52 46 L 68 46"
              stroke="#d4ff32"
              strokeWidth="3.2"
              strokeLinecap="round"
            />
            {/* Right Shutter Tech Brackets */}
            <line x1="50.5" y1="43" x2="50.5" y2="49" stroke="#64748b" strokeWidth="1.4" />
            <line x1="69.5" y1="43" x2="69.5" y2="49" stroke="#64748b" strokeWidth="1.4" />

            {/* Center Privacy Lockdown Lock Icon */}
            <path
              d="M 46 62 H 50 V 65.5 H 46 Z M 46.5 62 V 60.5 C 46.5 59.7 47.1 59.2 48 59.2 C 48.9 59.2 49.5 59.7 49.5 60.5 V 62"
              stroke="#d4ff32"
              strokeWidth="1.2"
              fill="none"
              strokeLinecap="round"
            />
          </g>
        )}

        {/* Chassis Status LEDs */}
        <circle cx="20" cy="74" r="1.5" fill="#10b981" />
        <circle cx="25" cy="74" r="1.5" fill="#38bdf8" />
        <circle cx="71" cy="74" r="1.5" fill="#64748b" />
        <circle cx="76" cy="74" r="1.5" fill={isPasswordFocused ? '#d4ff32' : '#334155'} />
      </svg>
    </div>
  )
}

function renderPaginationNumbers(currentPage: number, totalPages: number, onSelect: (p: number) => void) {
  const pages: (number | '...')[] = []
  if (totalPages <= 7) {
    for (let i = 1; i <= totalPages; i++) pages.push(i)
  } else {
    pages.push(1)
    if (currentPage > 3) pages.push('...')
    const start = Math.max(2, currentPage - 1)
    const end = Math.min(totalPages - 1, currentPage + 1)
    for (let i = start; i <= end; i++) pages.push(i)
    if (currentPage < totalPages - 2) pages.push('...')
    pages.push(totalPages)
  }

  return (
    <div className="neo-page-numbers">
      {pages.map((p, idx) =>
        p === '...' ? (
          <span key={`ellipsis-${idx}`} className="neo-page-ellipsis">
            ...
          </span>
        ) : (
          <button
            key={p}
            type="button"
            className={`neo-page-pill ${p === currentPage ? 'active' : ''}`}
            onClick={() => onSelect(p)}
          >
            {p}
          </button>
        )
      )}
    </div>
  )
}

export const ModeratorDashboard: React.FC<ModeratorDashboardProps> = ({ onBackToScanner }) => {
  const [token, setToken] = useState<string | null>(() => getStoredSession().token)
  const [user, setUser] = useState<ModeratorUser | null>(() => getStoredSession().user)

  // Navigation State (3 focused views: Dashboard, Queue, Audit)
  const [activeNav, setActiveNav] = useState<'DASHBOARD' | 'QUEUE' | 'AUDIT'>('DASHBOARD')
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false)

  // Auth Form State
  const [loginEmail, setLoginEmail] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [loginLoading, setLoginLoading] = useState(false)
  const [loginError, setLoginError] = useState<string | null>(null)
  const [isPasswordFocused, setIsPasswordFocused] = useState(false)
  const [showPassword, setShowPassword] = useState(false)

  // Dedicated Aggregated Stats State (High-performance metrics decoupled from full table arrays)
  const [stats, setStats] = useState<ModerationStats | null>(null)

  // Real Database Reports (Full dataset)
  const [allReports, setAllReports] = useState<ModerationQueueItem[]>([])
  const [activeTab, setActiveTab] = useState<'PENDING' | 'APPROVED' | 'REJECTED' | 'ALL'>('PENDING')
  const [searchQuery, setSearchQuery] = useState('')
  const [isLoadingQueue, setIsLoadingQueue] = useState(false)
  const [queueError, setQueueError] = useState<string | null>(null)

  // Queue Pagination State
  const [queuePage, setQueuePage] = useState(1)
  const [queuePageSize, setQueuePageSize] = useState<number>(10)

  // Audit Pagination State
  const [auditPage, setAuditPage] = useState(1)
  const [auditPageSize, setAuditPageSize] = useState<number>(10)

  // Dedicated Modal Dialog State
  const [detailModalReport, setDetailModalReport] = useState<ModerationQueueItem | null>(null)
  const [reviewModalReport, setReviewModalReport] = useState<ModerationQueueItem | null>(null)
  const [isProcessingReview, setIsProcessingReview] = useState(false)
  const [isSeeding, setIsSeeding] = useState(false)

  // Toast Notification
  const [toastMessage, setToastMessage] = useState<string | null>(null)

  const showToast = (msg: string) => {
    setToastMessage(msg)
    setTimeout(() => setToastMessage(null), 4000)
  }

  const handleSignOut = useCallback(() => {
    clearSession()
    setToken(null)
    setUser(null)
    setAllReports([])
    setStats(null)
  }, [])

  // Load aggregated stats from dedicated lightweight endpoint
  const loadStats = useCallback(async () => {
    if (!token) return
    const res = await fetchModerationStats(token)
    if (res.success && res.stats) {
      setStats(res.stats)
    }
  }, [token])

  // Load all reports from database to compute real dynamic metrics & feeds
  const loadReports = useCallback(
    async (showSpinner = false) => {
      if (!token) return
      if (showSpinner) setIsLoadingQueue(true)
      setQueueError(null)
      const res = await fetchModerationQueue(token, 'ALL', 1, 100)
      setIsLoadingQueue(false)
      if (res.success && res.reports) {
        setAllReports(res.reports)
      } else {
        setQueueError(res.error || 'Could not load moderation reports.')
        if (res.error?.includes('expired') || res.error?.includes('Unauthorized')) {
          handleSignOut()
        }
      }
      void loadStats()
    },
    [token, handleSignOut, loadStats]
  )

  useEffect(() => {
    let active = true
    if (!token) return

    fetchModerationStats(token).then((res) => {
      if (active && res.success && res.stats) {
        setStats(res.stats)
      }
    })

    fetchModerationQueue(token, 'ALL', 1, 100)
      .then((res) => {
        if (!active) return
        if (res.success && res.reports) {
          setAllReports(res.reports)
        } else {
          setQueueError(res.error || 'Could not load reports.')
          if (res.error?.includes('expired') || res.error?.includes('Unauthorized')) {
            handleSignOut()
          }
        }
      })
      .catch((err) => {
        if (!active) return
        setQueueError(err instanceof Error ? err.message : 'Network error connecting to moderation registry.')
      })

    return () => {
      active = false
    }
  }, [token, handleSignOut])

  // Automatically reset queue page to 1 whenever tab or search filter changes
  useEffect(() => {
    setQueuePage(1)
  }, [activeTab, searchQuery])

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoginLoading(true)
    setLoginError(null)

    const res = await loginModerator(loginEmail.trim(), loginPassword)
    setLoginLoading(false)

    if (res.success && res.token && res.user) {
      setToken(res.token)
      setUser(res.user)
      showToast(`Welcome, ${res.user.email} (Verified ${res.user.role})`)
    } else {
      setLoginError(res.error || 'Invalid credentials or missing moderator privileges.')
    }
  }

  const handleModalApprove = async (
    report: ModerationQueueItem,
    category: string,
    indicatorType: 'domain' | 'content_hash' | 'url',
    notes: string
  ) => {
    if (!token) return
    setIsProcessingReview(true)
    const res = await reviewModerationItem(token, {
      reportId: report.id,
      action: 'APPROVE',
      category,
      indicatorType: report.reported_domain ? indicatorType : 'content_hash',
      notes: notes.trim() || 'Approved by moderator and sanitized for threat intelligence.',
    })
    setIsProcessingReview(false)

    if (res.success) {
      showToast(`Report ${report.id.slice(0, 8)} approved and published to verified threat feed.`)
      setReviewModalReport(null)
      void loadReports()
    } else {
      showToast(`Approval failed: ${res.error}`)
    }
  }

  const handleModalReject = async (report: ModerationQueueItem) => {
    if (!token) return
    if (!window.confirm('Dismiss this report without publishing threat intelligence?')) return
    setIsProcessingReview(true)
    const res = await reviewModerationItem(token, {
      reportId: report.id,
      action: 'REJECT',
      notes: 'Dismissed by moderator as unverified or insufficient evidence.',
    })
    setIsProcessingReview(false)

    if (res.success) {
      showToast(`Report ${report.id.slice(0, 8)} marked as rejected.`)
      setReviewModalReport(null)
      void loadReports()
    } else {
      showToast(`Action failed: ${res.error}`)
    }
  }

  const handleSeedDemo = async () => {
    if (!token) return
    setIsSeeding(true)
    const res = await seedDemoReports(token)
    setIsSeeding(false)
    if (res.success) {
      showToast(`✓ Seeded ${res.count ?? 3} realistic Sri Lankan scam reports for evaluation.`)
      void loadReports(true)
    } else {
      showToast(`Seed failed: ${res.error}`)
    }
  }

  const handleExportData = () => {
    if (!allReports.length) {
      showToast('No reports currently in database to export.')
      return
    }
    const jsonStr = `data:text/json;charset=utf-8,${encodeURIComponent(JSON.stringify(allReports, null, 2))}`
    const downloadAnchor = document.createElement('a')
    downloadAnchor.setAttribute('href', jsonStr)
    downloadAnchor.setAttribute('download', `trustlens_threat_intelligence_${new Date().toISOString().slice(0, 10)}.json`)
    document.body.appendChild(downloadAnchor)
    downloadAnchor.click()
    downloadAnchor.remove()
    showToast('Threat intelligence feed exported successfully.')
  }

  // ── REAL DATABASE METRICS COMPUTATION (Priority: Stats Endpoint, Fallback: allReports) ──
  const pendingReports = useMemo(() => allReports.filter((r) => r.status === 'PENDING'), [allReports])
  const approvedReports = useMemo(() => allReports.filter((r) => r.status === 'APPROVED'), [allReports])
  const rejectedReports = useMemo(() => allReports.filter((r) => r.status === 'REJECTED'), [allReports])

  const pendingCount = stats?.metrics.pendingCount ?? pendingReports.length
  const confirmedThreatCount =
    stats?.metrics.confirmedThreatCount ?? approvedReports.filter((r) => r.report_type === 'suspicious').length
  const clearedSafeCount =
    stats?.metrics.clearedSafeCount ?? approvedReports.filter((r) => r.report_type === 'false_positive').length

  // Filtered reports for current tab & search
  const tabFilteredReports = useMemo(() => {
    if (activeTab === 'PENDING') return pendingReports
    if (activeTab === 'APPROVED') return approvedReports
    if (activeTab === 'REJECTED') return rejectedReports
    return allReports
  }, [activeTab, pendingReports, approvedReports, rejectedReports, allReports])

  const displayedReports = useMemo(() => {
    if (!searchQuery.trim()) return tabFilteredReports
    const q = searchQuery.toLowerCase().trim()
    return tabFilteredReports.filter((r) => {
      const ind = (r.reported_domain || '').toLowerCase()
      const notes = (r.notes || '').toLowerCase()
      const excerpt = (r.raw_excerpt || '').toLowerCase()
      const hash = (r.content_sha256 || '').toLowerCase()
      return ind.includes(q) || notes.includes(q) || excerpt.includes(q) || hash.includes(q)
    })
  }, [tabFilteredReports, searchQuery])

  // Paginated Queue Slices
  const queueTotalPages = Math.max(1, Math.ceil(displayedReports.length / queuePageSize))
  const paginatedReports = useMemo(() => {
    const start = (queuePage - 1) * queuePageSize
    return displayedReports.slice(start, start + queuePageSize)
  }, [displayedReports, queuePage, queuePageSize])

  // ── DYNAMIC WEEKLY INFLOW VELOCITY (Priority: Stats Endpoint, Fallback: allReports) ──
  const weeklyActivity = useMemo(() => {
    if (stats?.weeklyActivity && stats.weeklyActivity.length === 7) {
      const counts = stats.weeklyActivity
      const maxThreat = Math.max(...counts.map((c) => c.threats), 1)
      const maxResolved = Math.max(...counts.map((c) => c.resolved), 1)
      const maxVal = Math.max(maxThreat, maxResolved, 5)
      return { counts, maxVal }
    }

    const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
    const counts = days.map((day) => ({ day, threats: 0, resolved: 0 }))

    allReports.forEach((report) => {
      try {
        const date = new Date(report.created_at)
        const dayIndex = date.getDay()
        if (dayIndex >= 0 && dayIndex < 7) {
          counts[dayIndex].threats += 1
          if (report.status === 'APPROVED' || report.status === 'REJECTED') {
            counts[dayIndex].resolved += 1
          }
        }
      } catch {
        // Ignore invalid dates
      }
    })

    const maxThreat = Math.max(...counts.map((c) => c.threats), 1)
    const maxResolved = Math.max(...counts.map((c) => c.resolved), 1)
    const maxVal = Math.max(maxThreat, maxResolved, 5)

    return { counts, maxVal }
  }, [stats, allReports])

  // ── DYNAMIC CATEGORY BREAKDOWN (Priority: Stats Endpoint, Fallback: allReports) ──
  const categoryStats = useMemo(() => {
    if (stats?.threatCategories && stats.threatCategories.length > 0) {
      return stats.threatCategories.slice(0, 3)
    }

    if (allReports.length === 0) return []
    const map = new Map<string, number>()

    allReports.forEach((r) => {
      const cat = classifyReportCategory(r)
      map.set(cat, (map.get(cat) || 0) + 1)
    })

    return Array.from(map.entries())
      .map(([category, count]) => ({
        category,
        count,
        percentage: Math.round((count / allReports.length) * 100),
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 3)
  }, [stats, allReports])

  // ── DYNAMIC PRIORITY ALERT INCIDENT (Priority: Stats Endpoint, Fallback: pendingReports[0]) ──
  const priorityIncident = useMemo(() => {
    if (stats?.priorityIncident) {
      const match = allReports.find((r) => r.id === stats.priorityIncident?.id)
      if (match) return match
      return {
        id: stats.priorityIncident.id,
        submission_id: null,
        report_type: stats.priorityIncident.report_type,
        content_sha256: '',
        reported_domain: stats.priorityIncident.reported_domain,
        raw_excerpt: stats.priorityIncident.raw_excerpt,
        notes: stats.priorityIncident.notes,
        status: 'PENDING' as const,
        created_at: stats.priorityIncident.created_at,
        updated_at: stats.priorityIncident.created_at,
      }
    }
    if (pendingReports.length > 0) return pendingReports[0]
    return null
  }, [stats, allReports, pendingReports])

  const priorityExcerpt = useMemo(() => {
    if (!priorityIncident) return null
    const parsed = parseReportNotes(priorityIncident.notes)
    return priorityIncident.raw_excerpt || parsed.excerpt || parsed.userNotes
  }, [priorityIncident])

  // ── REAL MODERATION AUDIT TRAIL FROM DATABASE ────────────────────────────
  const resolvedAuditItems = useMemo(() => {
    return allReports.filter((r) => r.status === 'APPROVED' || r.status === 'REJECTED')
  }, [allReports])

  const auditTotalPages = Math.max(1, Math.ceil(resolvedAuditItems.length / auditPageSize))
  const paginatedAuditItems = useMemo(() => {
    const start = (auditPage - 1) * auditPageSize
    return resolvedAuditItems.slice(start, start + auditPageSize)
  }, [resolvedAuditItems, auditPage, auditPageSize])

  // Format today's date
  const todayStr = new Date().toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
  })

  // Render Login Card if not authenticated
  if (!token || !user) {
    return (
      <div className="neo-login-viewport">
        {/* Ambient background decorative orbs */}
        <div className="neo-login-glow-orb orb-1" />
        <div className="neo-login-glow-orb orb-2" />

        <div className="neo-login-container">
          <div className="neo-login-card">
            {/* Top Security Badge */}
            <div className="neo-login-security-tag">
              <ShieldCheck size={12} color="#047857" aria-hidden="true" />
              <span>TrustLens LK Cyber Threat Center</span>
            </div>

            {/* Interactive Cute Robot Avatar */}
            <div className="neo-robot-box">
              <CuteRobotAvatar
                isPasswordFocused={isPasswordFocused}
                isError={Boolean(loginError)}
              />
            </div>

            <div className="neo-login-header">
              <h2 className="neo-login-title">Moderator Portal</h2>
            </div>

            {loginError && (
              <div className="neo-login-error">
                <AlertCircle size={15} aria-hidden="true" />
                <span>{loginError}</span>
              </div>
            )}

            <form onSubmit={handleLogin} className="neo-login-form">
              <div className="neo-form-field">
                <label>Moderator Email</label>
                <div className="neo-input-icon-wrapper">
                  <Mail size={15} className="neo-input-leading-icon" aria-hidden="true" />
                  <input
                    type="email"
                    required
                    value={loginEmail}
                    onChange={(e) => setLoginEmail(e.target.value)}
                    placeholder="moderator@trustlens.lk"
                    autoFocus
                    className="neo-input-with-icon"
                  />
                </div>
              </div>

              <div className="neo-form-field">
                <label>Password</label>
                <div className="neo-input-icon-wrapper">
                  <Lock size={15} className="neo-input-leading-icon" aria-hidden="true" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    onFocus={() => setIsPasswordFocused(true)}
                    onBlur={() => setIsPasswordFocused(false)}
                    placeholder="••••••••••••"
                    className="neo-input-with-icon"
                  />
                  <button
                    type="button"
                    className="neo-btn-password-toggle"
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => setShowPassword((prev) => !prev)}
                    title={showPassword ? 'Hide password' : 'Show password'}
                    tabIndex={-1}
                  >
                    {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                className="neo-btn-full-lime"
                disabled={loginLoading || !loginPassword}
                style={{ marginTop: '8px' }}
              >
                {loginLoading ? (
                  <>
                    <span className="spinner" style={{ width: '14px', height: '14px', border: '2px solid #000', borderTopColor: 'transparent', borderRadius: '50%', display: 'inline-block', animation: 'spin 1s linear infinite' }} />
                    <span>Verifying RBAC Session...</span>
                  </>
                ) : (
                  'Sign In to Moderator Deck'
                )}
              </button>

              <button
                type="button"
                className="neo-btn-back-scanner"
                onClick={onBackToScanner}
              >
                <ArrowLeft size={13} aria-hidden="true" />
                <span>Back to Public Scanner</span>
              </button>
            </form>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="neo-dashboard-wrapper">
      {/* Toast Notification */}
      {toastMessage && <div className="neo-toast">{toastMessage}</div>}

      <div className="neo-dashboard-frame">
        {/* ── Fixed Left Sidebar (Permanently Docked on Scroll, Collapsible) ─ */}
        <aside className={`neo-sidebar ${isSidebarCollapsed ? 'collapsed' : ''}`}>
          <div>
            <div className="neo-brand-header">
              <div className="neo-brand-mark" title="TrustLens LK">TL</div>
              {!isSidebarCollapsed && (
                <div className="neo-brand-title">
                  TrustLens<span>LK</span>
                </div>
              )}
              <button
                type="button"
                className="neo-btn-toggle-sidebar"
                onClick={() => setIsSidebarCollapsed((prev) => !prev)}
                title={isSidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                aria-label={isSidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              >
                {isSidebarCollapsed ? (
                  <PanelLeftOpen size={16} aria-hidden="true" />
                ) : (
                  <PanelLeftClose size={16} aria-hidden="true" />
                )}
              </button>
            </div>

            <ul className="neo-nav-group">
              <li>
                <button
                  type="button"
                  className={`neo-nav-btn ${activeNav === 'DASHBOARD' ? 'active' : ''}`}
                  onClick={() => setActiveNav('DASHBOARD')}
                  title="Dashboard"
                >
                  <LayoutDashboard size={17} aria-hidden="true" />
                  {!isSidebarCollapsed && <span>Dashboard</span>}
                </button>
              </li>
              <li>
                <button
                  type="button"
                  className={`neo-nav-btn ${activeNav === 'QUEUE' ? 'active' : ''}`}
                  onClick={() => {
                    setActiveNav('QUEUE')
                    setActiveTab('PENDING')
                  }}
                  title="Queue"
                >
                  <Clock size={17} aria-hidden="true" />
                  {!isSidebarCollapsed && <span>Queue</span>}
                  {pendingCount > 0 && (
                    <span
                      className={isSidebarCollapsed ? 'neo-badge-dot' : 'neo-badge-count'}
                      title={`${pendingCount} pending reports`}
                    >
                      {!isSidebarCollapsed && pendingCount}
                    </span>
                  )}
                </button>
              </li>
              <li>
                <button
                  type="button"
                  className={`neo-nav-btn ${activeNav === 'AUDIT' ? 'active' : ''}`}
                  onClick={() => setActiveNav('AUDIT')}
                  title="Audit"
                >
                  <FileText size={17} aria-hidden="true" />
                  {!isSidebarCollapsed && <span>Audit</span>}
                </button>
              </li>
            </ul>
          </div>

          {/* User Profile Footer with Consistent Design System */}
          <div className="neo-sidebar-footer">
            <div className="neo-user-card" title={user.email}>
              <div className="neo-avatar">
                {user.email.slice(0, 2).toUpperCase()}
              </div>
              {!isSidebarCollapsed && (
                <div className="neo-user-details">
                  <span className="neo-user-name" title={user.email}>
                    {user.email.split('@')[0]}
                  </span>
                  <span className="neo-user-role">
                    Verified {user.role}
                  </span>
                </div>
              )}
            </div>

            {/* Action Buttons in Sidebar (Scanner hidden when collapsed) */}
            <div className="neo-sidebar-actions">
              <button
                type="button"
                className="neo-btn-sidebar-logout"
                onClick={handleSignOut}
                title="Sign out of moderation portal"
              >
                <LogOut size={13} aria-hidden="true" />
                {!isSidebarCollapsed && <span>Log Out</span>}
              </button>
              {!isSidebarCollapsed && (
                <button
                  type="button"
                  className="neo-btn-sidebar-scanner"
                  onClick={onBackToScanner}
                  title="Return to citizen scanner"
                >
                  <ArrowLeft size={13} aria-hidden="true" />
                  <span>Scanner</span>
                </button>
              )}
            </div>
          </div>
        </aside>

        {/* ── Main Canvas (Offset by Fixed Sidebar, Natural Window Flow) ─ */}
        <main className={`neo-canvas ${isSidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
          {/* Header */}
          <header className="neo-header">
            <div className="neo-header-titles">
              <h1>
                {activeNav === 'DASHBOARD' && 'Threat Intelligence Dashboard'}
                {activeNav === 'QUEUE' && 'Citizen Moderation Queue'}
                {activeNav === 'AUDIT' && 'Moderation Audit Trail'}
              </h1>
              <p className="neo-header-date">{todayStr} • Sri Lanka National Threat Center</p>
            </div>

            <div className="neo-header-actions">
              {/* Consistent Public Scanner Button */}
              <button
                type="button"
                className="neo-btn-header-scanner"
                onClick={onBackToScanner}
                title="Return to public scanner"
              >
                <ArrowLeft size={13} aria-hidden="true" />
                <span>Public Scanner</span>
              </button>
            </div>
          </header>

          {/* ========================================================================= */}
          {/* VIEW 1: DASHBOARD (Executive Overview & Intelligence Velocity)           */}
          {/* ========================================================================= */}
          {activeNav === 'DASHBOARD' && (
            <>
              {/* ── Row 1: Four Pastel Metric Cards (Clean, No Seed Button on Top) ──── */}
              <section className="neo-metrics-grid" aria-label="Summary statistics">
                {/* Card 1: Lavender (Pending) */}
                <div
                  className="neo-stat-card lavender"
                  onClick={() => {
                    setActiveNav('QUEUE')
                    setActiveTab('PENDING')
                  }}
                  title="Click to view pending reports in queue"
                >
                  <div className="neo-stat-top">
                    <span className="neo-stat-icon-circle">
                      <Clock size={12} aria-hidden="true" />
                    </span>
                    <span>Pending Verification</span>
                  </div>
                  <div className="neo-stat-value">
                    {pendingCount} Reports
                  </div>
                  <span className="neo-stat-subtext">Awaiting analyst consensus</span>
                </div>

                {/* Card 2: Blue (Confirmed Threats) */}
                <div
                  className="neo-stat-card blue"
                  onClick={() => {
                    setActiveNav('QUEUE')
                    setActiveTab('APPROVED')
                  }}
                  title="Click to view confirmed threats in queue"
                >
                  <div className="neo-stat-top">
                    <span className="neo-stat-icon-circle">
                      <ShieldAlert size={12} aria-hidden="true" />
                    </span>
                    <span>Confirmed Threats</span>
                  </div>
                  <div className="neo-stat-value">
                    {confirmedThreatCount} Active
                  </div>
                  <span className="neo-stat-subtext">Published to intelligence feed</span>
                </div>

                {/* Card 3: Mint (False Alarms / Safe) */}
                <div
                  className="neo-stat-card mint"
                  onClick={() => {
                    setActiveNav('QUEUE')
                    setActiveTab('APPROVED')
                  }}
                  title="Click to view false alarms in queue"
                >
                  <div className="neo-stat-top">
                    <span className="neo-stat-icon-circle">
                      <ShieldCheck size={12} aria-hidden="true" />
                    </span>
                    <span>False Alarms Cleared</span>
                  </div>
                  <div className="neo-stat-value">
                    {clearedSafeCount} Safe
                  </div>
                  <span className="neo-stat-subtext">Cleared via community review</span>
                </div>

                {/* Card 4: Deep Emerald Status Card (Clean, Seed Button Moved) */}
                <div
                  className="neo-stat-card emerald-hero"
                  onClick={() => {
                    setActiveNav('QUEUE')
                    setActiveTab('ALL')
                  }}
                  title="Click to view full registry"
                >
                  <div className="neo-stat-top">
                    <span className="neo-stat-icon-circle" style={{ background: 'rgba(255,255,255,0.2)' }}>
                      <Activity size={12} color="#ffffff" aria-hidden="true" />
                    </span>
                    <span style={{ color: '#ffffff' }}>Sri Lanka Threat Pulse</span>
                  </div>
                  <div className="neo-stat-value">
                    {allReports.length} Signals
                  </div>
                  <span className="neo-stat-subtext" style={{ color: 'rgba(255,255,255,0.85)' }}>
                    National registry & consensus active
                  </span>
                </div>
              </section>

              {/* ── Row 2: Threat Inflow Velocity (Expanded Full Width Across Row) ── */}
              <section className="neo-velocity-row">
                {/* Chart Widget (Full width across second row) */}
                <div className="neo-card">
                  <div className="neo-card-header">
                    <div>
                      <h3 className="neo-card-title">Threat Inflow Velocity</h3>
                      <span className="neo-card-subtitle">Real daily fraud submissions vs verified resolutions</span>
                    </div>
                    <button
                      type="button"
                      className="neo-btn-mini-lime"
                      onClick={handleExportData}
                      title="Export threat feed"
                    >
                      Export JSON
                    </button>
                  </div>

                  {/* High-Fidelity Velocity HTML/CSS Chart (Zero text distortion) */}
                  <div className="neo-chart-container full-width">
                    <div className="neo-velocity-chart-wrapper">
                      {/* Y Axis Labels (Crisp, native typography) */}
                      <div className="neo-velocity-yaxis">
                        <span>{weeklyActivity.maxVal}</span>
                        <span>{Math.round(weeklyActivity.maxVal / 2)}</span>
                        <span>{Math.round(weeklyActivity.maxVal / 4)}</span>
                        <span>0</span>
                      </div>

                      {/* Main Chart Plot Area */}
                      <div className="neo-velocity-plot-area">
                        {/* Horizontal Grid Lines */}
                        <div className="neo-velocity-grid-lines">
                          <div className="neo-grid-line" style={{ top: '0%' }} />
                          <div className="neo-grid-line" style={{ top: '33%' }} />
                          <div className="neo-grid-line" style={{ top: '66%' }} />
                          <div className="neo-grid-line base" style={{ top: '100%' }} />
                        </div>

                        {/* Day Columns */}
                        <div className="neo-velocity-columns">
                          {weeklyActivity.counts.map((item) => {
                            const threatPct = item.threats > 0 ? (item.threats / weeklyActivity.maxVal) * 95 : 3
                            const resolvedPct = item.resolved > 0 ? (item.resolved / weeklyActivity.maxVal) * 95 : 3

                            return (
                              <div key={item.day} className="neo-velocity-day-col">
                                <div className="neo-velocity-bar-pair">
                                  {/* Threat Bar (Lavender/Purple) */}
                                  <div
                                    className="neo-velocity-bar purple"
                                    style={{ height: `${threatPct}%` }}
                                    title={`${item.day}: ${item.threats} Submissions in Database`}
                                  />

                                  {/* Resolved Bar (Mint Green) */}
                                  <div
                                    className="neo-velocity-bar mint"
                                    style={{ height: `${resolvedPct}%` }}
                                    title={`${item.day}: ${item.resolved} Cleared or Verified`}
                                  />
                                </div>
                                <span className="neo-velocity-day-label">{item.day}</span>
                              </div>
                            )
                          })}
                        </div>
                      </div>
                    </div>

                    <div className="neo-chart-legend">
                      <span>
                        <span className="neo-chart-legend-dot purple" /> Inflow Submissions ({allReports.length})
                      </span>
                      <span>
                        <span className="neo-chart-legend-dot mint" /> Cleared & Verified ({approvedReports.length + rejectedReports.length})
                      </span>
                    </div>
                  </div>
                </div>
              </section>

              {/* ── Row 3: Category Breakdown, Urgent Review, Recent Intel (3 Columns) ─ */}
              <section className="neo-bottom-cards-row">
                {/* 1. Recent Verified Threats Card */}
                <div className="neo-card">
                  <div className="neo-card-header">
                    <div>
                      <h3 className="neo-card-title">Recent Verified Threat Intel</h3>
                      <span className="neo-card-subtitle">Active community-cleared signatures protecting citizens</span>
                    </div>
                    <button
                      type="button"
                      className="neo-btn-sidebar-logout"
                      onClick={() => {
                        setActiveNav('QUEUE')
                        setActiveTab('APPROVED')
                      }}
                      style={{ fontSize: '11px', padding: '4px 10px', color: '#0f172a' }}
                    >
                      View All Approved →
                    </button>
                  </div>

                  <div className="neo-snapshot-list">
                    {approvedReports.length === 0 ? (
                      <p style={{ fontSize: '12px', color: '#94a3b8', margin: '14px 0' }}>
                        No verified threat intelligence published yet.
                      </p>
                    ) : (
                      approvedReports.slice(0, 3).map((item) => (
                        <div key={item.id} className="neo-snapshot-item">
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <Globe size={13} color="#64748b" aria-hidden="true" />
                            <span className="neo-indicator-badge">
                              {formatCleanIndicator(item.reported_domain || item.content_sha256.slice(0, 12))}
                            </span>
                          </div>
                          <span style={{ fontSize: '11px', color: '#64748b' }}>
                            Published {formatRelativeTime(item.updated_at || item.created_at)}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* 2. Category Breakdown (Real Database Tally) */}
                <div className="neo-card">
                  <div className="neo-card-header">
                    <div>
                      <h3 className="neo-card-title">Category Breakdown</h3>
                      <span className="neo-card-subtitle">Real database threat classification</span>
                    </div>
                  </div>

                  <div className="neo-category-list">
                    {categoryStats.length === 0 ? (
                      <p style={{ fontSize: '12px', color: '#94a3b8', margin: '14px 0' }}>
                        No categorized reports recorded yet.
                      </p>
                    ) : (
                      categoryStats.map((cat) => (
                        <div
                          key={cat.category}
                          className="neo-category-row"
                          onClick={() => {
                            setActiveNav('QUEUE')
                            setSearchQuery(cat.category.split(' ')[0])
                          }}
                          title={`Click to filter Queue by ${cat.category}`}
                        >
                          <span>{cat.category}</span>
                          <div className="neo-category-meta">
                            <span className="neo-category-count">{cat.count}</span>
                            <span>{cat.percentage}%</span>
                            <ChevronRight size={14} aria-hidden="true" />
                          </div>
                        </div>
                      ))
                    )}
                  </div>

                  <div style={{ marginTop: 'auto', paddingTop: '12px', fontSize: '11px', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '5px' }}>
                    <CheckCircle2 size={12} color="#10b981" aria-hidden="true" />
                    <span>Calculated from live database reports</span>
                  </div>
                </div>

                {/* 3. Priority Incident Card (Real Pending Item from Database) */}
                <div className="neo-card">
                  <div className="neo-alert-card">
                    {priorityIncident ? (
                      <>
                        <div>
                          <span className="neo-priority-badge">Urgent Review • Needs Decision</span>
                          <h3 className="neo-card-title" style={{ fontSize: '15px', marginBottom: '6px' }}>
                            {priorityIncident.reported_domain
                              ? formatCleanIndicator(priorityIncident.reported_domain)
                              : 'Citizen Message Submission'}
                          </h3>
                          <p className="neo-alert-desc">
                            {priorityExcerpt ? `"${priorityExcerpt}"` : 'Awaiting review and sanitized classification.'}
                          </p>
                        </div>

                        <div>
                          <div className="neo-alert-meta">
                            <Clock size={12} aria-hidden="true" />
                            <span>Submitted {formatRelativeTime(priorityIncident.created_at)}</span>
                          </div>

                          <button
                            type="button"
                            className="neo-btn-dark-pill"
                            onClick={() => {
                              setActiveNav('QUEUE')
                              setActiveTab('PENDING')
                              setReviewModalReport(priorityIncident)
                            }}
                          >
                            Review in Queue →
                          </button>
                        </div>
                      </>
                    ) : (
                      <>
                        <div>
                          <span className="neo-priority-badge all-clear">✓ All Clear • Zero Pending</span>
                          <h3 className="neo-card-title" style={{ fontSize: '15px', marginBottom: '6px' }}>
                            Queue In Good Order
                          </h3>
                          <p className="neo-alert-desc">
                            All citizen submissions have been evaluated and resolved into the national verified intelligence registry.
                          </p>
                        </div>

                        <button
                          type="button"
                          className="neo-btn-dark-pill"
                          onClick={() => setActiveNav('QUEUE')}
                        >
                          View Full Queue →
                        </button>
                      </>
                    )}
                  </div>
                </div>
              </section>
            </>
          )}

          {/* ========================================================================= */}
          {/* VIEW 2: QUEUE (Full-Width Dedicated Queue Page)                          */}
          {/* ========================================================================= */}
          {activeNav === 'QUEUE' && (
            <section className="neo-queue-view-layout">
              <div className="neo-card">
                {/* Controls & Seed Button Placed Here */}
                <div className="neo-table-controls">
                  <div className="neo-filter-tabs">
                    {(['PENDING', 'APPROVED', 'REJECTED', 'ALL'] as const).map((tab) => (
                      <button
                        key={tab}
                        type="button"
                        className={`neo-filter-tab-btn ${activeTab === tab ? 'active' : ''}`}
                        onClick={() => {
                          setActiveTab(tab)
                        }}
                      >
                        {tab === 'PENDING'
                          ? `Pending (${pendingCount})`
                          : tab === 'APPROVED'
                            ? `Approved (${approvedReports.length})`
                            : tab === 'REJECTED'
                              ? `Rejected (${rejectedReports.length})`
                              : `All Reports (${allReports.length})`}
                      </button>
                    ))}
                  </div>

                  <div className="neo-table-actions">
                    <input
                      type="text"
                      className="neo-search-input"
                      placeholder="Search domain, hash, excerpt..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                    />

                    {/* Seed Demo Reports Button (Cleanly placed in toolbar) */}
                    <button
                      type="button"
                      className="neo-btn-seed-subtle"
                      onClick={() => void handleSeedDemo()}
                      disabled={isSeeding}
                      title="Seed realistic Sri Lankan reports for evaluation"
                    >
                      <Sparkles size={13} color="#84cc16" aria-hidden="true" />
                      <span>{isSeeding ? 'Seeding...' : 'Seed Demo Reports'}</span>
                    </button>

                    <button
                      type="button"
                      className="neo-btn-sidebar-logout"
                      onClick={() => void loadReports(true)}
                      disabled={isLoadingQueue}
                      title="Refresh data"
                      style={{ padding: '6px 10px' }}
                    >
                      <RefreshCw size={13} className={isLoadingQueue ? 'spin' : ''} aria-hidden="true" />
                    </button>
                  </div>
                </div>

                {queueError && (
                  <div style={{ background: '#fee2e2', color: '#991b1b', padding: '10px 14px', borderRadius: '10px', fontSize: '12px', marginBottom: '14px', fontWeight: 600 }}>
                    {queueError}
                  </div>
                )}

                {/* Data Table with Clean Pastel Badges */}
                <div className="neo-table-wrapper">
                  <table className="neo-table">
                    <thead>
                      <tr>
                        <th>Target Indicator</th>
                        <th>Category</th>
                        <th>Submitter Excerpt</th>
                        <th>Fingerprint</th>
                        <th>Status</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {displayedReports.length === 0 ? (
                        <tr>
                          <td colSpan={6} style={{ textAlign: 'center', padding: '36px', color: '#94a3b8' }}>
                            <CheckCircle2 size={32} color="#087f8c" style={{ margin: '0 auto 8px', display: 'block' }} />
                            <strong style={{ color: '#0f172a' }}>No reports found</strong>
                            <p style={{ margin: '4px 0 0', fontSize: '11.5px' }}>
                              {searchQuery ? 'Try clearing your search query.' : 'Queue is all clear for this filter.'}
                            </p>
                          </td>
                        </tr>
                      ) : (
                        paginatedReports.map((item) => {
                        const parsed = parseReportNotes(item.notes)
                        const excerpt = item.raw_excerpt || parsed.excerpt
                        const displayText = excerpt || parsed.userNotes || ''

                        return (
                          <tr key={item.id}>
                            {/* Indicator */}
                            <td>
                              <div className="neo-indicator-cell">
                                <Globe size={13} color="#64748b" aria-hidden="true" />
                                <span
                                  className={`neo-indicator-badge ${
                                    !item.reported_domain
                                      ? 'text-only'
                                      : item.status === 'APPROVED' && item.report_type === 'false_positive'
                                        ? 'safe'
                                        : ''
                                  }`}
                                >
                                  {formatCleanIndicator(item.reported_domain)}
                                </span>
                              </div>
                            </td>

                            {/* Classification */}
                            <td>
                              <span className={`neo-pill-badge ${item.report_type}`}>
                                {item.report_type === 'suspicious'
                                  ? 'Reported Threat'
                                  : item.report_type === 'false_positive'
                                    ? 'False Alarm'
                                    : 'Evaded Threat'}
                              </span>
                            </td>

                            {/* Submitter Excerpt with Modal Trigger */}
                            <td style={{ maxWidth: '320px' }}>
                              {displayText ? (
                                <div className="neo-excerpt-cell">
                                  <span
                                    className="neo-excerpt-text collapsed"
                                    title="Click to inspect full submission evidence"
                                    onClick={() => setDetailModalReport(item)}
                                    style={{ cursor: 'pointer' }}
                                  >
                                    {excerpt ? `"${excerpt}"` : parsed.userNotes}
                                  </span>
                                  <button
                                    type="button"
                                    className="neo-btn-excerpt-toggle"
                                    onClick={(e) => {
                                      e.stopPropagation()
                                      setDetailModalReport(item)
                                    }}
                                  >
                                    View full text
                                  </button>
                                </div>
                              ) : (
                                <span style={{ fontSize: '11.5px', color: '#94a3b8', fontStyle: 'italic' }}>
                                  No excerpt provided
                                </span>
                              )}
                            </td>

                            {/* SHA-256 Fingerprint */}
                            <td>
                              <span className="neo-fingerprint-badge" title={item.content_sha256}>
                                {item.content_sha256.slice(0, 10)}...
                              </span>
                            </td>

                            {/* Status */}
                            <td>
                              <span className={`neo-status-pill ${item.status}`}>
                                {item.status}
                              </span>
                            </td>

                            {/* Action Trigger */}
                            <td>
                              {item.status === 'PENDING' ? (
                                <button
                                  type="button"
                                  className="neo-btn-table-action"
                                  onClick={() => setReviewModalReport(item)}
                                >
                                  Review & Decide
                                </button>
                              ) : (
                                <button
                                  type="button"
                                  className="neo-btn-table-action"
                                  style={{
                                    background: '#f1f5f9',
                                    color: '#475569',
                                    borderColor: '#cbd5e1',
                                  }}
                                  onClick={() => setDetailModalReport(item)}
                                  title="Inspect submission record"
                                >
                                  Inspect
                                </button>
                              )}
                            </td>
                          </tr>
                        )
                      })
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Modern Pagination Bar */}
                {displayedReports.length > 0 && (
                  <div className="neo-pagination-bar">
                    <div className="neo-pagination-info">
                      <span>
                        Showing <strong>{(queuePage - 1) * queuePageSize + 1}</strong> to{' '}
                        <strong>{Math.min(queuePage * queuePageSize, displayedReports.length)}</strong> of{' '}
                        <strong>{displayedReports.length}</strong> reports
                      </span>
                      <div className="neo-page-size-selector">
                        <label htmlFor="queue-page-size">Per page:</label>
                        <select
                          id="queue-page-size"
                          value={queuePageSize}
                          onChange={(e) => {
                            setQueuePageSize(Number(e.target.value))
                            setQueuePage(1)
                          }}
                        >
                          <option value={10}>10</option>
                          <option value={20}>20</option>
                          <option value={50}>50</option>
                        </select>
                      </div>
                    </div>

                    <div className="neo-pagination-actions">
                      <button
                        type="button"
                        className="neo-btn-page-nav"
                        disabled={queuePage <= 1}
                        onClick={() => setQueuePage(1)}
                        title="First Page"
                      >
                        «
                      </button>
                      <button
                        type="button"
                        className="neo-btn-page-nav"
                        disabled={queuePage <= 1}
                        onClick={() => setQueuePage((p) => Math.max(1, p - 1))}
                        title="Previous Page"
                      >
                        ‹ Prev
                      </button>

                      {renderPaginationNumbers(queuePage, queueTotalPages, setQueuePage)}

                      <button
                        type="button"
                        className="neo-btn-page-nav"
                        disabled={queuePage >= queueTotalPages}
                        onClick={() => setQueuePage((p) => Math.min(queueTotalPages, p + 1))}
                        title="Next Page"
                      >
                        Next ›
                      </button>
                      <button
                        type="button"
                        className="neo-btn-page-nav"
                        disabled={queuePage >= queueTotalPages}
                        onClick={() => setQueuePage(queueTotalPages)}
                        title="Last Page"
                      >
                        »
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* ========================================================================= */}
          {/* VIEW 3: AUDIT (Clean Dedicated Audit Stream, Non-Valuable Tags Removed)    */}
          {/* ========================================================================= */}
          {activeNav === 'AUDIT' && (
            <section className="neo-queue-view-layout">
              {/* Complete Resolution Audit Trail Table */}
              <div className="neo-card">
                <div className="neo-card-header">
                  <div>
                    <h3 className="neo-card-title">Resolution Audit Stream</h3>
                    <span className="neo-card-subtitle">Permanent immutable record of moderator review actions</span>
                  </div>
                  <button
                    type="button"
                    className="neo-btn-sidebar-logout"
                    onClick={handleExportData}
                    style={{ fontSize: '11.5px', padding: '6px 14px', color: '#0f172a' }}
                  >
                    Export Audit Feed (JSON)
                  </button>
                </div>

                <div className="neo-table-wrapper">
                  <table className="neo-table">
                    <thead>
                      <tr>
                        <th>Resolved Indicator</th>
                        <th>Classification</th>
                        <th>Resolution Action</th>
                        <th>Submitter Notes / Excerpt</th>
                        <th>Fingerprint</th>
                        <th>Resolved Time</th>
                      </tr>
                    </thead>
                    <tbody>
                      {resolvedAuditItems.length === 0 ? (
                        <tr>
                          <td colSpan={6} style={{ textAlign: 'center', padding: '36px', color: '#94a3b8' }}>
                            <FileText size={32} color="#94a3b8" style={{ margin: '0 auto 8px', display: 'block' }} />
                            <strong style={{ color: '#0f172a' }}>No audit records yet</strong>
                            <p style={{ margin: '4px 0 0', fontSize: '11.5px' }}>
                              Review items in the Queue to generate audit trail entries.
                            </p>
                          </td>
                        </tr>
                      ) : (
                        paginatedAuditItems.map((item) => {
                          const parsed = parseReportNotes(item.notes)
                          const excerpt = item.raw_excerpt || parsed.excerpt

                          return (
                            <tr key={item.id}>
                              <td>
                                <div className="neo-indicator-cell">
                                  <Globe size={13} color="#64748b" aria-hidden="true" />
                                  <span className={`neo-indicator-badge ${item.status === 'APPROVED' && item.report_type === 'false_positive' ? 'safe' : ''}`}>
                                    {formatCleanIndicator(item.reported_domain)}
                                  </span>
                                </div>
                              </td>
                              <td>
                                <span className={`neo-pill-badge ${item.report_type}`}>
                                  {item.report_type === 'suspicious' ? 'Threat' : 'False Alarm'}
                                </span>
                              </td>
                              <td>
                                <span className={`neo-status-pill ${item.status}`}>
                                  {item.status}
                                </span>
                              </td>
                              <td style={{ maxWidth: '320px' }}>
                                {excerpt || parsed.userNotes ? (
                                  <div className="neo-excerpt-cell">
                                    <span
                                      className="neo-excerpt-text collapsed"
                                      title="Click to inspect full submission evidence"
                                      onClick={() => setDetailModalReport(item)}
                                      style={{ cursor: 'pointer' }}
                                    >
                                      {excerpt ? `"${excerpt}"` : parsed.userNotes}
                                    </span>
                                    <button
                                      type="button"
                                      className="neo-btn-excerpt-toggle"
                                      onClick={(e) => {
                                        e.stopPropagation()
                                        setDetailModalReport(item)
                                      }}
                                    >
                                      View full text
                                    </button>
                                  </div>
                                ) : (
                                  <span style={{ fontSize: '11.5px', color: '#94a3b8', fontStyle: 'italic' }}>
                                    No notes provided
                                  </span>
                                )}
                              </td>
                              <td>
                                <span className="neo-fingerprint-badge">
                                  {item.content_sha256.slice(0, 10)}...
                                </span>
                              </td>
                              <td style={{ fontSize: '11px', color: '#64748b' }}>
                                {formatRelativeTime(item.updated_at || item.created_at)}
                              </td>
                            </tr>
                          )
                        })
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Modern Audit Pagination Bar */}
                {resolvedAuditItems.length > 0 && (
                  <div className="neo-pagination-bar">
                    <div className="neo-pagination-info">
                      <span>
                        Showing <strong>{(auditPage - 1) * auditPageSize + 1}</strong> to{' '}
                        <strong>{Math.min(auditPage * auditPageSize, resolvedAuditItems.length)}</strong> of{' '}
                        <strong>{resolvedAuditItems.length}</strong> records
                      </span>
                      <div className="neo-page-size-selector">
                        <label htmlFor="audit-page-size">Per page:</label>
                        <select
                          id="audit-page-size"
                          value={auditPageSize}
                          onChange={(e) => {
                            setAuditPageSize(Number(e.target.value))
                            setAuditPage(1)
                          }}
                        >
                          <option value={10}>10</option>
                          <option value={20}>20</option>
                          <option value={50}>50</option>
                        </select>
                      </div>
                    </div>

                    <div className="neo-pagination-actions">
                      <button
                        type="button"
                        className="neo-btn-page-nav"
                        disabled={auditPage <= 1}
                        onClick={() => setAuditPage(1)}
                        title="First Page"
                      >
                        «
                      </button>
                      <button
                        type="button"
                        className="neo-btn-page-nav"
                        disabled={auditPage <= 1}
                        onClick={() => setAuditPage((p) => Math.max(1, p - 1))}
                        title="Previous Page"
                      >
                        ‹ Prev
                      </button>

                      {renderPaginationNumbers(auditPage, auditTotalPages, setAuditPage)}

                      <button
                        type="button"
                        className="neo-btn-page-nav"
                        disabled={auditPage >= auditTotalPages}
                        onClick={() => setAuditPage((p) => Math.min(auditTotalPages, p + 1))}
                        title="Next Page"
                      >
                        Next ›
                      </button>
                      <button
                        type="button"
                        className="neo-btn-page-nav"
                        disabled={auditPage >= auditTotalPages}
                        onClick={() => setAuditPage(auditTotalPages)}
                        title="Last Page"
                      >
                        »
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </section>
          )}
        </main>
      </div>

      {/* ── Evidence Detail & Full Text Modal (Inspect up to 10,000+ words) ── */}
      <ReportDetailModal
        isOpen={Boolean(detailModalReport)}
        report={detailModalReport}
        onClose={() => setDetailModalReport(null)}
        onOpenReview={
          detailModalReport?.status === 'PENDING'
            ? (rep) => {
                setDetailModalReport(null)
                setReviewModalReport(rep)
              }
            : undefined
        }
      />

      {/* ── Review Decision Modal (Consensus, Classification & Sanitization) ── */}
      <ReviewDecisionModal
        isOpen={Boolean(reviewModalReport)}
        report={reviewModalReport}
        onClose={() => setReviewModalReport(null)}
        onApprove={handleModalApprove}
        onReject={handleModalReject}
        isProcessing={isProcessingReview}
      />
    </div>
  )
}

export default ModeratorDashboard

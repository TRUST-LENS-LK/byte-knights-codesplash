import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  LayoutDashboard,
  ShieldCheck,
  ShieldAlert,
  Clock,
  CheckCircle2,
  RefreshCw,
  ArrowLeft,
  Globe,
  Sparkles,
  ChevronRight,
  FileText,
  AlertCircle,
  Download,
  ArrowRight,
  Hash,
  Phone,
  Power,
  Pencil,
  Copy,
  Check,
  ChevronDown,
  RotateCcw,
  XCircle,
  Menu,
  Search,
  CreditCard,
  Layers,
  PieChart,
  AlertTriangle,
  X,
  History,
  Trash2,
  FileSpreadsheet,
  Info,
} from 'lucide-react'
import {
  type ModerationQueueItem,
  type ModeratorUser,
  type ModerationStats,
  type VerifiedIntelligenceItem,
  type ModerationAuditLogItem,
  type AuditStorageStats,
  clearSession,
  fetchModerationQueue,
  fetchModerationStats,
  fetchEngineSettings,
  updateEngineSettings,
  fetchVerifiedIntelligence,
  toggleIntelligenceStatus,
  updateIntelligenceItem,
  getStoredSession,
  reviewModerationItem,
  seedDemoReports,
  clearDemoReports,
  fetchModerationAuditLogs,
  fetchAuditStorageStats,
  triggerAuditPurge,
  exportAuditLogsToCsv,
} from '../services/moderatorService'
import { defangIndicator } from '../services/reportingService'
import { formatRelativeTime } from '../utils/formatTime'
import { ReviewDecisionModal } from './modals/ReviewDecisionModal'
import { AuditDetailModal } from './modals/AuditDetailModal'
import { ModeratorLogin } from './ModeratorLogin'
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
  if (!rawNotes) return { threatCategory: null, excerpt: null, userNotes: null }
  const threatCategoryMatch = rawNotes.match(/\[Threat Category\]:\s*([^\n\r]+)/)
  const excerptMatch = rawNotes.match(/\[Reported Message Excerpt\]:\s*"([\s\S]*?)"(?:\n\n|$)/)
  const userNotesMatch = rawNotes.match(/\[Submitter Context\]:\s*([\s\S]*)$/)

  return {
    threatCategory: threatCategoryMatch ? threatCategoryMatch[1].trim() : null,
    excerpt: excerptMatch ? excerptMatch[1] : null,
    userNotes: userNotesMatch ? userNotesMatch[1] : (threatCategoryMatch || excerptMatch ? null : rawNotes),
  }
}

export function getReportTypeDisplay(type: string | undefined): {
  label: string
  badgeClass: string
} {
  if (type === 'false_positive') {
    return { label: 'False Alarm', badgeClass: 'pill-alarm' }
  }
  if (type === 'false_negative') {
    return { label: 'Evaded Detection', badgeClass: 'pill-evaded' }
  }
  return { label: 'Unreported Threat', badgeClass: 'pill-threat' }
}

export function getAuditActionBadge(action: ModerationAuditLogItem['action']) {
  switch (action) {
    case 'APPROVE':
      return { label: 'APPROVE', badgeClass: 'audit-badge-approve' }
    case 'REJECT':
      return { label: 'REJECT', badgeClass: 'audit-badge-reject' }
    case 'RETIRE':
      return { label: 'RETIRE', badgeClass: 'audit-badge-retire' }
    case 'TOGGLE_STATUS':
      return { label: 'STATUS TOGGLE', badgeClass: 'audit-badge-toggle' }
    case 'UPDATE_SETTINGS':
      return { label: 'ENGINE POLICY', badgeClass: 'audit-badge-setting' }
    case 'PURGE_EXPIRED':
      return { label: 'RETENTION PURGE', badgeClass: 'audit-badge-purge' }
    default:
      return { label: action, badgeClass: 'audit-badge-default' }
  }
}

export function formatDaysRemaining(expiresAt?: string, fallbackDays = 90): string {
  if (!expiresAt) return `${fallbackDays}d TTL`
  const ms = new Date(expiresAt).getTime() - Date.now()
  if (ms <= 0) return 'Expired'
  const days = Math.ceil(ms / (1000 * 60 * 60 * 24))
  return `${days}d TTL`
}

export function getAuditCategoryBadgeClass(category?: string | null, action?: string): string {
  const cat = (category || '').toLowerCase()
  if (action === 'REJECT' || cat.includes('false') || cat.includes('official') || cat.includes('safe') || cat.includes('dismissed')) {
    return 'false_positive'
  }
  if (action === 'RETIRE' || cat.includes('retire')) {
    return 'neutral'
  }
  if (action === 'UPDATE_SETTINGS' || action === 'TOGGLE_STATUS' || cat.includes('policy')) {
    return 'false_negative'
  }
  return 'suspicious'
}

/**
 * Categorize report dynamically based on real content & threat category
 */
function classifyReportCategory(item: ModerationQueueItem): string {
  const parsed = parseReportNotes(item.notes)
  if (parsed.threatCategory) return parsed.threatCategory
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

export function getReportRiskSignal(item: ModerationQueueItem): { level: 'HIGH' | 'MEDIUM' | 'LOW'; color: string } {
  // 1. Prioritize backend-computed deterministic triage signal from @trustlens/rules
  if (item.risk_signal) {
    return item.risk_signal
  }
  if (item.report_type === 'false_positive') {
    return { level: 'LOW', color: '#10B981' }
  }
  const rawDomain = item.reported_domain || ''
  const domain = rawDomain.toLowerCase().replace(/hxxps?:\/\//i, '').replace(/\[\.\]/g, '.').replace(/\[@\]/g, '@').trim()
  // Direct IP addresses (like 192.168.21.144) without domain routing are high risk infrastructure
  if (domain && /^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/.test(domain)) {
    return { level: 'HIGH', color: '#EF4444' }
  }
  const text = `${item.reported_domain || ''} ${item.notes || ''} ${item.raw_excerpt || ''}`.toLowerCase()
  if (/otp|pin|password|credential|boc|combank|bank|hnb|sampath|\.apk/.test(text)) {
    return { level: 'HIGH', color: '#EF4444' }
  }
  return { level: 'MEDIUM', color: '#F59E0B' }
}

export function getThreatDetails(item: ModerationQueueItem): {
  title: string
  subtitle: string
  type: 'phishing' | 'scam' | 'malware' | 'safe'
} {
  const rawDomain = item.reported_domain || ''
  const domain = rawDomain.toLowerCase().replace(/hxxps?:\/\//i, '').replace(/\[\.\]/g, '.').replace(/\[@\]/g, '@').trim()
  const text = `${item.reported_domain || ''} ${item.notes || ''} ${item.raw_excerpt || ''}`.toLowerCase()

  // 1. Prioritize backend-computed deterministic triage signal from @trustlens/rules
  if (item.threat) {
    // If backend mistakenly labeled a message-only report as Suspicious Domain, correct it
    if (!domain && item.threat.title === 'Suspicious Domain') {
      if (/subscription|invoice|refund|renew|charge|geek squad|norton|mcafee|paypal|apple/.test(text)) {
        return { title: 'Scam', subtitle: 'Subscription / Invoice Fraud', type: 'scam' }
      }
      return { title: 'Suspicious Message', subtitle: 'Citizen Submission', type: 'scam' }
    }
    return item.threat
  }

  if (item.report_type === 'false_positive') {
    return { title: 'False Alarm', subtitle: 'User Dispute', type: 'safe' }
  }

  if (domain && /^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/.test(domain)) {
    return { title: 'Suspicious Domain', subtitle: 'Raw IP Infrastructure', type: 'phishing' }
  }

  if (/\.apk|download|install|app|update|malware|trojan/.test(text)) {
    return { title: 'Malware', subtitle: 'Malicious Link / APK', type: 'malware' }
  }
  if (/subscription|invoice|refund|renew|charge|geek squad|norton|mcafee|paypal|apple/.test(text)) {
    return { title: 'Scam', subtitle: 'Subscription / Invoice Fraud', type: 'scam' }
  }
  if (/ceb|electricity|utility|water|bill|telecom|dialog|mobitel|job|earn|salary|advance|bonus|hiring|lottery|prize|won|lucky|cash|gift|reward|offer/.test(text)) {
    return { title: 'Scam', subtitle: 'Financial & Utility Fraud', type: 'scam' }
  }
  if (/boc|combank|bank|hnb|sampath|card|debit|credit|fund|login|verify|otp|pin|password|credential|security/.test(text)) {
    return { title: 'Phishing', subtitle: 'Credential Harvesting', type: 'phishing' }
  }

  if (!domain) {
    return { title: 'Suspicious Message', subtitle: 'Citizen Submission', type: 'scam' }
  }

  return { title: 'Suspicious Domain', subtitle: 'Unverified Web Target', type: 'phishing' }
}

function renderPaginationNumbers(currentPage: number, totalPages: number, onSelect: (p: number) => void) {
  if (totalPages <= 0) return null

  const maxVisible = 3
  let start = Math.max(1, currentPage - 1)
  let end = start + maxVisible - 1

  if (end > totalPages) {
    end = totalPages
    start = Math.max(1, end - maxVisible + 1)
  }

  const pages: number[] = []
  for (let i = start; i <= end; i++) {
    pages.push(i)
  }

  return (
    <div className="neo-page-numbers">
      {pages.map((p) => (
        <button
          key={p}
          type="button"
          className={`neo-page-pill ${p === currentPage ? 'active' : ''}`}
          onClick={() => onSelect(p)}
          title={`Go to page ${p}`}
        >
          {p}
        </button>
      ))}
    </div>
  )
}

/**
 * Mathematically generates a smooth, normalized Cubic Bezier SVG sparkline
 * path from a dynamic time-series array of values (chronological 7 days).
 */
export function generateSparklinePath(values: number[], width = 80, height = 32): string {
  if (!values || values.length === 0) {
    return `M 2,${height - 8} Q ${width / 2},${height - 8} ${width - 2},${height - 8}`
  }

  const paddingX = 3
  const paddingTop = 6
  const paddingBottom = 6
  const usableWidth = width - paddingX * 2
  const usableHeight = height - paddingTop - paddingBottom

  const min = Math.min(...values)
  const max = Math.max(...values)
  const range = max - min

  // Map each data point to its (x, y) canvas coordinate
  const points = values.map((val, idx) => {
    const x = paddingX + (idx / Math.max(values.length - 1, 1)) * usableWidth
    // Invert y: higher value -> smaller y (closer to top of SVG)
    let y: number
    if (range === 0) {
      y = max === 0 ? height - paddingBottom : height / 2
    } else {
      y = height - paddingBottom - ((val - min) / range) * usableHeight
    }
    return { x: Math.round(x * 10) / 10, y: Math.round(y * 10) / 10 }
  })

  if (points.length === 1) {
    return `M 2,${points[0].y} L ${width - 2},${points[0].y}`
  }

  // Generate a silky-smooth Catmull-Rom cubic Bezier path
  let path = `M ${points[0].x},${points[0].y}`
  for (let i = 0; i < points.length - 1; i++) {
    const p0 = points[Math.max(i - 1, 0)]
    const p1 = points[i]
    const p2 = points[i + 1]
    const p3 = points[Math.min(i + 2, points.length - 1)]

    const cp1x = p1.x + (p2.x - p0.x) / 6
    const cp1y = p1.y + (p2.y - p0.y) / 6
    const cp2x = p2.x - (p3.x - p1.x) / 6
    const cp2y = p2.y - (p3.y - p1.y) / 6

    path += ` C ${cp1x.toFixed(1)},${cp1y.toFixed(1)} ${cp2x.toFixed(1)},${cp2y.toFixed(1)} ${p2.x.toFixed(1)},${p2.y.toFixed(1)}`
  }

  return path
}

function getInitialNav(): 'DASHBOARD' | 'QUEUE' | 'AUDIT' | 'INTELLIGENCE' {
  if (typeof window !== 'undefined') {
    const hash = window.location.hash.toLowerCase()
    if (hash.includes('queue')) return 'QUEUE'
    if (hash.includes('audit')) return 'AUDIT'
    if (hash.includes('intelligence') || hash.includes('intel')) return 'INTELLIGENCE'
    if (hash.includes('dashboard')) return 'DASHBOARD'

    const stored = sessionStorage.getItem('trustlens_mod_nav')
    if (stored === 'QUEUE' || stored === 'AUDIT' || stored === 'INTELLIGENCE' || stored === 'DASHBOARD') {
      return stored
    }
  }
  return 'DASHBOARD'
}

interface DropdownOption<T extends string> {
  value: T
  label: string
  dotColor?: string
}

interface NeoFilterDropdownProps<T extends string> {
  label: string
  icon?: React.ReactNode
  value: T
  options: DropdownOption<T>[]
  onChange: (val: T) => void
  title?: string
}

function NeoFilterDropdown<T extends string>({
  label,
  icon,
  value,
  options,
  onChange,
  title,
}: NeoFilterDropdownProps<T>) {
  const [isOpen, setIsOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!isOpen) return
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setIsOpen(false)
      }
    }
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setIsOpen(false)
    }
    document.addEventListener('mousedown', handleClickOutside)
    document.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
      document.removeEventListener('keydown', handleKeyDown)
    }
  }, [isOpen])

  const selectedOption = options.find((opt) => opt.value === value)
  const isFiltered = value !== options[0]?.value

  return (
    <div className="neo-custom-filter-dropdown" ref={dropdownRef}>
      <button
        type="button"
        className={`neo-btn-filter-trigger ${isFiltered ? 'is-active' : ''} ${isOpen ? 'is-open' : ''}`}
        onClick={() => setIsOpen((prev) => !prev)}
        title={title || `Filter by ${label}`}
        aria-expanded={isOpen}
      >
        {icon && <span className="neo-filter-icon">{icon}</span>}
        <span className="neo-filter-label">
          {isFiltered ? selectedOption?.label || label : label}
        </span>
        {isFiltered && <span className="neo-filter-active-dot" />}
        <ChevronDown size={13} className={`neo-filter-chevron ${isOpen ? 'rotate' : ''}`} aria-hidden="true" />
      </button>

      {isOpen && (
        <div className="neo-filter-popover-menu" role="menu">
          {options.map((opt) => {
            const isSelected = opt.value === value
            return (
              <button
                key={opt.value}
                type="button"
                className={`neo-filter-option-item ${isSelected ? 'selected' : ''}`}
                onClick={() => {
                  onChange(opt.value)
                  setIsOpen(false)
                }}
                role="menuitem"
              >
                <div className="neo-filter-option-left">
                  {opt.dotColor && (
                    <span
                      className="neo-filter-option-dot"
                      style={{ backgroundColor: opt.dotColor }}
                    />
                  )}
                  <span className="neo-filter-option-text">{opt.label}</span>
                </div>
                {isSelected && <Check size={13} className="neo-filter-option-check" aria-hidden="true" />}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

export const ModeratorDashboard: React.FC<ModeratorDashboardProps> = ({ onBackToScanner }) => {
  const [token, setToken] = useState<string | null>(() => getStoredSession().token)
  const [user, setUser] = useState<ModeratorUser | null>(() => getStoredSession().user)

  // Navigation State (4 views: Dashboard, Queue, Audit, Intelligence) - Preserved across browser refresh
  const [activeNav, setActiveNav] = useState<'DASHBOARD' | 'QUEUE' | 'AUDIT' | 'INTELLIGENCE'>(getInitialNav)
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false)

  // Sync activeNav changes to sessionStorage and URL hash
  useEffect(() => {
    if (typeof window !== 'undefined') {
      sessionStorage.setItem('trustlens_mod_nav', activeNav)
      const targetHash = `#moderator/${activeNav.toLowerCase()}`
      if (window.location.hash !== targetHash) {
        window.history.replaceState(null, '', targetHash)
      }
    }
  }, [activeNav])

  // Listen to hashchange for browser back/forward buttons
  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.toLowerCase()
      if (hash.includes('queue')) setActiveNav('QUEUE')
      else if (hash.includes('audit')) setActiveNav('AUDIT')
      else if (hash.includes('intelligence') || hash.includes('intel')) setActiveNav('INTELLIGENCE')
      else if (hash.includes('dashboard') || hash === '#moderator') setActiveNav('DASHBOARD')
    }
    window.addEventListener('hashchange', handleHashChange)
    return () => window.removeEventListener('hashchange', handleHashChange)
  }, [])


  // Dedicated Aggregated Stats State (High-performance metrics decoupled from full table arrays)
  const [stats, setStats] = useState<ModerationStats | null>(null)

  // Real Database Reports (Full dataset)
  const [allReports, setAllReports] = useState<ModerationQueueItem[]>([])
  const [activeTab, setActiveTab] = useState<'PENDING' | 'APPROVED' | 'REJECTED' | 'ALL'>('PENDING')
  const [searchQuery, setSearchQuery] = useState('')
  const [filterType, setFilterType] = useState<'ALL' | 'suspicious' | 'false_positive' | 'false_negative'>('ALL')
  const [filterThreat, setFilterThreat] = useState<'ALL' | 'phishing' | 'scam' | 'malware' | 'safe'>('ALL')
  const [filterDate, setFilterDate] = useState<'ALL' | 'today' | '7days' | '30days'>('ALL')
  const [showDemoMenu, setShowDemoMenu] = useState(false)
  const [isLoadingQueue, setIsLoadingQueue] = useState(false)
  const [queueError, setQueueError] = useState<string | null>(null)

  // Verified Intelligence State
  const [intelligenceList, setIntelligenceList] = useState<VerifiedIntelligenceItem[]>([])
  const [intelStatusFilter, setIntelStatusFilter] = useState<'active' | 'retired' | 'all'>('all')
  const [intelTypeFilter, setIntelTypeFilter] = useState<'domain' | 'content_hash' | 'phone' | 'url' | 'all'>('all')
  const [intelRiskFilter, setIntelRiskFilter] = useState<'CONFIRMED_SCAM' | 'VERIFIED_SAFE' | 'all'>('all')
  const [intelSearchQuery, setIntelSearchQuery] = useState('')
  const [intelPage, setIntelPage] = useState(1)
  const [intelPageSize, setIntelPageSize] = useState<number>(10)
  const [intelTotal, setIntelTotal] = useState(0)
  const [intelTotalPages, setIntelTotalPages] = useState(1)
  const [isLoadingIntel, setIsLoadingIntel] = useState(false)
  const [intelError, setIntelError] = useState<string | null>(null)
  const [isUpdatingIntel, setIsUpdatingIntel] = useState(false)

  // Queue Pagination State
  const [queuePage, setQueuePage] = useState(1)
  const [queuePageSize, setQueuePageSize] = useState<number>(10)

  // Dedicated Real Audit Logs State & Retention Governance
  const [auditLogsList, setAuditLogsList] = useState<ModerationAuditLogItem[]>([])
  const [auditStorageStats, setAuditStorageStats] = useState<AuditStorageStats | null>(null)
  const [auditActionFilter, setAuditActionFilter] = useState<'ALL' | 'APPROVE' | 'REJECT' | 'RETIRE' | 'TOGGLE_STATUS' | 'UPDATE_SETTINGS' | 'PURGE_EXPIRED'>('ALL')
  const [auditSearchQuery, setAuditSearchQuery] = useState('')
  const [auditPage, setAuditPage] = useState(1)
  const [auditPageSize, setAuditPageSize] = useState<number>(10)
  const [auditTotal, setAuditTotal] = useState(0)
  const [auditTotalPages, setAuditTotalPages] = useState(1)
  const [isLoadingAudit, setIsLoadingAudit] = useState(false)
  const [auditError, setAuditError] = useState<string | null>(null)
  const [isPurgingAudit, setIsPurgingAudit] = useState(false)
  const [selectedAuditDetail, setSelectedAuditDetail] = useState<ModerationAuditLogItem | null>(null)
  const [retentionDays, setRetentionDays] = useState<number>(90)
  const [isUpdatingRetention, setIsUpdatingRetention] = useState(false)

  // Dedicated Modal Dialog State
  const [reviewModalReport, setReviewModalReport] = useState<ModerationQueueItem | null>(null)
  const [isProcessingReview, setIsProcessingReview] = useState(false)
  const [isSeeding, setIsSeeding] = useState(false)
  const [isClearing, setIsClearing] = useState(false)

  // Dynamic Threat Feedback Loop Engine State
  const [engineEnabled, setEngineEnabled] = useState<boolean>(true)
  const [isTogglingEngine, setIsTogglingEngine] = useState<boolean>(false)

  // Toast Notification
  const [toastMessage, setToastMessage] = useState<string | null>(null)
  const toastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const showToast = useCallback((msg: string) => {
    if (toastTimerRef.current) {
      clearTimeout(toastTimerRef.current)
    }
    setToastMessage(msg)
    toastTimerRef.current = setTimeout(() => {
      setToastMessage(null)
    }, 4500)
  }, [])

  const handleSignOut = useCallback(() => {
    clearSession()
    setToken(null)
    setUser(null)
    setAllReports([])
    setStats(null)
    showToast('✓ Signed out of moderator session.')
  }, [showToast])

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

  // Automatically reset queue page to 1 whenever tab or any filter changes
  useEffect(() => {
    setQueuePage(1)
  }, [activeTab, searchQuery, filterThreat, filterDate])


  // Load initial engine settings
  useEffect(() => {
    if (!token) return
    fetchEngineSettings(token).then((res) => {
      if (res.success && res.settings && typeof res.settings.enableVerifiedIntel === 'boolean') {
        setEngineEnabled(res.settings.enableVerifiedIntel)
      }
    })
  }, [token])

  const handleToggleEngine = async () => {
    if (!token || isTogglingEngine) return
    const nextState = !engineEnabled
    setIsTogglingEngine(true)
    // Optimistic update
    setEngineEnabled(nextState)
    const res = await updateEngineSettings(token, { enableVerifiedIntel: nextState })
    setIsTogglingEngine(false)
    if (res.success && res.settings) {
      if (typeof res.settings.enableVerifiedIntel === 'boolean') {
        setEngineEnabled(res.settings.enableVerifiedIntel)
      }
      showToast(
        nextState
          ? '⚡ Threat Feedback Loop ACTIVE: Real-time community intelligence matching enabled.'
          : '⏸️ Threat Feedback Loop PAUSED: Scanner will only use static heuristics.'
      )
    } else {
      setEngineEnabled(!nextState)
      showToast(`Failed to update engine status: ${res.error}`)
    }
  }

  // Load initial intelligence count
  useEffect(() => {
    if (!token) return
    fetchVerifiedIntelligence(token, { status: 'active', limit: 1 }).then((res) => {
      if (res.success && typeof res.total === 'number') {
        setIntelTotal(res.total)
      }
    })
  }, [token])

  const loadIntelligence = useCallback(
    async (showSpinner = false) => {
      if (!token) return
      if (showSpinner) setIsLoadingIntel(true)
      setIntelError(null)
      const res = await fetchVerifiedIntelligence(token, {
        status: intelStatusFilter,
        type: intelTypeFilter,
        riskLevel: intelRiskFilter,
        search: intelSearchQuery,
        page: intelPage,
        limit: intelPageSize,
      })
      setIsLoadingIntel(false)
      if (res.success && res.intelligence) {
        setIntelligenceList(res.intelligence)
        setIntelTotal(res.total || 0)
        setIntelTotalPages(res.totalPages || 1)
      } else {
        setIntelError(res.error || 'Could not load verified intelligence.')
      }
    },
    [token, intelStatusFilter, intelTypeFilter, intelRiskFilter, intelSearchQuery, intelPage, intelPageSize]
  )

  useEffect(() => {
    if (activeNav === 'INTELLIGENCE' && token) {
      void loadIntelligence(true)
    }
  }, [activeNav, token, loadIntelligence])

  const loadAuditLogs = useCallback(
    async (showSpinner = false) => {
      if (!token) return
      if (showSpinner) setIsLoadingAudit(true)
      setAuditError(null)
      const res = await fetchModerationAuditLogs(token, {
        action: auditActionFilter,
        search: auditSearchQuery,
        page: auditPage,
        limit: auditPageSize,
      })
      setIsLoadingAudit(false)
      if (res.success && res.auditLogs) {
        setAuditLogsList(res.auditLogs)
        setAuditTotal(res.total || 0)
        setAuditTotalPages(res.totalPages || 1)
      } else {
        setAuditError(res.error || 'Could not load audit logs.')
      }
    },
    [token, auditActionFilter, auditSearchQuery, auditPage, auditPageSize]
  )

  const loadAuditStats = useCallback(async () => {
    if (!token) return
    const res = await fetchAuditStorageStats(token)
    if (res.success && res.stats) {
      setAuditStorageStats(res.stats)
      if (typeof res.stats.retentionDays === 'number') {
        setRetentionDays(res.stats.retentionDays)
      }
    }
  }, [token])

  const handleRetentionDaysChange = async (newDays: number) => {
    if (!token || isUpdatingRetention || newDays === retentionDays) return
    setIsUpdatingRetention(true)
    const res = await updateEngineSettings(token, { auditRetentionDays: newDays })
    setIsUpdatingRetention(false)
    if (res.success) {
      setRetentionDays(newDays)
      showToast(`✓ Audit retention policy updated to ${newDays} days.`)
      void loadAuditStats()
      void loadAuditLogs(false)
    } else {
      showToast(`Failed to update retention policy: ${res.error || 'Unknown error'}`)
    }
  }

  useEffect(() => {
    if (activeNav === 'AUDIT' && token) {
      void loadAuditLogs(true)
      void loadAuditStats()
    }
  }, [activeNav, token, loadAuditLogs, loadAuditStats])

  const handleTriggerPurge = async () => {
    if (!token || isPurgingAudit) return
    if (
      !window.confirm(
        `Execute ${retentionDays}-Day Retention Policy purge now? Any logs older than ${retentionDays} days will be permanently cleaned up from the database.`
      )
    )
      return
    setIsPurgingAudit(true)
    const res = await triggerAuditPurge(token)
    setIsPurgingAudit(false)
    if (res.success) {
      showToast(`✓ Retention purge complete: ${res.purgedCount || 0} expired log(s) pruned.`)
      void loadAuditLogs(true)
      void loadAuditStats()
    } else {
      showToast(`Retention purge failed: ${res.error}`)
    }
  }

  const handleExportAuditJson = () => {
    if (!auditLogsList.length) {
      showToast('No audit logs to export.')
      return
    }
    const jsonStr = `data:text/json;charset=utf-8,${encodeURIComponent(JSON.stringify(auditLogsList, null, 2))}`
    const downloadAnchor = document.createElement('a')
    downloadAnchor.setAttribute('href', jsonStr)
    downloadAnchor.setAttribute('download', `trustlens_audit_trail_${new Date().toISOString().slice(0, 10)}.json`)
    document.body.appendChild(downloadAnchor)
    downloadAnchor.click()
    downloadAnchor.remove()
    showToast('✓ Audit trail exported to JSON.')
  }

  const handleExportAuditCsv = () => {
    if (!auditLogsList.length) {
      showToast('No audit logs to export.')
      return
    }
    exportAuditLogsToCsv(auditLogsList)
    showToast('✓ Audit trail exported to CSV.')
  }

  const handleToggleIntelStatus = async (item: VerifiedIntelligenceItem, newActive: boolean) => {
    if (!token) return
    const actionVerb = newActive ? 'reactivate' : 'retire'
    const promptMsg = newActive
      ? `Reactivate indicator "${item.defanged_value}" back into the active threat intelligence feed?`
      : `Retire indicator "${item.defanged_value}"? It will no longer be flagged as an active threat in public checks.`
    if (!window.confirm(promptMsg)) return

    // Optimistic update
    setIntelligenceList((prev) =>
      prev.map((i) => (i.id === item.id ? { ...i, active: newActive } : i))
    )

    setIsUpdatingIntel(true)
    const res = await toggleIntelligenceStatus(token, item.id, newActive, `Indicator ${actionVerb}d by moderator`)
    setIsUpdatingIntel(false)

    if (res.success) {
      showToast(`Indicator ${item.defanged_value} successfully ${actionVerb}d.`)
      void loadIntelligence()
      void loadReports()
    } else {
      // Revert on error
      setIntelligenceList((prev) =>
        prev.map((i) => (i.id === item.id ? { ...i, active: item.active } : i))
      )
      showToast(`Failed to update indicator: ${res.error}`)
    }
  }

  const [editingIntelId, setEditingIntelId] = useState<string | null>(null)
  const [editingIntelNoteText, setEditingIntelNoteText] = useState('')
  const [copiedHashId, setCopiedHashId] = useState<string | null>(null)

  const handleStartEditNote = (item: VerifiedIntelligenceItem) => {
    setEditingIntelId(item.id)
    setEditingIntelNoteText(item.notes || '')
  }

  const handleCancelEditNote = () => {
    setEditingIntelId(null)
    setEditingIntelNoteText('')
  }

  const handleSaveNote = async (item: VerifiedIntelligenceItem) => {
    if (!token) return
    const newNotes = editingIntelNoteText.trim()
    // Optimistic update
    setIntelligenceList((prev) =>
      prev.map((i) => (i.id === item.id ? { ...i, notes: newNotes } : i))
    )
    setEditingIntelId(null)

    setIsUpdatingIntel(true)
    const res = await updateIntelligenceItem(token, item.id, { notes: newNotes })
    setIsUpdatingIntel(false)

    if (res.success) {
      showToast('Threat intelligence note updated successfully.')
      void loadIntelligence()
    } else {
      // Revert
      setIntelligenceList((prev) =>
        prev.map((i) => (i.id === item.id ? { ...i, notes: item.notes } : i))
      )
      showToast(`Failed to update note: ${res.error}`)
    }
  }

  const handleCopyHash = (id: string, hash: string) => {
    navigator.clipboard.writeText(hash)
    setCopiedHashId(id)
    showToast(`✓ Copied: ${hash.length > 28 ? hash.slice(0, 26) + '...' : hash}`)
    setTimeout(() => setCopiedHashId(null), 2000)
  }

  const handleModalApprove = async (
    report: ModerationQueueItem,
    category: string,
    indicatorType: 'domain' | 'content_hash' | 'url',
    notes: string,
    confidence: number = 1.0
  ) => {
    if (!token) return
    setIsProcessingReview(true)
    const res = await reviewModerationItem(token, {
      reportId: report.id,
      action: 'APPROVE',
      category,
      indicatorType: report.reported_domain ? indicatorType : 'content_hash',
      notes: notes.trim() || 'Approved by moderator and sanitized for threat intelligence.',
      confidence,
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

  const handleClearDemo = async () => {
    if (!token) return
    if (!window.confirm('Clear all demo reports and test fixtures from the queue?')) return
    setIsClearing(true)
    const res = await clearDemoReports(token)
    setIsClearing(false)
    if (res.success) {
      showToast(`✓ Cleared ${res.count ?? 0} demo reports from queue.`)
      void loadReports(true)
    } else {
      showToast(`Clear failed: ${res.error}`)
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

  const uniqueDomainsCount = useMemo(() => {
    return new Set(allReports.map((r) => r.reported_domain).filter(Boolean)).size || 12
  }, [allReports])

  const { pendingToday, approvedToday, rejectedToday } = useMemo(() => {
    const today = new Date()
    today.setHours(0, 0, 0, 0)
    const pCount = pendingReports.filter((r) => new Date(r.created_at) >= today).length
    const aCount = approvedReports.filter((r) => new Date(r.updated_at || r.created_at) >= today).length
    const rCount = rejectedReports.filter((r) => new Date(r.updated_at || r.created_at) >= today).length
    return {
      pendingToday: pCount,
      approvedToday: aCount,
      rejectedToday: rCount,
    }
  }, [pendingReports, approvedReports, rejectedReports])

  // ── DYNAMIC 7-DAY SPARKLINE DATASETS (CHRONOLOGICAL: 6 DAYS AGO -> TODAY) ──
  const { pendingSparkline, approvedSparkline, rejectedSparkline, totalSparkline } = useMemo(() => {
    const now = new Date()
    const days: { start: Date; end: Date }[] = []

    for (let i = 6; i >= 0; i--) {
      const start = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i, 0, 0, 0, 0)
      const end = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i, 23, 59, 59, 999)
      days.push({ start, end })
    }

    const pendingData = days.map(({ start, end }) =>
      pendingReports.filter((r) => {
        const d = new Date(r.created_at)
        return d >= start && d <= end
      }).length
    )

    const approvedData = days.map(({ start, end }) =>
      approvedReports.filter((r) => {
        const d = new Date(r.updated_at || r.created_at)
        return d >= start && d <= end
      }).length
    )

    const rejectedData = days.map(({ start, end }) =>
      rejectedReports.filter((r) => {
        const d = new Date(r.updated_at || r.created_at)
        return d >= start && d <= end
      }).length
    )

    const totalData = days.map(({ start, end }) =>
      allReports.filter((r) => {
        const d = new Date(r.created_at)
        return d >= start && d <= end
      }).length
    )

    return {
      pendingSparkline: generateSparklinePath(pendingData),
      approvedSparkline: generateSparklinePath(approvedData),
      rejectedSparkline: generateSparklinePath(rejectedData),
      totalSparkline: generateSparklinePath(totalData),
    }
  }, [pendingReports, approvedReports, rejectedReports, allReports])

  const handleResetFilters = () => {
    setSearchQuery('')
    setFilterType('ALL')
    setFilterThreat('ALL')
    setFilterDate('ALL')
    setActiveTab('PENDING')
    setQueuePage(1)
    showToast('✓ Filters and search reset to defaults.')
  }

  // Filtered reports for current tab & search & advanced filters
  const tabFilteredReports = useMemo(() => {
    if (activeTab === 'PENDING') return pendingReports
    if (activeTab === 'APPROVED') return approvedReports
    if (activeTab === 'REJECTED') return rejectedReports
    return allReports
  }, [activeTab, pendingReports, approvedReports, rejectedReports, allReports])

  const displayedReports = useMemo(() => {
    let list = tabFilteredReports

    // 1. Text search
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim()
      list = list.filter((r) => {
        const ind = (r.reported_domain || '').toLowerCase()
        const notes = (r.notes || '').toLowerCase()
        const excerpt = (r.raw_excerpt || '').toLowerCase()
        const hash = (r.content_sha256 || '').toLowerCase()
        return ind.includes(q) || notes.includes(q) || excerpt.includes(q) || hash.includes(q)
      })
    }

    // 2. Report Type filter (Unreported Threat, False Alarm, Evaded Detection)
    if (filterType !== 'ALL') {
      list = list.filter((r) => r.report_type === filterType)
    }

    // 3. Threat category filter
    if (filterThreat !== 'ALL') {
      list = list.filter((r) => {
        const t = getThreatDetails(r).type
        return t === filterThreat
      })
    }

    // 3. Date filter
    if (filterDate !== 'ALL') {
      const now = new Date()
      if (filterDate === 'today') {
        const today = new Date(now.getFullYear(), now.getMonth(), now.getDate())
        list = list.filter((r) => {
          const d = new Date(r.created_at)
          return !isNaN(d.getTime()) && d >= today
        })
      } else if (filterDate === '7days') {
        const past = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)
        list = list.filter((r) => {
          const d = new Date(r.created_at)
          return !isNaN(d.getTime()) && d >= past
        })
      } else if (filterDate === '30days') {
        const past = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000)
        list = list.filter((r) => {
          const d = new Date(r.created_at)
          return !isNaN(d.getTime()) && d >= past
        })
      }
    }

    return list
  }, [tabFilteredReports, searchQuery, filterType, filterThreat, filterDate])

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

  // Format today's date
  const todayStr = new Date().toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
  })

  const handleLoginSuccess = (newToken: string, newUser: ModeratorUser) => {
    setToken(newToken)
    setUser(newUser)
    showToast(`✓ Welcome, ${newUser.email} (${newUser.role === 'moderator' ? 'Verified Moderator' : newUser.role})`)
  }

  // Render Login Card if not authenticated
  if (!token || !user) {
    return (
      <div key="page-moderator-login" className="trustlens-page-transition">
        {toastMessage && (
          <div className="neo-toast" role="status" aria-live="polite">
            <CheckCircle2 size={16} className="neo-toast-icon" aria-hidden="true" />
            <span className="neo-toast-text">{toastMessage}</span>
            <button
              type="button"
              className="neo-toast-close"
              onClick={() => setToastMessage(null)}
              aria-label="Dismiss notification"
            >
              <X size={14} aria-hidden="true" />
            </button>
          </div>
        )}
        <ModeratorLogin
          onSuccess={handleLoginSuccess}
          onBackToScanner={onBackToScanner}
        />
      </div>
    )
  }

  // ── REUSABLE 4-CARD KPI METRICS COMPONENT (MATCHING MOCKUP) ─────────────
  const renderKPICards = () => (
    <section className="neo-kpi-grid" aria-label="Summary statistics">
      {/* Card 1: Pending */}
      <div
        className="neo-kpi-card"
        onClick={() => {
          setActiveNav('QUEUE')
          setActiveTab('PENDING')
        }}
        title="Click to view pending reports in queue"
      >
        <div className="neo-kpi-content">
          <div className="neo-kpi-icon-circle red">
            <Clock size={16} aria-hidden="true" />
          </div>
          <div className="neo-kpi-body">
            <div className="neo-kpi-metric-row">
              <span className="neo-kpi-value">{pendingCount}</span>
              <span className="neo-kpi-label">Pending</span>
            </div>
            <div className="neo-kpi-trend red">
              <span>↑ {pendingToday} today</span>
            </div>
          </div>
        </div>
        <div className="neo-kpi-sparkline">
          <svg viewBox="0 0 80 32" className="neo-sparkline-svg red" aria-hidden="true">
            <path
              d={pendingSparkline}
              fill="none"
              stroke="#EF4444"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
      </div>

      {/* Card 2: Approved */}
      <div
        className="neo-kpi-card"
        onClick={() => {
          setActiveNav('QUEUE')
          setActiveTab('APPROVED')
        }}
        title={`Click to view approved reports (${confirmedThreatCount} confirmed threats, ${clearedSafeCount} false alarms verified safe)`}
      >
        <div className="neo-kpi-content">
          <div className="neo-kpi-icon-circle green">
            <CheckCircle2 size={16} aria-hidden="true" />
          </div>
          <div className="neo-kpi-body">
            <div className="neo-kpi-metric-row">
              <span className="neo-kpi-value">{String(approvedReports.length).padStart(2, '0')}</span>
              <span className="neo-kpi-label">Approved</span>
            </div>
            <div className="neo-kpi-trend green">
              <span>↑ {approvedToday} today</span>
            </div>
          </div>
        </div>
        <div className="neo-kpi-sparkline">
          <svg viewBox="0 0 80 32" className="neo-sparkline-svg green" aria-hidden="true">
            <path
              d={approvedSparkline}
              fill="none"
              stroke="#10B981"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
      </div>

      {/* Card 3: Rejected */}
      <div
        className="neo-kpi-card"
        onClick={() => {
          setActiveNav('QUEUE')
          setActiveTab('REJECTED')
        }}
        title="Click to view rejected reports in queue"
      >
        <div className="neo-kpi-content">
          <div className="neo-kpi-icon-circle orange">
            <XCircle size={16} aria-hidden="true" />
          </div>
          <div className="neo-kpi-body">
            <div className="neo-kpi-metric-row">
              <span className="neo-kpi-value">{String(rejectedReports.length).padStart(2, '0')}</span>
              <span className="neo-kpi-label">Rejected</span>
            </div>
            <div className="neo-kpi-trend orange">
              <span>↑ {rejectedToday} today</span>
            </div>
          </div>
        </div>
        <div className="neo-kpi-sparkline">
          <svg viewBox="0 0 80 32" className="neo-sparkline-svg orange" aria-hidden="true">
            <path
              d={rejectedSparkline}
              fill="none"
              stroke="#F97316"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
      </div>

      {/* Card 4: Total Reports */}
      <div
        className="neo-kpi-card"
        onClick={() => {
          setActiveNav('QUEUE')
          setActiveTab('ALL')
        }}
        title="Click to view all reports in queue"
      >
        <div className="neo-kpi-content">
          <div className="neo-kpi-icon-circle blue">
            <FileText size={16} aria-hidden="true" />
          </div>
          <div className="neo-kpi-body">
            <div className="neo-kpi-metric-row">
              <span className="neo-kpi-value">{allReports.length}</span>
              <span className="neo-kpi-label">Total Reports</span>
            </div>
            <div className="neo-kpi-subtext">
              <span>{uniqueDomainsCount} domains</span>
            </div>
          </div>
        </div>
        <div className="neo-kpi-sparkline">
          <svg viewBox="0 0 80 32" className="neo-sparkline-svg blue" aria-hidden="true">
            <path
              d={totalSparkline}
              fill="none"
              stroke="#0066FF"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
      </div>
    </section>
  )

  return (
    <div key="page-moderator-dashboard" className="neo-dashboard-wrapper trustlens-page-transition">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="neo-toast" role="status" aria-live="polite">
          <CheckCircle2 size={16} className="neo-toast-icon" aria-hidden="true" />
          <span className="neo-toast-text">{toastMessage}</span>
          <button
            type="button"
            className="neo-toast-close"
            onClick={() => setToastMessage(null)}
            aria-label="Dismiss notification"
          >
            <X size={14} aria-hidden="true" />
          </button>
        </div>
      )}

      <div className="neo-dashboard-frame">
        {/* ── Fixed Left Sidebar (Permanently Docked on Scroll, Collapsible) ─ */}
        <aside className={`neo-sidebar ${isSidebarCollapsed ? 'collapsed' : ''}`}>
          <div>
            <div className="neo-brand-header">
              <div className="neo-brand-mark" title="TrustLens LK">
                <img src="/TrustLens_Icon.png" alt="TrustLens LK" />
              </div>
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
                <Menu size={16} aria-hidden="true" />
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
                  className={`neo-nav-btn ${activeNav === 'INTELLIGENCE' ? 'active' : ''}`}
                  onClick={() => setActiveNav('INTELLIGENCE')}
                  title="Verified Intelligence"
                >
                  <ShieldCheck size={17} aria-hidden="true" />
                  {!isSidebarCollapsed && <span>Verified Intel</span>}
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
                    {user.role === 'moderator' ? 'Moderator' : user.role}
                  </span>
                </div>
              )}
            </div>

            {/* Action Buttons in Sidebar */}
            <div className="neo-sidebar-actions">
              <button
                type="button"
                className="neo-btn-sidebar-logout"
                onClick={handleSignOut}
                title="Sign out of moderation portal"
              >
                <ArrowLeft size={13} aria-hidden="true" />
                {!isSidebarCollapsed && <span>Log Out</span>}
              </button>
            </div>
          </div>
        </aside>

        {/* ── Main Canvas (Offset by Fixed Sidebar, Natural Window Flow) ─ */}
        <main className={`neo-canvas ${isSidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
          {/* Header */}
          <header className="neo-header">
            <div className="neo-header-titles">
              <h1 key={activeNav} className="neo-header-title-transition">
                {activeNav === 'DASHBOARD' && 'Moderator Threat Overview'}
                {activeNav === 'QUEUE' && 'Citizen Moderation Queue'}
                {activeNav === 'AUDIT' && 'Moderation Audit Trail'}
                {activeNav === 'INTELLIGENCE' && 'Verified Threat Intelligence Feed'}
              </h1>
              <p className="neo-header-date">{todayStr} · Sri Lanka National Threat Center</p>
            </div>

            <div className="neo-header-actions">
              {/* Dynamic Threat Feedback Loop Simple Toggle Button with Label */}
              <button
                type="button"
                className={`neo-feedback-toggle-btn ${engineEnabled ? 'on' : 'off'}`}
                onClick={handleToggleEngine}
                disabled={isTogglingEngine}
                title={
                  engineEnabled
                    ? 'Threat Feedback Loop is ACTIVE: Real-time community intelligence enabled. Click to pause.'
                    : 'Threat Feedback Loop is PAUSED: Scanner will only use static heuristics. Click to activate.'
                }
              >
                <span className="neo-feedback-toggle-label">Feedback Loop</span>
                <span className="neo-feedback-toggle-pill">
                  <span className="neo-feedback-toggle-knob" />
                  <span className="neo-feedback-toggle-status">{engineEnabled ? 'ON' : 'OFF'}</span>
                </span>
              </button>

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
            <div key="DASHBOARD" className="neo-view-transition neo-dashboard-view-layout">
              {/* ── Row 1: Four Modern KPI Metric Cards Matching Mockup ──── */}
              {renderKPICards()}

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
                <div className="neo-card neo-bottom-modern-card">
                  <div className="neo-card-header">
                    <div className="neo-card-header-left">
                      <div className="neo-card-icon-circle green">
                        <ShieldCheck size={18} aria-hidden="true" />
                      </div>
                      <h3 className="neo-card-title">Recent Verified Intel</h3>
                    </div>
                    <button
                      type="button"
                      className="neo-btn-toolbar-action"
                      onClick={() => {
                        setActiveNav('QUEUE')
                        setActiveTab('APPROVED')
                      }}
                      title="View all approved reports"
                    >
                      <span>View All ({approvedReports.length})</span>
                      <ArrowRight size={12} aria-hidden="true" />
                    </button>
                  </div>

                  <div className="neo-snapshot-list">
                    {approvedReports.length === 0 ? (
                      <div className="neo-empty-snapshot">
                        <ShieldCheck size={28} color="#94A3B8" aria-hidden="true" />
                        <p>No verified threat intelligence published yet.</p>
                      </div>
                    ) : (
                      approvedReports.slice(0, 3).map((item) => {
                        const isDomain = Boolean(item.reported_domain)
                        const indicatorText = formatCleanIndicator(item.reported_domain || item.content_sha256.slice(0, 14))
                        const isThreat = item.report_type === 'suspicious' || item.report_type === 'false_negative'
                        return (
                          <div key={item.id} className="neo-snapshot-item">
                            <div className="neo-snapshot-item-left">
                              <div className="neo-snapshot-icon-circle">
                                {isDomain ? <Globe size={13} aria-hidden="true" /> : <Hash size={13} aria-hidden="true" />}
                              </div>
                              <div className="neo-snapshot-target-col">
                                <div className="neo-snapshot-target-row">
                                  <span className="neo-indicator-badge" title={item.reported_domain || item.content_sha256}>
                                    {indicatorText}
                                  </span>
                                  <button
                                    type="button"
                                    className="neo-btn-copy-mini"
                                    onClick={(e) => {
                                      e.stopPropagation()
                                      handleCopyHash(item.id, item.reported_domain || item.content_sha256)
                                    }}
                                    title="Copy indicator"
                                  >
                                    {copiedHashId === item.id ? <Check size={11} color="#10B981" /> : <Copy size={11} />}
                                  </button>
                                </div>
                                <span className="neo-snapshot-category-tag">
                                  {classifyReportCategory(item)}
                                </span>
                              </div>
                            </div>
                            <div className="neo-snapshot-item-right">
                              <span className={`neo-verdict-pill ${isThreat ? 'threat' : 'safe'}`}>
                                {isThreat ? 'CONFIRMED' : 'SAFE'}
                              </span>
                              <span className="neo-snapshot-time">
                                <Clock size={11} aria-hidden="true" />
                                {formatRelativeTime(item.updated_at || item.created_at)}
                              </span>
                            </div>
                          </div>
                        )
                      })
                    )}
                  </div>
                </div>

                {/* 2. Category Breakdown (Real Database Tally) */}
                <div className="neo-card neo-bottom-modern-card">
                  <div className="neo-card-header">
                    <div className="neo-card-header-left">
                      <div className="neo-card-icon-circle blue">
                        <Layers size={18} aria-hidden="true" />
                      </div>
                      <h3 className="neo-card-title">Threat Classification</h3>
                    </div>
                  </div>

                  <div className="neo-category-list">
                    {categoryStats.length === 0 ? (
                      <div className="neo-empty-snapshot">
                        <PieChart size={28} color="#94A3B8" aria-hidden="true" />
                        <p>No categorized reports recorded yet.</p>
                      </div>
                    ) : (
                      categoryStats.map((cat) => {
                        const catLower = cat.category.toLowerCase()
                        let CatIcon = AlertTriangle
                        let barColor = '#0066FF'
                        if (catLower.includes('bank') || catLower.includes('phish')) {
                          CatIcon = CreditCard
                          barColor = '#6366F1'
                        } else if (catLower.includes('telecom') || catLower.includes('utility')) {
                          CatIcon = Phone
                          barColor = '#F59E0B'
                        } else if (catLower.includes('false') || catLower.includes('alarm')) {
                          CatIcon = ShieldCheck
                          barColor = '#10B981'
                        }

                        return (
                          <div
                            key={cat.category}
                            className="neo-category-row"
                            onClick={() => {
                              setActiveNav('QUEUE')
                              setSearchQuery(cat.category.split(' ')[0])
                            }}
                            title={`Click to filter Queue by ${cat.category}`}
                          >
                            <div className="neo-category-row-top">
                              <div className="neo-category-label-group">
                                <div className="neo-cat-icon-badge" style={{ color: barColor, background: `${barColor}15` }}>
                                  <CatIcon size={13} aria-hidden="true" />
                                </div>
                                <span className="neo-category-name">{cat.category}</span>
                              </div>
                              <div className="neo-category-meta">
                                <span className="neo-category-count">{cat.count}</span>
                                <span className="neo-category-pct">{cat.percentage}%</span>
                                <ChevronRight size={13} aria-hidden="true" />
                              </div>
                            </div>
                            <div className="neo-cat-progress-track">
                              <div
                                className="neo-cat-progress-fill"
                                style={{ width: `${Math.max(cat.percentage, 4)}%`, background: barColor }}
                              />
                            </div>
                          </div>
                        )
                      })
                    )}
                  </div>
                </div>

                {/* 3. Priority Incident Card (Real Pending Item from Database) */}
                <div className="neo-card neo-bottom-modern-card neo-spotlight-card">
                  {priorityIncident ? (
                    <div className="neo-spotlight-content">
                      <div className="neo-spotlight-top">
                        <div className="neo-priority-badge-live">
                          <span className="neo-pulse-dot-red" />
                          <span>URGENT TRIAGE • ACTION REQUIRED</span>
                        </div>

                        <div className="neo-spotlight-target-box">
                          <div className="neo-spotlight-target-left">
                            <div className="neo-spotlight-icon-circle">
                              <ShieldAlert size={18} aria-hidden="true" />
                            </div>
                            <div className="neo-spotlight-title-row">
                              <h4 className="neo-spotlight-title">
                                {priorityIncident.reported_domain
                                  ? formatCleanIndicator(priorityIncident.reported_domain)
                                  : 'Citizen Message Submission'}
                              </h4>
                              <button
                                type="button"
                                className="neo-btn-copy-mini"
                                onClick={() =>
                                  handleCopyHash(
                                    priorityIncident.id,
                                    priorityIncident.reported_domain || priorityIncident.content_sha256
                                  )
                                }
                                title="Copy indicator"
                              >
                                {copiedHashId === priorityIncident.id ? (
                                  <Check size={11} color="#10B981" />
                                ) : (
                                  <Copy size={11} />
                                )}
                              </button>
                            </div>
                          </div>
                          <span className="neo-risk-pill-high">HIGH RISK</span>
                        </div>

                        <div className="neo-spotlight-quote-box">
                          <span className="neo-quote-mark">“</span>
                          <p className="neo-spotlight-excerpt">
                            {priorityExcerpt || 'Awaiting review and sanitized classification.'}
                          </p>
                        </div>
                      </div>

                      <div className="neo-spotlight-bottom">
                        <div className="neo-spotlight-chips">
                          <div className="neo-spotlight-chip">
                            <Clock size={11} aria-hidden="true" />
                            <span>Submitted {formatRelativeTime(priorityIncident.created_at)}</span>
                          </div>
                          <div className="neo-spotlight-chip">
                            <Hash size={11} aria-hidden="true" />
                            <span>{priorityIncident.content_sha256.slice(0, 8)}...</span>
                          </div>
                        </div>

                        <button
                          type="button"
                          className="neo-btn-spotlight-action"
                          onClick={() => {
                            setActiveNav('QUEUE')
                            setActiveTab('PENDING')
                            setReviewModalReport(priorityIncident)
                          }}
                        >
                          <span>Review & Decide</span>
                          <ArrowRight size={14} aria-hidden="true" />
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="neo-spotlight-all-clear">
                      <div className="neo-all-clear-icon">
                        <CheckCircle2 size={36} color="#10B981" aria-hidden="true" />
                      </div>
                      <span className="neo-priority-badge-live all-clear">
                        <span>✓ ZERO BACKLOG • ALL CLEAR</span>
                      </span>
                      <h4 className="neo-spotlight-title">All Reports Reviewed</h4>
                      <p className="neo-alert-desc">
                        Every citizen submission in the queue has been evaluated and resolved.
                      </p>
                      <button
                        type="button"
                        className="neo-btn-spotlight-action"
                        onClick={() => setActiveNav('INTELLIGENCE')}
                      >
                        <span>Explore Verified Intel</span>
                        <ArrowRight size={14} aria-hidden="true" />
                      </button>
                    </div>
                  )}
                </div>
              </section>
            </div>
          )}

          {/* ========================================================================= */}
          {/* VIEW 2: QUEUE (Full-Width Dedicated Queue Page Matching Mockup)          */}
          {/* ========================================================================= */}
          {activeNav === 'QUEUE' && (
            <section key="QUEUE" className="neo-queue-view-layout neo-view-transition">
              {/* ── Queue Table Card with Modern Controls ──── */}
              <div className="neo-modern-table-card">
                {/* Modern Toolbar */}
                <div className="neo-modern-toolbar">
                  {/* Left: Segmented Filter Pill Tabs */}
                  <div className="neo-segmented-filter-group">
                    {(['PENDING', 'APPROVED', 'REJECTED', 'ALL'] as const).map((tab) => (
                      <button
                        key={tab}
                        type="button"
                        className={`neo-seg-pill ${activeTab === tab ? 'active' : ''}`}
                        onClick={() => setActiveTab(tab)}
                      >
                        {tab === 'PENDING'
                          ? `Pending ${pendingCount}`
                          : tab === 'APPROVED'
                            ? `Approved ${approvedReports.length}`
                            : tab === 'REJECTED'
                              ? `Rejected ${rejectedReports.length}`
                              : `All Reports ${allReports.length}`}
                      </button>
                    ))}
                  </div>

                  {/* Right: Search, Filter Dropdowns, Reset, and Demo Tools */}
                  <div className="neo-modern-toolbar-actions">
                    {/* Search Input */}
                    <div className="neo-toolbar-search-box">
                      <Search size={14} className="neo-search-icon-inside" aria-hidden="true" />
                      <input
                        type="text"
                        placeholder="Search domain, hash, excerpt..."
                        value={searchQuery}
                        onChange={(e) => {
                          setSearchQuery(e.target.value)
                          setQueuePage(1)
                        }}
                        className="neo-modern-search-input"
                      />
                    </div>

                    {/* Type Filter Dropdown (Unreported Threat, False Alarm, Evaded Detection) */}
                    <NeoFilterDropdown
                      label="Type"
                      icon={<Layers size={13} aria-hidden="true" />}
                      value={filterType}
                      onChange={(val) => {
                        setFilterType(val)
                        setQueuePage(1)
                      }}
                      options={[
                        { value: 'ALL', label: 'All Types' },
                        { value: 'suspicious', label: 'Unreported Threat', dotColor: '#EF4444' },
                        { value: 'false_positive', label: 'False Alarm', dotColor: '#10B981' },
                        { value: 'false_negative', label: 'Evaded Detection', dotColor: '#6366F1' },
                      ]}
                      title="Filter by report intent"
                    />

                    {/* Threat Filter Dropdown */}
                    <NeoFilterDropdown
                      label="Threat"
                      icon={<ShieldAlert size={13} aria-hidden="true" />}
                      value={filterThreat}
                      onChange={(val) => {
                        setFilterThreat(val)
                        setQueuePage(1)
                      }}
                      options={[
                        { value: 'ALL', label: 'All Threats' },
                        { value: 'phishing', label: 'Phishing', dotColor: '#EF4444' },
                        { value: 'scam', label: 'Scam', dotColor: '#F59E0B' },
                        { value: 'malware', label: 'Malware', dotColor: '#8B5CF6' },
                        { value: 'safe', label: 'False Alarm (Safe)', dotColor: '#10B981' },
                      ]}
                      title="Filter by threat classification"
                    />

                    {/* Date Filter Dropdown */}
                    <NeoFilterDropdown
                      label="Date"
                      icon={<Clock size={13} aria-hidden="true" />}
                      value={filterDate}
                      onChange={(val) => {
                        setFilterDate(val)
                        setQueuePage(1)
                      }}
                      options={[
                        { value: 'ALL', label: 'All Dates' },
                        { value: 'today', label: 'Today' },
                        { value: '7days', label: 'Last 7 Days' },
                        { value: '30days', label: 'Last 30 Days' },
                      ]}
                      title="Filter by submission date"
                    />

                    {/* Reset Button */}
                    <button
                      type="button"
                      className={`neo-btn-toolbar-reset ${searchQuery || filterType !== 'ALL' || filterThreat !== 'ALL' || filterDate !== 'ALL'
                        ? 'has-active-filters'
                        : ''
                        }`}
                      onClick={handleResetFilters}
                      title="Reset all filters and search"
                    >
                      <RotateCcw size={12} aria-hidden="true" />
                      <span>Reset</span>
                    </button>

                    {/* Demo Tools Dropdown Popup Menu */}
                    <div className="neo-demo-tools-wrapper">
                      <button
                        type="button"
                        className="neo-btn-demo-tools"
                        onClick={() => setShowDemoMenu((prev) => !prev)}
                        title="Quick evaluation & seeding utilities"
                      >
                        <Sparkles size={13} aria-hidden="true" />
                        <span>Demo Tools</span>
                        <ChevronDown size={13} aria-hidden="true" />
                      </button>

                      {showDemoMenu && (
                        <div className="neo-demo-dropdown-menu">
                          <button
                            type="button"
                            className="neo-demo-menu-item"
                            onClick={() => {
                              setShowDemoMenu(false)
                              void handleSeedDemo()
                            }}
                            disabled={isSeeding || isClearing}
                          >
                            <Sparkles size={13} color="#0066FF" aria-hidden="true" />
                            <span>{isSeeding ? 'Seeding...' : 'Seed Demo Reports'}</span>
                          </button>
                          <button
                            type="button"
                            className="neo-demo-menu-item"
                            onClick={() => {
                              setShowDemoMenu(false)
                              void handleClearDemo()
                            }}
                            disabled={isSeeding || isClearing}
                          >
                            <RotateCcw size={13} color="#64748B" aria-hidden="true" />
                            <span>{isClearing ? 'Clearing...' : 'Clear Demo Data'}</span>
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Error Banner */}
                {queueError && (
                  <div className="neo-modern-error-banner" role="alert">
                    <AlertCircle size={14} aria-hidden="true" />
                    <span>{queueError}</span>
                  </div>
                )}

                {/* Modern Data Table Matching Mockup */}
                <div className="neo-modern-table-wrapper">
                  <table className="neo-modern-table">
                    <thead>
                      <tr>
                        <th>TARGET</th>
                        <th>TYPE</th>
                        <th>THREAT</th>
                        <th>EXCERPT</th>
                        <th>FINGERPRINT</th>
                        <th>STATUS</th>
                        <th>ACTION</th>
                      </tr>
                    </thead>
                    <tbody key={`${activeTab}-${queuePage}`} className="neo-table-body-transition">
                      {isLoadingQueue ? (
                        <tr>
                          <td colSpan={7} style={{ textAlign: 'center', padding: '48px 20px', color: '#64748B' }}>
                            <RefreshCw size={24} className="neo-spin" style={{ margin: '0 auto 8px', display: 'block', color: '#0066FF' }} />
                            <strong style={{ color: '#0F172A', fontSize: '14px' }}>Loading queue reports...</strong>
                          </td>
                        </tr>
                      ) : displayedReports.length === 0 ? (
                        <tr>
                          <td colSpan={7} style={{ textAlign: 'center', padding: '48px 20px', color: '#94a3b8' }}>
                            <CheckCircle2 size={32} color="#0066FF" style={{ margin: '0 auto 8px', display: 'block' }} />
                            <strong style={{ color: '#0f172a', fontSize: '14px' }}>No reports found</strong>
                            <p style={{ margin: '4px 0 0', fontSize: '12px' }}>
                              {searchQuery || filterType !== 'ALL' || filterThreat !== 'ALL' || filterDate !== 'ALL'
                                ? 'Try adjusting or resetting your search and filters.'
                                : 'Queue is all clear for this category.'}
                            </p>
                          </td>
                        </tr>
                      ) : (
                        paginatedReports.map((item) => {
                          const parsed = parseReportNotes(item.notes)
                          const excerpt = item.raw_excerpt || parsed.excerpt
                          const displayText = excerpt || parsed.userNotes || ''
                          const typeInfo = getReportTypeDisplay(item.report_type)
                          const threat = getThreatDetails(item)
                          const specificCategory = parsed.threatCategory || threat.title
                          const isCopied = copiedHashId === item.id

                          return (
                            <tr key={item.id}>
                              {/* TARGET */}
                              <td>
                                <div className="neo-target-cell">
                                  <div className="neo-target-icon-circle">
                                    {item.reported_domain ? (
                                      <Globe size={14} color="#64748b" aria-hidden="true" />
                                    ) : (
                                      <FileText size={14} color="#64748b" aria-hidden="true" />
                                    )}
                                  </div>
                                  <div className="neo-target-info">
                                    <span className="neo-target-domain" title={item.reported_domain || 'Message-only'}>
                                      {formatCleanIndicator(item.reported_domain)}
                                    </span>
                                    <span className="neo-target-type">
                                      {item.reported_domain ? 'Domain' : 'Message'}
                                    </span>
                                  </div>
                                </div>
                              </td>

                              {/* TYPE (Report Intent) */}
                              <td>
                                <span className={`neo-report-type-pill ${typeInfo.badgeClass}`}>
                                  {typeInfo.label}
                                </span>
                              </td>

                              {/* THREAT */}
                              <td>
                                <div className="neo-threat-cell">
                                  <div className={`neo-threat-dot ${threat.type}`} />
                                  <div className="neo-threat-info">
                                    <span className="neo-threat-title">{specificCategory}</span>
                                    <span className="neo-threat-sub">{threat.subtitle}</span>
                                  </div>
                                </div>
                              </td>

                              {/* EXCERPT */}
                              <td style={{ maxWidth: '280px' }}>
                                {displayText ? (
                                  <span className="neo-modern-excerpt" title={displayText}>
                                    "{displayText.length > 55 ? displayText.slice(0, 55) + '...' : displayText}"
                                  </span>
                                ) : (
                                  <span className="neo-empty-excerpt">No excerpt provided</span>
                                )}
                              </td>

                              {/* FINGERPRINT */}
                              <td>
                                <div className="neo-fingerprint-cell">
                                  <span className="neo-fingerprint-text" title={item.content_sha256}>
                                    {item.content_sha256.slice(0, 10)}...
                                  </span>
                                  <button
                                    type="button"
                                    className="neo-btn-copy-hash"
                                    onClick={() => handleCopyHash(item.id, item.content_sha256)}
                                    title={isCopied ? 'Copied to clipboard!' : 'Copy full SHA-256 fingerprint'}
                                    aria-label="Copy SHA-256 fingerprint"
                                  >
                                    {isCopied ? (
                                      <Check size={12} color="#10B981" aria-hidden="true" />
                                    ) : (
                                      <Copy size={12} aria-hidden="true" />
                                    )}
                                  </button>
                                </div>
                              </td>

                              {/* STATUS */}
                              <td>
                                <span className={`neo-status-pill-modern ${item.status.toLowerCase()}`}>
                                  {item.status}
                                </span>
                              </td>

                              {/* ACTION */}
                              <td>
                                {item.status === 'PENDING' ? (
                                  <button
                                    type="button"
                                    className="neo-btn-review-action"
                                    onClick={() => setReviewModalReport(item)}
                                  >
                                    <span>Review</span>
                                    <ArrowRight size={13} aria-hidden="true" />
                                  </button>
                                ) : (
                                  <button
                                    type="button"
                                    className="neo-btn-inspect-action"
                                    onClick={() => setReviewModalReport(item)}
                                    title="Inspect submission record"
                                  >
                                    <span>Inspect</span>
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
          {/* VIEW 3: AUDIT TRAIL & RETENTION GOVERNANCE (Enterprise-Grade Subsystem)   */}
          {/* ========================================================================= */}
          {activeNav === 'AUDIT' && (
            <section key="AUDIT" className="neo-queue-view-layout neo-view-transition" aria-label="Audit Trail and Retention Governance">
              {/* Complete Resolution Audit Trail Table */}
              <div className="neo-modern-table-card">
                <div className="neo-modern-toolbar">
                  {/* Segmented Filter Pills */}
                  <div className="neo-segmented-filter-group">
                    {[
                      { id: 'ALL', label: `All (${auditTotal})` },
                      { id: 'APPROVE', label: `Approved (${auditStorageStats?.actionBreakdown?.approve || 0})` },
                      { id: 'REJECT', label: `Rejected (${auditStorageStats?.actionBreakdown?.reject || 0})` },
                      { id: 'RETIRE', label: `Retired (${auditStorageStats?.actionBreakdown?.retire || 0})` },
                      ...((auditStorageStats?.actionBreakdown?.settings || 0) + (auditStorageStats?.actionBreakdown?.toggle || 0) > 0
                        ? [
                            {
                              id: 'UPDATE_SETTINGS',
                              label: `Policies (${(auditStorageStats?.actionBreakdown?.settings || 0) + (auditStorageStats?.actionBreakdown?.toggle || 0)})`,
                            },
                          ]
                        : []),
                    ].map((tab) => (
                      <button
                        key={tab.id}
                        type="button"
                        className={`neo-seg-pill ${auditActionFilter === tab.id ? 'active' : ''}`}
                        onClick={() => {
                          setAuditActionFilter(tab.id as any)
                          setAuditPage(1)
                        }}
                      >
                        {tab.label}
                      </button>
                    ))}
                  </div>

                  {/* Right: Search, Retention Selector, Export and Prune Actions */}
                  <div className="neo-modern-toolbar-actions">
                    <div className="neo-toolbar-search-box">
                      <Search size={14} className="neo-search-icon-inside" aria-hidden="true" />
                      <input
                        type="text"
                        placeholder="Search target, actor, notes..."
                        value={auditSearchQuery}
                        onChange={(e) => {
                          setAuditSearchQuery(e.target.value)
                          setAuditPage(1)
                        }}
                        className="neo-modern-search-input"
                      />
                    </div>

                    {/* Retention Setting Selector Dropdown */}
                    <div className="neo-retention-selector-wrapper" title="Manually configure data retention TTL policy">
                      <Clock size={13} className="neo-retention-icon" aria-hidden="true" />
                      <select
                        className="neo-retention-select"
                        value={retentionDays}
                        disabled={isUpdatingRetention}
                        onChange={(e) => void handleRetentionDaysChange(Number(e.target.value))}
                        title="Set audit trail data retention period"
                      >
                        <option value={30}>TTL: 30 Days</option>
                        <option value={60}>TTL: 60 Days</option>
                        <option value={90}>TTL: 90 Days (Default)</option>
                        <option value={180}>TTL: 180 Days (6 Mos)</option>
                        <option value={365}>TTL: 365 Days (1 Yr)</option>
                      </select>
                    </div>

                    <button
                      type="button"
                      className="neo-btn-toolbar-reset has-active-filters"
                      onClick={handleExportAuditCsv}
                      title="Export audit log to CSV for compliance and record-keeping"
                    >
                      <FileSpreadsheet size={13} aria-hidden="true" />
                      <span>Export CSV</span>
                    </button>

                    <button
                      type="button"
                      className="neo-btn-toolbar-reset has-active-filters"
                      onClick={handleExportAuditJson}
                      title="Export audit log to JSON for cryptographic verification"
                    >
                      <Download size={13} aria-hidden="true" />
                      <span>Export JSON</span>
                    </button>

                    <button
                      type="button"
                      className="neo-btn-toolbar-prune"
                      onClick={handleTriggerPurge}
                      disabled={isPurgingAudit}
                      title={`Run retention purge now to delete expired logs past ${retentionDays} days`}
                    >
                      <Trash2 size={13} aria-hidden="true" />
                      <span>{isPurgingAudit ? 'Purging...' : 'Prune Expired'}</span>
                    </button>
                  </div>
                </div>

                <div className="neo-modern-table-wrapper">
                  <table className="neo-modern-table">
                    <thead>
                      <tr>
                        <th>ACTION</th>
                        <th>TARGET INDICATOR</th>
                        <th>CLASSIFICATION</th>
                        <th>ACTOR & ROLE</th>
                        <th>REASON / MODERATOR NOTES</th>
                        <th>TIME & RETENTION</th>
                        <th>DETAILS</th>
                      </tr>
                    </thead>
                    <tbody key={`${auditActionFilter}-${auditPage}`} className="neo-table-body-transition">
                      {isLoadingAudit ? (
                        <tr>
                          <td colSpan={7} style={{ textAlign: 'center', padding: '48px 20px', color: '#64748b' }}>
                            <div className="neo-audit-loading-spinner" />
                            <p style={{ margin: '10px 0 0', fontSize: '13px' }}>Loading governance audit trail...</p>
                          </td>
                        </tr>
                      ) : auditError ? (
                        <tr>
                          <td colSpan={7} style={{ textAlign: 'center', padding: '48px 20px', color: '#EF4444' }}>
                            <AlertCircle size={32} color="#EF4444" style={{ margin: '0 auto 8px', display: 'block' }} />
                            <strong style={{ color: '#0F172A', fontSize: '14px' }}>Failed to load audit trail</strong>
                            <p style={{ margin: '4px 0 0', fontSize: '12px', color: '#64748B' }}>
                              {auditError}
                            </p>
                          </td>
                        </tr>
                      ) : auditLogsList.length === 0 ? (
                        <tr>
                          <td colSpan={7} style={{ textAlign: 'center', padding: '48px 20px', color: '#94a3b8' }}>
                            <History size={32} color="#94a3b8" style={{ margin: '0 auto 8px', display: 'block' }} />
                            <strong style={{ color: '#0f172a', fontSize: '14px' }}>No audit records found</strong>
                            <p style={{ margin: '4px 0 0', fontSize: '12px' }}>
                              {auditSearchQuery || auditActionFilter !== 'ALL'
                                ? 'Try clearing or adjusting your search criteria.'
                                : 'Review items in the Queue or adjust settings to generate audit events.'}
                            </p>
                          </td>
                        </tr>
                      ) : (
                        auditLogsList.map((item) => {
                          const actionBadge = getAuditActionBadge(item.action)
                          const ttlStr = formatDaysRemaining(item.expires_at, retentionDays)

                          return (
                            <tr key={item.id}>
                              <td>
                                <span className={`neo-audit-action-pill ${actionBadge.badgeClass}`}>
                                  {actionBadge.label}
                                </span>
                              </td>
                              <td>
                                <div className="neo-target-cell">
                                  <div className="neo-target-icon-circle">
                                    <Globe size={14} color="#64748b" aria-hidden="true" />
                                  </div>
                                  <div className="neo-target-info">
                                    <span
                                      className="neo-target-domain"
                                      title={item.target_indicator || 'System/Policy'}
                                    >
                                      {item.target_indicator?.startsWith('policy.') || item.target_indicator?.startsWith('engine.')
                                        ? `Policy: ${item.target_indicator.replace(/^(policy|engine)\./, '')}`
                                        : item.target_indicator
                                          ? formatCleanIndicator(item.target_indicator)
                                          : 'Citizen Submission'}
                                    </span>
                                    <span className="neo-target-type">
                                      {item.target_indicator?.startsWith('policy.') || item.target_indicator?.startsWith('engine.')
                                        ? 'Engine Policy'
                                        : item.target_indicator?.startsWith('Report #')
                                          ? 'Citizen Report'
                                          : item.target_indicator?.startsWith('hxxp')
                                            ? 'Phishing URL'
                                            : item.target_indicator?.includes('[.]') || item.target_indicator?.includes('.')
                                              ? 'Threat Domain'
                                              : 'Threat Indicator'}
                                    </span>
                                  </div>
                                </div>
                              </td>
                              <td>
                                <span className={`neo-pill-badge ${getAuditCategoryBadgeClass(item.threat_category, item.action)}`}>
                                  {item.threat_category || (item.action === 'APPROVE' ? 'Confirmed Threat' : item.action === 'REJECT' ? 'False Alarm' : 'Policy Event')}
                                </span>
                              </td>
                              <td>
                                <div className="neo-actor-cell">
                                  <span className="neo-actor-email" title={item.actor_email || 'Verified Moderator'}>
                                    {item.actor_email || 'moderator@trustlens.lk'}
                                  </span>
                                  <span className="neo-actor-role-pill">
                                    {item.actor_role}
                                  </span>
                                </div>
                              </td>
                              <td style={{ maxWidth: '300px' }}>
                                {item.moderator_notes ? (
                                  <span className="neo-modern-excerpt" title={item.moderator_notes}>
                                    "{item.moderator_notes.length > 60
                                      ? item.moderator_notes.slice(0, 60) + '...'
                                      : item.moderator_notes}"
                                  </span>
                                ) : (
                                  <span className="neo-empty-excerpt">No notes supplied</span>
                                )}
                              </td>
                              <td>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '12px', color: '#64748B' }}>
                                    <Clock size={12} aria-hidden="true" />
                                    <span>{formatRelativeTime(item.created_at)}</span>
                                  </div>
                                  <span className="neo-audit-ttl-tag" title={`Auto-purges based on ${retentionDays}-day retention policy (${item.expires_at ? new Date(item.expires_at).toLocaleDateString() : 'Active'})`}>
                                    {ttlStr}
                                  </span>
                                </div>
                              </td>
                              <td>
                                <button
                                  type="button"
                                  className="neo-btn-audit-inspect"
                                  onClick={() => setSelectedAuditDetail(item)}
                                  title="Inspect full audit record"
                                >
                                  <Info size={13} aria-hidden="true" />
                                  <span>Inspect</span>
                                </button>
                              </td>
                            </tr>
                          )
                        })
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Modern Audit Pagination Bar */}
                {auditTotal > 0 && (
                  <div className="neo-pagination-bar">
                    <div className="neo-pagination-info">
                      <span>
                        Showing <strong>{(auditPage - 1) * auditPageSize + 1}</strong> to{' '}
                        <strong>{Math.min(auditPage * auditPageSize, auditTotal)}</strong> of{' '}
                        <strong>{auditTotal}</strong> audit records
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

          {/* ========================================================================= */}
          {/* VIEW 4: VERIFIED INTELLIGENCE MANAGEMENT TAB                             */}
          {/* ========================================================================= */}
          {activeNav === 'INTELLIGENCE' && (
            <section key="INTELLIGENCE" className="neo-queue-view-layout neo-view-transition" aria-label="Verified Intelligence Management">
              {/* Top 4 Stat Metric Cards (Modern Light Aesthetic) */}
              <div className="neo-intel-metrics-row">
                <div className="neo-intel-stat-card">
                  <div className="neo-intel-stat-top">
                    <div className="neo-intel-icon-circle blue">
                      <ShieldCheck size={18} aria-hidden="true" />
                    </div>
                    <span className="neo-intel-stat-label">Total Indicators</span>
                  </div>
                  <div className="neo-intel-stat-value">{intelTotal}</div>
                  <span className="neo-intel-stat-sub">Active community registry</span>
                </div>

                <div className="neo-intel-stat-card">
                  <div className="neo-intel-stat-top">
                    <div className="neo-intel-icon-circle red">
                      <ShieldAlert size={18} aria-hidden="true" />
                    </div>
                    <span className="neo-intel-stat-label">Confirmed Threats</span>
                  </div>
                  <div className="neo-intel-stat-value">
                    {intelligenceList.filter((i) => i.risk_level === 'CONFIRMED_SCAM' && i.active).length}
                  </div>
                  <span className="neo-intel-stat-sub red">Blocking scams & phishing</span>
                </div>

                <div className="neo-intel-stat-card">
                  <div className="neo-intel-stat-top">
                    <div className="neo-intel-icon-circle green">
                      <CheckCircle2 size={18} aria-hidden="true" />
                    </div>
                    <span className="neo-intel-stat-label">Verified Safe</span>
                  </div>
                  <div className="neo-intel-stat-value">
                    {intelligenceList.filter((i) => i.risk_level === 'VERIFIED_SAFE' && i.active).length}
                  </div>
                  <span className="neo-intel-stat-sub green">Whitelisted official domains</span>
                </div>

                <div className="neo-intel-stat-card">
                  <div className="neo-intel-stat-top">
                    <div className="neo-intel-icon-circle slate">
                      <Power size={18} aria-hidden="true" />
                    </div>
                    <span className="neo-intel-stat-label">Retired Indicators</span>
                  </div>
                  <div className="neo-intel-stat-value">
                    {intelligenceList.filter((i) => !i.active).length}
                  </div>
                  <span className="neo-intel-stat-sub">Archived / inactive</span>
                </div>
              </div>

              {/* Intelligence Table Card */}
              <div className="neo-modern-table-card">
                <div className="neo-modern-toolbar">
                  {/* Search Box */}
                  <div className="neo-toolbar-search-box">
                    <Search size={14} className="neo-search-icon-inside" aria-hidden="true" />
                    <input
                      type="text"
                      value={intelSearchQuery}
                      onChange={(e) => {
                        setIntelSearchQuery(e.target.value)
                        setIntelPage(1)
                      }}
                      placeholder="Search indicator, category, notes..."
                      className="neo-modern-search-input"
                    />
                  </div>

                  {/* Filter Selects */}
                  <div className="neo-modern-toolbar-actions">
                    {/* Status Filter */}
                    <NeoFilterDropdown
                      label="Status"
                      icon={<Power size={13} aria-hidden="true" />}
                      value={intelStatusFilter}
                      onChange={(val) => {
                        setIntelStatusFilter(val)
                        setIntelPage(1)
                      }}
                      options={[
                        { value: 'all', label: 'All Status' },
                        { value: 'active', label: 'Active Only', dotColor: '#10B981' },
                        { value: 'retired', label: 'Retired Only', dotColor: '#94A3B8' },
                      ]}
                      title="Filter by status"
                    />

                    {/* Indicator Type Filter */}
                    <NeoFilterDropdown
                      label="Type"
                      icon={<Layers size={13} aria-hidden="true" />}
                      value={intelTypeFilter}
                      onChange={(val) => {
                        setIntelTypeFilter(val)
                        setIntelPage(1)
                      }}
                      options={[
                        { value: 'all', label: 'All Types' },
                        { value: 'domain', label: 'Domain' },
                        { value: 'url', label: 'URL' },
                        { value: 'content_hash', label: 'Content Hash' },
                        { value: 'phone', label: 'Phone' },
                      ]}
                      title="Filter by indicator type"
                    />

                    {/* Risk Filter */}
                    <NeoFilterDropdown
                      label="Risk"
                      icon={<ShieldCheck size={13} aria-hidden="true" />}
                      value={intelRiskFilter}
                      onChange={(val) => {
                        setIntelRiskFilter(val)
                        setIntelPage(1)
                      }}
                      options={[
                        { value: 'all', label: 'All Risk' },
                        { value: 'CONFIRMED_SCAM', label: 'Confirmed Threat', dotColor: '#EF4444' },
                        { value: 'VERIFIED_SAFE', label: 'Verified Safe', dotColor: '#10B981' },
                      ]}
                      title="Filter by risk level"
                    />

                    <button
                      type="button"
                      className="neo-btn-toolbar-reset"
                      onClick={() => void loadIntelligence(true)}
                      disabled={isLoadingIntel}
                      title="Refresh intelligence feed"
                    >
                      <RefreshCw size={12} className={isLoadingIntel ? 'neo-spin' : ''} aria-hidden="true" />
                      <span>Refresh</span>
                    </button>
                  </div>
                </div>

                {intelError && (
                  <div className="neo-modern-error-banner" role="alert" style={{ marginBottom: '16px' }}>
                    <AlertCircle size={14} aria-hidden="true" />
                    <span>{intelError}</span>
                  </div>
                )}

                {/* Modern Table Container */}
                <div className="neo-modern-table-wrapper">
                  <table className="neo-modern-table">
                    <thead>
                      <tr>
                        <th>INDICATOR</th>
                        <th>TYPE</th>
                        <th>RISK LEVEL</th>
                        <th>CONFIDENCE</th>
                        <th>STATUS</th>
                        <th>DATE ADDED</th>
                        <th>ACTIONS</th>
                      </tr>
                    </thead>
                    <tbody key={`${intelStatusFilter}-${intelTypeFilter}-${intelRiskFilter}-${intelPage}`} className="neo-table-body-transition">
                      {isLoadingIntel ? (
                        <tr>
                          <td colSpan={7} style={{ textAlign: 'center', padding: '48px 20px', color: '#64748B' }}>
                            <RefreshCw size={24} className="neo-spin" style={{ margin: '0 auto 8px', display: 'block', color: '#0066FF' }} />
                            <strong style={{ color: '#0F172A', fontSize: '14px' }}>Loading verified threat intelligence...</strong>
                          </td>
                        </tr>
                      ) : intelligenceList.length === 0 ? (
                        <tr>
                          <td colSpan={7} style={{ textAlign: 'center', padding: '48px 20px', color: '#64748B' }}>
                            <ShieldCheck size={32} color="#0066FF" style={{ margin: '0 auto 8px', display: 'block' }} />
                            <strong style={{ color: '#0F172A', fontSize: '14px' }}>No threat intelligence indicators found</strong>
                            <p style={{ margin: '4px 0 0', fontSize: '12px', color: '#94A3B8' }}>
                              Approved reports will automatically appear here as sanitized intelligence indicators.
                            </p>
                          </td>
                        </tr>
                      ) : (
                        intelligenceList.map((item) => {
                          const isSafe = item.risk_level === 'VERIFIED_SAFE'
                          const isHash = item.indicator_type === 'content_hash'
                          const isEditing = editingIntelId === item.id
                          const isCopied = copiedHashId === item.id

                          return (
                            <tr key={item.id} className={!item.active ? 'neo-row-retired' : ''}>
                              <td>
                                <div className="neo-target-cell">
                                  <div className="neo-target-icon-circle">
                                    {item.indicator_type === 'domain' || item.indicator_type === 'url' ? (
                                      <Globe size={14} color="#0066FF" aria-hidden="true" />
                                    ) : item.indicator_type === 'phone' ? (
                                      <Phone size={14} color="#0066FF" aria-hidden="true" />
                                    ) : (
                                      <Hash size={14} color="#0066FF" aria-hidden="true" />
                                    )}
                                  </div>

                                  <div className="neo-target-info">
                                    {isHash ? (
                                      <div className="neo-fingerprint-cell">
                                        <span className="neo-fingerprint-text" title={item.defanged_value}>
                                          {item.defanged_value.slice(0, 10)}...{item.defanged_value.slice(-8)}
                                        </span>
                                        <button
                                          type="button"
                                          className="neo-btn-copy-hash"
                                          onClick={() => handleCopyHash(item.id, item.defanged_value)}
                                          title="Copy full SHA-256 fingerprint"
                                        >
                                          {isCopied ? <Check size={11} color="#10B981" /> : <Copy size={11} />}
                                        </button>
                                      </div>
                                    ) : (
                                      <span
                                        className="neo-target-domain"
                                        title={`Defanged: ${item.defanged_value}`}
                                      >
                                        {item.defanged_value}
                                      </span>
                                    )}

                                    {/* Inline Note Display / Edit */}
                                    {isEditing ? (
                                      <div className="neo-inline-note-editor">
                                        <input
                                          type="text"
                                          value={editingIntelNoteText}
                                          onChange={(e) => setEditingIntelNoteText(e.target.value)}
                                          placeholder="Add moderator note or excerpt..."
                                          className="neo-input-edit-note"
                                          autoFocus
                                        />
                                        <div className="neo-edit-note-actions">
                                          <button
                                            type="button"
                                            className="neo-btn-save-note"
                                            onClick={() => void handleSaveNote(item)}
                                            disabled={isUpdatingIntel}
                                          >
                                            Save
                                          </button>
                                          <button
                                            type="button"
                                            className="neo-btn-cancel-note"
                                            onClick={handleCancelEditNote}
                                          >
                                            Cancel
                                          </button>
                                        </div>
                                      </div>
                                    ) : (
                                      <div className="neo-intel-note-row">
                                        <span className="neo-intel-note-text" title={item.notes || 'No note attached'}>
                                          {item.notes ? item.notes : <em style={{ color: '#94a3b8' }}>No note attached</em>}
                                        </span>
                                        <button
                                          type="button"
                                          className="neo-btn-edit-note"
                                          onClick={() => handleStartEditNote(item)}
                                          title="Edit moderator note"
                                        >
                                          <Pencil size={10} aria-hidden="true" />
                                        </button>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              </td>

                              <td>
                                <span className="neo-type-badge">
                                  {item.indicator_type.toUpperCase()}
                                </span>
                              </td>

                              <td>
                                <div className="neo-risk-cell">
                                  <span className={`neo-risk-bullet ${isSafe ? 'low' : 'high'}`}>●</span>
                                  <span className={`neo-risk-text ${isSafe ? 'low' : 'high'}`}>
                                    {isSafe ? 'VERIFIED SAFE' : 'CONFIRMED SCAM'}
                                  </span>
                                </div>
                              </td>

                              <td>
                                <div className="neo-confidence-wrapper">
                                  <div
                                    className="neo-confidence-bar"
                                    style={{
                                      width: `${Math.round(item.confidence * 100)}%`,
                                      background: isSafe ? '#10B981' : '#EF4444',
                                    }}
                                  />
                                  <span>{Math.round(item.confidence * 100)}%</span>
                                </div>
                              </td>

                              <td>
                                <span className={`neo-status-pill-modern ${item.active ? 'approved' : 'rejected'}`}>
                                  {item.active ? 'ACTIVE' : 'RETIRED'}
                                </span>
                              </td>

                              <td style={{ fontSize: '12px', color: '#64748B' }}>
                                {formatRelativeTime(item.created_at)}
                              </td>

                              <td>
                                {item.active ? (
                                  <button
                                    type="button"
                                    className="neo-btn-retire-intel"
                                    onClick={() => handleToggleIntelStatus(item, false)}
                                    disabled={isUpdatingIntel}
                                    title="Retire this indicator from active threat matching"
                                  >
                                    <Power size={12} aria-hidden="true" />
                                    <span>Retire</span>
                                  </button>
                                ) : (
                                  <button
                                    type="button"
                                    className="neo-btn-reactivate-intel"
                                    onClick={() => handleToggleIntelStatus(item, true)}
                                    disabled={isUpdatingIntel}
                                    title="Reactivate this indicator in active threat matching"
                                  >
                                    <RefreshCw size={12} aria-hidden="true" />
                                    <span>Reactivate</span>
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

                {/* Pagination Controls */}
                {intelTotal > 0 && (
                  <div className="neo-pagination-bar">
                    <div className="neo-pagination-info">
                      <span>
                        Showing <strong>{(intelPage - 1) * intelPageSize + 1}</strong> to{' '}
                        <strong>{Math.min(intelPage * intelPageSize, intelTotal)}</strong> of{' '}
                        <strong>{intelTotal}</strong> indicators
                      </span>
                      <div className="neo-page-size-selector">
                        <label htmlFor="intel-page-size">Per page:</label>
                        <select
                          id="intel-page-size"
                          value={intelPageSize}
                          onChange={(e) => {
                            setIntelPageSize(Number(e.target.value))
                            setIntelPage(1)
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
                        disabled={intelPage <= 1}
                        onClick={() => setIntelPage(1)}
                        title="First Page"
                      >
                        «
                      </button>
                      <button
                        type="button"
                        className="neo-btn-page-nav"
                        disabled={intelPage <= 1}
                        onClick={() => setIntelPage((p) => Math.max(1, p - 1))}
                        title="Previous Page"
                      >
                        ‹ Prev
                      </button>

                      {renderPaginationNumbers(intelPage, intelTotalPages, setIntelPage)}

                      <button
                        type="button"
                        className="neo-btn-page-nav"
                        disabled={intelPage >= intelTotalPages}
                        onClick={() => setIntelPage((p) => Math.min(intelTotalPages, p + 1))}
                        title="Next Page"
                      >
                        Next ›
                      </button>
                      <button
                        type="button"
                        className="neo-btn-page-nav"
                        disabled={intelPage >= intelTotalPages}
                        onClick={() => setIntelPage(intelTotalPages)}
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

      {/* ── Review Decision Modal (Consensus, Classification & Sanitization) ── */}
      <ReviewDecisionModal
        isOpen={Boolean(reviewModalReport)}
        report={reviewModalReport}
        onClose={() => setReviewModalReport(null)}
        onApprove={handleModalApprove}
        onReject={handleModalReject}
        isProcessing={isProcessingReview}
      />

      {/* ── Audit Detail Modal (Deep Record Inspection) ── */}
      <AuditDetailModal
        isOpen={Boolean(selectedAuditDetail)}
        auditLog={selectedAuditDetail}
        onClose={() => setSelectedAuditDetail(null)}
      />
    </div>
  )
}

export default ModeratorDashboard

import React, { useCallback, useEffect, useState } from 'react'
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  AlertOctagon,
  Search,
  Clock,
  CheckCircle2,
  RefreshCw,
  LogOut,
  ArrowLeft,
  X,
  XCircle,
  Fingerprint,
  Globe,
  Sparkles,
  MessageSquareText,
  User,
} from 'lucide-react'
import {
  type ModerationQueueItem,
  type ModeratorUser,
  clearSession,
  fetchModerationQueue,
  getStoredSession,
  loginModerator,
  reviewModerationItem,
  seedDemoReports,
} from '../services/moderatorService'
import { defangIndicator } from '../services/reportingService'
import { formatRelativeTime } from '../utils/formatTime'
import './ModeratorDashboard.css'

export interface ModeratorDashboardProps {
  onBackToScanner: () => void
}

const CATEGORIES = [
  'Banking Phishing',
  'Job Scam',
  'Gov Impersonation',
  'Lottery / Prize Fraud',
  'OTP Theft',
  'Malicious Link / APK',
  'Telecom / Utility Bill Scam',
  'False Alarm',
]

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

export const ModeratorDashboard: React.FC<ModeratorDashboardProps> = ({ onBackToScanner }) => {
  const [token, setToken] = useState<string | null>(() => getStoredSession().token)
  const [user, setUser] = useState<ModeratorUser | null>(() => getStoredSession().user)

  // Auth Form State
  const [loginEmail, setLoginEmail] = useState('moderator@trustlens.lk')
  const [loginPassword, setLoginPassword] = useState('')
  const [loginLoading, setLoginLoading] = useState(false)
  const [loginError, setLoginError] = useState<string | null>(null)

  // Queue State
  const [reports, setReports] = useState<ModerationQueueItem[]>([])
  const [activeTab, setActiveTab] = useState<'PENDING' | 'APPROVED' | 'REJECTED' | 'ALL'>('PENDING')
  const [isLoadingQueue, setIsLoadingQueue] = useState(false)
  const [queueError, setQueueError] = useState<string | null>(null)

  // Active Review State
  const [activeReviewId, setActiveReviewId] = useState<string | null>(null)
  const [reviewCategory, setReviewCategory] = useState<string>('Banking Phishing')
  const [reviewIndicatorType, setReviewIndicatorType] = useState<'domain' | 'content_hash' | 'url'>('domain')
  const [reviewNotes, setReviewNotes] = useState<string>('')
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
    setReports([])
  }, [])

  const loadQueue = useCallback(
    async (showSpinner = false) => {
      if (!token) return
      if (showSpinner) setIsLoadingQueue(true)
      setQueueError(null)
      const res = await fetchModerationQueue(token, activeTab)
      setIsLoadingQueue(false)
      if (res.success && res.reports) {
        setReports(res.reports)
      } else {
        setQueueError(res.error || 'Could not load queue.')
        if (res.error?.includes('expired') || res.error?.includes('Unauthorized')) {
          handleSignOut()
        }
      }
    },
    [token, activeTab, handleSignOut]
  )

  // Load queue asynchronously whenever token or activeTab changes
  useEffect(() => {
    let active = true
    if (!token) return

    fetchModerationQueue(token, activeTab)
      .then((res) => {
        if (!active) return
        if (res.success && res.reports) {
          setReports(res.reports)
        } else {
          setQueueError(res.error || 'Could not load queue.')
          if (res.error?.includes('expired') || res.error?.includes('Unauthorized')) {
            handleSignOut()
          }
        }
      })
      .catch((err) => {
        if (!active) return
        setQueueError(err instanceof Error ? err.message : 'Network error loading queue')
      })

    return () => {
      active = false
    }
  }, [token, activeTab, handleSignOut])

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoginLoading(true)
    setLoginError(null)

    const res = await loginModerator(loginEmail.trim(), loginPassword)
    setLoginLoading(false)

    if (res.success && res.token && res.user) {
      setToken(res.token)
      setUser(res.user)
      showToast(`Welcome, ${res.user.email} (Role: ${res.user.role})`)
    } else {
      setLoginError(res.error || 'Invalid credentials or missing moderator privileges.')
    }
  }

  const handleApprove = async (report: ModerationQueueItem) => {
    if (!token) return
    setIsProcessingReview(true)
    const res = await reviewModerationItem(token, {
      reportId: report.id,
      action: 'APPROVE',
      category: reviewCategory,
      indicatorType: report.reported_domain ? reviewIndicatorType : 'content_hash',
      notes: reviewNotes.trim() || 'Approved by moderator and sanitized for threat intelligence.',
    })
    setIsProcessingReview(false)

    if (res.success) {
      showToast(`Report ${report.id.slice(0, 8)} approved and published to verified intelligence.`)
      setActiveReviewId(null)
      setReviewNotes('')
      void loadQueue()
    } else {
      showToast(`Approval failed: ${res.error}`)
    }
  }

  const handleReject = async (report: ModerationQueueItem) => {
    if (!token) return
    if (!window.confirm('Reject this report without publishing threat intelligence?')) return
    setIsProcessingReview(true)
    const res = await reviewModerationItem(token, {
      reportId: report.id,
      action: 'REJECT',
      notes: 'Dismissed by moderator as unverified or insufficient evidence.',
    })
    setIsProcessingReview(false)

    if (res.success) {
      showToast(`Report ${report.id.slice(0, 8)} marked as rejected.`)
      setActiveReviewId(null)
      void loadQueue()
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
      showToast(`✓ Seeded ${res.count ?? 3} realistic Sri Lankan scam reports for demonstration.`)
      void loadQueue(true)
    } else {
      showToast(`Seed failed: ${res.error}`)
    }
  }

  // Render Login Card if not authenticated
  if (!token || !user) {
    return (
      <div className="mod-login-wrap">
        <div className="mod-login-card">
          <div className="mod-login-header">
            <div className="mod-login-icon" aria-hidden="true">
              <Shield size={28} color="#087f8c" />
            </div>
            <h2>Moderator Portal</h2>
            <p>Role-verified dashboard for reviewing threat intelligence submissions.</p>
          </div>

          {loginError && (
            <div className="error-banner" role="alert">
              {loginError}
            </div>
          )}

          <div className="demo-credentials-hint">
            <span>Evaluation Account:</span>
            <code>moderator@trustlens.lk</code>
          </div>

          <form onSubmit={handleLogin} className="mod-login-form">
            <div className="form-group">
              <label htmlFor="mod-email">Moderator Email</label>
              <input
                id="mod-email"
                type="email"
                required
                value={loginEmail}
                onChange={(e) => setLoginEmail(e.target.value)}
                placeholder="moderator@trustlens.lk"
              />
            </div>

            <div className="form-group">
              <label htmlFor="mod-password">Password</label>
              <input
                id="mod-password"
                type="password"
                required
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
                placeholder="••••••••••••"
                autoFocus
              />
            </div>

            <button
              type="submit"
              className="btn-primary"
              disabled={loginLoading || !loginPassword}
              style={{ width: '100%', justifyContent: 'center', marginTop: '6px' }}
            >
              {loginLoading ? (
                <>
                  <span className="spinner" />
                  <span>Verifying RBAC Session...</span>
                </>
              ) : (
                'Sign In to Moderation Queue'
              )}
            </button>

            <button
              type="button"
              className="btn-secondary"
              onClick={onBackToScanner}
              style={{ width: '100%', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
            >
              <ArrowLeft size={14} aria-hidden="true" />
              <span>Back to Public Scanner</span>
            </button>
          </form>
        </div>
      </div>
    )
  }

  // Metrics calculations
  const pendingCount = reports.filter((r) => r.status === 'PENDING').length
  const suspiciousCount = reports.filter((r) => r.report_type === 'suspicious').length
  const falsePositiveCount = reports.filter((r) => r.report_type === 'false_positive').length

  return (
    <div className="mod-dashboard-container">
      {/* Toast Notification */}
      {toastMessage && <div className="mod-toast">{toastMessage}</div>}

      {/* Header Bar */}
      <div className="dashboard-header-bar">
        <div className="dashboard-title-group">
          <h2>
            <span>TrustLens LK Moderation Queue</span>
            <span className="badge-moderator-role" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
              <ShieldCheck size={13} aria-hidden="true" />
              <span>Verified {user.role}</span>
            </span>
          </h2>
          <p>Review community fraud reports, defang indicators, and publish verified intelligence.</p>
        </div>

        <div className="mod-user-controls">
          <span className="mod-email-pill">{user.email}</span>
          <button
            type="button"
            className="btn-signout"
            onClick={handleSignOut}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}
          >
            <LogOut size={13} aria-hidden="true" />
            <span>Sign Out</span>
          </button>
          <button
            type="button"
            className="btn-secondary"
            onClick={onBackToScanner}
            style={{ padding: '6px 12px', display: 'inline-flex', alignItems: 'center', gap: '5px' }}
          >
            <ArrowLeft size={13} aria-hidden="true" />
            <span>Public Scanner</span>
          </button>
        </div>
      </div>

      {/* Summary Metrics Bar */}
      <div className="metrics-row">
        <div className="metric-card">
          <div className="metric-icon pending" aria-hidden="true">
            <Clock size={20} color="#b7791f" />
          </div>
          <div className="metric-info">
            <h3>{activeTab === 'PENDING' ? reports.length : pendingCount}</h3>
            <span>Pending Review</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon intel" aria-hidden="true">
            <AlertOctagon size={20} color="#087f8c" />
          </div>
          <div className="metric-info">
            <h3>{suspiciousCount}</h3>
            <span>Reported Threats</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon shield" aria-hidden="true">
            <AlertTriangle size={20} color="#486581" />
          </div>
          <div className="metric-info">
            <h3>{falsePositiveCount}</h3>
            <span>False Alarm Disputes</span>
          </div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="filter-toolbar">
        <div className="status-tabs" role="tablist">
          {(['PENDING', 'APPROVED', 'REJECTED', 'ALL'] as const).map((tab) => (
            <button
              key={tab}
              role="tab"
              aria-selected={activeTab === tab}
              className={`status-tab-btn ${activeTab === tab ? 'active' : ''}`}
              onClick={() => setActiveTab(tab)}
            >
              {tab === 'PENDING'
                ? 'Pending Review'
                : tab === 'APPROVED'
                ? 'Approved Intel'
                : tab === 'REJECTED'
                ? 'Rejected'
                : 'All Reports'}
            </button>
          ))}
        </div>

        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <button
            type="button"
            className="btn-refresh"
            onClick={() => void handleSeedDemo()}
            disabled={isSeeding || isLoadingQueue}
            title="Populate realistic Sri Lankan threat reports for evaluation"
            style={{ background: '#f7fbfa', borderColor: '#b7e3e5', color: '#075e69' }}
          >
            {isSeeding ? (
              <span className="spinner" style={{ borderColor: '#087f8c transparent' }} />
            ) : (
              <Sparkles size={13} aria-hidden="true" color="#087f8c" />
            )}
            <span>Seed Demo Fixtures</span>
          </button>

          <button
            type="button"
            className="btn-refresh"
            onClick={() => void loadQueue(true)}
            disabled={isLoadingQueue}
          >
            {isLoadingQueue ? (
              <span className="spinner" style={{ borderColor: '#087f8c transparent' }} />
            ) : (
              <RefreshCw size={13} aria-hidden="true" />
            )}
            <span>Refresh Queue</span>
          </button>
        </div>
      </div>

      {queueError && (
        <div className="error-banner" role="alert">
          {queueError}
        </div>
      )}

      {/* Queue Items */}
      {reports.length === 0 && !isLoadingQueue ? (
        <div className="empty-queue-state">
          <div className="empty-icon" aria-hidden="true">
            <CheckCircle2 size={42} color="#087f8c" />
          </div>
          <h3>Queue is all clear</h3>
          <p>No reports currently matching the "{activeTab}" filter.</p>
        </div>
      ) : (
        <div className="queue-list">
          {reports.map((item) => {
            const isReviewing = activeReviewId === item.id
            const parsed = parseReportNotes(item.notes)
            const messageExcerpt = item.raw_excerpt || parsed.excerpt

            return (
              <div key={item.id} className="queue-item-card">
                <div className="queue-item-header">
                  <div className="queue-item-meta">
                    <span className={`badge-report-type ${item.report_type}`} style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
                      {item.report_type === 'suspicious' ? (
                        <>
                          <ShieldAlert size={13} aria-hidden="true" />
                          <span>Reported Threat</span>
                        </>
                      ) : item.report_type === 'false_positive' ? (
                        <>
                          <AlertTriangle size={13} aria-hidden="true" />
                          <span>False Positive</span>
                        </>
                      ) : (
                        <>
                          <Search size={13} aria-hidden="true" />
                          <span>Evaded Detection</span>
                        </>
                      )}
                    </span>
                    <span
                      className="report-timestamp"
                      title={new Date(item.created_at).toLocaleString()}
                    >
                      {formatRelativeTime(item.created_at)}
                    </span>
                  </div>

                  <span className={`badge-status ${item.status}`}>{item.status}</span>
                </div>

                {/* Threat Indicators Box */}
                <div className="queue-indicators">
                  {item.reported_domain ? (
                    <div className="queue-indicator-row">
                      <strong style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                        <Globe size={13} aria-hidden="true" />
                        <span>Target Indicator:</span>
                      </strong>
                      <code style={{ color: '#a33d31', fontWeight: 600, fontSize: '13px' }}>
                        {defangIndicator(item.reported_domain)}
                      </code>
                    </div>
                  ) : (
                    <div className="queue-indicator-row" style={{ color: '#b7791f' }}>
                      <strong style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                        <AlertTriangle size={13} aria-hidden="true" />
                        <span>Target Indicator:</span>
                      </strong>
                      <span style={{ fontSize: '12px', fontStyle: 'italic' }}>
                        No specific URL or domain provided (Message-only threat)
                      </span>
                    </div>
                  )}

                  {messageExcerpt && (
                    <div className="queue-indicator-row" style={{ alignItems: 'flex-start' }}>
                      <strong style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', flexShrink: 0, marginTop: '3px' }}>
                        <MessageSquareText size={13} color="#087f8c" aria-hidden="true" />
                        <span>Message Text:</span>
                      </strong>
                      <div style={{ fontSize: '13px', color: '#102a43', background: '#f0f4f8', padding: '8px 12px', borderRadius: '6px', width: '100%', wordBreak: 'break-word', borderLeft: '3px solid #087f8c', fontStyle: 'italic', lineHeight: '1.4' }}>
                        "{messageExcerpt}"
                      </div>
                    </div>
                  )}

                  <div className="queue-indicator-row">
                    <strong style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      <Fingerprint size={12} aria-hidden="true" />
                      <span>Content SHA-256:</span>
                    </strong>
                    <code style={{ fontSize: '11px' }}>{item.content_sha256}</code>
                  </div>
                </div>

                {/* Submitter Notes */}
                {parsed.userNotes && (
                  <div className="queue-user-notes" style={{ display: 'flex', alignItems: 'flex-start', gap: '6px' }}>
                    <strong style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', flexShrink: 0 }}>
                      <User size={12} aria-hidden="true" />
                      <span>Submitter Context:</span>
                    </strong>
                    <span>{parsed.userNotes}</span>
                  </div>
                )}

                {/* Inline Approval Panel */}
                {isReviewing && (
                  <div className="approval-panel">
                    <div className="approval-panel-header">
                      <span>Publish to Verified Intelligence Shield</span>
                      <button
                        type="button"
                        className="modal-close-btn"
                        style={{ width: '24px', height: '24px', padding: 0 }}
                        onClick={() => setActiveReviewId(null)}
                      >
                        <X size={14} aria-hidden="true" />
                      </button>
                    </div>

                    <div className="approval-form-grid">
                      <div className="form-group">
                        <label>Threat Category</label>
                        <select
                          value={reviewCategory}
                          onChange={(e) => setReviewCategory(e.target.value)}
                        >
                          {CATEGORIES.map((c) => (
                            <option key={c} value={c}>
                              {c}
                            </option>
                          ))}
                        </select>
                      </div>

                      {item.reported_domain && (
                        <div className="form-group">
                          <label>Publish Indicator As</label>
                          <select
                            value={reviewIndicatorType}
                            onChange={(e) =>
                              setReviewIndicatorType(
                                e.target.value as 'domain' | 'content_hash' | 'url'
                              )
                            }
                          >
                            <option value="domain">Domain ({defangIndicator(item.reported_domain)})</option>
                            <option value="content_hash">Full Content Hash</option>
                          </select>
                        </div>
                      )}
                    </div>

                    <div className="form-group">
                      <label>Sanitized Moderator Notes (Audit Log)</label>
                      <input
                        type="text"
                        value={reviewNotes}
                        onChange={(e) => setReviewNotes(e.target.value)}
                        placeholder="e.g. Confirmed phishing campaign targeting Commercial Bank users."
                      />
                    </div>

                    <div className="approval-panel-actions">
                      <button
                        type="button"
                        className="btn-secondary"
                        onClick={() => setActiveReviewId(null)}
                        disabled={isProcessingReview}
                      >
                        Cancel
                      </button>
                      <button
                        type="button"
                        className="btn-action-approve"
                        onClick={() => handleApprove(item)}
                        disabled={isProcessingReview}
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                      >
                        {isProcessingReview ? (
                          <>
                            <span className="spinner" />
                            <span>Publishing...</span>
                          </>
                        ) : (
                          <>
                            <ShieldCheck size={14} aria-hidden="true" />
                            <span>Confirm & Publish Threat DNA</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                )}

                {/* Card Action Controls (only for PENDING) */}
                {item.status === 'PENDING' && !isReviewing && (
                  <div className="queue-actions-bar">
                    <button
                      type="button"
                      className="btn-action-reject"
                      onClick={() => handleReject(item)}
                      disabled={isProcessingReview}
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}
                    >
                      <XCircle size={14} aria-hidden="true" />
                      <span>Dismiss / Reject</span>
                    </button>
                    <button
                      type="button"
                      className="btn-action-approve"
                      onClick={() => {
                        setActiveReviewId(item.id)
                        if (item.reported_domain) {
                          setReviewIndicatorType('domain')
                        } else {
                          setReviewIndicatorType('content_hash')
                        }
                      }}
                      disabled={isProcessingReview}
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}
                    >
                      <ShieldCheck size={14} aria-hidden="true" />
                      <span>Approve & Publish Intel</span>
                    </button>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

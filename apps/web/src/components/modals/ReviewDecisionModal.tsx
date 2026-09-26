import React, { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  X,
  Globe,
  Building2,
  FileText,
  Clock,
  Fingerprint,
  Copy,
  Check,
  History,
  AlertTriangle,
  TrendingUp,
  Sparkles,
  Info,
} from 'lucide-react'
import type { ModerationQueueItem, IndicatorHistoryContext } from '../../services/moderatorService'
import { fetchIndicatorIntelligenceContext, getStoredSession } from '../../services/moderatorService'
import { defangIndicator } from '../../services/reportingService'
import { formatRelativeTime } from '../../utils/formatTime'
import './ModeratorModals.css'

export interface ReviewDecisionModalProps {
  isOpen: boolean
  report: ModerationQueueItem | null
  onClose: () => void
  onApprove: (
    report: ModerationQueueItem,
    category: string,
    indicatorType: 'domain' | 'content_hash' | 'url',
    notes: string,
    confidence?: number,
    overrideProtectedEntity?: boolean,
    incidentReason?: string
  ) => Promise<void>
  onReject: (report: ModerationQueueItem) => Promise<void>
  isProcessing: boolean
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

function classifyReportCategory(item: ModerationQueueItem): string {
  const parsed = parseReportNotes(item.notes)
  if (parsed.threatCategory) return parsed.threatCategory
  if (item.report_type === 'false_positive') return 'False Alarm'
  const text = `${item.reported_domain || ''} ${item.notes || ''} ${item.raw_excerpt || ''}`.toLowerCase()
  if (/bank|banking|financial|account|card|debit|credit|fund/.test(text)) return 'Banking Phishing'
  if (/electricity|utility|water|bill|telecom|carrier|provider/.test(text)) return 'Telecom / Utility Bill Scam'
  if (/job|earn|part-time|salary|advance|bonus|hiring/.test(text)) return 'Job Scam'
  if (/lottery|prize|won|lucky|cash|gift|reward/.test(text)) return 'Lottery / Prize Fraud'
  if (/otp|code|pin|password|credential|security/.test(text)) return 'OTP Theft'
  if (/\.apk|download|install|app/.test(text)) return 'Malicious Link / APK'
  return 'Banking Phishing'
}

export const ReviewDecisionModal: React.FC<ReviewDecisionModalProps> = ({
  isOpen,
  report,
  onClose,
  onApprove,
  onReject,
  isProcessing,
}) => {
  const [category, setCategory] = useState('Banking Phishing')
  const [indicatorType, setIndicatorType] = useState<'domain' | 'content_hash' | 'url'>('domain')
  const [confidence, setConfidence] = useState<number>(1.0)
  const [notes, setNotes] = useState('')
  const [copiedExcerpt, setCopiedExcerpt] = useState(false)
  const [copiedHash, setCopiedHash] = useState(false)
  const [copiedId, setCopiedId] = useState(false)
  const [overrideProtectedEntity, setOverrideProtectedEntity] = useState(false)
  const [incidentReason, setIncidentReason] = useState('')
  const [guardrailError, setGuardrailError] = useState<string | null>(null)
  const [intelContext, setIntelContext] = useState<IndicatorHistoryContext | null>(null)
  const [loadingContext, setLoadingContext] = useState(false)
  const [confirmRevocation, setConfirmRevocation] = useState(false)

  // Sync category and fetch intelligence context when report changes
  useEffect(() => {
    if (report) {
      setCategory(classifyReportCategory(report))
      setIndicatorType(report.reported_domain ? 'domain' : 'content_hash')
      setConfidence(1.0)
      setNotes('')
      setCopiedExcerpt(false)
      setCopiedHash(false)
      setCopiedId(false)
      setOverrideProtectedEntity(false)
      setIncidentReason('')
      setGuardrailError(null)
      setConfirmRevocation(false)
    }
  }, [report])

  // Fetch intelligence context & historical decisions whenever modal opens for a report
  useEffect(() => {
    let isMounted = true
    if (isOpen && report?.id) {
      const session = getStoredSession()
      if (session.token) {
        setLoadingContext(true)
        fetchIndicatorIntelligenceContext(session.token, report.id)
          .then((res) => {
            if (isMounted && res.success && res.context) {
              setIntelContext(res.context)
            }
          })
          .catch(() => {})
          .finally(() => {
            if (isMounted) setLoadingContext(false)
          })
      }
    } else {
      setIntelContext(null)
      setConfirmRevocation(false)
    }
    return () => {
      isMounted = false
    }
  }, [isOpen, report?.id])

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !isProcessing) onClose()
    }
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown)
    }
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, isProcessing, onClose])

  // Prevent background page from scrolling when modal is open
  useEffect(() => {
    if (isOpen) {
      const originalOverflow = document.body.style.overflow
      document.body.style.overflow = 'hidden'
      return () => {
        document.body.style.overflow = originalOverflow
      }
    }
  }, [isOpen])

  if (!isOpen || !report) return null

  const parsed = parseReportNotes(report.notes)
  const excerpt = report.raw_excerpt || parsed.excerpt
  const isPending = report.status === 'PENDING'
  const isApproved = report.status === 'APPROVED'
  const isRejected = report.status === 'REJECTED'

  const wordCount = excerpt ? excerpt.trim().split(/\s+/).filter(Boolean).length : 0
  const charCount = excerpt ? excerpt.length : 0

  const handleCopyExcerpt = () => {
    if (!excerpt) return
    navigator.clipboard.writeText(excerpt)
    setCopiedExcerpt(true)
    setTimeout(() => setCopiedExcerpt(false), 2000)
  }

  const handleCopyHash = () => {
    navigator.clipboard.writeText(report.content_sha256)
    setCopiedHash(true)
    setTimeout(() => setCopiedHash(false), 2000)
  }

  const handleCopyId = () => {
    if (!report?.id) return
    navigator.clipboard.writeText(report.id)
    setCopiedId(true)
    setTimeout(() => setCopiedId(false), 2000)
  }

  return createPortal(
    <div className="neo-modal-backdrop" onClick={() => !isProcessing && onClose()} role="dialog" aria-modal="true">
      <div className="neo-modal-dialog decision-size" onClick={(e) => e.stopPropagation()}>
        {/* Modal Header */}
        <div className="neo-modal-header">
          <div className="neo-modal-header-left">
            <div className={`neo-modal-header-icon ${isApproved ? 'blue' : isRejected ? 'red' : 'blue'}`}>
              {isApproved ? (
                <ShieldCheck size={20} aria-hidden="true" />
              ) : isRejected ? (
                <ShieldAlert size={20} aria-hidden="true" />
              ) : (
                <ShieldCheck size={20} aria-hidden="true" />
              )}
            </div>
            <div>
              <h3 className="neo-modal-title">
                {isPending ? 'Moderator Review & Decision Deck' : 'Moderation Record Inspection'}
              </h3>
              <div className="neo-modal-subtitle">
                <button
                  type="button"
                  onClick={handleCopyId}
                  className="neo-report-id-copy-btn"
                  title={`Click to copy full Report ID: ${report.id}`}
                >
                  <span className="neo-report-id-label">Report ID:</span>
                  <span className="neo-report-id-code">{report.id.slice(0, 8)}...</span>
                  {copiedId ? (
                    <Check size={11} color="#10b981" />
                  ) : (
                    <Copy size={11} />
                  )}
                  {copiedId && <span className="neo-copied-text">Copied</span>}
                </button>
                <span>•</span>
                <Clock size={12} aria-hidden="true" />
                <span>Submitted {formatRelativeTime(report.created_at)}</span>
                <span>•</span>
                <span className={`neo-status-pill-modern ${report.status.toLowerCase()}`}>
                  {report.status}
                </span>
              </div>
            </div>
          </div>
          <button
            type="button"
            className="neo-modal-btn-close"
            onClick={() => !isProcessing && onClose()}
            disabled={isProcessing}
            title="Close dialog (Esc)"
          >
            <X size={16} aria-hidden="true" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="neo-modal-body">
          {/* Metadata & Evidence Header Card */}
          <div className="neo-modal-meta-grid">
            <div className="neo-modal-meta-item">
              <span className="neo-modal-meta-label">Target Indicator</span>
              <div className="neo-modal-meta-val">
                <Globe size={14} color="#0066FF" aria-hidden="true" />
                <span className={`neo-indicator-badge ${!report.reported_domain ? 'text-only' : ''}`}>
                  {report.reported_domain ? defangIndicator(report.reported_domain) : 'Message-only text'}
                </span>
              </div>
            </div>

            <div className="neo-modal-meta-item">
              <span className="neo-modal-meta-label">Citizen Intent & Classification</span>
              <div className="neo-modal-meta-val" style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                <span className={`neo-pill-badge ${report.report_type}`}>
                  {report.report_type === 'suspicious'
                    ? 'Unreported Threat'
                    : report.report_type === 'false_positive'
                      ? 'False Alarm'
                      : 'Evaded Detection'}
                </span>
                {parsed.threatCategory && (
                  <span style={{ background: '#EFF6FF', color: '#0066FF', border: '1px solid #BFDBFE', borderRadius: '5px', padding: '2px 7px', fontSize: '11px', fontWeight: 700 }}>
                    {parsed.threatCategory}
                  </span>
                )}
              </div>
            </div>

            <div className="neo-modal-meta-item full-width">
              <span className="neo-modal-meta-label">Cryptographic Fingerprint</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="neo-fingerprint-badge" style={{ fontFamily: 'monospace', fontSize: '11px', padding: '4px 10px' }}>
                  <Fingerprint size={12} style={{ display: 'inline', marginRight: '5px' }} />
                  {report.content_sha256}
                </span>
                <button
                  type="button"
                  onClick={handleCopyHash}
                  className="neo-modal-btn-copy"
                  title="Copy SHA-256 Fingerprint"
                >
                  {copiedHash ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                  <span>{copiedHash ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Protected Entity Guardrail Banner */}
          {report.protected_entity?.isProtected && (
            <div className={`neo-protected-entity-banner ${report.protected_entity.type === 'OFFICIAL_NATIONAL' ? 'national' : 'global'}`}>
              <div className="neo-protected-banner-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span className="neo-protected-badge-lg">
                    {report.protected_entity.type === 'OFFICIAL_NATIONAL' ? (
                      <Building2 size={13} strokeWidth={2.2} />
                    ) : (
                      <Globe size={13} strokeWidth={2.2} />
                    )}
                    <span>
                      {report.protected_entity.badge?.replace(/[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/gu, '').trim() ||
                        (report.protected_entity.type === 'OFFICIAL_NATIONAL' ? 'Official National Entity' : 'Top Global Platform')}
                    </span>
                  </span>
                  <span className="neo-protected-entity-title">
                    {report.protected_entity.name}
                  </span>
                </div>
                <span className="neo-protected-domain-pill">
                  {report.protected_entity.domain}
                </span>
              </div>

              <p className="neo-protected-warning-text">
                {report.protected_entity.warning}
              </p>

              <div className="neo-protected-recommendation-card">
                <div className="neo-recom-left">
                  <div className="neo-recom-tag-row">
                    <span className={`neo-recom-pill ${report.report_type === 'false_positive' ? 'safe' : 'reject'}`}>
                      {report.report_type === 'false_positive' ? (
                        <ShieldCheck size={12} strokeWidth={2.4} />
                      ) : (
                        <ShieldAlert size={12} strokeWidth={2.4} />
                      )}
                      <span>{report.report_type === 'false_positive' ? 'SAFE ACTION' : 'RECOMMENDED ACTION'}</span>
                    </span>
                  </div>
                  <p className="neo-recom-desc">
                    {report.report_type === 'false_positive'
                      ? 'Approving this report will mark this entity as VERIFIED_SAFE and protect it from false alarms.'
                      : 'Dismiss / Reject Report — Legitimate entity. Approving this domain as a malicious threat would cause widespread false positives.'}
                  </p>
                </div>
                {isPending && report.report_type !== 'false_positive' && (
                  <div className="neo-recom-right">
                    <button
                      type="button"
                      className="neo-btn-dismiss-recommended"
                      onClick={() => onReject(report)}
                      disabled={isProcessing}
                      title="Recommended action: Dismiss false report"
                    >
                      <ShieldCheck size={13} strokeWidth={2.2} />
                      <span>Dismiss as Legitimate Entity</span>
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Evidence Excerpt Box (Handles up to 10,000+ words gracefully) */}
          <div className="neo-modal-text-section">
            <div className="neo-modal-text-header">
              <div className="neo-modal-text-header-left">
                <FileText size={14} color="#0066FF" aria-hidden="true" />
                <span>Reported Evidence Payload</span>
                {excerpt && (
                  <span className="neo-modal-text-badge">
                    {wordCount} words • {charCount} chars
                  </span>
                )}
              </div>
              {excerpt && (
                <button
                  type="button"
                  className="neo-modal-btn-copy"
                  onClick={handleCopyExcerpt}
                  title="Copy full evidence payload"
                >
                  {copiedExcerpt ? (
                    <>
                      <Check size={12} color="#10b981" />
                      <span style={{ color: '#10b981' }}>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy size={12} />
                      <span>Copy Payload</span>
                    </>
                  )}
                </button>
              )}
            </div>
            {excerpt ? (
              <pre className="neo-modal-code-block">
                {excerpt}
              </pre>
            ) : (
              <div style={{ fontSize: '12.5px', color: '#94a3b8', fontStyle: 'italic', padding: '14px 16px', background: '#f8fafc', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
                No raw message excerpt attached to this report.
              </div>
            )}
            {parsed.userNotes && (
              <div className="neo-modal-notes-callout">
                <span className="neo-modal-notes-label">
                  <CheckCircle2 size={13} aria-hidden="true" />
                  <span>Submitter Context</span>
                </span>
                <p className="neo-modal-notes-text">{parsed.userNotes}</p>
              </div>
            )}
          </div>

          {/* Intelligence Radar & Historical Decisions Memory Card */}
          <div className="neo-intel-history-card">
            <div className="neo-intel-history-header">
              <div className="neo-intel-history-title-group">
                <div className="neo-intel-icon-wrapper">
                  <History size={15} strokeWidth={2.2} />
                </div>
                <div>
                  <h4 className="neo-intel-title">Intelligence Radar & Decision Memory</h4>
                  <p className="neo-intel-subtitle">Cross-referenced against verified national threat intelligence and moderator audit history</p>
                </div>
              </div>
              {loadingContext ? (
                <span className="neo-intel-loading-pill">
                  <span className="spinner-sm" />
                  <span>Inspecting...</span>
                </span>
              ) : (
                <span className="neo-intel-target-pill">
                  {intelContext?.targetIndicator ? defangIndicator(intelContext.targetIndicator) : (report.reported_domain ? defangIndicator(report.reported_domain) : 'Active Target')}
                </span>
              )}
            </div>

            <div className="neo-intel-history-body">
              {loadingContext ? (
                <div className="neo-intel-skeleton-grid" aria-busy="true" aria-label="Loading intelligence radar">
                  <div className="neo-intel-skeleton-box shimmer" />
                  <div className="neo-intel-skeleton-box shimmer" />
                </div>
              ) : (
                <div className="neo-intel-content-reveal">
                  {/* Active Intelligence Status & Decision Counts Grid */}
                  <div className="neo-intel-grid">
                    <div className="neo-intel-grid-col">
                      <span className="neo-intel-col-label">Active Intelligence Status</span>
                      <div className="neo-intel-status-row">
                        {intelContext?.hasActiveIntel && intelContext.activeIntel ? (
                          <div className={`neo-intel-status-chip ${intelContext.activeIntel.risk_level === 'CONFIRMED_SCAM' ? 'threat' : 'safe'}`}>
                            {intelContext.activeIntel.risk_level === 'CONFIRMED_SCAM' ? (
                              <ShieldAlert size={13} strokeWidth={2.2} />
                            ) : (
                              <ShieldCheck size={13} strokeWidth={2.2} />
                            )}
                            <span className="neo-intel-chip-text">
                              {intelContext.activeIntel.risk_level === 'CONFIRMED_SCAM' ? 'Confirmed Threat IoC' : 'Verified Legitimate Entity'}
                            </span>
                            <span className="neo-intel-chip-meta">
                              {(intelContext.activeIntel.confidence * 100).toFixed(0)}% Conf • {intelContext.activeIntel.report_count} Report{intelContext.activeIntel.report_count > 1 ? 's' : ''}
                            </span>
                          </div>
                        ) : (
                          <div className="neo-intel-status-chip clean">
                            <Sparkles size={13} strokeWidth={2.2} />
                            <span className="neo-intel-chip-text">Fresh Target Indicator</span>
                            <span className="neo-intel-chip-meta">No prior verified intelligence</span>
                          </div>
                        )}
                      </div>
                    </div>

                    <div className="neo-intel-grid-col">
                      <span className="neo-intel-col-label">Prior Decisions on this Indicator</span>
                      <div className="neo-intel-status-row">
                        {intelContext?.priorDecisions && intelContext.priorDecisions.totalPriorEvents > 0 ? (
                          <div className="neo-intel-history-pills">
                            {intelContext.priorDecisions.totalRejections > 0 && (
                              <span className="neo-intel-history-pill reject" title="Number of past rejected reports for this target">
                                {intelContext.priorDecisions.totalRejections} Rejected
                              </span>
                            )}
                            {intelContext.priorDecisions.totalApprovals > 0 && (
                              <span className="neo-intel-history-pill approve" title="Number of past approved reports for this target">
                                {intelContext.priorDecisions.totalApprovals} Approved
                              </span>
                            )}
                            {intelContext.priorDecisions.totalRetirements > 0 && (
                              <span className="neo-intel-history-pill retire" title="Number of past indicator retirements or reclassifications">
                                {intelContext.priorDecisions.totalRetirements} Retired
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="neo-intel-dim-text">No previous moderator decisions on file</span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Conflict Alert Box if Opposing Signals Exist */}
                  {intelContext?.isConflict && (
                    <div className="neo-intel-conflict-alert">
                      <div className="neo-intel-conflict-header">
                        <AlertTriangle size={15} color="#DC2626" strokeWidth={2.4} />
                        <span className="neo-intel-conflict-title">Intelligence Conflict Alert</span>
                      </div>
                      <p className="neo-intel-conflict-desc">{intelContext.conflictExplanation}</p>
                      <div className="neo-intel-conflict-consequence">
                        <Info size={13} color="#D97706" />
                        <span>{intelContext.revocationConsequence}</span>
                      </div>
                      {isPending && (
                        <label className="neo-intel-conflict-confirm-label">
                          <input
                            type="checkbox"
                            checked={confirmRevocation}
                            onChange={(e) => {
                              setConfirmRevocation(e.target.checked)
                              setGuardrailError(null)
                            }}
                          />
                          <span>I authorize revoking the opposing active intelligence record upon approval.</span>
                        </label>
                      )}
                    </div>
                  )}

                  {/* Corroboration Alert Box if Agreeing Signals Exist */}
                  {intelContext?.isCorroborating && !intelContext?.isConflict && (
                    <div className="neo-intel-corroboration-alert">
                      <div className="neo-intel-corroboration-header">
                        <TrendingUp size={14} color="#0284C7" strokeWidth={2.2} />
                        <span>Threat Corroboration Detected</span>
                      </div>
                      <p className="neo-intel-corroboration-desc">{intelContext.corroborationSummary}</p>
                    </div>
                  )}

                  {/* Prior Rejection Notes Callout if applicable */}
                  {intelContext?.priorDecisions?.latestRejection && (
                    <div className="neo-intel-past-rejection-callout">
                      <div className="neo-intel-rejection-header">
                        <History size={13} color="#64748B" />
                        <span>Past Moderator Rejection Context</span>
                        <span className="neo-intel-rejection-time">
                          {formatRelativeTime(intelContext.priorDecisions.latestRejection.createdAt)}
                        </span>
                      </div>
                      <p className="neo-intel-rejection-notes">
                        "{intelContext.priorDecisions.latestRejection.notes || 'Dismissed without notes'}"
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Decision Form Controls (Interactive if PENDING, Read-only summary if resolved) */}
          {isPending ? (
            <div className="neo-modal-decision-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13.5px', fontWeight: 700, color: '#0f172a' }}>
                <CheckCircle2 size={16} color="#0066FF" aria-hidden="true" />
                <span>Consensus & Intelligence Publication Parameters</span>
              </div>

              {/* Circuit Breaker Controls for Protected Entities */}
              {report.protected_entity?.isProtected && report.report_type !== 'false_positive' && (
                <div className="neo-circuit-breaker-card">
                  <div className="neo-circuit-breaker-header">
                    <ShieldAlert size={16} color="#E11D48" aria-hidden="true" />
                    <span>Protected Entity Circuit Breaker Active</span>
                  </div>
                  <p className="neo-circuit-breaker-desc">
                    Direct approval is locked for official national entities and high-reputation global platforms. If this domain is genuinely compromised (e.g. sub-domain takeover, DNS hijacking, or active abuse), you must provide manual incident authorization:
                  </p>
                  <label className="neo-circuit-breaker-checkbox-label">
                    <input
                      type="checkbox"
                      checked={overrideProtectedEntity}
                      onChange={(e) => {
                        setOverrideProtectedEntity(e.target.checked)
                        setGuardrailError(null)
                      }}
                    />
                    <span>I confirm an active, verified security compromise or critical incident on this domain</span>
                  </label>
                  {overrideProtectedEntity && (
                    <div className="neo-form-field" style={{ marginTop: '8px' }}>
                      <label className="neo-form-label">Incident Reason / CERT Ticket Ref *</label>
                      <input
                        type="text"
                        value={incidentReason}
                        onChange={(e) => {
                          setIncidentReason(e.target.value)
                          setGuardrailError(null)
                        }}
                        placeholder="e.g. SLCERT-INC-2026-089: Confirmed unauthorized DNS hijacking"
                        className="neo-modal-input"
                      />
                    </div>
                  )}
                </div>
              )}

              <div className="neo-modal-decision-grid">
                <div className="neo-form-field">
                  <label className="neo-form-label">Threat Category</label>
                  <select
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                    className="neo-modal-select"
                  >
                    {CATEGORIES.map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="neo-form-field">
                  <label className="neo-form-label">Confidence Assessment</label>
                  <select
                    value={confidence}
                    onChange={(e) => setConfidence(parseFloat(e.target.value))}
                    className="neo-modal-select"
                  >
                    <option value={1.0}>Definite Threat (1.00 / 100%) — Confirmed IoC</option>
                    <option value={0.85}>High Probability (0.85 / 85%) — Strong Markers</option>
                    <option value={0.70}>Suspicious (0.70 / 70%) — Moderate Certainty</option>
                  </select>
                </div>

                {report.reported_domain && (
                  <div className="neo-form-field" style={{ gridColumn: 'span 2' }}>
                    <label className="neo-form-label">Publish Target As</label>
                    <select
                      value={indicatorType}
                      onChange={(e) => setIndicatorType(e.target.value as 'domain' | 'content_hash' | 'url')}
                      className="neo-modal-select"
                    >
                      <option value="domain">Defanged Domain Name ({defangIndicator(report.reported_domain)})</option>
                      <option value="content_hash">Content Fingerprint (SHA-256)</option>
                      <option value="url">Raw Normalized URL</option>
                    </select>
                  </div>
                )}
              </div>

              <div className="neo-form-field">
                <label className="neo-form-label">
                  Moderator Sanitization & Audit Notes
                </label>
                <input
                  type="text"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="e.g. Confirmed phishing domain impersonating Commercial Bank of Ceylon OTP screen."
                  className="neo-modal-input"
                />
              </div>

              {/* Guardrail error feedback */}
              {guardrailError && (
                <div className="neo-guardrail-error-banner" role="alert">
                  <ShieldAlert size={15} color="#991B1B" aria-hidden="true" />
                  <span>{guardrailError}</span>
                </div>
              )}


            </div>
          ) : (
            <div className="neo-modal-decision-card" style={{ background: '#F8FAFC', border: '1px solid #E2E8F0' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13.5px', fontWeight: 700, color: '#0F172A' }}>
                <ShieldCheck size={16} color={isApproved ? '#10B981' : '#EF4444'} aria-hidden="true" />
                <span>Moderation Status: {report.status}</span>
              </div>
              <p style={{ margin: '4px 0 0', fontSize: '12.5px', color: '#64748B' }}>
                {isApproved
                  ? 'This report was approved by a verified moderator and published to the Sri Lankan threat intelligence registry.'
                  : 'This report was reviewed and dismissed by a moderator.'}
              </p>
            </div>
          )}
        </div>

        {/* Modal Footer Actions */}
        <div className="neo-modal-footer">
          {isPending ? (
            <>
              <button
                type="button"
                className="neo-modal-btn-reject"
                onClick={() => onReject(report)}
                disabled={isProcessing}
              >
                Dismiss / Reject Report
              </button>

              <div className="neo-modal-footer-actions">
                <button
                  type="button"
                  className="neo-modal-btn-subtle"
                  onClick={onClose}
                  disabled={isProcessing}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="neo-modal-btn-action-lime"
                  onClick={() => {
                    if (report.protected_entity?.isProtected && report.report_type !== 'false_positive') {
                      if (!overrideProtectedEntity) {
                        setGuardrailError('Circuit Breaker Active: Check the override confirmation box to proceed, or click Dismiss.')
                        return
                      }
                      if (!incidentReason.trim()) {
                        setGuardrailError('An incident reason or CERT ticket reference is required for protected entities.')
                        return
                      }
                    }
                    if (intelContext?.isConflict && !confirmRevocation) {
                      setGuardrailError('Intelligence Conflict Guard: Please check the authorization box in the Intelligence Radar above to confirm revoking the opposing active indicator.')
                      return
                    }
                    setGuardrailError(null)
                    void onApprove(
                      report,
                      category,
                      indicatorType,
                      notes,
                      confidence,
                      overrideProtectedEntity,
                      incidentReason.trim() || undefined
                    )
                  }}
                  disabled={isProcessing}
                >
                  {isProcessing ? (
                    <>
                      <span className="spinner" style={{ width: '13px', height: '13px', border: '2px solid #fff', borderTopColor: 'transparent', borderRadius: '50%', display: 'inline-block', animation: 'spin 1s linear infinite' }} />
                      <span>Processing...</span>
                    </>
                  ) : (
                    <>
                      <ShieldCheck size={15} aria-hidden="true" />
                      <span>Confirm & Publish Intelligence</span>
                    </>
                  )}
                </button>
              </div>
            </>
          ) : (
            <div style={{ display: 'flex', justifyContent: 'flex-end', width: '100%' }}>
              <button
                type="button"
                className="neo-modal-btn-subtle"
                onClick={onClose}
                style={{ padding: '8px 24px' }}
              >
                Close Record
              </button>
            </div>
          )}
        </div>
      </div>
    </div>,
    document.body
  )
}

export default ReviewDecisionModal

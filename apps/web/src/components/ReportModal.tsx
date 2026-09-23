import React, { useEffect, useState, useCallback, useMemo } from 'react'
import { createPortal } from 'react-dom'
import {
  ShieldAlert,
  AlertTriangle,
  Search,
  CheckCircle2,
  X,
  Globe,
  Copy,
  Check,
  Send,
  Hash,
  Lock,
  DollarSign,
  Briefcase,
  Download,
  UserX,
  AlertCircle,
  Landmark,
  Store,
  MessageCircle,
  FileText,
  Pencil,
} from 'lucide-react'
import {
  type CreatedReport,
  type ReportType,
  computeSha256,
  defangIndicator,
  submitUserReport,
} from '../services/reportingService'
import './ReportModal.css'

export interface ReportModalProps {
  isOpen: boolean
  onClose: () => void
  content: string
  reportedDomain?: string | null
  submissionId?: string | null
}

export interface ThreatCategoryOption {
  id: string
  label: string
  sublabel: string
  icon: React.ComponentType<{ size?: number; className?: string; 'aria-hidden'?: boolean | 'true' | 'false' }>
  color: string
}

const REPORT_TYPE_TABS: Array<{
  type: ReportType
  label: string
  icon: React.ComponentType<{ size?: number; 'aria-hidden'?: boolean | 'true' | 'false' }>
  badgeClass: string
}> = [
  {
    type: 'suspicious',
    label: 'Unreported Threat',
    icon: ShieldAlert,
    badgeClass: 'tab-threat',
  },
  {
    type: 'false_positive',
    label: 'False Alarm',
    icon: AlertTriangle,
    badgeClass: 'tab-alarm',
  },
  {
    type: 'false_negative',
    label: 'Evaded Detection',
    icon: Search,
    badgeClass: 'tab-evaded',
  },
]

const THREAT_CATEGORIES: ThreatCategoryOption[] = [
  {
    id: 'phishing',
    label: 'Phishing',
    sublabel: 'Credential / OTP Theft',
    icon: Lock,
    color: '#EF4444',
  },
  {
    id: 'financial_scam',
    label: 'Financial Scam',
    sublabel: 'Utility, Lottery, Advance Fee',
    icon: DollarSign,
    color: '#F59E0B',
  },
  {
    id: 'job_scam',
    label: 'Fake Job Scam',
    sublabel: 'Task & Hiring Fraud',
    icon: Briefcase,
    color: '#0066FF',
  },
  {
    id: 'malware',
    label: 'Malware / APK',
    sublabel: 'Malicious App Download',
    icon: Download,
    color: '#8B5CF6',
  },
  {
    id: 'impersonation',
    label: 'Impersonation',
    sublabel: 'Spoofing Bank or CEB',
    icon: UserX,
    color: '#EC4899',
  },
  {
    id: 'other',
    label: 'Other Threat',
    sublabel: 'Suspicious Content',
    icon: AlertCircle,
    color: '#64748B',
  },
]

const FALSE_ALARM_CATEGORIES: ThreatCategoryOption[] = [
  {
    id: 'official_institution',
    label: 'Official Institution',
    sublabel: 'Bank, Gov, CEB, Telecom',
    icon: Landmark,
    color: '#10B981',
  },
  {
    id: 'legitimate_business',
    label: 'Legitimate Merchant',
    sublabel: 'Store, Service, Delivery',
    icon: Store,
    color: '#0284C7',
  },
  {
    id: 'personal_message',
    label: 'Personal Message',
    sublabel: 'Known Safe Contact',
    icon: MessageCircle,
    color: '#6366F1',
  },
]

function detectDefaultThreat(text: string, domain?: string | null): string {
  const t = `${domain || ''} ${text}`.toLowerCase()
  if (/boc|combank|bank|hnb|sampath|login|verify|credential|pin|otp|password|security|card/.test(t)) {
    return 'phishing'
  }
  if (/job|earn|part-time|salary|hiring|advance|task|telegram/.test(t)) {
    return 'job_scam'
  }
  if (/\.apk|download|install|app|update|trojan|malware/.test(t)) {
    return 'malware'
  }
  if (/ceb|electricity|water|bill|telecom|dialog|mobitel|lottery|prize|won|lucky|cash|gift|reward|offer/.test(t)) {
    return 'financial_scam'
  }
  return 'phishing'
}

export const ReportModal: React.FC<ReportModalProps> = ({
  isOpen,
  onClose,
  content,
  reportedDomain,
  submissionId,
}) => {
  const [reportType, setReportType] = useState<ReportType>('suspicious')
  const [threatCategory, setThreatCategory] = useState<string>('phishing')
  const [notes, setNotes] = useState('')
  const [sha256, setSha256] = useState<string>('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [successReport, setSuccessReport] = useState<CreatedReport | null>(null)
  const [copiedId, setCopiedId] = useState(false)
  const [isEditingTarget, setIsEditingTarget] = useState(false)

  const detectedTarget = useMemo(() => {
    return (
      reportedDomain ||
      content.match(/https?:\/\/[^\s/$.?#].[^\s]*/i)?.[0] ||
      content.match(/[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?/i)?.[0] ||
      ''
    )
  }, [reportedDomain, content])

  const [manualIndicator, setManualIndicator] = useState<string | null>(null)
  const targetIndicator = manualIndicator !== null ? manualIndicator : detectedTarget

  useEffect(() => {
    if (isOpen && !content.trim() && !reportedDomain) {
      setIsEditingTarget(true)
    }
  }, [isOpen, content, reportedDomain])

  // Compute client-side SHA-256
  useEffect(() => {
    if (isOpen) {
      const source = content.trim() || targetIndicator.trim() || notes.trim() || `community-report-${Date.now()}`
      computeSha256(source).then(setSha256).catch(() => setSha256(''))
    }
  }, [content, targetIndicator, notes, isOpen])

  // Intelligently pre-select the most relevant threat category when modal opens
  useEffect(() => {
    if (isOpen) {
      if (reportType === 'false_positive') {
        setThreatCategory('official_institution')
      } else {
        setThreatCategory(detectDefaultThreat(content, targetIndicator))
      }
    }
  }, [isOpen, reportType, content, targetIndicator])

  const handleClose = useCallback(() => {
    if (isSubmitting) return
    setError(null)
    setSuccessReport(null)
    setNotes('')
    setManualIndicator(null)
    setCopiedId(false)
    setIsEditingTarget(false)
    onClose()
  }, [isSubmitting, onClose])

  // Escape key handler
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen && !isSubmitting) {
        handleClose()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, isSubmitting, handleClose])

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

  const handleCopyId = (id: string) => {
    navigator.clipboard.writeText(id)
    setCopiedId(true)
    setTimeout(() => setCopiedId(false), 2000)
  }

  if (!isOpen) return null

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!targetIndicator.trim() && !content.trim() && !notes.trim()) {
      setError('Please provide a suspicious link, phone number, or description of the scam.')
      return
    }

    let hash = sha256
    if (!hash) {
      const source = content.trim() || targetIndicator.trim() || notes.trim() || `community-report-${Date.now()}`
      hash = await computeSha256(source).catch(() => '')
    }

    if (!hash) {
      setError('Cryptographic fingerprint could not be computed for this content.')
      return
    }

    setIsSubmitting(true)
    setError(null)

    try {
      const finalTarget = targetIndicator.trim() ? defangIndicator(targetIndicator.trim()) : null
      const excerpt = content.trim().length > 250 ? content.trim().slice(0, 247) + '...' : content.trim()

      const res = await submitUserReport({
        reportType,
        threatCategory,
        contentSha256: hash,
        reportedDomain: finalTarget,
        notes: notes.trim() || null,
        submissionId: submissionId || null,
        rawExcerpt: excerpt || null,
      })

      if (res.success && res.report) {
        setSuccessReport(res.report)
      } else {
        setError(res.error || 'Failed to submit report. Please try again.')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred.')
    } finally {
      setIsSubmitting(false)
    }
  }

  const defangedPreview = targetIndicator.trim() ? defangIndicator(targetIndicator.trim()) : ''
  const availableCategories = reportType === 'false_positive' ? FALSE_ALARM_CATEGORIES : THREAT_CATEGORIES

  return createPortal(
    <div
      className="modal-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget && !isSubmitting) {
          handleClose()
        }
      }}
      role="presentation"
    >
      <div
        className="report-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
      >
        {/* Accent Bar */}
        <div className="modal-top-accent" aria-hidden="true" />

        {successReport ? (
          <div className="success-view">
            <div className="success-icon-badge" aria-hidden="true">
              <CheckCircle2 size={36} />
            </div>

            <div className="success-text-block">
              <h4 id="modal-title">Report Submitted to Threat Queue</h4>
              <p>
                Thank you for contributing to Sri Lanka's scam defense network. Your report has been dispatched to community moderators for validation.
              </p>
            </div>

            <div className="success-ref-card">
              <div className="success-ref-item">
                <span className="success-ref-tag">INCIDENT REFERENCE ID</span>
                <button
                  type="button"
                  className="success-copy-ref-btn"
                  onClick={() => handleCopyId(successReport.id)}
                  title="Copy Reference ID"
                >
                  <code>{successReport.id}</code>
                  {copiedId ? <Check size={13} color="#10B981" /> : <Copy size={13} />}
                </button>
              </div>

              <div className="success-meta-row">
                <span className="meta-label">Intent</span>
                <span className="meta-badge">
                  {reportType === 'suspicious'
                    ? 'Unreported Threat'
                    : reportType === 'false_positive'
                      ? 'False Alarm'
                      : 'Evaded Detection'}
                </span>
              </div>

              {threatCategory && (
                <div className="success-meta-row">
                  <span className="meta-label">Classification</span>
                  <span className="meta-badge threat">
                    {availableCategories.find((c) => c.id === threatCategory)?.label || threatCategory}
                  </span>
                </div>
              )}

              {successReport.reported_domain && (
                <div className="success-meta-row">
                  <span className="meta-label">Target Indicator</span>
                  <code className="meta-defanged">{successReport.reported_domain}</code>
                </div>
              )}
            </div>

            <div className="modal-actions-single">
              <button
                type="button"
                className="btn-primary done-btn"
                onClick={handleClose}
                autoFocus
              >
                <span>Done</span>
              </button>
            </div>
          </div>
        ) : (
          <>
            {/* Header */}
            <div className="modal-header">
              <div className="modal-header-left">
                <div className="modal-header-icon">
                  <ShieldAlert size={20} aria-hidden="true" />
                </div>
                <div className="modal-header-text">
                  <h3 id="modal-title">Report Suspicious Content</h3>
                  <p>Help calibrate Sri Lankan fraud defenses by flagging new threats or false alarms.</p>
                </div>
              </div>
              <button
                type="button"
                className="modal-close-btn"
                onClick={handleClose}
                aria-label="Close dialog"
                disabled={isSubmitting}
              >
                <X size={16} aria-hidden="true" />
              </button>
            </div>

            {error && (
              <div className="error-banner" role="alert">
                <AlertTriangle size={15} aria-hidden="true" />
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="report-form">
              {/* ── Section 1: Unified Scanned Target Preview ──────────────── */}
              <div className="clean-preview-strip">
                <div className="clean-preview-top">
                  <div className="clean-preview-target">
                    {defangedPreview ? (
                      <span className="target-pill">
                        <Globe size={12} aria-hidden="true" />
                        <code title={targetIndicator}>{defangedPreview}</code>
                      </span>
                    ) : (
                      <span className="target-pill message">
                        <FileText size={12} aria-hidden="true" />
                        <span>Message Text</span>
                      </span>
                    )}

                    <button
                      type="button"
                      className="btn-edit-target"
                      onClick={() => setIsEditingTarget((prev) => !prev)}
                      title="Edit target indicator"
                    >
                      <Pencil size={11} aria-hidden="true" />
                      <span>{isEditingTarget ? 'Close' : 'Edit Target'}</span>
                    </button>
                  </div>

                  {sha256 && (
                    <span className="fingerprint-pill" title={`SHA-256: ${sha256}`}>
                      <Hash size={11} aria-hidden="true" />
                      <span>{sha256.slice(0, 10)}...</span>
                    </span>
                  )}
                </div>

                {isEditingTarget && (
                  <div className="inline-target-input-row">
                    <input
                      type="text"
                      value={targetIndicator}
                      onChange={(e) => setManualIndicator(e.target.value)}
                      placeholder="e.g. ceb-online-payment.top"
                      className="clean-target-input"
                    />
                  </div>
                )}

                {content && (
                  <div className="clean-snippet-quote">
                    "{content.length > 120 ? content.slice(0, 118) + '...' : content}"
                  </div>
                )}
              </div>

              {/* ── Section 2: Report Intent (Segmented 3-Pill Switch) ────── */}
              <div className="form-group">
                <label className="clean-section-label">1. Reason for Reporting</label>
                <div className="clean-intent-pills" role="radiogroup" aria-label="Reason for reporting">
                  {REPORT_TYPE_TABS.map((tab) => {
                    const isSelected = reportType === tab.type
                    const TabIcon = tab.icon
                    return (
                      <button
                        type="button"
                        key={tab.type}
                        className={`clean-intent-pill ${tab.badgeClass} ${isSelected ? 'active' : ''}`}
                        role="radio"
                        aria-checked={isSelected}
                        onClick={() => {
                          setReportType(tab.type)
                          if (tab.type === 'false_positive') {
                            setThreatCategory('official_institution')
                          } else if (threatCategory === 'official_institution' || threatCategory === 'legitimate_business' || threatCategory === 'personal_message') {
                            setThreatCategory('phishing')
                          }
                        }}
                      >
                        <TabIcon size={14} aria-hidden="true" />
                        <span>{tab.label}</span>
                        {isSelected && <span className="clean-active-dot" aria-hidden="true" />}
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* ── Section 3: Threat Type Classification Grid ────────────── */}
              <div className="form-group">
                <label className="clean-section-label">
                  2. {reportType === 'false_positive' ? 'Dispute Category' : 'Threat Classification'}
                </label>
                <div className="clean-threat-grid" role="radiogroup" aria-label="Threat classification">
                  {availableCategories.map((cat) => {
                    const isSelected = threatCategory === cat.id
                    const CatIcon = cat.icon
                    return (
                      <button
                        type="button"
                        key={cat.id}
                        className={`clean-threat-card ${isSelected ? 'selected' : ''}`}
                        role="radio"
                        aria-checked={isSelected}
                        onClick={() => setThreatCategory(cat.id)}
                      >
                        <div
                          className="clean-threat-icon-box"
                          style={{
                            color: cat.color,
                            backgroundColor: `${cat.color}15`,
                          }}
                        >
                          <CatIcon size={14} aria-hidden="true" />
                        </div>
                        <div className="clean-threat-text">
                          <span className="clean-threat-title">{cat.label}</span>
                          <span className="clean-threat-sub">{cat.sublabel}</span>
                        </div>
                        {isSelected && (
                          <div className="clean-threat-check">
                            <Check size={11} strokeWidth={3} aria-hidden="true" />
                          </div>
                        )}
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* ── Section 4: Context Notes (Clean Textarea) ─────────────── */}
              <div className="form-group">
                <div className="clean-label-counter-row">
                  <label htmlFor="report-notes" className="clean-section-label">
                    3. Additional Context <span className="optional-tag">(Optional)</span>
                  </label>
                  <span className={`clean-counter ${notes.length >= 1950 ? 'near-limit' : ''}`}>
                    {notes.length} / 2000
                  </span>
                </div>
                <textarea
                  id="report-notes"
                  className="clean-notes-textarea"
                  maxLength={2000}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="e.g. Sent via WhatsApp from +94 77... claiming to be Commercial Bank with a fake login link."
                  rows={2}
                />
              </div>

              {/* ── Section 5: Modal Footer with Submit & Cancel ──────────── */}
              <div className="clean-modal-footer">
                <div className="clean-footer-actions">
                  <button
                    type="button"
                    className="btn-modal-cancel"
                    onClick={handleClose}
                    disabled={isSubmitting}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="btn-modal-submit"
                    disabled={isSubmitting || !sha256}
                  >
                    {isSubmitting ? (
                      <>
                        <span className="btn-spinner" />
                        <span>Submitting...</span>
                      </>
                    ) : (
                      <>
                        <Send size={13} aria-hidden="true" />
                        <span>Submit to Threat Queue</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </form>
          </>
        )}
      </div>
    </div>,
    document.body
  )
}

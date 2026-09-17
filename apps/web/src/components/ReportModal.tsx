import React, { useEffect, useState, useCallback } from 'react'
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
  ShieldCheck,
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

const REPORT_TYPE_CONFIG: Record<
  ReportType,
  {
    icon: React.ComponentType<{ size?: number; 'aria-hidden'?: boolean | 'true' | 'false' }>
    title: string
    desc: string
    color: string
    typeClass: string
  }
> = {
  suspicious: {
    icon: ShieldAlert,
    title: 'Unreported Threat',
    desc: 'Phishing, bank fraud, fake job, or malicious link',
    color: '#e11d48',
    typeClass: 'is-threat',
  },
  false_positive: {
    icon: AlertTriangle,
    title: 'False Alarm',
    desc: 'Legitimate message incorrectly flagged as risky',
    color: '#d97706',
    typeClass: 'is-alarm',
  },
  false_negative: {
    icon: Search,
    title: 'Evaded Detection',
    desc: 'Dangerous scam that bypassed safety filters',
    color: '#0284c7',
    typeClass: 'is-evaded',
  },
}

export const ReportModal: React.FC<ReportModalProps> = ({
  isOpen,
  onClose,
  content,
  reportedDomain,
  submissionId,
}) => {
  const [reportType, setReportType] = useState<ReportType>('suspicious')
  const [notes, setNotes] = useState('')
  const [sha256, setSha256] = useState<string>('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [successReport, setSuccessReport] = useState<CreatedReport | null>(null)
  const [copiedId, setCopiedId] = useState(false)

  const detectedTarget =
    reportedDomain ||
    content.match(/https?:\/\/[^\s/$.?#].[^\s]*/i)?.[0] ||
    content.match(/[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?/i)?.[0] ||
    ''
  const [manualIndicator, setManualIndicator] = useState<string | null>(null)
  const targetIndicator = manualIndicator !== null ? manualIndicator : detectedTarget

  // Compute client-side SHA-256
  useEffect(() => {
    if (content && isOpen) {
      computeSha256(content).then(setSha256).catch(() => setSha256(''))
    }
  }, [content, isOpen])

  const handleClose = useCallback(() => {
    if (isSubmitting) return
    setError(null)
    setSuccessReport(null)
    setNotes('')
    setManualIndicator(null)
    setCopiedId(false)
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

  const handleCopyId = (id: string) => {
    navigator.clipboard.writeText(id)
    setCopiedId(true)
    setTimeout(() => setCopiedId(false), 2000)
  }

  if (!isOpen) return null

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!sha256) {
      setError('Cryptographic fingerprint could not be computed for this content.')
      return
    }

    setIsSubmitting(true)
    setError(null)

    try {
      const finalTarget = targetIndicator.trim() ? defangIndicator(targetIndicator.trim()) : null
      const excerpt = content.trim().length > 300 ? content.trim().slice(0, 297) + '...' : content.trim()

      const res = await submitUserReport({
        reportType,
        contentSha256: sha256,
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

  return (
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
        {/* Subtle Brand Accent Bar */}
        <div className="modal-top-accent" aria-hidden="true" />

        {successReport ? (
          <div className="success-view">
            <div className="success-icon-badge" aria-hidden="true">
              <CheckCircle2 size={36} />
            </div>

            <div className="success-text-block">
              <h4 id="modal-title">Threat Report Submitted</h4>
              <p>
                Thank you for protecting Sri Lankan citizens. Your report is now in the TrustLens moderation pipeline.
              </p>
            </div>

            <div className="success-ref-card">
              <div className="success-ref-item">
                <span className="success-ref-tag">INCIDENT REFERENCE</span>
                <button
                  type="button"
                  className="success-copy-ref-btn"
                  onClick={() => handleCopyId(successReport.id)}
                  title="Copy Reference ID"
                >
                  <code>{successReport.id}</code>
                  {copiedId ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                </button>
              </div>

              <div className="success-meta-row">
                <span className="meta-label">Classification</span>
                <span className="meta-badge">
                  {REPORT_TYPE_CONFIG[successReport.report_type]?.title || successReport.report_type}
                </span>
              </div>

              {successReport.reported_domain && (
                <div className="success-meta-row">
                  <span className="meta-label">Defanged Target</span>
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
            {/* Modal Header */}
            <div className="modal-header">
              <div className="modal-header-text">
                <h3 id="modal-title">Report Threat or False Alarm</h3>
                <p>Help improve TrustLens detection for Sri Lankan fraud patterns.</p>
              </div>
              <button
                type="button"
                className="modal-close-btn"
                onClick={handleClose}
                aria-label="Close dialog"
                disabled={isSubmitting}
              >
                <X size={17} aria-hidden="true" />
              </button>
            </div>

            {error && (
              <div className="error-banner" role="alert">
                <AlertTriangle size={15} aria-hidden="true" />
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="report-form">
              {/* 1. Reason Selection Cards */}
              <div className="form-group">
                <label className="form-label" id="reason-label">
                  Reason for Reporting
                </label>

                <div
                  className="reason-grid"
                  role="radiogroup"
                  aria-labelledby="reason-label"
                >
                  {(Object.keys(REPORT_TYPE_CONFIG) as ReportType[]).map((type) => {
                    const cfg = REPORT_TYPE_CONFIG[type]
                    const IconComponent = cfg.icon
                    const isSelected = reportType === type
                    return (
                      <button
                        type="button"
                        key={type}
                        className={`reason-card ${cfg.typeClass} ${isSelected ? 'selected' : ''}`}
                        role="radio"
                        aria-checked={isSelected}
                        onClick={() => setReportType(type)}
                      >
                        <div className="reason-header">
                          <div className={`reason-icon-box ${cfg.typeClass}`}>
                            <IconComponent size={17} aria-hidden="true" />
                          </div>
                          <div className={`reason-radio ${isSelected ? 'active' : ''}`} aria-hidden="true">
                            {isSelected && <Check size={10} strokeWidth={3} />}
                          </div>
                        </div>
                        <div className="reason-text">
                          <span className="reason-title">{cfg.title}</span>
                          <span className="reason-desc">{cfg.desc}</span>
                        </div>
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* 2. Scanned Snippet & Target URL (Clean, side-by-side or stacked cleanly) */}
              <div className="form-row-compact">
                {content && (
                  <div className="snippet-box">
                    <span className="snippet-label">Scanned Content Snippet</span>
                    <p className="snippet-text">
                      "{content.length > 140 ? content.slice(0, 137) + '...' : content}"
                    </p>
                  </div>
                )}

                <div className="target-box">
                  <div className="target-label-row">
                    <label htmlFor="target-indicator" className="form-label-inline">
                      <Globe size={12} aria-hidden="true" />
                      <span>Target URL / Domain</span>
                    </label>
                    {defangedPreview && (
                      <span className="defanged-pill" title="Indicators are safely defanged before transmission">
                        <code>{defangedPreview}</code>
                      </span>
                    )}
                  </div>
                  <input
                    id="target-indicator"
                    type="text"
                    value={targetIndicator}
                    onChange={(e) => setManualIndicator(e.target.value)}
                    placeholder="e.g. ceb-online-pay.top"
                    className="target-input-field"
                  />
                </div>
              </div>

              {/* 3. Additional Context */}
              <div className="form-group">
                <div className="label-with-counter">
                  <label htmlFor="report-notes" className="form-label">
                    Additional Context <span className="optional-tag">(Optional)</span>
                  </label>
                  <span className={`counter-text ${notes.length >= 1950 ? 'limit-near' : ''}`}>
                    {notes.length} / 2000
                  </span>
                </div>
                <textarea
                  id="report-notes"
                  className="notes-textarea"
                  maxLength={2000}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="e.g. Received via WhatsApp claiming to be Commercial Bank with a reward link."
                  rows={2}
                />
              </div>

              {/* 4. Footer with Privacy Assurance & Action Buttons */}
              <div className="modal-footer">
                <div className="privacy-assurance">
                  <ShieldCheck size={14} color="#087f8c" aria-hidden="true" />
                  <span>Zero-PII • Content hashed locally • Submitter anonymous</span>
                </div>

                <div className="footer-buttons">
                  <button
                    type="button"
                    className="btn-cancel"
                    onClick={handleClose}
                    disabled={isSubmitting}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="btn-submit"
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
    </div>
  )
}

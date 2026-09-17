import React, { useEffect, useState, useCallback } from 'react'
import {
  ShieldAlert,
  AlertTriangle,
  Search,
  CheckCircle2,
  ShieldCheck,
  X,
  Fingerprint,
  Globe,
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
    icon: React.ComponentType<{ size?: number; color?: string; 'aria-hidden'?: boolean | 'true' | 'false' }>
    title: string
    desc: string
    color: string
  }
> = {
  suspicious: {
    icon: ShieldAlert,
    title: 'Unreported Threat',
    desc: 'Phishing, bank fraud, fake job offer, or malicious link.',
    color: '#a33d31',
  },
  false_positive: {
    icon: AlertTriangle,
    title: 'False Alarm',
    desc: 'Legitimate message from an official organization or bank.',
    color: '#b7791f',
  },
  false_negative: {
    icon: Search,
    title: 'Evaded Detection',
    desc: 'TrustLens rated this safe, but it is dangerous fraud.',
    color: '#087f8c',
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

  const detectedTarget = reportedDomain || content.match(/https?:\/\/[^\s/$.?#].[^\s]*/i)?.[0] || content.match(/[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?/i)?.[0] || ''
  const [manualIndicator, setManualIndicator] = useState<string | null>(null)
  const targetIndicator = manualIndicator !== null ? manualIndicator : detectedTarget

  // Compute client-side SHA-256 whenever the content changes
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
    onClose()
  }, [isSubmitting, onClose])

  // Handle escape key closing
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen && !isSubmitting) {
        handleClose()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, isSubmitting, handleClose])

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
        {successReport ? (
          <div className="success-view">
            <div className="success-icon-circle" aria-hidden="true">
              <CheckCircle2 size={36} color="#087f8c" />
            </div>
            <h4 id="modal-title">Threat Intelligence Reported</h4>
            <p>
              Thank you for protecting Sri Lankan citizens. Your submission has been
              cryptographically hashed and placed in the verified moderation queue.
            </p>
            <span className="report-ref-badge">
              Report ID: {successReport.id.slice(0, 8)}...
            </span>

            <div className="indicator-box" style={{ width: '100%', marginTop: '8px' }}>
              <div className="indicator-row">
                <span className="indicator-label">Classification</span>
                <span className="indicator-value">
                  {REPORT_TYPE_CONFIG[successReport.report_type]?.title || successReport.report_type}
                </span>
              </div>
              <div className="indicator-row">
                <span className="indicator-label">SHA-256 Fingerprint</span>
                <span className="hash-preview">
                  {successReport.content_sha256.slice(0, 24)}...
                </span>
              </div>
            </div>

            <div className="modal-actions" style={{ width: '100%', justifyContent: 'center' }}>
              <button
                type="button"
                className="btn-primary"
                onClick={handleClose}
                autoFocus
              >
                Done
              </button>
            </div>
          </div>
        ) : (
          <>
            <div className="modal-header">
              <div>
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
                <X size={18} aria-hidden="true" />
              </button>
            </div>

            {error && (
              <div className="error-banner" role="alert">
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} style={{ display: 'contents' }}>
              <div>
                <label className="reason-group-label" id="reason-label">
                  Reason for Reporting
                </label>
                <div
                  className="reason-cards"
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
                        className={`reason-card ${isSelected ? 'selected' : ''}`}
                        role="radio"
                        aria-checked={isSelected}
                        onClick={() => setReportType(type)}
                      >
                        <span className="reason-icon">
                          <IconComponent size={20} color={cfg.color} aria-hidden="true" />
                        </span>
                        <span className="reason-title">{cfg.title}</span>
                        <span className="reason-desc">{cfg.desc}</span>
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Scanned excerpt + Target input — compact row */}
              <div className="report-two-col">
                {/* Left: Excerpt + Target */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {content && (
                    <div style={{ background: '#f0f4f8', borderLeft: '3px solid #087f8c', borderRadius: '6px', padding: '8px 10px' }}>
                      <span style={{ display: 'block', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600, color: '#087f8c', marginBottom: '2px' }}>
                        Scanned Excerpt
                      </span>
                      <p style={{ margin: 0, fontSize: '11px', color: '#102a43', fontStyle: 'italic', wordBreak: 'break-word', maxHeight: '40px', overflowY: 'auto', lineHeight: 1.35 }}>
                        "{content.length > 150 ? content.slice(0, 147) + '...' : content}"
                      </p>
                    </div>
                  )}
                  <div className="notes-group">
                    <label htmlFor="target-indicator" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: 700, color: '#102a43' }}>
                      <Globe size={12} aria-hidden="true" />
                      <span>Target URL / Domain</span>
                    </label>
                    <input
                      id="target-indicator"
                      type="text"
                      value={targetIndicator}
                      onChange={(e) => setManualIndicator(e.target.value)}
                      placeholder="e.g. ceb-online-pay.top"
                      style={{
                        width: '100%',
                        padding: '7px 10px',
                        borderRadius: '7px',
                        border: '1px solid #d9e2ec',
                        fontSize: '12px',
                        fontFamily: 'monospace',
                        background: '#ffffff',
                        colorScheme: 'light',
                        boxSizing: 'border-box',
                      }}
                    />
                  </div>
                </div>

                {/* Right: Fingerprint + indicator */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div className="indicator-box">
                    {targetIndicator.trim() && (
                      <div className="indicator-row">
                        <span className="indicator-label">Defanged</span>
                        <span className="indicator-value" style={{ color: '#a33d31', fontWeight: 600, fontSize: '11px' }}>
                          {defangIndicator(targetIndicator.trim())}
                        </span>
                      </div>
                    )}
                    <div className="indicator-row">
                      <span className="indicator-label" style={{ display: 'inline-flex', alignItems: 'center', gap: '3px' }}>
                        <Fingerprint size={11} color="#087f8c" aria-hidden="true" />
                        SHA-256
                      </span>
                      <span className="hash-preview" title={sha256} style={{ fontSize: '10px' }}>
                        {sha256 ? `${sha256.slice(0, 20)}...` : 'Computing...'}
                      </span>
                    </div>
                  </div>
                  <div className="privacy-badge">
                    <ShieldCheck size={13} aria-hidden="true" style={{ flexShrink: 0 }} />
                    <span>
                      <strong>Privacy First:</strong> Indicators defanged, payloads hashed. PII never indexed.
                    </span>
                  </div>
                </div>
              </div>

              {/* Additional Context Notes */}
              <div className="notes-group">
                <div className="notes-header">
                  <label htmlFor="report-notes" style={{ fontSize: '12px' }}>Additional Context (Optional)</label>
                  <span
                    className={`char-counter ${notes.length >= 1950 ? 'warning' : ''}`}
                  >
                    {notes.length} / 2000
                  </span>
                </div>
                <textarea
                  id="report-notes"
                  className="report-notes-textarea"
                  maxLength={2000}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="e.g. 'Received via WhatsApp SMS claiming to be Commercial Bank asking to redeem reward points'."
                  rows={2}
                />
              </div>

              <div className="modal-actions">
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={handleClose}
                  disabled={isSubmitting}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn-primary"
                  disabled={isSubmitting || !sha256}
                >
                  {isSubmitting ? (
                    <>
                      <span className="spinner" />
                      <span>Submitting...</span>
                    </>
                  ) : (
                    'Submit to Threat Queue'
                  )}
                </button>
              </div>
            </form>
          </>
        )}
      </div>
    </div>
  )
}

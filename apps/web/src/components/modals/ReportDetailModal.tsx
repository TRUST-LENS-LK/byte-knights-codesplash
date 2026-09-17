import React, { useEffect, useState } from 'react'
import {
  FileText,
  Globe,
  X,
  Copy,
  Check,
  Clock,
  Fingerprint,
  ShieldCheck,
} from 'lucide-react'
import type { ModerationQueueItem } from '../../services/moderatorService'
import { defangIndicator } from '../../services/reportingService'
import { formatRelativeTime } from '../../utils/formatTime'
import './ModeratorModals.css'

export interface ReportDetailModalProps {
  isOpen: boolean
  report: ModerationQueueItem | null
  onClose: () => void
  onOpenReview?: (report: ModerationQueueItem) => void
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

export const ReportDetailModal: React.FC<ReportDetailModalProps> = ({
  isOpen,
  report,
  onClose,
  onOpenReview,
}) => {
  const [copiedExcerpt, setCopiedExcerpt] = useState(false)
  const [copiedHash, setCopiedHash] = useState(false)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown)
    }
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  if (!isOpen || !report) return null

  const parsed = parseReportNotes(report.notes)
  const excerpt = report.raw_excerpt || parsed.excerpt
  const displayText = excerpt || parsed.userNotes || 'No raw message text was attached to this report.'

  const wordCount = displayText.trim().split(/\s+/).filter(Boolean).length
  const charCount = displayText.length

  const handleCopyExcerpt = () => {
    if (!displayText) return
    void navigator.clipboard.writeText(displayText)
    setCopiedExcerpt(true)
    setTimeout(() => setCopiedExcerpt(false), 2000)
  }

  const handleCopyHash = () => {
    void navigator.clipboard.writeText(report.content_sha256)
    setCopiedHash(true)
    setTimeout(() => setCopiedHash(false), 2000)
  }

  return (
    <div className="neo-modal-backdrop" onClick={onClose} role="dialog" aria-modal="true">
      <div className="neo-modal-dialog detail-size" onClick={(e) => e.stopPropagation()}>
        {/* Modal Header */}
        <div className="neo-modal-header">
          <div className="neo-modal-header-left">
            <div className="neo-modal-header-icon blue">
              <FileText size={18} aria-hidden="true" />
            </div>
            <div>
              <h3 className="neo-modal-title">Threat Submission Evidence</h3>
              <p className="neo-modal-subtitle">
                <span>Report ID: {report.id.slice(0, 8)}...</span>
                <span>•</span>
                <Clock size={12} aria-hidden="true" />
                <span>Submitted {formatRelativeTime(report.created_at)}</span>
              </p>
            </div>
          </div>
          <button
            type="button"
            className="neo-modal-btn-close"
            onClick={onClose}
            title="Close modal (Esc)"
          >
            <X size={18} aria-hidden="true" />
          </button>
        </div>

        {/* Modal Scrollable Body */}
        <div className="neo-modal-body">
          {/* Metadata Grid */}
          <div className="neo-modal-meta-grid">
            <div className="neo-modal-meta-item">
              <span className="neo-modal-meta-label">Target Indicator</span>
              <div className="neo-modal-meta-val">
                <Globe size={13} color="#64748b" aria-hidden="true" />
                <span className={`neo-indicator-badge ${!report.reported_domain ? 'text-only' : ''}`}>
                  {report.reported_domain ? defangIndicator(report.reported_domain) : 'Message-only text'}
                </span>
              </div>
            </div>

            <div className="neo-modal-meta-item">
              <span className="neo-modal-meta-label">Classification</span>
              <div className="neo-modal-meta-val">
                <span className={`neo-pill-badge ${report.report_type}`}>
                  {report.report_type === 'suspicious'
                    ? 'Reported Threat'
                    : report.report_type === 'false_positive'
                      ? 'False Alarm'
                      : 'Evaded Threat'}
                </span>
              </div>
            </div>

            <div className="neo-modal-meta-item">
              <span className="neo-modal-meta-label">Moderation Status</span>
              <div className="neo-modal-meta-val">
                <span className={`neo-status-pill ${report.status}`}>
                  {report.status}
                </span>
              </div>
            </div>

            <div className="neo-modal-meta-item">
              <span className="neo-modal-meta-label">Exact Timestamp</span>
              <div className="neo-modal-meta-val" style={{ fontSize: '12px' }}>
                {new Date(report.created_at).toLocaleString()}
              </div>
            </div>

            <div className="neo-modal-meta-item full-width">
              <span className="neo-modal-meta-label">Content SHA-256 Fingerprint</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="neo-fingerprint-badge" style={{ fontFamily: 'monospace', fontSize: '11.5px', padding: '3px 8px' }}>
                  <Fingerprint size={12} style={{ display: 'inline', marginRight: '4px' }} />
                  {report.content_sha256}
                </span>
                <button
                  type="button"
                  className="neo-modal-btn-copy"
                  onClick={handleCopyHash}
                  title="Copy SHA-256 hash"
                >
                  {copiedHash ? <Check size={12} color="#15803d" /> : <Copy size={12} />}
                  <span>{copiedHash ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Submitter Notes Callout (if any) */}
          {parsed.userNotes && (
            <div className="neo-modal-notes-callout">
              <span className="neo-modal-notes-label">Citizen Submitter Context</span>
              <p className="neo-modal-notes-text">{parsed.userNotes}</p>
            </div>
          )}

          {/* Complete Submitter Message Excerpt Viewport */}
          <div className="neo-modal-text-section">
            <div className="neo-modal-text-header">
              <div className="neo-modal-text-header-left">
                <FileText size={14} color="#0f172a" aria-hidden="true" />
                <span>Complete Message Payload Evidence</span>
              </div>
              <div className="neo-modal-text-header-right">
                <span className="neo-modal-count-badge">
                  {wordCount.toLocaleString()} words • {charCount.toLocaleString()} characters
                </span>
                <button
                  type="button"
                  className="neo-modal-btn-copy"
                  onClick={handleCopyExcerpt}
                  title="Copy complete excerpt text"
                >
                  {copiedExcerpt ? <Check size={12} color="#15803d" /> : <Copy size={12} />}
                  <span>{copiedExcerpt ? 'Copied Text' : 'Copy Payload'}</span>
                </button>
              </div>
            </div>

            <pre className="neo-modal-code-block" tabIndex={0}>
              {displayText}
            </pre>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="neo-modal-footer">
          <span style={{ fontSize: '11.5px', color: '#94a3b8' }}>
            TrustLens LK • Threat Intelligence Verification
          </span>
          <div className="neo-modal-footer-actions">
            <button type="button" className="neo-modal-btn-subtle" onClick={onClose}>
              Close
            </button>
            {report.status === 'PENDING' && onOpenReview && (
              <button
                type="button"
                className="neo-modal-btn-action-lime"
                onClick={() => {
                  onClose()
                  onOpenReview(report)
                }}
              >
                <ShieldCheck size={14} aria-hidden="true" />
                <span>Proceed to Review & Decide</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default ReportDetailModal

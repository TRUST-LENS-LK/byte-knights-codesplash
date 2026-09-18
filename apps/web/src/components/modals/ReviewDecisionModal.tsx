import React, { useEffect, useState } from 'react'
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  X,
  Globe,
  FileText,
  Clock,
  Fingerprint,
  Copy,
  Check,
} from 'lucide-react'
import type { ModerationQueueItem } from '../../services/moderatorService'
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
    notes: string
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

function classifyReportCategory(item: ModerationQueueItem): string {
  if (item.report_type === 'false_positive') return 'False Alarm'
  const text = `${item.reported_domain || ''} ${item.notes || ''} ${item.raw_excerpt || ''}`.toLowerCase()
  if (/boc|combank|bank|hnb|sampath|card|debit|credit|fund/.test(text)) return 'Banking Phishing'
  if (/ceb|electricity|utility|water|bill|telecom|dialog|mobitel/.test(text)) return 'Telecom / Utility Bill Scam'
  if (/job|earn|part-time|salary|advance|bonus|hiring/.test(text)) return 'Job Scam'
  if (/lottery|prize|won|lucky|cash|gift|reward/.test(text)) return 'Lottery / Prize Fraud'
  if (/otp|code|pin|password|credential|security/.test(text)) return 'OTP Theft'
  if (/\.apk|download|install|app/.test(text)) return 'Malicious Link / APK'
  return 'Banking Phishing'
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
  const [notes, setNotes] = useState('')
  const [copiedExcerpt, setCopiedExcerpt] = useState(false)
  const [copiedHash, setCopiedHash] = useState(false)

  // Sync category with report classification when report changes
  useEffect(() => {
    if (report) {
      setCategory(classifyReportCategory(report))
      setIndicatorType(report.reported_domain ? 'domain' : 'content_hash')
      setNotes('')
      setCopiedExcerpt(false)
      setCopiedHash(false)
    }
  }, [report])

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !isProcessing) onClose()
    }
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown)
    }
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, isProcessing, onClose])

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

  return (
    <div className="neo-modal-backdrop" onClick={() => !isProcessing && onClose()} role="dialog" aria-modal="true">
      <div className="neo-modal-dialog decision-size" onClick={(e) => e.stopPropagation()}>
        {/* Modal Header */}
        <div className="neo-modal-header">
          <div className="neo-modal-header-left">
            <div className={`neo-modal-header-icon ${isApproved ? 'blue' : isRejected ? 'amber' : 'amber'}`}>
              {isApproved ? (
                <ShieldCheck size={18} color="#087f8c" aria-hidden="true" />
              ) : (
                <ShieldAlert size={18} aria-hidden="true" />
              )}
            </div>
            <div>
              <h3 className="neo-modal-title">
                {isPending ? 'Moderator Review & Decision Deck' : 'Moderation Record Inspection'}
              </h3>
              <p className="neo-modal-subtitle">
                <span>Report ID: {report.id.slice(0, 8)}...</span>
                <span>•</span>
                <Clock size={12} aria-hidden="true" />
                <span>Submitted {formatRelativeTime(report.created_at)}</span>
                <span>•</span>
                <span className={`neo-status-pill ${report.status}`} style={{ fontSize: '10px', padding: '1px 6px' }}>
                  {report.status}
                </span>
              </p>
            </div>
          </div>
          <button
            type="button"
            className="neo-modal-btn-close"
            onClick={() => !isProcessing && onClose()}
            disabled={isProcessing}
            title="Close dialog (Esc)"
          >
            <X size={18} aria-hidden="true" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="neo-modal-body">
          {/* Metadata & Evidence Header Card */}
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
              <span className="neo-modal-meta-label">Citizen Classification</span>
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

            <div className="neo-modal-meta-item full-width">
              <span className="neo-modal-meta-label">SHA-256 Fingerprint</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="neo-fingerprint-badge" style={{ fontFamily: 'monospace', fontSize: '11px', padding: '3px 8px' }}>
                  <Fingerprint size={12} style={{ display: 'inline', marginRight: '4px' }} />
                  {report.content_sha256}
                </span>
                <button
                  type="button"
                  onClick={handleCopyHash}
                  className="neo-modal-btn-copy"
                  title="Copy SHA-256 Fingerprint"
                  style={{ fontSize: '11px', padding: '2px 6px', border: '1px solid #cbd5e1', borderRadius: '5px', background: '#ffffff', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '3px' }}
                >
                  {copiedHash ? <Check size={11} color="#10b981" /> : <Copy size={11} />}
                  <span>{copiedHash ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Evidence Excerpt Box (Handles up to 10,000+ words gracefully) */}
          <div className="neo-modal-text-section">
            <div className="neo-modal-text-header">
              <div className="neo-modal-text-header-left">
                <FileText size={13} color="#475569" aria-hidden="true" />
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
                  style={{ fontSize: '11px', padding: '2px 7px', border: '1px solid #cbd5e1', borderRadius: '5px', background: '#ffffff', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
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
              <pre className="neo-modal-code-block" style={{ maxHeight: '220px', overflowY: 'auto' }}>
                {excerpt}
              </pre>
            ) : (
              <div style={{ fontSize: '12.5px', color: '#94a3b8', fontStyle: 'italic', padding: '12px 14px', background: '#f8fafc', borderRadius: '10px' }}>
                No raw message excerpt attached to this report.
              </div>
            )}
            {parsed.userNotes && (
              <div className="neo-modal-notes-callout" style={{ marginTop: '6px' }}>
                <span className="neo-modal-notes-label">Submitter Context</span>
                <p className="neo-modal-notes-text">{parsed.userNotes}</p>
              </div>
            )}
          </div>

          {/* Decision Form Controls (Interactive if PENDING, Read-only summary if resolved) */}
          {isPending ? (
            <div className="neo-modal-decision-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', fontWeight: 700, color: '#0f172a' }}>
                <CheckCircle2 size={15} color="#15803d" aria-hidden="true" />
                <span>Consensus & Intelligence Publication Parameters</span>
              </div>

              <div className="neo-modal-decision-grid">
                <div className="neo-form-field">
                  <label style={{ fontSize: '12px', fontWeight: 600, color: '#334155' }}>Threat Category</label>
                  <select
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                    style={{ padding: '8px 10px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '12.5px' }}
                  >
                    {CATEGORIES.map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </select>
                </div>

                {report.reported_domain && (
                  <div className="neo-form-field">
                    <label style={{ fontSize: '12px', fontWeight: 600, color: '#334155' }}>Publish Target As</label>
                    <select
                      value={indicatorType}
                      onChange={(e) => setIndicatorType(e.target.value as 'domain' | 'content_hash' | 'url')}
                      style={{ padding: '8px 10px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '12.5px' }}
                    >
                      <option value="domain">Defanged Domain Name ({defangIndicator(report.reported_domain)})</option>
                      <option value="content_hash">Content Fingerprint (SHA-256)</option>
                      <option value="url">Raw Normalized URL</option>
                    </select>
                  </div>
                )}
              </div>

              <div className="neo-form-field">
                <label style={{ fontSize: '12px', fontWeight: 600, color: '#334155' }}>
                  Moderator Sanitization & Audit Notes
                </label>
                <input
                  type="text"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="e.g. Confirmed phishing domain impersonating Commercial Bank of Ceylon OTP screen."
                  style={{ padding: '8px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '12.5px' }}
                />
              </div>

              {/* PII Stripping Guarantee */}
              <div className="neo-modal-pii-badge">
                <ShieldCheck size={14} color="#047857" aria-hidden="true" />
                <span>PII Protection Enforced: Submitter email and identifying markers are automatically stripped prior to publishing.</span>
              </div>
            </div>
          ) : (
            <div className="neo-modal-decision-card" style={{ background: '#f8fafc', border: '1px solid #e2e8f0' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', fontWeight: 700, color: '#0f172a' }}>
                <ShieldCheck size={15} color={isApproved ? '#087f8c' : '#dc2626'} aria-hidden="true" />
                <span>Moderation Status: {report.status}</span>
              </div>
              <p style={{ margin: '4px 0 0', fontSize: '12px', color: '#64748b' }}>
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
                  onClick={() => onApprove(report, category, indicatorType, notes)}
                  disabled={isProcessing}
                >
                  {isProcessing ? (
                    <>
                      <span className="spinner" style={{ width: '13px', height: '13px', border: '2px solid #000', borderTopColor: 'transparent', borderRadius: '50%', display: 'inline-block', animation: 'spin 1s linear infinite' }} />
                      <span>Processing...</span>
                    </>
                  ) : (
                    <>
                      <ShieldCheck size={14} aria-hidden="true" />
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
    </div>
  )
}

export default ReviewDecisionModal

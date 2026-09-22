import React, { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import {
  FileSearch,
  Clock,
  User,
  ShieldAlert,
  ShieldCheck,
  Power,
  RefreshCw,
  Sliders,
  Trash2,
  Copy,
  Check,
  X,
  Download,
  Calendar,
} from 'lucide-react'
import type { ModerationAuditLogItem } from '../../services/moderatorService'
import { formatRelativeTime } from '../../utils/formatTime'
import './ModeratorModals.css'

export interface AuditDetailModalProps {
  isOpen: boolean
  auditLog: ModerationAuditLogItem | null
  onClose: () => void
}

function getActionIcon(action: string) {
  switch (action) {
    case 'APPROVE':
      return <ShieldCheck size={14} aria-hidden="true" />
    case 'REJECT':
      return <ShieldAlert size={14} aria-hidden="true" />
    case 'RETIRE':
      return <Power size={14} aria-hidden="true" />
    case 'TOGGLE_STATUS':
      return <RefreshCw size={14} aria-hidden="true" />
    case 'UPDATE_SETTINGS':
      return <Sliders size={14} aria-hidden="true" />
    case 'PURGE_EXPIRED':
      return <Trash2 size={14} aria-hidden="true" />
    default:
      return <FileSearch size={14} aria-hidden="true" />
  }
}

function getActionBadgeClass(action: string): string {
  switch (action) {
    case 'APPROVE':
      return 'audit-badge-approve'
    case 'REJECT':
      return 'audit-badge-reject'
    case 'RETIRE':
      return 'audit-badge-retire'
    case 'TOGGLE_STATUS':
      return 'audit-badge-toggle'
    case 'UPDATE_SETTINGS':
      return 'audit-badge-setting'
    case 'PURGE_EXPIRED':
      return 'audit-badge-purge'
    default:
      return 'audit-badge-default'
  }
}

export const AuditDetailModal: React.FC<AuditDetailModalProps> = ({
  isOpen,
  auditLog,
  onClose,
}) => {
  const [copiedIndicator, setCopiedIndicator] = useState(false)
  const [copiedId, setCopiedId] = useState(false)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown)
    }
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  useEffect(() => {
    if (isOpen) {
      const originalOverflow = document.body.style.overflow
      document.body.style.overflow = 'hidden'
      return () => {
        document.body.style.overflow = originalOverflow
      }
    }
  }, [isOpen])

  if (!isOpen || !auditLog) return null

  const handleCopyIndicator = () => {
    if (!auditLog.target_indicator) return
    navigator.clipboard.writeText(auditLog.target_indicator)
    setCopiedIndicator(true)
    setTimeout(() => setCopiedIndicator(false), 2000)
  }

  const handleCopyId = () => {
    navigator.clipboard.writeText(String(auditLog.id))
    setCopiedId(true)
    setTimeout(() => setCopiedId(false), 2000)
  }

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(auditLog, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `audit_entry_${auditLog.id}.json`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  // Calculate remaining days until retention purge
  let remainingTtlText = '90 Days TTL'
  if (auditLog.expires_at) {
    const expiresMs = new Date(auditLog.expires_at).getTime()
    const nowMs = Date.now()
    const diffDays = Math.max(0, Math.ceil((expiresMs - nowMs) / (1000 * 60 * 60 * 24)))
    remainingTtlText = `${diffDays} days remaining (TTL)`
  }

  return createPortal(
    <div className="neo-modal-backdrop" onClick={onClose} role="dialog" aria-modal="true">
      <div className="neo-modal-dialog detail-size" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="neo-modal-header">
          <div className="neo-modal-header-left">
            <div className="neo-modal-header-icon blue">
              <FileSearch size={22} aria-hidden="true" />
            </div>
            <div>
              <h3 className="neo-modal-title">Audit Record Inspection</h3>
              <p className="neo-modal-subtitle">
                <span
                  onClick={handleCopyId}
                  style={{ cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                  title="Click to copy full Record ID"
                >
                  Record #{String(auditLog.id).slice(0, 8)}
                  {copiedId ? <Check size={11} color="#10B981" /> : <Copy size={11} style={{ opacity: 0.7 }} />}
                </span>
                <span>•</span>
                <Clock size={12} aria-hidden="true" />
                <span>{formatRelativeTime(auditLog.created_at)}</span>
                <span>•</span>
                <span className={`neo-audit-action-pill ${getActionBadgeClass(auditLog.action)}`}>
                  {getActionIcon(auditLog.action)}
                  <span>{auditLog.action.replace('_', ' ')}</span>
                </span>
              </p>
            </div>
          </div>
          <button
            type="button"
            className="neo-modal-btn-close"
            onClick={onClose}
            title="Close modal (Esc)"
          >
            <X size={16} aria-hidden="true" />
          </button>
        </div>

        {/* Body */}
        <div className="neo-modal-body">
          {/* Metadata Grid */}
          <div className="neo-modal-meta-grid">
            <div className="neo-modal-meta-item">
              <span className="neo-modal-meta-label">Action Performed</span>
              <div className="neo-modal-meta-val">
                <span className={`neo-audit-action-pill ${getActionBadgeClass(auditLog.action)}`}>
                  {getActionIcon(auditLog.action)}
                  <span>{auditLog.action}</span>
                </span>
              </div>
            </div>

            <div className="neo-modal-meta-item">
              <span className="neo-modal-meta-label">Actor Attribution</span>
              <div className="neo-modal-meta-val">
                <User size={14} style={{ color: '#64748B' }} aria-hidden="true" />
                <span style={{ fontWeight: 600 }}>{auditLog.actor_email || 'System Agent'}</span>
                <span className="neo-role-tag" style={{ marginLeft: 4 }}>
                  {auditLog.actor_role.toUpperCase()}
                </span>
              </div>
            </div>

            <div className="neo-modal-meta-item">
              <span className="neo-modal-meta-label">Timestamp (UTC)</span>
              <div className="neo-modal-meta-val" style={{ fontFamily: 'ui-monospace, monospace', fontSize: '12px' }}>
                <Calendar size={13} style={{ color: '#64748B' }} aria-hidden="true" />
                <span>{new Date(auditLog.created_at).toLocaleString()}</span>
              </div>
            </div>

            <div className="neo-modal-meta-item">
              <span className="neo-modal-meta-label">Data Retention (90-Day Policy)</span>
              <div className="neo-modal-meta-val">
                <span className="neo-audit-ttl-tag">
                  <Clock size={12} aria-hidden="true" />
                  <span>{remainingTtlText}</span>
                </span>
              </div>
            </div>

            {auditLog.target_indicator && (
              <div className="neo-modal-meta-item full-width">
                <span className="neo-modal-meta-label">Target Indicator (Defanged)</span>
                <div className="neo-modal-meta-val" style={{ justifyContent: 'space-between' }}>
                  <code style={{ background: '#F1F5F9', padding: '4px 8px', borderRadius: '6px', fontSize: '12.5px', color: '#0F172A', wordBreak: 'break-all' }}>
                    {auditLog.target_indicator}
                  </code>
                  <button
                    type="button"
                    className="neo-modal-btn-copy"
                    onClick={handleCopyIndicator}
                    title="Copy indicator"
                  >
                    {copiedIndicator ? <Check size={12} color="#10B981" /> : <Copy size={12} />}
                    <span>{copiedIndicator ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
              </div>
            )}

            {auditLog.threat_category && (
              <div className="neo-modal-meta-item">
                <span className="neo-modal-meta-label">Threat Classification</span>
                <div className="neo-modal-meta-val">
                  <span className="neo-threat-tag" style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', padding: '3px 8px', borderRadius: '6px', fontSize: '12px' }}>
                    {auditLog.threat_category}
                  </span>
                </div>
              </div>
            )}

            {auditLog.confidence !== null && auditLog.confidence !== undefined && (
              <div className="neo-modal-meta-item">
                <span className="neo-modal-meta-label">Confidence Score</span>
                <div className="neo-modal-meta-val">
                  <span style={{ fontWeight: 700, color: auditLog.confidence >= 0.8 ? '#10B981' : '#F59E0B' }}>
                    {Math.round(auditLog.confidence * 100)}% ({auditLog.confidence.toFixed(2)})
                  </span>
                </div>
              </div>
            )}

            {auditLog.report_id && (
              <div className="neo-modal-meta-item full-width">
                <span className="neo-modal-meta-label">Associated Report Reference</span>
                <div className="neo-modal-meta-val">
                  <code style={{ background: '#F1F5F9', padding: '3px 6px', borderRadius: '4px', fontSize: '12px' }}>
                    {auditLog.report_id}
                  </code>
                </div>
              </div>
            )}
          </div>

          {/* Notes & Justification */}
          <div className="neo-modal-text-section">
            <div className="neo-modal-text-header">
              <div className="neo-modal-text-header-left">
                <span>Moderator Justification & Audit Context</span>
              </div>
            </div>
            <pre className="neo-modal-code-block" style={{ minHeight: '80px', maxHeight: '180px' }}>
              {auditLog.moderator_notes || 'No contextual notes recorded for this operation.'}
            </pre>
          </div>
        </div>

        {/* Footer */}
        <div className="neo-modal-footer">
          <button
            type="button"
            className="neo-modal-btn-subtle"
            onClick={handleExportJson}
            title="Export record as JSON"
          >
            <Download size={14} aria-hidden="true" />
            <span>Export JSON</span>
          </button>

          <div className="neo-modal-footer-actions">
            <button
              type="button"
              className="neo-modal-btn-subtle"
              onClick={onClose}
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>,
    document.body
  )
}

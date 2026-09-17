import React from 'react'
import { ShieldAlert, ArrowRight } from 'lucide-react'

export interface CommunityReportBarProps {
  onReportClick: () => void
}

export const CommunityReportBar: React.FC<CommunityReportBarProps> = ({ onReportClick }) => {
  return (
    <div className="community-report-bar">
      <div className="community-report-info">
        <h4>
          <ShieldAlert size={18} color="#087f8c" aria-hidden="true" />
          <span>Community Threat Shield</span>
        </h4>
        <p>
          Notice an inaccuracy or an active ongoing scam? Report this finding to alert moderators and protect other Sri Lankan citizens.
        </p>
      </div>
      <button
        type="button"
        className="btn-report-trigger"
        onClick={onReportClick}
      >
        <span>Flag or Report Result</span>
        <ArrowRight size={14} aria-hidden="true" />
      </button>
    </div>
  )
}

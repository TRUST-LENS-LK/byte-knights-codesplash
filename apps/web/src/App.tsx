import { useEffect, useMemo, useState } from 'react'
import { Shield, ShieldCheck, AlertOctagon, AlertTriangle } from 'lucide-react'
import { analyzeSubmission, analyzeWithApi } from './services/analysisService'
import { CommunityReportBar } from './components/CommunityReportBar'
import { ReportModal } from './components/ReportModal'
import { ModeratorDashboard } from './components/ModeratorDashboard'
import './App.css'

interface IntelligenceOverlay {
  netVerdict: 'CONFIRMED_SCAM' | 'VERIFIED_SAFE' | 'CONFLICTED' | 'OFFICIAL_ENTITY' | 'POSSIBLE_IMPERSONATION' | 'NO_INTEL'
  scamConfidence: number
  safeConfidence: number
  signalCount: number
  scamCount?: number
  safeCount?: number
  consensusRatio?: number
  consensusSummary?: string
  hasDirectoryMatch?: boolean
  officialOrganization?: string | null
  behavioralOverride?: boolean
  reconciliationTrace: string[]
}

function App() {
  const [view, setView] = useState<'checker' | 'moderator'>(() => {
    if (typeof window !== 'undefined') {
      const hash = window.location.hash
      if (hash.startsWith('#moderator')) return 'moderator'
      const stored = sessionStorage.getItem('trustlens_view')
      if (stored === 'moderator') return 'moderator'
    }
    return 'checker'
  })

  // Sync view changes to sessionStorage and URL hash
  useEffect(() => {
    if (view === 'moderator') {
      sessionStorage.setItem('trustlens_view', 'moderator')
      if (!window.location.hash.startsWith('#moderator')) {
        window.location.hash = '#moderator'
      }
    } else {
      sessionStorage.setItem('trustlens_view', 'checker')
      if (window.location.hash.startsWith('#moderator')) {
        window.history.replaceState(null, '', window.location.pathname + window.location.search)
      }
    }
  }, [view])

  // Listen to browser back/forward hash changes
  useEffect(() => {
    const handleHashChange = () => {
      const isMod = window.location.hash.startsWith('#moderator')
      setView(isMod ? 'moderator' : 'checker')
    }
    window.addEventListener('hashchange', handleHashChange)
    return () => window.removeEventListener('hashchange', handleHashChange)
  }, [])

  const [isReportModalOpen, setIsReportModalOpen] = useState(false)
  const [text, setText] = useState('')
  const [checked, setChecked] = useState(false)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [apiAnalysis, setApiAnalysis] = useState<ReturnType<typeof analyzeSubmission> | null>(null)
  const [apiMode, setApiMode] = useState<'local' | 'api'>('local')
  const [intelligenceOverlay, setIntelligenceOverlay] = useState<IntelligenceOverlay | null>(null)
  const analysis = useMemo(() => analyzeSubmission(text), [text])
  const { decision, entities } = apiAnalysis ?? analysis

  // Determine display risk and state classes
  const isOfficialEntity = intelligenceOverlay?.netVerdict === 'OFFICIAL_ENTITY'
  const isVerifiedSafe = (intelligenceOverlay?.netVerdict === 'VERIFIED_SAFE' && (decision.recommendation as string) === 'VERIFIED_SAFE') || isOfficialEntity
  const isImpersonation = intelligenceOverlay?.netVerdict === 'POSSIBLE_IMPERSONATION'
  const isConfirmedScam = intelligenceOverlay?.netVerdict === 'CONFIRMED_SCAM' || isImpersonation
  const isConflicted = intelligenceOverlay?.netVerdict === 'CONFLICTED'

  const risk = isOfficialEntity
    ? 'Official Entity'
    : isVerifiedSafe
      ? 'Verified Safe'
      : isImpersonation
        ? 'High Risk — Spoofing'
        : isConflicted
          ? 'Disputed / High Risk'
          : decision.riskBand === 'HIGH'
            ? 'High Risk'
            : decision.riskBand === 'MEDIUM'
              ? 'Suspicious'
              : 'Likely Safe'

  const resultClass = isOfficialEntity
    ? 'official-entity'
    : isVerifiedSafe
      ? 'verified-safe'
      : isConflicted
        ? 'conflicted'
        : risk.toLowerCase().replace(/[^a-z0-9]+/g, '-')

  const checkMessage = async () => {
    setIsAnalyzing(true)
    setIntelligenceOverlay(null)
    try {
      const result = await analyzeWithApi(text)
      setApiAnalysis(result)
      setApiMode('api')
      // Extract intelligenceOverlay from the raw API response if present
      if ((result as Record<string, unknown>).intelligenceOverlay) {
        setIntelligenceOverlay((result as Record<string, unknown>).intelligenceOverlay as IntelligenceOverlay)
      }
      setChecked(true)
    } catch {
      setApiAnalysis(null)
      setApiMode('local')
      setChecked(true)
    } finally {
      setIsAnalyzing(false)
    }
  }

  const detectedDomain = entities.find((e) => e.type === 'url' || e.type === 'domain')?.value || null

  const handleBackToScanner = () => {
    sessionStorage.setItem('trustlens_view', 'checker')
    sessionStorage.removeItem('trustlens_mod_nav')
    if (typeof window !== 'undefined') {
      window.history.replaceState(null, '', window.location.pathname + window.location.search)
    }
    setView('checker')
  }

  if (view === 'moderator') {
    return <ModeratorDashboard onBackToScanner={handleBackToScanner} />
  }

  return (
    <main className="app-shell">
      <nav className="nav">
        <span className="brand-mark">TL</span>
        <span className="brand" style={{ cursor: 'pointer' }} onClick={handleBackToScanner}>TrustLens <em>LK</em></span>
        <span className="nav-note">Scam decision support</span>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => {
              sessionStorage.setItem('trustlens_view', 'moderator')
              setView('moderator')
            }}
            style={{ fontSize: '12px', padding: '6px 14px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
          >
            <Shield size={14} aria-hidden="true" />
            <span>Moderator Portal</span>
          </button>
        </div>
      </nav>
      <>
        <section className="hero">
          <div className="hero-copy"><p className="eyebrow">Check before you act</p><h1>Does this message deserve your trust?</h1><p className="intro">Paste a suspicious message or link. TrustLens looks for warning signs and explains the safest next step.</p><div className="trust-points"><span>Evidence based</span><span>Private by default</span><span>Built for Sri Lanka</span></div></div>
          <div className="checker-card"><label htmlFor="message">Suspicious message or URL</label><textarea id="message" value={text} maxLength={10000} onChange={(event) => { setText(event.target.value); setChecked(false); setIntelligenceOverlay(null) }} placeholder="Example: Congratulations! You have been selected for a job. Pay Rs. 5,000 today and send your OTP..." /><div className="card-footer"><span>{text.length}/10,000 characters</span><button type="button" onClick={() => void checkMessage()} disabled={!text.trim() || isAnalyzing}>{isAnalyzing ? 'Checking...' : 'Check safely'}</button></div><p className="privacy-note">Do not include passwords, OTPs, or unnecessary private information.</p><small>Analysis: {apiMode === 'api' ? 'local API' : 'offline fallback'}</small></div>
        </section>
        {checked && (
          <section className={`result ${resultClass}`} aria-live="polite">
            <div className="result-header">
              <div>
                <p className="eyebrow">Your recommendation</p>
                <h2 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  {isOfficialEntity && <ShieldCheck size={28} color="#0f766e" aria-hidden="true" />}
                  {!isOfficialEntity && isVerifiedSafe && <ShieldCheck size={28} color="#057a55" aria-hidden="true" />}
                  {isConfirmedScam && <AlertOctagon size={28} color="#a33d31" aria-hidden="true" />}
                  {isConflicted && <AlertTriangle size={28} color="#b45309" aria-hidden="true" />}
                  {!isVerifiedSafe && !isConfirmedScam && !isConflicted && decision.riskBand === 'MEDIUM' && (
                    <AlertTriangle size={28} color="#b7791f" aria-hidden="true" />
                  )}
                  {risk}
                </h2>
              </div>
              <p className="result-action">{decision.recommendation.replaceAll('_', ' ')}</p>
            </div>

            {/* Contextual summary based on verdict */}
            <p className="result-summary">
              {isOfficialEntity
                ? `This domain is verified in the official Sri Lankan national registry as the digital property of ${intelligenceOverlay?.officialOrganization || 'an approved institution'}.`
                : isImpersonation
                  ? 'CRITICAL ALERT: Although this message references a verified entity, it requests credentials or advance payment. Threat actors frequently impersonate legitimate organizations.'
                  : isVerifiedSafe
                    ? 'This content has been reviewed and verified as legitimate by community moderators and the TrustLens intelligence network.'
                    : isConfirmedScam
                      ? 'This content matches confirmed threat intelligence verified by community moderators.'
                      : isConflicted
                        ? 'Community intelligence submissions are divided. Under fail-closed security policy, it is treated as HIGH RISK until resolved.'
                        : risk === 'High Risk'
                          ? 'This content contains strong indicators commonly associated with scams.'
                          : risk === 'Suspicious'
                            ? 'Some warning signs were found, but the available evidence is not conclusive.'
                            : 'No significant indicators were found in the submitted content.'}
            </p>

            {/* Intelligence Overlay Banner */}
            {intelligenceOverlay && intelligenceOverlay.netVerdict !== 'NO_INTEL' && (
              <div className={`intel-overlay ${intelligenceOverlay.netVerdict.toLowerCase().replace(/_/g, '-')}`}>
                <div className="intel-overlay-header">
                  {isOfficialEntity && <ShieldCheck size={18} aria-hidden="true" />}
                  {!isOfficialEntity && isVerifiedSafe && <ShieldCheck size={18} aria-hidden="true" />}
                  {isConfirmedScam && <AlertOctagon size={18} aria-hidden="true" />}
                  {isConflicted && <AlertTriangle size={18} aria-hidden="true" />}
                  <strong>
                    {intelligenceOverlay.netVerdict === 'OFFICIAL_ENTITY' && `National Registry — ${intelligenceOverlay.officialOrganization || 'Verified Official'}`}
                    {intelligenceOverlay.netVerdict === 'POSSIBLE_IMPERSONATION' && 'Impersonation Alert — Threat Override'}
                    {intelligenceOverlay.netVerdict === 'VERIFIED_SAFE' && 'Community Verified — Safe'}
                    {intelligenceOverlay.netVerdict === 'CONFIRMED_SCAM' && 'Threat Intelligence — Confirmed Scam'}
                    {intelligenceOverlay.netVerdict === 'CONFLICTED' && 'Conflicting Submissions — Fail-Closed Warning'}
                  </strong>
                  <span className="intel-confidence">
                    {isVerifiedSafe
                      ? `${Math.round(intelligenceOverlay.safeConfidence * 100)}% safe confidence`
                      : `${Math.round(intelligenceOverlay.scamConfidence * 100)}% scam confidence`}
                  </span>
                </div>

                {/* Community Consensus Bar (displayed when both safe and scam submissions exist) */}
                {Boolean((intelligenceOverlay.scamCount ?? 0) > 0 && (intelligenceOverlay.safeCount ?? 0) > 0) && (
                  <div className="consensus-meter">
                    <div className="consensus-bar-header">
                      <span>Community Consensus Ratio</span>
                      <span>{intelligenceOverlay.consensusSummary}</span>
                    </div>
                    <div className="consensus-bar-track">
                      <div
                        className="consensus-bar-safe"
                        style={{
                          width: `${Math.round(
                            ((intelligenceOverlay.safeCount ?? 0) /
                              ((intelligenceOverlay.safeCount ?? 0) + (intelligenceOverlay.scamCount ?? 0))) *
                            100
                          )}%`,
                        }}
                      />
                      <div
                        className="consensus-bar-scam"
                        style={{
                          width: `${Math.round(
                            ((intelligenceOverlay.scamCount ?? 0) /
                              ((intelligenceOverlay.safeCount ?? 0) + (intelligenceOverlay.scamCount ?? 0))) *
                            100
                          )}%`,
                        }}
                      />
                    </div>
                    <div className="consensus-labels">
                      <span className="safe-label">🛡️ {intelligenceOverlay.safeCount} Verified Safe</span>
                      <span className="scam-label">⚠️ {intelligenceOverlay.scamCount} Threat Reports</span>
                    </div>
                  </div>
                )}

                <div className="intel-trace">
                  {intelligenceOverlay.reconciliationTrace.map((line, i) => (
                    <p key={i}>{line}</p>
                  ))}
                </div>
              </div>
            )}

            {entities.length > 0 && <div className="entities"><div className="section-label">Detected details</div><div className="entity-list">{entities.map((entity, index) => <span className="entity" key={`${entity.type}-${index}`}><strong>{entity.type}</strong> {entity.type === 'url' ? entity.value.replace(/^https?:\/\//, 'hxxps://').replaceAll('.', '[.]') : entity.normalizedValue ?? entity.value}</span>)}</div></div>}
            {decision.findings.length ? <div className="findings">{decision.findings.map((finding, idx) => <article className="finding" key={`${finding.canonicalSignal}-${idx}`}><span className={`signal-dot ${finding.strength > .8 ? 'high' : finding.strength === 0.0 ? 'safe' : 'medium'}`}></span><div><strong>{finding.category}</strong><p>{finding.canonicalSignal.replaceAll('_', ' ')}</p><small>Evidence: {finding.evidence}</small></div></article>)}</div> : <p className="empty-finding">This does not guarantee that the content is safe. Verify important requests through an official channel.</p>}
            <div className="next-step"><strong>Recommended action</strong><span>{decision.safeActions[0]}</span></div>
            <CommunityReportBar onReportClick={() => setIsReportModalOpen(true)} />
          </section>
        )}
        <ReportModal isOpen={isReportModalOpen} onClose={() => setIsReportModalOpen(false)} content={text} reportedDomain={detectedDomain} />
      </>
      <footer><span>TrustLens LK</span><span>Rules and verified checks guide the recommendation.</span></footer>
    </main>
  )
}

export default App


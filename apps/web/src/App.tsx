import { useMemo, useState } from 'react'
import { Shield, ShieldCheck, AlertOctagon, AlertTriangle, MessageSquare, Camera } from 'lucide-react'
import { analyzeSubmission, analyzeWithApi, detectSubmissionType } from './services/analysisService'
import { CommunityReportBar } from './components/CommunityReportBar'
import { ReportModal } from './components/ReportModal'
import { ModeratorDashboard } from './components/ModeratorDashboard'
import { ScreenshotOcrUploader } from './components/ScreenshotOcrUploader'
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

// Breaks a domain or URL so it cannot be accidentally clicked or copied as a
// live link when shown in the result screen, per the project's rule that
// suspicious destinations are always defanged before display.
function defangDisplay(value: string): string {
  return value.replace(/^http/i, 'hxxp').replaceAll('.', '[.]')
}

function App() {
  const [view, setView] = useState<'checker' | 'moderator'>('checker')
  const [inputMode, setInputMode] = useState<'text' | 'screenshot'>('text')
  const [isReportModalOpen, setIsReportModalOpen] = useState(false)
  const [text, setText] = useState('')
  const [checked, setChecked] = useState(false)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [apiAnalysis, setApiAnalysis] = useState<ReturnType<typeof analyzeSubmission> | null>(null)
  const [apiMode, setApiMode] = useState<'local' | 'api'>('local')
  const [intelligenceOverlay, setIntelligenceOverlay] = useState<IntelligenceOverlay | null>(null)
  const [ocrConfidence, setOcrConfidence] = useState<number | null>(null)

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

  const checkMessage = async (overrideText?: string, typeOverride?: 'message' | 'url' | 'screenshot') => {
    const targetText = overrideText ?? text
    // A screenshot submission always keeps its explicit type. Otherwise,
    // detect whether the whole input is a bare URL rather than trusting the
    // stale submissionType state, so pasting just a link is actually checked
    // as a dedicated URL submission instead of always as a free-text message.
    const targetType = typeOverride ?? detectSubmissionType(targetText)
    if (!targetText.trim()) return

    setIsAnalyzing(true)
    setIntelligenceOverlay(null)
    try {
      const result = await analyzeWithApi(targetText, targetType)
      setApiAnalysis(result)
      setApiMode('api')
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

  const handleOcrConfirmed = (correctedText: string, confidence: number) => {
    setText(correctedText)
    setOcrConfidence(confidence)
    setChecked(false)
    void checkMessage(correctedText, 'screenshot')
  }

  const detectedDomain = entities.find((e) => e.type === 'url' || e.type === 'domain')?.value || null

  // Surfaces the domain identity check (Member 3's slice) distinctly from
  // the generic findings list below, since "who owns this domain" deserves a
  // clearer claimed-vs-actual comparison than a plain evidence card gives.
  const domainFinding = decision.findings.find(
    (finding) => finding.canonicalSignal === 'domain_mismatch' || finding.canonicalSignal === 'approved_domain',
  )
  const claimedOrganization = entities.find((entity) => entity.type === 'organization')?.value ?? null
  const actualDomain = entities.find((entity) => entity.type === 'domain')?.value ?? detectedDomain

  if (view === 'moderator') {
    return <ModeratorDashboard onBackToScanner={() => setView('checker')} />
  }

  return (
    <main className="app-shell">
      <nav className="nav">
        <span className="brand-mark">TL</span>
        <span className="brand" style={{ cursor: 'pointer' }} onClick={() => setView('checker')}>TrustLens <em>LK</em></span>
        <span className="nav-note">Scam decision support</span>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button type="button" className="btn-secondary" onClick={() => setView('moderator')} style={{ fontSize: '12px', padding: '6px 14px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
            <Shield size={14} aria-hidden="true" />
            <span>Moderator Portal</span>
          </button>
        </div>
      </nav>

      <>
        <section className="hero">
          <div className="hero-copy">
            <p className="eyebrow">Check before you act</p>
            <h1>Does this message deserve your trust?</h1>
            <p className="intro">Paste a suspicious message, URL link, or upload a screenshot. TrustLens looks for warning signs and explains the safest next step.</p>
            <div className="trust-points">
              <span>Evidence based</span>
              <span>Private by default</span>
              <span>Built for Sri Lanka</span>
            </div>
          </div>

          <div className="checker-card">
            {/* Input Mode Tabs */}
            <div className="input-mode-tabs" style={{ display: 'flex', gap: '8px', marginBottom: '14px' }}>
              <button
                type="button"
                className={`tab-btn ${inputMode === 'text' ? 'active' : ''}`}
                onClick={() => { setInputMode('text'); setOcrConfidence(null) }}
                style={{
                  padding: '8px 14px',
                  borderRadius: '6px',
                  border: inputMode === 'text' ? '1px solid #38bdf8' : '1px solid #334155',
                  background: inputMode === 'text' ? '#0369a1' : '#1e293b',
                  color: '#fff',
                  cursor: 'pointer',
                  fontSize: '13px',
                  fontWeight: 600,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <MessageSquare size={14} />
                Text / URL
              </button>

              <button
                type="button"
                className={`tab-btn ${inputMode === 'screenshot' ? 'active' : ''}`}
                onClick={() => setInputMode('screenshot')}
                style={{
                  padding: '8px 14px',
                  borderRadius: '6px',
                  border: inputMode === 'screenshot' ? '1px solid #38bdf8' : '1px solid #334155',
                  background: inputMode === 'screenshot' ? '#0369a1' : '#1e293b',
                  color: '#fff',
                  cursor: 'pointer',
                  fontSize: '13px',
                  fontWeight: 600,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <Camera size={14} />
                Upload Screenshot (OCR)
              </button>
            </div>

            {inputMode === 'screenshot' ? (
              <ScreenshotOcrUploader
                onTextConfirmed={handleOcrConfirmed}
                onCancel={() => setInputMode('text')}
              />
            ) : (
              <>
                <label htmlFor="message">Suspicious message or URL</label>
                <textarea
                  id="message"
                  value={text}
                  maxLength={10000}
                  onChange={(event) => {
                    setText(event.target.value)
                    setChecked(false)
                    setIntelligenceOverlay(null)
                    setOcrConfidence(null)
                  }}
                  placeholder="Example: Congratulations! You have been selected for a job. Pay Rs. 5,000 today and send your OTP..."
                />
                <div className="card-footer">
                  <span>{text.length}/10,000 characters</span>
                  <button
                    type="button"
                    onClick={() => void checkMessage()}
                    disabled={!text.trim() || isAnalyzing}
                  >
                    {isAnalyzing ? 'Checking...' : 'Check safely'}
                  </button>
                </div>
              </>
            )}

            <p className="privacy-note">Do not include passwords, OTPs, or unnecessary private information.</p>
            <small>
              Analysis: {apiMode === 'api' ? 'local API' : 'offline fallback'}
              {ocrConfidence !== null && ` | OCR Confidence: ${ocrConfidence}%`}
            </small>
          </div>
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

            {intelligenceOverlay && intelligenceOverlay.netVerdict !== 'NO_INTEL' && (
              <div className={`intel-overlay ${intelligenceOverlay.netVerdict.toLowerCase().replace(/_/g, '-')}`}>
                <div className="intel-summary">
                  <strong>Community Consensus:</strong> {intelligenceOverlay.consensusSummary}
                </div>
                {intelligenceOverlay.reconciliationTrace.length > 0 && (
                  <details className="intel-trace-details">
                    <summary>View Audit Trace ({intelligenceOverlay.reconciliationTrace.length} steps)</summary>
                    <ul>
                      {intelligenceOverlay.reconciliationTrace.map((step, idx) => (
                        <li key={idx}>{step}</li>
                      ))}
                    </ul>
                  </details>
                )}
              </div>
            )}

            {domainFinding && (
              <div
                className={`domain-evidence ${domainFinding.canonicalSignal === 'domain_mismatch' ? 'mismatch' : 'matched'}`}
                style={{
                  border: `1px solid ${domainFinding.canonicalSignal === 'domain_mismatch' ? '#dc2626' : '#16a34a'}`,
                  borderRadius: '8px',
                  padding: '14px 16px',
                  margin: '16px 0',
                  background: domainFinding.canonicalSignal === 'domain_mismatch' ? 'rgba(220,38,38,0.08)' : 'rgba(22,163,74,0.08)',
                }}
              >
                <h3 style={{ margin: '0 0 8px', fontSize: '14px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  {domainFinding.canonicalSignal === 'domain_mismatch' ? (
                    <AlertOctagon size={16} color="#dc2626" aria-hidden="true" />
                  ) : (
                    <ShieldCheck size={16} color="#16a34a" aria-hidden="true" />
                  )}
                  Domain identity check
                </h3>
                <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap', fontSize: '13px', marginBottom: '8px' }}>
                  {claimedOrganization && (
                    <div>
                      <strong>Claims to be:</strong> {claimedOrganization}
                    </div>
                  )}
                  {actualDomain && (
                    <div>
                      <strong>Actual destination:</strong> <code>{defangDisplay(actualDomain)}</code>
                    </div>
                  )}
                </div>
                <p style={{ margin: 0, fontSize: '13px' }}>{domainFinding.evidence}</p>
              </div>
            )}

            <div className="result-grid">
              <div className="findings">
                <h3>Detected signals ({decision.findings.length})</h3>
                {decision.findings.length === 0 && <p className="empty-state">No explicit scam indicators matched standard rules.</p>}
                {decision.findings.map((finding, idx) => (
                  <article key={`${finding.canonicalSignal}-${idx}`} className="finding-card">
                    <header>
                      <span className="signal">{finding.canonicalSignal}</span>
                      <span className="source">{finding.source}</span>
                    </header>
                    <p className="evidence">"{finding.evidence}"</p>
                    <small className="category">{finding.category}</small>
                    {finding.limitation && <p className="limitation">{finding.limitation}</p>}
                  </article>
                ))}
              </div>

              <div className="actions">
                <h3>Recommended safe actions</h3>
                <ul>
                  {decision.safeActions.map((actionItem, index) => (
                    <li key={index}>{actionItem}</li>
                  ))}
                </ul>

                {decision.limitations.length > 0 && (
                  <div className="limitations-box">
                    <h4>System Knowledge Limits</h4>
                    <ul>
                      {decision.limitations.map((limit, idx) => (
                        <li key={idx}>{limit}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          </section>
        )}
      </>

      <CommunityReportBar onReportClick={() => setIsReportModalOpen(true)} />
      <ReportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        content={text}
        reportedDomain={detectedDomain}
      />
    </main>
  )
}

export default App

import { useMemo, useState } from 'react'
import { analyzeSubmission, analyzeWithApi, submitReport } from './services/analysisService'
import type { ReportType } from './services/analysisService'
import './App.css'

function App() {
  const [text, setText] = useState('')
  const [checked, setChecked] = useState(false)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [apiAnalysis, setApiAnalysis] = useState<ReturnType<typeof analyzeSubmission> | null>(null)
  const [apiMode, setApiMode] = useState<'local' | 'api'>('local')

  // Report state
  const [reportOpen, setReportOpen] = useState(false)
  const [reportType, setReportType] = useState<ReportType>('suspicious')
  const [reportNotes, setReportNotes] = useState('')
  const [isReporting, setIsReporting] = useState(false)
  const [reportState, setReportState] = useState<'idle' | 'success' | 'error'>('idle')

  const analysis = useMemo(() => analyzeSubmission(text), [text])
  const { decision, entities } = apiAnalysis ?? analysis
  const risk = decision.riskBand === 'HIGH' ? 'High Risk' : decision.riskBand === 'MEDIUM' ? 'Suspicious' : 'Likely Safe'

  const checkMessage = async () => {
    setIsAnalyzing(true)
    setChecked(false)
    setReportOpen(false)
    setReportState('idle')
    try {
      const result = await analyzeWithApi(text)
      setApiAnalysis(result)
      setApiMode('api')
    } catch {
      setApiAnalysis(null)
      setApiMode('local')
    } finally {
      setChecked(true)
      setIsAnalyzing(false)
    }
  }

  const handleReport = async () => {
    setIsReporting(true)
    setReportState('idle')
    // Extract first domain entity if present
    const domainEntity = entities.find((e) => e.type === 'domain')
    try {
      await submitReport(text, reportType, reportNotes, domainEntity?.value)
      setReportState('success')
      setReportOpen(false)
      setReportNotes('')
    } catch {
      setReportState('error')
    } finally {
      setIsReporting(false)
    }
  }

  return (
    <main className="app-shell">
      <nav className="nav">
        <span className="brand-mark">TL</span>
        <span className="brand">TrustLens <em>LK</em></span>
        <span className="nav-note">Scam decision support</span>
      </nav>

      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">Check before you act</p>
          <h1>Does this message deserve your trust?</h1>
          <p className="intro">Paste a suspicious message or link. TrustLens looks for warning signs and explains the safest next step.</p>
          <div className="trust-points">
            <span>Evidence based</span>
            <span>Private by default</span>
            <span>Built for Sri Lanka</span>
          </div>
        </div>

        <div className="checker-card">
          <label htmlFor="message">Suspicious message or URL</label>
          <textarea
            id="message"
            value={text}
            maxLength={10000}
            onChange={(e) => { setText(e.target.value); setChecked(false); setReportOpen(false); setReportState('idle') }}
            placeholder="Example: Congratulations! You have been selected for a job. Pay Rs. 5,000 today and send your OTP..."
          />
          <div className="card-footer">
            <span>{text.length}/10,000 characters</span>
            <button type="button" id="check-btn" onClick={() => void checkMessage()} disabled={!text.trim() || isAnalyzing}>
              {isAnalyzing ? 'Checking…' : 'Check safely'}
            </button>
          </div>
          <p className="privacy-note">Do not include passwords, OTPs, or unnecessary private information.</p>
          <small>Analysis: {apiMode === 'api' ? 'live API' : 'offline fallback'}</small>
        </div>
      </section>

      {checked && (
        <section className={`result ${risk.toLowerCase().replace(' ', '-')}`} aria-live="polite">
          <div className="result-header">
            <div>
              <p className="eyebrow">Your recommendation</p>
              <h2>{risk}</h2>
            </div>
            <p className="result-action">{decision.recommendation.replaceAll('_', ' ')}</p>
          </div>

          <p className="result-summary">
            {risk === 'High Risk'
              ? 'This content contains strong indicators commonly associated with scams.'
              : risk === 'Suspicious'
                ? 'Some warning signs were found, but the available evidence is not conclusive.'
                : 'No significant indicators were found in the submitted content.'}
          </p>

          {entities.length > 0 && (
            <div className="entities">
              <div className="section-label">Detected details</div>
              <div className="entity-list">
                {entities.map((entity, index) => (
                  <span className="entity" key={`${entity.type}-${index}`}>
                    <strong>{entity.type}</strong>{' '}
                    {entity.type === 'url'
                      ? entity.value.replace(/^https?:\/\//, 'hxxps://').replaceAll('.', '[.]')
                      : (entity.normalizedValue ?? entity.value)}
                  </span>
                ))}
              </div>
            </div>
          )}

          {decision.findings.length ? (
            <div className="findings">
              {decision.findings.map((finding) => (
                <article className="finding" key={finding.canonicalSignal}>
                  <span className={`signal-dot ${finding.strength > 0.8 ? 'high' : 'medium'}`} />
                  <div>
                    <strong>{finding.category}</strong>
                    <p>{finding.canonicalSignal.replaceAll('_', ' ')}</p>
                    <small>Evidence: {finding.evidence}</small>
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <p className="empty-finding">This does not guarantee that the content is safe. Verify important requests through an official channel.</p>
          )}

          <div className="next-step">
            <strong>Recommended action</strong>
            <span>{decision.safeActions[0]}</span>
          </div>

          {/* Report section */}
          <div className="report-section">
            {reportState === 'success' && (
              <p className="report-success">✓ Thank you — your report has been submitted for review.</p>
            )}
            {reportState === 'error' && (
              <p className="report-error">Report could not be submitted. Please try again later.</p>
            )}
            {reportState === 'idle' && !reportOpen && (
              <button type="button" id="report-btn" className="report-toggle" onClick={() => setReportOpen(true)}>
                Report this content
              </button>
            )}
            {reportOpen && reportState === 'idle' && (
              <div className="report-form">
                <p className="report-form-title">Report this content</p>
                <div className="report-types">
                  {(['suspicious', 'false_positive', 'false_negative'] as ReportType[]).map((type) => (
                    <label key={type} className={`report-type-label ${reportType === type ? 'active' : ''}`}>
                      <input
                        type="radio"
                        name="reportType"
                        value={type}
                        checked={reportType === type}
                        onChange={() => setReportType(type)}
                      />
                      {type === 'suspicious' ? 'It\'s a scam' : type === 'false_positive' ? 'False alarm' : 'Missed a scam'}
                    </label>
                  ))}
                </div>
                <textarea
                  className="report-notes"
                  placeholder="Optional: add any context or notes (max 2,000 characters)"
                  maxLength={2000}
                  value={reportNotes}
                  onChange={(e) => setReportNotes(e.target.value)}
                />
                <p className="report-privacy">Your report is reviewed by our team before it affects any analysis. No personal data is stored.</p>
                <div className="report-actions">
                  <button type="button" id="cancel-report-btn" className="report-cancel" onClick={() => { setReportOpen(false); setReportNotes('') }}>
                    Cancel
                  </button>
                  <button type="button" id="submit-report-btn" className="report-submit" onClick={() => void handleReport()} disabled={isReporting}>
                    {isReporting ? 'Submitting…' : 'Submit report'}
                  </button>
                </div>
              </div>
            )}
          </div>
        </section>
      )}

      <footer>
        <span>TrustLens LK</span>
        <span>Rules and verified checks guide the recommendation.</span>
      </footer>
    </main>
  )
}

export default App

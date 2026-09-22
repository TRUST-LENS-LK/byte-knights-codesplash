import { useMemo, useState, useEffect, useRef } from 'react'
import {
  ShieldCheck,
  ShieldAlert,
  AlertOctagon,
  AlertTriangle,
  Globe,
  Lock,
  CreditCard,
  Mail,
  FileText,
  Zap,
  X,
  Info,
  Terminal,
  Copy,
  Check,
  Eye,
  Activity,
  Layers,
  Building2,
  Maximize2,
  Radio,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  Flag,
  CheckCircle2,
} from 'lucide-react'
import { analyzeSubmission, analyzeWithApi, detectSubmissionType, normalizeUrlInput } from './services/analysisService'
import { ScreenshotOcrUploader } from './components/ScreenshotOcrUploader'
import { Camera } from 'lucide-react'
import { ReportModal } from './components/ReportModal'
import { ModeratorDashboard } from './components/ModeratorDashboard'
import './App.css'
import './components/NavSentinelDock.css'

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

interface ScannerEvidenceItem {
  url?: string
  forms?: number
  loginForms?: number
  passwordFields?: number
  paymentFields?: number
  emailFields?: number
  externalDomains?: string[]
  screenshotBase64?: string
}


function App() {
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', 'light')
    try {
      localStorage.setItem('tl-theme', 'light')
    } catch {
      /* ignore */
    }
  }, [])

  const [view, setView] = useState<'checker' | 'moderator'>('checker')
  const [isReportModalOpen, setIsReportModalOpen] = useState(false)
  const [text, setText] = useState('')
  const [checked, setChecked] = useState(false)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [apiAnalysis, setApiAnalysis] = useState<ReturnType<typeof analyzeSubmission> | null>(null)
  const [apiMode, setApiMode] = useState<'local' | 'api'>('local')
  const [inputType, setInputType] = useState<'message' | 'screenshot'>('message')
  const [intelligenceOverlay, setIntelligenceOverlay] = useState<IntelligenceOverlay | null>(null)

  // Results Dashboard Tabs & UI states (defaults to 'all' so users see complete evidence at once)
  const [activeTab, setActiveTab] = useState<'all' | 'signals' | 'sandbox' | 'intel'>('all')
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [selectedScreenshot, setSelectedScreenshot] = useState<string | null>(null)
  const [showTechnicalTrace, setShowTechnicalTrace] = useState(false)

  const resultRef = useRef<HTMLElement>(null)

  const analysis = useMemo(() => analyzeSubmission(text), [text])
  const activeResult = apiAnalysis ?? analysis
  const { decision, entities } = activeResult
  const scannerEvidence = (activeResult as { scannerEvidence?: ScannerEvidenceItem[] }).scannerEvidence

  // Determine display risk and state classes
  const isOfficialEntity = intelligenceOverlay?.netVerdict === 'OFFICIAL_ENTITY'
  const isVerifiedSafe =
    (intelligenceOverlay?.netVerdict === 'VERIFIED_SAFE' && (decision.recommendation as string) === 'VERIFIED_SAFE') ||
    isOfficialEntity
  const isImpersonation = intelligenceOverlay?.netVerdict === 'POSSIBLE_IMPERSONATION'
  const isConfirmedScam = intelligenceOverlay?.netVerdict === 'CONFIRMED_SCAM' || isImpersonation
  const isConflicted = intelligenceOverlay?.netVerdict === 'CONFLICTED'

  const risk = isOfficialEntity
    ? 'Official Verified Entity'
    : isVerifiedSafe
      ? 'Verified Safe Service'
      : isImpersonation
        ? 'Critical Risk — Spoofing Attack'
        : isConflicted
          ? 'Disputed / High Risk Alert'
          : decision.riskBand === 'HIGH' || isConfirmedScam
            ? 'High Threat — Phishing Detected'
            : decision.riskBand === 'MEDIUM'
              ? 'Suspicious Activity Warning'
              : 'Low Risk — Likely Safe'

  const verdictVariantClass = isOfficialEntity
    ? 'official-entity'
    : isVerifiedSafe
      ? 'verified-safe'
      : isConflicted
        ? 'conflicted'
        : decision.riskBand === 'HIGH' || isConfirmedScam
          ? 'high-risk'
          : decision.riskBand === 'MEDIUM'
            ? 'suspicious'
            : 'verified-safe'

  const checkMessage = async (overrideText?: string, typeOverride?: 'message' | 'url' | 'screenshot') => {
    let targetText = overrideText ?? text
    if (!targetText.trim()) return
    
    let finalType: 'message' | 'url' | 'screenshot' = 'message'
    
    if (typeOverride) {
      finalType = typeOverride
    } else if (inputType === 'screenshot') {
      finalType = 'screenshot'
    } else {
      const trimmed = targetText.trim()
      const isUrlLike = detectSubmissionType(trimmed) === 'url' || /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/.*)?$/.test(trimmed)
      if (isUrlLike && !/\s/.test(trimmed)) {
        targetText = normalizeUrlInput(trimmed)
        finalType = 'url'
      }
    }

    setIsAnalyzing(true)
    setIntelligenceOverlay(null)
    try {
      const result = await analyzeWithApi(targetText, finalType)
      setApiAnalysis(result)
      setApiMode('api')
      if ((result as Record<string, unknown>).intelligenceOverlay) {
        setIntelligenceOverlay((result as Record<string, unknown>).intelligenceOverlay as IntelligenceOverlay)
      }
      setChecked(true)
      setActiveTab('signals')
      setTimeout(() => {
        resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
      }, 100)
    } catch {
      setApiAnalysis(null)
      setApiMode('local')
      setChecked(true)
      setActiveTab('signals')
      setTimeout(() => {
        resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
      }, 100)
    } finally {
      setIsAnalyzing(false)
    }
  }

  const detectedDomain = entities.find((e) => e.type === 'url' || e.type === 'domain')?.value || null

  const defangUrl = (val: string) => {
    return val.replace(/^https?:\/\//, 'hxxps://').replaceAll('.', '[.]')
  }

  const handleCopy = (content: string, key: string) => {
    navigator.clipboard.writeText(content).then(() => {
      setCopiedKey(key)
      setTimeout(() => setCopiedKey(null), 2000)
    }).catch(() => {
      /* clipboard write rejected */
    })
  }

  const hasScreenshot = Boolean(scannerEvidence?.some((ev) => Boolean(ev.screenshotBase64)))

  // Clean, professional formatting for limitations (filters out raw call stack dumps)
  const sanitizedLimitations = useMemo(() => {
    const raw = ((decision as Record<string, unknown>).limitations as string[]) || []
    const clean: string[] = []
    const seen = new Set<string>()

    for (const item of raw) {
      if (!item) continue
      // If it's a raw Playwright stack trace or call log
      if (item.includes('Call log:') || item.includes('page.goto:') || item.includes('net::ERR_')) {
        const summary = 'Target domain could not be resolved or reached via public DNS (characteristic of disposable or inactive phishing hosts).'
        if (!seen.has(summary)) {
          clean.push(summary)
          seen.add(summary)
        }
        continue
      }
      if (item.includes('chrome-error:') || item.includes('net::ERR_NAME_NOT_RESOLVED')) {
        continue
      }
      if (!seen.has(item)) {
        clean.push(item)
        seen.add(item)
      }
    }
    return clean
  }, [decision])

  if (view === 'moderator') {
    return <ModeratorDashboard onBackToScanner={() => setView('checker')} />
  }

  return (
    <main className="app-shell">
      {/* ── Minimal Clean Navigation Header ────────────────────────── */}
      <header className="nav-header">
        <div
          className="nav-brand"
          onClick={() => setView('checker')}
          title="TrustLens LK"
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter') setView('checker')
          }}
        >
          <div className="nav-logo-box">
            <img src="/TrustLens_Icon.png" alt="TrustLens LK" className="nav-logo-img" />
          </div>
          <div className="nav-brand-title">
            TrustLens <span className="nav-brand-badge">LK</span>
          </div>
        </div>

        <div className="nav-actions">
          <button
            type="button"
            className="nav-btn-portal"
            onClick={() => setView('moderator')}
            title="Moderator Portal"
          >
            <ShieldCheck size={16} />
            <span>Moderator Portal</span>
          </button>
        </div>
      </header>

      {/* ── Hero Section & Analysis Console ───────────────────────── */}
      <section className="hero">
        <div className="hero-copy">
          <div className="hero-eyebrow">
            <Zap size={13} />
            <span>Sri Lanka National Scam Defense</span>
          </div>
          <h1>Does this message deserve your trust?</h1>
          <p className="hero-description">
            Verify suspicious SMS, WhatsApp messages, payment requests, or links. TrustLens executes deterministic NLP rules, live headless browser sandbox DOM inspection, and threat intelligence.
          </p>
          <div className="hero-features">
            <span className="feature-tag">🛡️ Anti-SSRF Browser Sandbox</span>
            <span className="feature-tag">⚡ Zero AI Hallucination</span>
            <span className="feature-tag">🔒 Private by Default</span>
            <span className="feature-tag">🇱🇰 Sinhala/Tamil/EN Heuristics</span>
          </div>
        </div>

        {/* Input Console Card */}
        <div className="console-card">
          <div className="console-card-header">
            <div className="console-label-row">
              <span className="console-label">Suspicious Message or Link</span>
              {text.trim() && (
                <button
                  type="button"
                  className="clear-btn"
                  onClick={() => {
                    setText('')
                    setChecked(false)
                    setIntelligenceOverlay(null)
                  }}
                >
                  <X size={12} style={{ marginRight: 3, verticalAlign: 'middle' }} />
                  Clear
                </button>
              )}
            </div>
          </div>

          <div className="input-mode-tabs">
            <button
              type="button"
              className={`input-mode-tab ${inputType === 'message' ? 'active' : ''}`}
              onClick={() => setInputType('message')}
            >
              <FileText size={15} />
              <span>Text / URL</span>
            </button>
            <button
              type="button"
              className={`input-mode-tab ${inputType === 'screenshot' ? 'active' : ''}`}
              onClick={() => setInputType('screenshot')}
            >
              <Camera size={15} />
              <span>Upload Screenshot (OCR)</span>
            </button>
          </div>
          {inputType === 'screenshot' && (
            <ScreenshotOcrUploader 
              onTextConfirmed={(ocrText) => {
                setText(ocrText)
              }}
            />
          )}
          {inputType === 'message' && (
            <div className="textarea-wrapper">
            <textarea
              id="message"
              className="console-textarea"
              value={text}
              maxLength={10000}
              onChange={(e) => {
                setText(e.target.value)
                setChecked(false)
                setIntelligenceOverlay(null)
              }}
              placeholder="Paste SMS, WhatsApp forward, email body, or suspicious URL here..."
            />
          </div>
          )}

          <div className="console-card-footer">
            <div className="console-meta">
              <span className="char-counter">{text.length.toLocaleString()} / 10,000 characters</span>
              <span className="privacy-badge">
                <Info size={12} />
                <span>No passwords or private OTPs will ever be logged. ({apiMode === 'api' ? 'Sandbox API' : 'Local Analysis'})</span>
              </span>
            </div>
            <button
              type="button"
              className="btn-scan"
              onClick={() => void checkMessage()}
              disabled={!text.trim() || isAnalyzing}
            >
              {isAnalyzing ? (
                <>
                  <span className="spinner" />
                  <span>Inspecting Sandbox...</span>
                </>
              ) : (
                <>
                  <ShieldCheck size={17} />
                  <span>Analyze Safely</span>
                </>
              )}
            </button>
          </div>
        </div>
      </section>

      {/* ══════════════════════════════════════════════════════════════
          Executive Threat Results Dashboard
         ══════════════════════════════════════════════════════════════ */}
      {checked && (
        <section ref={resultRef} id="results-dashboard" className="result-section" aria-live="polite">
          
          {/* ── 1. The Command Center Verdict Banner ────────────────── */}
          <div className={`command-verdict-banner ${verdictVariantClass}`}>
            
            {/* Top Meta Strip */}
            <div className="command-banner-top">
              <div className="command-status-badge">
                <span className="status-beacon" />
                <span className="status-badge-text">
                  {isOfficialEntity && 'GOVERNMENT REGISTRY VERIFIED'}
                  {!isOfficialEntity && isVerifiedSafe && 'VERIFIED SAFE CONTENT'}
                  {isImpersonation && 'CRITICAL: SPOOFING DETECTED'}
                  {isConflicted && 'DISPUTED THREAT SIGNALS'}
                  {!isOfficialEntity && !isVerifiedSafe && !isImpersonation && !isConflicted && (decision.riskBand === 'HIGH' || isConfirmedScam) && 'CRITICAL: PHISHING THREAT DETECTED'}
                  {!isOfficialEntity && !isVerifiedSafe && !isImpersonation && !isConflicted && decision.riskBand === 'MEDIUM' && 'ACTION REQUIRED: SUSPICIOUS ACTIVITY'}
                  {!isOfficialEntity && !isVerifiedSafe && !isImpersonation && !isConflicted && decision.riskBand === 'LOW' && 'VERIFIED LEGITIMATE'}
                </span>
              </div>

              {detectedDomain && (
                <div className="target-domain-badge">
                  <Globe size={13} />
                  <span className="target-domain-label">Target:</span>
                  <span className="target-domain-val">{defangUrl(detectedDomain)}</span>
                  <button
                    type="button"
                    className="copy-chip-btn"
                    onClick={() => handleCopy(defangUrl(detectedDomain), 'target-url')}
                    title="Copy Defanged URL"
                  >
                    {copiedKey === 'target-url' ? <Check size={12} color="#059669" /> : <Copy size={12} />}
                  </button>
                </div>
              )}

              <div className="engine-meta-pill">
                <span>Anti-SSRF Sandbox • Deterministic NLP v2</span>
              </div>
            </div>

            {/* Main Headline & Verdict Card Row */}
            <div className="command-banner-body">
              <div className="verdict-icon-container">
                {isOfficialEntity && <ShieldCheck size={36} />}
                {!isOfficialEntity && isVerifiedSafe && <ShieldCheck size={36} />}
                {(isConfirmedScam || decision.riskBand === 'HIGH') && <AlertOctagon size={36} />}
                {(isConflicted || decision.riskBand === 'MEDIUM') && !isConfirmedScam && <AlertTriangle size={36} />}
                {!isOfficialEntity && !isVerifiedSafe && !isConfirmedScam && decision.riskBand !== 'HIGH' && decision.riskBand !== 'MEDIUM' && (
                  <ShieldCheck size={36} />
                )}
              </div>

              <div className="verdict-headline-group">
                <span className="verdict-subheading">Assessment Clearance</span>
                <h2 className="verdict-primary-title">{risk}</h2>
                <p className="verdict-explanation">
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
                            : decision.riskBand === 'HIGH'
                              ? 'This message contains aggressive social engineering or deceptive patterns typical of online financial fraud.'
                              : decision.riskBand === 'MEDIUM'
                                ? 'Several warning signs were detected. The sender or link should not be trusted without independent phone verification.'
                                : 'No active phishing, OTP harvesting, or extortion signatures were identified.'}
                </p>
              </div>

              {/* Action Directive Strip */}
              <div className="verdict-cta-group">
                <div className="verdict-recommendation-tag">
                  {decision.recommendation.replaceAll('_', ' ')}
                </div>
                <button
                  type="button"
                  className="btn-banner-report"
                  onClick={() => setIsReportModalOpen(true)}
                >
                  <Flag size={13} />
                  <span>Flag or Report</span>
                </button>
              </div>
            </div>

            {/* High-Contrast Action Callout */}
            {decision.safeActions && decision.safeActions.length > 0 && (
              <div className="verdict-immediate-action">
                <div className="action-callout-header">
                  <Zap size={14} className="action-zap-icon" />
                  <span className="action-callout-label">Immediate Protective Directive</span>
                </div>
                <p className="action-callout-text">{decision.safeActions[0]}</p>
              </div>
            )}

            {/* At-A-Glance Stat Pills Row */}
            <div className="command-banner-stats">
              <div className="stat-pill">
                <span className="stat-label">Threat Band</span>
                <span className="stat-value">{decision.riskBand}</span>
              </div>
              <div className="stat-pill">
                <span className="stat-label">Flagged Signals</span>
                <span className="stat-value">{decision.findings.length} Flagged</span>
              </div>
              <div className="stat-pill">
                <span className="stat-label">Browser Sandbox</span>
                <span className="stat-value">
                  {hasScreenshot ? '📸 DOM Screenshot Captured' : scannerEvidence?.length ? 'Isolated DOM Inspected' : 'Text Analysis Active'}
                </span>
              </div>
              <div className="stat-pill">
                <span className="stat-label">Registry Match</span>
                <span className="stat-value">
                  {isOfficialEntity ? 'Approved National Entity' : 'Unregistered Source'}
                </span>
              </div>
            </div>

          </div>

          {/* ── 2. Segmented Navigation Tabs ─────────────────────────── */}
          <div className="dashboard-tabs-container">
            <nav className="dashboard-tabs" aria-label="Analysis Details Tabs">
              <button
                type="button"
                className={`tab-btn ${activeTab === 'all' ? 'active' : ''}`}
                onClick={() => setActiveTab('all')}
              >
                <Layers size={16} />
                <span>All Evidence (Overview)</span>
              </button>

              <button
                type="button"
                className={`tab-btn ${activeTab === 'signals' ? 'active' : ''}`}
                onClick={() => setActiveTab('signals')}
              >
                <Activity size={16} />
                <span>Threat Signals</span>
                <span className="tab-counter">{decision.findings.length}</span>
              </button>

              <button
                type="button"
                className={`tab-btn ${activeTab === 'sandbox' ? 'active' : ''}`}
                onClick={() => setActiveTab('sandbox')}
              >
                <Terminal size={16} />
                <span>Safe Browser Sandbox</span>
                {hasScreenshot ? (
                  <span className="tab-badge-pill green">📸 Proof</span>
                ) : (
                  <span className="tab-counter">{scannerEvidence?.length ?? 0}</span>
                )}
              </button>

              <button
                type="button"
                className={`tab-btn ${activeTab === 'intel' ? 'active' : ''}`}
                onClick={() => setActiveTab('intel')}
              >
                <Building2 size={16} />
                <span>National Intel & Consensus</span>
                {intelligenceOverlay && intelligenceOverlay.netVerdict !== 'NO_INTEL' && (
                  <span className="tab-badge-pill purple">Live Intel</span>
                )}
              </button>
            </nav>
          </div>

          {/* ── 3. Tab Contents ───────────────────────────────────────── */}
          <div className="dashboard-content-area">

            {/* ── TAB 1: THREAT SIGNALS & EXTRACTED IOCS ─────────────── */}
            {(activeTab === 'all' || activeTab === 'signals') && (
              <div className="tab-pane active" id="tab-signals">
                {activeTab === 'all' && (
                  <div className="section-overview-header">
                    <div className="section-overview-title">
                      <Activity size={18} color="var(--brand-primary)" />
                      <h3>Pillar 1: Threat Signals & Extracted Indicators</h3>
                    </div>
                    <span className="section-overview-badge">
                      {decision.findings.length} Flagged Pattern{decision.findings.length === 1 ? '' : 's'}
                    </span>
                  </div>
                )}
                <div className="tab-grid-layout">
                  {/* Left Column: Flagged Behavioral Signals */}
                  <div className="pane-column-main">
                    <div className="pane-card">
                      <div className="pane-card-header">
                        <div className="pane-title-group">
                          <Activity size={18} color="var(--brand-primary)" />
                          <h3>Heuristic Detection Signals</h3>
                        </div>
                        <span className="pane-meta-tag">
                          {decision.findings.length} pattern{decision.findings.length === 1 ? '' : 's'} matched
                        </span>
                      </div>

                      {decision.findings.length > 0 ? (
                        <div className="signals-list">
                          {decision.findings.map((finding, idx) => (
                            <div className="signal-card-item" key={`${finding.canonicalSignal}-${idx}`}>
                              <div className="signal-item-top">
                                <span className="signal-category-pill">{finding.category}</span>
                                <span
                                  className={`signal-threat-pill ${
                                    finding.strength > 0.8
                                      ? 'high'
                                      : finding.strength === 0.0
                                        ? 'safe'
                                        : 'warning'
                                  }`}
                                >
                                  {finding.strength > 0.8 ? 'Critical Threat' : finding.strength === 0.0 ? 'Safe Signal' : 'Warning'}
                                </span>
                              </div>

                              <div className="signal-name-row">
                                <span className="signal-canonical-name">
                                  {finding.canonicalSignal.replaceAll('_', ' ')}
                                </span>
                              </div>

                              <div className="signal-evidence-quote">
                                <span className="quote-label">Observed text evidence:</span>
                                <p className="quote-content">"{finding.evidence}"</p>
                              </div>

                              {finding.limitation && (
                                <p className="signal-explanation-text">
                                  <strong>Security Note: </strong>{finding.limitation}
                                </p>
                              )}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="empty-state-card">
                          <CheckCircle2 size={32} color="var(--risk-safe)" />
                          <h4>No Malicious Patterns Detected</h4>
                          <p>The message does not contain known fraud signatures, OTP theft triggers, or high-risk advance fee patterns.</p>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Right Column: Extracted Indicators of Compromise (IOCs) */}
                  <div className="pane-column-side">
                    <div className="pane-card">
                      <div className="pane-card-header">
                        <div className="pane-title-group">
                          <Globe size={18} color="var(--brand-secondary)" />
                          <h3>Extracted Indicators (IOCs)</h3>
                        </div>
                        <span className="pane-meta-tag">{entities.length} items</span>
                      </div>

                      {entities.length > 0 ? (
                        <div className="ioc-cards-grid">
                          {entities.map((entity, index) => {
                            const isUrl = entity.type === 'url'
                            const displayVal = isUrl ? defangUrl(entity.value) : String(entity.normalizedValue ?? entity.value)
                            const copyKey = `entity-${index}`

                            return (
                              <div className="ioc-card-item" key={copyKey}>
                                <div className="ioc-item-header">
                                  <span className={`ioc-entity-badge ${entity.type}`}>{entity.type}</span>
                                  <button
                                    type="button"
                                    className="ioc-copy-btn"
                                    onClick={() => handleCopy(displayVal, copyKey)}
                                    title="Copy indicator value"
                                  >
                                    {copiedKey === copyKey ? (
                                      <span className="copied-tag"><Check size={11} /> Copied</span>
                                    ) : (
                                      <span className="copy-tag"><Copy size={11} /> Copy</span>
                                    )}
                                  </button>
                                </div>
                                <span className="ioc-value-code">{displayVal}</span>
                              </div>
                            )
                          })}
                        </div>
                      ) : (
                        <div className="empty-ioc-box">
                          <span>No URLs, phone numbers, or amounts detected in input.</span>
                        </div>
                      )}
                    </div>

                    {/* Community Report Prompt Card */}
                    <div className="community-shield-card">
                      <div className="shield-icon-badge">
                        <ShieldAlert size={20} color="var(--brand-primary)" />
                      </div>
                      <div className="shield-card-body">
                        <h4>Sri Lanka Community Defense</h4>
                        <p>Have information regarding this sender or noticed an active scam? Help safeguard citizens across Sri Lanka by reporting.</p>
                        <button
                          type="button"
                          className="btn-community-report"
                          onClick={() => setIsReportModalOpen(true)}
                        >
                          <Flag size={14} />
                          <span>Submit Community Report</span>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* ── TAB 2: LIVE BROWSER SANDBOX & PROOF ───────────────── */}
            {(activeTab === 'all' || activeTab === 'sandbox') && (
              <div className="tab-pane active" id="tab-sandbox" style={activeTab === 'all' ? { marginTop: '28px' } : undefined}>
                {activeTab === 'all' && (
                  <div className="section-overview-header">
                    <div className="section-overview-title">
                      <Terminal size={18} color="var(--brand-secondary)" />
                      <h3>Pillar 2: Safe Browser Sandbox & Visual Proof</h3>
                    </div>
                    <span className="section-overview-badge">
                      {hasScreenshot ? '📸 DOM Screenshot Captured' : scannerEvidence?.length ? 'Isolated DOM Inspected' : 'Text Analysis Active'}
                    </span>
                  </div>
                )}
                {scannerEvidence && scannerEvidence.length > 0 ? (
                  <div className="sandbox-panel">
                    {scannerEvidence.map((ev, sIdx) => {
                      const hasPasswordHarvesting = (ev.passwordFields ?? 0) > 0
                      const hasPaymentCoercion = (ev.paymentFields ?? 0) > 0

                      return (
                        <div key={sIdx} className="sandbox-evidence-container">
                          
                          {/* Top Sandbox Diagnostic Header */}
                          <div className="sandbox-top-card">
                            <div className="sandbox-intro-group">
                              <div className="sandbox-icon-wrap">
                                <Terminal size={22} color="var(--brand-secondary)" />
                              </div>
                              <div className="sandbox-intro-text">
                                <h3>Playwright Headless Browser Sandbox</h3>
                                <p>Rendered in an isolated Docker container with strict anti-SSRF DNS pinning, redirect filtering, and &lt;5MB data cap.</p>
                              </div>
                            </div>
                            <div className="sandbox-badges-row">
                              <span className="sandbox-sec-tag">🔒 Anti-SSRF Enforced</span>
                              <span className="sandbox-sec-tag">⚡ 5MB Byte Cap</span>
                              <span className="sandbox-sec-tag">🛡️ Isolated DOM</span>
                            </div>
                          </div>

                          {/* DOM Security Diagnostics Grid */}
                          <div className="sandbox-metrics-row">
                            <div className="sb-metric-card">
                              <div className="sb-metric-top">
                                <span>Total HTML Forms</span>
                                <FileText size={15} />
                              </div>
                              <div className="sb-metric-val">{ev.forms ?? 0}</div>
                              <span className="sb-metric-desc">Form elements detected</span>
                            </div>

                            <div className={`sb-metric-card ${hasPasswordHarvesting ? 'danger-alert' : ''}`}>
                              <div className="sb-metric-top">
                                <span>Password Fields</span>
                                <Lock size={15} />
                              </div>
                              <div className="sb-metric-val">{ev.passwordFields ?? 0}</div>
                              <span className="sb-metric-desc">
                                {hasPasswordHarvesting ? '⚠️ Credential Harvest Attempt' : 'No password inputs found'}
                              </span>
                            </div>

                            <div className={`sb-metric-card ${hasPaymentCoercion ? 'danger-alert' : ''}`}>
                              <div className="sb-metric-top">
                                <span>Payment / Card Inputs</span>
                                <CreditCard size={15} />
                              </div>
                              <div className="sb-metric-val">{ev.paymentFields ?? 0}</div>
                              <span className="sb-metric-desc">
                                {hasPaymentCoercion ? '⚠️ Financial Input Detected' : 'No credit card inputs'}
                              </span>
                            </div>

                            <div className="sb-metric-card">
                              <div className="sb-metric-top">
                                <span>Email / Auth Fields</span>
                                <Mail size={15} />
                              </div>
                              <div className="sb-metric-val">{ev.emailFields ?? 0}</div>
                              <span className="sb-metric-desc">User identifier inputs</span>
                            </div>
                          </div>

                          {/* Visual Proof: Mock macOS Browser Window Frame */}
                          {ev.screenshotBase64 && (
                            <div className="browser-mockup-wrapper">
                              <div className="browser-mockup-header-title">
                                <Eye size={15} />
                                <span>Live Visual Render Capture:</span>
                              </div>

                              <div className="browser-mockup">
                                <div className="browser-chrome-bar">
                                  <div className="browser-dots">
                                    <span className="dot red" />
                                    <span className="dot yellow" />
                                    <span className="dot green" />
                                  </div>
                                  <div className="browser-address-bar">
                                    <Lock size={12} className="browser-lock-icon" />
                                    <span className="browser-url-text">{defangUrl(ev.url || 'target-url')}</span>
                                    <span className="browser-sandboxed-tag">ISOLATED RENDER</span>
                                  </div>
                                  <button
                                    type="button"
                                    className="btn-expand-screenshot"
                                    onClick={() => setSelectedScreenshot(`data:image/jpeg;base64,${ev.screenshotBase64}`)}
                                  >
                                    <Maximize2 size={13} />
                                    <span>Full View</span>
                                  </button>
                                </div>

                                <div
                                  className="browser-viewport"
                                  onClick={() => setSelectedScreenshot(`data:image/jpeg;base64,${ev.screenshotBase64}`)}
                                >
                                  <img
                                    src={`data:image/jpeg;base64,${ev.screenshotBase64}`}
                                    alt="Isolated Sandbox Render"
                                    className="sandbox-screenshot-img"
                                  />
                                  <div className="browser-viewport-overlay">
                                    <Maximize2 size={24} />
                                    <span>Click to open full resolution capture</span>
                                  </div>
                                </div>
                              </div>
                            </div>
                          )}

                          {/* Contacted External Domains */}
                          {ev.externalDomains && ev.externalDomains.length > 0 && (
                            <div className="external-connections-card">
                              <div className="ext-conn-header">
                                <Radio size={14} color="var(--brand-secondary)" />
                                <span>Third-Party Network Connections Contacted ({ev.externalDomains.length}):</span>
                              </div>
                              <div className="ext-conn-chips">
                                {ev.externalDomains.map((domain, dIdx) => (
                                  <span className="ext-domain-chip" key={dIdx}>
                                    {domain.replaceAll('.', '[.]')}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}

                        </div>
                      )
                    })}
                  </div>
                ) : (
                  <div className="empty-sandbox-state">
                    <Terminal size={40} color="var(--text-muted)" />
                    <h4>No External Link Detonation Required</h4>
                    <p>The submitted content is text-only without active URLs. When messages contain hyperlinks, TrustLens spins up an isolated Playwright browser container to safely render and inspect the destination DOM.</p>
                  </div>
                )}
              </div>
            )}

            {/* ── TAB 3: NATIONAL REGISTRY & COMMUNITY INTEL ────────── */}
            {(activeTab === 'all' || activeTab === 'intel') && (
              <div className="tab-pane active" id="tab-intel" style={activeTab === 'all' ? { marginTop: '28px' } : undefined}>
                {activeTab === 'all' && (
                  <div className="section-overview-header">
                    <div className="section-overview-title">
                      <Building2 size={18} color="var(--brand-primary)" />
                      <h3>Pillar 3: National Registry & Community Consensus</h3>
                    </div>
                    <span className="section-overview-badge">
                      {isOfficialEntity ? 'Approved National Entity' : 'Crowdsourced Intelligence'}
                    </span>
                  </div>
                )}
                <div className="intel-tab-layout">
                  
                  {/* National Entity Check Card */}
                  <div className="intel-card-box">
                    <div className="intel-box-header">
                      <div className="intel-box-title-group">
                        <Building2 size={20} color="var(--brand-primary)" />
                        <h3>Sri Lanka National Entity Directory Verification</h3>
                      </div>
                      <span className={`intel-status-pill ${isOfficialEntity ? 'verified' : 'unverified'}`}>
                        {isOfficialEntity ? 'Verified Official' : 'Unregistered'}
                      </span>
                    </div>

                    <div className="intel-box-content">
                      {isOfficialEntity ? (
                        <div className="official-match-details">
                          <CheckCircle2 size={28} color="var(--risk-safe)" />
                          <div>
                            <h4>Authorized Digital Service</h4>
                            <p>This resource belongs to <strong>{intelligenceOverlay?.officialOrganization || 'an official government department or registered commercial bank'}</strong> listed in the Sri Lanka Central Bank (CBSL) & Gov.lk digital directory.</p>
                          </div>
                        </div>
                      ) : (
                        <div className="unregistered-match-details">
                          <Info size={24} color="var(--text-muted)" />
                          <div>
                            <h4>No Official Government or Banking Match</h4>
                            <p>The sender or URL domain does not match any authenticated government (.gov.lk) or approved financial institution digital records.</p>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Community Consensus Bar */}
                  {intelligenceOverlay && (intelligenceOverlay.scamCount ?? 0) + (intelligenceOverlay.safeCount ?? 0) > 0 && (
                    <div className="intel-card-box">
                      <div className="intel-box-header">
                        <div className="intel-box-title-group">
                          <ShieldCheck size={20} color="var(--brand-primary)" />
                          <h3>Community Intelligence Consensus</h3>
                        </div>
                        <span className="consensus-summary-pill">{intelligenceOverlay.consensusSummary}</span>
                      </div>

                      <div className="consensus-bar-section">
                        <div className="consensus-track">
                          <div
                            className="consensus-fill-safe"
                            style={{
                              width: `${Math.round(
                                ((intelligenceOverlay.safeCount ?? 0) /
                                  ((intelligenceOverlay.safeCount ?? 0) + (intelligenceOverlay.scamCount ?? 0))) *
                                  100
                              )}%`,
                            }}
                          />
                          <div
                            className="consensus-fill-scam"
                            style={{
                              width: `${Math.round(
                                ((intelligenceOverlay.scamCount ?? 0) /
                                  ((intelligenceOverlay.safeCount ?? 0) + (intelligenceOverlay.scamCount ?? 0))) *
                                  100
                              )}%`,
                            }}
                          />
                        </div>
                        <div className="consensus-metric-labels">
                          <span className="label-safe">🛡️ {intelligenceOverlay.safeCount} Verified Safe Reports</span>
                          <span className="label-scam">⚠️ {intelligenceOverlay.scamCount} Phishing Threat Reports</span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Transparent Limitations & Scope */}
                  {sanitizedLimitations.length > 0 && (
                    <div className="intel-card-box">
                      <div className="intel-box-header">
                        <div className="intel-box-title-group">
                          <Info size={18} color="var(--risk-medium)" />
                          <h3>Scanner Scope & Environmental Limitations</h3>
                        </div>
                      </div>
                      <ul className="sanitized-limitations-list">
                        {sanitizedLimitations.map((lim, lIdx) => (
                          <li key={lIdx}>{lim}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Technical Audit Trace (Collapsible Accordion) */}
                  <div className="intel-card-box collapsible">
                    <button
                      type="button"
                      className="accordion-header-btn"
                      onClick={() => setShowTechnicalTrace(!showTechnicalTrace)}
                    >
                      <div className="accordion-title-group">
                        <Terminal size={17} />
                        <span>Technical Audit & Reconciliation Details</span>
                        <span className="policy-pill">Policy: {decision.policyVersion}</span>
                      </div>
                      {showTechnicalTrace ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                    </button>

                    {showTechnicalTrace && (
                      <div className="accordion-body">
                        {intelligenceOverlay?.reconciliationTrace && intelligenceOverlay.reconciliationTrace.length > 0 ? (
                          <div className="trace-terminal-view">
                            {intelligenceOverlay.reconciliationTrace.map((line, tIdx) => (
                              <div key={tIdx} className="trace-line">
                                <span className="trace-prefix">&gt;</span>
                                <span className="trace-text">{line}</span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="no-trace-text">Standard heuristic decision pipeline executed without conflict.</p>
                        )}
                      </div>
                    )}
                  </div>

                </div>
              </div>
            )}

          </div>

          {/* New Scan / Restart Action Button */}
          <div className="dashboard-bottom-bar">
            <button
              type="button"
              className="btn-new-scan"
              onClick={() => {
                setText('')
                setChecked(false)
                setIntelligenceOverlay(null)
                window.scrollTo({ top: 0, behavior: 'smooth' })
              }}
            >
              <RefreshCw size={15} />
              <span>Analyze Another Message</span>
            </button>
          </div>

        </section>
      )}

      {/* ── Screenshot Lightbox Modal ───────────────────────────────── */}
      {selectedScreenshot && (
        <div className="lightbox-overlay" onClick={() => setSelectedScreenshot(null)}>
          <div className="lightbox-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="lightbox-header">
              <span className="lightbox-title">Captured DOM Sandbox Render</span>
              <button
                type="button"
                className="btn-close-lightbox"
                onClick={() => setSelectedScreenshot(null)}
              >
                <X size={18} />
              </button>
            </div>
            <div className="lightbox-image-wrapper">
              <img src={selectedScreenshot} alt="Sandbox Full View" className="lightbox-img" />
            </div>
          </div>
        </div>
      )}

      {/* ── Report Modal ───────────────────────────────────────────── */}
      <ReportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        content={text}
        reportedDomain={detectedDomain}
      />

      {/* ── Footer ─────────────────────────────────────────────────── */}
      <footer>
        <span className="footer-brand">TrustLens LK</span>
        <span>Deterministic heuristics & verified sandbox inspection guide each recommendation.</span>
      </footer>
    </main>
  )
}

export default App

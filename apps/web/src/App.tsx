import { useMemo, useState, useEffect, useRef, useCallback } from 'react'
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
import {
  TopAnnouncementBar,
  ScamTrendsSection,
  HowItWorksSection,
  FaqSection,
  AboutMissionSection,
  LandingFooter,
} from './components/LandingSections'
import './App.css'
import './components/NavSentinelDock.css'
import { Sparkles } from 'lucide-react'

interface AiValidation {
  verdict: 'AGREE' | 'DISAGREE' | 'UNCERTAIN'
  confidence: number
  reasoning: string
  originalRiskBand: 'LOW' | 'MEDIUM' | 'HIGH' | 'UNKNOWN'
  adjustedRiskBand: 'LOW' | 'MEDIUM' | 'HIGH' | 'UNKNOWN'
  appliedAction: 'DOWNGRADED' | 'UPGRADED' | 'HARD_BLOCKED' | 'RETAINED'
  evaluatedAt?: string
}

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
  isPartial?: boolean
  isAdultContent?: boolean
}


function getInitialAppView(): 'checker' | 'moderator' {
  if (typeof window !== 'undefined') {
    const hash = window.location.hash.toLowerCase()
    if (hash.startsWith('#moderator')) {
      return 'moderator'
    }
    const path = window.location.pathname.toLowerCase()
    if (path.includes('/moderator')) {
      return 'moderator'
    }
    try {
      const saved = sessionStorage.getItem('trustlens_app_view')
      if (saved === 'moderator') {
        return 'moderator'
      }
    } catch {
      /* ignore */
    }
  }
  return 'checker'
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

  const [view, setView] = useState<'checker' | 'moderator'>(getInitialAppView)

  // Keep sessionStorage in sync with view
  useEffect(() => {
    try {
      sessionStorage.setItem('trustlens_app_view', view)
    } catch {
      /* ignore */
    }
  }, [view])

  // Sync view when browser hash changes (e.g. Back/Forward button)
  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.toLowerCase()
      if (hash.startsWith('#moderator')) {
        setView('moderator')
      } else if (hash === '' || hash === '#' || hash.startsWith('#scanner') || hash.startsWith('#checker')) {
        setView('checker')
      }
    }

    window.addEventListener('hashchange', handleHashChange)
    window.addEventListener('popstate', handleHashChange)
    return () => {
      window.removeEventListener('hashchange', handleHashChange)
      window.removeEventListener('popstate', handleHashChange)
    }
  }, [])

  const handleOpenModerator = useCallback(() => {
    setView('moderator')
    if (typeof window !== 'undefined') {
      try {
        sessionStorage.setItem('trustlens_app_view', 'moderator')
        const savedModNav = sessionStorage.getItem('trustlens_mod_nav')?.toLowerCase() || 'dashboard'
        if (!window.location.hash.toLowerCase().startsWith('#moderator')) {
          window.history.pushState(null, '', `#moderator/${savedModNav}`)
        }
      } catch {
        /* ignore */
      }
    }
  }, [])

  const handleBackToScanner = useCallback(() => {
    setView('checker')
    if (typeof window !== 'undefined') {
      try {
        sessionStorage.setItem('trustlens_app_view', 'checker')
        if (window.location.hash.toLowerCase().startsWith('#moderator')) {
          window.history.pushState(null, '', window.location.pathname + window.location.search)
        }
      } catch {
        /* ignore */
      }
    }
  }, [])
  const [isReportModalOpen, setIsReportModalOpen] = useState(false)
  const [text, setText] = useState('')
  const [checked, setChecked] = useState(false)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [apiAnalysis, setApiAnalysis] = useState<ReturnType<typeof analyzeSubmission> | null>(null)
  const [, setApiMode] = useState<'local' | 'api'>('local')
  const [inputType, setInputType] = useState<'message' | 'screenshot'>('message')
  const [intelligenceOverlay, setIntelligenceOverlay] = useState<IntelligenceOverlay | null>(null)
  const [aiValidation, setAiValidation] = useState<AiValidation | null>(null)

  const [activeTab, setActiveTab] = useState<'all' | 'signals' | 'sandbox' | 'intel' | 'layer5'>('all')
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [selectedScreenshot, setSelectedScreenshot] = useState<string | null>(null)
  const [showTechnicalTrace, setShowTechnicalTrace] = useState(false)

  const handleTabClick = (tab: 'all' | 'signals' | 'sandbox' | 'intel' | 'layer5') => {
    setActiveTab(tab)
    setTimeout(() => {
      const tabsSection = document.getElementById('dashboard-tabs-section')
      if (tabsSection) {
        tabsSection.scrollIntoView({ behavior: 'smooth', block: 'start' })
      }
    }, 50)
  }

  // ScrollSpy: Track current viewport section to highlight active nav bar link
  const [activeSection, setActiveSection] = useState<'checker' | 'scam-trends' | 'how-it-works' | 'faq' | 'about'>('checker')

  useEffect(() => {
    const handleScroll = () => {
      const scrollPos = window.scrollY + 200
      const isAtBottom = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 60

      if (isAtBottom) {
        setActiveSection('about')
        return
      }

      const sections: Array<{ id: 'checker' | 'scam-trends' | 'how-it-works' | 'faq' | 'about'; el: HTMLElement | null }> = [
        { id: 'checker', el: document.getElementById('checker-console') },
        { id: 'scam-trends', el: document.getElementById('scam-trends') },
        { id: 'how-it-works', el: document.getElementById('how-it-works') },
        { id: 'faq', el: document.getElementById('faq') },
        { id: 'about', el: document.getElementById('about') },
      ]

      for (let i = sections.length - 1; i >= 0; i--) {
        const sec = sections[i]
        if (sec.el && sec.el.offsetTop <= scrollPos) {
          setActiveSection(sec.id)
          break
        }
      }
    }

    window.addEventListener('scroll', handleScroll, { passive: true })
    handleScroll()
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

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
        ? 'Critical Risk - Spoofing Attack'
        : isConflicted
          ? 'Disputed / High Risk Alert'
          : decision.riskBand === 'HIGH' || isConfirmedScam
            ? 'High Threat - Phishing Detected'
            : decision.riskBand === 'MEDIUM'
              ? 'Suspicious Activity Warning'
              : 'Low Risk - Likely Safe'

  const verdictVariantClass = isOfficialEntity
    ? 'official-entity'
    : isVerifiedSafe
      ? 'verified-safe'
      : (decision.riskBand === 'HIGH' || isConfirmedScam || isImpersonation)
        ? 'high-risk'
        : isConflicted
          ? 'conflicted'
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
    setAiValidation(null)
    try {
      const result = await analyzeWithApi(targetText, finalType)
      setApiAnalysis(result)
      setApiMode('api')
      if ((result as Record<string, unknown>).intelligenceOverlay) {
        setIntelligenceOverlay((result as Record<string, unknown>).intelligenceOverlay as IntelligenceOverlay)
      }
      if ((result as Record<string, unknown>).aiValidation) {
        setAiValidation((result as Record<string, unknown>).aiValidation as AiValidation)
      }
      setChecked(true)
      setActiveTab('all')
      setTimeout(() => {
        resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
      }, 100)
    } catch {
      setApiAnalysis(null)
      setApiMode('local')
      setChecked(true)
      setActiveTab('all')
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


  const hasDangerousInputs = Boolean(scannerEvidence?.some((ev) => (ev.passwordFields ?? 0) > 0 || (ev.paymentFields ?? 0) > 0))

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

  const handleSelectSample = (sampleText: string) => {
    setText(sampleText)
    setInputType('message')
    setChecked(false)
    setIntelligenceOverlay(null)
    const consoleEl = document.getElementById('checker-console')
    if (consoleEl) {
      consoleEl.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }
  }

  const handleStartCheck = () => {
    const consoleEl = document.getElementById('checker-console')
    if (consoleEl) {
      consoleEl.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }
  }

  if (view === 'moderator') {
    return <ModeratorDashboard onBackToScanner={handleBackToScanner} />
  }

  return (
    <>
      <TopAnnouncementBar />
      <main className="app-shell">
        {/* ── Sleek Modern Navigation Header ────────────────────── */}
        <header className="nav-header">
          <div
            className="nav-brand"
            onClick={() => {
              handleBackToScanner()
              window.scrollTo({ top: 0, behavior: 'smooth' })
            }}
            title="TrustLens LK"
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                handleBackToScanner()
                window.scrollTo({ top: 0, behavior: 'smooth' })
              }
            }}
          >
            <div className="nav-logo-box">
              <img src="/TrustLens_Icon.png" alt="TrustLens LK" className="nav-logo-img" />
            </div>
            <div className="nav-brand-title">
              Trust<span className="brand-lens">Lens</span> <span className="brand-lk">LK</span>
            </div>
          </div>

          {/* Navigation Links with Active Indicator */}
          <nav className="nav-links" aria-label="Main Navigation">
            <a
              href="#checker-console"
              className={`nav-link ${activeSection === 'checker' ? 'active' : ''}`}
              onClick={(e) => {
                e.preventDefault()
                setActiveSection('checker')
                document.getElementById('checker-console')?.scrollIntoView({ behavior: 'smooth', block: 'center' })
              }}
            >
              Check a Scam
            </a>
            <a
              href="#scam-trends"
              className={`nav-link ${activeSection === 'scam-trends' ? 'active' : ''}`}
              onClick={(e) => {
                e.preventDefault()
                setActiveSection('scam-trends')
                document.getElementById('scam-trends')?.scrollIntoView({ behavior: 'smooth' })
              }}
            >
              Scam Trends
            </a>
            <a
              href="#how-it-works"
              className={`nav-link ${activeSection === 'how-it-works' ? 'active' : ''}`}
              onClick={(e) => {
                e.preventDefault()
                setActiveSection('how-it-works')
                document.getElementById('how-it-works')?.scrollIntoView({ behavior: 'smooth' })
              }}
            >
              How It Works
            </a>
            <a
              href="#faq"
              className={`nav-link ${activeSection === 'faq' ? 'active' : ''}`}
              onClick={(e) => {
                e.preventDefault()
                setActiveSection('faq')
                document.getElementById('faq')?.scrollIntoView({ behavior: 'smooth' })
              }}
            >
              FAQ
            </a>
            <a
              href="#about"
              className={`nav-link ${activeSection === 'about' ? 'active' : ''}`}
              onClick={(e) => {
                e.preventDefault()
                setActiveSection('about')
                document.getElementById('about')?.scrollIntoView({ behavior: 'smooth' })
              }}
            >
              About
            </a>
          </nav>

          <div className="nav-actions">
            <button
              type="button"
              className="nav-btn-report"
              onClick={() => setIsReportModalOpen(true)}
              title="Report a Scam"
            >
              <ShieldAlert size={15} />
              <span>Report Scam</span>
            </button>
            <button
              type="button"
              className="nav-btn-portal"
              onClick={handleOpenModerator}
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
            <h1>Does this message deserve your trust?</h1>
            <p className="hero-description">
              Instantly verify suspicious SMS, WhatsApp messages, payment requests, or URLs to protect yourself from digital scams in Sri Lanka.
            </p>
            <div className="hero-trust-strip">
              <div className="trust-item">
                <ShieldCheck size={16} className="trust-icon" />
                <span>Safely Checks Links for Danger</span>
              </div>
              <div className="trust-item">
                <CheckCircle2 size={16} className="trust-icon" />
                <span>Checks Official Bank &amp; Gov Sites</span>
              </div>
              <div className="trust-item">
                <Lock size={16} className="trust-icon" />
                <span>100% Private, Messages Never Saved</span>
              </div>
            </div>
          </div>

          {/* Input Console Card */}
          <div id="checker-console" className="console-card">
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
                    <X size={13} style={{ marginRight: 3, verticalAlign: 'middle' }} />
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

            <div className="console-input-slot">
              {inputType === 'screenshot' ? (
                <ScreenshotOcrUploader
                  onTextConfirmed={(ocrText) => {
                    setText(ocrText)
                    setInputType('message')
                  }}
                  onCancel={() => setInputType('message')}
                />
              ) : (
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
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
                        e.preventDefault()
                        if (text.trim() && !isAnalyzing) {
                          void checkMessage()
                        }
                      }
                    }}
                    placeholder="Paste suspicious SMS, WhatsApp message, email, or URL link here..."
                    title="Type your message or URL and press Enter to analyze (Shift+Enter for newline)"
                  />
                </div>
              )}
            </div>

            <div className="console-card-footer">
              <div className="console-meta">
                <span className="char-counter">{text.length.toLocaleString()} / 10,000 characters</span>
                <span className="privacy-badge">
                  <Info size={13} />
                  <span>100% private, nothing saved</span>
                </span>
              </div>
              <button
                type="button"
                className="btn-scan"
                onClick={() => void checkMessage()}
                disabled={!text.trim() || isAnalyzing}
                title="Press Enter ↵ to analyze (Shift+Enter for new line)"
              >
                {isAnalyzing ? (
                  <>
                    <span className="spinner" />
                    <span>Analyzing message...</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck size={17} />
                    <span>Analyze Message</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </section>

        {/* ══════════════════════════════════════════════════════════════
          Clean Human-Designed Analysis Results Section
         ══════════════════════════════════════════════════════════════ */}
        {checked && (
          <section
            ref={resultRef}
            id="results-dashboard"
            className={`result-section risk-border-${verdictVariantClass}`}
            aria-live="polite"
          >
            {/* ── 1. Clean Verdict Card ───────────────────────────────── */}
            <div className={`command-verdict-banner ${verdictVariantClass}`}>

              {/* Top Meta Strip */}
              <div className="command-banner-top">
                <div className="command-status-badge">
                  <span className="status-badge-text">
                    {isOfficialEntity && 'Verified Official Institution'}
                    {!isOfficialEntity && isVerifiedSafe && 'Verified Safe Content'}
                    {isImpersonation && 'Fake / Impersonation Alert'}
                    {isConflicted && 'Mixed Signals / Needs Caution'}
                    {!isOfficialEntity && !isVerifiedSafe && !isImpersonation && !isConflicted && (decision.riskBand === 'HIGH' || isConfirmedScam) && 'Scam Detected'}
                    {!isOfficialEntity && !isVerifiedSafe && !isImpersonation && !isConflicted && decision.riskBand === 'MEDIUM' && 'Suspicious Activity Warning'}
                    {!isOfficialEntity && !isVerifiedSafe && !isImpersonation && !isConflicted && decision.riskBand === 'LOW' && 'Verified Safe & Normal'}
                  </span>
                </div>

                {detectedDomain && (
                  <div className="target-domain-badge">
                    <Globe size={13} />
                    <span className="target-domain-label">Website:</span>
                    <span className="target-domain-val">{defangUrl(detectedDomain)}</span>
                    <button
                      type="button"
                      className="copy-chip-btn"
                      onClick={() => handleCopy(defangUrl(detectedDomain), 'target-url')}
                      title="Copy Link"
                    >
                      {copiedKey === 'target-url' ? <Check size={12} color="#059669" /> : <Copy size={12} />}
                    </button>
                  </div>
                )}
              </div>

              {/* Main Headline & Summary */}
              <div className="command-banner-body">
                <div className="verdict-icon-container">
                  {isOfficialEntity && <ShieldCheck size={32} />}
                  {!isOfficialEntity && isVerifiedSafe && <ShieldCheck size={32} />}
                  {(isConfirmedScam || decision.riskBand === 'HIGH') && <AlertOctagon size={32} />}
                  {(isConflicted || decision.riskBand === 'MEDIUM') && !isConfirmedScam && <AlertTriangle size={32} />}
                  {!isOfficialEntity && !isVerifiedSafe && !isConfirmedScam && decision.riskBand !== 'HIGH' && decision.riskBand !== 'MEDIUM' && (
                    <ShieldCheck size={32} />
                  )}
                </div>

                <div className="verdict-headline-group">
                  <h2 className="verdict-primary-title">{risk}</h2>
                  <p className="verdict-explanation">
                    {aiValidation?.reasoning
                      ? aiValidation.reasoning
                      : isOfficialEntity
                        ? `This website is verified in official Sri Lankan directories as belonging to ${intelligenceOverlay?.officialOrganization || 'an authorized institution'}.`
                        : isImpersonation
                          ? 'This message pretends to be a recognized bank or government service, but asks for login details or payment through an unauthorized channel.'
                          : isVerifiedSafe
                            ? 'This content has been reviewed and confirmed safe.'
                            : isConfirmedScam
                              ? 'This message matches confirmed fraud and scam reports in Sri Lanka.'
                              : decision.riskBand === 'HIGH'
                                ? 'This message contains deceptive tricks typical of online banking and phishing scams.'
                                : decision.riskBand === 'MEDIUM'
                                  ? 'Warning signs were identified. Verify the sender independently before taking action.'
                                  : 'No scam or phishing patterns were detected in this message.'}
                  </p>
                </div>

                <div className="verdict-cta-group">
                  <button
                    type="button"
                    className="btn-banner-report"
                    onClick={() => setIsReportModalOpen(true)}
                  >
                    <Flag size={14} />
                    <span>Report Scam</span>
                  </button>
                </div>
              </div>

              {/* AI Reasoning Insight Box */}
              {aiValidation && (
                <div className="verdict-ai-spotlight">
                  <div className="ai-spotlight-header">
                    <div className="ai-spotlight-title">
                      <Sparkles size={16} color="#8B5CF6" />
                      <span>AI Reasoning (Gemini Intelligence)</span>
                    </div>
                    <span className="ai-confidence-pill">
                      {Math.round(aiValidation.confidence * 100)}% Confidence
                    </span>
                  </div>
                  <p className="ai-spotlight-quote">{aiValidation.reasoning}</p>
                </div>
              )}

              {/* Protective Guidance */}
              {decision.safeActions && decision.safeActions.length > 0 && (
                <div className="verdict-immediate-action">
                  <Zap size={15} className="action-zap-icon" />
                  <span className="action-callout-text"><strong>Recommendation:</strong> {decision.safeActions[0]}</span>
                </div>
              )}
            </div>




            {/* ── 2. Segmented Navigation Tabs ─────────────────────────── */}
            <div className="dashboard-tabs-container" id="dashboard-tabs-section">
              <nav className="dashboard-tabs" aria-label="Analysis Details Tabs">
                <button
                  type="button"
                  className={`tab-btn ${activeTab === 'all' ? 'active' : ''}`}
                  onClick={() => handleTabClick('all')}
                >
                  <Layers size={16} />
                  <span>Scan Summary</span>
                </button>

                <button
                  type="button"
                  className={`tab-btn ${activeTab === 'signals' ? 'active' : ''}`}
                  onClick={() => handleTabClick('signals')}
                >
                  <Activity size={16} />
                  <span>Warning Signs</span>
                  <span className={`tab-counter ${decision.findings.length > 0 ? 'danger' : 'clean'}`}>
                    {decision.findings.length}
                  </span>
                </button>

                <button
                  type="button"
                  className={`tab-btn ${activeTab === 'sandbox' ? 'active' : ''}`}
                  onClick={() => handleTabClick('sandbox')}
                >
                  <Terminal size={16} />
                  <span>Website Safety Scan</span>
                  {hasDangerousInputs ? (
                    <span className="tab-badge-pill red">Alert</span>
                  ) : (
                    <span className={`tab-counter ${scannerEvidence?.length ? 'clean' : ''}`}>
                      {scannerEvidence?.length ?? 0}
                    </span>
                  )}
                </button>

                <button
                  type="button"
                  className={`tab-btn ${activeTab === 'intel' ? 'active' : ''}`}
                  onClick={() => handleTabClick('intel')}
                >
                  <Building2 size={16} />
                  <span>Official Checks & Reports</span>
                  {isOfficialEntity ? (
                    <span className="tab-badge-pill official">Official</span>
                  ) : isConfirmedScam ? (
                    <span className="tab-badge-pill red">Flagged</span>
                  ) : null}
                </button>

                <button
                  type="button"
                  className={`tab-btn ${activeTab === 'layer5' ? 'active' : ''}`}
                  onClick={() => handleTabClick('layer5')}
                >
                  <Sparkles size={16} />
                  <span>AI Scam Analysis</span>
                </button>
              </nav>
            </div>

            {/* ── 3. Tab Contents ───────────────────────────────────────── */}
            <div className={`dashboard-content-area ${activeTab === 'all' ? 'no-scroll' : ''}`}>

              {/* ── TAB SUMMARY: ALL EVIDENCE ──────────────────────────── */}
              {activeTab === 'all' && (
                <div className="tab-pane active" id="tab-summary">
                  <div className="at-a-glance-section">
                    <h3 className="at-a-glance-title">Analysis Summary</h3>
                    <div className="summary-guidance-msg" style={{ margin: '-10px 0 24px 0', color: 'var(--text-muted)', fontSize: '14px', lineHeight: '1.5', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Info size={16} color="var(--brand-secondary)" />
                      <span>Click the tabs above to see website safety scans, official records, and AI analysis.</span>
                    </div>
                    <div className="at-a-glance-grid">
                      <div className="at-a-glance-card">
                        <div className="at-a-glance-icon risk-icon">
                          <ShieldAlert size={20} />
                        </div>
                        <div className="at-a-glance-info">
                          <span className="at-a-glance-val">{decision.riskBand}</span>
                          <span className="at-a-glance-label">Threat Level</span>
                        </div>
                      </div>

                      <div className="at-a-glance-card">
                        <div className="at-a-glance-icon signals-icon">
                          <Activity size={20} />
                        </div>
                        <div className="at-a-glance-info">
                          <span className="at-a-glance-val">{decision.findings.length} Signals</span>
                          <span className="at-a-glance-label">Warning Signs</span>
                        </div>
                      </div>

                      <div className="at-a-glance-card">
                        <div className="at-a-glance-icon web-icon">
                          <Globe size={20} />
                        </div>
                        <div className="at-a-glance-info">
                          <span className="at-a-glance-val">
                            {scannerEvidence?.length ? 'Link Inspected' : 'Text Analysis'}
                          </span>
                          <span className="at-a-glance-label">Website Safety Check</span>
                        </div>
                      </div>

                      <div className="at-a-glance-card">
                        <div className="at-a-glance-icon registry-icon">
                          <Building2 size={20} />
                        </div>
                        <div className="at-a-glance-info">
                          <span className="at-a-glance-val">
                            {isOfficialEntity ? 'Verified Official' : 'Unregistered'}
                          </span>
                          <span className="at-a-glance-label">Official Bank & Gov Match</span>
                        </div>
                      </div>
                    </div>

                    {/* Summary Explanations */}
                    <div className="summary-explanation-box" style={{ marginTop: '36px' }}>
                      <h4 style={{ margin: '0 0 16px 0', fontSize: '14px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: '700' }}>Card Legend</h4>
                      <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '22px' }}>
                        <li style={{ display: 'flex', gap: '14px', alignItems: 'flex-start' }}>
                          <ShieldAlert size={20} color="#ef4444" style={{ flexShrink: 0, marginTop: '1px' }} />
                          <span style={{ fontSize: '14.5px', color: 'var(--text-muted)', lineHeight: '1.5' }}>
                            <strong style={{ color: 'var(--text-primary)', marginRight: '6px' }}>Threat Level:</strong>
                            The overall danger rating based on psychological manipulation tactics and known scam patterns.
                          </span>
                        </li>
                        <li style={{ display: 'flex', gap: '14px', alignItems: 'flex-start' }}>
                          <Activity size={20} color="#f59e0b" style={{ flexShrink: 0, marginTop: '1px' }} />
                          <span style={{ fontSize: '14.5px', color: 'var(--text-muted)', lineHeight: '1.5' }}>
                            <strong style={{ color: 'var(--text-primary)', marginRight: '6px' }}>Warning Signs:</strong>
                            Specific scam tricks like false urgency, threats, or fake prize promises detected in the text.
                          </span>
                        </li>
                        <li style={{ display: 'flex', gap: '14px', alignItems: 'flex-start' }}>
                          <Globe size={20} color="#3b82f6" style={{ flexShrink: 0, marginTop: '1px' }} />
                          <span style={{ fontSize: '14.5px', color: 'var(--text-muted)', lineHeight: '1.5' }}>
                            <strong style={{ color: 'var(--text-primary)', marginRight: '6px' }}>Website Safety Check:</strong>
                            Shows if links were safely inspected in a protected environment for fake login forms or malicious downloads.
                          </span>
                        </li>
                        <li style={{ display: 'flex', gap: '14px', alignItems: 'flex-start' }}>
                          <Building2 size={20} color="#10b981" style={{ flexShrink: 0, marginTop: '1px' }} />
                          <span style={{ fontSize: '14.5px', color: 'var(--text-muted)', lineHeight: '1.5' }}>
                            <strong style={{ color: 'var(--text-primary)', marginRight: '6px' }}>Official Bank &amp; Gov Match:</strong>
                            Cross-checks against Sri Lankan bank and government records to confirm if the sender is authentic.
                          </span>
                        </li>
                      </ul>
                    </div>

                  </div>
                </div>
              )}

              {/* ── TAB 1: THREAT SIGNALS & EXTRACTED IOCS ─────────────── */}
              {activeTab === 'signals' && (
                <div className="tab-pane active" id="tab-signals">

                  <div className="tab-grid-layout">
                    {/* Left Column: Flagged Behavioral Signals */}
                    <div className="pane-column-main">
                      <div className="pane-card">
                        <div className="pane-card-header">
                          <div className="pane-title-group">
                            <Activity size={18} color="var(--brand-primary)" />
                            <h3>Suspicious Patterns Detected</h3>
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
                                    className={`signal-threat-pill ${finding.strength > 0.8
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

                    {/* Right Column: Detected Links, Phone Numbers & Details */}
                    <div className="pane-column-side">
                      <div className="pane-card">
                        <div className="pane-card-header">
                          <div className="pane-title-group">
                            <Globe size={18} color="var(--brand-secondary)" />
                            <h3>Detected Links &amp; Details</h3>
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
                                      title="Copy value"
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
                            <span>No website links, phone numbers, or account amounts found in message.</span>
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
              {activeTab === 'sandbox' && (
                <div className="tab-pane active" id="tab-sandbox">

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
                                  <h3>Live Website Scanner</h3>
                                  <p>Opens the website safely in a secure test room to check for fake pages and scams without putting your phone or computer at risk.</p>
                                </div>
                              </div>
                              <div className="sandbox-badges-row">
                                <span className="sandbox-sec-tag">Protected Safe Browsing</span>
                                <span className="sandbox-sec-tag">Fast Scanning</span>
                                <span className="sandbox-sec-tag">Isolated Test Room</span>
                                {ev.isAdultContent && (
                                  <span className="sandbox-sec-tag adult-badge-tag" title="Domain flagged as age-restricted or explicit adult material. Visual screenshot suppressed.">
                                    18+ Content Filtered
                                  </span>
                                )}
                                {ev.isPartial && (
                                  <span className="sandbox-sec-tag partial-capture-tag" title="The target server was slow to respond; visible layout and form inputs were securely captured before timeout.">
                                    Partial Capture (Slow Target Server)
                                  </span>
                                )}
                              </div>
                            </div>

                            {/* Security Diagnostics Grid */}
                            <div className="sandbox-metrics-row">
                              <div className="sb-metric-card">
                                <div className="sb-metric-top">
                                  <span>Input Forms on Page</span>
                                  <FileText size={15} />
                                </div>
                                <div className="sb-metric-val">{ev.forms ?? 0}</div>
                                <span className="sb-metric-desc">Data collection forms found</span>
                              </div>

                              <div className={`sb-metric-card ${hasPasswordHarvesting ? 'danger-alert' : ''}`}>
                                <div className="sb-metric-top">
                                  <span>Password Fields</span>
                                  <Lock size={15} />
                                </div>
                                <div className="sb-metric-val">{ev.passwordFields ?? 0}</div>
                                <span className="sb-metric-desc">
                                  {hasPasswordHarvesting ? 'Stealing Passwords Detected!' : 'No password fields found'}
                                </span>
                              </div>

                              <div className={`sb-metric-card ${hasPaymentCoercion ? 'danger-alert' : ''}`}>
                                <div className="sb-metric-top">
                                  <span>Payment / Card Inputs</span>
                                  <CreditCard size={15} />
                                </div>
                                <div className="sb-metric-val">{ev.paymentFields ?? 0}</div>
                                <span className="sb-metric-desc">
                                  {hasPaymentCoercion ? 'Asking for Bank/Card Details!' : 'No bank card fields found'}
                                </span>
                              </div>

                              <div className="sb-metric-card">
                                <div className="sb-metric-top">
                                  <span>Email / Username Fields</span>
                                  <Mail size={15} />
                                </div>
                                <div className="sb-metric-val">{ev.emailFields ?? 0}</div>
                                <span className="sb-metric-desc">Login inputs found</span>
                              </div>
                            </div>

                            {/* Visual Proof or Safety Shield */}
                            {ev.isAdultContent ? (
                              <div className="browser-mockup-wrapper">
                                <div className="browser-mockup-header-title">
                                  <ShieldAlert size={15} color="#d97706" />
                                  <span>Content Safety Guard:</span>
                                </div>

                                <div className="browser-mockup adult-content-shield">
                                  <div className="browser-chrome-bar">
                                    <div className="browser-dots">
                                      <span className="dot red" />
                                      <span className="dot yellow" />
                                      <span className="dot green" />
                                    </div>
                                    <div className="browser-address-bar">
                                      <Lock size={12} className="browser-lock-icon" />
                                      <span className="browser-url-text">{defangUrl(ev.url || 'target-url')}</span>
                                      <span className="browser-adult-tag">18+ RESTRICTED</span>
                                    </div>
                                  </div>

                                  <div className="sandbox-adult-guard-body">
                                    <div className="adult-guard-icon-wrap">
                                      <ShieldAlert size={36} color="#d97706" />
                                    </div>
                                    <h4>18+ Explicit Content Detected</h4>
                                    <p>
                                      Live screenshot is hidden by the safety filter to avoid displaying explicit adult material.
                                    </p>
                                    <span className="adult-guard-subtext">
                                      Checks for fake login forms and password theft remain fully active below.
                                    </span>
                                  </div>
                                </div>
                              </div>
                            ) : ev.screenshotBase64 ? (
                              <div className="browser-mockup-wrapper">
                                <div className="browser-mockup-header-title">
                                  <Eye size={15} />
                                  <span>Live Website Screenshot:</span>
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
                                      <span className="browser-sandboxed-tag">SECURE SCAN</span>
                                      {ev.isPartial && (
                                        <span className="browser-partial-tag" title="Target web server responded slowly; partial capture preserved.">
                                          PARTIAL CAPTURE
                                        </span>
                                      )}
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
                                      alt="Secure Scan Screenshot"
                                      className="sandbox-screenshot-img"
                                    />
                                    <div className="browser-viewport-overlay">
                                      <Maximize2 size={24} />
                                      <span>Click to open full resolution capture</span>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            ) : null}

                            {/* Contacted External Domains */}
                            {ev.externalDomains && ev.externalDomains.length > 0 && (
                              <div className="external-connections-card">
                                <div className="ext-conn-header">
                                  <Radio size={14} color="var(--brand-secondary)" />
                                  <span>Other Websites Contacted in Background ({ev.externalDomains.length}):</span>
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
                      <h4>No Website Links to Inspect</h4>
                      <p>This message contains text only. If a message contains a website link, TrustLens safely visits and inspects it in a protected environment to check for fake login screens and scams without risking your device.</p>
                    </div>
                  )}


                </div>
              )}

              {/* ── TAB 3: NATIONAL REGISTRY & COMMUNITY INTEL ────────── */}
              {activeTab === 'intel' && (
                <div className="tab-pane active" id="tab-intel">

                  <div className="intel-tab-layout">

                    {/* National Entity Check Card */}
                    <div className="intel-card-box">
                      <div className="intel-box-header">
                        <div className="intel-box-title-group">
                          <Building2 size={20} color="var(--brand-primary)" />
                          <h3>Official Sri Lankan Organization Check</h3>
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
                            <h3>Community Reports &amp; Verification</h3>
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
                            <span className="label-safe">{intelligenceOverlay.safeCount} Verified Safe Reports</span>
                            <span className="label-scam">{intelligenceOverlay.scamCount} Scam Reports</span>
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
                            <h3>Important Safety Notes</h3>
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
                          <span>Technical Details (For IT Specialists)</span>
                          <span className="policy-pill">Policy: {decision.policyVersion}</span>
                        </div>
                        {showTechnicalTrace ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                      </button>

                      {showTechnicalTrace && (() => {
                        const decTrace = (decision as Record<string, unknown>).reconciliationTrace as string[] | undefined
                        const activeTrace = (decTrace && decTrace.length > 0) ? decTrace : (intelligenceOverlay?.reconciliationTrace || [])
                        return (
                          <div className="accordion-body">
                            {activeTrace.length > 0 ? (
                              <div className="trace-terminal-view">
                                {activeTrace.map((line: string, tIdx: number) => (
                                  <div key={tIdx} className="trace-line">
                                    <span className="trace-prefix">&gt;</span>
                                    <span className="trace-text">{line}</span>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className="no-trace-text">Standard scam detection rules executed cleanly without conflict.</p>
                            )}
                          </div>
                        )
                      })()}
                    </div>

                  </div>
                </div>
              )}

              {/* ── TAB 4: LAYER 5 AI CONTEXT ────────────────────────── */}
              {activeTab === 'layer5' && (
                <div className="tab-pane active" id="tab-layer5">
                  {aiValidation ? (
                    <>
                      <div className="intel-card-box ai-context-card">
                        <div className="intel-box-header">
                          <div className="intel-box-title-group">
                            <Sparkles size={18} color="#8B5CF6" />
                            <h3>AI Scam Analysis (Powered by Gemini AI)</h3>
                          </div>
                          <span className={`intel-status-pill ai-action-pill ${aiValidation.appliedAction.toLowerCase()}`}>
                            {aiValidation.appliedAction === 'DOWNGRADED'
                              ? `Downgraded (${aiValidation.originalRiskBand} ➔ ${aiValidation.adjustedRiskBand})`
                              : aiValidation.appliedAction === 'UPGRADED'
                                ? `Upgraded (${aiValidation.originalRiskBand} ➔ ${aiValidation.adjustedRiskBand})`
                                : aiValidation.appliedAction === 'HARD_BLOCKED'
                                  ? 'High Alert Preserved'
                                  : 'Verdict Retained'}
                          </span>
                        </div>
                        <div className="ai-context-content">
                          <p className="ai-reasoning-quote">"{aiValidation.reasoning}"</p>
                          <div className="ai-context-meta">
                            <span>Verdict: <strong>{aiValidation.verdict}</strong></span>
                            <span>Confidence: <strong>{Math.round(aiValidation.confidence * 100)}%</strong></span>
                          </div>
                        </div>
                      </div>

                      {/* AI Explanation Text */}
                      <div className="intel-card-box" style={{ marginTop: '24px' }}>
                        <div className="ai-explanation-note">
                          <h4 style={{ margin: '0 0 16px 0', fontSize: '15px', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <Sparkles size={16} color="var(--brand-primary)" />
                            How AI Scam Analysis Helps You
                          </h4>
                          <p style={{ fontSize: '14px', color: 'var(--text-muted)', lineHeight: '1.6', margin: '0 0 16px 0' }}>
                            Our AI reads between the lines to catch sneaky psychological manipulation, urgent threats, or fake promises that standard keyword filters might miss. It understands local context and everyday language to give you a clear, human explanation.
                          </p>
                          <div style={{ padding: '16px', backgroundColor: 'var(--bg-surface-hover)', borderRadius: '10px', borderLeft: '3px solid var(--risk-medium)' }}>
                            <p style={{ fontSize: '14px', color: 'var(--text-primary)', lineHeight: '1.6', margin: 0 }}>
                              <strong style={{ color: 'var(--risk-medium)', marginRight: '6px' }}>Helpful Tip:</strong>
                              While our AI has high accuracy, scammers constantly invent new tricks. Always verify with official helplines before sending money or passwords.
                            </p>
                          </div>
                        </div>
                      </div>
                    </>
                  ) : (
                    <div className="empty-sandbox-state">
                      <Sparkles size={40} color="var(--text-muted)" />
                      <h4>AI Evaluation Not Needed</h4>
                      <p>Standard safety rules gave a clear, decisive answer immediately without needing extra AI processing.</p>
                    </div>
                  )}
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
                <span className="lightbox-title">Captured Website Screenshot</span>
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

        {/* ── Active LK Scam Trends ───────────────────────────────────── */}
        <ScamTrendsSection onSelectSample={handleSelectSample} />

        {/* ── How Scam Checking Works ─────────────────────────────────── */}
        <HowItWorksSection onStartCheck={handleStartCheck} />

        {/* ── Frequently Asked Questions ──────────────────────────────── */}
        <FaqSection />

        {/* ── Mission & Story ─────────────────────────────────────────── */}
        <AboutMissionSection onStartCheck={handleStartCheck} />

        {/* ── Report Modal ───────────────────────────────────────────── */}
        <ReportModal
          isOpen={isReportModalOpen}
          onClose={() => setIsReportModalOpen(false)}
          content={text}
          reportedDomain={detectedDomain}
        />

        {/* ── Rich Multi-Column Footer ─────────────────────────────────── */}
        <LandingFooter
          onOpenReportModal={() => setIsReportModalOpen(true)}
          onBackToScanner={handleStartCheck}
        />
      </main>
    </>
  )
}

export default App

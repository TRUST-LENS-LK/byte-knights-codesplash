import React, { useState } from 'react'
import {
  ShieldCheck,
  Search,
  MessageSquare,
  Globe,
  PhoneCall,
  ExternalLink,
  ChevronDown,
  ArrowRight,
  Zap,
  HelpCircle,
  TrendingUp,
  Smartphone,
  Copy,
  Check,
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  Landmark,
  Briefcase,
  Package,
} from 'lucide-react'
import './LandingSections.css'

// ── 1. Top Announcement Bar ──────────────────────────────────────────
export const TopAnnouncementBar: React.FC = () => {
  return (
    <div className="top-announcement-bar">
      <div className="top-announcement-content">
        <span className="announcement-badge">National Cyber Advisory</span>
        <span className="announcement-text">
          Received a suspicious electricity bill, bank SMS, or WhatsApp offer? Verify safely before clicking.
        </span>
        <a href="tel:1937" className="announcement-hotline" title="Call Sri Lanka CERT">
          <PhoneCall size={12} />
          <span>Sri Lanka CERT Hotline: <strong>1937</strong></span>
        </a>
      </div>
    </div>
  )
}

// ── 2. Sri Lanka Scam Trends & Reality Simulator ─────────────────────
export interface ScamSimulation {
  id: string
  tabLabel: string
  iconComponent: React.ComponentType<{ size?: number; className?: string }>
  logoUrl?: string
  title: string
  subtitle: string
  category: string
  riskBadge: 'CRITICAL' | 'HIGH'
  reportedThisWeek: number
  senderHeader: string
  senderSub: string
  carrier: string
  timestamp: string
  messagePrefix: string
  highlightUrgency: string
  messageMiddle: string
  highlightLink: string
  messageSuffix?: string
  fullRawText: string
  redFlags: Array<{
    title: string
    detail: string
  }>
  safeAlternative: string
  officialHotline: string
}

const SRI_LANKA_SCAM_SIMULATIONS: ScamSimulation[] = [
  {
    id: 'ceb-sms',
    tabLabel: 'CEB Power Cut SMS',
    iconComponent: Zap,
    logoUrl: '/ceb_logo.png',
    title: 'Electricity Bill Disconnection SMS',
    subtitle: 'Impersonating Ceylon Electricity Board (CEB)',
    category: 'State Utility Phishing',
    riskBadge: 'CRITICAL',
    reportedThisWeek: 84,
    senderHeader: 'CEB-ALERT',
    senderSub: 'Unregistered Sender • Not in Verified LK Registry',
    carrier: 'Dialog 4G',
    timestamp: 'Today, 2:41 PM',
    messagePrefix: 'CEB Alert: Your electricity connection will be ',
    highlightUrgency: 'disconnected tonight at 10:00 PM',
    messageMiddle: ' due to unpaid bill of Rs. 4,250. Settle now to avoid disconnection: ',
    highlightLink: 'https://ceb-bill-payment-lk.online/portal',
    fullRawText:
      'CEB Alert: Your electricity connection will be disconnected tonight at 10:00 PM due to unpaid bill of Rs. 4,250. Settle now to avoid disconnection: https://ceb-bill-payment-lk.online/portal',
    redFlags: [
      {
        title: 'Fake Foreign Domain (.online)',
        detail: 'Registered in Iceland 3 days ago. Official government and state utilities always use .lk or ceb.lk.',
      },
      {
        title: 'Manufactured Panic',
        detail: 'Threatens power cutoff in a few hours to trigger panic and stop you from checking your actual bill.',
      },
      {
        title: 'Debit Card & OTP Interception',
        detail: 'The fraudulent webpage mimics a payment gateway to harvest your debit card CVV and bank SMS OTP.',
      },
    ],
    safeAlternative: 'Always pay bills exclusively via the official CEB Care mobile app or ceb.lk.',
    officialHotline: 'CEB 24/7 Hotline: 1987',
  },
  {
    id: 'combank-kyc',
    tabLabel: 'Bank eBanking KYC',
    iconComponent: Landmark,
    logoUrl: '/combank_logo.svg',
    title: 'Bank Account Suspension Phishing',
    subtitle: 'Spoofing Commercial Bank & Bank of Ceylon',
    category: 'Banking Credential Theft',
    riskBadge: 'CRITICAL',
    reportedThisWeek: 62,
    senderHeader: 'COMBANK-SEC',
    senderSub: 'Spoofed Caller ID • Anonymous GSM Gateway',
    carrier: 'Mobitel 4G',
    timestamp: 'Today, 11:15 AM',
    messagePrefix: 'COMMERCIAL BANK: Your ComBank digital account has been ',
    highlightUrgency: 'temporarily locked due to unverified KYC',
    messageMiddle: '. Please update your debit card immediately to restore access: ',
    highlightLink: 'https://combank-online-update.me/verify',
    fullRawText:
      'COMMERCIAL BANK: Your ComBank digital account has been temporarily locked due to unverified KYC. Please update your debit card immediately to restore access: https://combank-online-update.me/verify',
    redFlags: [
      {
        title: 'Suspicious TLD (.me)',
        detail: 'Legitimate Sri Lankan commercial banks never host verification portals on random foreign domains.',
      },
      {
        title: 'Banks Never Text Login Links',
        detail: 'Official banking policies in Sri Lanka strictly forbid sending clickable links requiring user credentials.',
      },
      {
        title: 'Complete Account Takeover',
        detail: 'Submitting your credentials allows criminals to instantly enroll unauthorized mobile devices.',
      },
    ],
    safeAlternative: 'Only access internet banking by manually typing combank.lk into your secure browser.',
    officialHotline: 'ComBank 24/7 Emergency: 011-2353596',
  },
  {
    id: 'whatsapp-job',
    tabLabel: 'WhatsApp Task Fraud',
    iconComponent: Briefcase,
    logoUrl: '/whatsapp_logo.svg',
    title: 'Remote Job & YouTube Task Scam',
    subtitle: 'Advance Fee & Pyramid Task Schemes',
    category: 'Financial Fraud',
    riskBadge: 'HIGH',
    reportedThisWeek: 47,
    senderHeader: 'HR Recruiter +94 76 892 1044',
    senderSub: 'WhatsApp Business • Unverified Profile',
    carrier: 'WhatsApp',
    timestamp: 'Yesterday, 5:30 PM',
    messagePrefix: 'Hello! Remote part-time job offer for Sri Lankan citizens. ',
    highlightUrgency: 'Earn Rs. 5,000–15,000 daily',
    messageMiddle: ' liking YouTube videos and following Telegram channels. Payouts via eZ Cash. Connect with manager: ',
    highlightLink: 'https://t.me/LK_TasksManager_Bot',
    fullRawText:
      'Hello! Remote part-time job offer for Sri Lankan citizens. Earn Rs. 5,000–15,000 daily liking YouTube videos and following Telegram channels. Payouts via eZ Cash. Connect with manager: https://t.me/LK_TasksManager_Bot',
    redFlags: [
      {
        title: 'Unrealistic Guaranteed Earnings',
        detail: 'Legitimate global companies never pay thousands of rupees for simply liking social media posts.',
      },
      {
        title: 'Bait-and-Switch Trap',
        detail: 'Scammers pay a tiny sum (Rs. 500) initially to gain your trust, then demand a deposit of Rs. 20,000+.',
      },
      {
        title: 'Anonymous Telegram Payouts',
        detail: 'Uses anonymous handles so victims have no legal recourse when the scammers vanish with their money.',
      },
    ],
    safeAlternative: 'Never pay upfront fees or deposit money to receive job assignments or remote wages.',
    officialHotline: 'Report Fraud: Sri Lanka Police CID',
  },
  {
    id: 'slpost-customs',
    tabLabel: 'Customs Delivery Fee',
    iconComponent: Package,
    logoUrl: '/slpost_logo.png',
    title: 'Parcel Delivery Clearance Scam',
    subtitle: 'Impersonating Sri Lanka Post & Couriers',
    category: 'Courier Impersonation',
    riskBadge: 'HIGH',
    reportedThisWeek: 39,
    senderHeader: 'SL-POST',
    senderSub: 'SMS Broadcast • Unregistered Route',
    carrier: 'Airtel 4G',
    timestamp: 'Today, 9:02 AM',
    messagePrefix: 'SL-POST: Incoming international parcel LK-982412 is on hold. ',
    highlightUrgency: 'Pay customs duty fee of Rs. 380',
    messageMiddle: ' within 48h to avoid package return: ',
    highlightLink: 'https://slpost-parcel-clearance.net',
    fullRawText:
      'SL-POST: Incoming international parcel LK-982412 is on hold. Pay customs duty fee of Rs. 380 within 48h to avoid package return: https://slpost-parcel-clearance.net',
    redFlags: [
      {
        title: 'Phantom Package Tactic',
        detail: 'Sent indiscriminately to mobile users whether or not they have placed international orders.',
      },
      {
        title: 'Micro-Fee Trick',
        detail: 'Requests a small fee (Rs. 380) so victims lower their guard and willingly type their card details.',
      },
      {
        title: 'Recurring Card Charges',
        detail: 'Capturing your CVV and card details allows the fraud ring to run recurring international charges.',
      },
    ],
    safeAlternative: 'Sri Lanka Post customs charges are settled at your local post office, not via arbitrary web links.',
    officialHotline: 'Sri Lanka Post Hotline: 1950',
  },
]

interface ScamTrendsProps {
  onSelectSample: (text: string) => void
}

export const ScamTrendsSection: React.FC<ScamTrendsProps> = ({ onSelectSample }) => {
  const [activeId, setActiveId] = useState<string>('ceb-sms')
  const [copied, setCopied] = useState(false)

  const activeScam = SRI_LANKA_SCAM_SIMULATIONS.find((s) => s.id === activeId) || SRI_LANKA_SCAM_SIMULATIONS[0]

  const handleCopy = (txt: string) => {
    navigator.clipboard.writeText(txt).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }).catch(() => {})
  }

  return (
    <section id="scam-trends" className="landing-section scam-simulator-section">
      {/* Header */}
      <div className="section-header-center">
        <div className="section-eyebrow">
          <TrendingUp size={14} />
          <span>LIVE THREAT PULSE</span>
        </div>
        <h2 className="section-title">Active Scam Campaigns in Sri Lanka</h2>
        <p className="section-subtitle">
          Real fraudulent messages circulating right now across Sri Lankan mobile networks. Select a campaign to inspect the deceptive message, review detected red flags, and test it in the scanner.
        </p>
      </div>

      {/* Interactive Scenario Switcher */}
      <div className="scam-scenario-tabs" role="tablist">
        {SRI_LANKA_SCAM_SIMULATIONS.map((item) => {
          const isActive = item.id === activeId
          return (
            <button
              key={item.id}
              type="button"
              role="tab"
              aria-selected={isActive}
              className={`scam-scenario-tab ${isActive ? 'active' : ''}`}
              onClick={() => setActiveId(item.id)}
            >
              <span className="tab-scenario-icon">
                {item.logoUrl ? (
                  <img
                    src={item.logoUrl}
                    alt={item.tabLabel}
                    className="tab-scenario-logo-img"
                    loading="lazy"
                  />
                ) : (
                  <item.iconComponent size={16} />
                )}
              </span>
              <div className="tab-scenario-info">
                <span className="tab-scenario-name">{item.tabLabel}</span>
                <span className="tab-scenario-count">{item.reportedThisWeek} reports this week</span>
              </div>
              {isActive && <span className="tab-active-dot" />}
            </button>
          )
        })}
      </div>

      {/* Master Detail Simulator Deck */}
      <div className="scam-simulator-stage">
        
        {/* Left Column: Authentic Mobile Device Preview */}
        <div className="simulator-phone-wrapper">
          <div className="simulator-phone-frame">
            {/* Phone Status Bar */}
            <div className="phone-status-bar">
              <span className="phone-carrier">{activeScam.carrier}</span>
              <span className="phone-clock">2:48 PM</span>
              <span className="phone-battery">84%</span>
            </div>

            {/* Conversation Header */}
            <div className="phone-chat-header">
              <div className="phone-avatar-badge">
                {activeScam.logoUrl ? (
                  <img
                    src={activeScam.logoUrl}
                    alt={activeScam.senderHeader}
                    className="phone-avatar-logo-img"
                  />
                ) : (
                  <Smartphone size={18} />
                )}
              </div>
              <div className="phone-sender-details">
                <div className="phone-sender-name-row">
                  <span className="phone-sender-title">{activeScam.senderHeader}</span>
                  <span className="phone-unverified-tag">
                    <AlertTriangle size={11} />
                    Unverified
                  </span>
                </div>
                <span className="phone-sender-sub">{activeScam.senderSub}</span>
              </div>
            </div>

            {/* Message Area */}
            <div className="phone-chat-body">
              <div className="phone-timestamp-divider">
                <span>{activeScam.timestamp}</span>
              </div>

              {/* Realistic Message Bubble */}
              <div className="phone-sms-bubble">
                <p className="phone-sms-text">
                  {activeScam.messagePrefix}
                  <mark className="sms-highlight-urgency" title="Red Flag: Artificial Panic">
                    {activeScam.highlightUrgency}
                  </mark>
                  {activeScam.messageMiddle}
                  <mark className="sms-highlight-link" title="Red Flag: Fake Domain">
                    {activeScam.highlightLink}
                  </mark>
                </p>
                <div className="sms-bubble-footer">
                  <span className="sms-bubble-time">Delivered • 2:41 PM</span>
                  <button
                    type="button"
                    className="btn-copy-bubble"
                    onClick={() => handleCopy(activeScam.fullRawText)}
                    title="Copy message content"
                  >
                    {copied ? <Check size={12} color="#059669" /> : <Copy size={12} />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
              </div>

              {/* Carrier Warning Notice */}
              <div className="phone-carrier-advisory">
                <ShieldAlert size={14} />
                <span>Security Warning: Message contains unverified links asking for sensitive information.</span>
              </div>
            </div>

            {/* Phone Bottom Notch */}
            <div className="phone-home-indicator" />
          </div>
        </div>

        {/* Right Column: Forensic Red-Flag Breakdown */}
        <div className="simulator-dossier-panel">
          <div className="dossier-header">
            <div className="dossier-badge-row">
              <span className={`risk-badge-pill ${activeScam.riskBadge.toLowerCase()}`}>
                <AlertTriangle size={12} style={{ marginRight: 4, verticalAlign: 'middle' }} />
                {activeScam.riskBadge} RISK
              </span>
              <span className="dossier-category-tag">{activeScam.category}</span>
            </div>
            <h3 className="dossier-title">{activeScam.title}</h3>
            <p className="dossier-subtitle">{activeScam.subtitle}</p>
          </div>

          {/* Red Flag List */}
          <div className="dossier-flags-list">
            <h4 className="flags-list-heading">Detected Red Flags:</h4>
            {activeScam.redFlags.map((flag, fIdx) => (
              <div key={fIdx} className="dossier-flag-card">
                <div className="flag-number-badge">{fIdx + 1}</div>
                <div className="flag-content">
                  <h5 className="flag-title">{flag.title}</h5>
                  <p className="flag-detail">{flag.detail}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Safe Alternative Box */}
          <div className="dossier-safe-box">
            <div className="safe-box-header">
              <CheckCircle2 size={16} color="#059669" />
              <span>Official Safe Channel:</span>
            </div>
            <p className="safe-box-text">{activeScam.safeAlternative}</p>
            <span className="safe-box-hotline">{activeScam.officialHotline}</span>
          </div>

          {/* Action Trigger */}
          <div className="dossier-action-row">
            <button
              type="button"
              className="btn-simulate-scanner"
              onClick={() => onSelectSample(activeScam.fullRawText)}
              title="Send this exact message into the TrustLens Scanner"
            >
              <span>Test This Scam in Scanner</span>
              <ArrowRight size={16} />
            </button>
            <span className="dossier-sample-note">Loads this message directly into the scanner</span>
          </div>
        </div>

      </div>

      {/* Live Sri Lanka Fraud Pulse Ticker */}
      <div className="scam-pulse-ticker">
        <div className="pulse-item">
          <span className="pulse-dot" />
          <span className="pulse-label">Average Victim Loss Prevented:</span>
          <strong className="pulse-val">Rs. 18,500 – 95,000</strong>
        </div>
        <div className="pulse-divider" />
        <div className="pulse-item">
          <span className="pulse-label">Active Sri Lankan Phishing Hosts Blocked:</span>
          <strong className="pulse-val">1,420+ LK Targets</strong>
        </div>
        <div className="pulse-divider" />
        <div className="pulse-item">
          <span className="pulse-label">Most Targeted Provinces:</span>
          <strong className="pulse-val">Western, Central & Southern</strong>
        </div>
      </div>
    </section>
  )
}

// ── 3. How It Works Section ──────────────────────────────────────────
export const HowItWorksSection: React.FC<{ onStartCheck: () => void }> = ({ onStartCheck }) => {
  const [isVisible, setIsVisible] = React.useState(false);
  const sectionRef = React.useRef<HTMLElement>(null);

  React.useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true);
          observer.disconnect();
        }
      },
      { threshold: 0.2 }
    );

    if (sectionRef.current) {
      observer.observe(sectionRef.current);
    }

    return () => observer.disconnect();
  }, []);

  return (
    <section id="how-it-works" className="landing-section how-it-works-section" ref={sectionRef}>
      <div className={`how-it-works-container ${isVisible ? 'animate-cards' : ''}`}>
        
        {/* Left Column: Process Steps */}
        <div className="how-it-works-left">
          <div className="section-eyebrow">
            <Zap size={14} />
            <span>HOW IT WORKS</span>
          </div>
          <h2 className="section-title">
            Check any suspicious link or message in three simple steps
          </h2>
          <p className="section-subtitle">
            Got an unexpected SMS, WhatsApp forward, or bank alert? Verify it here before you click the link, reply, or share your OTP.
          </p>

          <div className="process-steps-grid">
            <div className="process-step-card">
              <div className="step-icon-bubble">
                <MessageSquare size={20} />
              </div>
              <div className="step-content">
                <h4 className="step-title">1. Submit message</h4>
                <p className="step-text">
                  Paste any suspicious text, link, or upload a screenshot.
                </p>
              </div>
            </div>

            <div className="process-step-card">
              <div className="step-icon-bubble">
                <Search size={20} />
              </div>
              <div className="step-content">
                <h4 className="step-title">2. AI Analysis</h4>
                <p className="step-text">
                  Our system instantly checks for hidden scam signals.
                </p>
              </div>
            </div>

            <div className="process-step-card">
              <div className="step-icon-bubble">
                <ShieldCheck size={20} />
              </div>
              <div className="step-content">
                <h4 className="step-title">3. Get a verdict</h4>
                <p className="step-text">
                  Receive a clear answer on whether it's safe or a scam.
                </p>
              </div>
            </div>

            <div className="process-step-card">
              <div className="step-icon-bubble">
                <Globe size={20} />
              </div>
              <div className="step-content">
                <h4 className="step-title">4. Protect others</h4>
                <p className="step-text">
                  Every check helps block threats for the community.
                </p>
              </div>
            </div>
          </div>

          <div className="how-it-works-cta-row">
            <button type="button" className="btn-primary-action" onClick={onStartCheck}>
              <ShieldCheck size={16} />
              <span>Check a Message Now</span>
            </button>
            <span className="no-signup-note">Free public service — no sign-up or download needed</span>
          </div>
        </div>

      </div>
    </section>
  )
}

// ── 4. Frequently Asked Questions (FAQ Accordion) ────────────────────
interface FaqItem {
  question: string
  answer: string
}

const FAQ_DATA: FaqItem[] = [
  {
    question: 'What is TrustLens LK, and how does it work?',
    answer:
      'TrustLens LK is a free public tool built for Sri Lanka to verify suspicious messages, SMS alerts, and web links before you click or share sensitive information. It checks domain registration records, official Sri Lankan institution directories, and active phishing patterns to provide an instant, evidence-based verdict.',
  },
  {
    question: 'What types of content can I check?',
    answer:
      'You can check suspicious website links, SMS alerts (like CEB power cut notices or courier fees), WhatsApp messages, Telegram investment forwards, and screenshots taken from your mobile phone using our built-in image OCR scanner.',
  },
  {
    question: 'How does TrustLens determine if something is a scam?',
    answer:
      'We evaluate multiple verifiable signals: how recently the domain was created, SSL certificates, brand impersonation, urgent pressure language, deceptive login or payment forms (asking for passwords, card CVVs, or OTPs), and active Sri Lankan threat reports.',
  },
  {
    question: 'Is TrustLens LK completely free to use?',
    answer:
      'Yes, 100% free with no hidden fees, accounts, or sign-ups required. It is built as a public service to protect citizens from cyber fraud.',
  },
  {
    question: 'Is my personal data or message stored?',
    answer:
      'No. Submissions are processed in real time and discarded from memory. Private credentials such as passwords, debit card numbers, and bank SMS OTPs are automatically stripped out and never saved or shared.',
  },
  {
    question: 'Can TrustLens guarantee that something is 100% safe?',
    answer:
      'TrustLens provides an evidence-based risk assessment based on known scam infrastructure and verified directories. If an unknown message or caller asks you for money or passwords, always verify directly by calling the organization’s official published helpline.',
  },
  {
    question: 'What should I do if I already clicked a suspicious link or transferred money?',
    answer:
      'Act quickly: (1) Call your bank’s 24/7 hotline immediately to freeze your card and digital banking access. (2) Change your online banking passwords from a separate safe phone or computer. (3) Report the incident to the Sri Lanka CERT hotline by calling 1937, and contact the Police Cyber Crime Division at 011-2320141.',
  },
]

export const FaqSection: React.FC = () => {
  const [openIndex, setOpenIndex] = useState<number | null>(0)

  const toggleFaq = (index: number) => {
    setOpenIndex(openIndex === index ? null : index)
  }

  return (
    <section id="faq" className="landing-section faq-section">
      <div className="section-header-center">
        <div className="section-eyebrow">
          <HelpCircle size={14} />
          <span>HELP & ADVICE</span>
        </div>
        <h2 className="section-title">Frequently Asked Questions</h2>
        <p className="section-subtitle">
          Everything you need to know about checking scams, data privacy, and staying safe online in Sri Lanka.
        </p>
      </div>

      <div className="faq-accordion-list">
        {FAQ_DATA.map((item, idx) => {
          const isOpen = openIndex === idx
          return (
            <div
              key={idx}
              className={`faq-accordion-item ${isOpen ? 'open' : ''}`}
            >
              <button
                type="button"
                className="faq-accordion-header"
                onClick={() => toggleFaq(idx)}
                aria-expanded={isOpen}
              >
                <span className="faq-question-text">{item.question}</span>
                <span className={`faq-chevron ${isOpen ? 'rotated' : ''}`}>
                  <ChevronDown size={19} />
                </span>
              </button>

              {isOpen && (
                <div className="faq-accordion-body">
                  <p className="faq-answer-text">{item.answer}</p>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </section>
  )
}

// ── 5. About & Mission Section ───────────────────────────────────────
export const AboutMissionSection: React.FC<{ onStartCheck: () => void }> = ({ onStartCheck }) => {
  return (
    <section id="about" className="landing-section about-mission-section">
      <div className="about-mission-card">
        <div className="mission-eyebrow-pill">
          <ShieldCheck size={14} />
          <span>PUBLIC CYBER DEFENSE INITIATIVE</span>
        </div>
        <h2 className="mission-title">Scams are evolving. Your protection should too.</h2>
        <div className="mission-grid">
          <div className="mission-grid-item">
            <div className="mission-icon-box">
              <AlertTriangle size={20} />
            </div>
            <div className="mission-text-content">
              <h4>The Growing Threat</h4>
              <p>Thousands of Sri Lankans lose money daily to deceptive SMS alerts, fake investment schemes, and spoofed bank portals.</p>
            </div>
          </div>
          <div className="mission-grid-item">
            <div className="mission-icon-box">
              <Search size={20} />
            </div>
            <div className="mission-text-content">
              <h4>A Free Second Opinion</h4>
              <p>We provide families, elders, and banking consumers a secure platform to verify messages when something doesn't feel right.</p>
            </div>
          </div>
          <div className="mission-grid-item">
            <div className="mission-icon-box">
              <ShieldCheck size={20} />
            </div>
            <div className="mission-text-content">
              <h4>Collective Defense</h4>
              <p>Together with community vigilance and national threat intelligence, we are building digital resilience for Sri Lanka.</p>
            </div>
          </div>
        </div>

        <div className="mission-actions">
          <button type="button" className="btn-primary-action mission-btn-primary" onClick={onStartCheck}>
            <ShieldCheck size={16} />
            <span>Verify a Suspicious Message</span>
          </button>
          <a href="tel:1937" className="btn-outline-hotline" title="Call Sri Lanka CERT">
            <PhoneCall size={15} />
            <span>Sri Lanka CERT Hotline: 1937</span>
          </a>
        </div>
      </div>
    </section>
  )
}

// ── 6. Comprehensive Professional Footer ─────────────────────────────
interface FooterProps {
  onOpenReportModal: () => void
  onBackToScanner: () => void
}

export const LandingFooter: React.FC<FooterProps> = ({ onOpenReportModal, onBackToScanner }) => {
  const scrollTo = (id: string) => {
    const el = document.getElementById(id)
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' })
    } else {
      window.scrollTo({ top: 0, behavior: 'smooth' })
    }
  }

  return (
    <footer className="rich-landing-footer">
      <div className="footer-columns-grid">
        
        {/* Column 1: Brand & Emergency */}
        <div className="footer-col footer-col-brand">
          <div className="footer-brand-header">
            <div className="footer-logo-box">
              <img src="/TrustLens_Icon.png" alt="TrustLens LK" className="footer-logo-img" />
            </div>
            <span className="footer-brand-name">
              TrustLens <span className="nav-brand-badge">LK</span>
            </span>
          </div>
          <p className="footer-brand-mission">
            Sri Lanka’s Scam Decision Support & Threat Intelligence Platform. Protecting citizens, families, and digital banking consumers against phishing and cyber fraud.
          </p>
          <div className="footer-hotline-box">
            <span className="footer-hotline-label">Emergency Cyber Incident Hotline:</span>
            <a href="tel:1937" className="footer-hotline-number">
              <PhoneCall size={14} />
              <span>Dial 1937 (Sri Lanka CERT)</span>
            </a>
          </div>
        </div>

        {/* Column 2: Scam Check Tools */}
        <div className="footer-col">
          <h4 className="footer-col-title">Scam Check Tools</h4>
          <ul className="footer-links-list">
            <li>
              <a href="#checker" onClick={(e) => { e.preventDefault(); onBackToScanner(); }}>
                Link & URL Safety Scanner
              </a>
            </li>
            <li>
              <a href="#checker" onClick={(e) => { e.preventDefault(); onBackToScanner(); }}>
                Screenshot OCR Reader
              </a>
            </li>
            <li>
              <a href="#checker" onClick={(e) => { e.preventDefault(); onBackToScanner(); }}>
                SMS & WhatsApp Scam Detector
              </a>
            </li>
            <li>
              <a href="#checker" onClick={(e) => { e.preventDefault(); onBackToScanner(); }}>
                Bank Spoofing Verifier
              </a>
            </li>
            <li>
              <button type="button" className="footer-action-link" onClick={onOpenReportModal}>
                Report a New Scam
              </button>
            </li>
          </ul>
        </div>

        {/* Column 3: Common Sri Lanka Scams */}
        <div className="footer-col">
          <h4 className="footer-col-title">Common LK Scams</h4>
          <ul className="footer-links-list">
            <li>
              <a href="#scam-trends" onClick={(e) => { e.preventDefault(); scrollTo('scam-trends'); }}>
                Electricity Bill (CEB) SMS Scams
              </a>
            </li>
            <li>
              <a href="#scam-trends" onClick={(e) => { e.preventDefault(); scrollTo('scam-trends'); }}>
                Commercial Bank / BOC Phishing
              </a>
            </li>
            <li>
              <a href="#scam-trends" onClick={(e) => { e.preventDefault(); scrollTo('scam-trends'); }}>
                Sri Lanka Post Customs Clearance
              </a>
            </li>
            <li>
              <a href="#scam-trends" onClick={(e) => { e.preventDefault(); scrollTo('scam-trends'); }}>
                WhatsApp Daily Task & Job Scams
              </a>
            </li>
            <li>
              <a href="#scam-trends" onClick={(e) => { e.preventDefault(); scrollTo('scam-trends'); }}>
                Telegram Crypto Investment Fraud
              </a>
            </li>
          </ul>
        </div>

        {/* Column 4: Official Emergency Resources */}
        <div className="footer-col">
          <h4 className="footer-col-title">Official Resources</h4>
          <ul className="footer-links-list">
            <li>
              <a href="https://www.cert.gov.lk" target="_blank" rel="noreferrer" className="external-link-item">
                <span>Sri Lanka CERT | CC</span>
                <ExternalLink size={12} />
              </a>
            </li>
            <li>
              <a href="https://www.cbsl.gov.lk" target="_blank" rel="noreferrer" className="external-link-item">
                <span>Central Bank of Sri Lanka</span>
                <ExternalLink size={12} />
              </a>
            </li>
            <li>
              <span className="footer-static-info">Police CID Cyber Crime: 011-2320141</span>
            </li>
            <li>
              <a href="#faq" onClick={(e) => { e.preventDefault(); scrollTo('faq'); }}>
                Frequently Asked Questions
              </a>
            </li>
            <li>
              <a href="#how-it-works" onClick={(e) => { e.preventDefault(); scrollTo('how-it-works'); }}>
                How Scam Verification Works
              </a>
            </li>
          </ul>
        </div>

      </div>

      {/* Bottom Bar */}
      <div className="footer-bottom-bar">
        <p className="footer-copyright">
          © 2026 TrustLens LK — Sri Lanka National Scam Defense. Built for public cyber resilience.
        </p>
        <div className="footer-bottom-badges">
          <span className="bottom-badge">Privacy-First Architecture</span>
          <span className="bottom-divider">•</span>
          <span className="bottom-badge">Real-Time Threat Analysis</span>
          <span className="bottom-divider">•</span>
          <span className="bottom-badge">Sri Lanka Cyber Resilience</span>
        </div>
      </div>
    </footer>
  )
}

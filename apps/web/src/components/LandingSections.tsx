import React, { useState, useEffect, useCallback } from 'react'
import {
  ShieldCheck,
  Search,
  MessageSquare,
  Globe,
  PhoneCall,
  ExternalLink,
  ChevronDown,
  AlertOctagon,
  Zap,
  HelpCircle,
  CheckCircle2,
  ShieldAlert,
  Landmark,
  Package,
  Briefcase,
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

// ── 2. Sri Lanka Scam Breakdown: How Scammers Trick You ───────────────
interface ThreatCategory {
  id: string
  label: string
  iconComponent: React.ComponentType<{ size?: number; className?: string }>
  logoUrl?: string
  targetEntity: string
  chain: {
    origin: { step: string; text: string; sub: string }
    lure: { step: string; text: string; sub: string }
    payload: { step: string; text: string; sub: string }
  }
  defense: {
    authority: string
    officialDomain: string
    policy: string
    hotline: string
    hotlineLabel: string
  }
}

const SRI_LANKA_THREAT_CATEGORIES: ThreatCategory[] = [
  {
    id: 'utilities',
    label: 'Electricity Bill (CEB)',
    iconComponent: Zap,
    logoUrl: '/ceb_logo.png',
    targetEntity: 'Ceylon Electricity Board (CEB)',
    chain: {
      origin: {
        step: '1 · The Message',
        text: 'Power cut tonight at 10 PM',
        sub: 'Urgent SMS from unknown number',
      },
      lure: {
        step: '2 · The Trap',
        text: 'Pay overdue bill now via link',
        sub: 'Takes you to fake payment site',
      },
      payload: {
        step: '3 · The Loss',
        text: 'Steals card details & OTP',
        sub: 'Bank card drained instantly',
      },
    },
    defense: {
      authority: 'Ceylon Electricity Board',
      officialDomain: 'ceb.lk',
      policy: 'CEB gives 10-day notice on paper bills. They never demand card payment via SMS links.',
      hotline: '1987',
      hotlineLabel: 'CEB Helpline',
    },
  },
  {
    id: 'banking',
    label: 'Bank Accounts',
    iconComponent: Landmark,
    logoUrl: '/combank_logo.svg',
    targetEntity: 'Commercial Banks (ComBank, BOC, Sampath)',
    chain: {
      origin: {
        step: '1 · The Message',
        text: 'Account or card is blocked',
        sub: 'Fake security alert SMS',
      },
      lure: {
        step: '2 · The Trap',
        text: 'Click here to verify identity',
        sub: 'Cloned bank login page',
      },
      payload: {
        step: '3 · The Loss',
        text: 'Steals your password & OTP',
        sub: 'Unauthorized money transfers',
      },
    },
    defense: {
      authority: 'Central Bank of Sri Lanka (CBSL)',
      officialDomain: 'combank.lk',
      policy: 'Sri Lankan banks NEVER send clickable links in SMS. Any SMS with a login link is a scam.',
      hotline: '011-2353596',
      hotlineLabel: 'Bank Card Center',
    },
  },
  {
    id: 'logistics',
    label: 'Postal Packages',
    iconComponent: Package,
    logoUrl: '/slpost_logo.png',
    targetEntity: 'Department of Posts & Customs',
    chain: {
      origin: {
        step: '1 · The Message',
        text: 'Parcel delivery failed',
        sub: 'SMS claiming missing address',
      },
      lure: {
        step: '2 · The Trap',
        text: 'Pay Rs. 380 fee to reschedule',
        sub: 'Fake postal tracking website',
      },
      payload: {
        step: '3 · The Loss',
        text: 'Steals your card numbers',
        sub: 'Unauthorized payments charged',
      },
    },
    defense: {
      authority: 'Department of Posts, Sri Lanka',
      officialDomain: 'slpost.gov.lk',
      policy: 'Sri Lanka Post delivers printed slips to your home. They never ask for SMS fee payments.',
      hotline: '1950',
      hotlineLabel: 'Postal Helpline',
    },
  },
  {
    id: 'recruitment',
    label: 'WhatsApp Job Offers',
    iconComponent: Briefcase,
    logoUrl: '/whatsapp_logo.svg',
    targetEntity: 'WhatsApp & Telegram Job Offers',
    chain: {
      origin: {
        step: '1 · The Message',
        text: 'Earn Rs. 15,000/day liking videos',
        sub: 'Stranger texts you on WhatsApp',
      },
      lure: {
        step: '2 · The Trap',
        text: 'Deposit money to unlock VIP pay',
        sub: 'Gives tiny test payout first',
      },
      payload: {
        step: '3 · The Loss',
        text: 'Scammers block you & take cash',
        sub: 'All deposited money is lost',
      },
    },
    defense: {
      authority: 'Sri Lanka Police Cyber Crimes Division',
      officialDomain: 'police.lk',
      policy: 'Real companies never hire on WhatsApp or ask for deposits to receive a salary.',
      hotline: '011-2422176',
      hotlineLabel: 'Police Cyber Crimes',
    },
  },
]

interface ScamTrendsProps {
  onSelectSample?: (text: string) => void
}

export const ScamTrendsSection: React.FC<ScamTrendsProps> = () => {
  const [activeIndex, setActiveIndex] = useState(0)
  const [direction, setDirection] = useState<'next' | 'prev'>('next')
  const [animating, setAnimating] = useState(false)
  const total = SRI_LANKA_THREAT_CATEGORIES.length

  const goTo = useCallback(
    (nextIndex: number, dir: 'next' | 'prev') => {
      if (animating) return
      setDirection(dir)
      setAnimating(true)
      setTimeout(() => {
        setActiveIndex((nextIndex + total) % total)
        setAnimating(false)
      }, 380)
    },
    [animating, total]
  )

  const goNext = useCallback(() => goTo(activeIndex + 1, 'next'), [goTo, activeIndex])
  const goPrev = useCallback(() => goTo(activeIndex - 1, 'prev'), [goTo, activeIndex])

  // Auto-advance every 6 seconds
  useEffect(() => {
    const timer = setInterval(goNext, 6000)
    return () => clearInterval(timer)
  }, [goNext])

  const current = SRI_LANKA_THREAT_CATEGORIES[activeIndex]

  return (
    <section id="scam-trends" className="landing-section threat-intel-section">
      <div className="section-header-center">
        <div className="section-eyebrow">
          <ShieldAlert size={14} />
          <span>HOW SCAMS WORK</span>
        </div>
        <h2 className="section-title">How Scammers Trick People in Sri Lanka</h2>
        <p className="section-subtitle">
          See the simple 3-step trick scammers use, and what real organizations actually do.
        </p>
      </div>

      {/* Slideshow Card */}
      <div className="slideshow-outer">

        {/* Prev Button */}
        <button
          type="button"
          className="slide-nav-btn slide-nav-prev"
          onClick={goPrev}
          aria-label="Previous scam"
        >
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M13 4L7 10L13 16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </button>

        {/* Slide Content */}
        <div className="slideshow-viewport">
          <div
            className={`slide-content-wrapper ${
              animating ? (direction === 'next' ? 'slide-exit-left' : 'slide-exit-right') : 'slide-enter'
            }`}
          >
            {/* Compact Structured Slide Card */}
            <div className="slide-compact-container">
              {/* Header: Visible Logo + Title + Hotline */}
              <div className="slide-compact-header">
                <div className="slide-brand-group">
                  <div className="slide-brand-logo-tile">
                    {current.logoUrl ? (
                      <img src={current.logoUrl} alt={current.label} className="slide-brand-logo-img" />
                    ) : (
                      <current.iconComponent size={24} className="slide-brand-fallback-icon" />
                    )}
                  </div>
                  <div className="slide-brand-text">
                    <div className="slide-brand-meta">
                      <span className="slide-category-tag-sm">{current.label}</span>
                      <code className="slide-domain-pill">{current.defense.officialDomain}</code>
                    </div>
                    <h3 className="slide-target-title">{current.targetEntity}</h3>
                  </div>
                </div>

                <a href={`tel:${current.defense.hotline}`} className="slide-hotline-badge" title="Call official helpline">
                  <PhoneCall size={13} />
                  <span>{current.defense.hotlineLabel}: <strong>{current.defense.hotline}</strong></span>
                </a>
              </div>

              {/* 3 Step Flow: Compact Horizontal Cards */}
              <div className="slide-steps-grid">
                {/* Step 1: The Message */}
                <div className="slide-mini-card">
                  <span className="mini-phase-label phase-blue">{current.chain.origin.step}</span>
                  <h4 className="mini-step-text">{current.chain.origin.text}</h4>
                  <p className="mini-step-sub">{current.chain.origin.sub}</p>
                </div>

                {/* Arrow */}
                <div className="slide-step-arrow" aria-hidden="true">
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M5 12H19M19 12L13 6M19 12L13 18" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </div>

                {/* Step 2: The Trap */}
                <div className="slide-mini-card">
                  <span className="mini-phase-label phase-amber">{current.chain.lure.step}</span>
                  <h4 className="mini-step-text">{current.chain.lure.text}</h4>
                  <p className="mini-step-sub">{current.chain.lure.sub}</p>
                </div>

                {/* Arrow */}
                <div className="slide-step-arrow" aria-hidden="true">
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M5 12H19M19 12L13 6M19 12L13 18" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </div>

                {/* Step 3: The Loss */}
                <div className="slide-mini-card">
                  <span className="mini-phase-label phase-red">{current.chain.payload.step}</span>
                  <h4 className="mini-step-text">{current.chain.payload.text}</h4>
                  <p className="mini-step-sub">{current.chain.payload.sub}</p>
                </div>
              </div>

              {/* Defense Strip: Natural & Understated */}
              <div className="slide-slim-defense">
                <ShieldCheck size={16} className="defense-shield-icon" />
                <span className="defense-rule-lead">Real Rule:</span>
                <span className="defense-rule-body">{current.defense.policy}</span>
              </div>
            
            </div>
          </div>
        </div>

        {/* Next Button */}
        <button
          type="button"
          className="slide-nav-btn slide-nav-next"
          onClick={goNext}
          aria-label="Next scam"
        >
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M7 4L13 10L7 16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </button>

        {/* Dot Indicators */}
        <div className="slide-dots">
          {SRI_LANKA_THREAT_CATEGORIES.map((cat, i) => (
            <button
              key={cat.id}
              type="button"
              className={`slide-dot ${i === activeIndex ? 'active' : ''}`}
              onClick={() => goTo(i, i > activeIndex ? 'next' : 'prev')}
              aria-label={cat.label}
            />
          ))}
        </div>
      </div>
    </section>
  )
}

// ── 3. How It Works Section ──────────────────────────────────────────
export const HowItWorksSection: React.FC<{ onStartCheck: () => void }> = ({ onStartCheck }) => {
  return (
    <section id="how-it-works" className="landing-section how-it-works-section">
      <div className="how-it-works-container">
        
        {/* Left Column: Process Steps */}
        <div className="how-it-works-left">
          <div className="section-eyebrow">
            <Zap size={14} />
            <span>HOW IT WORKS</span>
          </div>
          <h2 className="section-title">
            A free scam check, whenever you need a second opinion
          </h2>
          <p className="section-subtitle">
            Don't risk your savings or passwords. TrustLens LK gives you immediate clarity on suspicious messages and links before damage is done.
          </p>

          <div className="process-steps-list">
            <div className="process-step-item">
              <div className="step-icon-bubble">
                <MessageSquare size={20} />
              </div>
              <div className="step-content">
                <h4 className="step-title">1. Submit a suspicious message or link</h4>
                <p className="step-text">
                  Paste text from SMS, WhatsApp, Telegram, email, or a suspicious web URL. You can also upload a mobile screenshot with built-in OCR.
                </p>
              </div>
            </div>

            <div className="process-step-item">
              <div className="step-icon-bubble">
                <Search size={20} />
              </div>
              <div className="step-content">
                <h4 className="step-title">2. TrustLens checks for scam signals</h4>
                <p className="step-text">
                  Our multi-layer engine inspects domain age, spoofed brand logos, credential phishing forms, hidden scripts, and national blacklist records.
                </p>
              </div>
            </div>

            <div className="process-step-item">
              <div className="step-icon-bubble">
                <ShieldCheck size={20} />
              </div>
              <div className="step-content">
                <h4 className="step-title">3. Get a fast, clear answer and next steps</h4>
                <p className="step-text">
                  You'll quickly get a clear verdict, along with an easy-to-understand explanation and guidance on what to do next.
                </p>
              </div>
            </div>

            <div className="process-step-item">
              <div className="step-icon-bubble">
                <Globe size={20} />
              </div>
              <div className="step-content">
                <h4 className="step-title">4. Community & National Defense</h4>
                <p className="step-text">
                  Every scam checked helps train collective intelligence, alerting Sri Lanka CERT and fellow citizens to prevent further victims.
                </p>
              </div>
            </div>
          </div>

          <div className="how-it-works-cta-row">
            <button type="button" className="btn-primary-action" onClick={onStartCheck}>
              <ShieldCheck size={16} />
              <span>Run a Quick Scam Check</span>
            </button>
            <span className="no-signup-note">Free public service — no account needed</span>
          </div>
        </div>

        {/* Right Column: Realistic Preview Card (Matching user inspiration image) */}
        <div className="how-it-works-right">
          <div className="sample-verdict-card">
            <div className="sample-verdict-header">
              <div className="sample-verdict-badge">
                <AlertOctagon size={18} />
                <span>Definitely a scam</span>
              </div>
              <span className="sample-category-tag">Spear Phishing</span>
            </div>

            <p className="sample-threat-summary">
              The message received is a targeted phishing attack impersonating <strong>Ceylon Electricity Board (CEB)</strong>, with 58 similar reports this week.
            </p>

            <div className="sample-breakdown-box">
              <h5 className="breakdown-title">
                <ShieldAlert size={15} />
                <span>Why it's a scam</span>
              </h5>
              <p className="breakdown-text">
                Your link points to an unverified domain (<strong>ceb-bill-payment-lk.online</strong>) registered only 3 days ago in Iceland, masquerading as a Sri Lankan state utility.
              </p>
              <p className="breakdown-text">
                The webpage contains deceptive form fields attempting to harvest debit card CVVs and SMS OTP verification codes.
              </p>
            </div>

            <div className="sample-next-steps-box">
              <h5 className="next-steps-title">
                <CheckCircle2 size={15} />
                <span>Recommended next steps</span>
              </h5>
              <ul className="next-steps-list">
                <li>
                  <span className="step-num">1</span>
                  <span><strong>Do not click the link</strong> or enter any banking details.</span>
                </li>
                <li>
                  <span className="step-num">2</span>
                  <span><strong>Never share your SMS OTP</strong> with anyone calling or texting.</span>
                </li>
                <li>
                  <span className="step-num">3</span>
                  <span>Report the suspicious message to Sri Lanka CERT hotline (<strong>1937</strong>).</span>
                </li>
              </ul>
            </div>

            <div className="sample-card-footer">
              <span className="sample-confidence">Verified by TrustLens Threat Engine</span>
              <span className="sample-hotline-pill">Hotline: 1937</span>
            </div>
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
      'TrustLens LK is a free national scam decision-support tool built for Sri Lanka. It combines domain reputation analysis, simulated browser sandbox scanning, and community threat reports to detect malicious links, fake government messages, and banking fraud before citizens fall victim.',
  },
  {
    question: 'What types of content can I check?',
    answer:
      'You can check suspicious website URLs, SMS messages (like CEB electricity bill or courier alerts), WhatsApp job offers, Telegram investment links, and mobile screenshots of text conversations using our built-in OCR image scanner.',
  },
  {
    question: 'How does TrustLens decide if something is a scam?',
    answer:
      'We inspect multiple safety factors: domain registration age, SSL authenticity, deceptive brand impersonation, urgent pressure tactics, dangerous input fields (asking for passwords, card CVVs, or OTPs), and national threat intelligence reports.',
  },
  {
    question: 'Is TrustLens LK completely free to use?',
    answer:
      'Yes, 100% free and open for public protection. There is no sign-up, email registration, or credit card required.',
  },
  {
    question: 'What happens to what I submit? Is my privacy protected?',
    answer:
      'Your privacy is strictly respected. Submissions are processed securely in temporary memory. Passwords, personal identification, and private banking numbers are automatically stripped and never stored or disclosed in public records.',
  },
  {
    question: 'Can TrustLens guarantee that something is 100% safe or a scam?',
    answer:
      'TrustLens provides a high-confidence advisory assessment based on rigorous heuristics and sandbox scans. However, cybercriminals constantly invent new tactics. If in doubt, always contact the organization directly through official, verified phone numbers.',
  },
  {
    question: 'What should I do if I already clicked a suspicious link or sent money?',
    answer:
      'Take immediate action: (1) Call your bank’s 24/7 hotline to freeze your card and digital banking accounts. (2) Change your passwords from a separate trusted device. (3) Report the fraud to Sri Lanka CERT by calling 1937, and file a complaint with the Sri Lanka Police CID Cyber Crime Division.',
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
          Everything you need to know about checking scams, privacy, and protecting your digital safety in Sri Lanka.
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
          <span>SRI LANKA SCAM DEFENSE INITIATIVE</span>
        </div>
        <h2 className="mission-title">Scams are evolving. Your protection should too.</h2>
        <p className="mission-lead">
          Every month, thousands of Sri Lankans lose their hard-earned money to deceptive SMS alerts, fake investment schemes, and spoofed bank portals. Fueled by automated tools, online scams have become convincing and dangerous.
        </p>
        <p className="mission-body">
          TrustLens LK was founded to give Sri Lankan families, elders, and digital banking consumers a free second opinion whenever something doesn't feel right. Together with community vigilance and national threat intelligence, we are building digital resilience for Sri Lanka.
        </p>

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

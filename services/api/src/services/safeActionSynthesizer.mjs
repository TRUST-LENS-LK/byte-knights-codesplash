/**
 * TrustLens LK — Contextual Safe Action Synthesizer
 * ───────────────────────────────────────────────────
 * Dynamically synthesizes threat-tailored action checklists for citizens based
 * strictly on evaluated signals, database directory metadata, and statutory reporting authorities.
 *
 * Fully dynamic: No hardcoded organization names, phone numbers, or static dictionaries.
 */

/**
 * Synthesizes a contextual, deduplicated action checklist tailored to the evaluated risk.
 *
 * @param {Object} options
 * @param {'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN'} options.riskBand
 * @param {string} options.recommendation
 * @param {Array} options.findings
 * @param {string|null} [options.claimedOrg]
 * @param {string|null} [options.matchedOrg]
 * @param {string|null} [options.sourceUrl]
 * @param {boolean} [options.isAdvisory]
 * @param {boolean} [options.isTransactional]
 * @param {boolean} [options.isCoercive]
 * @param {Array} [options.authorities]
 * @returns {string[]}
 */
export function synthesizeSafeActions({
  riskBand,
  recommendation,
  findings = [],
  claimedOrg = null,
  matchedOrg = null,
  sourceUrl = null,
  isAdvisory = false,
  isTransactional = false,
  isPromotion = false,
  isCoercive = false,
  authorities = [],
}) {
  const actions = new Set()
  const signals = new Set(findings.map((f) => f.canonicalSignal))
  const relevantOrg = matchedOrg || claimedOrg

  // 1. Genuine Defensive / Advisory Context
  if (isAdvisory) {
    actions.add('This notice contains defensive educational guidance. No scam intent detected.')
    actions.add('Remember that genuine financial and public institutions will never ask for your OTP, PIN, or passwords over SMS or phone calls.')
    if (relevantOrg) {
      actions.add(`For official notices and services, always access ${relevantOrg} through their verified portal${sourceUrl ? ` (${sourceUrl})` : ''}.`)
    }
    return Array.from(actions)
  }

  // 1b. Genuine Transactional / OTP Delivery Notification Context
  if (isTransactional) {
    actions.add('This message appears to be an automated transaction verification notification delivering a one-time code.')
    actions.add('Verify that the merchant name and transaction amount correspond exactly to the purchase you are making.')
    actions.add('CRITICAL: Never disclose, forward, or speak this OTP to anyone over phone or text. Genuine bank or merchant staff will never ask for it.')
    actions.add('If you did not initiate this transaction, contact your card issuing bank immediately to freeze your card.')
    return Array.from(actions)
  }

  // 1c. Genuine Commercial Promotion / Informational Notice Context
  if (isPromotion) {
    actions.add('This communication appears to be a legitimate commercial promotion or informational update.')
    actions.add('No fraudulent patterns, coercive lures, or credential demands were detected.')
    if (relevantOrg) {
      actions.add(`Verify promotions and place orders directly through ${relevantOrg}'s official portal${sourceUrl ? ` (${sourceUrl})` : ''}.`)
    } else {
      actions.add('Always ensure you access promotions through the merchant\'s verified official website or mobile app.')
    }
    return Array.from(actions)
  }

  // 1d. Genuine Verified Safe Official Portal Context
  if (riskBand === 'LOW' && recommendation === 'VERIFIED_SAFE') {
    actions.add(`This destination is confirmed as an authentic official portal${relevantOrg ? ` for ${relevantOrg}` : ''}.`)
    actions.add('Always ensure your browser address bar displays a secure HTTPS connection and the correct domain name.')
    if (relevantOrg && sourceUrl) {
      actions.add(`Official portal confirmed: ${sourceUrl}`)
    }
    return Array.from(actions)
  }

  // 2. High Risk / Critical Threat Directives
  if (riskBand === 'HIGH') {
    actions.add('Do not click any links, download attachments, or share personal or financial information.')

    // Credential Theft / OTP Warning
    if (signals.has('credential_request') || signals.has('embedded_credentials') || recommendation === 'OFFICIAL_ENTITY_WITH_CAUTION') {
      actions.add('CRITICAL: Never share your OTP, PIN, password, or card security code with anyone. Legitimate organizations never request them.')
      actions.add('If you have already entered credentials on the linked site, contact your financial institution immediately to freeze accounts and reset access credentials.')
    }

    // Advance Payment / Fee Warning
    if (signals.has('advance_payment') || signals.has('payment_demand')) {
      actions.add('Do not send any upfront fees, registration deposits, or processing transfers.')
    }

    // Job Scam / Coercive Task Lure Warning
    if (signals.has('job_scam') || signals.has('fake_job') || signals.has('coercive_scam_lure') || isCoercive) {
      actions.add('Be alert to fraudulent job or task offers promising quick daily earnings. Legitimate employers do not recruit through untrusted messaging links or demand task deposits.')
    }

    // Domain Impersonation / Lookalike Warning
    if (signals.has('domain_mismatch')) {
      actions.add(`The destination link does not belong to ${relevantOrg || 'the claimed organization'}. Verify domain authenticity before proceeding.`)
    }

    // Known Malicious Threat / Malware
    if (signals.has('known_malicious_domain') || signals.has('unsafe_url_target')) {
      actions.add('This destination is flagged on verified cyber-threat registries as actively hosting deceptive or malicious content.')
    }

    // Organization Contact
    if (relevantOrg) {
      actions.add(`Verify your account status directly with ${relevantOrg} via their official customer care or website${sourceUrl ? ` (${sourceUrl})` : ''}. Do not use contact details provided in the message.`)
    }

    // Dynamic Statutory Reporting Channels from Directory
    if (Array.isArray(authorities) && authorities.length > 0) {
      for (const auth of authorities) {
        if (!auth?.name) continue
        const contactRef = auth.officialDomain || auth.sourceUrl || auth.official_domain || auth.source_url
        actions.add(`Report this fraudulent communication to ${auth.name}${contactRef ? ` via official channel (${contactRef})` : ''}.`)
      }
    } else {
      actions.add('Report this fraudulent message and any associated payment demands to your local law enforcement cybercrime division.')
      actions.add('Submit suspicious links and cyber threat indicators to your national cybersecurity emergency response authority.')
    }

    return Array.from(actions).slice(0, 5)
  }

  // 3. Medium Risk (Cautious / Unverified) Directives
  if (riskBand === 'MEDIUM') {
    actions.add('Do not act on this request until you have independently verified the sender through an official channel.')

    if (signals.has('new_domain_risk')) {
      actions.add('The linked domain was registered recently. Newly created domains carry a higher risk of being part of temporary fraudulent campaigns.')
    }

    if (signals.has('urgency')) {
      actions.add('Be cautious of artificial deadlines or threats of immediate account suspension. Urgency is commonly used to pressure hasty decisions.')
    }

    if (relevantOrg) {
      actions.add(`Verify this communication directly with ${relevantOrg} through their official channels.`)
    } else {
      actions.add('Search for the organization\'s official customer care details separately — do not rely on contact information in the message.')
    }

    actions.add('Never reveal one-time passwords (OTPs) or banking credentials under any circumstances.')
    return Array.from(actions).slice(0, 4)
  }

  // 4. Low Risk / Safe Directives
  actions.add('No critical threat indicators were detected, but continue exercising standard digital caution.')
  actions.add('Always ensure your browser address bar displays a valid HTTPS connection and the exact official domain before entering sensitive details.')
  actions.add('Never share OTPs, PINs, or passwords with anyone.')

  return Array.from(actions)
}

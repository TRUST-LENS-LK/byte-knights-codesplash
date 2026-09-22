import { GOOGLE_SAFE_BROWSING_API_KEY } from '../config/env.mjs'

const API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
const REQUEST_TIMEOUT_MS = 4_000

// Tier 4 of the domain verification pipeline: live threat reputation via
// Google Safe Browsing, the same database Chrome itself uses to block
// known phishing/malware sites. This is fail-open by design in two ways:
// no API key configured, or the API being unreachable, both result in this
// tier being silently skipped, never in blocking or slowing down analysis.
export function isSafeBrowsingConfigured() {
  return Boolean(GOOGLE_SAFE_BROWSING_API_KEY)
}

function buildFinding(url, threatType) {
  const labels = {
    MALWARE: 'distributing malware',
    SOCIAL_ENGINEERING: 'a known phishing or social engineering site',
    UNWANTED_SOFTWARE: 'distributing unwanted software',
    POTENTIALLY_HARMFUL_APPLICATION: 'hosting a potentially harmful application',
  }
  return {
    canonicalSignal: 'known_malicious_domain',
    category: 'Domain verification',
    evidence: `${url} is listed by Google Safe Browsing as ${labels[threatType] || 'a known threat'}.`,
    source: 'DOMAIN_DIRECTORY',
    strength: 0.98,
    confidence: 0.95,
    limitation: 'Reflects Google Safe Browsing\'s database at the time of this check; a clean result does not guarantee future safety.',
    detectorVersion: 'safe-browsing-v1',
  }
}

/**
 * Queries Google Safe Browsing v4 for a single URL. Returns the list of
 * threat types found (empty when clean), or null when the check could not
 * be completed at all (no key configured, network failure, non-2xx
 * response), so callers can tell "checked and clean" apart from "could not
 * check".
 */
export async function checkUrlAgainstSafeBrowsing(url) {
  if (!GOOGLE_SAFE_BROWSING_API_KEY) return null

  const body = {
    client: { clientId: 'trustlens-lk', clientVersion: '1.0.0' },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }],
    },
  }

  const response = await fetch(`${API_URL}?key=${encodeURIComponent(GOOGLE_SAFE_BROWSING_API_KEY)}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  })
  if (!response.ok) return null
  const data = await response.json().catch(() => null)
  if (!data?.matches) return []
  return [...new Set(data.matches.map((match) => match.threatType))]
}

/**
 * Full Tier 4 check for use in the analyze pipeline: looks at the first URL
 * entity found (Safe Browsing checks full URLs, not just domains, since a
 * threat can be scoped to a specific path). Any failure (no key, network
 * error, timeout) is swallowed, this tier is supplementary, never critical.
 */
export async function checkSafeBrowsing(entities) {
  if (!isSafeBrowsingConfigured()) return { findings: [] }
  const urlEntity = entities.find((entity) => entity.type === 'url')
  if (!urlEntity) return { findings: [] }
  const url = urlEntity.normalizedValue || urlEntity.value
  if (!url) return { findings: [] }

  try {
    const threatTypes = await checkUrlAgainstSafeBrowsing(url)
    if (!threatTypes || threatTypes.length === 0) return { findings: [] }
    return { findings: threatTypes.map((threatType) => buildFinding(url, threatType)) }
  } catch {
    return { findings: [] }
  }
}

/**
 * A confirmed Google Safe Browsing hit is a critical override, the same
 * pattern already used for domain_mismatch (domainVerification.mjs) and
 * severe scanner findings (analysis.mjs): being live-listed as malware or
 * phishing is about as strong a signal as this system can produce.
 */
export function applyKnownMaliciousRisk(decision) {
  const flagged = decision.findings.some((finding) => finding.canonicalSignal === 'known_malicious_domain')
  if (flagged) {
    decision.riskBand = 'HIGH'
    decision.recommendation = 'STOP_AND_AVOID'
    decision.safeActions = [
      'Do not click, pay, reply, or share credentials.',
      'This link is listed as a known threat by Google Safe Browsing. Do not open it.',
    ]
    decision.overridesApplied = [...(decision.overridesApplied || []), 'known_malicious_domain_override']
  }
}

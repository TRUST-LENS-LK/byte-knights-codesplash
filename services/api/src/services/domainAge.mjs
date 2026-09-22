const RDAP_TIMEOUT_MS = 3_000
const CT_TIMEOUT_MS = 3_000
const NEW_DOMAIN_THRESHOLD_DAYS = 14
const MS_PER_DAY = 24 * 60 * 60 * 1000

// Several of these free/public services (confirmed for rdap.org) return 403
// for requests with Node's default fetch User-Agent, likely generic bot
// protection. Identifying the client honestly, as any well-behaved consumer
// of a free public service should, resolves this.
const CLIENT_USER_AGENT = 'Mozilla/5.0 (compatible; TrustLensLK/1.0; +https://github.com/codesplash26-hackathon/byte-knights)'

/**
 * Queries RDAP (the modern, structured replacement for WHOIS) via rdap.org,
 * which bootstraps to the correct authoritative registry automatically.
 * Returns the domain's registration date, or null when RDAP has no data,
 * which is expected and normal for registries that do not run an RDAP
 * service at all (confirmed live for .lk: this returns null, not an error).
 */
export async function queryRdapRegistrationDate(domain) {
  const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
    headers: { accept: 'application/rdap+json', 'user-agent': CLIENT_USER_AGENT },
    signal: AbortSignal.timeout(RDAP_TIMEOUT_MS),
  })
  if (!response.ok) return null
  const data = await response.json().catch(() => null)
  const registrationEvent = data?.events?.find((event) => event.eventAction === 'registration')
  if (!registrationEvent?.eventDate) return null
  const date = new Date(registrationEvent.eventDate)
  return Number.isNaN(date.getTime()) ? null : date
}

async function earliestCertDate(rows) {
  if (!Array.isArray(rows) || !rows.length) return null
  const dates = rows.map((row) => new Date(row.not_before)).filter((date) => !Number.isNaN(date.getTime()))
  if (!dates.length) return null
  return new Date(Math.min(...dates.map((date) => date.getTime())))
}

/**
 * Falls back to Certificate Transparency logs (crt.sh, a free public CT-log
 * search service) when RDAP has no data for this TLD, as is the case for
 * .lk (confirmed live: LK Domain Registry runs neither RDAP nor a
 * traditional port-43 WHOIS server at all). Returns the date of the
 * earliest SSL certificate ever logged for the domain, a proxy for "when
 * this site first went live", not its literal registration date.
 */
export async function queryCrtShFirstCertDate(domain) {
  const response = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, {
    headers: { 'user-agent': CLIENT_USER_AGENT },
    signal: AbortSignal.timeout(CT_TIMEOUT_MS),
  })
  if (!response.ok) return null
  const rows = await response.json().catch(() => null)
  return earliestCertDate(rows)
}

/** Same purpose as queryCrtShFirstCertDate, via a second independent CT-log
 * search service (Certspotter/SSLMate), used as a backup since crt.sh is a
 * free community service known to be occasionally overloaded. */
export async function queryCertspotterFirstCertDate(domain) {
  const response = await fetch(
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`,
    { headers: { 'user-agent': CLIENT_USER_AGENT }, signal: AbortSignal.timeout(CT_TIMEOUT_MS) },
  )
  if (!response.ok) return null
  const rows = await response.json().catch(() => null)
  return earliestCertDate(rows)
}

/**
 * Unified domain-age lookup: RDAP first (most authoritative, an actual
 * registration date), falling back to CT logs (crt.sh, then Certspotter)
 * when RDAP has nothing, which is expected for TLDs like .lk that run no
 * RDAP/WHOIS service. Returns null, not an error, when no source has data;
 * that is a legitimate "age unknown" outcome, not a failure.
 */
export async function estimateDomainAge(domain) {
  try {
    const rdapDate = await queryRdapRegistrationDate(domain)
    if (rdapDate) return { date: rdapDate, source: 'RDAP' }
  } catch {
    // fall through to CT logs
  }

  try {
    const crtDate = await queryCrtShFirstCertDate(domain)
    if (crtDate) return { date: crtDate, source: 'CT_LOG_CRTSH' }
  } catch {
    // fall through to the backup CT-log source
  }

  try {
    const spotterDate = await queryCertspotterFirstCertDate(domain)
    if (spotterDate) return { date: spotterDate, source: 'CT_LOG_CERTSPOTTER' }
  } catch {
    // all sources exhausted
  }

  return null
}

/**
 * Pure decision logic, deliberately separated from the network-calling
 * functions above so it can be unit tested without live external calls.
 * Given an age result (or null) and the current time, decides whether to
 * emit a new_domain_risk finding.
 */
export function buildDomainAgeOutcome(domain, ageResult, now = new Date()) {
  if (!ageResult) {
    return { findings: [], limitations: [`Domain age for ${domain} could not be determined (no RDAP or certificate transparency data available).`] }
  }

  const ageDays = Math.floor((now.getTime() - ageResult.date.getTime()) / MS_PER_DAY)
  if (ageDays < 0 || ageDays >= NEW_DOMAIN_THRESHOLD_DAYS) {
    return { findings: [], limitations: [] }
  }

  const isRdap = ageResult.source === 'RDAP'
  return {
    findings: [
      {
        canonicalSignal: 'new_domain_risk',
        category: 'Domain verification',
        evidence: `${domain} appears to have been ${isRdap ? 'registered' : 'first seen with an SSL certificate'} only ${ageDays} day(s) ago (source: ${ageResult.source}).`,
        source: 'DOMAIN_DIRECTORY',
        strength: 0.75,
        confidence: isRdap ? 0.9 : 0.6,
        limitation: isRdap
          ? 'Domain registration date alone does not prove malicious intent; it is one supporting signal among several.'
          : "Estimated from the domain's first known SSL certificate, not its exact registration date, since RDAP/WHOIS is unavailable for this domain's registry.",
        detectorVersion: 'domain-age-v1',
      },
    ],
    limitations: [],
  }
}

/**
 * Tier 5 of the domain verification pipeline: is the destination domain
 * suspiciously new? Wraps estimateDomainAge and buildDomainAgeOutcome for
 * direct use in the analyze pipeline, swallowing any unexpected error so a
 * flaky external service never breaks the overall analysis.
 */
export async function checkDomainAge(entities) {
  const domainEntity = entities.find((entity) => entity.type === 'domain')
  if (!domainEntity) return { findings: [], limitations: [] }
  const domain = (domainEntity.normalizedValue || domainEntity.value || '').toLowerCase()
  if (!domain) return { findings: [], limitations: [] }

  try {
    const ageResult = await estimateDomainAge(domain)
    return buildDomainAgeOutcome(domain, ageResult)
  } catch {
    return { findings: [], limitations: [] }
  }
}

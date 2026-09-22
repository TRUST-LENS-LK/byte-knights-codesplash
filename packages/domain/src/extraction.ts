import { parse } from 'tldts'

// Sri Lankan public-suffix-aware URL and domain extraction. Uses tldts (a
// maintained, TypeScript-native implementation of Mozilla's Public Suffix
// List) instead of a hand-rolled list, so multi-level Sri Lankan suffixes
// (gov.lk, ac.lk, com.lk, org.lk, net.lk, edu.lk, sch.lk) and every other
// registry's suffix rules are handled correctly, not just guessed at.

export type UrlValidationResult =
  | { valid: true; normalized: string }
  | { valid: false; reason: string }

/**
 * Accepts only http/https URLs and returns a normalized form (lowercase
 * host, no default port, no trailing dot). Anything else, including
 * dangerous schemes like javascript: or data:, is rejected with a reason.
 */
export function validateAndNormalizeUrl(rawUrl: string): UrlValidationResult {
  let parsed: URL
  try {
    parsed = new URL(rawUrl.trim())
  } catch {
    return { valid: false, reason: 'URL could not be parsed.' }
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, reason: `Scheme "${parsed.protocol}" is not allowed; only http and https are supported.` }
  }
  parsed.hostname = parsed.hostname.toLowerCase().replace(/\.$/, '')
  if ((parsed.protocol === 'http:' && parsed.port === '80') || (parsed.protocol === 'https:' && parsed.port === '443')) {
    parsed.port = ''
  }
  return { valid: true, normalized: parsed.toString() }
}

/**
 * Extracts the true registrable (apex) domain from a URL or bare hostname,
 * respecting multi-level public suffixes. Returns null when the input has
 * no recognizable domain (a bare IP address, for example, has no
 * registrable domain in this sense).
 *
 * Examples:
 *   https://jobs.dialog.lk/apply  -> dialog.lk   (strips the "jobs" subdomain)
 *   https://portal.ird.gov.lk/tax -> ird.gov.lk  (gov.lk is the suffix, not just lk)
 *   https://online.cmb.ac.lk/lms  -> cmb.ac.lk   (ac.lk is the suffix)
 */
export function extractRegistrableDomain(urlOrHostname: string): string | null {
  const result = parse(urlOrHostname, { allowPrivateDomains: false })
  return result.domain ?? null
}

/**
 * Returns how many labels of subdomain sit in front of the registrable
 * domain, correctly ignoring the public suffix itself. This is the
 * suffix-aware replacement for a naive `hostname.split('.').length` count,
 * which over-counts on multi-level suffixes like gov.lk: "www.mail.cert.gov.lk"
 * has 5 labels total but only 2 levels of subdomain ("www.mail") once
 * "cert.gov.lk" is recognized as the registrable domain.
 */
export function getSubdomainDepth(urlOrHostname: string): number {
  const result = parse(urlOrHostname, { allowPrivateDomains: false })
  if (!result.subdomain) return 0
  return result.subdomain.split('.').filter(Boolean).length
}

/**
 * True when the hostname is a raw IPv4 or IPv6 address rather than a name,
 * for example "http://192.168.1.1/login" or "http://[::1]/admin".
 */
export function isIpAddressHost(urlOrHostname: string): boolean {
  const result = parse(urlOrHostname)
  return Boolean(result.isIp)
}

/**
 * True when the hostname contains a punycode-encoded label (xn--...), the
 * mechanism used for internationalized domain names and, commonly, for
 * homograph lookalike attacks (a Cyrillic "а" standing in for a Latin "a").
 * This only flags that punycode is present; it does not attempt to decode
 * or judge whether the underlying characters are actually deceptive.
 */
export function hasPunycodeLabel(urlOrHostname: string): boolean {
  const result = parse(urlOrHostname)
  const hostname = result.hostname ?? ''
  return hostname.split('.').some((label) => label.startsWith('xn--'))
}

// A short, explicit list of well-known URL shortener domains. Not
// exhaustive by design: the point is to catch the handful of very common
// ones a scam message is likely to actually use, not to maintain a
// comprehensive registry of every shortener that has ever existed.
const KNOWN_URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'rebrand.ly',
  'cutt.ly',
  'shorturl.at',
])

export function isKnownUrlShortener(urlOrHostname: string): boolean {
  const domain = extractRegistrableDomain(urlOrHostname)
  return domain ? KNOWN_URL_SHORTENERS.has(domain) : false
}

/**
 * Breaks a URL or domain so it cannot be accidentally clicked or copied as
 * a live link when displayed, per the project's rule that suspicious
 * destinations are always shown defanged.
 */
export function defangUrl(value: string): string {
  return value.replace(/^http/i, 'hxxp').replace(/\./g, '[.]')
}

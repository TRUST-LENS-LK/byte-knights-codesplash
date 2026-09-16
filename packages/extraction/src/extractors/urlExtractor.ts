import { type ExtractedEntity } from '../../../../packages/contracts/src/index'

/**
 * Matches both standard and defanged URLs.
 *
 * Standard:  https://example.com/path
 * Defanged:  hxxps://example[.]com/path  (security researcher notation)
 */
const URL_PATTERN =
  /(?:hxxps?|https?):\/\/[^\s<>()\[\]"']+(?:\[[^\]]*\][^\s<>()\[\]"']*)?/gi

/**
 * Matches the domain portion inside a URL.
 * Handles both normal dots (.) and defanged dots ([.]).
 *
 * e.g. "fake-recruitment.lk" or "jobs-lk[.]com"
 */
const DOMAIN_INSIDE_URL = /(?:hxxps?|https?):\/\/([^\s/<>()\[\]"']+)/i

/**
 * Normalizes a defanged URL back to a usable form:
 *   hxxps:// -> https://
 *   hxxp://  -> http://
 *   [.]      -> .
 */
function normalizeUrl(raw: string): string {
  return raw
    .replace(/^hxxps/i, 'https')
    .replace(/^hxxp/i, 'http')
    .replace(/\[\.\]/g, '.')
    // Strip trailing punctuation that may have been captured
    .replace(/[.,!?;:]+$/, '')
}

/**
 * Normalizes a domain string by removing defanged dot notation.
 */
function normalizeDomain(raw: string): string {
  return raw.replace(/\[\.\]/g, '.').replace(/\[\.]/g, '.').toLowerCase()
}

/**
 * Extracts all URL and domain entities from the given text.
 *
 * Each entity includes:
 *   - `value`          — raw matched string from the text
 *   - `normalizedValue`— cleaned/defanged version
 *   - `startIndex`     — zero-based character start in the raw input
 *   - `endIndex`       — zero-based character end (exclusive) in the raw input
 */
export function extractUrls(text: string): ExtractedEntity[] {
  const results: ExtractedEntity[] = []

  // Reset lastIndex for global regex before each use
  URL_PATTERN.lastIndex = 0

  for (const match of text.matchAll(URL_PATTERN)) {
    const value = match[0]
    const startIndex = match.index!
    const endIndex = startIndex + value.length
    const normalizedValue = normalizeUrl(value)

    // Add the URL entity
    results.push({
      type: 'url',
      value,
      normalizedValue,
      sourceSpan: value,
      startIndex,
      endIndex,
      confidence: 0.97,
    })

    // Also extract the domain from within the URL
    const domainMatch = DOMAIN_INSIDE_URL.exec(value)
    if (domainMatch) {
      const rawDomain = domainMatch[1]
      // Strip trailing path/query, keep domain only
      const domainOnly = rawDomain.split('/')[0]
      const domainStart = startIndex + value.indexOf(domainOnly)
      const domainEnd = domainStart + domainOnly.length

      results.push({
        type: 'domain',
        value: domainOnly,
        normalizedValue: normalizeDomain(domainOnly),
        sourceSpan: domainOnly,
        startIndex: domainStart,
        endIndex: domainEnd,
        confidence: 0.97,
      })
    }
  }

  return results
}

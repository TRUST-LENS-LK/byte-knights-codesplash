import { type ExtractedEntity } from '@trustlens/contracts'

/**
 * Matches both standard and defanged URLs.
 *
 * Standard:  https://example.com/path
 * Defanged:  hxxps://example[.]com/path  (security researcher notation)
 */
const URL_PATTERN =
  /(?:hxxps?|https?):\/\/[^\s<>()\[\]"']+(?:\[[^\]]*\][^\s<>()\[\]"']*)?/gi

/**
 * Matches bare URLs without a protocol prefix.
 *
 * These are domain.tld/path patterns like:
 *   bit.ly/4wxTL8M
 *   t.co/abc123
 *   tinyurl.com/y5abc
 *   example.com/login/page
 *
 * A slash + path is required to distinguish from plain domain references
 * (which are handled separately by the bare-domain extractor) and to
 * avoid false positives on strings like "Rs.12,500" or "version 2.0".
 */
const BARE_URL_PATTERN =
  /(?:^|(?<=[\s,;()\[\]<>]))([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+\/[^\s<>()\[\]"',!?;:]+)/gm

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

  // Track spans already covered by protocol-prefixed URLs so bare-URL
  // matches don't duplicate them.
  const coveredSpans: Array<{ start: number; end: number }> = []

  // ── Pass 1: Protocol-prefixed URLs (https://…, hxxps://…) ────────
  URL_PATTERN.lastIndex = 0

  for (const match of text.matchAll(URL_PATTERN)) {
    const value = match[0]
    const startIndex = match.index!
    const endIndex = startIndex + value.length
    const normalizedValue = normalizeUrl(value)

    results.push({
      type: 'url',
      value,
      normalizedValue,
      sourceSpan: value,
      startIndex,
      endIndex,
      confidence: 0.97,
    })

    coveredSpans.push({ start: startIndex, end: endIndex })

    // Also extract the domain from within the URL
    const domainMatch = DOMAIN_INSIDE_URL.exec(value)
    if (domainMatch) {
      const rawDomain = domainMatch[1]
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

  // ── Pass 2: Bare URLs without protocol (bit.ly/4wxTL8M, t.co/x) ──
  BARE_URL_PATTERN.lastIndex = 0

  for (const match of text.matchAll(BARE_URL_PATTERN)) {
    const value = match[1] ?? match[0]
    const startIndex = match.index! + (match[0].length - value.length)
    const endIndex = startIndex + value.length

    // Skip if this span is already covered by a protocol-prefixed URL
    const alreadyCovered = coveredSpans.some(
      (span) => startIndex >= span.start && endIndex <= span.end
    )
    if (alreadyCovered) continue

    // Strip trailing punctuation that may have been captured
    const cleaned = value.replace(/[.,!?;:]+$/, '')
    const normalizedValue = `https://${cleaned}`

    results.push({
      type: 'url',
      value: cleaned,
      normalizedValue,
      sourceSpan: cleaned,
      startIndex,
      endIndex: startIndex + cleaned.length,
      confidence: 0.92,
    })

    // Extract the domain from the bare URL
    const domainOnly = cleaned.split('/')[0]
    const domainStart = startIndex
    const domainEnd = domainStart + domainOnly.length

    results.push({
      type: 'domain',
      value: domainOnly,
      normalizedValue: domainOnly.toLowerCase(),
      sourceSpan: domainOnly,
      startIndex: domainStart,
      endIndex: domainEnd,
      confidence: 0.92,
    })
  }

  return results
}

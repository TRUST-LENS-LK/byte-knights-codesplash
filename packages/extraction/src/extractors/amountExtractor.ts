import { type ExtractedEntity } from '@trustlens/contracts'

/**
 * Currency amount patterns supported:
 *
 *  LKR (Sri Lankan Rupee):
 *    Rs. 2,500          — standard Sri Lankan notation with period
 *    Rs 1500            — no period
 *    Rs.18,000          — no space
 *    LKR 2,000          — ISO code
 *    LKR2000            — ISO code no space
 *    5000/=             — Sri Lankan slash notation
 *    5,000/=            — with comma separator
 *    රු. 3,500          — Sinhala rupee symbol (Unicode රු)
 *
 *  USD (US Dollar):
 *    USD 25             — ISO code
 *    $500               — symbol
 *    $ 500              — symbol with space
 *
 *  Generic large numbers with currency context:
 *    50,000 LKR         — amount before currency
 */
const AMOUNT_PATTERNS: { pattern: RegExp; currency: string }[] = [
  // Rs. or Rs variants (Sri Lankan rupee, symbol before amount)
  {
    pattern: /Rs\.?\s?[\d,]+(?:\/=)?(?:\.\d{1,2})?/gi,
    currency: 'LKR',
  },
  // LKR ISO code before or after amount
  {
    pattern: /LKR\s?[\d,]+(?:\/=)?(?:\.\d{1,2})?/gi,
    currency: 'LKR',
  },
  // Amount followed by LKR
  {
    pattern: /[\d,]+(?:\.\d{1,2})?\s?LKR/gi,
    currency: 'LKR',
  },
  // Sri Lankan slash notation  5000/=  or  5,000/=
  {
    pattern: /[\d,]+(?:\.\d{1,2})?\/=/g,
    currency: 'LKR',
  },
  // Sinhala rupee symbol රු followed by amount
  {
    pattern: /රු\.?\s?[\d,]+(?:\/=)?(?:\.\d{1,2})?/g,
    currency: 'LKR',
  },
  // USD ISO code
  {
    pattern: /USD\s?[\d,]+(?:\.\d{1,2})?/gi,
    currency: 'USD',
  },
  // Dollar symbol
  {
    pattern: /\$\s?[\d,]+(?:\.\d{1,2})?/g,
    currency: 'USD',
  },
]

/**
 * Strips currency symbols, commas, and whitespace from a matched string
 * to produce a clean numeric string.
 *
 * Examples:
 *   "Rs. 2,500"  → "2500"
 *   "LKR 1,000"  → "1000"
 *   "5,000/="    → "5000"
 *   "$25"        → "25"
 */
function extractNumericValue(raw: string): number {
  // Remove currency symbols, letters, spaces, commas, /=
  const cleaned = raw
    .replace(/[Rs\.LKRUSDරු\s$,\/=]/gi, '')
    .trim()

  return parseFloat(cleaned) || 0
}

/**
 * Produces a normalized amount string in the form "CURRENCY AMOUNT".
 * e.g. "LKR 2500" or "USD 25"
 */
function normalizeAmount(raw: string, currency: string): string {
  const numeric = extractNumericValue(raw)
  return `${currency} ${numeric}`
}

/**
 * Extracts all currency amount entities from the given text.
 *
 * Deduplication: if two patterns match the same character range,
 * only the first (highest-priority) match is kept.
 *
 * Each entity includes:
 *   - `value`          — raw matched string from the text
 *   - `normalizedValue`— canonical "CURRENCY AMOUNT" string e.g. "LKR 2500"
 *   - `startIndex`     — zero-based character start in the raw input
 *   - `endIndex`       — zero-based character end (exclusive) in the raw input
 */
export function extractAmounts(text: string): ExtractedEntity[] {
  // Track covered character ranges to avoid duplicate matches
  const coveredRanges: Array<{ start: number; end: number }> = []

  const results: ExtractedEntity[] = []

  for (const { pattern, currency } of AMOUNT_PATTERNS) {
    pattern.lastIndex = 0

    for (const match of text.matchAll(pattern)) {
      const value = match[0]
      const startIndex = match.index!
      const endIndex = startIndex + value.length

      // Skip if this range overlaps with an already-matched range
      const overlaps = coveredRanges.some(
        (range) => startIndex < range.end && endIndex > range.start
      )
      if (overlaps) continue

      // Skip implausibly small matches (e.g. lone "$" or "Rs.")
      const numeric = extractNumericValue(value)
      if (numeric <= 0) continue

      coveredRanges.push({ start: startIndex, end: endIndex })

      results.push({
        type: 'amount',
        value,
        normalizedValue: normalizeAmount(value, currency),
        sourceSpan: value,
        startIndex,
        endIndex,
        confidence: 0.93,
      })
    }
  }

  // Return in document order
  results.sort((a, b) => (a.startIndex ?? 0) - (b.startIndex ?? 0))

  return results
}

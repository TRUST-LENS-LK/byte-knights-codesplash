import { type ExtractedEntity } from '../../../../packages/contracts/src/index'

/**
 * Sri Lankan phone number patterns supported:
 *
 *  Mobile (07x):
 *    0771234567          — no spaces
 *    0 77 123 4567       — spaced
 *    077-123-4567        — hyphenated
 *    +94771234567        — E.164 no spaces
 *    +94 77 123 4567     — E.164 spaced
 *    +94-77-123-4567     — E.164 hyphenated
 *
 *  Landline (0xx where xx is area code):
 *    0112345678          — Colombo, no spaces
 *    011-234-5678        — Colombo, hyphenated
 *    +94 11 234 5678     — E.164 Colombo
 *
 * Sri Lankan mobile operator prefixes: 70, 71, 72, 74, 75, 76, 77, 78
 * Common landline area codes: 11 (Colombo), 21, 23, 25, 26, 27, 31, etc.
 */
const PHONE_PATTERN =
  /(?:\+94|0)[\s-]?(?:\d[\s-]?){8,9}\d/g

/**
 * Strips all whitespace and hyphens from a raw phone match,
 * then normalises to E.164 Sri Lankan format: +94XXXXXXXXX
 */
function normalizePhone(raw: string): string {
  // Remove spaces, hyphens
  const digits = raw.replace(/[\s\-]/g, '')

  if (digits.startsWith('+94')) {
    // Already in +94 format — ensure exactly 11 chars (+94 + 9 digits)
    const number = digits.slice(3)
    return `+94${number.padStart(9, '0')}`
  }

  if (digits.startsWith('0')) {
    // Local format 0XXXXXXXXX → +94XXXXXXXXX
    return `+94${digits.slice(1)}`
  }

  return digits
}

/**
 * Returns true if the normalized number looks like a valid
 * Sri Lankan number (+94 followed by 9 digits, with a valid prefix).
 */
function isValidSriLankanNumber(normalized: string): boolean {
  if (!/^\+94\d{9}$/.test(normalized)) return false

  const subscriber = normalized.slice(3) // 9-digit local number
  const prefix = parseInt(subscriber.slice(0, 2), 10)

  // Valid mobile prefixes
  const mobilePrefixes = [70, 71, 72, 74, 75, 76, 77, 78]
  // Valid landline area codes (first 2 digits when leading 0 is removed)
  const landlinePrefixes = [11, 21, 23, 24, 25, 26, 27, 31, 32, 33, 34, 35, 36, 37, 38, 41, 45, 47, 51, 52, 54, 55, 57, 63, 65, 66, 67]

  return mobilePrefixes.includes(prefix) || landlinePrefixes.includes(prefix)
}

/**
 * Extracts all Sri Lankan phone number entities from the given text.
 *
 * Each entity includes:
 *   - `value`          — raw matched string from the text
 *   - `normalizedValue`— E.164 canonical form (+94XXXXXXXXX)
 *   - `startIndex`     — zero-based character start in the raw input
 *   - `endIndex`       — zero-based character end (exclusive) in the raw input
 */
export function extractPhones(text: string): ExtractedEntity[] {
  const results: ExtractedEntity[] = []

  PHONE_PATTERN.lastIndex = 0

  for (const match of text.matchAll(PHONE_PATTERN)) {
    const value = match[0]
    const startIndex = match.index!
    const endIndex = startIndex + value.length
    const normalizedValue = normalizePhone(value)

    // Skip if it doesn't look like a real Sri Lankan number
    if (!isValidSriLankanNumber(normalizedValue)) continue

    results.push({
      type: 'phone',
      value,
      normalizedValue,
      sourceSpan: value,
      startIndex,
      endIndex,
      confidence: 0.92,
    })
  }

  return results
}

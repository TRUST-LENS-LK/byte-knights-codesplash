import { type ExtractedEntity } from '@trustlens/contracts'

/**
 * Organization name extraction strategy:
 *
 * Two complementary approaches are combined:
 *
 * 1. SUFFIX-BASED: Capture a preceding proper-noun phrase before a known
 *    organizational suffix keyword (e.g. "Sampath Bank", "XYZ Pvt Ltd").
 *
 * 2. KEYWORD-BASED: Detect well-known Sri Lankan organization names and
 *    common scam-delivery channels (e.g. "WhatsApp Admin", "Telegram Group").
 */

// ---------------------------------------------------------------------------
// 1. Suffix-based patterns
//    Matches: [1–4 capitalized words] followed by an org-type suffix keyword
// ---------------------------------------------------------------------------
const SUFFIX_PATTERNS: RegExp[] = [
  // Banks & financial institutions
  /(?:[A-Z][a-zA-Z]{1,20}\s){1,3}(?:Bank|Finance|Leasing|Insurance|Savings|Capital|Fund|Credit)/g,
  // Private / public companies
  /(?:[A-Z][a-zA-Z]{1,20}\s){1,3}(?:Pvt\.?\s*Ltd\.?|PLC|Limited|Holdings|Group|Corporation|Enterprises|Company|Co\.)/g,
  // Government bodies
  /(?:[A-Z][a-zA-Z]{1,20}\s){1,4}(?:Department|Ministry|Authority|Commission|Board|Council|Service|Agency|Police|Court)/g,
  // Telecoms
  /(?:[A-Z][a-zA-Z]{1,20}\s){1,2}(?:Telecom|Mobile|Network|Communications)/g,
]

// ---------------------------------------------------------------------------
// 2. Keyword / known-name patterns
//    Hard-coded well-known Sri Lankan organizations and scam-delivery channels
// ---------------------------------------------------------------------------
const KNOWN_ORGANIZATIONS: RegExp[] = [
  // Major Sri Lankan banks (exact name matching, case-insensitive)
  /\bBank of Ceylon\b/gi,
  /\bPeoples?\s*Bank\b/gi,
  /\bSampath\s*Bank\b/gi,
  /\bCommercial\s*Bank\b/gi,
  /\bHatton\s*National\s*Bank\b/gi,
  /\bHNB\b/g,
  /\bBOC\b/g,
  /\bNDB\b/g,
  /\bDFCC\b/g,
  /\bSeylan\s*Bank\b/gi,
  /\bNTB\b/g,
  /\bNations\s*Trust\s*Bank\b/gi,
  // Telecom operators
  /\bDialog\b/gi,
  /\bMobitel\b/gi,
  /\bHutch\b/gi,
  /\bAirtel\b/gi,
  /\bSLT\b/g,
  // Government / official
  /\bSri\s*Lanka\s*Police\b/gi,
  /\bCentral\s*Bank(?:\s*of\s*Sri\s*Lanka)?\b/gi,
  /\bERB\b/g,
  /\bSLEA\b/g,
  // Common scam delivery channels
  /\bWhatsApp\s*(?:Admin|Group|Channel)\b/gi,
  /\bTelegram\s*(?:Admin|Group|Channel|Bot)\b/gi,
  /\bViber\s*(?:Group|Admin)?\b/gi,
]

// ---------------------------------------------------------------------------
// Deduplication helper
// ---------------------------------------------------------------------------
function overlaps(
  a: { start: number; end: number },
  b: { start: number; end: number }
): boolean {
  return a.start < b.end && a.end > b.start
}

/**
 * Extracts all organization name entities from the given text.
 *
 * Each entity includes:
 *   - `value`          — raw matched string from the text
 *   - `normalizedValue`— trimmed version of the matched string
 *   - `startIndex`     — zero-based character start in the raw input
 *   - `endIndex`       — zero-based character end (exclusive) in the raw input
 */
export function extractOrganizations(text: string): ExtractedEntity[] {
  const coveredRanges: Array<{ start: number; end: number }> = []
  const results: ExtractedEntity[] = []

  function addMatch(value: string, startIndex: number): void {
    const trimmed = value.trim()
    if (trimmed.length < 3) return

    const endIndex = startIndex + value.length

    // Adjust startIndex for any leading whitespace stripped during trim
    const leadingSpaces = value.length - value.trimStart().length
    const adjustedStart = startIndex + leadingSpaces
    const adjustedEnd = adjustedStart + trimmed.length

    if (coveredRanges.some((r) => overlaps(r, { start: adjustedStart, end: adjustedEnd }))) return

    coveredRanges.push({ start: adjustedStart, end: adjustedEnd })

    results.push({
      type: 'organization',
      value: trimmed,
      normalizedValue: trimmed,
      sourceSpan: trimmed,
      startIndex: adjustedStart,
      endIndex: adjustedEnd,
      confidence: 0.82,
    })
  }

  // Run suffix-based patterns
  for (const pattern of SUFFIX_PATTERNS) {
    pattern.lastIndex = 0
    for (const match of text.matchAll(pattern)) {
      addMatch(match[0], match.index!)
    }
  }

  // Run known-name patterns (higher confidence — bump after insertion)
  for (const pattern of KNOWN_ORGANIZATIONS) {
    pattern.lastIndex = 0
    for (const match of text.matchAll(pattern)) {
      const value = match[0].trim()
      const startIndex = match.index!
      const endIndex = startIndex + match[0].length

      if (coveredRanges.some((r) => overlaps(r, { start: startIndex, end: endIndex }))) continue

      coveredRanges.push({ start: startIndex, end: endIndex })

      results.push({
        type: 'organization',
        value,
        normalizedValue: value,
        sourceSpan: value,
        startIndex,
        endIndex,
        // Known orgs carry higher confidence than suffix heuristics
        confidence: 0.95,
      })
    }
  }

  // Return results in document order
  results.sort((a, b) => (a.startIndex ?? 0) - (b.startIndex ?? 0))

  return results
}

import { extractedEntitySchema, type ExtractedEntity } from '../../../packages/contracts/src/index'
import { extractUrls } from './extractors/urlExtractor'
import { extractPhones } from './extractors/phoneExtractor'
import { extractAmounts } from './extractors/amountExtractor'
import { extractOrganizations } from './extractors/organizationExtractor'

// ---------------------------------------------------------------------------
// Email extractor (inline — simple enough to not need its own module)
// ---------------------------------------------------------------------------
const EMAIL_PATTERN = /[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+/gi

function extractEmails(text: string): ExtractedEntity[] {
  const results: ExtractedEntity[] = []
  EMAIL_PATTERN.lastIndex = 0

  for (const match of text.matchAll(EMAIL_PATTERN)) {
    const value = match[0]
    const startIndex = match.index!
    const endIndex = startIndex + value.length

    results.push(
      extractedEntitySchema.parse({
        type: 'email',
        value,
        normalizedValue: value.toLowerCase(),
        sourceSpan: value,
        startIndex,
        endIndex,
        confidence: 0.97,
      })
    )
  }

  return results
}

// ---------------------------------------------------------------------------
// Overlap deduplication helper
// ---------------------------------------------------------------------------

/** Pairs of entity types that are intentionally allowed to overlap. */
const ALLOWED_OVERLAP_PAIRS = new Set([
  'url:domain',
  'domain:url',
])

function hasOverlap(
  existing: ExtractedEntity[],
  candidate: ExtractedEntity
): boolean {
  return existing.some(
    (e) => {
      if (
        e.startIndex === undefined ||
        e.endIndex === undefined ||
        candidate.startIndex === undefined ||
        candidate.endIndex === undefined
      ) return false

      const spansOverlap =
        candidate.startIndex < e.endIndex &&
        candidate.endIndex > e.startIndex

      if (!spansOverlap) return false

      // Allow intentional pairs (e.g. url + domain) to coexist
      const pairKey = `${candidate.type}:${e.type}`
      if (ALLOWED_OVERLAP_PAIRS.has(pairKey)) return false

      return true
    }
  )
}

// ---------------------------------------------------------------------------
// Main public API
// ---------------------------------------------------------------------------

/**
 * Extracts all structured entities from raw text.
 *
 * Entity types returned:
 *   - url          — standard and defanged URLs
 *   - domain       — domain portion of each URL
 *   - phone        — Sri Lankan mobile and landline numbers (E.164)
 *   - email        — email addresses
 *   - amount       — LKR/USD monetary amounts
 *   - organization — Sri Lankan org names and scam delivery channels
 *
 * All entities include:
 *   - value          — raw matched string
 *   - normalizedValue— canonical / cleaned form
 *   - startIndex     — zero-based character start in the raw input
 *   - endIndex       — zero-based character end (exclusive) in the raw input
 *   - confidence     — 0–1 confidence score
 */
export function extractEntities(text: string): ExtractedEntity[] {
  if (!text || text.trim().length === 0) return []

  // Collect from all extractors
  const candidates: ExtractedEntity[] = [
    ...extractUrls(text),
    ...extractPhones(text),
    ...extractEmails(text),
    ...extractAmounts(text),
    ...extractOrganizations(text),
  ]

  // Sort by startIndex so document order is maintained
  candidates.sort((a, b) => (a.startIndex ?? 0) - (b.startIndex ?? 0))

  // Deduplicate: skip any entity whose span overlaps an already-accepted one
  const accepted: ExtractedEntity[] = []
  for (const entity of candidates) {
    if (!hasOverlap(accepted, entity)) {
      accepted.push(entity)
    }
  }

  return accepted
}


import { analyzeMessage } from '@trustlens/rules'
import { extractEntities as extractEntitiesExtraction } from '@trustlens/extraction'
import { submissionSchema } from '@trustlens/contracts'

// Re-export the shared analyzeMessage so callers inside the API can use it directly.
export { analyzeMessage }

// Use the shared extraction package for entity extraction and augment with domain entities.
// Preserves startIndex, endIndex, and sourceSpan from the shared package so span-aware
// features (persistence, UI highlighting) can use them downstream.
export function extractEntities(text) {
  try {
    const raw = extractEntitiesExtraction(text).map((entity) => ({
      type: entity.type,
      value: entity.type === 'url' ? entity.normalizedValue ?? entity.value : entity.value,
      normalizedValue: entity.normalizedValue ?? null,
      sourceSpan: entity.sourceSpan ?? null,
      startIndex: entity.startIndex ?? null,
      endIndex: entity.endIndex ?? null,
      confidence: entity.confidence ?? null,
    }))
    // Augment with domain entities derived from URL entities (not in shared package).
    // Domain entities from the URL extractor already carry span info; only add here
    // for any URL that did NOT already produce a domain entity.
    const existingDomainValues = new Set(
      raw.filter((e) => e.type === 'domain').map((e) => e.value)
    )
    const domainEntities = []
    for (const entity of raw.filter((e) => e.type === 'url')) {
      try {
        const hostname = new URL(entity.value).hostname.toLowerCase()
        if (hostname && !existingDomainValues.has(hostname)) {
          domainEntities.push({
            type: 'domain',
            value: hostname,
            normalizedValue: hostname,
            sourceSpan: null,
            startIndex: entity.startIndex,
            endIndex: entity.endIndex,
            confidence: 0.98,
          })
        }
      } catch { /* skip unparseable URLs */ }
    }
    const all = [...raw, ...domainEntities]
    // Deduplicate by type + value.
    return all.filter((entity, index, arr) => arr.findIndex((c) => c.type === entity.type && c.value === entity.value) === index)
  } catch {
    return extractEntitiesInline(text)
  }
}

// Inline fallback — kept in sync with the shared extraction package.
// Used only when the extraction package itself throws an unexpected error.
function extractEntitiesInline(text) {
  const entities = []
  for (const match of text.matchAll(/https?:\/\/[^\s<>()]+/gi)) {
    const value = match[0].replace(/[),.!?]+$/, '')
    const startIndex = match.index
    const endIndex = startIndex + value.length
    entities.push({ type: 'url', value, sourceSpan: value, startIndex, endIndex, confidence: 0.99 })
    try {
      const hostname = new URL(value).hostname.toLowerCase()
      if (hostname) entities.push({ type: 'domain', value: hostname, normalizedValue: hostname, sourceSpan: null, startIndex, endIndex, confidence: 0.98 })
    } catch {
      // Keep the URL entity when the submitted value is not parseable.
    }
  }
  // Extract bare domains (e.g. "scam.lk", "bank-verify.com") not already captured via URL extraction
  for (const match of text.matchAll(/(?:^|[\s,;()\[\]<>])([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)(?=[)\]>.,;:!?\s]|$)/gm)) {
    const domain = match[1].toLowerCase()
    const startIndex = match.index + match[0].indexOf(match[1])
    const endIndex = startIndex + domain.length
    const alreadyHas = entities.some((e) => e.type === 'domain' && e.value === domain)
    if (!alreadyHas && !text.includes(`@${domain}`)) {
      entities.push({ type: 'domain', value: domain, normalizedValue: domain, sourceSpan: match[1], startIndex, endIndex, confidence: 0.90 })
    }
  }
  for (const match of text.matchAll(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g)) {
    const startIndex = match.index
    const endIndex = startIndex + match[0].length
    entities.push({ type: 'email', value: match[0], sourceSpan: match[0], startIndex, endIndex, confidence: 0.99 })
  }
  for (const match of text.matchAll(/(?:\+94|0)\s*\d{2}\s*\d{3}\s*\d{4}/g)) {
    const startIndex = match.index
    const endIndex = startIndex + match[0].length
    entities.push({ type: 'phone', value: match[0], normalizedValue: match[0].replace(/\s+/g, '').replace(/^0/, '+94'), sourceSpan: match[0], startIndex, endIndex, confidence: 0.95 })
  }
  for (const match of text.matchAll(/(?:Rs\.?|LKR)\s?[\d,]+(?:\.\d{1,2})?/gi)) {
    const startIndex = match.index
    const endIndex = startIndex + match[0].length
    entities.push({ type: 'amount', value: match[0], sourceSpan: match[0], startIndex, endIndex, confidence: 0.94 })
  }
  return entities.filter((entity, index, all) => all.findIndex((candidate) => candidate.type === entity.type && candidate.value === entity.value) === index)
}

export function analyze(text) {
  return analyzeMessage(text)
}

/**
 * Validates a submission body using the shared Zod schema from @trustlens/contracts.
 * Returns a human-readable error string on failure, or null if valid.
 *
 * Using the contract schema here ensures the API and packages always agree on
 * what a valid submission looks like — a single source of truth.
 */
export function validateSubmission(body) {
  const result = submissionSchema.safeParse(body)
  if (result.success) return null
  // Return the first issue's message, which matches the contract's human-readable descriptions.
  const firstIssue = result.error.issues[0]
  // Map Zod field paths to the error messages the existing API tests expect.
  const field = firstIssue?.path[0]
  if (field === 'type') return 'type must be message, url, or screenshot.'
  if (field === 'languageHint') return 'languageHint is not supported.'
  if (field === 'retentionConsent') return 'retentionConsent must be a boolean.'
  return firstIssue?.message ?? 'Invalid submission.'
}

export function applyScannerRisk(decision) {
  const severe = decision.findings.some((finding) => ['embedded_credentials', 'unsafe_url_target'].includes(finding.canonicalSignal))
  const structural = decision.findings.some((finding) => finding.source === 'SCANNER')
  if (severe) {
    decision.riskBand = 'HIGH'
    decision.recommendation = 'STOP_AND_AVOID'
    decision.safeActions = ['Do not open or share the URL.', 'Verify the sender and organization through an independent official channel.']
  } else if (structural && decision.riskBand === 'LOW') {
    decision.riskBand = 'MEDIUM'
    decision.recommendation = 'VERIFY_INDEPENDENTLY'
  }
  return decision
}

export function validateReport(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return 'Request body must be a JSON object.'
  if (!['suspicious', 'false_positive', 'false_negative'].includes(body.reportType)) return 'reportType must be suspicious, false_positive, or false_negative.'
  if (typeof body.text !== 'string' || !body.text.trim()) return 'text is required.'
  if (body.text.length > 10_000) return 'text must be at most 10,000 characters.'
  if (body.notes !== undefined && (typeof body.notes !== 'string' || body.notes.length > 2_000)) return 'notes must be at most 2,000 characters.'
  if (body.reportedDomain !== undefined && (typeof body.reportedDomain !== 'string' || body.reportedDomain.length > 253)) return 'reportedDomain is invalid.'
  return null
}

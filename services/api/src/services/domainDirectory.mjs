import { SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL } from '../config/env.mjs'
import { isDirectoryEntryStale, matchesOfficialDomain } from '@trustlens/domain'

const LOOKUP_TIMEOUT_MS = 3_000

// Maps a raw Supabase row (snake_case) to the camelCase shape defined by
// officialDomainRecordSchema in @trustlens/contracts.
function toRecord(row) {
  return {
    id: row.id,
    name: row.name,
    officialDomain: row.official_domain,
    category: row.category ?? null,
    sourceUrl: row.source_url ?? null,
    reviewer: row.reviewer ?? null,
    verifiedAt: row.verified_at ?? null,
    nextReviewDate: row.next_review_date ?? null,
    status: row.status ?? 'ACTIVE',
    active: row.active ?? true,
  }
}

async function fetchActiveRecords() {
  const params = new URLSearchParams({ active: 'eq.true', order: 'name.asc' })
  const response = await fetch(`${SUPABASE_URL}/rest/v1/approved_organizations?${params}`, {
    headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` },
    signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
  })
  if (!response.ok) throw new Error('Domain directory request failed')
  const rows = await response.json()
  return rows.map(toRecord)
}

/**
 * Lists directory entries for display, for example a future admin or
 * transparency screen. Stale entries are excluded by default since they are
 * not meant to be relied on until re-reviewed; pass includeStale to see them
 * anyway (their outcome is still marked stale by the caller if needed).
 */
export async function listDomainDirectory({ category, includeStale = false } = {}) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return []
  const records = await fetchActiveRecords()
  const filtered = category
    ? records.filter((record) => (record.category || '').toLowerCase() === category.toLowerCase())
    : records
  if (includeStale) return filtered
  return filtered.filter((record) => !isDirectoryEntryStale(record))
}

/**
 * Looks up one domain against the directory and returns a
 * domainVerificationSchema-shaped outcome. UNKNOWN means "not verified", not
 * "fraudulent" — the directory only ever confirms matches, it never asserts
 * that an unlisted domain is unsafe.
 */
export async function lookupDomainDirectory(domain) {
  if (!domain || typeof domain !== 'string') return { outcome: 'UNKNOWN', matchedRecord: null }
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return { outcome: 'UNKNOWN', matchedRecord: null }

  const normalized = domain.trim().toLowerCase()
  const records = await fetchActiveRecords()
  const match = records.find((record) => matchesOfficialDomain(normalized, record.officialDomain))
  if (!match) return { outcome: 'UNKNOWN', matchedRecord: null }
  if (isDirectoryEntryStale(match)) return { outcome: 'STALE', matchedRecord: match }
  return { outcome: 'MATCHED', matchedRecord: match }
}

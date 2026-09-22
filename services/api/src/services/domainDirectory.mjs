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
 * Lists every directory entry regardless of active/status, for the
 * moderator management screen. Unlike listDomainDirectory (used by the
 * public read endpoint and the verification pipeline), this intentionally
 * shows retired and inactive rows too, since a moderator needs to see and
 * be able to reactivate them, not just the currently-usable subset.
 */
export async function listAllDomainDirectoryEntries() {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return []
  const params = new URLSearchParams({ order: 'name.asc' })
  const response = await fetch(`${SUPABASE_URL}/rest/v1/approved_organizations?${params}`, {
    headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` },
    signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
  })
  if (!response.ok) throw new Error('Domain directory request failed')
  const rows = await response.json()
  return rows.map(toRecord)
}

/**
 * Adds a new organization to the directory. Only reachable through the
 * moderator-protected /api/moderation/domains route; the review date
 * defaults to 90 days out, matching the staleness policy used everywhere
 * else (packages/domain isDirectoryEntryStale, the seed data).
 */
export async function createDomainDirectoryEntry(data, reviewer) {
  const nextReviewDate = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10)
  const response = await fetch(`${SUPABASE_URL}/rest/v1/approved_organizations`, {
    method: 'POST',
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      'content-type': 'application/json',
      Prefer: 'return=representation',
    },
    body: JSON.stringify({
      name: data.name,
      official_domain: data.officialDomain,
      category: data.category || null,
      source_url: data.sourceUrl || null,
      reviewer,
      verified_at: new Date().toISOString(),
      next_review_date: nextReviewDate,
      status: 'ACTIVE',
      active: true,
    }),
    signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
  })
  if (!response.ok) {
    const text = await response.text().catch(() => '')
    throw new Error(`Failed to create domain directory entry: ${text.slice(0, 300)}`)
  }
  const [row] = await response.json()
  return toRecord(row)
}

/**
 * Updates an existing directory entry: status (ACTIVE/STALE/RETIRED),
 * category, source URL, review notes, or the active flag. Always stamps the
 * acting moderator as reviewer and refreshes verified_at/next_review_date
 * when the status is being set back to ACTIVE, so re-approving a retired
 * entry restarts its 90-day review clock rather than leaving a stale date.
 */
export async function updateDomainDirectoryEntry(id, updates, reviewer) {
  const patch = { reviewer }
  if (updates.status !== undefined) patch.status = updates.status
  if (updates.category !== undefined) patch.category = updates.category
  if (updates.sourceUrl !== undefined) patch.source_url = updates.sourceUrl
  if (updates.reviewNotes !== undefined) patch.review_notes = updates.reviewNotes
  if (updates.active !== undefined) patch.active = updates.active
  if (updates.status === 'ACTIVE') {
    patch.verified_at = new Date().toISOString()
    patch.next_review_date = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10)
  }

  const response = await fetch(`${SUPABASE_URL}/rest/v1/approved_organizations?id=eq.${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      'content-type': 'application/json',
      Prefer: 'return=representation',
    },
    body: JSON.stringify(patch),
    signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
  })
  if (!response.ok) {
    const text = await response.text().catch(() => '')
    throw new Error(`Failed to update domain directory entry: ${text.slice(0, 300)}`)
  }
  const rows = await response.json()
  if (!rows.length) throw new Error('Domain directory entry not found.')
  return toRecord(rows[0])
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

import { TOP_20K_GLOBAL_DOMAINS } from './data/top20kGlobalDomains'
import { extractRegistrableDomain } from './extraction'

// Tier 3, L1: an in-memory Set of the top ~20,000 globally popular domains
// (from the Tranco research-oriented ranking), checked before ever touching
// the database. A Set lookup here costs on the order of microseconds versus
// several milliseconds for a network round trip to Supabase, so this tier
// should never be the slow part of an analysis request.
let cachedSet: Set<string> | null = null

function getSet(): Set<string> {
  if (!cachedSet) {
    cachedSet = new Set(TOP_20K_GLOBAL_DOMAINS.split('\n').filter(Boolean))
  }
  return cachedSet
}

/**
 * True when the given URL or bare domain's registrable domain is in the L1
 * top-20k global list. Does not consult the database; callers should fall
 * through to an L2 (database) lookup on a false result before concluding a
 * domain is unknown, since the full Tranco list has 1,000,000 entries, not
 * just the top 20,000 kept in memory here.
 */
export function isTopGlobalDomain(urlOrDomain: string): boolean {
  const domain = extractRegistrableDomain(urlOrDomain) ?? urlOrDomain.trim().toLowerCase()
  if (!domain) return false
  return getSet().has(domain)
}

/** Exposed for tests and diagnostics; not meant for use in request handling. */
export function topGlobalDomainCount(): number {
  return getSet().size
}

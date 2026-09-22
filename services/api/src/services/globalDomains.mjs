import { isTopGlobalDomain } from '@trustlens/domain'
import { SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL } from '../config/env.mjs'

const LOOKUP_TIMEOUT_MS = 3_000

async function isInL2GlobalDomains(domain) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return false
  const params = new URLSearchParams({ domain: `eq.${domain}`, select: 'domain', limit: '1' })
  const response = await fetch(`${SUPABASE_URL}/rest/v1/global_trusted_domains?${params}`, {
    headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` },
    signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
  })
  if (!response.ok) throw new Error('Global domain L2 lookup failed')
  const rows = await response.json()
  return rows.length > 0
}

function buildFinding(domain, tier) {
  return {
    canonicalSignal: 'known_global_domain',
    category: 'Domain verification',
    evidence: `${domain} is a globally well-known domain (Tranco top-1M ranking, ${tier} cache hit).`,
    source: 'DOMAIN_DIRECTORY',
    strength: 0.5,
    confidence: 0.8,
    limitation: 'Global popularity is supporting evidence only; it does not confirm this specific message is legitimate, and does not rule out impersonation elsewhere in the same message.',
    detectorVersion: 'global-domains-v1',
  }
}

/**
 * Tier 3 of the domain verification pipeline: is this domain one of the
 * world's most popular sites, even though it is not in our own curated
 * official_domains directory? Checks the in-memory L1 cache (top ~20k,
 * microsecond lookup) first, and only falls through to an L2 database query
 * (the full 1M-domain Tranco list) when L1 misses. Deliberately weaker
 * (strength 0.5) than a curated directory match (0.75), since this tier
 * only establishes general global popularity, not that the domain belongs
 * to whatever organization a message claims.
 */
export async function checkGlobalDomainTrust(entities) {
  const domainEntity = entities.find((entity) => entity.type === 'domain')
  if (!domainEntity) return { findings: [] }
  const domain = (domainEntity.normalizedValue || domainEntity.value || '').toLowerCase()
  if (!domain) return { findings: [] }

  if (isTopGlobalDomain(domain)) {
    return { findings: [buildFinding(domain, 'L1')] }
  }

  try {
    const foundInL2 = await isInL2GlobalDomains(domain)
    if (foundInL2) return { findings: [buildFinding(domain, 'L2')] }
  } catch {
    // This tier is supplementary evidence, not a critical check; a failed
    // L2 lookup should never block or fail the overall analysis.
  }

  return { findings: [] }
}

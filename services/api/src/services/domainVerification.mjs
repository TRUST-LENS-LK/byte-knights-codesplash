import { SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL } from '../config/env.mjs'

const LOOKUP_TIMEOUT_MS = 3_000

export async function verifyApprovedDomains(entities) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return []
  const domains = [...new Set(entities.filter((entity) => entity.type === 'domain').map((entity) => entity.normalizedValue || entity.value).map((domain) => domain.toLowerCase()))]
  if (!domains.length) return []

  const params = new URLSearchParams({ active: 'eq.true', select: 'name,official_domain,category,source_url' })
  const response = await fetch(`${SUPABASE_URL}/rest/v1/approved_organizations?${params}`, {
    headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` },
    signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
  })
  if (!response.ok) throw new Error('Approved-domain lookup failed')
  const organizations = await response.json()
  return organizations.filter((organization) => domains.some((domain) => domain === organization.official_domain || domain.endsWith(`.${organization.official_domain}`))).map((organization) => ({
    canonicalSignal: 'approved_domain',
    category: 'Domain verification',
    evidence: `${organization.official_domain} is listed for ${organization.name}.`,
    source: 'DOMAIN_DIRECTORY',
    strength: 0.75,
    confidence: 0.9,
    limitation: 'An approved domain does not prove that every message from it is safe.',
    organization: organization.name,
    domain: organization.official_domain,
    sourceUrl: organization.source_url || null,
  }))
}

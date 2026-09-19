import { SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL } from '../config/env.mjs'
import { listDomainDirectory } from './domainDirectory.mjs'
import { checkOrganizationDomainMatch } from '@trustlens/domain'

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

/**
 * Compares the first claimed organization name found in a submission against
 * the first destination domain found, using the shared pure-logic check from
 * @trustlens/domain. Only ever turns a MISMATCH into a finding: a MATCHED
 * result is intentionally not duplicated here, since verifyApprovedDomains
 * above already covers the positive case for a bare domain, and emitting both
 * would double count the same underlying fact. UNKNOWN is silent by design,
 * per the project's rule that absence of directory data is neutral, never a
 * safety signal. STALE is surfaced as a limitation instead of a finding,
 * since a stale entry cannot be used as evidence in either direction.
 */
export async function checkClaimedOrganizationDomain(entities) {
  const organizationEntity = entities.find((entity) => entity.type === 'organization')
  const domainEntity = entities.find((entity) => entity.type === 'domain')
  if (!organizationEntity || !domainEntity) return { findings: [], limitations: [] }

  const directory = await listDomainDirectory({ includeStale: true })
  if (!directory.length) return { findings: [], limitations: [] }

  const domainValue = (domainEntity.normalizedValue || domainEntity.value).toLowerCase()
  const result = checkOrganizationDomainMatch(organizationEntity.value, domainValue, directory)

  if (result.outcome === 'MISMATCH') {
    return {
      findings: [
        {
          canonicalSignal: 'domain_mismatch',
          category: 'Domain verification',
          evidence: result.evidence,
          source: 'DOMAIN_DIRECTORY',
          strength: 0.9,
          confidence: 0.85,
          limitation: 'Organization name matching is based on extracted text and may miss abbreviations.',
        },
      ],
      limitations: [],
    }
  }

  if (result.outcome === 'STALE') {
    return {
      findings: [],
      limitations: [
        `The directory entry for "${organizationEntity.value}" is due for re-review and could not be used to verify this domain.`,
      ],
    }
  }

  return { findings: [], limitations: [] }
}

/**
 * A domain mismatch, an organization claiming to be one entity while linking
 * to an unrelated domain, is treated as a critical override, the same way
 * applyScannerRisk in analysis.mjs escalates risk for severe scanner
 * findings. This follows the pattern that codebase already established
 * rather than introducing a new one.
 */
export function applyDomainMismatchRisk(decision) {
  const mismatch = decision.findings.some((finding) => finding.canonicalSignal === 'domain_mismatch')
  if (mismatch) {
    decision.riskBand = 'HIGH'
    decision.recommendation = 'STOP_AND_AVOID'
    decision.safeActions = [
      'Do not click, pay, reply, or share credentials.',
      'Verify through the organization\'s official website found independently, not through this message.',
    ]
    decision.overridesApplied = [...(decision.overridesApplied || []), 'domain_mismatch_override']
  }
  return decision
}

import type { DomainVerification, OfficialDomainRecord } from '@trustlens/contracts'

export * from './extraction'

// The fields needed to decide staleness, so callers don't have to build a
// full OfficialDomainRecord just to check one entry.
export type StalenessInput = Pick<OfficialDomainRecord, 'status' | 'nextReviewDate'>

/**
 * A directory entry stops being usable as positive evidence once it is either
 * explicitly retired or moderator-marked stale, or once its review date has
 * passed, even if the stored status column has not been updated yet. The date
 * check is always recomputed here rather than trusted from the stored status
 * alone, so a forgotten review cannot silently keep contributing positive
 * evidence forever.
 */
export function isDirectoryEntryStale(record: StalenessInput, now: Date = new Date()): boolean {
  if (record.status === 'RETIRED' || record.status === 'STALE') return true
  if (!record.nextReviewDate) return false
  const reviewDate = new Date(record.nextReviewDate)
  if (Number.isNaN(reviewDate.getTime())) return false
  return reviewDate.getTime() < now.getTime()
}

/**
 * True when a submitted domain is exactly the official domain, or a
 * subdomain of it, for example "online.boc.lk" matches an official domain of
 * "boc.lk", but "notboc.lk" does not. Comparison is case-insensitive; both
 * values are normalized defensively even though callers should already be
 * passing lowercased, trimmed strings.
 */
export function matchesOfficialDomain(submittedDomain: string, officialDomain: string): boolean {
  const submitted = submittedDomain.trim().toLowerCase()
  const official = officialDomain.trim().toLowerCase()
  if (!submitted || !official) return false
  return submitted === official || submitted.endsWith(`.${official}`)
}

/**
 * Finds the directory record for a claimed organization name extracted from a
 * message, for example "Bank of Ceylon" or "Virtusa Pvt Ltd". Tries an exact
 * name match first, then falls back to a substring match in either direction
 * so a longer extracted phrase (with a trailing "Pvt Ltd" or "PLC") still
 * finds a shorter directory name, and vice versa.
 *
 * Known limitation: this does not resolve bare abbreviations such as "BOC" or
 * "HNB" to their full directory name. The extraction package already
 * recognizes these abbreviations as organization entities, so a message using
 * only "BOC" will currently produce an UNKNOWN outcome rather than a MATCHED
 * or MISMATCH one. Resolving that needs an alias list per directory entry,
 * tracked as a follow-up rather than built here to keep this change focused.
 */
export function findOrganizationRecord(
  claimedOrganizationName: string,
  directory: OfficialDomainRecord[],
): OfficialDomainRecord | null {
  const claimed = claimedOrganizationName.trim().toLowerCase()
  if (!claimed) return null
  const exact = directory.find((record) => record.name.trim().toLowerCase() === claimed)
  if (exact) return exact
  const partial = directory.find((record) => {
    const name = record.name.trim().toLowerCase()
    return name.length > 0 && (claimed.includes(name) || name.includes(claimed))
  })
  return partial ?? null
}

/**
 * Compares a claimed organization name against the domain a message actually
 * points to. This is the core "who owns this domain" check for the slice: an
 * organization we cannot find in the directory yields UNKNOWN (never treated
 * as proof of fraud), a stale directory entry yields STALE (cannot be used as
 * positive evidence right now), and a found, current entry yields either
 * MATCHED or MISMATCH depending on whether the domains agree.
 */
export function checkOrganizationDomainMatch(
  claimedOrganizationName: string,
  actualDomain: string,
  directory: OfficialDomainRecord[],
  now: Date = new Date(),
): DomainVerification {
  const checkedAt = now.toISOString()
  const claimed = claimedOrganizationName?.trim() ?? ''
  const domain = actualDomain?.trim().toLowerCase() ?? ''

  if (!claimed || !domain) {
    return {
      submittedDomain: domain,
      claimedOrganization: claimed || null,
      outcome: 'UNKNOWN',
      matchedRecord: null,
      evidence: 'Not enough information was extracted to compare the claimed organization against the destination domain.',
      checkedAt,
    }
  }

  const record = findOrganizationRecord(claimed, directory)
  if (!record) {
    return {
      submittedDomain: domain,
      claimedOrganization: claimed,
      outcome: 'UNKNOWN',
      matchedRecord: null,
      evidence: `"${claimed}" was not found in the official domain directory, so its real domain could not be confirmed.`,
      checkedAt,
    }
  }

  if (isDirectoryEntryStale(record)) {
    return {
      submittedDomain: domain,
      claimedOrganization: claimed,
      outcome: 'STALE',
      matchedRecord: record,
      evidence: `The directory entry for "${record.name}" is due for re-review, so it cannot be used to confirm this domain right now.`,
      checkedAt,
    }
  }

  const matches = matchesOfficialDomain(domain, record.officialDomain)
  return {
    submittedDomain: domain,
    claimedOrganization: claimed,
    outcome: matches ? 'MATCHED' : 'MISMATCH',
    matchedRecord: record,
    evidence: matches
      ? `${domain} matches the official domain on file for ${record.name}.`
      : `The message claims to be from ${record.name}, whose official domain is ${record.officialDomain}, but the destination domain is ${domain}.`,
    checkedAt,
  }
}

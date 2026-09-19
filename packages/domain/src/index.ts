import type { OfficialDomainRecord } from '@trustlens/contracts'

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

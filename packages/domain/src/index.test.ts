import { describe, expect, it } from 'vitest'
import { isDirectoryEntryStale } from './index'

const FIXED_NOW = new Date('2026-09-19T00:00:00Z')

describe('isDirectoryEntryStale', () => {
  it('is not stale when status is ACTIVE and the review date is in the future', () => {
    expect(isDirectoryEntryStale({ status: 'ACTIVE', nextReviewDate: '2026-12-12' }, FIXED_NOW)).toBe(false)
  })

  it('is stale when the review date has already passed, even if status still says ACTIVE', () => {
    expect(isDirectoryEntryStale({ status: 'ACTIVE', nextReviewDate: '2026-01-01' }, FIXED_NOW)).toBe(true)
  })

  it('is stale when status is explicitly STALE, regardless of the date', () => {
    expect(isDirectoryEntryStale({ status: 'STALE', nextReviewDate: '2099-01-01' }, FIXED_NOW)).toBe(true)
  })

  it('is stale when status is RETIRED, regardless of the date', () => {
    expect(isDirectoryEntryStale({ status: 'RETIRED', nextReviewDate: '2099-01-01' }, FIXED_NOW)).toBe(true)
  })

  it('is not stale when there is no review date yet and status is ACTIVE', () => {
    expect(isDirectoryEntryStale({ status: 'ACTIVE', nextReviewDate: null }, FIXED_NOW)).toBe(false)
  })

  it('is not stale on the exact boundary date at midnight before it passes', () => {
    expect(isDirectoryEntryStale({ status: 'ACTIVE', nextReviewDate: '2026-09-20' }, FIXED_NOW)).toBe(false)
  })

  it('treats an unparseable review date as not stale rather than throwing', () => {
    expect(isDirectoryEntryStale({ status: 'ACTIVE', nextReviewDate: 'not-a-date' }, FIXED_NOW)).toBe(false)
  })
})

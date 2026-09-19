import { describe, expect, it } from 'vitest'
import type { OfficialDomainRecord } from '@trustlens/contracts'
import {
  checkOrganizationDomainMatch,
  findOrganizationRecord,
  isDirectoryEntryStale,
  matchesOfficialDomain,
} from './index'

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

describe('matchesOfficialDomain', () => {
  it('matches an exact domain', () => {
    expect(matchesOfficialDomain('boc.lk', 'boc.lk')).toBe(true)
  })

  it('matches a subdomain of the official domain', () => {
    expect(matchesOfficialDomain('online.boc.lk', 'boc.lk')).toBe(true)
  })

  it('does not match a lookalike domain that merely contains the official domain as a substring', () => {
    expect(matchesOfficialDomain('notboc.lk', 'boc.lk')).toBe(false)
    expect(matchesOfficialDomain('boc.lk.evil.com', 'boc.lk')).toBe(false)
  })

  it('is case-insensitive', () => {
    expect(matchesOfficialDomain('Online.BOC.LK', 'boc.lk')).toBe(true)
  })

  it('rejects empty inputs', () => {
    expect(matchesOfficialDomain('', 'boc.lk')).toBe(false)
    expect(matchesOfficialDomain('boc.lk', '')).toBe(false)
  })
})

const DIRECTORY: OfficialDomainRecord[] = [
  { name: 'Bank of Ceylon', officialDomain: 'boc.lk', status: 'ACTIVE', nextReviewDate: '2026-12-12', active: true },
  { name: 'Virtusa', officialDomain: 'virtusa.com', status: 'ACTIVE', nextReviewDate: '2026-12-12', active: true },
  { name: 'Sri Lanka CERT', officialDomain: 'cert.gov.lk', status: 'STALE', nextReviewDate: '2020-01-01', active: true },
]

describe('findOrganizationRecord', () => {
  it('finds an exact, case-insensitive name match', () => {
    expect(findOrganizationRecord('bank of ceylon', DIRECTORY)?.officialDomain).toBe('boc.lk')
  })

  it('finds a directory entry via a longer extracted phrase (trailing company suffix)', () => {
    expect(findOrganizationRecord('Virtusa Pvt Ltd', DIRECTORY)?.officialDomain).toBe('virtusa.com')
  })

  it('returns null for an organization not in the directory', () => {
    expect(findOrganizationRecord('Some Random Company', DIRECTORY)).toBeNull()
  })

  it('returns null for an empty name', () => {
    expect(findOrganizationRecord('', DIRECTORY)).toBeNull()
  })
})

describe('checkOrganizationDomainMatch', () => {
  it('returns MATCHED when the claimed organization owns the destination domain', () => {
    const result = checkOrganizationDomainMatch('Bank of Ceylon', 'boc.lk', DIRECTORY, FIXED_NOW)
    expect(result.outcome).toBe('MATCHED')
    expect(result.matchedRecord?.officialDomain).toBe('boc.lk')
  })

  it('returns MATCHED for a subdomain of the claimed organization\'s official domain', () => {
    const result = checkOrganizationDomainMatch('Bank of Ceylon', 'secure.boc.lk', DIRECTORY, FIXED_NOW)
    expect(result.outcome).toBe('MATCHED')
  })

  it('returns MISMATCH when the claimed organization does not own the destination domain', () => {
    const result = checkOrganizationDomainMatch('Virtusa Pvt Ltd', 'virtusa-careers-login.com', DIRECTORY, FIXED_NOW)
    expect(result.outcome).toBe('MISMATCH')
    expect(result.matchedRecord?.officialDomain).toBe('virtusa.com')
    expect(result.evidence).toContain('virtusa.com')
  })

  it('returns UNKNOWN when the claimed organization is not in the directory', () => {
    const result = checkOrganizationDomainMatch('Totally Unknown Company', 'unknown-domain.com', DIRECTORY, FIXED_NOW)
    expect(result.outcome).toBe('UNKNOWN')
    expect(result.matchedRecord).toBeNull()
  })

  it('returns UNKNOWN rather than throwing when inputs are missing', () => {
    expect(checkOrganizationDomainMatch('', 'boc.lk', DIRECTORY, FIXED_NOW).outcome).toBe('UNKNOWN')
    expect(checkOrganizationDomainMatch('Bank of Ceylon', '', DIRECTORY, FIXED_NOW).outcome).toBe('UNKNOWN')
  })

  it('returns STALE when the matched directory entry is due for re-review, even if the domain matches', () => {
    const result = checkOrganizationDomainMatch('Sri Lanka CERT', 'cert.gov.lk', DIRECTORY, FIXED_NOW)
    expect(result.outcome).toBe('STALE')
  })
})

import { describe, expect, it } from 'vitest'
import { extractEntities } from './index'

describe('extractEntities', () => {
  it('extracts Sri Lankan contact and payment entities', () => {
    const entities = extractEntities('Call 077 040 4173 or email help@example.com. Pay Rs. 5,000 at https://example.com/apply.')
    expect(entities.map((e) => e.type)).toEqual(expect.arrayContaining(['phone', 'email', 'amount', 'url']))
    expect(entities.find((e) => e.type === 'phone')?.normalizedValue).toBe('+94770404173')
  })

  it('normalizes +94 prefix phone numbers', () => {
    const entities = extractEntities('Call +94 71 234 5678 for details.')
    const phone = entities.find((e) => e.type === 'phone')
    expect(phone).toBeDefined()
    expect(phone?.normalizedValue).toBe('+94712345678')
  })

  it('extracts LKR amount variants', () => {
    const entities = extractEntities('Send LKR 15000 or Rs.500 to complete.')
    const amounts = entities.filter((e) => e.type === 'amount')
    expect(amounts.length).toBeGreaterThanOrEqual(1)
  })

  it('strips trailing punctuation from URLs', () => {
    const entities = extractEntities('Visit https://example.com/apply.')
    const url = entities.find((e) => e.type === 'url')
    expect(url?.value).not.toMatch(/\.$/)
    expect(url?.normalizedValue).not.toMatch(/\.$/)
  })

  it('deduplicates identical entities', () => {
    const entities = extractEntities('https://example.com and https://example.com again')
    const urls = entities.filter((e) => e.type === 'url')
    expect(urls.length).toBe(1)
  })

  it('returns empty array for clean text', () => {
    const entities = extractEntities('The meeting is at 10 AM in the office.')
    expect(entities).toHaveLength(0)
  })
})


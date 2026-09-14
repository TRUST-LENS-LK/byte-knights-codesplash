import { describe, expect, it } from 'vitest'
import { extractEntities } from './index'

describe('extractEntities', () => {
  it('extracts Sri Lankan contact and payment entities', () => {
    const entities = extractEntities('Call 077 040 4173 or email help@example.com. Pay Rs. 5,000 at https://example.com/apply.')
    expect(entities.map((entity) => entity.type)).toEqual(expect.arrayContaining(['phone', 'email', 'amount', 'url']))
    expect(entities.find((entity) => entity.type === 'phone')?.normalizedValue).toBe('+94770404173')
  })
})

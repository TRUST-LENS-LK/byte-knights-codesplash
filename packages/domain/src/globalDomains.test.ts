import { describe, expect, it } from 'vitest'
import { isTopGlobalDomain, topGlobalDomainCount } from './globalDomains'

describe('isTopGlobalDomain', () => {
  it('recognizes a globally well-known domain', () => {
    expect(isTopGlobalDomain('google.com')).toBe(true)
    expect(isTopGlobalDomain('github.com')).toBe(true)
  })

  it('recognizes a domain via a full URL, not just a bare hostname', () => {
    expect(isTopGlobalDomain('https://www.google.com/search?q=test')).toBe(true)
  })

  it('recognizes it regardless of a subdomain', () => {
    expect(isTopGlobalDomain('https://mail.google.com')).toBe(true)
  })

  it('is false for an obscure or made-up domain', () => {
    expect(isTopGlobalDomain('totally-random-scam-site-12345.xyz')).toBe(false)
  })

  it('is false for empty input', () => {
    expect(isTopGlobalDomain('')).toBe(false)
  })

  it('recognizes Sri Lankan domains that are actually globally ranked, like slt.lk', () => {
    expect(isTopGlobalDomain('slt.lk')).toBe(true)
  })
})

describe('topGlobalDomainCount', () => {
  it('loaded exactly 20,000 domains', () => {
    expect(topGlobalDomainCount()).toBe(20000)
  })
})

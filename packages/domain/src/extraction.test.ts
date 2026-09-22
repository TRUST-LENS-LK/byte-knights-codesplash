import { describe, expect, it } from 'vitest'
import {
  defangUrl,
  extractRegistrableDomain,
  getSubdomainDepth,
  hasPunycodeLabel,
  isIpAddressHost,
  isKnownUrlShortener,
  validateAndNormalizeUrl,
} from './extraction'

describe('validateAndNormalizeUrl', () => {
  it('accepts http and https', () => {
    expect(validateAndNormalizeUrl('https://boc.lk').valid).toBe(true)
    expect(validateAndNormalizeUrl('http://boc.lk').valid).toBe(true)
  })

  it('rejects dangerous schemes', () => {
    expect(validateAndNormalizeUrl('javascript:alert(1)').valid).toBe(false)
    expect(validateAndNormalizeUrl('data:text/html,<script>alert(1)</script>').valid).toBe(false)
    expect(validateAndNormalizeUrl('file:///etc/passwd').valid).toBe(false)
    expect(validateAndNormalizeUrl('ftp://example.com').valid).toBe(false)
  })

  it('rejects unparseable input', () => {
    expect(validateAndNormalizeUrl('not a url at all').valid).toBe(false)
  })

  it('lowercases the hostname', () => {
    const result = validateAndNormalizeUrl('https://ONLINE.BOC.LK/Login')
    expect(result.valid && result.normalized).toBe('https://online.boc.lk/Login')
  })

  it('strips a default port', () => {
    const result = validateAndNormalizeUrl('https://boc.lk:443/login')
    expect(result.valid && result.normalized).toBe('https://boc.lk/login')
  })

  it('keeps a non-default port', () => {
    const result = validateAndNormalizeUrl('https://boc.lk:8443/login')
    expect(result.valid && result.normalized).toBe('https://boc.lk:8443/login')
  })
})

describe('extractRegistrableDomain', () => {
  it('strips a simple subdomain under a plain .lk suffix', () => {
    expect(extractRegistrableDomain('https://jobs.dialog.lk/apply')).toBe('dialog.lk')
  })

  it('recognizes gov.lk as the public suffix, not just lk', () => {
    expect(extractRegistrableDomain('https://portal.ird.gov.lk/tax')).toBe('ird.gov.lk')
  })

  it('recognizes ac.lk as the public suffix', () => {
    expect(extractRegistrableDomain('https://online.cmb.ac.lk/lms')).toBe('cmb.ac.lk')
  })

  it('handles a bare apex domain with no subdomain', () => {
    expect(extractRegistrableDomain('https://boc.lk')).toBe('boc.lk')
  })

  it('handles ordinary generic TLDs unaffected by Sri Lankan suffix rules', () => {
    expect(extractRegistrableDomain('https://virtusa-careers-login.com')).toBe('virtusa-careers-login.com')
  })

  it('returns null for a bare IP address', () => {
    expect(extractRegistrableDomain('http://192.168.1.1/login')).toBeNull()
  })
})

describe('getSubdomainDepth', () => {
  it('is 0 for a bare apex domain', () => {
    expect(getSubdomainDepth('https://boc.lk')).toBe(0)
  })

  it('is 1 for a single subdomain label', () => {
    expect(getSubdomainDepth('https://online.boc.lk')).toBe(1)
  })

  it('correctly counts only 2 levels for www.mail.cert.gov.lk, not 5', () => {
    // This is the exact case that a naive hostname.split('.').length count
    // (5 labels total) would over-flag as suspiciously deep. Once gov.lk is
    // recognized as the public suffix, only "www.mail" is subdomain, depth 2.
    expect(getSubdomainDepth('https://www.mail.cert.gov.lk')).toBe(2)
  })
})

describe('isIpAddressHost', () => {
  it('detects a raw IPv4 host', () => {
    expect(isIpAddressHost('http://192.168.1.1/login')).toBe(true)
  })

  it('detects a raw IPv6 host', () => {
    expect(isIpAddressHost('http://[2001:db8::1]/login')).toBe(true)
  })

  it('is false for a normal domain', () => {
    expect(isIpAddressHost('https://boc.lk')).toBe(false)
  })
})

describe('hasPunycodeLabel', () => {
  it('detects a punycode-encoded label', () => {
    expect(hasPunycodeLabel('https://xn--80ak6aa92e.com')).toBe(true)
  })

  it('is false for an ordinary ASCII domain', () => {
    expect(hasPunycodeLabel('https://boc.lk')).toBe(false)
  })
})

describe('isKnownUrlShortener', () => {
  it('detects known shorteners', () => {
    expect(isKnownUrlShortener('https://bit.ly/abc123')).toBe(true)
    expect(isKnownUrlShortener('https://tinyurl.com/abc123')).toBe(true)
  })

  it('is false for an unrelated domain', () => {
    expect(isKnownUrlShortener('https://boc.lk')).toBe(false)
  })
})

describe('defangUrl', () => {
  it('breaks the scheme and dots so the link cannot be clicked', () => {
    expect(defangUrl('https://virtusa-careers-login.com')).toBe('hxxps://virtusa-careers-login[.]com')
  })
})

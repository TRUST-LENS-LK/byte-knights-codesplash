import { chromium } from 'playwright-core'
import { Resolver, lookup } from 'node:dns/promises'

// Dedicated Cloudflare Family DNS resolver (1.1.1.3 / 1.0.0.3) for zero-cost malware & adult filtering
const familyDnsResolver = new Resolver()
try {
  familyDnsResolver.setServers(['1.1.1.3', '1.0.0.3'])
} catch {
  // Fallback to default if setServers throws in custom environments
}

// Known adult TLDs and regex patterns (Layer 1)
const ADULT_TLD_REGEX = /\.(xxx|adult|porn|sex)$/i
const ADULT_KEYWORDS_REGEX = /(?:^|[.-])(porn|xxx|adult|erotic|nsfw|sex|nude|cams?|tubes?|fuck|boobs?|hentai|strip|dildo)(?:[.-]|$)/i
const KNOWN_ADULT_DOMAINS = new Set([
  'eporner.com',
  'pornhub.com',
  'xvideos.com',
  'xnxx.com',
  'redtube.com',
  'chaturbate.com',
  'onlyfans.com',
  'youporn.com',
  'xhamster.com',
  'spankbang.com',
  'beeg.com',
  'stripchat.com',
  'cam4.com',
  'fapchat.com',
  'livejasmin.com',
  'bonga.com',
  'bongacams.com',
  'tube8.com',
  'porn.com',
  'thumbzilla.com',
  'hqporner.com',
  'txxx.com',
  'daftsex.com'
])

export function isKnownAdultDomain(hostname) {
  if (!hostname) return false
  const cleanHost = hostname.toLowerCase().replace(/^www\./, '')
  if (KNOWN_ADULT_DOMAINS.has(cleanHost)) return true
  if (ADULT_TLD_REGEX.test(cleanHost)) return true
  if (ADULT_KEYWORDS_REGEX.test(cleanHost)) return true
  return false
}

export async function isCloudflareFamilyBlocked(hostname) {
  if (!hostname) return false
  try {
    const addresses = await familyDnsResolver.resolve4(hostname).catch(() => [])
    // Cloudflare Family DNS (1.1.1.3) resolves adult / malware domains to 0.0.0.0
    if (addresses.includes('0.0.0.0')) {
      return true
    }
  } catch {
    // If resolution fails or throws, ignore
  }
  return false
}

const SCAN_TIMEOUT = parseInt(process.env.SCAN_TIMEOUT || '15000', 10)
const MAX_REDIRECTS = parseInt(process.env.MAX_REDIRECTS || '5', 10)
const MAX_TEXT_LENGTH = parseInt(process.env.MAX_TEXT_LENGTH || '15000', 10)
const MAX_EXTERNAL_DOMAINS = 50

// Block private IP ranges (DNS rebinding protection)
function isPrivateIp(ip) {
  if (!ip) return false
  if (ip === '::1' || ip === '::') return process.env.ALLOW_LOCAL_TEST !== '1'
  if (ip.startsWith('fc00:') || ip.startsWith('fd00:') || ip.startsWith('fe80:')) return true
  if (ip.startsWith('::ffff:')) ip = ip.split(':').pop() // IPv4-mapped IPv6

  const parts = ip.split('.').map(Number)
  if (parts.length !== 4) return false
  const [a, b] = parts

  if (process.env.ALLOW_LOCAL_TEST === '1' && a === 127) return false

  if (a === 10) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 169 && b === 254) return true
  if (a === 127 || a === 0) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a === 198 && (b === 18 || b === 19)) return true
  if (a >= 224 && a <= 239) return true

  return false
}

// No caching here on purpose. The DNS check below and Chromium's own
// connection are still two separate resolutions (a full fix would require
// fetching each resource ourselves with a pinned IP instead of letting the
// browser resolve independently), so this cannot fully close a DNS-rebinding
// race by itself. Not caching at least means every single request gets a
// fresh lookup checked immediately before continue(), shrinking that window
// to the minimum achievable without a larger rewrite of this interceptor.
let browser = null
export async function scanUrl(targetUrl) {
  const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined
  const browser = await chromium.launch({
    executablePath,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  })

  const context = await browser.newContext({
    acceptDownloads: false, // Security: block downloads
    viewport: { width: 1280, height: 800 },
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
  })

  const page = await context.newPage()
  const limitations = []
  let totalRedirects = 0

  // Security & Performance: DNS Rebinding Protection, Media Blocking & Redirect SSRF handling
  await page.route('**/*', async (route) => {
    const request = route.request()
    const resourceType = request.resourceType()
    let requestUrl
    try {
      requestUrl = new URL(request.url())
    } catch {
      return route.abort('blockedbyclient').catch(() => {})
    }
    
    // Fast-abort large audio/video streaming files to preserve bandwidth, but allow fonts, images, and stylesheets
    if (
      resourceType === 'media' ||
      /\.(mp4|webm|ogg|mp3|wav|flac|aac)(\?.*)?$/i.test(requestUrl.pathname)
    ) {
      return route.abort('blockedbyclient').catch(() => {})
    }

    // Only allow http/https
    if (requestUrl.protocol !== 'http:' && requestUrl.protocol !== 'https:') {
      limitations.push(`Blocked unsafe protocol: ${requestUrl.protocol}`)
      return route.abort('blockedbyclient').catch(() => {})
    }

    try {
      const { address } = await lookup(requestUrl.hostname)

      if (isPrivateIp(address)) {
        console.warn(`[Scanner] Blocked request to private IP ${address} for ${requestUrl.hostname}`)
        limitations.push('Blocked navigation to private or internal network address')
        return route.abort('blockedbyclient').catch(() => {})
      }
    } catch {
      limitations.push(`DNS resolution failed for ${requestUrl.hostname}`)
      return route.abort('namenotresolved').catch(() => {})
    }

    // Instead of route.continue(), which allows native browser redirect following (bypassing our route handler),
    // we use route.fetch with maxRedirects: 0 to manually intercept and inspect redirect destinations.
    try {
      const fetchResponse = await route.fetch({ maxRedirects: 0 })
      const status = fetchResponse.status()
      const maxBytes = parseInt(process.env.MAX_PAGE_BYTES || '5242880', 10)
      
      // Phase 4: Enforce Response Size Limits (Content-Length)
      const contentLength = parseInt(fetchResponse.headers()['content-length'] || '0', 10)
      if (contentLength > maxBytes) {
        limitations.push('Blocked resource exceeding maximum allowed size (Header)')
        return route.abort('blockedbyclient')
      }
      
      if (status >= 300 && status < 400) {
        const location = fetchResponse.headers()['location']
        if (location) {
          if (request.isNavigationRequest()) {
            totalRedirects++
            if (totalRedirects > MAX_REDIRECTS) {
              limitations.push(`Scan stopped: Exceeded maximum redirect limit of ${MAX_REDIRECTS}`)
              return route.abort('blockedbyclient').catch(() => {})
            }
          } else {
            // Subresource redirect: verify destination doesn't target private network
            try {
              const redirectTarget = new URL(location, requestUrl)
              const { address } = await lookup(redirectTarget.hostname)
              if (isPrivateIp(address)) {
                limitations.push(`Blocked redirect for subresource ${redirectTarget.hostname}`)
                return route.abort('blockedbyclient').catch(() => {})
              }
            } catch {
              return route.abort('namenotresolved').catch(() => {})
            }
          }
        }
      }

      // Read the actual body to measure downloaded bytes
      const body = await fetchResponse.body().catch(() => Buffer.alloc(0))
      if (body.length > maxBytes) {
        limitations.push('Blocked resource exceeding maximum allowed actual size (Body)')
        return route.abort('blockedbyclient').catch(() => {})
      }
      
      return route.fulfill({ response: fetchResponse, body })
    } catch (e) {
      return route.abort('failed').catch(() => {})
    }
  })

  try {
    let currentUrl = (targetUrl || '').trim()
    // Normalize defanged notation (hxxps:// -> https://, [.] -> .) and bare domains
    currentUrl = currentUrl
      .replace(/^hxxps:\/\//i, 'https://')
      .replace(/^hxxp:\/\//i, 'http://')
      .replace(/\[\.\]/g, '.')
    if (!/^https?:\/\//i.test(currentUrl)) {
      currentUrl = `https://${currentUrl}`
    }

    let isAdultContent = false
    try {
      const initialHost = new URL(currentUrl).hostname
      if (isKnownAdultDomain(initialHost)) {
        isAdultContent = true
      } else if (await isCloudflareFamilyBlocked(initialHost)) {
        isAdultContent = true
      }
    } catch {
      // Handled in navigation
    }

    let response = null
    try {
      response = await page.goto(currentUrl, { waitUntil: 'load', timeout: SCAN_TIMEOUT }).catch(async (err) => {
        if (err.message.includes('Timeout')) {
          return page.goto(currentUrl, { waitUntil: 'domcontentloaded', timeout: 5000 }).catch(() => null)
        }
        throw err
      })
    } catch (e) {
      if (e.message.includes('Timeout')) {
        limitations.push(`Scan timed out after ${SCAN_TIMEOUT}ms`)
      } else if (!e.message.includes('ERR_BLOCKED_BY_CLIENT') || limitations.length === 0) {
        limitations.push(`Navigation failed: ${e.message}`)
      }
    }
    const finalUrl = page.url() || currentUrl
    try {
      const finalHost = new URL(finalUrl).hostname
      if (!isAdultContent && (isKnownAdultDomain(finalHost) || await isCloudflareFamilyBlocked(finalHost))) {
        isAdultContent = true
      }
    } catch {}
    
    let isPartial = false
    if (!response && limitations.length > 0) {
      const hasContent = await page.evaluate(() => Boolean(document.body && document.body.innerHTML.length > 50)).catch(() => false)
      if (hasContent) {
        isPartial = true
      } else {
        throw new Error('No response received from target URL')
      }
    } else if (!response) {
      throw new Error('No response received from target URL')
    }

    const title = await page.title().catch(() => '')
    const isHttps = finalUrl.startsWith('https://')
    
    // Extract innerText of the body (ignores script/style tags visually)
    const textContent = await page.evaluate(() => document.body?.innerText || '').catch(() => '')

    // Phase 3: Extract structured evidence deterministically
    const evidence = await page.evaluate((maxDomains) => {
      const forms = Array.from(document.querySelectorAll('form'))
      let passwordFields = 0
      let emailFields = 0
      let loginForms = 0
      
      forms.forEach(form => {
        const hasPassword = form.querySelector('input[type="password"]') !== null
        const hasEmail = form.querySelector('input[type="email"], input[name*="user" i], input[name*="email" i], input[name*="login" i]') !== null
        
        if (hasPassword) passwordFields++
        if (hasEmail) emailFields++
        if (hasPassword || (form.action && form.action.toLowerCase().includes('login')) || (form.id && form.id.toLowerCase().includes('login'))) {
          loginForms++
        }
      })
      
      const pageHostname = window.location.hostname
      const externalDomainsSet = new Set()
      
      document.querySelectorAll('a[href], form[action]').forEach(el => {
        try {
          const urlStr = el.href || el.action
          if (!urlStr) return
          const url = new URL(urlStr, window.location.href)
          if (url.protocol === 'http:' || url.protocol === 'https:') {
            if (url.hostname && url.hostname !== pageHostname) {
              externalDomainsSet.add(url.hostname)
            }
          }
        } catch {
          // ignore invalid URLs
        }
      })

      return {
        forms: forms.length,
        loginForms,
        passwordFields,
        emailFields,
        paymentFields: 0,
        externalDomains: Array.from(externalDomainsSet).slice(0, maxDomains)
      }
    }, MAX_EXTERNAL_DOMAINS).catch(() => ({
      forms: 0, loginForms: 0, passwordFields: 0, emailFields: 0, paymentFields: 0, externalDomains: []
    }))

    // Layer 3: Inspect HTML meta rating and explicit keywords in DOM
    if (!isAdultContent) {
      const isAdultMeta = await page.evaluate(() => {
        const ratingMeta = document.querySelector('meta[name="rating" i], meta[name="RATING" i]')
        if (ratingMeta) {
          const content = (ratingMeta.getAttribute('content') || '').toLowerCase()
          if (content.includes('adult') || content.includes('rta') || content.includes('mature') || content.includes('18+')) {
            return true
          }
        }
        const titleText = (document.title || '').toLowerCase()
        const metaDesc = (document.querySelector('meta[name="description" i]')?.getAttribute('content') || '').toLowerCase()
        if (/(?:^|\s)(porn|xxx|18\+|adults only|explicit sex|free porn)(?:\s|$)/i.test(`${titleText} ${metaDesc}`)) {
          return true
        }
        return false
      }).catch(() => false)

      if (isAdultMeta) {
        isAdultContent = true
      }
    }

    // Ensure all styles, web fonts, and dynamic JavaScript hydration have completely rendered
    await page.waitForLoadState('networkidle', { timeout: 4000 }).catch(() => {})
    await page.waitForTimeout(1000).catch(() => {})

    evidence.isPartial = isPartial
    evidence.isAdultContent = isAdultContent

    // Visual Capture Safety Guard: Suppress visual screenshot if adult content is detected
    if (isAdultContent) {
      limitations.push('Visual capture suppressed: 18+ adult content detected by safety filter.')
      evidence.screenshotBase64 = null
    } else {
      const screenshotBuffer = await page.screenshot({ type: 'jpeg', quality: 85, fullPage: false }).catch(() => null)
      if (screenshotBuffer) {
        evidence.screenshotBase64 = screenshotBuffer.toString('base64')
      }
    }

    return {
      status: limitations.length > 0 ? 'completed_with_limitations' : 'completed',
      requestedUrl: targetUrl,
      finalUrl,
      title,
      redirectCount: totalRedirects,
      https: isHttps,
      evidence,
      isPartial,
      isAdultContent,
      limitations: Array.from(new Set(limitations)),
      textContent: textContent.trim().slice(0, MAX_TEXT_LENGTH), // Bound text size
      httpStatus: response ? response.status() : 0
    }
  } finally {
    await context.close().catch(() => {})
    await browser.close().catch(() => {})
  }
}

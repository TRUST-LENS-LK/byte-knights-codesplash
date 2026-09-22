import { chromium } from 'playwright-core'
import { lookup } from 'node:dns/promises'

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

const dnsCache = new Map()
export async function scanUrl(targetUrl) {
  const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined
  const browser = await chromium.launch({
    executablePath,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  })

  const context = await browser.newContext({
    acceptDownloads: false, // Security: block downloads
  })

  const page = await context.newPage()
  const limitations = []
  let totalRedirects = 0

  // Security: DNS Rebinding Protection & Redirect SSRF handling via request interception
  await page.route('**/*', async (route) => {
    const request = route.request()
    const requestUrl = new URL(request.url())
    
    // Only allow http/https
    if (requestUrl.protocol !== 'http:' && requestUrl.protocol !== 'https:') {
      limitations.push(`Blocked unsafe protocol: ${requestUrl.protocol}`)
      return route.abort('blockedbyclient')
    }

    try {
      let address = dnsCache.get(requestUrl.hostname)
      if (!address) {
        const result = await lookup(requestUrl.hostname)
        address = result.address
        dnsCache.set(requestUrl.hostname, address)
      }
      
      if (isPrivateIp(address)) {
        console.warn(`[Scanner] Blocked request to private IP ${address} for ${requestUrl.hostname}`)
        limitations.push('Blocked navigation to private or internal network address')
        return route.abort('blockedbyclient')
      }
    } catch {
      limitations.push(`DNS resolution failed for ${requestUrl.hostname}`)
      return route.abort('namenotresolved')
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
            // Store the redirect URL to be handled by the outer loop for top-level navigations
            page._nextRedirectUrl = new URL(location, requestUrl).href
          } else {
            // Subresource redirect: block to prevent native redirection bypassing SSRF checks
            limitations.push(`Blocked redirect for subresource ${requestUrl.hostname}`)
          }
          return route.abort('blockedbyclient')
        }
      }

      // Read the actual body to measure downloaded bytes
      const body = await fetchResponse.body().catch(() => Buffer.alloc(0))
      if (body.length > maxBytes) {
        limitations.push('Blocked resource exceeding maximum allowed actual size (Body)')
        return route.abort('blockedbyclient')
      }
      
      return route.fulfill({ response: fetchResponse, body })
    } catch (e) {
      return route.abort('failed')
    }
  })

  try {
    let currentUrl = targetUrl
    let response = null
    let finalUrl = currentUrl
    let totalRedirects = 0

    while (true) {
      page._nextRedirectUrl = null
      try {
        response = await page.goto(currentUrl, { waitUntil: 'domcontentloaded', timeout: SCAN_TIMEOUT })
      } catch (e) {
        if (page._nextRedirectUrl) {
          totalRedirects++
          if (totalRedirects > MAX_REDIRECTS) {
            limitations.push(`Scan stopped: Exceeded maximum redirect limit of ${MAX_REDIRECTS}`)
            break
          }
          currentUrl = page._nextRedirectUrl
          continue
        }
        if (e.message.includes('Timeout')) {
          limitations.push(`Scan timed out after ${SCAN_TIMEOUT}ms`)
        } else if (!e.message.includes('ERR_BLOCKED_BY_CLIENT') || limitations.length === 0) {
          // If it's a blocked request, limitations should already have been populated by the route handler
          limitations.push(`Navigation failed: ${e.message}`)
        }
      }
      finalUrl = currentUrl
      break
    }
    
    if (!response && limitations.length === 0) {
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

    const screenshotBuffer = await page.screenshot({ type: 'jpeg', quality: 50 }).catch(() => null)
    if (screenshotBuffer) {
      evidence.screenshotBase64 = screenshotBuffer.toString('base64')
    }

    return {
      status: limitations.length > 0 ? 'completed_with_limitations' : 'completed',
      requestedUrl: targetUrl,
      finalUrl,
      title,
      redirectCount: totalRedirects,
      https: isHttps,
      evidence,
      limitations: Array.from(new Set(limitations)),
      textContent: textContent.trim().slice(0, MAX_TEXT_LENGTH), // Bound text size
      httpStatus: response ? response.status() : 0
    }
  } finally {
    await context.close().catch(() => {})
    await browser.close().catch(() => {})
  }
}

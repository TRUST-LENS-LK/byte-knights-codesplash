import { chromium } from 'playwright-core'
import { lookup } from 'node:dns/promises'

// Block private IP ranges (DNS rebinding protection)
function isPrivateIp(ip) {
  if (!ip) return false
  if (ip === '::1' || ip === '::') return true
  if (ip.startsWith('fc00:') || ip.startsWith('fd00:') || ip.startsWith('fe80:')) return true
  if (ip.startsWith('::ffff:')) ip = ip.split(':').pop() // IPv4-mapped IPv6

  const parts = ip.split('.').map(Number)
  if (parts.length !== 4) return false
  const [a, b] = parts

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
let browser = null

export async function scanUrl(targetUrl) {
  if (!browser) {
    // In the docker container, chromium executable is in the path or provided by playwright docker image
    // For local dev, you'd need playwright installed, but we use playwright-core
    // The official image has chromium at /ms-playwright/chromium-*/chrome-linux/chrome
    const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined
    browser = await chromium.launch({
      executablePath,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
    })
    
    // Stability: Auto-recover if the browser crashes internally
    browser.on('disconnected', () => { browser = null })
  }

  const context = await browser.newContext({
    acceptDownloads: false, // Security: block downloads
  })

  const page = await context.newPage()

  // Security: DNS Rebinding Protection via request interception
  await page.route('**/*', async (route) => {
    const request = route.request()
    const requestUrl = new URL(request.url())
    
    // Only allow http/https
    if (requestUrl.protocol !== 'http:' && requestUrl.protocol !== 'https:') {
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
        return route.abort('blockedbyclient')
      }
    } catch {
      return route.abort('namenotresolved')
    }

    route.continue()
  })

  try {
    // Navigate with a timeout
    const response = await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 8000 })
    
    if (!response) {
      throw new Error('No response received from target URL')
    }

    const finalUrl = page.url()
    const title = await page.title()
    // Extract innerText of the body (ignores script/style tags visually)
    const textContent = await page.evaluate(() => document.body?.innerText || '')

    return {
      requestedUrl: targetUrl,
      finalUrl,
      title,
      textContent: textContent.trim().slice(0, 15000), // Cap at 15k chars
      status: response.status()
    }
  } finally {
    await context.close()
  }
}

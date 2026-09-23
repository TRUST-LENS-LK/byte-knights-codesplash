import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { scanUrl } from '../src/scanner.mjs'
import { createServer } from 'node:http'

// A simple mock server to test redirects and evidence extraction
function createMockServer() {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      if (req.url === '/redirect-safe') {
        res.writeHead(302, { Location: '/evidence' })
        res.end()
      } else if (req.url === '/redirect-loop-1') {
        res.writeHead(302, { Location: '/redirect-loop-2' })
        res.end()
      } else if (req.url === '/redirect-loop-2') {
        res.writeHead(302, { Location: '/redirect-loop-1' })
        res.end()
      } else if (req.url === '/redirect-private') {
        res.writeHead(302, { Location: 'http://192.168.1.1' })
        res.end()
      } else if (req.url === '/evidence') {
        res.writeHead(200, { 'Content-Type': 'text/html' })
        res.end(`
          <html>
            <head><title>Evidence Test</title></head>
            <body>
              <form action="/login" method="POST" id="login-form">
                <input type="text" name="username" />
                <input type="password" name="pwd" />
              </form>
              <form action="http://example.com/subscribe">
                <input type="email" name="email" />
              </form>
              <a href="https://external-site.com/link1">Link 1</a>
              <a href="https://external-site.com/link2">Link 2</a>
              <a href="/internal-link">Internal</a>
            </body>
          </html>
        `)
      } else if (req.url === '/timeout') {
        // Just hang indefinitely
      } else {
        res.writeHead(404)
        res.end()
      }
    })
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port
      resolve({ server, url: `http://127.0.0.1:${port}` })
    })
  })
}

describe('Scanner Containment, SSRF Protection, and Evidence', () => {
  let mockServer, mockUrl
  
  test('setup mock server', async () => {
    const mock = await createMockServer()
    mockServer = mock.server
    mockUrl = mock.url
  })

  test('Should successfully scan a safe public URL', async () => {
    const result = await scanUrl('http://example.com')
    assert.equal(result.status, 'completed')
    assert.ok(result.title.includes('Example Domain'))
  })

  test('Should block local loopback address (127.0.0.1)', async () => {
    const result = await scanUrl('http://127.0.0.1')
    console.log('127 RESULT LIMITATIONS:', result.limitations)
    assert.equal(result.status, 'completed_with_limitations')
    assert.ok(result.limitations.some(l => l.includes('Blocked navigation to private')))
  })

  test('Should block localhost', async () => {
    const result = await scanUrl('http://localhost')
    assert.equal(result.status, 'completed_with_limitations')
    assert.ok(result.limitations.some(l => l.includes('Blocked navigation to private') || l.includes('DNS resolution failed')))
  })

  test('Should block cloud metadata IP (169.254.169.254)', async () => {
    const result = await scanUrl('http://169.254.169.254')
    assert.equal(result.status, 'completed_with_limitations')
    assert.ok(result.limitations.some(l => l.includes('Blocked navigation to private')))
  })

  test('Should block private network IP (192.168.1.1)', async () => {
    const result = await scanUrl('http://192.168.1.1')
    assert.equal(result.status, 'completed_with_limitations')
    assert.ok(result.limitations.some(l => l.includes('Blocked navigation to private')))
  })

  // NEW TESTS
  test('Should successfully extract evidence', async () => {
    process.env.ALLOW_LOCAL_TEST = '1'
    const result = await scanUrl(mockUrl + '/evidence')
    process.env.ALLOW_LOCAL_TEST = '0'
    console.log('EVIDENCE RESULT:', JSON.stringify(result.evidence))
    
    assert.equal(result.status, 'completed')
    assert.ok(result.evidence)
    assert.equal(result.evidence.forms, 2)
    assert.equal(result.evidence.loginForms, 1)
    assert.equal(result.evidence.passwordFields, 1)
    assert.equal(result.evidence.emailFields, 2)
    assert.equal(result.evidence.externalDomains.length, 2)
    assert.ok(result.evidence.externalDomains.includes('external-site.com'))
    assert.ok(result.evidence.externalDomains.includes('example.com'))
  })

  test('Should test redirect loops and limits', async () => {
    process.env.ALLOW_LOCAL_TEST = '1'
    const result = await scanUrl(mockUrl + '/redirect-loop-1')
    process.env.ALLOW_LOCAL_TEST = '0'
    console.log('LOOP LIMITATIONS:', result.limitations)
    
    assert.equal(result.status, 'completed_with_limitations')
    assert.ok(result.limitations.some(l => l.includes('Exceeded maximum redirect limit') || l.includes('ERR_TOO_MANY_REDIRECTS')))
  })

  test('Should test redirect to private IP', async () => {
    process.env.ALLOW_LOCAL_TEST = '1'
    const result = await scanUrl(mockUrl + '/redirect-private')
    process.env.ALLOW_LOCAL_TEST = '0'
    console.log('REDIRECT PRIVATE LIMITATIONS:', result.limitations)
    
    assert.equal(result.status, 'completed_with_limitations')
    assert.ok(result.limitations.some(l => l.includes('Blocked navigation to private')))
  })

  test('Should respect timeout and return limitations safely', async () => {
    // A domain that drops packets or hangs (like a non-routable public IP)
    // 192.0.2.1 is TEST-NET-1 and drops packets
    const result = await scanUrl('http://192.0.2.1')
    assert.equal(result.status, 'completed_with_limitations')
    assert.ok(result.limitations.some(l => l.includes('timed out') || l.includes('Navigation failed')))
  })

  test('teardown', () => {
    if (mockServer) mockServer.close()
  })
})

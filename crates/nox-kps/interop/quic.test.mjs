// Interop: the reference Node QUIC client (@kpstreams/quic-client 0.2.1)
// against a nox-kps binary and a mock of the node's loopback services.
//
//   cargo build --locked -p nox-kps && (cd crates/nox-kps/interop && npm ci && npm test)
//   NOX_KPS_BIN=/path/to/nox-kps npm test   (default: the workspace's target/debug/nox-kps)
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, execFileSync } from 'node:child_process'
import { createServer } from 'node:http'
import { createSocket } from 'node:dgram'
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createInterface } from 'node:readline'
import { dial } from '@kpstreams/quic-client'

const here = dirname(fileURLToPath(import.meta.url))
const BIN = process.env.NOX_KPS_BIN ?? join(here, '..', '..', '..', 'target', 'debug', 'nox-kps')
const PACKET_BYTES = 32768
const SURB_ID = '00112233445566778899aabbccddeeff'

let upstream
let upstreamSeen = []
let child
let address
let certhash
let bundleHash
let bundleBytes
let otherCerthash

function freeUdpPort () {
  return new Promise((resolve) => {
    const sock = createSocket('udp4')
    sock.bind(0, '127.0.0.1', () => {
      const { port } = sock.address()
      sock.close(() => resolve(port))
    })
  })
}

function freeTcpPort () {
  return new Promise((resolve) => {
    const srv = createServer()
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => resolve(port))
    })
  })
}

function startUpstream () {
  return new Promise((resolve) => {
    const srv = createServer((req, res) => {
      const chunks = []
      req.on('data', (c) => chunks.push(c))
      req.on('end', () => {
        const body = Buffer.concat(chunks)
        upstreamSeen.push({ method: req.method, url: req.url, headers: req.headers, length: body.length })
        if (req.method === 'POST' && req.url === '/api/v1/packets') {
          res.writeHead(202, { 'content-type': 'text/plain' }).end('accepted')
        } else if (req.method === 'POST' && req.url === '/api/v1/responses/claim') {
          const ids = JSON.parse(body.toString()).surb_ids
          res.writeHead(200, { 'content-type': 'application/json' })
            .end(JSON.stringify(ids.map((id) => ({ id, data: [1, 2, 3] }))))
        } else if (req.url === '/topology') {
          res.writeHead(200, { 'content-type': 'application/json' }).end('{"nodes":[]}')
        } else if (req.url === '/health') {
          res.writeHead(200).end('ok')
        } else {
          res.writeHead(404).end()
        }
      })
    })
    srv.listen(0, '127.0.0.1', () => resolve(srv))
  })
}

/** One KPS-HTTP/1 exchange on a fresh stream; returns { status, headers, body }. */
async function exchange (conn, method, path, { headers = {}, body } = {}) {
  const stream = await conn.openStream()
  const lines = [`${method} ${path} HTTP/1.1`, `Host: ${certhash}`]
  for (const [k, v] of Object.entries(headers)) lines.push(`${k}: ${v}`)
  if (body) lines.push(`Content-Length: ${body.length}`)
  const head = new TextEncoder().encode(lines.join('\r\n') + '\r\n\r\n')
  const writer = stream.writable.getWriter()
  await writer.write(body ? Buffer.concat([head, body]) : head)
  await writer.close()
  const chunks = []
  for await (const chunk of stream.readable) chunks.push(Buffer.from(chunk))
  const raw = Buffer.concat(chunks)
  const split = raw.indexOf('\r\n\r\n')
  assert.ok(split > 0, `complete response head (got ${raw.length} bytes)`)
  const [statusLine, ...headerLines] = raw.subarray(0, split).toString().split('\r\n')
  const [version, status] = statusLine.split(' ')
  assert.equal(version, 'HTTP/1.1')
  const parsed = Object.fromEntries(headerLines.map((l) => {
    const i = l.indexOf(':')
    return [l.slice(0, i).toLowerCase(), l.slice(i + 1).trim()]
  }))
  const payload = raw.subarray(split + 4)
  assert.equal(parsed['transfer-encoding'], undefined)
  if (parsed['content-length'] !== undefined && method !== 'HEAD') {
    assert.equal(Number(parsed['content-length']), payload.length, 'Content-Length matches the body')
  }
  return { status: Number(status), headers: parsed, body: payload }
}

before(async () => {
  upstream = await startUpstream()
  const up = `127.0.0.1:${upstream.address().port}`
  const dir = mkdtempSync(join(tmpdir(), 'nox-kps-interop-'))
  const udp = await freeUdpPort()
  const admin = await freeTcpPort()
  const config = join(dir, 'nox-kps.toml')
  writeFileSync(config, [
    `listen = "127.0.0.1:${udp}"`,
    'advertise = ["127.0.0.1"]',
    'allow_private_advertise = true',
    `key_file = "${join(dir, 'kps.key')}"`,
    `keccak_dir = "${join(dir, 'keccak')}"`,
    `upstream_ingress = "${up}"`,
    `upstream_topology = "${up}"`,
    `admin_listen = "127.0.0.1:${admin}"`,
    'log_format = "text"',
    '[limits]',
    'topology_cache_ms = 0',
    'health_cache_ms = 0',
    '[shutdown]',
    'grace_period_ms = 2000',
    'close_linger_ms = 200',
  ].join('\n'))
  const init = execFileSync(BIN, ['--config', config, 'init']).toString()
  const confirmed = init.match(/^config line: (expected_certhash = "uEi[^"]+")$/m)[1]
  writeFileSync(config, `${confirmed}\n${readFileSync(config, 'utf8')}`)
  bundleBytes = Buffer.from('(()=>{self.postMessage("nox anon-rpc worker")})();\n')
  writeFileSync(join(dir, 'worker.js'), bundleBytes)
  const added = execFileSync(BIN, ['--config', config, 'bundle', 'add', join(dir, 'worker.js')]).toString()
  bundleHash = added.match(/added: ([0-9a-f]{64})/)[1]
  const addrOut = execFileSync(BIN, ['--config', config, 'address']).toString()
  address = addrOut.match(/address: (\S+)/)[1]
  certhash = address.split(':').pop()
  // A second, unrelated identity: a valid certhash that is not the server's.
  const env = { ...process.env, NOX_KPS__KEY_FILE: join(dir, 'other.key') }
  execFileSync(BIN, ['--config', config, 'init'], { env })
  const other = execFileSync(BIN, ['--config', config, 'address'], { env }).toString()
  otherCerthash = other.match(/address: (\S+)/)[1].split(':').pop()
  assert.notEqual(otherCerthash, certhash)

  child = spawn(BIN, ['--config', config, 'run'], { stdio: ['ignore', 'pipe', 'inherit'] })
  const rl = createInterface({ input: child.stdout })
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('nox-kps did not start')), 20000)
    rl.on('line', (line) => {
      if (line.includes('admin endpoint')) {
        clearTimeout(timer)
        resolve()
      }
    })
  })
})

after(async () => {
  if (child) {
    child.kill('SIGTERM')
    await new Promise((resolve) => child.on('exit', resolve))
  }
  upstream?.close()
})

test('GET /health over QUIC', async () => {
  const conn = await dial(address, { signal: AbortSignal.timeout(10000) })
  const res = await exchange(conn, 'GET', '/health')
  assert.equal(res.status, 200)
  assert.equal(res.body.toString(), '{"status":"ok"}')
  await conn.close()
})

test('a 32 KiB packet reaches the node with the client IP header', async () => {
  upstreamSeen = []
  const conn = await dial(address, { signal: AbortSignal.timeout(10000) })
  const res = await exchange(conn, 'POST', '/api/v1/packets', {
    headers: { 'Content-Type': 'application/octet-stream', 'X-Real-IP': '6.6.6.6' },
    body: Buffer.alloc(PACKET_BYTES, 7),
  })
  assert.equal(res.status, 202)
  const seen = upstreamSeen.find((r) => r.url === '/api/v1/packets')
  assert.equal(seen.length, PACKET_BYTES)
  assert.equal(seen.headers['x-real-ip'], '127.0.0.1')
  await conn.close()
})

test('claim and topology round trips; refusals stay local', async () => {
  const conn = await dial(address, { signal: AbortSignal.timeout(10000) })
  const claim = await exchange(conn, 'POST', '/api/v1/responses/claim', {
    headers: { 'Content-Type': 'application/json' },
    body: Buffer.from(JSON.stringify({ surb_ids: [SURB_ID] })),
  })
  assert.equal(claim.status, 200)
  assert.equal(JSON.parse(claim.body)[0].id, SURB_ID)
  assert.equal((await exchange(conn, 'GET', '/topology')).status, 200)
  assert.equal((await exchange(conn, 'GET', '/api/v1/ws')).status, 404)
  assert.equal((await exchange(conn, 'GET', '/api/v1/packets')).status, 405)
  await conn.close()
})

test('metadata and the kps: bundle resolver', async () => {
  const conn = await dial(address, { signal: AbortSignal.timeout(10000) })
  const meta = JSON.parse((await exchange(conn, 'GET', '/metadata.json')).body)
  assert.equal(meta.protocol, 'nox-kps-http/1')
  assert.ok(meta.capabilities.includes('worker-bundles'))
  const res = await exchange(conn, 'GET', `/keccak/${bundleHash.slice(0, 2)}/${bundleHash.slice(2)}`)
  assert.equal(res.status, 200)
  assert.equal(res.headers['content-type'], 'text/javascript')
  assert.equal(res.headers['cache-control'], 'public, max-age=31536000, immutable')
  assert.deepEqual(res.body, bundleBytes)
  await conn.close()
})

test('two parallel connections from one client both serve exchanges', async () => {
  const [a, b] = await Promise.all([
    dial(address, { signal: AbortSignal.timeout(10000) }),
    dial(address, { signal: AbortSignal.timeout(10000) }),
  ])
  const [ra, rb] = await Promise.all([exchange(a, 'GET', '/health'), exchange(b, 'GET', '/health')])
  assert.deepEqual([ra.status, rb.status], [200, 200])
  await Promise.all([a.close(), b.close()])
})

test('a wrong certhash is refused by the client', async () => {
  const [ip, port] = address.split(':')
  await assert.rejects(dial(`${ip}:${port}:${otherCerthash}`, { signal: AbortSignal.timeout(10000) }))
})

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { EventEmitter } from 'node:events'
import ts from 'typescript'
import { encode } from 'cbor-x'

// Entirely synthetic fixtures. No IDE cache, user account file, or network access.
const project = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const cacheRoot = path.join(project, 'node_modules', '.cache')
await fs.mkdir(cacheRoot, { recursive: true })
const temporary = await fs.mkdtemp(path.join(cacheRoot, 'kiro-web-test-'))
const require = createRequire(import.meta.url)
for (const name of ['kiroWebCredentials', 'kiroWebBrowserLauncher', 'kiroWebBrowser']) {
  const source = await fs.readFile(path.join(project, 'src/main', `${name}.ts`), 'utf8')
  const output = ts.transpileModule(source, { compilerOptions: {
    module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true
  } }).outputText
  await fs.writeFile(path.join(temporary, `${name}.js`), output)
}
const { KiroWebCredentialCoordinator, mergeCredentialSnapshots, tokenHash, REFRESH_UNCERTAIN_ERROR, WebLoginError } = require(path.join(temporary, 'kiroWebCredentials.js'))
const { KiroWebBrowser, csrfFromHtml } = require(path.join(temporary, 'kiroWebBrowser.js'))
const { chromeArguments } = require(path.join(temporary, 'kiroWebBrowserLauncher.js'))
const key = randomBytes(32)
const protect = text => {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv)
  const bytes = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()])
  return Buffer.concat([iv, cipher.getAuthTag(), bytes])
}
const unprotect = bytes => {
  const cipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12))
  cipher.setAuthTag(bytes.subarray(12, 28))
  return Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]).toString('utf8')
}
let nextFixture = 0
const fixture = async (options = {}) => {
  const directory = path.join(temporary, `fixture-${++nextFixture}`)
  const provider = options.provider || 'Github'
  const account = { id: 'fixture-account', email: 'fixture@example.test', userId: 'fixture-user', idp: provider,
    credentials: { provider, authMethod: 'social', refreshToken: 'fixture-rt-0', accessToken: 'fixture-manager-at', expiresAt: 9000 } }
  const state = { account, commits: [], failCommit: false }
  const dependencies = { directory: path.join(directory, 'credentials'), accounts: () => [state.account], encrypt: protect, decrypt: unprotect,
    beforeWebRefresh: options.guard || (async () => {}),
    commit: async (snapshot, head) => {
      if (state.failCommit) throw Error('fixture disk unavailable')
      assert.equal(snapshot.credentials.refreshToken, state.account.credentials.refreshToken)
      state.commits.push({ ...head })
      state.account = { ...state.account, credentials: { ...state.account.credentials,
        refreshToken: head.refreshToken, accessToken: head.accessToken, expiresAt: head.expiresAt, credentialRevision: head.revision } }
    } }
  return { directory, state, dependencies, coordinator: new KiroWebCredentialCoordinator(dependencies) }
}

for (const provider of ['Github', 'Google']) test(`${provider}: Web and manager serialize the same lineage and never reuse the pre-rotation RT`, async () => {
  const f = await fixture({ provider })
  let active = 0
  const web = f.coordinator.webRefresh('fixture-account', async token => {
    assert.equal(++active, 1); assert.equal(token, 'fixture-rt-0')
    await new Promise(resolve => setTimeout(resolve, 15)); active--
    return { success: true, accessToken: 'fixture-web-at', refreshToken: 'fixture-rt-1', expiresIn: 3600 }
  })
  const manager = f.coordinator.managerRefresh('fixture-rt-0', async token => {
    assert.equal(++active, 1); assert.equal(token, 'fixture-rt-1'); active--
    return { success: true, accessToken: 'fixture-manager-at-2', refreshToken: 'fixture-rt-2', expiresIn: 3600 }
  })
  await Promise.all([web, manager])
  assert.equal(f.state.commits[0].accessToken, 'fixture-manager-at', 'Web AT must not replace the manager/IDE AT')
  assert.equal(f.state.account.credentials.refreshToken, 'fixture-rt-2')
  assert.equal(f.state.account.credentials.accessToken, 'fixture-manager-at-2')
})

test('concurrent manager requests share one refresh task', async () => {
  const f = await fixture(); let calls = 0
  const run = async () => { calls++; await new Promise(resolve => setTimeout(resolve, 15)); return { success: true, accessToken: 'fixture-at-new' } }
  const values = await Promise.all([f.coordinator.managerRefresh('fixture-rt-0', run), f.coordinator.managerRefresh('fixture-rt-0', run)])
  assert.equal(calls, 1); assert.deepEqual(values[0], values[1])
})

test('durable rotated credentials recover after a store commit failure', async () => {
  const f = await fixture(); f.state.failCommit = true
  await assert.rejects(f.coordinator.webRefresh('fixture-account', async () => ({ success: true, accessToken: 'fixture-web-new', refreshToken: 'fixture-rt-1' })))
  const bytes = await fs.readFile(path.join(f.dependencies.directory, `${tokenHash('fixture-account')}.enc`))
  assert.equal(bytes.includes(Buffer.from('fixture-rt-1')), false)
  assert.equal(JSON.parse(unprotect(bytes)).refreshToken, 'fixture-rt-1')
  f.state.failCommit = false
  const restarted = new KiroWebCredentialCoordinator(f.dependencies)
  await restarted.webRefresh('fixture-account', async latest => {
    assert.equal(latest, 'fixture-rt-1')
    return { success: true, accessToken: 'fixture-web-newer' }
  })
  assert.equal(f.state.account.credentials.refreshToken, 'fixture-rt-1')
})

test('ambiguous refresh remains blocked after restart; explicit new credentials permit recovery', async () => {
  const f = await fixture()
  await f.coordinator.webRefresh('fixture-account', async () => ({ success: false, error: REFRESH_UNCERTAIN_ERROR }))
  let calls = 0
  const restarted = new KiroWebCredentialCoordinator(f.dependencies)
  await assert.rejects(restarted.webRefresh('fixture-account', async () => { calls++; return { success: false } }))
  assert.equal(calls, 0)
  f.state.account.credentials.refreshToken = 'fixture-fresh-login-rt'
  await restarted.webRefresh('fixture-account', async latest => {
    calls++; assert.equal(latest, 'fixture-fresh-login-rt'); return { success: true, accessToken: 'fixture-at' }
  })
  assert.equal(calls, 1)
})

test('corrupt recovery and IDE guard fail before consuming a token', async () => {
  const f = await fixture({ guard: async () => { throw new WebLoginError('fixture IDE is active') } })
  let called = false
  await assert.rejects(f.coordinator.webRefresh('fixture-account', async () => { called = true; return { success: false } }))
  assert.equal(called, false)
  await fs.mkdir(f.dependencies.directory, { recursive: true })
  await fs.writeFile(path.join(f.dependencies.directory, `${tokenHash('fixture-account')}.enc`), 'corrupt fixture')
  const restarted = new KiroWebCredentialCoordinator(f.dependencies)
  await assert.rejects(restarted.webRefresh('fixture-account', async () => { called = true; return { success: false } }))
  assert.equal(called, false)
})

test('delayed renderer saves preserve newer credentials while retaining account edits', () => {
  const saved = { accounts: { a: { id: 'a', credentials: { accessToken: 'fixture-new-at', refreshToken: 'fixture-new-rt', credentialRevision: 4, expiresAt: 4000 } } } }
  const incoming = { accounts: { a: { id: 'a', nickname: 'new nickname', credentials: { accessToken: 'fixture-old-at', refreshToken: 'fixture-old-rt', credentialRevision: 3, expiresAt: 1000 } } } }
  const merged = mergeCredentialSnapshots(incoming, saved)
  assert.equal(merged.accounts.a.nickname, 'new nickname')
  assert.deepEqual(merged.accounts.a.credentials, saved.accounts.a.credentials)
})

test('CSRF extraction handles actual meta attribute variants; launch args isolate profiles', () => {
  assert.equal(csrfFromHtml('<meta content="fixture-content" name="csrf-token">'), 'fixture-content')
  assert.equal(csrfFromHtml("<meta name='csrf-token' value='fixture-value' content='other'>"), 'fixture-value')
  assert.equal(csrfFromHtml('<meta name="user-status" content="anonymous">'), undefined)
  const args = chromeArguments('C:\\fixture profiles\\account', 32345)
  assert.ok(args.includes('--user-data-dir=C:\\fixture profiles\\account'))
  assert.ok(args.includes('--remote-debugging-address=127.0.0.1'))
  assert.equal(args.some(arg => arg.includes('RefreshToken')), false)
  assert.throws(() => chromeArguments('C:\\fixture', 32345, 'http://user:secret@localhost:8123'))
  assert.throws(() => chromeArguments('C:\\fixture', 0))
})

function fakeBrowser(f, options = {}) {
  const profiles = new Map(), launches = [], routes = new Map(), pages = []
  const server = { rt: 'fixture-rt-0', refreshCalls: 0, mismatch: false, closeCalls: 0 }
  const response = (status, data) => ({ status: () => status, ok: () => status >= 200 && status < 300,
    body: async () => Buffer.from(encode(data)), text: async () => String(data) })
  const launcher = async profile => {
    launches.push(profile)
    if (options.waitLaunch) await options.waitLaunch
    const jar = new Map(profiles.get(profile) || [])
    const browser = new EventEmitter()
    const page = { urls: [], focuses: 0, goto: async url => { page.urls.push(url) }, bringToFront: async () => { page.focuses++ },
      evaluate: async (_fn, request) => {
        if (request.path.endsWith('/RefreshToken')) server.internalNonce = request.nonce
        const headers = { 'smithy-protocol': 'rpc-v2-cbor', 'X-CSRF-Token': request.csrf }
        const result = request.body ? await context.request.post(request.path, { headers }) : await context.request.get(request.path)
        return { status: result.status(), bytes: [...(request.body ? await result.body() : Buffer.from(await result.text()))] }
      } }
    pages.push(page)
    const context = { addCookies: async cookies => { for (const c of cookies) jar.set(c.name, { domain: 'app.kiro.dev', path: '/', ...c }) },
      cookies: async () => [...jar.values()].map(c => ({ ...c })),
      clearCookies: async filter => { if (!filter) jar.clear(); else jar.delete(filter.name) },
      route: async (url, handler) => { routes.set(url, handler) },
      addInitScript: async () => {},
      newCDPSession: async () => ({ send: async () => {}, detach: async () => {} }), request: {
        dispose: async () => {},
        get: async () => {
          const at = jar.get('AccessToken')?.value
          if (at?.startsWith('fixture-web-at-')) jar.set('UserId', { name: 'UserId', value: 'fixture-user', domain: 'app.kiro.dev', path: '/' })
          return response(200, at ? '<meta name="csrf-token" value="fixture-page-csrf">' : '<meta name="user-status" value="anonymous">')
        },
        post: async (url, request) => {
          assert.equal(request.headers['smithy-protocol'], 'rpc-v2-cbor')
          if (url.endsWith('/RefreshToken')) {
            server.refreshCalls++
            assert.equal(jar.get('RefreshToken')?.value, server.rt)
            assert.equal(jar.get('Idp')?.value, f.state.account.credentials.provider)
            assert.equal(request.headers['X-CSRF-Token'], 'fixture-page-csrf')
            assert.equal(request.headers.Authorization, undefined)
            server.rt = `fixture-rt-${server.refreshCalls}`
            jar.set('RefreshToken', { name: 'RefreshToken', value: server.rt, domain: 'app.kiro.dev', path: '/' })
            jar.set('AccessToken', { name: 'AccessToken', value: `fixture-web-at-${server.refreshCalls}`, domain: 'app.kiro.dev', path: '/' })
            return response(200, { accessToken: `fixture-web-at-${server.refreshCalls}`, csrfToken: 'fixture-new-csrf', expiresIn: 3600 })
          }
          return response(200, { status: 'Active', idp: server.providerOverride || f.state.account.credentials.provider, email: 'fixture@example.test', userId: server.mismatch ? 'fixture-other-user' : 'fixture-user' })
        }
      } }
    return { context, page, browser, pid: 1, close: async () => { server.closeCalls++; profiles.set(profile, [...jar.entries()]); browser.emit('disconnected') } }
  }
  const web = new KiroWebBrowser({ directory: path.join(f.directory, 'web'), account: id => id === f.state.account.id ? f.state.account : undefined,
    coordinator: f.coordinator, encrypt: protect, decrypt: unprotect, proxy: () => undefined, launcher })
  return { web, server, launches, routes, profiles, pages }
}

for (const provider of ['Github', 'Google']) test(`${provider}: Web bootstrap rotates shared RT, preserves manager AT, reuses window and persists encrypted identity`, async () => {
  const f = await fixture({ provider }), mock = fakeBrowser(f)
  const result = await mock.web.open('fixture-account')
  assert.equal(result.success, true)
  assert.equal(f.state.account.credentials.refreshToken, 'fixture-rt-1')
  assert.equal(f.state.account.credentials.accessToken, 'fixture-manager-at')
  assert.equal((await mock.web.open('fixture-account')).reused, true)
  assert.equal(mock.launches.length, 1)
  const interceptor = mock.routes.get('https://app.kiro.dev/service/KiroWebPortalService/operation/RefreshToken')
  const returned = []
  const route = () => ({ request: () => ({ method: () => 'POST', headers: () => ({}), frame: () => ({ url: () => 'https://app.kiro.dev/home', page: () => mock.pages[0] }) }),
    fulfill: async value => returned.push(value) })
  await Promise.all([interceptor(route()), interceptor(route())])
  assert.equal(mock.server.refreshCalls, 2, 'automatic concurrent refreshes share a single task')
  assert.equal(returned.length, 2); assert.ok(returned.every(r => r.status === 200))
  assert.equal(f.state.account.credentials.refreshToken, 'fixture-rt-2')
  const bindingFile = path.join(f.directory, 'web/state', `${tokenHash('fixture-account')}.binding.enc`)
  const binding = await fs.readFile(bindingFile)
  assert.equal(binding.includes(Buffer.from('fixture-user')), false)
  assert.equal(JSON.parse(unprotect(binding)).userId, 'fixture-user')
  assert.equal(JSON.parse(unprotect(binding)).provider, provider)
  await mock.web.shutdown()
  assert.equal(mock.server.closeCalls, 1, 'synchronous disconnect must not reenter close')
})

test('Google identity cannot be accepted as Github and unsupported providers cannot launch', async () => {
  const f = await fixture({ provider: 'Google' }), mock = fakeBrowser(f)
  mock.server.providerOverride = 'Github'
  const result = await mock.web.open('fixture-account')
  assert.equal(result.success, false)
  assert.match(result.error, /身份校验失败/)
  assert.equal(f.state.account.credentials.refreshToken, 'fixture-rt-0')
  await mock.web.shutdown()
  const other = await fixture({ provider: 'BuilderId' }), blocked = fakeBrowser(other)
  assert.equal((await blocked.web.open('fixture-account')).success, false)
  assert.equal(blocked.launches.length, 0)
  await blocked.web.shutdown()
})

test('double click shares startup; separate profile IDs remain path-safe', async () => {
  const f = await fixture(); let release
  const mock = fakeBrowser(f, { waitLaunch: new Promise(resolve => { release = resolve }) })
  const first = mock.web.open('fixture-account'), second = mock.web.open('fixture-account')
  release()
  assert.equal((await first).success, true); assert.equal((await second).reused, true)
  assert.equal(mock.launches.length, 1)
  assert.equal(path.basename(mock.launches[0]), tokenHash('fixture-account'))
  assert.notEqual(tokenHash('fixture-account'), tokenHash('another-account'))
  await mock.web.shutdown()
})

test('refresh interceptor rejects foreign frames and removes its private marker', async () => {
  const f = await fixture(), mock = fakeBrowser(f)
  assert.equal((await mock.web.open('fixture-account')).success, true)
  const intercept = mock.routes.get('https://app.kiro.dev/service/KiroWebPortalService/operation/RefreshToken')
  let aborted = 0, continued
  const base = { abort: async () => { aborted++ }, continue: async value => { continued = value },
    fulfill: async () => assert.fail('request must not be fulfilled') }
  await intercept({ ...base, request: () => ({ method: () => 'POST', headers: () => ({}),
    frame: () => ({ url: () => 'https://untrusted.example.test/' }) }) })
  assert.equal(aborted, 1)
  await intercept({ ...base, request: () => ({ method: () => 'POST',
    headers: () => ({ 'x-kiro-manager-internal': mock.server.internalNonce, accept: 'application/cbor' }),
    frame: () => ({ url: () => 'https://app.kiro.dev/home' }) }) })
  assert.deepEqual(continued.headers, { accept: 'application/cbor' })
  assert.equal(mock.server.refreshCalls, 1)
  await mock.web.shutdown()
})

test('identity mismatch never opens home and preserves rotated credentials for recovery', async () => {
  const f = await fixture(), mock = fakeBrowser(f)
  mock.server.mismatch = true
  const result = await mock.web.open('fixture-account')
  assert.equal(result.success, false); assert.match(result.error, /身份校验失败/)
  assert.equal(f.state.account.credentials.refreshToken, 'fixture-rt-0')
  const recovery = JSON.parse(unprotect(await fs.readFile(path.join(f.directory, 'web/state', `${tokenHash('fixture-account')}.recovery.enc`))))
  assert.equal(recovery.cookies.find(c => c.name === 'RefreshToken').value, 'fixture-rt-1')
  assert.equal((await mock.web.open('missing')).success, false)
  await mock.web.shutdown()
})

test('running-IDE guard is surfaced without sending a refresh or leaking raw errors', async () => {
  const f = await fixture({ guard: async () => { throw new WebLoginError('fixture IDE is active') } }), mock = fakeBrowser(f)
  const result = await mock.web.open('fixture-account')
  assert.equal(result.success, false); assert.match(result.error, /fixture IDE is active/)
  assert.equal(mock.server.refreshCalls, 0)
  await mock.web.shutdown()
})

test.after(async () => {
  const absolute = path.resolve(temporary)
  assert.ok(absolute.startsWith(path.resolve(cacheRoot) + path.sep))
  assert.ok(path.basename(absolute).startsWith('kiro-web-test-'))
  await fs.rm(absolute, { recursive: true, force: true })
})

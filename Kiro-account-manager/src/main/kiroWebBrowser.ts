import { encode, decode } from 'cbor-x'
import { readFile, mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import type { BrowserContext, Page } from 'playwright-core'
import { launchKiroChrome, type ChromeRun } from './kiroWebBrowserLauncher'
import { atomicPrivateWrite, tokenHash, WebLoginError, type WebAccount, type KiroWebCredentialCoordinator, type TokenRefreshResult } from './kiroWebCredentials'

const ORIGIN = 'https://app.kiro.dev'
const RPC = `${ORIGIN}/service/KiroWebPortalService/operation/`
const BOOTSTRAP_AT = 'kiro-account-manager-web-bootstrap'
const AUTH_NAMES = /^(AccessToken|RefreshToken|Idp|UserId|SessionToken)$/

export interface OpenKiroWebResult { success: boolean; reused?: boolean; error?: string }
interface Binding { userId: string; sourceHash: string; provider: string }
interface PortalResult extends TokenRefreshResult { csrfToken?: string; data?: Record<string, unknown> }
interface WebSession {
  accountId: string
  run?: ChromeRun
  ready: Promise<OpenKiroWebResult>
  binding?: Binding
  refresh?: Promise<PortalResult>
  closing?: Promise<void>
  internalNonce: string
}
interface PortalResponse { status: number; bytes: number[] }

export interface KiroWebBrowserDependencies {
  directory: string
  account: (id: string) => WebAccount | undefined
  coordinator: KiroWebCredentialCoordinator
  encrypt: (text: string) => Buffer
  decrypt: (data: Buffer) => string
  proxy: (id: string) => string | undefined
  launcher?: (profile: string, proxy?: string, signal?: AbortSignal) => Promise<ChromeRun>
}

function attribute(tag: string, name: string): string | undefined {
  const value = new RegExp(`\\b${name}\\s*=\\s*(["'])(.*?)\\1`, 'i').exec(tag)?.[2]
  return value?.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&')
}

export function csrfFromHtml(html: string): string | undefined {
  for (const tag of html.match(/<meta\b[^>]*>/gi) || []) {
    if (attribute(tag, 'name') === 'csrf-token') return attribute(tag, 'value') ?? attribute(tag, 'content')
  }
  return undefined
}

function portalError(status: number, data: Record<string, unknown>): string {
  // Never return raw upstream messages, headers, bodies, URLs, or cookie values.
  const type = String(data.__type || '').split('#').pop()
  if (type === 'AccountSuspendedException') return '该账号暂不可使用 Kiro Web，请按官方流程处理账号状态'
  if (status === 401 || status === 403) return 'Kiro Web 拒绝了当前凭据，请重新授权该账号'
  if (status === 429) return 'Kiro Web 请求过于频繁，请稍后重试'
  return `Kiro Web 请求失败（HTTP ${status}）`
}

function decodedResponse(response: PortalResponse): Record<string, unknown> {
  const bytes = Buffer.from(response.bytes)
  if (bytes.byteLength > 1024 * 1024) throw new WebLoginError('Kiro Web 返回了异常大小的响应')
  try { return decode(bytes) as Record<string, unknown> } catch { throw new WebLoginError('无法解析 Kiro Web 响应') }
}

/** Account-scoped persistent Chrome windows. No token crosses the renderer IPC. */
export class KiroWebBrowser {
  private sessions = new Map<string, WebSession>()
  private stop = new AbortController()
  constructor(private deps: KiroWebBrowserDependencies) {}

  private filename(id: string, suffix: string): string { return join(this.deps.directory, 'state', `${tokenHash(id)}.${suffix}.enc`) }
  private async save(id: string, suffix: string, value: unknown): Promise<void> {
    await mkdir(join(this.deps.directory, 'state'), { recursive: true })
    await atomicPrivateWrite(this.filename(id, suffix), this.deps.encrypt(JSON.stringify(value)))
  }
  private async binding(account: WebAccount): Promise<Binding | undefined> {
    try {
      const value = JSON.parse(this.deps.decrypt(await readFile(this.filename(account.id, 'binding')))) as Binding
      if (value.provider === 'Github' && await this.deps.coordinator.sameLineage(account.id, value.sourceHash)) return value
      return undefined
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
      throw new WebLoginError('无法读取该账号的加密网页资料，请先检查恢复记录')
    }
  }

  async open(accountId: string): Promise<OpenKiroWebResult> {
    if (this.stop.signal.aborted) return { success: false, error: '应用正在退出' }
    const account = this.deps.account(accountId)
    if (!account) return { success: false, error: '账号不存在' }
    if ((account.credentials.provider || account.idp) !== 'Github') {
      return { success: false, error: '当前版本仅支持已验证的 GitHub 账号网页登录' }
    }
    if (!account.credentials.refreshToken) return { success: false, error: '该账号缺少 Refresh Token' }
    const existing = this.sessions.get(accountId)
    if (existing) {
      const result = await existing.ready
      if (!result.success) return result
      if (existing.closing || !existing.run) return { success: false, error: '该账号浏览器正在关闭，请稍后重试' }
      if (existing.binding && !await this.deps.coordinator.sameLineage(accountId, existing.binding.sourceHash)) {
        await this.close(existing)
        return this.open(accountId)
      }
      try { await existing.run.page.bringToFront(); return { success: true, reused: true } } catch {
        return { success: false, error: '该账号浏览器已断开，请关闭窗口后重试' }
      }
    }
    // Publish the placeholder before launching, so double clicks share this task.
    const session: WebSession = { accountId, internalNonce: randomUUID(), ready: Promise.resolve({ success: false }) }
    this.sessions.set(accountId, session)
    session.ready = this.start(session, account).catch(async error => {
      try { await this.close(session) } catch { /* retain failed-close ownership */ }
      return { success: false, error: error instanceof WebLoginError ? error.message : '无法打开 Kiro Web，请检查 Chrome、网络或账号代理' }
    })
    return session.ready
  }

  private async start(session: WebSession, account: WebAccount): Promise<OpenKiroWebResult> {
    const profile = join(this.deps.directory, 'profiles', tokenHash(account.id))
    session.run = await (this.deps.launcher || launchKiroChrome)(profile, this.deps.proxy(account.id), this.stop.signal)
    if (this.stop.signal.aborted) throw new WebLoginError('应用正在退出')
    const { context, browser, page } = session.run
    browser.on('disconnected', () => { if (!session.closing) void this.close(session).catch(() => {}) })
    await context.route(`${RPC}RefreshToken`, async route => {
      try {
        if (route.request().method() !== 'POST' || new URL(route.request().frame().url()).origin !== ORIGIN) {
          await route.abort()
          return
        }
        const headers = route.request().headers()
        if (headers['x-kiro-manager-internal'] === session.internalNonce) {
          delete headers['x-kiro-manager-internal']
          await route.continue({ headers })
          return
        }
        const result = await this.refresh(session, route.request().frame().page())
        await route.fulfill({ status: result.success ? 200 : 401, contentType: 'application/cbor',
          body: Buffer.from(encode(result.success ? result.data : { __type: 'UnauthorizedException', message: result.error })) })
      } catch {
        await route.fulfill({ status: 401, contentType: 'application/cbor',
          body: Buffer.from(encode({ __type: 'UnauthorizedException', message: '网页续期已停止，请从管理器重新打开' })) }).catch(() => {})
      }
    })
    // A Web sign-out clears this profile only; it must not revoke a shared IDE RT.
    await context.route(`${RPC}Logout`, async route => {
      if (route.request().method() !== 'POST' || new URL(route.request().frame().url()).origin !== ORIGIN) {
        await route.abort()
        return
      }
      await this.clearAuth(context)
      await route.fulfill({ status: 200, contentType: 'application/cbor', body: Buffer.from(encode({})) })
    })
    // Start on an inert same-origin document. Bootstrap and RPC requests then use
    // Chrome's own networking/proxy/cookie jar, not a separate Node HTTP stack.
    const cdp = await context.newCDPSession(page)
    await cdp.send('Emulation.setScriptExecutionDisabled', { value: true })
    await cdp.send('Storage.clearDataForOrigin', { origin: ORIGIN, storageTypes: 'service_workers' })
    await context.addInitScript(() => {
      if (location.origin === 'https://app.kiro.dev' && navigator.serviceWorker) {
        navigator.serviceWorker.register = () => Promise.reject(new Error('Service workers are disabled in this managed profile'))
      }
    })
    await page.goto(`${ORIGIN}/signin`, { waitUntil: 'domcontentloaded', timeout: 15_000 })
    session.binding = await this.binding(account)
    let reused = false
    if (session.binding) {
      const csrf = await this.bootstrap(session, page)
      if (csrf) {
        const info = await this.userInfo(session, page, csrf)
        reused = info.status === 'Active' && info.userId === session.binding.userId && info.idp === 'Github'
      }
    }
    await cdp.send('Emulation.setScriptExecutionDisabled', { value: false })
    await cdp.detach()
    if (!reused) {
      await this.clearAuth(context)
      await context.addCookies([{ name: 'AccessToken', value: BOOTSTRAP_AT, url: ORIGIN,
        httpOnly: true, secure: true, sameSite: 'Lax' }])
      const result = await this.refresh(session)
      if (!result.success) throw new WebLoginError(result.error || 'Kiro Web 登录失败')
    }
    await page.goto(`${ORIGIN}/home`, { waitUntil: 'domcontentloaded', timeout: 15_000 })
    await page.bringToFront()
    return { success: true, reused }
  }

  private async clearAuth(context: BrowserContext): Promise<void> {
    for (const cookie of await context.cookies(ORIGIN)) {
      if (AUTH_NAMES.test(cookie.name)) await context.clearCookies({ name: cookie.name, domain: cookie.domain, path: cookie.path })
    }
  }

  private async browserRequest(session: WebSession, host: Page, path: string, csrf?: string, body?: Record<string, unknown>): Promise<PortalResponse> {
    return host.evaluate(async request => {
      if (location.origin !== 'https://app.kiro.dev') throw new Error('Managed authentication page is no longer on Kiro')
      const headers: Record<string, string> = { accept: request.body ? 'application/cbor' : 'text/html' }
      if (request.body) {
        headers['content-type'] = 'application/cbor'
        headers['smithy-protocol'] = 'rpc-v2-cbor'
      }
      if (request.csrf) headers['X-CSRF-Token'] = request.csrf
      if (request.nonce) headers['X-Kiro-Manager-Internal'] = request.nonce
      const response = await fetch(request.path, { method: request.body ? 'POST' : 'GET',
        credentials: 'same-origin', redirect: 'error', signal: AbortSignal.timeout(10_000), headers,
        body: request.body ? new Uint8Array(request.body) : undefined })
      return { status: response.status, bytes: [...new Uint8Array(await response.arrayBuffer())] }
    }, { path, csrf, body: body ? [...Buffer.from(encode(body))] : undefined,
      nonce: path.endsWith('/RefreshToken') ? session.internalNonce : undefined })
  }

  private async bootstrap(session: WebSession, host: Page): Promise<string | undefined> {
    const response = await this.browserRequest(session, host, '/')
    if (response.status !== 200) throw new WebLoginError('Kiro Web 主页不可用，请检查网络或账号代理')
    return csrfFromHtml(Buffer.from(response.bytes).toString('utf8'))
  }

  private async userInfo(session: WebSession, host: Page, csrf: string): Promise<Record<string, unknown>> {
    const response = await this.browserRequest(session, host, `${RPC}GetUserInfo`, csrf, { origin: 'KIRO_IDE' })
    return response.status === 200 ? decodedResponse(response) : {}
  }

  private refresh(session: WebSession, host = session.run!.page): Promise<PortalResult> {
    if (session.refresh) return session.refresh
    const task = this.deps.coordinator.webRefresh(session.accountId, latest => this.performRefresh(session, host, latest))
    session.refresh = task
    void task.finally(() => { if (session.refresh === task) session.refresh = undefined }).catch(() => {})
    return task
  }

  private async performRefresh(session: WebSession, host: Page, latest: string): Promise<PortalResult> {
    const context = session.run!.context
    const current = this.deps.account(session.accountId)
    if (!current) throw new WebLoginError('账号已删除')
    await context.addCookies([
      { name: 'RefreshToken', value: latest, url: ORIGIN, httpOnly: true, secure: true, sameSite: 'Lax' },
      { name: 'Idp', value: 'Github', url: ORIGIN, httpOnly: true, secure: true, sameSite: 'Lax' }
    ])
    if (!(await context.cookies(ORIGIN)).some(c => c.name === 'AccessToken')) {
      await context.addCookies([{ name: 'AccessToken', value: BOOTSTRAP_AT, url: ORIGIN,
        httpOnly: true, secure: true, sameSite: 'Lax' }])
    }
    // Always derive CSRF after the latest RT and Idp have been installed. Keep
    // any UserId cookie issued by the server; deleting it can invalidate CSRF.
    const csrf = await this.bootstrap(session, host)
    if (!csrf) return { success: false, error: 'Kiro Web 未提供 CSRF，认证流程可能已变化' }
    const response = await this.browserRequest(session, host, `${RPC}RefreshToken`, csrf, {})
    const cookies = await context.cookies(ORIGIN)
    const refreshToken = cookies.find(c => c.name === 'RefreshToken')?.value || latest
    // Even a malformed body or a failing follow-up must not lose a rotated RT.
    if (response.status === 200 || refreshToken !== latest) {
      await this.save(session.accountId, 'recovery', { cookies, sourceHash: tokenHash(latest), status: response.status })
    }
    const data = decodedResponse(response)
    if (response.status !== 200) {
      if (refreshToken !== latest) throw new WebLoginError('异常刷新响应包含新凭据，已保留恢复记录并停止续期')
      return { success: false, error: portalError(response.status, data) }
    }
    // Durable, protected recovery BEFORE further verification can fail.
    await this.save(session.accountId, 'recovery', { data, cookies, sourceHash: tokenHash(latest) })
    if (typeof data.accessToken !== 'string' || !data.accessToken || typeof data.csrfToken !== 'string' || !data.csrfToken) {
      throw new WebLoginError('Kiro Web 刷新响应不完整，已保留恢复记录')
    }
    const info = await this.userInfo(session, host, data.csrfToken)
    if (info.status !== 'Active' || info.idp !== 'Github' || typeof info.userId !== 'string' ||
      (current.userId && info.userId !== current.userId) ||
      (session.binding && info.userId !== session.binding.userId) ||
      (!current.userId && current.email && String(info.email || '').toLowerCase() !== current.email.toLowerCase())) {
      throw new WebLoginError('网页账号身份校验失败，已停止登录并保留恢复记录')
    }
    session.binding = { userId: info.userId, sourceHash: tokenHash(refreshToken), provider: 'Github' }
    await this.save(session.accountId, 'binding', session.binding)
    return { success: true, accessToken: data.accessToken, refreshToken,
      csrfToken: data.csrfToken, expiresIn: typeof data.expiresIn === 'number' ? data.expiresIn : 3600, data }
  }

  private close(session: WebSession): Promise<void> {
    if (session.closing) return session.closing
    // Publish the close promise before a synchronous disconnected event can reenter.
    session.closing = Promise.resolve().then(async () => {
      if (session.run) {
        await session.run.close()
      }
      if (this.sessions.get(session.accountId) === session) this.sessions.delete(session.accountId)
    })
    return session.closing
  }

  async shutdown(): Promise<void> {
    this.stop.abort()
    await Promise.allSettled([...this.sessions.values()].map(async session => {
      if (!session.run) await session.ready
      await this.close(session)
    }))
  }
}

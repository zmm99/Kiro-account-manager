import { createHash, randomUUID } from 'node:crypto'
import * as fs from 'node:fs/promises'
import { join } from 'node:path'

export interface WebAccount {
  id: string
  email?: string
  userId?: string
  idp?: string
  credentials: {
    refreshToken?: string
    accessToken?: string
    expiresAt?: number
    provider?: string
    authMethod?: string
    credentialRevision?: number
    [key: string]: unknown
  }
}

export interface TokenRefreshResult {
  success: boolean
  refreshToken?: string
  accessToken?: string
  expiresIn?: number
  error?: string
}

interface CredentialHead {
  accountId: string
  provider: string
  refreshToken: string
  hashes: string[]
  revision: number
  pending: boolean
  accessToken?: string
  expiresAt?: number
}

export interface CredentialDependencies {
  directory: string
  accounts: () => WebAccount[]
  encrypt: (text: string) => Buffer
  decrypt: (data: Buffer) => string
  commit: (account: WebAccount, head: {
    refreshToken: string; revision: number; accessToken?: string; expiresAt?: number
  }) => Promise<void>
  beforeWebRefresh: (account: WebAccount, refreshToken: string) => Promise<void>
}

export const tokenHash = (value: string): string => createHash('sha256').update(value).digest('hex')
export class WebLoginError extends Error {}
export const REFRESH_UNCERTAIN_ERROR = '网络中断，刷新结果不确定；请勿重试旧 RT'

/** Same-directory replacement; a truncated credential file is never published. */
export async function atomicPrivateWrite(file: string, data: Buffer | string): Promise<void> {
  const temporary = `${file}.${randomUUID()}.tmp`
  try {
    const handle = await fs.open(temporary, 'wx', 0o600)
    try { await handle.writeFile(data); await handle.sync() } finally { await handle.close() }
    await fs.rename(temporary, file)
  } finally {
    await fs.unlink(temporary).catch(() => {})
  }
}

/**
 * One lease per credential lineage, shared by manager and intercepted Web refreshes.
 * A protected pending journal is written BEFORE the request. After an ambiguous
 * transport/crash, old RTs are not automatically replayed.
 */
export class KiroWebCredentialCoordinator {
  private tails = new Map<string, Promise<void>>()
  private heads = new Map<string, CredentialHead>()
  private blocked = new Set<string>()
  private managerTasks = new Map<string, Promise<TokenRefreshResult>>()
  constructor(private deps: CredentialDependencies) {}

  private filename(id: string): string { return join(this.deps.directory, `${tokenHash(id)}.enc`) }
  private provider(account: WebAccount): string { return account.credentials.provider || account.idp || '' }

  private async readHead(account: WebAccount): Promise<CredentialHead | undefined> {
    let head = this.heads.get(account.id)
    if (!head) {
      try {
        const bytes = await fs.readFile(this.filename(account.id))
        head = JSON.parse(this.deps.decrypt(bytes)) as CredentialHead
        if (head.accountId !== account.id || !Array.isArray(head.hashes) || typeof head.refreshToken !== 'string') {
          throw new WebLoginError('Invalid credential journal')
        }
        this.heads.set(account.id, head)
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
          throw new WebLoginError('无法读取加密凭据恢复记录，请先恢复凭据，勿重复刷新')
        }
      }
    }
    if (head && (head.provider !== this.provider(account) ||
      !head.hashes.includes(tokenHash(account.credentials.refreshToken || '')))) return undefined
    return head
  }

  private async writeHead(head: CredentialHead): Promise<void> {
    await fs.mkdir(this.deps.directory, { recursive: true })
    // Encryption has no plaintext fallback.
    await atomicPrivateWrite(this.filename(head.accountId), this.deps.encrypt(JSON.stringify(head)))
    this.heads.set(head.accountId, head)
  }

  private async lock<T>(key: string, action: () => Promise<T>): Promise<T> {
    const previous = this.tails.get(key) || Promise.resolve()
    let release!: () => void
    const gate = new Promise<void>(resolve => { release = resolve })
    const tail = previous.then(() => gate)
    this.tails.set(key, tail)
    await previous
    try { return await action() } finally {
      release()
      if (this.tails.get(key) === tail) this.tails.delete(key)
    }
  }

  private async findAccount(token: string): Promise<WebAccount | undefined> {
    const hash = tokenHash(token)
    for (const account of this.deps.accounts()) {
      if (account.credentials.refreshToken === token) return account
      const head = await this.readHead(account)
      if (head?.hashes.includes(hash)) return account
    }
    return undefined
  }

  async managerRefresh<T extends TokenRefreshResult>(token: string, run: (latest: string) => Promise<T>): Promise<T> {
    const account = await this.findAccount(token)
    if (!account || this.provider(account) !== 'Github') return this.lock(`untracked:${tokenHash(token)}`, () => run(token))
    const existing = this.managerTasks.get(account.id)
    if (existing) return existing as Promise<T>
    const task = this.refresh(account.id, 'manager', run)
    this.managerTasks.set(account.id, task)
    void task.finally(() => { if (this.managerTasks.get(account.id) === task) this.managerTasks.delete(account.id) }).catch(() => {})
    return task
  }

  async sameLineage(id: string, hash: string): Promise<boolean> {
    const account = this.deps.accounts().find(a => a.id === id)
    if (!account?.credentials.refreshToken) return false
    return tokenHash(account.credentials.refreshToken) === hash || !!(await this.readHead(account))?.hashes.includes(hash)
  }

  async webRefresh<T extends TokenRefreshResult>(id: string, run: (latest: string) => Promise<T>): Promise<T> {
    return this.refresh(id, 'web', run)
  }

  private async refresh<T extends TokenRefreshResult>(id: string, kind: 'manager' | 'web', run: (rt: string) => Promise<T>): Promise<T> {
    const selected = this.deps.accounts().find(a => a.id === id)
    if (!selected?.credentials.refreshToken) throw new WebLoginError('账号不存在或缺少 Refresh Token')
    // Duplicate imported rows sharing an RT also share the same lease.
    const canonical = await this.findAccount(selected.credentials.refreshToken)
    return this.lock(canonical?.id || id, async () => {
      const account = this.deps.accounts().find(a => a.id === id)
      if (!account?.credentials.refreshToken) throw new WebLoginError('账号已删除或凭据已变更')
      const previous = await this.readHead(account)
      if (!previous) this.blocked.delete(id) // Explicitly replaced credentials start a new lineage.
      if (this.blocked.has(id) || previous?.pending) {
        throw new WebLoginError('上次刷新结果不确定，已停止复用旧 RT；请恢复凭据或重新授权')
      }
      const currentRt = previous?.refreshToken || account.credentials.refreshToken
      if (kind === 'web') await this.deps.beforeWebRefresh(account, currentRt)
      // Recover a completed durable commit before issuing another request.
      if (previous && (previous.refreshToken !== account.credentials.refreshToken ||
        previous.revision > (account.credentials.credentialRevision || 0))) {
        await this.deps.commit(account, previous)
      }
      const freshAccount = this.deps.accounts().find(a => a.id === id)!
      const pending: CredentialHead = {
        accountId: id, provider: this.provider(account), refreshToken: currentRt,
        hashes: [...new Set([...(previous?.hashes || []), tokenHash(currentRt)])],
        revision: Math.max(previous?.revision || 0, freshAccount.credentials.credentialRevision || 0),
        accessToken: freshAccount.credentials.accessToken, expiresAt: freshAccount.credentials.expiresAt,
        pending: true
      }
      await this.writeHead(pending)
      let result: T
      try { result = await run(currentRt) } catch (error) {
        this.blocked.add(id)
        if (error instanceof WebLoginError) throw error
        throw new WebLoginError('刷新结果不确定，已保留加密恢复记录；不会重试旧 RT')
      }
      if (!result.success || !result.accessToken) {
        if (result.error === REFRESH_UNCERTAIN_ERROR) {
          this.blocked.add(id)
          return result
        }
        await this.writeHead({ ...pending, pending: false })
        return result
      }
      const nextRt = result.refreshToken || currentRt
      const next: CredentialHead = {
        ...pending, refreshToken: nextRt,
        hashes: [...new Set([...pending.hashes, tokenHash(nextRt)])],
        revision: pending.revision + 1, pending: false,
        // Web AT is NOT substituted for the IDE/manager AT.
        accessToken: kind === 'manager' ? result.accessToken : freshAccount.credentials.accessToken,
        expiresAt: kind === 'manager' ? Date.now() + (result.expiresIn || 3600) * 1000 : freshAccount.credentials.expiresAt
      }
      try {
        await this.writeHead(next)
        await this.deps.commit(freshAccount, next)
      } catch {
        this.blocked.add(id)
        throw new WebLoginError('新凭据提交未完成，已停止刷新；请检查加密恢复记录')
      }
      return { ...result, refreshToken: nextRt }
    })
  }
}

let sharedCoordinator: KiroWebCredentialCoordinator | undefined
export function configureKiroWebCredentials(coordinator: KiroWebCredentialCoordinator): void { sharedCoordinator = coordinator }
export async function coordinateManagerRefresh<T extends TokenRefreshResult>(token: string, run: (latest: string) => Promise<T>): Promise<T> {
  return sharedCoordinator ? sharedCoordinator.managerRefresh(token, run) : run(token)
}

/** Protect the authoritative credential revision from delayed renderer snapshots. */
export function mergeCredentialSnapshots<T>(incoming: T, current: T): T {
  const next = incoming as { accounts?: Record<string, WebAccount> }
  const saved = current as { accounts?: Record<string, WebAccount> } | undefined
  if (!next?.accounts || !saved?.accounts) return incoming
  for (const [id, account] of Object.entries(next.accounts)) {
    const newer = saved.accounts[id]?.credentials
    if (newer && account.credentials &&
      (newer.credentialRevision || 0) > (account.credentials.credentialRevision || 0)) {
      account.credentials = { ...account.credentials, accessToken: newer.accessToken,
        refreshToken: newer.refreshToken, expiresAt: newer.expiresAt, credentialRevision: newer.credentialRevision }
    }
  }
  return incoming
}

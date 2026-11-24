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

export function socialWebProvider(account: WebAccount): 'Github' | 'Google' | undefined {
  const provider = account.credentials.provider || account.idp
  return provider === 'Github' || provider === 'Google' ? provider : undefined
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

/** Serialize manager and Web refreshes that share a rotating credential. */
export class KiroWebCredentialCoordinator {
  private tails = new Map<string, Promise<void>>()
  private heads = new Map<string, CredentialHead>()
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
    // Retain the confirmed rotation for the next attempt even if the disk write fails.
    this.heads.set(head.accountId, head)
    await fs.mkdir(this.deps.directory, { recursive: true })
    // Encryption has no plaintext fallback.
    await atomicPrivateWrite(this.filename(head.accountId), this.deps.encrypt(JSON.stringify(head)))
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
    if (!account || !socialWebProvider(account)) return this.lock(`untracked:${tokenHash(token)}`, () => run(token))
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
      let account = this.deps.accounts().find(a => a.id === id)
      if (!account?.credentials.refreshToken) throw new WebLoginError('账号已删除或凭据已变更')
      const previous = await this.readHead(account)
      // Older versions also journaled in-flight attempts. Only a newer revision
      // carries credentials to recover; the legacy pending flag does not affect retries.
      if (previous && previous.revision > (account.credentials.credentialRevision || 0)) {
        await this.deps.commit(account, previous)
        account = this.deps.accounts().find(a => a.id === id)
        if (!account?.credentials.refreshToken) throw new WebLoginError('账号已删除或凭据已变更')
      }
      const currentRt = account.credentials.refreshToken
      if (kind === 'web') await this.deps.beforeWebRefresh(account, currentRt)
      const result = await run(currentRt)
      if (!result.success || !result.accessToken) return result

      const nextRt = result.refreshToken || currentRt
      const next: CredentialHead = {
        accountId: id, provider: this.provider(account), refreshToken: nextRt,
        hashes: [...new Set([...(previous?.hashes || []), tokenHash(currentRt), tokenHash(nextRt)])],
        revision: (account.credentials.credentialRevision || 0) + 1,
        accessToken: kind === 'manager' ? result.accessToken : account.credentials.accessToken,
        expiresAt: kind === 'manager' ? Date.now() + (result.expiresIn || 3600) * 1000 : account.credentials.expiresAt
      }
      try {
        await this.writeHead(next)
        await this.deps.commit(account, next)
      } catch {
        throw new WebLoginError('新凭据保存失败，请检查本地存储后重试')
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

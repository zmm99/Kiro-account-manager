import { spawn, execFile, type ChildProcess } from 'node:child_process'
import { createServer } from 'node:net'
import { access, mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { WebLoginError } from './kiroWebCredentials'
import { chromium, type Browser, type BrowserContext, type Page } from 'playwright-core'

export interface ChromeRun {
  browser: Browser
  context: BrowserContext
  page: Page
  pid: number
  close: () => Promise<void>
}

export function chromeCandidates(env = process.env): string[] {
  return [env.PROGRAMFILES, env['PROGRAMFILES(X86)'], env.LOCALAPPDATA]
    .filter((value): value is string => !!value)
    .map(base => join(base, 'Google', 'Chrome', 'Application', 'chrome.exe'))
}

export function chromeArguments(profile: string, port: number, proxy?: string): string[] {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new WebLoginError('无效的浏览器调试端口')
  const args = [
    `--user-data-dir=${profile}`, '--remote-debugging-address=127.0.0.1',
    `--remote-debugging-port=${port}`, '--no-first-run', '--no-default-browser-check',
    '--disable-session-crashed-bubble', '--hide-crash-restore-bubble', '--disable-background-mode',
    '--no-startup-window', '--start-maximized'
  ]
  if (proxy) {
    const url = new URL(proxy)
    if (url.username || url.password) throw new WebLoginError('网页浏览器暂不支持带用户名密码的账号代理')
    if (!['http:', 'https:', 'socks4:', 'socks5:'].includes(url.protocol)) throw new WebLoginError('账号代理协议不受支持')
    args.push(`--proxy-server=${url.protocol}//${url.host}`)
  }
  // Do not restore authenticated tabs before the refresh coordinator is attached.
  return args
}

async function availablePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as { port: number }).port
      server.close(error => error ? reject(error) : resolve(port))
    })
  })
}

function exited(child: ChildProcess): boolean { return child.exitCode !== null || child.signalCode !== null }

async function waitForExit(child: ChildProcess, milliseconds: number): Promise<boolean> {
  if (exited(child)) return true
  return new Promise(resolve => {
    const onExit = (): void => { clearTimeout(timer); resolve(true) }
    const timer = setTimeout(() => { child.off('exit', onExit); resolve(exited(child)) }, milliseconds)
    child.once('exit', onExit)
  })
}

async function stopOwnedChild(child: ChildProcess): Promise<void> {
  if (exited(child) || !child.pid) return
  await new Promise<void>(resolve => {
    // Only this attempt's recorded PID, never a browser image-name kill.
    execFile('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, timeout: 2000 }, () => resolve())
  })
  if (!await waitForExit(child, 1000)) throw new WebLoginError('浏览器尚未完全关闭，请稍后再试')
}

export async function launchKiroChrome(profile: string, proxy?: string, signal?: AbortSignal): Promise<ChromeRun> {
  if (signal?.aborted) throw new WebLoginError('应用正在退出')
  if (process.platform !== 'win32') throw new WebLoginError('独立 Kiro Web 浏览器目前支持 Windows Chrome')
  let executable: string | undefined
  for (const candidate of chromeCandidates()) {
    try { await access(candidate); executable = candidate; break } catch { /* next installed Chrome */ }
  }
  if (!executable) throw new WebLoginError('未找到 Google Chrome，请先安装 Chrome')
  await mkdir(profile, { recursive: true })
  const port = await availablePort()
  const args = chromeArguments(profile, port, proxy)
  const child = spawn(executable, args, { stdio: 'ignore', windowsHide: false })
  let spawnFailed = false
  child.once('error', () => { spawnFailed = true })
  let browser: Browser | undefined
  try {
    const deadline = Date.now() + 10_000
    let ready = false
    while (Date.now() < deadline && !signal?.aborted && !spawnFailed && !exited(child)) {
      try {
        const response = await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(800) })
        if (response.ok) { ready = true; break }
      } catch { /* bounded readiness probe */ }
      await new Promise(resolve => setTimeout(resolve, 200))
    }
    if (!ready) throw new WebLoginError('Chrome 启动超时或该账号 Profile 已被其他窗口占用')
    browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, { timeout: 5000 })
    const context = browser.contexts()[0]
    if (!context || !child.pid) throw new WebLoginError('Chrome 未创建可用的账号 Profile')
    const page = context.pages().find(p => p.url() === 'about:blank') || await context.newPage()
    let closing: Promise<void> | undefined
    const close = (): Promise<void> => closing ||= (async () => {
      try {
        await Promise.race([
          browser!.newBrowserCDPSession().then(session => session.send('Browser.close')),
          new Promise(resolve => setTimeout(resolve, 1500))
        ])
      } catch { /* force owned process below */ }
      if (!await waitForExit(child, 1000)) await stopOwnedChild(child)
    })()
    return { browser, context, page, pid: child.pid, close }
  } catch {
    try { await browser?.close() } catch { /* PID cleanup below */ }
    await stopOwnedChild(child)
    throw new WebLoginError('无法启动独立 Chrome；请确认浏览器已安装且该账号 Profile 未被占用')
  }
}

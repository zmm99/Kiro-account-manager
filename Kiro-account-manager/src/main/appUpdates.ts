import { app, autoUpdater as electronUpdater, ipcMain, type BrowserWindow } from 'electron'
import { autoUpdater } from 'electron-updater'

const REPOSITORY = 'zmm99/Kiro-account-manager'

interface GitHubRelease {
  tag_name: string
  name: string | null
  body: string | null
  published_at: string
  assets: Array<{ name: string; browser_download_url: string; size: number }>
}

function isNewerRelease(latest: string, current: string): boolean {
  const [currentVersion, prerelease] = current.split('+', 1)[0].split('-', 2)
  const latestParts = latest.split('.').map(Number)
  const currentParts = currentVersion.split('.').map(Number)
  const difference = latestParts.map((part, index) => part - currentParts[index]).find(diff => diff !== 0)
  return difference === undefined ? prerelease !== undefined : difference > 0
}

export function registerAppUpdates(
  getWindow: () => BrowserWindow | null,
  fetchRelease: (url: string, options: RequestInit) => Promise<Response>,
  onInstallQuit: () => void
): () => void {
  // The unsigned macOS build and sideloaded Snap use GitHub downloads.
  const candidate = app.isPackaged && process.platform !== 'darwin' && !process.env.SNAP
    ? autoUpdater
    : undefined
  const updater = candidate?.isUpdaterActive() ? candidate : undefined
  const currentVersion = app.getVersion()

  const send = (channel: string, ...args: unknown[]): void => {
    const window = getWindow()
    if (window && !window.isDestroyed()) window.webContents.send(channel, ...args)
  }

  const checkLatestRelease = async () => {
    try {
      const response = await fetchRelease(`https://api.github.com/repos/${REPOSITORY}/releases/latest`, {
        headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'Kiro-Account-Manager' },
        signal: AbortSignal.timeout(10000)
      })
      if (response.status === 404) throw new Error('未找到发布版本')
      if (!response.ok) throw new Error(`GitHub API 错误: ${response.status}`)

      const release = await response.json() as GitHubRelease
      const latestVersion = release.tag_name.replace(/^v/, '')
      if (!/^\d+\.\d+\.\d+$/.test(latestVersion)) throw new Error('GitHub Release 版本号格式无效')

      return {
        hasUpdate: isNewerRelease(latestVersion, currentVersion),
        currentVersion,
        latestVersion,
        releaseNotes: release.body || '',
        releaseName: release.name || `v${latestVersion}`,
        releaseUrl: `https://github.com/${REPOSITORY}/releases/tag/${encodeURIComponent(release.tag_name)}`,
        publishedAt: release.published_at,
        assets: release.assets.map(asset => ({
          name: asset.name,
          downloadUrl: asset.browser_download_url,
          size: asset.size
        }))
      }
    } catch (error) {
      console.error('[Update] GitHub release check failed:', error)
      return { hasUpdate: false, currentVersion, error: error instanceof Error ? error.message : '检查更新失败' }
    }
  }

  const checkForUpdates = async () => {
    if (!app.isPackaged) return { hasUpdate: false, message: '开发环境不支持自动更新' }

    if (updater) {
      try {
        const result = await updater.checkForUpdates()
        if (result) {
          return {
            hasUpdate: result.isUpdateAvailable,
            version: result.updateInfo.version,
            releaseDate: result.updateInfo.releaseDate
          }
        }
      } catch (error) {
        console.error('[Update] In-app update check failed:', error)
      }
    }

    const release = await checkLatestRelease()
    if (release.hasUpdate) {
      send('update-available', {
        version: release.latestVersion,
        releaseDate: release.publishedAt,
        releaseNotes: release.releaseNotes,
        releaseUrl: release.releaseUrl
      })
    }
    return { hasUpdate: release.hasUpdate, version: release.latestVersion, error: release.error }
  }

  if (updater) {
    updater.autoDownload = false
    updater.autoInstallOnAppQuit = false
    updater.on('checking-for-update', () => send('update-checking'))
    updater.on('update-available', ({ version, releaseDate }) => send('update-available', { version, releaseDate }))
    updater.on('update-not-available', ({ version }) => send('update-not-available', { version }))
    updater.on('download-progress', progress => send('update-download-progress', progress))
    updater.on('update-downloaded', ({ version, releaseDate }) => send('update-downloaded', { version, releaseDate }))
    updater.on('error', error => send('update-error', error.message))
    electronUpdater.on('before-quit-for-update', onInstallQuit)
  }

  ipcMain.handle('check-for-updates', checkForUpdates)
  ipcMain.handle('check-for-updates-manual', checkLatestRelease)
  ipcMain.handle('download-update', async () => {
    if (!updater) return { success: false, error: '请从 GitHub Release 下载更新' }
    try {
      await updater.downloadUpdate()
      return { success: true }
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : '下载更新失败' }
    }
  })
  ipcMain.handle('install-update', () => updater?.quitAndInstall(false, true))

  return () => {
    if (app.isPackaged) setTimeout(() => void checkForUpdates(), 3000)
  }
}

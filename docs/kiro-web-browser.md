# 独立 Chrome 打开 Kiro Web

账号卡片操作栏新增地球图标。点击后，管理器为该账号启动独立 Chrome Profile，使用账号现有 Refresh Token 建立网页会话，并打开 `https://app.kiro.dev/home`。重复点击聚焦现有窗口，关闭窗口不会删除 Profile。管理器完全退出时会关闭自己启动的浏览器。

当前实现支持 Windows、已安装的 Google Chrome，以及带 Refresh Token 的 GitHub 账号。支持无用户名密码的 HTTP/HTTPS/SOCKS 账号代理；带认证的代理会明确报错。此次没有生成安装包。

## 此 fork 的更新与本地打包

本地 `origin` 指向 `zmm99/Kiro-account-manager`。该分支关闭应用启动更新检查、手动检查、下载和安装更新；不再加载 `electron-updater`，关于页面显示“更新已关闭”。升级时手动安装新编译的版本。构建配置的 GitHub 发布目标也已改为该 fork。

在嵌套的 `Kiro-account-manager` 项目目录内，依次执行 `npm run build` 和 `npx electron-builder --win nsis --x64 --publish never`，仅生成本地安装包，不上传 Release。安装前导出账号备份并退出托盘中的旧程序。

## 登录与凭据维护

- 前端 IPC 只发送账号 ID，新增流程不把 Token 放进命令行或错误日志。
- 每个账号独立保存 Profile，目录名为账号 ID 的 SHA-256，位于 Electron `userData/kiro-web/profiles`。
- 首次登录先访问 Kiro 同源页面，以占位 AT、当前 RT、`Idp=Github` 请求主页取得 CSRF，再通过浏览器原生 `fetch` 调用 `RefreshToken`。不主动填写 UserId；保留服务器后续发放的 UserId Cookie。
- 使用 `GetUserInfo` 验证 Active 状态、GitHub 提供商及账号身份，然后打开首页。服务端拒绝凭据或账号状态异常时停止。
- 复用有效 Profile 时直接验证身份，不无条件消耗 RT。
- 管理器与网页沿用同一条 RT 链，通过主进程协调器串行刷新。网页自动发出的 `RefreshToken` 也进入协调器；同一窗口的并发刷新合并为一次。网页 AT 保留在网页，管理器/IDE AT 保留各自用途。
- 新 RT 在提交账号存储前先写入系统加密保护的恢复记录。待处理状态在请求前落盘；网络中断、崩溃或结果不确定时阻止旧 RT 自动重放。完整成功记录可在下次刷新前恢复提交；不完整记录需要人工恢复或重新授权，当前没有专门的恢复界面。
- 账号存储包含凭据修订号，避免延迟的界面保存覆盖新 RT。匹配到同一旧 RT 的本地 IDE 文件只原子替换 RT，保留 IDE AT。

这些措施协调的是本管理器控制的刷新。独立运行的 IDE 不参与该锁，因此检测到目标账号与运行中的 IDE 共用凭据时，网页建立/续期会停止并提示先退出 IDE。用户随后重新启动 IDE 时会读取同步后的文件。其他客户端也应避免同时消耗同一条 RT 链。

网页 `Logout` 请求在受管 Profile 内执行本地认证 Cookie 清理，不向服务器撤销共享 RT。需要服务器撤销时，应通过官方账号管理流程操作。

## 文件与边界

主要实现分离为：

- [kiroWebBrowser.ts](../Kiro-account-manager/src/main/kiroWebBrowser.ts)：登录、身份校验、Profile 会话和网页刷新拦截。
- [kiroWebCredentials.ts](../Kiro-account-manager/src/main/kiroWebCredentials.ts)：RT 锁、加密日志、原子写入、修订号合并。
- [kiroWebBrowserLauncher.ts](../Kiro-account-manager/src/main/kiroWebBrowserLauncher.ts)：Chrome 探测、启动与 PID 范围内关闭。

账号存储、IPC 与按钮仅保留接入代码。恢复记录通过 Electron `safeStorage` 加密，没有明文降级。Profile 仍应按包含登录凭据的浏览器资料保护，不应上传或共享；它不会因删除管理器账号而自动删除。

本实现使用此前正常授权研究中验证的网页流程，不能据此认定它是官方承诺兼容的公共 SDK。Kiro 的 Cookie、CSRF 或接口变化可能需要适配。不能推断所有 RT 都是严格一次性；实现始终按可能发生轮换处理。

## 验证记录（2026-10-30）

已完成：

- `npm run test:kiro-web`：12 项模拟测试通过，覆盖串行/并发刷新、提交失败恢复、不确定结果阻断、修订号合并、身份错配、IDE 保护、私有标记移除、非 Kiro 来源拒绝及窗口复用。
- `npm run build`：Node/Web 类型检查和生产构建通过。存在原有 logger/tlsClientPool 动静态导入提示。
- 三个新增主进程模块 ESLint 错误检查通过。
- 实际 Chrome + 本地请求拦截：首次登录、重复点击、两次并发网页刷新、Cookie 持久化、关闭重开复用成功；重开没有增加上游刷新次数，管理器 AT 保持不变。
- 实际构建产物在 Chrome 渲染：地球按钮与原操作按钮同尺寸，点击只发送账号 ID，页面没有未捕获异常。[预览使用模拟账号](research/kiro-web-button-preview.png)。
- 测试 Chrome 已关闭，调试监听端口和测试 Profile 已清理。

本次实现验证使用模拟凭据与模拟接口，没有读取或刷新生产账号 RT，也没有对完整 Electron 程序进行真实账号验收。此前独立测试账号的最小参数研究与本次自动化测试的证据范围不同；原始研究记录只在本地保存，不纳入仓库。

下一步实际验收应继续使用可消耗的独立测试账号，确认首次打开、网页自动续期、管理器再次刷新、关闭重开均成功，再考虑将其用于日常账号。

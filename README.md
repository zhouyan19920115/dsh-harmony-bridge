# dsh-harmony-bridge

**给 DeepSeek Harness 用的鸿蒙手机桥接插件。** 装一次，DSH 启动就自动把桥接拉起来——
手机端不用再把「桌面端安装包」发到电脑，直接在同 WiFi 下点「自动发现」就能配对。

> 项目主页：<https://github.com/zhouyan19920115/dsh-harmony>
> 手机 App（HarmonyOS NEXT）也在这个仓库里：`harmony/`；桥接源码：`bridge/`。

## 它解决什么问题

旧做法是：手机上点「把桌面端发到电脑」→ 保存 zip → 微信/蓝牙/星闪传到电脑 → 解压 → 双击启动脚本。
每换一台电脑都要来一遍，而且电脑上还得装 Node。

装了这个插件之后：

1. 电脑上装好 DeepSeek Harness；
2. 在 DSH 的「插件市场」里搜索 `dsh-harmony-bridge`（或从本地 `.tgz` 安装）→ 重启 DSH；
3. 手机 App 点「自动发现」→ 选中这台电脑，结束。

桥接随 DSH 启停，不再有单独的黑框窗口要维护。

## 功能

- **局域网发现**：`GET /_dsh/discover`，手机在同一 WiFi 下自动找到这台电脑；
- **HTTP + WebSocket API**：会话树、消息流、发指令、队列、模型、技能、`ask_user_question` 的回答；
- **配对令牌**：首次配对后手机保存令牌，之后免输入；
- **可选的云中继**：不在同一局域网时也能用（`relay` 配置项）；
- **可选推送**：华为 Push Kit 角标/通知（手机端上报 token 后生效）。

## 安装

### 方式 A：插件市场（推荐）

1. DSH → 设置 → 插件市场；
2. 搜索 `dsh-harmony-bridge` → 安装 → 重启 DSH。

### 方式 B：本地安装

```bash
# 在仓库根目录
cd plugins/dsh-harmony-bridge
npm pack                     # 生成 dsh-harmony-bridge-0.1.0.tgz
```

然后在 DSH 的插件管理器里选「从本地文件安装」，选这个 `.tgz`，重启 DSH。

### 方式 C：给插件市场做索引（插件作者/发布者用）

本插件自带一份市场索引 `market/index.json`，把自己的索引地址加到 DSH 配置里即可被搜索到：

```yaml
# ~/.dsh/profiles/desktop/cordis.patch.yml
- id: plugin-market
  name: "@deepseek-ai/dsh-plugin-market"
  config:
    indexes:
      - https://raw.githubusercontent.com/zhouyan19920115/dsh-harmony/main/plugins/dsh-harmony-bridge/market/index.json
```

## 装完要设置什么？

**基本上什么都不用设。** 装好插件 → 重启 DSH → 手机点「自动探测」就结束了：

- 桥接默认监听 `0.0.0.0:8787`，随 DSH 自动启停；
- 令牌沿用 `~/.dsh-harmony-bridge/bridge.json`（如果之前手动跑过桥接，文件还在，手机**不用重新配对**）；
- 手机端不用填地址、不用填令牌、不用点「开始共享」。

只有这些情况才需要动配置（改 `~/.dsh/profiles/desktop/cordis.patch.yml` 里 `harmony-bridge` 的 `config`）：

| 情况 | 改什么 |
|---|---|
| 8787 端口被别的程序占了 | `port: 8790`（手机自动发现会自动读到新端口） |
| 只想本机/云中继访问，不暴露局域网 | `host: 127.0.0.1` |
| 想离开局域网也能连 | `relay: wss://...`（+ `relayPublicUrl`） |
| 想换令牌 / 多实例隔离 | `statePath: 另一个路径`（换路径 = 所有手机要重新配对） |
| 排查启动问题 | `verbose: true`（桥接日志直接打到 DSH 控制台） |
| 不想随 DSH 自动启动 | `autoStart: false`（之后手动跑也行） |

另外两个环境前提：

- 电脑防火墙要放行这个端口（Windows 首次运行会弹窗，允许「专用网络」即可）；
- 想随时被手机连上，DSH 本身要开机自启。

## 配置

装好后在 `~/.dsh/profiles/desktop/cordis.patch.yml` 里能改（都有默认值）：

```yaml
- id: harmony-bridge
  name: dsh-harmony-bridge
  config:
    port: 8787              # 桥接监听端口
    host: 0.0.0.0           # 局域网可见（只给本机用就填 127.0.0.1）
    autoStart: true
    verbose: false          # true = 桥接日志直接打到 DSH 控制台
    # statePath: C:\Users\你\.dsh-harmony-bridge\bridge.json
    # relay: wss://your-relay.example.com/bridge
```

改完重启 DSH 生效；桥接的配对令牌保存在 `statePath`，删掉它等于让所有手机重新配对。

## DSH 里的设置 UI

装好后 DSH 的设置里会多出「**DSH Harmony 桥接**」一节（插件自带的客户端 UI），
插件列表里那一行的「配置」也能打开同一个面板：

- 显示桥接地址、是否随 DSH 启动、配置文件路径；
- 可改：端口、监听地址、relay、relayPublicUrl、relayName、deviceId/deviceToken、
  account/accountToken、relayCa、autoStart、verbose；
- 保存到 `~/.dsh-harmony-bridge/plugin-config.json`，**重启 DSH 生效**；
- 另外还有浏览器版设置页：`http://<电脑IP>:<端口>/settings?token=<桥接令牌>`（手机 App 里有入口）。

## 兼容性

- **手机 App**：HarmonyOS NEXT（手机/平板），**没有 iOS / Android 客户端**；
- **桥接**：Node 20+，Windows/macOS/Linux 都能跑；
- **DSH 插件**：取决于 DSH 桌面端支持的平台（Windows 已验证）；
- **鸿蒙电脑**：DSH 桌面端目前没有鸿蒙 PC 版，所以插件方案跑不了；手机 App 本身可在鸿蒙 PC 运行，
  但仍需另一台电脑跑桥接。

详见仓库 `docs/COMPATIBILITY.md`。

## 默认零配置

装好插件 → 在 DSH 里启用 → 手机点「自动探测」，**不需要任何配置**：

- 端口默认 8787、监听 0.0.0.0、随 DSH 自动启动；
- 不需要填 IP、不需要填令牌；
- 只有在 8787 被占用、或要跨网络（云中继）时才需要改设置。

**插件和文档里不写死任何公网地址。** 需要云中继时，`relay` 请填**你自己的域名**
（例如 `wss://relay.example.com/bridge`），不要暴露服务器公网 IP；域名用 A 记录指向你的中继服务器即可。

## 端口与手机「自动探测」

手机 App 的自动探测是**固定扫 8787 端口**的（`Discovery.ets` 里 `BRIDGE_PORT = 8787`），
发现后连接地址就是 `http://<电脑IP>:8787`（列表顶部会显示这一行）。

所以：

- 插件端口保持默认 **8787** 最省事，手机不用填任何地址；
- 如果改成别的端口，自动探测会找不到，需要在手机上**手动填地址**（`IP:端口`）；
- 需要「服务器设置」时，填的是 `relay`（云中继地址），不是 IP —— 局域网里 IP 由自动发现提供。

插件导出了 `Config`（schemastery schema），DSH 的插件管理器会据此渲染设置表单
（端口 / 监听地址 / 令牌路径 / 中继地址 / 中继公开地址 / 设备名 / 自动启动 / 日志），
改完重启 DSH 生效。插件本身没有独立页面；要独立设置页需要再做一个 `dsh-client-ui-*` 前端插件。

## 常见问题：手机扫不到电脑（Windows）

如果手机「自动探测」一直 0 台，多半是 **Windows 防火墙**：

- 插件拉起的桥接进程是 `DeepSeek Harness.exe`，不是 `node.exe`；
- Windows 把 WiFi 判成「公用网络」时默认阻止入站，手机就连不上 8787。

处理：以管理员身份运行

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\allow-firewall.ps1
```

它会为 `DeepSeek Harness.exe` 和 `node.exe` 各加一条 TCP 8787 入站放行规则。
验证：电脑上 `curl http://<局域网IP>:8787/_dsh/discover` 能返回 JSON；手机再点「自动探测」。

## 常见问题：中继域名连不上

如果 `relay` 用的是**套了 Cloudflare 代理（橙云）的域名**，桥接可能报
`websocket connect ... timed out` —— 因为中继通常用自签 TLS，Cloudflare 代理连不上后端。
两种处理：

1. 把该域名在 Cloudflare 里改成 **DNS only（灰云）**，直接解析到中继服务器；
2. 或者换一个**不走代理**的子域名（比如 `relay2.example.com`）指向同一台服务器。

改完 DNS 后重启 DSH（或桥接）即可恢复云中继；局域网自动探测不受影响。

## 安全

- 桥接默认只监听局域网，DSH 的 loopback RPC 仍然要 owner cookie；
- 手机必须持有配对令牌才能调 API；
- 不想暴露在局域网时把 `host` 改成 `127.0.0.1`，再搭配云中继使用。

## 手机端两个方案

App 的「把桌面端发到电脑」面板里现在有两种方式：

- **方案一 · 装 DSH 插件**（推荐）：电脑装 DSH + 本插件，手机直接自动发现；
- **方案二 · 发送文件**：不支持插件的环境（没装 DSH、或想跑独立桥接）时，仍然可以把
  `dsh-harmony-desktop.zip` 发到电脑，解压后双击「双击我-开始.cmd」。

## 目录

```
plugins/dsh-harmony-bridge/
├── package.json          # DSH 插件包（dsh.bundle.patch 指向 cordis.patch.yml）
├── cordis.patch.yml      # 把插件插进 DSH 配置
├── lib/index.js          # 插件入口：拉起/收起桥接子进程
├── bridge/               # 桥接源码（从仓库 bridge/ 同步，随插件发布）
├── market/index.json     # 插件市场索引（发布用）
└── README.md
```

桥接源码有更新时，在仓库根目录执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\sync-plugin-bridge.ps1
```

## License

MIT，见仓库根目录 `LICENSE`。

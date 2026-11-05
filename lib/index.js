/**
 * DSH Harmony Bridge —— DeepSeek Harness 插件入口。
 *
 * 这个插件把「手机桥接」搬进 DSH：DSH 启动时自动拉起本机桥接（LAN 发现 + HTTP/WebSocket +
 * 可选的云中继），DSH 退出时一起停掉。手机端不需要再把桌面端安装包传到电脑，
 * 只要电脑装了 DSH + 这个插件，就能用「自动发现」配对。
 *
 * 实现上是把随插件打包的 `bridge/src/cli.js` 作为子进程运行（Node 20+ 语义，零第三方依赖）。
 * 用 `ELECTRON_RUN_AS_NODE=1` 让 DSH 桌面端自带的 Electron 二进制按 Node 执行，
 * 这样用户电脑上即使没有单独装 Node 也能跑。
 *
 * 配置（cordis.patch.yml 里的 config，全部可选）：
 *   port           桥接监听端口，默认 8787
 *   host           监听地址，默认 0.0.0.0（局域网内手机可见）
 *   statePath      桥接状态文件（内含配对令牌），默认 ~/.dsh-harmony-bridge/bridge.json
 *   relay          云中继地址，例如 wss://relay.example.com/bridge（可选）
 *   relayPublicUrl 中继对手机暴露的公开地址（可选）
 *   relayName      中继里显示的设备名（可选）
 *   autoStart      是否随 DSH 自动启动，默认 true
 *   verbose        是否把桥接日志直接打到 DSH 控制台，默认 false（只记 logger）
 */

import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import os, { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import z from '@deepseek-ai/schemastery';

export const name = 'harmony-bridge';

/**
 * 插件设置（DSH 的插件管理器会按这个 schema 渲染表单）。
 *
 * 默认值就是「装完不用改」：
 *   port 8787 / host 0.0.0.0 / autoStart true / relay 关闭。
 */
export const Config = z.object({
  port: z.natural().default(8787)
    .description('桥接端口。手机「自动探测」只扫 8787；改成别的端口需要在手机上手动填地址。'),
  host: z.string().default('0.0.0.0')
    .description('监听地址。0.0.0.0 = 局域网可连；127.0.0.1 = 只有本机/云中继能连。'),
  statePath: z.string().default('')
    .description('配对令牌存放路径。留空 = ~/.dsh-harmony-bridge/bridge.json（沿用旧令牌，手机不用重新配对）。'),
  relay: z.string().default('')
    .description('云中继地址，例如 wss://relay.example.com/bridge。留空 = 只走局域网。'),
  relayPublicUrl: z.string().default('')
    .description('中继对手机暴露的公开地址（可选，中继地址推导不出来时填）。'),
  relayName: z.string().default('')
    .description('中继里显示的设备名（可选，默认电脑主机名）。'),
  deviceId: z.string().default('')
    .description('中继的设备号（第一次接云中继时填；已有 bridge.json 凭据的电脑留空）。'),
  deviceToken: z.string().default('')
    .description('中继的设备令牌（和 deviceId 一起填）。'),
  account: z.string().default('')
    .description('中继账号（多设备归到一个账号时填，可选）。'),
  accountToken: z.string().default('')
    .description('中继账号令牌（和 account 一起填）。'),
  relayCa: z.string().default('')
    .description('中继自签证书的 PEM 文件路径（可选）。'),
  autoStart: z.boolean().default(true)
    .description('随 DSH 一起启动桥接（关掉后需要自己手动跑）。'),
  verbose: z.boolean().default(false)
    .description('把桥接日志直接打到 DSH 控制台（排查用）。'),
});

/** 客户端设置页通过 DSH 的 webServer 读写配置（没有 webServer 时只是少一个 UI，桥接照跑）。 */
export const inject = ['webServer'];

const here = dirname(fileURLToPath(import.meta.url));
/** 插件包里的桥接 CLI：lib/index.js → ../bridge/src/cli.js */
const bridgeCli = resolve(here, '..', 'bridge', 'src', 'cli.js');

/** 把任意日志块转成一行，避免把多行日志灌进 DSH 的 logger。 */
function oneLine(value) {
  return String(value).replace(/\r?\n/g, ' ').trim();
}

/** 设置文件路径（和桥接 /settings 页面共用）。 */
function configFilePath() {
  return process.env.DSH_BRIDGE_CONFIG
    ? configFileResolve(process.env.DSH_BRIDGE_CONFIG)
    : join(homedir(), '.dsh-harmony-bridge', 'plugin-config.json');
}

function configFileResolve(value) {
  return value;
}

const CONFIG_KEYS = ['port', 'host', 'relay', 'relayPublicUrl', 'relayName',
  'deviceId', 'deviceToken', 'account', 'accountToken', 'relayCa', 'autoStart', 'verbose'];

function readConfigFile() {
  try {
    const parsed = JSON.parse(readFileSync(configFilePath(), 'utf8'));
    return parsed !== null && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function writeConfigFile(body) {
  const current = readConfigFile();
  for (const key of CONFIG_KEYS) {
    if (body !== null && typeof body === 'object' && Object.hasOwn(body, key)) {
      current[key] = body[key];
    }
  }
  const file = configFilePath();
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(current, null, 2), { mode: 0o600 });
  return { ok: true, file, config: current };
}

/**
 * 给 DSH 客户端插件注册本地 API：
 *   GET  /plugins/dsh-harmony-bridge/api/status  当前配置 + 桥接端口
 *   GET  /plugins/dsh-harmony-bridge/api/config  当前配置
 *   POST /plugins/dsh-harmony-bridge/api/config  保存配置
 *
 * 只接受 loopback 请求（DSH 的 web 界面在本机）。
 */
function registerClientApi(ctx, effective) {
  ctx.inject(['webServer'], (webCtx) => {
    const webServer = webCtx.webServer;
    if (webServer === undefined || typeof webServer.register !== 'function') return;
    const prefix = '/plugins/dsh-harmony-bridge/api';
    const sendJson = (res, status, payload) => {
      const text = JSON.stringify(payload);
      res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(text) });
      res.end(text);
    };
    const isLoopback = (req) => {
      const address = req.socket?.remoteAddress ?? '';
      return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1';
    };
    const handler = async (req, res) => {
      if (!isLoopback(req)) {
        sendJson(res, 403, { ok: false, error: 'loopback requests only' });
        return;
      }
      const url = new URL(req.url ?? '/', 'http://127.0.0.1');
      try {
        if (req.method === 'GET' && url.pathname === `${prefix}/status`) {
          const config = { ...effective, ...readConfigFile() };
          const port = config.port ?? 8787;
          const host = config.host ?? '0.0.0.0';
          let lanIp = '127.0.0.1';
          try {
            for (const infos of Object.values(os.networkInterfaces())) {
              for (const info of infos ?? []) {
                if (info.family === 'IPv4' && !info.internal) { lanIp = info.address; break; }
              }
              if (lanIp !== '127.0.0.1') break;
            }
          } catch { /* ignore */ }
          const shownHost = host === '0.0.0.0' ? lanIp : host;
          sendJson(res, 200, {
            ok: true,
            config,
            configFile: configFilePath(),
            bridge: {
              url: `http://${shownHost}:${port}`,
              host,
              port,
              lanIp,
              autoStart: config.autoStart !== false,
            },
          });
          return;
        }
        if (req.method === 'GET' && url.pathname === `${prefix}/config`) {
          sendJson(res, 200, { ok: true, config: readConfigFile(), configFile: configFilePath() });
          return;
        }
        if (req.method === 'POST' && url.pathname === `${prefix}/config`) {
          const chunks = [];
          for await (const chunk of req) chunks.push(chunk);
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
          sendJson(res, 200, writeConfigFile(body));
          return;
        }
        sendJson(res, 404, { ok: false, error: 'unknown endpoint' });
      } catch (error) {
        ctx.logger?.warn?.(`[harmony-bridge] client api failed: ${error instanceof Error ? error.message : String(error)}`);
        sendJson(res, 500, { ok: false, error: error instanceof Error ? error.message : String(error) });
      }
    };
    ctx.effect(() => webServer.register({ kind: 'prefix', path: prefix, handler }), 'harmony-bridge: local settings API');
  });
}

/**
 * 启动桥接（cordis 插件入口）。
 *
 * @param {import('@deepseek-ai/cordis').Context} ctx cordis 上下文
 * @param {object} config 插件配置（见文件头注释）
 */
export function apply(ctx, config = {}) {
  // 网页设置页(桥接 /settings)写的是这个文件；文件里的值优先于 cordis 配置
  const configFile = process.env.DSH_BRIDGE_CONFIG
    ? process.env.DSH_BRIDGE_CONFIG
    : join(homedir(), '.dsh-harmony-bridge', 'plugin-config.json');
  let fileConfig = {};
  try {
    if (existsSync(configFile)) fileConfig = JSON.parse(readFileSync(configFile, 'utf8')) ?? {};
  } catch {
    fileConfig = {};
  }
  config = { ...config, ...fileConfig };

  if (config.autoStart === false) {
    ctx.logger?.info?.('[harmony-bridge] autoStart=false，跳过启动');
    return;
  }
  if (!existsSync(bridgeCli)) {
    ctx.logger?.warn?.(`[harmony-bridge] 找不到桥接代码: ${bridgeCli}`);
    return;
  }

  const port = Number(config.port ?? 8787);
  const host = String(config.host ?? '0.0.0.0');
  const statePath = config.statePath !== undefined && String(config.statePath).length > 0
    ? String(config.statePath)
    : join(homedir(), '.dsh-harmony-bridge', 'bridge.json');

  const args = [bridgeCli, '--port', String(port), '--host', host, '--state', statePath];
  if (config.relay) args.push('--relay', String(config.relay));
  if (config.relayPublicUrl) args.push('--relay-public-url', String(config.relayPublicUrl));
  if (config.relayName) args.push('--relay-name', String(config.relayName));
  if (config.relayCa) args.push('--relay-ca', String(config.relayCa));
  if (config.deviceId) args.push('--device-id', String(config.deviceId));
  if (config.deviceToken) args.push('--device-token', String(config.deviceToken));
  if (config.account) args.push('--account', String(config.account));
  if (config.accountToken) args.push('--account-token', String(config.accountToken));

  const child = spawn(process.execPath, args, {
    cwd: dirname(bridgeCli),
    windowsHide: true,
    env: {
      ...process.env,
      // DSH 桌面端里 process.execPath 是 Electron；这个开关让它按 Node 运行桥接。
      ELECTRON_RUN_AS_NODE: '1',
    },
    stdio: config.verbose ? 'inherit' : ['ignore', 'pipe', 'pipe'],
  });

  if (!config.verbose) {
    child.stdout?.on('data', (chunk) => {
      for (const line of String(chunk).split(/\r?\n/)) {
        if (line.trim().length > 0) ctx.logger?.debug?.(`[harmony-bridge] ${oneLine(line)}`);
      }
    });
    child.stderr?.on('data', (chunk) => {
      for (const line of String(chunk).split(/\r?\n/)) {
        if (line.trim().length > 0) ctx.logger?.warn?.(`[harmony-bridge] ${oneLine(line)}`);
      }
    });
  }

  child.on('error', (error) => {
    ctx.logger?.warn?.(`[harmony-bridge] 启动失败: ${error.message}`);
  });
  child.on('exit', (code, signal) => {
    if (code !== 0) ctx.logger?.warn?.(`[harmony-bridge] 桥接进程退出 code=${code} signal=${signal ?? '-'}`);
  });

  ctx.logger?.info?.(`[harmony-bridge] 已启动: http://${host}:${port} (state=${statePath})`);
  ctx.logger?.info?.(`[harmony-bridge] 设置页: http://${host}:${port}/settings (打开后填桥接令牌)`);
  registerClientApi(ctx, config);

  // DSH 关闭 / 插件卸载时，把桥接一起停掉，避免残留进程占着端口。
  ctx.on('dispose', () => {
    if (child.exitCode !== null) return;
    child.kill('SIGTERM');
    const timer = setTimeout(() => {
      if (child.exitCode === null) child.kill('SIGKILL');
    }, 3000);
    timer.unref?.();
  });
}

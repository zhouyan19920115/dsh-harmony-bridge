// Adapter for the running DeepSeek Harness desktop application.
//
// DSH exposes a Typert RPC surface on `http://127.0.0.1:10748`:
//   POST /api/<namespace>/<method>  body {"type":"client-request","rpcId","method","payload":{"args":{…}}}
// There is no bearer token: authentication uses an owner cookie that the client mints from the
// on-disk browser-session secret (`~/.dsh/.credentials.yaml`). The listener also enforces a Host
// fence, so every request must carry `Host: 127.0.0.1:10748`.
//
// Live data (streaming) is only available over the `/api/remote.mux` WebSocket carrier.

import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import { dshHome } from './config.js';
import { WebSocketClient } from './ws.js';

/**
 * Wire argument key per endpoint (`parameter.wire ?? parameter.name`).
 * A `null` value marks an endpoint whose arguments are **flat**: they are sent as the fields of
 * `payload.args` itself instead of being wrapped in a single `request` object.
 */
const ARG_KEYS = {
  'session/list': '_request',
  'session/page': 'request',
  'session/prompt': 'request',
  'session/cancel': 'request',
  'session/create': 'request',
  // The path → Workspace resolver of the host. `request` wraps `{path}`.
  'workspace/create': 'request',
  'agentPresets/list': null,
  'session/rename': 'request',
  'session/projections': 'request',
  'session/selectModel': 'request',
  'session/updateQueue': 'request',
  'skills/list': 'request',
  // Flat argument endpoints (verified against the running application).
  'session/modelCatalog': null,
  'commands/list': null,
  // Flat: the descriptor wants `agentId`, `line` and `submittedAttachments` directly.
  'commands/execute': null,
  'userQuestions/answer': null,
  'permissionPresets/catalog': null,
  'fileReferences/list': null,
};

/** An error raised by DSH itself. */
export class DshError extends Error {
  constructor(code, message, details) {
    super(message);
    this.name = 'DshError';
    this.code = code;
    this.details = details;
  }
}

/**
 * The first DSH version that is not affected by the local Host header bypass
 * (CVE-2026-82533, CVSS 9.4). Older hosts trust a forged `Host` header, so a page in the
 * local browser could talk to the DSH as if it were the owner.
 */
export const DSH_MINIMUM_VERSION = '0.1.2-alpha.1';

/**
 * How long the bridge waits before it looks the DSH up again.
 *
 * A desktop upgrade restarts the application and it may come back on another port; the
 * re-discovery in `DshClient.rediscover()` closes that gap. The cooldown keeps a DSH that is
 * simply not running from being hammered with port scans.
 */
export const REDISCOVER_COOLDOWN_MS = 30_000;

/** The error codes that mean "nothing is listening there any more". */
const CONNECTION_ERROR_CODES = new Set([
  'ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH', 'ENOTFOUND', 'EPIPE',
]);

/**
 * Is this a "the port is gone" error?
 *
 * Only a connection failure justifies looking the DSH up again: a timeout usually means the
 * desktop is busy, and a protocol error means the desktop is there but says something else.
 */
function isConnectionError(error) {
  if (error instanceof DshError) return false;
  const code = error?.code;
  if (typeof code === 'string' && CONNECTION_ERROR_CODES.has(code)) return true;
  const message = error instanceof Error ? error.message : String(error ?? '');
  return /ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|ENOTFOUND|EPIPE|socket hang up/iu.test(message);
}

/**
 * Compare two version strings the way semver does (the parts, then the prerelease).
 * Returns a negative number when `a` is older than `b`.
 */
export function compareVersions(a, b) {
  const parse = (value) => {
    const text = String(value ?? '').trim().replace(/^v/u, '');
    const [core, prerelease] = text.split('-', 2);
    const parts = core.split('.').map((part) => {
      const number = Number.parseInt(part, 10);
      return Number.isFinite(number) ? number : 0;
    });
    while (parts.length < 3) parts.push(0);
    return { parts, prerelease: prerelease ?? null };
  };

  const left = parse(a);
  const right = parse(b);
  for (let i = 0; i < 3; i += 1) {
    if (left.parts[i] !== right.parts[i]) return left.parts[i] - right.parts[i];
  }
  // A prerelease is older than the release it belongs to.
  if (left.prerelease === right.prerelease) return 0;
  if (left.prerelease === null) return 1;
  if (right.prerelease === null) return -1;
  return left.prerelease.localeCompare(right.prerelease, 'en', { numeric: true });
}

/**
 * Read the version of the installed DSH.
 *
 * The desktop runtime writes it into `~/.dsh/dsh-runtimes/<runtime>/runtime.json`
 * (`desktopVersion`). `null` when the DSH cannot be found.
 */
export function readDshVersion(home = dshHome()) {
  const runtimes = path.join(home, 'dsh-runtimes');
  let entries;
  try {
    entries = fs.readdirSync(runtimes, { withFileTypes: true });
  } catch {
    return null;
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const file = path.join(runtimes, entry.name, 'runtime.json');
    try {
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (typeof parsed?.desktopVersion === 'string' && parsed.desktopVersion.length > 0) {
        return parsed.desktopVersion;
      }
    } catch {
      // Try the next runtime.
    }
  }
  return null;
}

/** Is the DSH version free of the known local bypass? */
export function isDshVersionSafe(version) {
  if (typeof version !== 'string' || version.length === 0) return true;
  return compareVersions(version, DSH_MINIMUM_VERSION) >= 0;
}

/**
 * Read the browser-session signing secret out of `~/.dsh/.credentials.yaml`.
 * The file is YAML, but the record we need has a fixed shape, so a targeted block scan is used
 * instead of pulling in a YAML parser.
 */
export function readBrowserSessionSecret(home = dshHome()) {
  const file = path.join(home, '.credentials.yaml');
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }

  const lines = text.split(/\r?\n/u);
  const blockIndex = lines.findIndex((line) => /^\s*client-connection\/browser-session\s*:\s*$/u.test(line));
  if (blockIndex !== -1) {
    const indent = lines[blockIndex].search(/\S/u);
    for (let i = blockIndex + 1; i < lines.length; i += 1) {
      const line = lines[i];
      if (line.trim().length === 0) continue;
      const lineIndent = line.search(/\S/u);
      if (lineIndent <= indent) break;
      const match = /^\s*secret\s*:\s*["']?([A-Za-z0-9_\-+/=]+)["']?\s*$/u.exec(line);
      if (match) return match[1];
    }
  }

  // Fallback: the record block may be inlined differently.
  const fallback = /client-connection\/browser-session\s*:[\s\S]{0,400}?secret\s*:\s*["']?([A-Za-z0-9_\-+/=]+)["']?/u.exec(text);
  return fallback ? fallback[1] : null;
}

function base64Url(buffer) {
  return Buffer.from(buffer).toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

/**
 * Mint the DSH owner cookie for one authority (`host:port`).
 * Cookie name  : `dsh-auth-` + base64url(sha256(authority))
 * Cookie value : `v1.` + base64url(payload) + `.` + base64url(HMAC-SHA256(secret, payload))
 */
export function mintOwnerCookie(secret, authority, { ttlMs = 30 * 24 * 60 * 60 * 1000 } = {}) {
  const key = Buffer.from(String(secret).replaceAll('-', '+').replaceAll('_', '/'), 'base64');
  if (key.length === 0) throw new Error('dsh: the browser-session secret could not be decoded');
  const issuedAt = Date.now();
  const payload = { version: 1, authority, issuedAt, expiresAt: issuedAt + ttlMs };
  const body = base64Url(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signature = crypto.createHmac('sha256', key).update(body).digest();
  const name = `dsh-auth-${base64Url(crypto.createHash('sha256').update(authority).digest())}`;
  return `${name}=v1.${body}.${base64Url(signature)}`;
}

/** One plain HTTP request with full control over the headers (including `Host`). */
function httpRequest({ url, method = 'POST', headers = {}, body, timeoutMs = 15_000 }) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const transport = target.protocol === 'https:' ? https : http;
    const payload = body === undefined ? null : Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
    const request = transport.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      method,
      path: `${target.pathname}${target.search}`,
      headers: {
        ...headers,
        ...(payload ? { 'content-length': payload.length } : {}),
      },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({
        status: response.statusCode ?? 0,
        headers: response.headers,
        text: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    request.setTimeout(timeoutMs, () => {
      request.destroy(new Error(`dsh: request to ${url} timed out`));
    });
    request.on('error', reject);
    if (payload) request.write(payload);
    request.end();
  });
}

/**
 * The ports that listen on the loopback interface.
 *
 * The DSH desktop host picks a free port for itself (10748 when it is free, something else
 * otherwise), so the bridge cannot rely on a fixed port.
 */
export function listeningPorts() {
  const commands = process.platform === 'win32'
    // 绝对路径优先: 插件/被别的进程拉起时 PATH 可能没有 System32, 只写 'netstat' 会找不到 ⇒ 桥接
    // 就只能去猜默认端口(10748), 导致 pending/运行中全是 0。
    ? [['C:\\Windows\\System32\\netstat.exe', ['-ano', '-p', 'tcp']], ['netstat', ['-ano', '-p', 'tcp']]]
    : [['ss', ['-tln']], ['netstat', ['-an']]];
  for (const [command, args] of commands) {
    let output = '';
    try {
      output = execFileSync(command, args, { encoding: 'utf8', timeout: 5000, windowsHide: true });
    } catch {
      continue;
    }
    const ports = new Set();
    for (const line of output.split(/\r?\n/u)) {
      const match = /:(\d{2,5})\s+\S+\s+LISTENING/iu.exec(line)
        ?? /LISTEN\s+\d+\s+\d+\s+.*:(\d{2,5})\s/iu.exec(line)
        ?? /127\.0\.0\.1:(\d{2,5})/iu.exec(line)
        ?? /0\.0\.0\.0:(\d{2,5})/iu.exec(line)
        ?? /\[::1?\]:(\d{2,5})/iu.exec(line);
      if (match) ports.add(Number(match[1]));
    }
    if (ports.size > 0) return [...ports].sort((a, b) => a - b);
  }
  return [];
}

/**
 * Log with the same shape as the bridge logger (`[bridge] INFO ...`).
 *
 * The discovery lives in this module and the logger lives in the cli, so the two cannot import
 * each other without a cycle. The format is repeated here on purpose: it keeps the discovery
 * self contained and lets it report the candidates without a caller.
 */
function noteLog(level, message) {
  const stamp = new Date().toISOString().replace('T', ' ').slice(0, 23);
  process.stdout.write(`${stamp} [bridge] ${level.toUpperCase().padEnd(5)} ${message}\n`);
}

/**
 * Ask one candidate whether it is a DSH host.
 *
 * The probe is a cheap DSH specific call (the permission catalog). A host that answers with a
 * DSH envelope is a DSH host; the status code is kept as well, because the real application
 * answers `401` when the owner cookie is missing.
 */
async function probeDshHost(baseUrl, secret, timeoutMs) {
  const headers = { 'content-type': 'application/json' };
  if (secret !== null) {
    headers.host = new URL(baseUrl).host;
    headers.cookie = mintOwnerCookie(secret, headers.host);
  }
  try {
    const response = await httpRequest({
      url: `${baseUrl}/api/permissionPresets/catalog`,
      method: 'POST',
      headers,
      body: JSON.stringify({
        type: 'client-request',
        rpcId: crypto.randomUUID(),
        method: 'permissionPresets/catalog',
        payload: { args: {} },
      }),
      timeoutMs,
    });
    if (response.status !== 200) return { ok: false, status: response.status };
    const parsed = JSON.parse(response.text);
    return { ok: parsed?.type === 'server-response', status: response.status };
  } catch {
    return { ok: false, status: 0 };
  }
}

/**
 * Find the DSH desktop host when its port is not known.
 *
 * More than one process can answer on the loopback interface: the real application, but also a
 * leftover instance or a test double that mimics the RPC. "The first port that answers" is
 * therefore not good enough — the bridge could end up talking to the wrong one.
 *
 * The probe asks **every** candidate (in parallel, so it stays fast) and ranks the answers:
 *
 * 1. the host that **enforces the owner cookie** wins. The real application refuses a request
 *    without the cookie (the loopback fence), a permissive test double answers everything.
 * 2. then the default port (10748 is what the application picks when it is free).
 * 3. then the lowest port.
 *
 * The candidates are always printed, so a wrong pick is visible and can be pinned with
 * `--dsh-url`.
 *
 * @param {{defaultPort?: number, home?: string, timeoutMs?: number, ports?: number[] | null, log?: (level: string, message: string) => void}} [options]
 * @returns {Promise<string|null>} the base url, or `null` when DSH was not found
 */
export async function discoverDshUrl({
  defaultPort = 10748,
  home = dshHome(),
  timeoutMs = 1500,
  ports = null,
  log = noteLog,
} = {}) {
  const candidates = [...new Set(ports ?? [defaultPort, ...listeningPorts()])].sort((a, b) => a - b);
  const secret = readBrowserSessionSecret(home);
  const probed = await Promise.all(candidates.map(async (port) => {
    const baseUrl = `http://127.0.0.1:${port}`;
    const authed = await probeDshHost(baseUrl, secret, timeoutMs);
    if (!authed.ok) return null;
    // The real application rejects a request without the owner cookie; a permissive test
    // double answers everything. The fenced one is the real thing.
    const anonymous = await probeDshHost(baseUrl, null, timeoutMs);
    return { port, url: baseUrl, fenced: !anonymous.ok };
  }));
  const answers = probed.filter((answer) => answer !== null);
  if (answers.length === 0) {
    log('info', `dsh candidates: none of the ${candidates.length} loopback port(s) answered`);
    return null;
  }
  const fenced = answers.filter((answer) => answer.fenced);
  const pool = fenced.length > 0 ? fenced : answers;
  const winner = pool.find((answer) => answer.port === defaultPort) ?? pool[0];
  const summary = answers.map((answer) => `${answer.port}${answer.fenced ? ' (fenced)' : ''}`).join(', ');
  log('info', `dsh candidates: ${summary} -> ${winner.url}`
    + (answers.length > 1 ? ' (use --dsh-url to pick another one)' : ''));
  if (answers.length > 1 && fenced.length === 0) {
    log('warn', 'several hosts answer like a DSH, none of them checks the owner cookie; '
      + 'the first one is used');
  }
  return winner.url;
}

/**
 * The sequence number of one page record.
 * The DSH wraps every event in a record (`{event, …}`), but a plain event is accepted too.
 */
function recordSeq(record) {
  const seq = record?.event?.seq ?? record?.seq;
  return Number.isFinite(seq) ? seq : null;
}

/**
 * Normalise one page of history.
 *
 * The records are sorted by sequence (oldest first) so the phone can append them as they are,
 * and the range of the page is reported as well: the phone needs it to ask for the next (older)
 * page with `beforeSeq`.
 */
export function normalizePage(value) {
  const records = Array.isArray(value?.records) ? value.records : [];
  const sorted = [...records].sort((a, b) => (recordSeq(a) ?? 0) - (recordSeq(b) ?? 0));
  const seqs = sorted.map(recordSeq).filter((seq) => seq !== null);
  return {
    records: sorted,
    hasMore: Boolean(value?.hasMore),
    oldestSeq: seqs.length > 0 ? Math.min(...seqs) : null,
    newestSeq: seqs.length > 0 ? Math.max(...seqs) : null,
  };
}

/**
 * Read the real cursor out of the DSH's "past cursor" error.
 *
 * The DSH answers a too large cursor with `session page through seq 999 is past cursor 420`;
 * that is the cheapest way to learn the cursor of a session the bridge knows nothing about.
 *
 * @returns {number|null} the cursor, or `null` when the error says nothing about it
 */
export function cursorFromError(error) {
  const message = error instanceof Error ? error.message : String(error ?? '');
  const match = /past cursor\s+(\d+)/u.exec(message);
  if (match === null) return null;
  const cursor = Number.parseInt(match[1], 10);
  return Number.isFinite(cursor) && cursor > 0 ? cursor : null;
}

/**
 * Client for the running DSH desktop application.
 */
export class DshClient {
  /**
   * The DSH application is a single process that also runs the agent, so a request can be slow
   * when it is busy: the session list of a large account takes tens of seconds. The timeout is
   * generous on purpose — the bridge serves the cached rows while a slow refresh runs in the
   * background.
   */
  constructor({
    baseUrl = 'http://127.0.0.1:10748',
    home = dshHome(),
    timeoutMs = 60_000,
    log = null,
    allowRediscovery = false,
    ports = null,
  } = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/u, '');
    this.url = new URL(this.baseUrl);
    this.home = home;
    this.timeoutMs = timeoutMs;
    this.log = log;
    /**
     * May the client look the DSH up again when the port stops answering?
     *
     * Only when the url was found automatically. A pinned url (`--dsh-url`) is the operator's
     * decision, and silently talking to a different host instead would be worse than failing.
     */
    this.allowRediscovery = allowRediscovery;
    /**
     * The ports the re-discovery may probe.
     *
     * `null` means "every port that is listening", which is what the desktop needs. A test can
     * narrow it down to one port.
     */
    this.ports = ports;
    this.secret = null;
    this.cookie = null;
    this.lastError = null;
    /** When the DSH was looked up the last time (throttles the re-discovery). */
    this.lastDiscoverAt = 0;
    /** The in-flight re-discovery, so parallel calls share one lookup. */
    this.rediscovering = null;
  }

  /** The port the DSH was last seen on. */
  get port() {
    return Number(this.url.port) || 10748;
  }

  /**
   * Point the client at another DSH.
   *
   * The owner cookie is bound to the authority (`host:port`), so a new port needs a new cookie.
   */
  setBaseUrl(baseUrl) {
    const next = baseUrl.replace(/\/+$/u, '');
    if (next === this.baseUrl) return false;
    this.baseUrl = next;
    this.url = new URL(next);
    this.secret = null;
    this.cookie = null;
    return true;
  }

  /**
   * Look the DSH up again.
   *
   * A desktop upgrade restarts the application, and it may come back on another port. The
   * discovery runs at most once per cooldown, so a DSH that is simply not running is not
   * hammered with port scans.
   *
   * @returns {Promise<string|null>} the new base url, or `null` when nothing changed
   */
  async rediscover() {
    if (!this.allowRediscovery) return null;
    if (this.rediscovering !== null) return this.rediscovering;
    const wait = this.lastDiscoverAt + REDISCOVER_COOLDOWN_MS - Date.now();
    if (wait > 0) return null;
    this.rediscovering = (async () => {
      this.lastDiscoverAt = Date.now();
      const found = await discoverDshUrl({
        defaultPort: this.port,
        home: this.home,
        ports: this.ports,
        log: (level, message) => this.log?.(level, message) ?? null,
      });
      if (found === null) return null;
      if (!this.setBaseUrl(found)) return null;
      this.log?.('info', `dsh host       : ${found} (found again after the old port stopped answering)`);
      return found;
    })();
    try {
      return await this.rediscovering;
    } finally {
      this.rediscovering = null;
    }
  }

  /** The `host:port` authority DSH binds the cookie to. */
  get authority() {
    return this.url.host;
  }

  /** The cookie header value, minting it on first use. */
  cookieHeader() {
    if (this.cookie === null) {
      const secret = readBrowserSessionSecret(this.home);
      if (secret === null) throw new DshError('dsh/credentials-missing', `no client-connection/browser-session secret in ${path.join(this.home, '.credentials.yaml')}`);
      this.secret = secret;
      this.cookie = mintOwnerCookie(secret, this.authority);
    }
    return this.cookie;
  }

  /** Headers every DSH request must carry. */
  authHeaders() {
    return {
      host: this.authority,
      cookie: this.cookieHeader(),
      'content-type': 'application/json',
      accept: 'application/json',
    };
  }

  /**
   * Call one Typert endpoint.
   *
   * The arguments are wrapped in the endpoint's wire key (`request` by default, `_request` for
   * `session/list`). Endpoints whose arguments are flat get them sent as the fields of
   * `payload.args` directly.
   *
   * @param {string} endpoint
   * @param {Record<string, unknown>} args
   * @param {{timeoutMs?: number}} [options] a longer timeout for the slow endpoints
   */
  async rpc(endpoint, args = {}, options = {}) {
    const key = Object.hasOwn(ARG_KEYS, endpoint) ? ARG_KEYS[endpoint] : 'request';
    const wireArgs = key === null ? { ...args } : { [key]: args };
    const envelope = {
      type: 'client-request',
      rpcId: crypto.randomUUID(),
      method: endpoint,
      payload: { args: wireArgs },
    };
    const send = () => httpRequest({
      url: `${this.baseUrl}/api/${endpoint}`,
      method: 'POST',
      headers: this.authHeaders(),
      body: JSON.stringify(envelope),
      timeoutMs: options.timeoutMs ?? this.timeoutMs,
    });

    let response;
    try {
      response = await send();
    } catch (error) {
      // The port may be gone: a desktop upgrade restarts the DSH, and it can come back on
      // another port. Look it up once more and retry against the new place.
      if (!isConnectionError(error)) throw error;
      const found = await this.rediscover();
      if (found === null) throw error;
      try {
        response = await send();
      } catch {
        // The original error is the meaningful one: the DSH we were pointed at is unreachable.
        // A failed retry must not change how the failure is reported.
        throw error;
      }
    }

    if (response.status === 401) throw new DshError('dsh/unauthorized', 'DSH rejected the bridge credential (401)');
    if (response.status === 403) throw new DshError('dsh/forbidden', 'DSH rejected the request host (403)');
    if (response.status !== 200) throw new DshError('dsh/http-error', `DSH answered HTTP ${response.status} for ${endpoint}`);

    let parsed;
    try {
      parsed = JSON.parse(response.text);
    } catch {
      throw new DshError('dsh/bad-response', `DSH returned a non-JSON body for ${endpoint}`);
    }
    if (parsed?.type !== 'server-response') throw new DshError('dsh/bad-response', `DSH returned an unexpected envelope for ${endpoint}`);
    if (parsed.result?.ok === true) return parsed.result.value;
    const error = parsed.result?.error ?? {};
    throw new DshError(error.code ?? 'dsh/error', error.message ?? `DSH call ${endpoint} failed`, error.details);
  }

  /** Check that DSH is reachable and that the bridge credential is accepted. */
  async probe() {
    try {
      await this.rpc('session/list', {});
      this.lastError = null;
      return { reachable: true, authenticated: true, error: null };
    } catch (error) {
      this.lastError = error;
      const reachable = error instanceof DshError && error.code !== 'dsh/credentials-missing';
      return {
        reachable,
        authenticated: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /** Raw session rows as DSH reports them. */
  async listSessionRows() {
    const value = await this.rpc('session/list', {});
    const items = Array.isArray(value?.items) ? value.items : Array.isArray(value?.sessions) ? value.sessions : [];
    return items;
  }

  /**
   * One history page — the **newest** page by default.
   *
   * The page ends at `throughSeq` (the cursor of the session). The DSH refuses a cursor that is
   * past the real one, so a cursor that is too large is not an error but a source of information:
   * the DSH names the real cursor in the message ("... is past cursor 420") and the page is
   * asked for again with it.
   *
   * A caller that does not know the cursor lets the adapter find it: the projection of the
   * session carries it (`asOfSeq`).
   *
   * @param {string} sessionId
   * @param {{throughSeq?: number|null, beforeSeq?: number, maxMessages?: number, address?: object}} options
   * @returns {Promise<{records: object[], hasMore: boolean, oldestSeq: number|null, newestSeq: number|null}>}
   */
  async pageMessages(sessionId, { throughSeq = null, beforeSeq, maxMessages = 200, address } = {}) {
    const request = {
      address: address ?? { kind: 'session', sessionId },
      maxMessages,
      ...(beforeSeq === undefined ? {} : { beforeSeq }),
    };
    let asked = throughSeq !== null && throughSeq !== undefined ? throughSeq : null;
    if (asked === null) {
      // 没有游标: 问桌面端自己要(投影里的 asOfSeq 就是最新序号)。
      const cursor = await this.sessionCursor(sessionId);
      // 还是不知道的话, 就问一个肯定超过游标的值: DSH 会在错误里说出真实的游标。
      asked = cursor ?? Number.MAX_SAFE_INTEGER;
    }
    try {
      return normalizePage(await this.rpc('session/page', { ...request, throughSeq: asked }));
    } catch (error) {
      const cursor = cursorFromError(error);
      if (cursor === null || cursor === asked) throw error;
      return normalizePage(await this.rpc('session/page', { ...request, throughSeq: cursor }));
    }
  }

  /**
   * The cursor of a session: the sequence number of its newest event.
   *
   * The projection of the session carries it (`asOfSeq`). `null` when the desktop does not
   * answer (an unknown session, or a busy application).
   */
  async sessionCursor(sessionId) {
    try {
      const value = await this.rpc('session/projections', { sessionId });
      const asOf = value?.asOfSeq;
      return Number.isFinite(asOf) && asOf > 0 ? asOf : null;
    } catch {
      return null;
    }
  }

  /** Submit a user instruction that the desktop agent actually executes. */
  async submitPrompt(sessionId, text, { mode = 'queue', requestId = crypto.randomUUID(), clientTimeZone } = {}) {
    const value = await this.rpc('session/prompt', {
      requestId,
      sessionId,
      mode: mode === 'interrupt' || mode === 'steer' ? 'steer' : 'queue',
      content: [{ type: 'text', text: String(text) }],
      ...(clientTimeZone ? { clientTimeZone } : {}),
    });
    return { accepted: value?.accepted === true, requestId };
  }

  /** Cancel the active turn of a session. */
  async cancel(sessionId) {
    const value = await this.rpc('session/cancel', { sessionId });
    return { accepted: value?.accepted === true };
  }

  /**
   * The Workspace of the desktop that owns `path`, or `undefined` when there is none.
   *
   * `workspace/create` is the host's own path → Workspace resolver: it canonicalises the
   * path (through `realpath`), so `D:/app/x` and `D:\app\x` name the same Workspace, and it
   * is idempotent for a directory that already has one (`created: false`). A directory that
   * has none gets one — the same thing the desktop itself does for every session directory
   * it sees.
   *
   * @param {string} path - the directory to resolve.
   * @returns {Promise<{workspaceId: string, path: string, created: boolean}|undefined>}
   */
  async resolveWorkspace(path) {
    if (typeof path !== 'string' || path.trim().length === 0) return undefined;
    const value = await this.rpc('workspace/create', { path: path.trim() });
    const workspace = value?.workspace;
    if (typeof workspace?.workspaceId !== 'string' || workspace.workspaceId.length === 0) return undefined;
    return {
      workspaceId: workspace.workspaceId,
      path: typeof workspace.path === 'string' && workspace.path.length > 0 ? workspace.path : path.trim(),
      created: value?.created === true,
    };
  }

  /**
   * Create a session in `cwd`, in the Workspace that owns that directory.
   *
   * The desktop files a session under a Workspace only when the session is **created** with
   * a `workspaceId`: a session created with a bare `cwd` keeps the right working directory
   * but stays in the desktop's "ungrouped" bucket forever. So the path is resolved to its
   * Workspace first, and the Workspace is what the session is created in.
   *
   * The resolution is best effort. When the desktop cannot answer (an older build, a
   * directory it refuses) the session is created with the plain `cwd`, which is what
   * happened before — the phone still gets its session.
   *
   * @param {{cwd?: string, agentPreset?: string}} options
   * @returns {Promise<{sessionId: string|null, agentPreset: string|null, workspaceId?: string}>}
   */
  async createSession({ cwd, agentPreset } = {}) {
    const directory = typeof cwd === 'string' && cwd.trim().length > 0 ? cwd.trim() : null;
    let workspaceId;
    if (directory !== null) {
      try {
        workspaceId = (await this.resolveWorkspace(directory))?.workspaceId;
      } catch (error) {
        this.log?.('warn', `the workspace of "${directory}" could not be resolved: ${error instanceof Error ? error.message : String(error)}`);
        workspaceId = undefined;
      }
    }
    const create = async (target) => await this.rpc('session/create', {
      ...target,
      ...(agentPreset ? { agentPreset } : {}),
    });
    let value;
    try {
      value = await create(workspaceId === undefined
        ? (directory === null ? {} : { cwd: directory })
        : { workspaceId });
    } catch (error) {
      // The Workspace was deleted between the resolution and the creation. The session is
      // still worth having, so it is created in the plain directory instead.
      if (workspaceId === undefined || error?.code !== 'workspace/not-found') throw error;
      this.log?.('warn', `the workspace "${workspaceId}" is gone; the session is created in the plain directory`);
      value = await create(directory === null ? {} : { cwd: directory });
      workspaceId = undefined;
    }
    return {
      sessionId: value?.sessionId ?? null,
      agentPreset: value?.agentPreset ?? null,
      ...(workspaceId === undefined ? {} : { workspaceId }),
    };
  }

  /** Rename a session. */
  async renameSession(sessionId, title) {
    await this.rpc('session/rename', { sessionId, title });
    return { ok: true };
  }

  /**
   * The projection baseline of a session (its inbox, model selection, permissions, …).
   *
   * The DSH application currently answers this endpoint with "build context fail" for
   * every session, and the same data already rides along with `session/list` (every row
   * carries its own `projections`). So this call is a *best effort*: when it fails the
   * caller falls back to the projections from the session list instead of failing the
   * whole request. A failing projection must never take the session tree, the pending
   * counter or the push-token registration down with it.
   */
  async projections(sessionId) {
    try {
      const value = await this.rpc('session/projections', { sessionId });
      if (value !== null && value !== undefined) return value;
    } catch (error) {
      this.log?.('warn', `the projections of ${sessionId} could not be read: ${error instanceof Error ? error.message : String(error)}`);
    }
    return null;
  }

  /** The catalog of the models that can be selected. */
  async modelCatalog() {
    return this.rpc('session/modelCatalog', {});
  }

  /** Select the model of a session. */
  async selectModel(sessionId, { provider, model, reasoningEffort } = {}) {
    const value = await this.rpc('session/selectModel', {
      sessionId,
      provider,
      model,
      ...(reasoningEffort === undefined ? {} : { reasoningEffort }),
    });
    return value?.selected ?? { provider, model, ...(reasoningEffort === undefined ? {} : { reasoningEffort }) };
  }

  /** Mutate one queued item of a session (edit, remove or steer it). */
  async updateQueue(sessionId, itemId, action) {
    await this.rpc('session/updateQueue', { sessionId, itemId, action });
    return { ok: true };
  }

  /**
   * Answer the desktop's open question(s) of one ask call.
   *
   * DSH steers the answer into the agent as a user message and closes the question in the
   * projection; `answers` is [{ id, selected: string[], custom?: string }].
   */
  async answerQuestions(sessionId, callId, answers) {
    // DSH 返回 boolean: true = 这条提问真的被接住并关闭了, false = 没人接
    // (前台等待中的提问只有当前前台客户端能答, 别的客户端 call 会静默 false)。
    const value = await this.rpc('userQuestions/answer', {
      agentId: sessionId,
      callId,
      answer: { answers },
    });
    return value === true;
  }

  /** The slash commands of the desktop application. */
  async listCommands(agentId) {
    const value = await this.rpc('commands/list', { agentId });
    return Array.isArray(value) ? value : [];
  }

  /**
   * The skills a session can use.
   *
   * DSH collects the skills from every provider on the machine, which takes far longer than a
   * normal call (tens of seconds on a cold session) — so this call gets its own, longer timeout.
   */
  async listSkills(sessionId) {
    const value = await this.rpc('skills/list', { sessionId }, { timeoutMs: 120_000 });
    return Array.isArray(value?.skills) ? value.skills : [];
  }

  /** The agent presets the desktop offers (the "mode" of a new conversation). */
  async agentPresets() {
    return this.rpc('agentPresets/list', {});
  }
  /** The permission presets the desktop application offers. */
  async permissionPresets() {
    const value = await this.rpc('permissionPresets/catalog', {});
    return {
      options: Array.isArray(value?.options) ? value.options : [],
      defaultOptions: Array.isArray(value?.defaultOptions) ? value.defaultOptions : [],
      defaultPreset: typeof value?.defaultPreset === 'string' ? value.defaultPreset : null,
    };
  }

  /**
   * Run a slash command in a session (without sending anything to the model).
   *
   * This is the same write path the desktop's own permission capsule uses: the web client
   * submits `/permission <preset>` to the live session, the host's command registry resolves it
   * and the handler appends the permission knob events.
   *
   * @param {string} sessionId the session (agent) the command runs in
   * @param {string} line the complete slash-command line, e.g. `/permission workspace-write`
   * @returns {{ok: boolean, text: string}}
   */
  async executeCommand(sessionId, line) {
    const value = await this.rpc('commands/execute', {
      agentId: sessionId,
      line: String(line),
      submittedAttachments: [],
    });
    const result = value?.result ?? null;
    if (result === null) {
      // The host resolves nothing for an unknown name or a syntax error.
      return { ok: false, text: `the host does not know the command "${line}"` };
    }
    return {
      ok: result.kind === 'success',
      text: typeof result.text === 'string' ? result.text : '',
    };
  }

  /**
   * Switch the permission preset of a session.
   *
   * The DSH remote surface has no `setPermission`; the write path is the `/permission` command
   * that the desktop's permission capsule uses (see `docs/ACCOUNT.md` / the DSH package
   * `@deepseek-ai/dsh-permission-presets`). The command handler appends the three knob events
   * (`permission/preset`, `sandbox/mode`, `approval/policy`), so the session's projected
   * permission really changes.
   *
   * @param {string} sessionId the session to change
   * @param {string} preset one of the names of `permissionPresets/catalog`
   * @returns {{ok: boolean, preset: string, text: string}}
   */
  async setSessionPermission(sessionId, preset) {
    const name = String(preset ?? '').trim();
    if (name.length === 0) throw new DshError('dsh/invalid-permission', 'the permission preset must not be empty');
    const result = await this.executeCommand(sessionId, `/permission ${name}`);
    if (!result.ok) {
      throw new DshError('dsh/permission-rejected', result.text.length > 0 ? result.text : `the permission preset "${name}" was rejected`);
    }
    return { ok: true, preset: name, text: result.text };
  }

  /** The files that can be referenced with `@` in a session. */
  async listFileReferences(agentId, query) {
    const value = await this.rpc('fileReferences/list', { agentId, query });
    return Array.isArray(value) ? value : [];
  }

  /**
   * Open a `session/follow` stream over the `/api/remote.mux` WebSocket carrier.
   * `handlers` receives `{ snapshot, event, delta, error }` callbacks.
   * Returns `{ close() }`.
   */
  async openFollow(sessionId, handlers = {}, { maxMessages = 200, address } = {}) {
    const target = new URL(this.baseUrl);
    target.protocol = target.protocol === 'https:' ? 'wss:' : 'ws:';
    target.pathname = '/api/remote.mux';
    target.search = '';

    const client = new WebSocketClient(target.href, {
      headers: { Cookie: this.cookieHeader(), Host: this.authority },
    });
    const streamId = crypto.randomUUID();

    client.on('message', (text) => {
      let frame;
      try {
        frame = JSON.parse(text);
      } catch {
        return;
      }
      if (frame?.streamId !== undefined && frame.streamId !== streamId) return;
      if (frame?.type === 'item') {
        const value = frame.value;
        if (value?.type === 'snapshot') handlers.onSnapshot?.(value);
        else if (value?.type === 'event') handlers.onEvent?.(value.event);
        else if (value?.type === 'assistant-stream') handlers.onDelta?.(value.frame);
        return;
      }
      if (frame?.type === 'error') handlers.onError?.(frame.error);
    });
    client.on('error', (error) => handlers.onError?.({ code: 'dsh/stream-error', message: error.message }));
    client.on('close', () => handlers.onClose?.());

    /* Keepalive: 每 20 秒发一个 WebSocket ping。
       这条链路是 bridge → relay → DSH，中间任何一跳有空闲超时，
       都会把「等着 agent 慢慢回话」的长连接掐掉 ——
       实测：首条回复 8~11 秒时逐字帧正常，200 秒时逐字帧全丢（0 个 delta），
       表现就是「等得越久，回传越少」。ping 让连接不会被当成空闲连接回收。
       BRIDGE_FOLLOW_PING_MS=0 可以关掉它（用来做 A/B 对照）。 */
    const pingMs = Number(process.env.BRIDGE_FOLLOW_PING_MS || 20000);
    const keepAlive = pingMs > 0 ? setInterval(() => {
      try { client.ping(); } catch { /* 连接已经没了，等 close 事件处理 */ }
    }, pingMs) : null;
    keepAlive?.unref?.();

    await client.connect();
    client.send(JSON.stringify({
      type: 'open',
      streamId,
      endpoint: 'session/follow',
      payload: {
        args: {
          request: {
            address: address ?? { kind: 'session', sessionId },
            assistantStream: true,
            maxMessages,
          },
        },
      },
    }));

    return {
      streamId,
      close() {
        if (keepAlive) clearInterval(keepAlive);
        try {
          client.send(JSON.stringify({ type: 'cancel', streamId }));
        } catch {
          // The carrier may already be gone.
        }
        client.close();
      },
    };
  }
}

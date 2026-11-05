// LAN discovery and pairing of the desktop bridge.
//
// The problem this solves: a phone on the same network does not know which of the (many)
// computers runs the bridge. The answer is built into the network itself: a computer that does
// not run the bridge does not answer `GET /_dsh/discover` at all, so the phone only ever sees
// the machines that really have the desktop agent.
//
// The discovery endpoint cannot require the token (the phone is not paired yet) and therefore
// only returns harmless information: the name of the machine, its address and a short lived
// pairing code. The token itself is handed out by `POST /api/v1/pair`, which checks that code.
//
// Everything here is built on the node: builtins only, no dependencies.

import crypto from 'node:crypto';
import os from 'node:os';

import { PROTOCOL_VERSION, SERVER_NAME } from './protocol.js';

/** The discovery endpoint (no token). */
export const DISCOVER_PATH = '/_dsh/discover';

/** The endpoint that exchanges the pairing code for the token (no token). */
export const PAIR_PATH = '/api/v1/pair';

/** The endpoint the phone asks for the cloud relay configuration (token required). */
export const REMOTE_CONFIG_PATH = '/api/v1/remote-config';

/** How long a pairing code stays valid. */
export const DEFAULT_CODE_TTL_MS = 60_000;

/** How many wrong codes are tolerated before the code is replaced. */
export const MAX_CODE_ATTEMPTS = 5;

/** Compare two strings without leaking their content through timing. */
function timingSafeEquals(a, b) {
  const left = Buffer.from(String(a), 'utf8');
  const right = Buffer.from(String(b), 'utf8');
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

/**
 * A short pairing code that rotates on its own.
 *
 * * it is valid for `ttlMs` (60 seconds by default);
 * * it is **single use**: a successful check replaces it immediately;
 * * too many wrong guesses replace it as well, so a brute force cannot keep hammering one
 *   code for a whole minute.
 */
export class PairingCode {
  constructor({ ttlMs = DEFAULT_CODE_TTL_MS, digits = 6, now = () => Date.now() } = {}) {
    this.ttlMs = ttlMs;
    this.digits = digits;
    this.now = now;
    this.code = '';
    this.expiresAt = 0;
    this.attempts = 0;
    this.#generate();
  }

  #generate() {
    const max = 10 ** this.digits;
    this.code = String(crypto.randomInt(max)).padStart(this.digits, '0');
    this.expiresAt = this.now() + this.ttlMs;
    this.attempts = 0;
  }

  /** The current code. A new one is generated when the old one expired. */
  current() {
    if (this.now() >= this.expiresAt) this.#generate();
    return { code: this.code, expiresAt: this.expiresAt };
  }

  /**
   * Check a code.
   *
   * @param {string} code the code the phone sent
   * @returns {boolean} `true` when the code was right (it is then replaced)
   */
  verify(code) {
    const current = this.current();
    const candidate = String(code ?? '').trim();
    if (!timingSafeEquals(candidate, current.code)) {
      this.attempts += 1;
      if (this.attempts >= MAX_CODE_ATTEMPTS) this.#generate();
      return false;
    }
    this.#generate();
    return true;
  }
}

/**
 * The relay base url of the phone side.
 *
 * The device handshake of the relay happens on the relay port; a relay that terminates TLS for
 * the phone usually listens on another port, so `--relay-public-url` overrides the derived one.
 * (Same rule as `relayHttpBase()` in `router.js`; it is repeated here so that this module stays
 * independent of the rest of the bridge.)
 */
function relayHttpBase(relayUrl, publicUrl, lanHost = '') {
  if (publicUrl !== null && publicUrl !== undefined && String(publicUrl).length > 0) {
    return String(publicUrl).replace(/\/+$/u, '');
  }
  const url = new URL(relayUrl);
  const protocol = url.protocol === 'wss:' ? 'https:' : url.protocol === 'ws:' ? 'http:' : url.protocol;
  // A relay that runs on this machine is reached through the loopback address, which the
  // phone cannot use — the LAN address is the one that works from a phone.
  const loopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '::1';
  const host = loopback && typeof lanHost === 'string' && lanHost.length > 0 ? lanHost : url.hostname;
  const port = url.port.length > 0 ? `:${url.port}` : '';
  return `${protocol}//${host}${port}`;
}

/**
 * The discovery and pairing service of one bridge.
 *
 * It only reads the bridge options and the state file, so it can be created without starting
 * anything else.
 */
export class DiscoveryService {
  constructor({ options = {}, state = {}, log = () => {}, codeTtlMs = DEFAULT_CODE_TTL_MS, now = () => Date.now() } = {}) {
    this.options = options ?? {};
    this.state = state ?? {};
    this.log = log;
    this.code = new PairingCode({ ttlMs: codeTtlMs, now });
    this.announced = '';
  }

  /** The name of this machine as the phone should show it. */
  get name() {
    const relayName = this.options.relayName;
    if (typeof relayName === 'string' && relayName.length > 0) return relayName;
    return os.hostname();
  }

  /** The host the phone has to use to reach this bridge. */
  get host() {
    const host = this.options.pairingHost;
    if (typeof host === 'string' && host.length > 0) return host;
    return '127.0.0.1';
  }

  /** The port the bridge listens on. */
  get port() {
    const port = Number(this.options.port);
    return Number.isInteger(port) && port > 0 ? port : 8787;
  }

  /** The address the phone has to use to reach this bridge. */
  get url() {
    return `http://${this.host}:${this.port}`;
  }

  /**
   * The current pairing code, printed to the console the first time it is used.
   *
   * The code rotates on its own, so the console always shows the code that is valid right now.
   */
  currentCode() {
    const current = this.code.current();
    if (current.code !== this.announced) {
      this.announced = current.code;
      const seconds = Math.max(1, Math.round((current.expiresAt - this.code.now()) / 1000));
      this.log('info', `pairing code : ${current.code} (valid for ${seconds} s, the phone can also ask GET ${DISCOVER_PATH})`);
    }
    return current;
  }

  /**
   * `GET /_dsh/discover` — the answer of "is there a desktop agent on this machine?".
   *
   * Only harmless information, plus the short lived pairing code.
   */
  discover() {
    const { code, expiresAt } = this.currentCode();
    return {
      name: this.name,
      version: PROTOCOL_VERSION,
      server: SERVER_NAME,
      url: this.url,
      host: this.host,
      port: this.port,
      code,
      expiresAt,
    };
  }

  /**
   * `POST /api/v1/pair` — exchange the pairing code for the token.
   *
   * @param {string} code the code the phone sent
   * @returns {{ok: true, token: string, url: string, name: string} | {ok: false, reason: string}}
   */
  pair(code) {
    if (!this.code.verify(code)) {
      return { ok: false, reason: '配对码无效或已过期' };
    }
    return { ok: true, token: this.state.token, url: this.url, name: this.name };
  }

  /**
   * `GET /api/v1/remote-config` — everything the phone needs to switch to the cloud relay.
   *
   * The phone keeps the bridge token (the relay forwards the `Authorization` header to the
   * bridge unchanged), so switching is only a matter of pointing the phone at the relay.
   */
  remoteConfig() {
    const relay = this.options.relay ?? null;
    if (relay === null || String(relay).length === 0) {
      return { available: false, reason: '桌面端没有配置云中继' };
    }
    const accountId = String(this.options.account ?? '');
    const deviceId = String(this.options.deviceId ?? '');
    const base = relayHttpBase(relay, this.options.relayPublicUrl ?? null, this.host);
    const prefix = accountId.length > 0 ? `/${accountId}/${deviceId}` : `/${deviceId}`;
    // The phone must not build the WebSocket address itself: the relay has its own route for
    // the phone side (`/<deviceId>/ws`) and the scheme follows the public url (wss on the internet).
    const wsBase = base.replace(/^http:/u, 'ws:').replace(/^https:/u, 'wss:');
    // **双通道**: 主地址可能走 Cloudflare 隧道(隐藏源站 IP, 但国内到 CF 边缘偶尔超时),
    // 再给一个直连地址兜底 —— 手机先试主地址, 超时就自动回落, 用户不用管。
    const directBase = relayHttpBase(relay, null, this.host);
    const directWsBase = directBase.replace(/^http:/u, 'ws:').replace(/^https:/u, 'wss:');
    const hasFallback = directBase !== base;
    return {
      available: true,
      relayUrl: `${base}${prefix}`,
      wsUrl: `${wsBase}/${deviceId}/ws`,
      ...(hasFallback
        ? { fallbackRelayUrl: `${directBase}${prefix}`, fallbackWsUrl: `${directWsBase}/${deviceId}/ws` }
        : {}),
      token: this.state.token,
      accountId,
      deviceId,
      name: this.name,
    };
  }
}

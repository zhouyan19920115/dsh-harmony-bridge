// Desktop-side outbound relay client (docs/RELAY.md).
//
// The phone cannot reach the desktop over the LAN any more (CGNAT, no port forwarding), so the
// desktop dials the cloud relay *out*, the phone dials the relay too and the relay splices the
// two byte streams. This file is the device half of that protocol:
//
//   * it opens one WebSocket to `ws://<relay>/bridge?token=…&deviceId=…`,
//   * it says `HELLO` and waits for `HELLO_OK`,
//   * it answers the relay's `OPEN` requests by connecting to its own local HTTP server
//     (`127.0.0.1:<bridgePort>` — nothing else is allowed, the relay must not be able to use the
//     desktop as a jump host into the LAN),
//   * and it pumps the bytes of every stream through the relay with `DATA` frames.
//
// The WebSocket transport is the one of `ws.js` (the hand rolled RFC 6455 implementation the
// bridge already uses for the DSH carrier): this file only adds what the relay protocol needs
// and `ws.js` does not have — binary frames and TLS. No second WebSocket implementation.

import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';
import os from 'node:os';
import dns from 'node:dns/promises';
import { EventEmitter } from 'node:events';

import { FrameParser, OPCODE, WebSocketClient, acceptKey, encodeFrame } from './ws.js';

/* ------------------------------------------------------------------ protocol constants */

/** Frame types of the relay protocol (docs/RELAY.md §3.1). */
export const RELAY_TYPE = Object.freeze({
  OPEN: 0x01,
  OPEN_OK: 0x02,
  OPEN_ERR: 0x03,
  DATA: 0x04,
  CLOSE: 0x05,
  HELLO: 0x10,
  HELLO_OK: 0x11,
  PING: 0x12,
  PONG: 0x13,
});

/** `streamId (4B BE) | type (1B) | length (4B BE) | payload` (docs/RELAY.md §3). */
export const RELAY_HEADER_SIZE = 9;

/** The maximum payload of a single `DATA` frame; bigger writes are split (docs/RELAY.md §3.2). */
export const MAX_DATA_PAYLOAD = 256 * 1024;

/** Reconnect backoff bounds (2 s → 30 s). */
export const DEFAULT_RECONNECT_MIN_MS = 2000;
export const DEFAULT_RECONNECT_MAX_MS = 30000;

/**
 * How long one address may take before the next one is tried.
 *
 * A handshake through a CDN is a second or two; a black holed address never answers at all. So
 * the wait has to be long enough for the slow case and short enough that the bad case does not
 * hold the whole connect up.
 */
export const CONNECT_ATTEMPT_TIMEOUT_MS = 12000;

/** How many addresses of the relay are tried before the connect is given up. */
export const MAX_CONNECT_ATTEMPTS = 3;

/**
 * The heartbeat of the relay connection.
 *
 * A connection that is idle looks dead to the middle boxes on the way (Cloudflare drops a
 * WebSocket that says nothing for a while), and a connection that is half open looks alive
 * to this process. So the device pings the relay every {@link DEFAULT_HEARTBEAT_INTERVAL_MS}
 * and reconnects when the pongs stop coming.
 *
 * Ten seconds, not twenty five: behind a CDN or a tunnel the boxes on the way cut a line
 * that says nothing for ~20-30 s, and a 25 s heartbeat sits right on that edge — the
 * connection then drops every minute or two. Ten seconds is cheap and keeps the line busy.
 */
export const DEFAULT_HEARTBEAT_INTERVAL_MS = 10000;

/** How many heartbeats in a row may go unanswered before the connection is redialled. */
export const DEFAULT_HEARTBEAT_MAX_MISSES = 3;

/* ------------------------------------------------------------------------- frame codec */

/**
 * Encode one relay frame.
 * `streamId (4B BE) | type (1B) | length (4B BE) | payload`.
 */
export function encodeRelayFrame(streamId, type, payload = Buffer.alloc(0)) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
  const frame = Buffer.allocUnsafe(RELAY_HEADER_SIZE + body.length);
  frame.writeUInt32BE(streamId >>> 0, 0);
  frame.writeUInt8(type & 0xff, 4);
  frame.writeUInt32BE(body.length, 5);
  body.copy(frame, RELAY_HEADER_SIZE);
  return frame;
}

/**
 * Decode one relay frame out of `buffer`.
 * Returns `null` when the buffer does not hold a complete frame yet.
 */
export function decodeRelayFrame(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < RELAY_HEADER_SIZE) return null;
  const streamId = buffer.readUInt32BE(0);
  const type = buffer.readUInt8(4);
  const length = buffer.readUInt32BE(5);
  if (buffer.length < RELAY_HEADER_SIZE + length) return null;
  return { streamId, type, payload: Buffer.from(buffer.subarray(RELAY_HEADER_SIZE, RELAY_HEADER_SIZE + length)) };
}

/**
 * An incremental relay frame decoder.
 * The relay frames travel inside binary WebSocket messages; this decoder copes with a frame that
 * is split over several messages and with several frames inside one message.
 */
export class RelayFrameDecoder {
  constructor() {
    this.buffer = Buffer.alloc(0);
  }

  /** Feed bytes, get back every complete frame. */
  push(chunk) {
    this.buffer = this.buffer.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.buffer, chunk]);
    const frames = [];
    for (;;) {
      const frame = decodeRelayFrame(this.buffer);
      if (frame === null) break;
      this.buffer = this.buffer.subarray(RELAY_HEADER_SIZE + frame.payload.length);
      frames.push(frame);
    }
    return frames;
  }
}

/**
 * Build the URL of the device connection (docs/RELAY.md §2.1).
 * The token and the device id travel in the query string because the handshake cannot carry
 * custom headers.
 *
 * With an account the handshake carries it as well (docs/ACCOUNT.md §4):
 *
 *   * `accountId` — the account the device belongs to;
 *   * `accountToken` — the secret of that account. A device that presents it joins the account
 *     when it is not registered yet.
 *
 * @param {string} baseUrl the relay url
 * @param {{deviceToken: string, deviceId: string, accountId?: string, accountToken?: string}} options
 * @returns {URL}
 */
export function buildRelayUrl(baseUrl, { deviceToken, deviceId, accountId = null, accountToken = null }) {
  const url = new URL(baseUrl);
  if (url.protocol !== 'ws:' && url.protocol !== 'wss:') {
    throw new Error(`the relay URL must use ws:// or wss:// (got "${url.protocol}")`);
  }
  if (!url.pathname || url.pathname === '/') url.pathname = '/bridge';
  // The tokens do NOT travel through the url: a query string ends up in the access log of every
  // proxy on the way, and the relay is the one place that must not see them in the clear. The
  // device authenticates with its first frame instead (see `RelayClient#connect`).
  url.searchParams.set('deviceId', deviceId);
  if (accountId) url.searchParams.set('accountId', accountId);
  return url;
}

/**
 * Build the handshake header that carries the secrets of the device.
 *
 * The relay reads the device token and the account token from the `Sec-WebSocket-Protocol`
 * header of the handshake (`dsh-device.<token>`, `dsh-account.<token>`), because a token in the
 * url of the handshake ends up in the access log of every proxy on the way.
 *
 * The contract is mirrored in `relay/src/relay-protocol.js` (the relay is a separate program).
 *
 * @param {{deviceToken: string, accountToken?: string|null, accountId?: string|null}} options
 * @returns {string} the value of the `Sec-WebSocket-Protocol` header
 */
export function buildRelayProtocolHeader({ deviceToken, accountToken = null, accountId = null }) {
  const parts = [];
  if (typeof deviceToken === 'string' && deviceToken.length > 0) parts.push(`dsh-device.${deviceToken}`);
  if (typeof accountToken === 'string' && accountToken.length > 0) parts.push(`dsh-account.${accountToken}`);
  if (typeof accountId === 'string' && accountId.length > 0) parts.push(`dsh-account-id.${accountId}`);
  return parts.join(', ');
}

/**
 * The address the phone has to type in its "桌面端地址" field.
 *
 * The relay's phone side port is not part of the device handshake, so the relay port is used as
 * the best guess; when the relay terminates TLS on a separate phone side port the operator has to
 * replace the port (and the scheme) by hand.
 *
 * With an account the url carries it: `http://host:port/<accountId>/<deviceId>`. The phone app
 * treats everything behind the host as the path prefix, so it works without a change.
 *
 * @param {string} baseUrl the relay url
 * @param {string} deviceId the device id
 * @param {string} [accountId] the account id
 * @param {string} [publicUrl] the public base url of the relay (overrides the derived one)
 */
export function relayPhoneUrl(baseUrl, deviceId, accountId = null, publicUrl = null) {
  if (publicUrl) {
    const base = String(publicUrl).replace(/\/+$/u, '');
    return accountId ? `${base}/${accountId}/${deviceId}` : `${base}/${deviceId}`;
  }
  const url = new URL(baseUrl);
  const port = url.port || (url.protocol === 'wss:' ? '443' : '80');
  const scheme = url.protocol === 'wss:' ? 'https' : 'http';
  return accountId
    ? `${scheme}://${url.hostname}:${port}/${accountId}/${deviceId}`
    : `${scheme}://${url.hostname}:${port}/${deviceId}`;
}

/* --------------------------------------------------------------------- websocket layer */

/**
 * A `FrameParser` that also surfaces the binary frames.
 *
 * `WebSocketClient` only emits text messages, but the relay protocol is binary, so the parser
 * collects the binary payloads (and reassembles the fragments of a fragmented message) and hands
 * them over to `onBinary`.
 */
class BinaryFrameParser extends FrameParser {
  constructor(options) {
    super(options);
    this.onBinary = null;
    this.fragments = [];
  }

  push(chunk) {
    const frames = super.push(chunk);
    const others = [];
    for (const frame of frames) {
      if (frame.opcode !== OPCODE.BINARY && frame.opcode !== OPCODE.CONTINUATION) {
        others.push(frame);
        continue;
      }
      if (frame.opcode === OPCODE.BINARY) this.fragments = [];
      this.fragments.push(frame.payload);
      if (!frame.fin) continue;
      const payload = Buffer.concat(this.fragments);
      this.fragments = [];
      if (this.onBinary) this.onBinary(payload);
    }
    return others;
  }
}

/**
 * The WebSocket client of the relay connection.
 *
 * It extends the bridge's `WebSocketClient` with the two things the relay protocol needs and
 * `ws.js` does not have: binary frames and TLS.
 */
export class RelayWebSocketClient extends WebSocketClient {
  constructor(url, options = {}) {
    super(url, options);
    const maxPayload = options.maxPayload ?? 32 * 1024 * 1024;
    this.parser = new BinaryFrameParser({ requireMask: false, maxPayload });
    this.parser.onBinary = (payload) => this.emit('binary', payload);
  }

  /** Send a binary message (the relay frames travel inside binary WebSocket messages). */
  sendBinary(payload) {
    if (this.closed || !this.socket) return;
    const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
    this.socket.write(encodeFrame(OPCODE.BINARY, body, { mask: true }));
  }
}

/**
 * The TLS flavour of {@link RelayWebSocketClient}.
 *
 * `ws.js` speaks plain `ws://` over `net.connect` only and must not be edited, so the handshake
 * is repeated here on top of `tls.connect`. The frame codec itself is still the one of `ws.js`
 * (`acceptKey`, `FrameParser`, `encodeFrame`).
 */
export class TlsRelayWebSocketClient extends RelayWebSocketClient {
  constructor(url, options = {}) {
    super(url, options);
    this.rejectUnauthorized = options.rejectUnauthorized ?? true;
    // The trust anchor of a self signed relay certificate (PEM). The certificate is still
    // verified, `rejectUnauthorized` stays on.
    this.ca = options.ca ?? null;
    /** The certificate of the relay (filled after the handshake). */
    this.certificate = null;
  }

  connect() {
    if (this.url.protocol !== 'wss:') return super.connect();
    return this.#connectToAnyAddress();
  }

  /**
   * Try every address of the relay, one after the other.
   *
   * Why: the relay may sit behind a CDN, and a CDN hands out many addresses. From some routes
   * one of them is a black hole — the TCP handshake goes through, but the TLS handshake never
   * answers, so the connect hangs until the timeout. Trying the next address turns that hang
   * into a fast success ✓.
   */
  async #connectToAnyAddress() {
    const addresses = (await this.#resolveAddresses()).slice(0, MAX_CONNECT_ATTEMPTS);
    const failures = [];
    for (const address of addresses) {
      try {
        return await this.#connectTo(address);
      } catch (error) {
        failures.push(`${address}: ${error?.message ?? error}`);
      }
    }
    const reason = failures.length > 0 ? failures.join(' | ') : 'no address to try';
    throw new Error(`websocket connect to ${this.url.href} failed (${reason})`);
  }

  /** The addresses of the relay: the ones the resolver gives, the name itself as a fallback. */
  async #resolveAddresses() {
    try {
      const found = await dns.lookup(this.url.hostname, { all: true, verbatim: true });
      if (found.length > 0) return found.map((entry) => entry.address);
    } catch {
      // The resolver is unhappy — the normal connect will report the real problem.
    }
    return [this.url.hostname];
  }

  /** One TLS + WebSocket handshake against one address. */
  #connectTo(address) {
    const url = this.url;
    return new Promise((resolve, reject) => {
      const key = crypto.randomBytes(16).toString('base64');
      const socket = tls.connect({
        host: address,
        port: Number(url.port || 443),
        // SNI must not carry an IP address, Node refuses such a handshake.
        servername: net.isIP(url.hostname) === 0 ? url.hostname : undefined,
        rejectUnauthorized: this.rejectUnauthorized,
        ...(this.ca ? { ca: this.ca } : {}),
      });
      this.socket = socket;

      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error(`websocket connect to ${url.href} (via ${address}) timed out`));
      }, CONNECT_ATTEMPT_TIMEOUT_MS);
      timer.unref?.();

      let settled = false;
      const fail = (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        reject(error);
      };

      socket.on('error', (error) => {
        if (settled) {
          this.#emitClose();
          return;
        }
        fail(error);
      });

      socket.on('secureConnect', () => {
        this.certificate = describeCertificate(socket.getPeerCertificate());
        const lines = [
          `GET ${url.pathname}${url.search} HTTP/1.1`,
          `Host: ${url.host}`,
          'Upgrade: websocket',
          'Connection: Upgrade',
          `Sec-WebSocket-Key: ${key}`,
          'Sec-WebSocket-Version: 13',
        ];
        for (const [name, value] of Object.entries(this.headers)) lines.push(`${name}: ${value}`);
        lines.push('\r\n');
        socket.write(lines.join('\r\n'));
      });

      let handshake = Buffer.alloc(0);
      const onHandshake = (chunk) => {
        handshake = Buffer.concat([handshake, chunk]);
        const end = handshake.indexOf('\r\n\r\n');
        if (end === -1) return;
        socket.removeListener('data', onHandshake);
        const head = handshake.subarray(0, end).toString('latin1');
        const rest = handshake.subarray(end + 4);
        const statusLine = head.split('\r\n')[0] ?? '';
        if (!/ 101 /u.test(statusLine)) {
          fail(new Error(`websocket handshake failed: ${statusLine.trim()}`));
          return;
        }
        const accept = /sec-websocket-accept:\s*(\S+)/iu.exec(head)?.[1];
        if (accept !== acceptKey(key)) {
          fail(new Error('websocket handshake failed: bad Sec-WebSocket-Accept'));
          return;
        }
        clearTimeout(timer);
        socket.on('data', (data) => this.#onData(data));
        socket.on('close', () => this.#emitClose());
        if (rest.length > 0) this.#onData(rest);
        this.handshakeDone = true;
        settled = true;
        this.emit('open');
        resolve(this);
      };
      socket.on('data', onHandshake);
    });
  }

  #onData(chunk) {
    let frames;
    try {
      frames = this.parser.push(chunk);
    } catch (error) {
      this.emit('error', error);
      this.close();
      return;
    }
    for (const frame of frames) {
      if (frame.opcode === OPCODE.TEXT) this.emit('message', frame.payload.toString('utf8'));
      else if (frame.opcode === OPCODE.PING) this.pong(frame.payload);
      else if (frame.opcode === OPCODE.CLOSE) {
        this.socket?.end();
        this.#emitClose();
      }
    }
  }

  #emitClose() {
    if (this.tornDown) return;
    this.tornDown = true;
    this.emit('close');
  }
}

/* --------------------------------------------------------------------- the relay client */

/** Split `"<host>:<port>"` into its two parts; `null` when the text is malformed. */
export function parseTarget(value) {
  const text = String(value ?? '').trim();
  const at = text.lastIndexOf(':');
  if (at <= 0) return null;
  const host = text.slice(0, at);
  const port = Number.parseInt(text.slice(at + 1), 10);
  if (host.length === 0) return null;
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
  return { host, port };
}

/**
 * Describe the certificate of the relay.
 * The SHA256 fingerprint is what the phone pins, the subject is what the user compares.
 */
export function describeCertificate(peer) {
  if (!peer || !peer.raw) return null;
  const fingerprint = crypto.createHash('sha256').update(peer.raw).digest('hex').toUpperCase();
  const subject = peer.subject
    ? Object.entries(peer.subject)
      .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(',') : value}`)
      .join(' ')
    : '';
  return { fingerprint, subject, altNames: peer.subjectaltname ?? '' };
}

/**
 * The desktop side of the cloud relay.
 *
 * Events: `connected` (the `HELLO_OK` arrived), `disconnected` (the connection was lost) and
 * `error`. `status()` reports what the banner needs.
 */
export class RelayClient extends EventEmitter {
  /** Is the device registered at the relay right now? */
  #connected = false;

  constructor({
    url,
    deviceToken,
    deviceId,
    name = os.hostname(),
    accountId = null,
    accountToken = null,
    bridgeToken = null,
    targetPort,
    log = () => {},
    reconnectMinMs = DEFAULT_RECONNECT_MIN_MS,
    reconnectMaxMs = DEFAULT_RECONNECT_MAX_MS,
    heartbeatIntervalMs = DEFAULT_HEARTBEAT_INTERVAL_MS,
    heartbeatMaxMisses = DEFAULT_HEARTBEAT_MAX_MISSES,
    handshakeTimeoutMs = 10000,
    rejectUnauthorized = true,
    ca = null,
  } = {}) {
    super();
    if (!url) throw new Error('the relay URL is required');
    if (!deviceToken) throw new Error('the device token is required');
    if (!deviceId) throw new Error('the device id is required');
    if (!Number.isInteger(Number(targetPort)) || Number(targetPort) <= 0) {
      throw new Error('the local bridge port is required');
    }

    this.baseUrl = new URL(url);
    this.url = buildRelayUrl(url, { deviceToken, deviceId, accountId, accountToken });
    this.deviceToken = deviceToken;
    this.deviceId = deviceId;
    this.name = name;
    this.accountId = accountId;
    this.accountToken = accountToken;
    /**
     * The token the phone of this bridge holds.
     *
     * The relay keeps only its hash and uses it to tell whether a client that connects to the
     * phone side of the relay really is the phone of this bridge.
     */
    this.bridgeToken = typeof bridgeToken === 'string' && bridgeToken.length > 0 ? bridgeToken : null;
    this.targetPort = Number(targetPort);
    this.log = log;
    this.reconnectMinMs = reconnectMinMs;
    this.reconnectMaxMs = reconnectMaxMs;
    this.heartbeatIntervalMs = heartbeatIntervalMs;
    this.heartbeatMaxMisses = heartbeatMaxMisses;
    this.handshakeTimeoutMs = handshakeTimeoutMs;
    this.rejectUnauthorized = rejectUnauthorized;
    // The trust anchor of a self signed relay certificate (PEM). `rejectUnauthorized` stays on.
    this.ca = ca;

    this.client = null;
    this.streams = new Map();
    this.decoder = new RelayFrameDecoder();
    this.lastError = null;
    this.since = null;
    this.stopped = true;
    this.backoffMs = reconnectMinMs;
    this.reconnectTimer = null;
    this.wake = null;
    this.loop = null;
    this.handshake = null;
    this.handshakeTimer = null;
    /** The timer of the heartbeat (a ping every `heartbeatIntervalMs`). */
    this.heartbeatTimer = null;
    /** A ping is on the way and no pong came back yet. */
    this.heartbeatPending = false;
    /** How many heartbeats in a row went unanswered. */
    this.heartbeatMisses = 0;
  }

  /** Start dialling the relay (and keep dialling it until {@link stop} is called). */
  start() {
    if (!this.stopped) return this;
    this.stopped = false;
    this.backoffMs = this.reconnectMinMs;
    this.loop = this.#run();
    return this;
  }

  /** Stop dialling the relay and drop every open stream. */
  async stop() {
    this.stopped = true;
    this.#teardown();
    if (this.wake) this.wake();
    if (this.loop) await this.loop.catch(() => {});
    this.loop = null;
    this.log('info', 'the relay client stopped');
  }

  /** Is the device currently registered at the relay? */
  get connected() {
    return this.#connected;
  }

  /** What the banner needs to know about the relay connection. */
  status() {
    return {
      connected: this.connected,
      deviceId: this.deviceId,
      accountId: this.accountId,
      since: this.since,
      lastError: this.lastError,
    };
  }

  /**
   * Wait until the device is registered at the relay.
   * Resolves `true` when the handshake succeeded, `false` when the timeout expired.
   */
  waitForConnection(timeoutMs = 2000) {
    if (this.#connected) return Promise.resolve(true);
    return new Promise((resolve) => {
      const onConnected = () => {
        clearTimeout(timer);
        resolve(true);
      };
      const timer = setTimeout(() => {
        this.off('connected', onConnected);
        resolve(false);
      }, timeoutMs);
      this.once('connected', onConnected);
    });
  }

  /* ----------------------------------------------------------------- the connect loop */

  async #run() {
    while (!this.stopped) {
      try {
        await this.#connect();
      } catch (error) {
        this.lastError = error instanceof Error ? error.message : String(error);
        this.log('warn', `the relay connection failed: ${this.lastError}`);
      }
      if (this.stopped) break;
      const delay = this.backoffMs;
      this.backoffMs = Math.min(this.backoffMs * 2, this.reconnectMaxMs);
      this.log('info', `reconnecting to the relay in ${Math.round(delay / 1000)} s`);
      await this.#sleep(delay);
    }
  }

  #sleep(ms) {
    return new Promise((resolve) => {
      const finish = () => {
        clearTimeout(timer);
        this.reconnectTimer = null;
        this.wake = null;
        resolve();
      };
      const timer = setTimeout(finish, ms);
      this.reconnectTimer = timer;
      this.wake = finish;
    });
  }

  /** One connection attempt; resolves when the connection ends, rejects when it never started. */
  #connect() {
    return new Promise((resolve, reject) => {
      const client = this.#createClient();
      this.client = client;
      this.decoder = new RelayFrameDecoder();

      const fail = (error) => {
        if (this.handshake === null) return;
        this.handshake = null;
        clearTimeout(this.handshakeTimer);
        this.handshakeTimer = null;
        this.#teardown();
        reject(error);
      };
      const done = () => {
        if (this.handshake === null) return;
        this.handshake = null;
        clearTimeout(this.handshakeTimer);
        this.handshakeTimer = null;
        resolve();
      };
      // `established` becomes true with the `HELLO_OK`; the promise is settled when the
      // connection ends, not when the handshake succeeds.
      this.handshake = { fail, done, established: false };

      client.on('binary', (payload) => this.#onBinary(payload));
      client.on('error', (error) => {
        this.lastError = error instanceof Error ? error.message : String(error);
        if (this.handshake !== null && !this.handshake.established) fail(error);
        else this.log('warn', `relay connection error: ${this.lastError}`);
      });
      client.on('close', () => {
        this.#onConnectionClosed();
        if (this.handshake === null || this.handshake.established) {
          done();
          return;
        }
        if (client.handshakeDone) {
          fail(new Error('the relay closed the connection during the handshake'));
          return;
        }
        // The connection never came up: the connect promise carries the real reason (ECONNREFUSED,
        // a rejected handshake, …). It settles a tick later, so the fallback waits for it.
        const fallback = setTimeout(() => {
          if (this.handshake !== null && !this.handshake.established) {
            fail(new Error('the relay connection failed before the handshake'));
          }
        }, 0);
        fallback.unref?.();
      });

      client.connect().then(() => {
        this.log('info', `the relay socket is open (${this.#safeUrl()})`);
        // The spec asks for `{ deviceId, name }`; the port is an optional extra the relay uses to
        // find the local bridge port (`session.devicePort` beats its own configuration). The
        // account id tells the relay which account the device belongs to (docs/ACCOUNT.md).
        // The secrets do NOT travel with this frame: they are part of the handshake header.
        this.#send(RELAY_TYPE.HELLO, 0, Buffer.from(JSON.stringify({
          deviceId: this.deviceId,
          name: this.name,
          port: this.targetPort,
          ...(this.accountId ? { accountId: this.accountId } : {}),
          // The token the phone of this bridge holds. The relay keeps only its hash: it has to
          // compare the token a phone presents, it never needs the token itself.
          ...(this.bridgeToken ? { bridgeToken: this.bridgeToken } : {}),
        }), 'utf8'));
        this.handshakeTimer = setTimeout(
          () => fail(new Error('the relay did not answer the handshake in time')),
          this.handshakeTimeoutMs,
        );
      }).catch((error) => fail(error));
    });
  }

  #createClient() {
    // The secrets travel with the handshake header, not with the url: a query string ends up in
    // the access log of every proxy on the way.
    const headers = {
      'Sec-WebSocket-Protocol': buildRelayProtocolHeader({
        deviceToken: this.deviceToken,
        accountToken: this.accountToken,
        accountId: this.accountId,
      }),
    };
    const options = { headers, maxPayload: 32 * 1024 * 1024, timeoutMs: 10000 };
    if (this.url.protocol === 'wss:') {
      return new TlsRelayWebSocketClient(this.url.href, {
        ...options,
        rejectUnauthorized: this.rejectUnauthorized,
        ca: this.ca,
      });
    }
    return new RelayWebSocketClient(this.url.href, options);
  }

  /**
   * The certificate of the relay (only with `wss://`).
   * The SHA256 fingerprint is what the phone pins, so it is worth showing it.
   */
  certificate() {
    return this.client?.certificate ?? null;
  }

  /** The connection URL without the secrets (the tokens must never reach the log). */
  #safeUrl() {
    const copy = new URL(this.url.href);
    copy.searchParams.delete('token');
    copy.searchParams.delete('accountToken');
    return copy.toString();
  }

  /** Close the WebSocket and drop every stream. */
  #teardown() {
    this.#connected = false;
    this.since = null;
    this.#stopHeartbeat();
    this.#closeStreams();
    const client = this.client;
    this.client = null;
    try {
      client?.close();
    } catch {
      // The socket may already be gone.
    }
  }

  /**
   * The heartbeat of the relay connection.
   *
   * A ping goes out every `heartbeatIntervalMs`; the relay answers with a pong. When the pongs
   * stop coming the connection is half open (the socket is gone, the process does not know it
   * yet), so the connection is closed and the connect loop dials the relay again.
   */
  #startHeartbeat() {
    this.#stopHeartbeat();
    if (!(this.heartbeatIntervalMs > 0)) return;
    this.heartbeatTimer = setInterval(() => this.#heartbeatTick(), this.heartbeatIntervalMs);
    // The heartbeat must not keep the process alive on its own.
    this.heartbeatTimer.unref?.();
  }

  #stopHeartbeat() {
    if (this.heartbeatTimer !== null) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    this.heartbeatPending = false;
    this.heartbeatMisses = 0;
  }

  #heartbeatTick() {
    if (this.stopped || this.client === null) return;
    if (this.heartbeatPending) {
      // The pong of the last ping never arrived.
      this.heartbeatMisses += 1;
      this.heartbeatPending = false;
      if (this.heartbeatMisses >= this.heartbeatMaxMisses) {
        this.log('warn', `the relay did not answer ${this.heartbeatMisses} heartbeats, reconnecting`);
        // Closing the socket ends this connection attempt; the connect loop dials again.
        try {
          this.client.close();
        } catch {
          // The socket is already gone.
        }
        return;
      }
    }
    // A protocol level ping as well: a proxy in between (a CDN, a load balancer) only counts
    // protocol frames. Our own heartbeat is a data frame, so such a proxy sees an idle line and
    // hangs up after a while (Cloudflare: ~100 s) even though the relay is right there ✓.
    this.client.ping?.();
    // The heartbeat is a control frame: it never carries data and it never shows up in a log.
    this.heartbeatPending = this.#send(RELAY_TYPE.PING, 0, Buffer.alloc(0));
  }

  #onConnectionClosed() {
    const wasConnected = this.#connected;
    this.#connected = false;
    this.since = null;
    this.#stopHeartbeat();
    this.#closeStreams();
    if (wasConnected) {
      this.log('warn', 'the relay connection was lost');
      this.emit('disconnected');
    }
  }

  /* --------------------------------------------------------------------- frame handling */

  #onBinary(payload) {
    let frames;
    try {
      frames = this.decoder.push(payload);
    } catch (error) {
      this.log('warn', `malformed relay frame: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    for (const frame of frames) this.#onFrame(frame);
  }

  #onFrame(frame) {
    const { streamId, type, payload } = frame;
    switch (type) {
      case RELAY_TYPE.OPEN:
        this.#onOpen(streamId, payload);
        break;
      case RELAY_TYPE.OPEN_OK:
        break;
      case RELAY_TYPE.OPEN_ERR:
        this.log('warn', `the relay refused the stream ${streamId}: ${payload.toString('utf8')}`);
        break;
      case RELAY_TYPE.DATA:
        this.#onData(streamId, payload);
        break;
      case RELAY_TYPE.CLOSE:
        this.#onClose(streamId);
        break;
      case RELAY_TYPE.HELLO_OK:
        this.#onHelloOk(payload);
        break;
      case RELAY_TYPE.PING:
        this.#send(RELAY_TYPE.PONG, 0, Buffer.alloc(0));
        break;
      case RELAY_TYPE.PONG:
        // The relay is alive: the connection is not half open.
        this.heartbeatPending = false;
        this.heartbeatMisses = 0;
        // A heartbeat line in the log: it shows that the connection is still warm. The frame
        // itself is a control frame and never carries anything.
        this.log('debug', 'the relay heartbeat: the relay answered');
        break;
      default:
        this.log('warn', `unsupported relay frame type 0x${type.toString(16).padStart(2, '0')}`);
        break;
    }
  }

  #onHelloOk(payload) {
    if (this.#connected) return;
    this.#connected = true;
    this.since = Date.now();
    this.lastError = null;
    this.backoffMs = this.reconnectMinMs;
    let info = payload.toString('utf8');
    try {
      const parsed = JSON.parse(info);
      if (parsed && typeof parsed.relay === 'string') info = `${parsed.relay} ${parsed.version ?? ''}`.trim();
    } catch {
      // The payload is informational only.
    }
    this.log('info', `the relay accepted the device "${this.name}" (${this.deviceId}) — ${info}`);
    this.emit('connected', this.status());
    // The handshake is over, but the connection stays: the connect promise is settled when the
    // socket closes. From now on the heartbeat keeps the connection alive and proves that it is.
    this.#startHeartbeat();
    if (this.handshake !== null) this.handshake.established = true;
    clearTimeout(this.handshakeTimer);
    this.handshakeTimer = null;
  }

  #onOpen(streamId, payload) {
    const target = payload.toString('utf8').trim();
    const parsed = parseTarget(target);
    if (parsed === null) {
      this.#openError(streamId, `malformed open target "${target}"`);
      return;
    }
    // The relay must not be able to use the desktop as a jump host into the LAN
    // (docs/RELAY.md §6): only the local bridge port may be opened.
    if (parsed.host !== '127.0.0.1' || parsed.port !== this.targetPort) {
      this.log('warn', `refusing to open "${target}": only 127.0.0.1:${this.targetPort} is allowed`);
      this.#openError(streamId, `refusing to open "${target}": only 127.0.0.1:${this.targetPort} is allowed`);
      return;
    }

    const socket = net.connect({ host: '127.0.0.1', port: this.targetPort });
    socket.setNoDelay(true);
    const record = { socket, opened: false, failed: false };
    this.streams.set(streamId, record);

    socket.on('connect', () => {
      record.opened = true;
      this.#send(RELAY_TYPE.OPEN_OK, streamId, Buffer.alloc(0));
    });
    socket.on('data', (chunk) => {
      for (let offset = 0; offset < chunk.length; offset += MAX_DATA_PAYLOAD) {
        const end = Math.min(offset + MAX_DATA_PAYLOAD, chunk.length);
        this.#send(RELAY_TYPE.DATA, streamId, chunk.subarray(offset, end));
      }
    });
    socket.on('error', (error) => {
      record.failed = true;
      const message = error instanceof Error ? error.message : String(error);
      if (!record.opened) {
        this.log('warn', `cannot open "${target}": ${message}`);
        this.#openError(streamId, `cannot open "${target}": ${message}`);
      } else {
        this.log('warn', `the stream ${streamId} failed: ${message}`);
      }
      socket.destroy();
    });
    socket.on('close', () => {
      if (this.streams.get(streamId) === record) this.streams.delete(streamId);
      if (record.failed) return;
      // The local side is gone: tell the relay so it can release the phone side.
      this.#send(RELAY_TYPE.CLOSE, streamId, Buffer.alloc(0));
    });
  }

  #openError(streamId, message) {
    this.#send(RELAY_TYPE.OPEN_ERR, streamId, Buffer.from(String(message), 'utf8'));
  }

  #onData(streamId, payload) {
    const record = this.streams.get(streamId);
    if (!record) {
      this.log('warn', `data for the unknown stream ${streamId}`);
      return;
    }
    try {
      record.socket.write(payload);
    } catch (error) {
      this.log('warn', `cannot write to the stream ${streamId}: ${error instanceof Error ? error.message : String(error)}`);
      record.socket.destroy();
    }
  }

  #onClose(streamId) {
    const record = this.streams.get(streamId);
    if (!record) return;
    this.streams.delete(streamId);
    record.socket.destroy();
  }

  /** Destroy every open stream (the relay connection is gone, so no CLOSE frame is needed). */
  #closeStreams() {
    for (const record of this.streams.values()) {
      try {
        record.socket.destroy();
      } catch {
        // The socket may already be gone.
      }
    }
    this.streams.clear();
  }

  /* ---------------------------------------------------------------------- frame writing */

  /** Send one relay frame; `false` when the connection is gone. */
  #send(type, streamId, payload) {
    const client = this.client;
    if (!client || client.closed) return false;
    try {
      client.sendBinary(encodeRelayFrame(streamId, type, payload));
      return true;
    } catch (error) {
      this.log('warn', `cannot write to the relay: ${error instanceof Error ? error.message : String(error)}`);
      return false;
    }
  }
}

// Minimal RFC 6455 WebSocket implementation (server + client) with zero dependencies.
//
// Only what the bridge needs: the handshake, text frames, ping/pong, close, and client→server
// masking. Frames are parsed by a state-free incremental parser so the same code serves the
// phone-facing server and the upstream DSH client.

import crypto from 'node:crypto';
import net from 'node:net';
import { EventEmitter } from 'node:events';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export const OPCODE = Object.freeze({
  CONTINUATION: 0x0,
  TEXT: 0x1,
  BINARY: 0x2,
  CLOSE: 0x8,
  PING: 0x9,
  PONG: 0xa,
});

const CLOSE_NORMAL = 1000;
const CLOSE_GOING_AWAY = 1001;
const CLOSE_PROTOCOL_ERROR = 1002;
const CLOSE_UNSUPPORTED = 1003;
const CLOSE_TOO_LARGE = 1009;

/** Compute the `Sec-WebSocket-Accept` value for a client key. */
export function acceptKey(key) {
  return crypto.createHash('sha1').update(`${key}${GUID}`, 'utf8').digest('base64');
}

/** Encode one WebSocket frame. */
export function encodeFrame(opcode, payload = Buffer.alloc(0), { fin = true, mask = false, maskKey } = {}) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
  const length = data.length;
  let header;

  if (length < 126) {
    header = Buffer.alloc(2);
    header[1] = length;
  } else if (length < 65536) {
    header = Buffer.alloc(4);
    header[1] = 126;
    header.writeUInt16BE(length, 2);
  } else {
    header = Buffer.alloc(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(length), 2);
  }
  header[0] = (fin ? 0x80 : 0x00) | (opcode & 0x0f);

  if (!mask) return Buffer.concat([header, data]);

  const key = maskKey ?? crypto.randomBytes(4);
  header[1] |= 0x80;
  const masked = Buffer.allocUnsafe(length);
  for (let i = 0; i < length; i += 1) masked[i] = data[i] ^ key[i & 3];
  return Buffer.concat([header, key, masked]);
}

/** Build a close frame payload. */
export function encodeClosePayload(code, reason = '') {
  const reasonBytes = Buffer.from(String(reason), 'utf8');
  const payload = Buffer.allocUnsafe(2 + reasonBytes.length);
  payload.writeUInt16BE(code, 0);
  reasonBytes.copy(payload, 2);
  return payload;
}

/**
 * Incremental frame parser.
 * `push()` returns the frames that became complete; a partially received frame is buffered.
 */
export class FrameParser {
  constructor({ requireMask = false, maxPayload = 16 * 1024 * 1024 } = {}) {
    this.requireMask = requireMask;
    this.maxPayload = maxPayload;
    this.buffer = Buffer.alloc(0);
    this.fragments = [];
    this.fragmentOpcode = null;
  }

  push(chunk) {
    this.buffer = this.buffer.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.buffer, chunk]);
    const frames = [];
    for (;;) {
      const frame = this.#readOne();
      if (frame === null) break;
      frames.push(frame);
    }
    return frames;
  }

  #readOne() {
    const buffer = this.buffer;
    if (buffer.length < 2) return null;

    const first = buffer[0];
    const second = buffer[1];
    const fin = (first & 0x80) !== 0;
    const opcode = first & 0x0f;
    const masked = (second & 0x80) !== 0;
    let length = second & 0x7f;
    let offset = 2;

    if (length === 126) {
      if (buffer.length < offset + 2) return null;
      length = buffer.readUInt16BE(offset);
      offset += 2;
    } else if (length === 127) {
      if (buffer.length < offset + 8) return null;
      const big = buffer.readBigUInt64BE(offset);
      if (big > BigInt(this.maxPayload)) throw new Error('websocket frame exceeds the payload limit');
      length = Number(big);
      offset += 8;
    }

    if (length > this.maxPayload) throw new Error('websocket frame exceeds the payload limit');
    if (this.requireMask && !masked) throw new Error('websocket client frames must be masked');

    let maskKey = null;
    if (masked) {
      if (buffer.length < offset + 4) return null;
      maskKey = buffer.subarray(offset, offset + 4);
      offset += 4;
    }

    if (buffer.length < offset + length) return null;

    const payload = Buffer.from(buffer.subarray(offset, offset + length));
    if (maskKey) {
      for (let i = 0; i < payload.length; i += 1) payload[i] ^= maskKey[i & 3];
    }
    this.buffer = buffer.subarray(offset + length);
    return { fin, opcode, payload };
  }
}

/**
 * A server-side WebSocket connection.
 * Emits `message` (text string), `ping`, `close`, `error`.
 */
export class WebSocketConnection extends EventEmitter {
  constructor(socket, { maxPayload = 16 * 1024 * 1024 } = {}) {
    super();
    this.socket = socket;
    this.parser = new FrameParser({ requireMask: true, maxPayload });
    this.closed = false;
    this.closeSent = false;

    socket.on('data', (chunk) => this.#onData(chunk));
    socket.on('error', (error) => {
      this.emit('error', error);
      this.#teardown(CLOSE_GOING_AWAY);
    });
    socket.on('close', () => this.#teardown(CLOSE_GOING_AWAY));
  }

  #onData(chunk) {
    let frames;
    try {
      frames = this.parser.push(chunk);
    } catch (error) {
      this.close(CLOSE_PROTOCOL_ERROR, error.message);
      return;
    }

    for (const frame of frames) {
      switch (frame.opcode) {
        case OPCODE.PING:
          this.#write(encodeFrame(OPCODE.PONG, frame.payload));
          break;
        case OPCODE.PONG:
          this.emit('pong', frame.payload);
          break;
        case OPCODE.CLOSE: {
          const code = frame.payload.length >= 2 ? frame.payload.readUInt16BE(0) : CLOSE_NORMAL;
          this.#sendClose(code);
          break;
        }
        case OPCODE.CONTINUATION:
        case OPCODE.TEXT:
        case OPCODE.BINARY: {
          if (frame.opcode !== OPCODE.CONTINUATION) {
            this.parser.fragments = [];
            this.parser.fragmentOpcode = frame.opcode;
          }
          this.parser.fragments.push(frame.payload);
          if (!frame.fin) break;
          const complete = Buffer.concat(this.parser.fragments);
          const opcodeUsed = this.parser.fragmentOpcode ?? OPCODE.TEXT;
          this.parser.fragments = [];
          this.parser.fragmentOpcode = null;
          if (opcodeUsed === OPCODE.TEXT) this.emit('message', complete.toString('utf8'));
          else this.emit('binary', complete);
          break;
        }
        default:
          this.close(CLOSE_PROTOCOL_ERROR, `unsupported opcode ${frame.opcode}`);
          break;
      }
    }
  }

  #write(buffer) {
    if (this.closed || this.socket.destroyed) return;
    this.socket.write(buffer);
  }

  /** Send a text message. */
  send(text) {
    this.#write(encodeFrame(OPCODE.TEXT, Buffer.from(String(text), 'utf8')));
  }

  /** Send a ping. */
  ping(payload = Buffer.alloc(0)) {
    this.#write(encodeFrame(OPCODE.PING, payload));
  }

  /** Send a pong. */
  pong(payload = Buffer.alloc(0)) {
    this.#write(encodeFrame(OPCODE.PONG, payload));
  }

  #sendClose(code) {
    if (!this.closeSent) {
      this.closeSent = true;
      this.#write(encodeFrame(OPCODE.CLOSE, encodeClosePayload(code)));
    }
    this.socket.end();
    this.#teardown(code);
  }

  /** Close the connection with a status code. */
  close(code = CLOSE_NORMAL, reason = '') {
    if (this.closed) return;
    this.#sendClose(code);
  }

  #teardown(code) {
    if (this.closed) return;
    this.closed = true;
    this.emit('close', code);
    this.removeAllListeners('message');
  }
}

/**
 * Complete the server side of the WebSocket handshake.
 * Returns a {@link WebSocketConnection} or `null` when the request is not a valid upgrade.
 */
export function acceptWebSocket(req, socket, head, { maxPayload } = {}) {
  const key = req.headers['sec-websocket-key'];
  const upgrade = String(req.headers.upgrade ?? '').toLowerCase();
  const version = String(req.headers['sec-websocket-version'] ?? '');
  if (upgrade !== 'websocket' || typeof key !== 'string' || key.length === 0 || version !== '13') {
    socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return null;
  }

  socket.setNoDelay(true);
  // 客户端提了子协议(中继模式下手机会带 `dsh-device.<令牌>`)就**回显**它 ✓
  // —— 严格的客户端(WHATWG/undici)要求: 客户端提了子协议, 服务端必须回一个,
  //    不回显的话它直接判握手失败(close 1006)✗
  const offered = String(req.headers['sec-websocket-protocol'] ?? '')
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
  const handshake = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${acceptKey(key)}`,
  ];
  if (offered.length > 0) {
    handshake.push(`Sec-WebSocket-Protocol: ${offered[0]}`);
  }
  socket.write([...handshake, '\r\n'].join('\r\n'));

  const connection = new WebSocketConnection(socket, { maxPayload });
  if (head && head.length > 0) connection.parser.push(head);
  return connection;
}

/**
 * A tiny client-side WebSocket, used to talk to the DSH `remote.mux` carrier.
 * Emits `open`, `message`, `close`, `error`.
 */
export class WebSocketClient extends EventEmitter {
  constructor(url, { headers = {}, maxPayload = 32 * 1024 * 1024, timeoutMs = 10_000 } = {}) {
    super();
    this.url = new URL(url);
    this.headers = headers;
    // A server never masks the frames it sends, so the client parser must not require a mask.
    this.parser = new FrameParser({ requireMask: false, maxPayload });
    this.socket = null;
    this.closed = false;
    this.tornDown = false;
    this.handshakeDone = false;
    this.timeoutMs = timeoutMs;
  }

  connect() {
    return new Promise((resolve, reject) => {
      const key = crypto.randomBytes(16).toString('base64');
      const socket = (this.socket = net.connect({
        host: this.url.hostname,
        port: Number(this.url.port || 80),
      }));

      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error(`websocket connect to ${this.url.href} timed out`));
      }, this.timeoutMs);
      timer.unref?.();

      socket.on('error', (error) => {
        clearTimeout(timer);
        if (!this.handshakeDone) {
          this.#teardown();
          reject(error);
          return;
        }
        // After the handshake an error must not crash a client without an error listener.
        if (!this.tornDown) this.emit('error', error);
        this.#teardown();
      });

      socket.on('connect', () => {
        const lines = [
          `GET ${this.url.pathname}${this.url.search} HTTP/1.1`,
          `Host: ${this.url.host}`,
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
          socket.destroy();
          clearTimeout(timer);
          reject(new Error(`websocket handshake failed: ${statusLine.trim()}`));
          return;
        }
        const accept = /sec-websocket-accept:\s*(\S+)/iu.exec(head)?.[1];
        if (accept !== acceptKey(key)) {
          socket.destroy();
          clearTimeout(timer);
          reject(new Error('websocket handshake failed: bad Sec-WebSocket-Accept'));
          return;
        }
        clearTimeout(timer);
        socket.on('data', (data) => this.#onData(data));
        socket.on('close', () => this.#teardown());
        socket.on('error', (error) => {
          if (!this.tornDown) this.emit('error', error);
          this.#teardown();
        });
        if (rest.length > 0) this.#onData(rest);
        this.handshakeDone = true;
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
        this.#teardown();
      }
    }
  }

  /** Send a text message (client frames are masked as RFC 6455 requires). */
  send(text) {
    if (this.closed || !this.socket) return;
    this.socket.write(encodeFrame(OPCODE.TEXT, Buffer.from(String(text), 'utf8'), { mask: true }));
  }

  /** Send a pong. */
  pong(payload = Buffer.alloc(0)) {
    if (this.closed || !this.socket) return;
    this.socket.write(encodeFrame(OPCODE.PONG, payload, { mask: true }));
  }

  /**
   * Send a **protocol level** ping (RFC 6455, opcode 0x9).
   *
   * Why the application heartbeat is not enough: a proxy in between (a CDN, a load balancer)
   * only counts protocol level frames. Our own heartbeat travels as a data frame, so the proxy
   * sees an idle line and hangs up after a while (Cloudflare: ~100 s). A ping every now and then
   * keeps the line open through a proxy.
   */
  ping(payload = Buffer.alloc(0)) {
    if (this.closed || !this.socket) return;
    this.socket.write(encodeFrame(OPCODE.PING, payload, { mask: true }));
  }

  /**
   * Send a **protocol level** ping (RFC 6455, opcode 0x9).
   *
   * Why the application heartbeat is not enough: a proxy in between (a CDN, a load balancer)
   * only counts protocol level frames. Our own heartbeat travels as a data frame, so the proxy
   * sees an idle line and hangs up after a while (Cloudflare: ~100 s). A ping every now and then
   * keeps the line open through a proxy.
   */
  ping(payload = Buffer.alloc(0)) {
    if (this.closed || !this.socket) return;
    this.socket.write(encodeFrame(OPCODE.PING, payload, { mask: true }));
  }

  /**
   * Send a **protocol level** ping (RFC 6455, opcode 0x9).
   *
   * Why the application heartbeat is not enough: a proxy in between (a CDN, a load balancer)
   * only counts protocol level frames. Our own heartbeat travels as a data frame, so the proxy
   * sees an idle line and hangs up after a while (Cloudflare: ~100 s). A ping every now and then
   * keeps the line open through a proxy.
   */
  ping(payload = Buffer.alloc(0)) {
    if (this.closed || !this.socket) return;
    this.socket.write(encodeFrame(OPCODE.PING, payload, { mask: true }));
  }

  /** Close the connection. */
  close() {
    if (this.closed) return;
    this.closed = true;
    try {
      this.socket?.write(encodeFrame(OPCODE.CLOSE, encodeClosePayload(CLOSE_NORMAL), { mask: true }));
      this.socket?.end();
    } catch {
      // The socket may already be gone.
    }
    this.#teardown();
  }

  #teardown() {
    if (this.tornDown) return;
    this.tornDown = true;
    this.emit('close');
  }
}

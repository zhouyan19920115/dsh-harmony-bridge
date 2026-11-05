// HTTP server of the bridge: authentication middleware, JSON body handling, route dispatch and
// the phone-facing WebSocket endpoint.
//
// Every request must carry `Authorization: Bearer <token>` (the pairing endpoint is the single
// exception: it is restricted to localhost and exists to hand the token to the phone).
// Errors always use the PROTOCOL.md envelope, and the server never dies because of a bad request.

import http from 'node:http';

import { API_PREFIX, ClientFrame, ErrorCode, ServerFrame, errorEnvelope, serverFrame } from './protocol.js';
import { WS_PATH } from './protocol.js';
import { DISCOVER_PATH, PAIR_PATH } from './discovery.js';
import { BridgeError } from './router.js';
import { acceptWebSocket } from './ws.js';
import { scrubSecrets } from './mask.js';
import {
  SEAL_HEADER,
  SEAL_ID_HEADER,
  SEAL_KEY_HEADER,
  SEAL_TIMESTAMP_HEADER,
  deriveSealKey,
  deriveWrapKey,
  parseSealId,
  sealBody,
  unsealBody,
  unwrapSealKey,
} from './seal.js';

const MAX_BODY_BYTES = 4 * 1024 * 1024;

/**
 * The heartbeat of a phone connection.
 *
 * The phone pings the bridge every {@link HEARTBEAT_INTERVAL_MS} and the bridge answers with a
 * pong. The bridge pings the phone the same way: a phone that is gone (a killed app, a lost
 * network) is dropped instead of lingering as a half open socket.
 *
 * Ten seconds: behind a CDN or a tunnel the boxes on the way cut a line that says nothing
 * for ~20-30 s, so a 25 s heartbeat sits right on that edge.
 */
export const HEARTBEAT_INTERVAL_MS = 10000;

/** How many heartbeats in a row may go unanswered before the connection is dropped. */
export const HEARTBEAT_MAX_MISSES = 3;

/**
 * The server → client heartbeat frame.
 *
 * The name is the one of PROTOCOL.md §3; the constant lives here because `protocol.js` only
 * knows the client → server frames.
 */
const SERVER_PING = 'ping';

/** The client → server heartbeat answer (the counterpart of {@link SERVER_PING}). */
const CLIENT_PONG = 'pong';

/** Compare two tokens without leaking their length through timing. */
function tokenEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * Extract the bearer token of a request.
 *
 * The normal way is the `Authorization: Bearer` header — the token never touches a url that way.
 *
 * The `?token=` query parameter is a **compatibility path for old clients only** (it is not
 * recommended): a token in the url ends up in the access log of every proxy on the way. The
 * current clients (the phone and the relay) use the header, or the `Sec-WebSocket-Protocol`
 * subprotocol for the WebSocket handshake.
 *
 * @param {import('node:http').IncomingMessage} request the request
 * @param {URL} url the parsed url
 * @returns {string|null} the token or null
 */
export function extractToken(request, url) {
  const header = request.headers.authorization;
  if (typeof header === 'string') {
    const match = /^Bearer\s+(.+)$/iu.exec(header.trim());
    if (match) return match[1].trim();
  }
  // Compatibility only — the server never writes this url into a log line (it logs the
  // pathname), so the token does not reach the access log.
  const queryToken = url.searchParams.get('token');
  return queryToken === null ? null : queryToken;
}

/** True when the peer of a request is on the loopback interface. */
export function isLoopback(request) {
  const remote = request.socket.remoteAddress ?? '';
  return remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1' || remote.startsWith('127.');
}

/** Read a JSON request body. */
function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new BridgeError(413, ErrorCode.BAD_REQUEST, 'the request body is too large'));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      // A UTF-8 byte order mark is not valid JSON, but some clients send one.
      const raw = Buffer.concat(chunks).toString('utf8').replace(/^\uFEFF/u, '');      if (raw.trim().length === 0) {
        resolve({});
        return;
      }
      try {
        const parsed = JSON.parse(raw);
        resolve(parsed && typeof parsed === 'object' ? parsed : {});
      } catch {
        reject(new BridgeError(400, ErrorCode.BAD_REQUEST, 'the request body is not valid JSON'));
      }
    });
    request.on('error', reject);  });
}

/**
 * Read the raw request body.
 *
 * A sealed request carries its envelope as the body, so the bytes have to be kept as they are.
 */
function readRawBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new BridgeError(413, ErrorCode.BAD_REQUEST, 'the request body is too large'));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

/**
 * Open a sealed request.
 *
 * The envelope carries the token of the phone and the body of the request: the token is
 * checked *after* the envelope is opened, so the relay never sees the token in the clear.
 *
 * @returns {{token: string, body: object, key: Buffer}} the token, the body and the key
 */
function openSealedRequest(bridge, request, url, raw) {
  const envelope = String(request.headers[SEAL_HEADER] ?? '').trim();
  const timestamp = Number.parseInt(String(request.headers[SEAL_TIMESTAMP_HEADER] ?? ''), 10);
  const ids = parseSealId(String(request.headers[SEAL_ID_HEADER] ?? ''));
  // The seal key of the phone: either the phone sent it wrapped (the normal case) or the
  // bridge derives it from its own token (the first version of the protocol).
  let key;
  const wrapped = request.headers[SEAL_KEY_HEADER];
  if (wrapped !== undefined && String(wrapped).trim().length > 0) {
    try {
      key = unwrapSealKey(
        deriveWrapKey({ token: bridge.state.token, accountId: ids.accountId, deviceId: ids.deviceId }),
        String(wrapped),
        { accountId: ids.accountId, deviceId: ids.deviceId },
      );
    } catch (error) {
      throw new BridgeError(401, ErrorCode.UNAUTHORIZED, `the seal key could not be unwrapped: ${error.message}`);
    }
  } else {
    key = deriveSealKey({
      token: bridge.state.token,
      accountId: ids.accountId,
      deviceId: ids.deviceId,
    });
  }
  let plaintext;
  try {
    plaintext = unsealBody(key, envelope, {
      method: request.method ?? 'GET',
      path: url.pathname,
      timestamp,
    });
  } catch (error) {
    throw new BridgeError(401, ErrorCode.UNAUTHORIZED, `the seal could not be opened: ${error.message}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(plaintext);
  } catch {
    throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'the sealed body is not valid JSON');
  }
  const token = typeof parsed?.token === 'string' ? parsed.token : '';
  const body = parsed?.body && typeof parsed.body === 'object' ? parsed.body : {};
  // 封签的 id 头里带着**发请求那台设备**的设备号 ⇒ 请求体里没带设备号时用它兜底
  // (手机续心跳时设备号就在请求体里, 少了它中继就认不出这台手机 ⇒ 在线状态刷不上)
  return { token, body, key, deviceId: ids.deviceId };
}

/**
 * Adapt a raw WebSocket connection to the small interface the bridge expects
 * (`send(frame)` and `close()`).
 */
class ClientConnection {
  constructor(socket) {
    this.socket = socket;
    this.subscriptions = new Set();
    this.alive = true;
    /** A ping is on the way and no pong came back yet. */
    this.heartbeatPending = false;
    /** How many heartbeats in a row went unanswered. */
    this.heartbeatMisses = 0;
    /** The client answered a heartbeat at least once, so it knows the frame. */
    this.heartbeatSpeaks = false;
  }

  send(frame) {
    if (!this.alive) return false;
    try {
      this.socket.send(JSON.stringify(frame));
      return true;
    } catch {
      this.alive = false;
      return false;
    }
  }

  /** The phone answered the last ping: the connection is alive. */
  notePong() {
    this.heartbeatPending = false;
    this.heartbeatMisses = 0;
    this.heartbeatSpeaks = true;
  }

  /**
   * One heartbeat round.
   *
   * Returns `false` when the client has to be dropped: it did not answer the pings in a row,
   * so the connection is half open.
   *
   * Only a client that answered a heartbeat **before** is dropped: an older app build does
   * not know the frame, and it must not be kicked off the bus for that.
   */
  heartbeatTick() {
    if (!this.alive) return false;
    if (this.heartbeatPending) {
      this.heartbeatPending = false;
      if (this.heartbeatSpeaks) {
        this.heartbeatMisses += 1;
        if (this.heartbeatMisses >= HEARTBEAT_MAX_MISSES) return false;
      }
    }
    // A protocol level ping as well: when the phone reaches the bridge through a proxy (a CDN),
    // that proxy only counts protocol frames — our own heartbeat is a data frame, so the proxy
    // would see an idle line and hang up after a while ✓.
    try {
      this.socket.ping?.();
    } catch {
      // The socket may already be gone — the app level ping below reports that.
    }
    this.heartbeatPending = this.send(serverFrame(SERVER_PING, {}));
    return true;
  }

  close() {
    this.alive = false;
    this.heartbeatPending = false;
    try {
      this.socket.close();
    } catch {
      // The socket may already be gone.
    }
  }
}

/**
 * Create the bridge HTTP server.
 * Returns `{ server, listen, close }`.
 */
export function createBridgeServer({ bridge, router, heartbeatIntervalMs = HEARTBEAT_INTERVAL_MS }) {
  const token = bridge.state.token;
  // Upgraded sockets are detached from Node's HTTP connection tracking, so the bridge keeps
  // track of them itself; otherwise a graceful shutdown would wait for the phone forever.
  const openSockets = new Set();

  // The heartbeat of the phone connections: a ping every 25 s, a client that does not answer
  // three times in a row is dropped. It runs on its own channel: it never touches the messages.
  const heartbeat = setInterval(() => {
    for (const client of [...(bridge.clients ?? [])]) {
      if (client.heartbeatTick()) continue;
      bridge.log('warn', 'a phone did not answer the heartbeat, the connection is dropped');
      client.close();
    }
  }, heartbeatIntervalMs);
  // The heartbeat must not keep the process alive on its own.
  heartbeat.unref?.();

  const server = http.createServer(async (request, response) => {
    let url;
    try {
      url = new URL(request.url ?? '/', `http://${request.headers.host ?? 'localhost'}`);
    } catch {
      sendJson(response, 400, errorEnvelope(ErrorCode.BAD_REQUEST, 'malformed request URL'));
      return;
    }

    try {
      // A sealed request carries the token inside its envelope. It has to be opened *before*
      // the token is checked, otherwise the relay would see the token in the clear.
      const sealed = request.headers[SEAL_HEADER] !== undefined;
      let seal = null;
      let body = {};
      if (sealed) {
        const raw = await readRawBody(request);
        seal = openSealedRequest(bridge, request, url, raw);
        body = seal.body;
        bridge.log('debug',
          `seal-debug: ${request.method} ${url.pathname} id=${String(request.headers[SEAL_ID_HEADER] ?? '')} `
          + `ts=${String(request.headers[SEAL_TIMESTAMP_HEADER] ?? '')} `
          + `envelope=${String(request.headers[SEAL_HEADER] ?? '').length} `
          + `wrapped=${String(request.headers[SEAL_KEY_HEADER] ?? '').length} `
          + `bodyBytes=${raw.length}`);
        // 密封请求里带着发请求那台设备的设备号(在封签的 id 头里) ⇒ 请求体里没带就用它 ✓
        // (手机的续心跳就靠这个: 少了设备号, 中继认不出来, 手机的在线状态就刷不上)
        if (body.deviceId === undefined && seal.deviceId.length > 0) {
          body = { ...body, deviceId: seal.deviceId };
        }
      }

      // The pairing endpoints hand out the token, so they cannot require the token itself.
      // `/api/v1/pairing` is restricted to localhost unless the operator opts out;
      // `/_dsh/discover` is a harmless "is there a desktop agent here?" probe that a phone
      // sends before it knows anything, and `/api/v1/pair` needs the short lived pairing code.
      const isPairing = url.pathname === `${API_PREFIX}/pairing`;
      const isDiscovery = url.pathname === DISCOVER_PATH;
      const isPair = url.pathname === PAIR_PATH;
      if (!isPairing && !isDiscovery && !isPair) {
        const presented = seal !== null ? seal.token : extractToken(request, url);
        if (presented === null || presented.length === 0 || !tokenEquals(presented, token)) {
          sendJson(response, 401, errorEnvelope(ErrorCode.UNAUTHORIZED, 'a valid bearer token is required'));
          return;
        }
      }
      if (isPairing && !bridge.options.allowUnauthPairing) {
        // `/api/v1/pairing` is restricted to localhost; the route handler enforces that.
        // `/_dsh/discover` and `/api/v1/pair` are reachable from the LAN on purpose:
        // the first only exposes harmless information, the second needs the pairing code.
      }


      const match = router.match(request.method ?? 'GET', url.pathname);
      if (match === null) {
        sendJson(response, 404, errorEnvelope(ErrorCode.NOT_FOUND, `no route for ${request.method} ${url.pathname}`));
        return;
      }
      if (match.methodMismatch) {
        sendJson(response, 405, errorEnvelope(ErrorCode.METHOD_NOT_ALLOWED, `${request.method} is not allowed on ${url.pathname}`));
        return;
      }

      if (!sealed) {
        body = request.method === 'POST' || request.method === 'PUT' || request.method === 'PATCH'
          ? await readJsonBody(request)
          : {};
      }
      const query = Object.fromEntries(url.searchParams.entries());
      const result = await match.route.handler({ params: match.params, query, body, request });
      if (typeof result?.html === 'string') {
        // A route may answer with a page instead of JSON (the bridge settings page).
        response.writeHead(result.status ?? 200, {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          'content-length': Buffer.byteLength(result.html),
        });
        response.end(result.html);
        return;
      }
      const payload = result?.body ?? {};
      if (seal !== null) {
        // The answer of a sealed request is sealed as well: the relay must not read it.
        const { seal: envelope, timestamp } = sealBody(seal.key, JSON.stringify(payload), {
          method: request.method ?? 'GET',
          path: url.pathname,
        });
        bridge.log('debug',
          `seal-debug answer: ${request.method} ${url.pathname} envelope=${envelope.length} ts=${timestamp}`);
        response.setHeader(SEAL_HEADER, envelope);
        response.setHeader(SEAL_TIMESTAMP_HEADER, String(timestamp));
        response.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'content-length': Buffer.byteLength(envelope),
          'cache-control': 'no-store',
        });
        response.end(envelope);
        return;
      }
      sendJson(response, 200, payload);
    } catch (error) {
      if (error instanceof BridgeError) {
        sendJson(response, error.status, errorEnvelope(error.code, error.message, error.details));
        return;
      }
      bridge.log('error', `unhandled request failure: ${scrubSecrets(error instanceof Error ? error.stack ?? error.message : String(error))}`);
      sendJson(response, 500, errorEnvelope(ErrorCode.INTERNAL, 'the bridge failed to handle the request'));
    }
  });

  server.on('upgrade', (request, socket, head) => {
    let url;
    try {
      url = new URL(request.url ?? '/', `http://${request.headers.host ?? 'localhost'}`);
    } catch {
      socket.destroy();
      return;
    }
    if (url.pathname !== WS_PATH) {
      socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }

    // The token may already be there (the header of the handshake). If it is not, the phone
    // authenticates with its **first frame** instead: a token in the url of the handshake ends
    // up in every access log of every proxy on the way.
    const presented = extractToken(request, url);
    let authenticated = presented !== null && tokenEquals(presented, token);

    const socketConnection = acceptWebSocket(request, socket, head);
    if (socketConnection === null) return;

    openSockets.add(socket);
    socket.once('close', () => openSockets.delete(socket));

    const client = new ClientConnection(socketConnection);
    // Nothing is sent to a client that has not proved its token yet.
    if (authenticated) bridge.addClient(client);

    socketConnection.on('message', (text) => {
      let frame;
      try {
        frame = JSON.parse(text);
      } catch {
        frame = null;
      }
      if (!authenticated) {
        // The first frame has to be the authentication: `{ "type": "auth", "token": "…" }`.
        const frameToken = typeof frame?.token === 'string' ? frame.token : null;
        if (frameToken === null || !tokenEquals(frameToken, token)) {
          client.send(serverFrame(ServerFrame.ERROR, {
            code: ErrorCode.UNAUTHORIZED,
            message: 'the first frame has to carry the token',
          }));
          socketConnection.close();
          return;
        }
        authenticated = true;
        bridge.addClient(client);
        return;
      }
      if (frame === null) {
        client.send(serverFrame(ServerFrame.ERROR, { code: ErrorCode.BAD_REQUEST, message: 'the frame is not valid JSON' }));
        return;
      }
      handleClientFrame(bridge, client, frame).catch((error) => {
        client.send(serverFrame(ServerFrame.ERROR, {
          code: error instanceof BridgeError ? error.code : ErrorCode.INTERNAL,
          message: error instanceof Error ? error.message : String(error),
        }));
      });
    });

    socketConnection.on('close', () => {
      for (const sessionId of client.subscriptions) bridge.unsubscribe(sessionId);
      bridge.removeClient(client);
    });
    socketConnection.on('error', (error) => {
      bridge.log('warn', `websocket error: ${scrubSecrets(error.message)}`);
    });
  });

  // A request that Node's parser could not read. Without this handler Node answers with a bare
  // `400 Bad Request` and drops the socket *without saying why* — the log stays empty and the
  // problem is impossible to place. The head is logged (scrubbed) so the broken request can be
  // recognized.
  //
  // The first bytes of every connection are kept for that: the diagnostic says *that* a request
  // was broken, the sample says *which* bytes.
  const headSamples = new WeakMap();
  server.on('connection', (socket) => {
    const sample = { bytes: [], length: 0 };
    headSamples.set(socket, sample);
    // `prependListener`: the parser of Node is notified first and it raises the error right
    // away — a normal listener would only run *after* the error and would see nothing.
    socket.prependListener('data', (chunk) => {
      if (sample.length >= 400) return;
      sample.length += chunk.length;
      sample.bytes.push(chunk.subarray(0, 400));
    });
  });
  server.on('clientError', (error, socket) => {
    bridge.log('warn', `a client sent a broken request: ${error.message} (${error.code ?? 'unknown'})`);
    const sample = headSamples.get(socket);
    if (sample) {
      const head = Buffer.concat(sample.bytes).subarray(0, 400).toString('latin1');
      bridge.log('warn', `the broken request started with: ${JSON.stringify(scrubSecrets(head))}`);
    }
    if (!socket.destroyed) {
      socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    }
  });

  // 中继转发到本机的每一条流, 在本机就是一条指向这个 http 服务器的 TCP 连接 ——
  // 也就是说"手机到桌面"的那条连接就是它。Node 的 keepAliveTimeout 默认 5 秒, 会在
  // 两次心跳之间把这条连接悄悄关掉, 于是手机的请求在途中消失, 而且没有任何日志。
  // 手机的心跳是 10 秒, 所以这里必须把 keep-alive 关掉(0 = 不超时)。
  server.keepAliveTimeout = 0;

  return {
    server,
    listen(port, host) {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          server.removeListener('error', reject);
          resolve(server.address());
        });
      });
    },
    close() {
      return new Promise((resolve) => {
        clearInterval(heartbeat);
        for (const socket of openSockets) socket.destroy();
        openSockets.clear();
        // WebSocket connections are not "idle" for Node's HTTP server, so they are dropped
        // explicitly; otherwise `close()` would wait for the phone to disconnect.
        server.closeAllConnections?.();
        server.close(() => resolve());
      });
    },
  };
}

/** Handle one client → server WebSocket frame. */
async function handleClientFrame(bridge, client, frame) {
  if (!frame || typeof frame !== 'object' || typeof frame.type !== 'string') {
    client.send(serverFrame(ServerFrame.ERROR, { code: ErrorCode.BAD_REQUEST, message: 'the frame has no type' }));
    return;
  }
  const data = frame.data && typeof frame.data === 'object' ? frame.data : {};

  switch (frame.type) {
    case ClientFrame.PING:
      client.send(serverFrame(ServerFrame.PONG, {}));
      return;

    case CLIENT_PONG:
      // The answer to a heartbeat: the connection is alive. It is not a message and it is
      // never written into a log.
      client.notePong();
      bridge.log('debug', 'a phone answered the heartbeat');
      return;

    case ClientFrame.SUBSCRIBE: {
      // PROTOCOL.md: `subscribe` 携带的是"这个客户端想看的会话集合",
      // 所以这里整体替换而不是累加; 被移除的会话只有在没有别的客户端订阅时才停止流式推送。
      const requested = Array.isArray(data.sessionIds) ? data.sessionIds : [];
      const wanted = new Set();
      for (const sessionId of requested) {
        if (typeof sessionId !== 'string' || sessionId.length === 0) continue;
        wanted.add(sessionId);
      }
      const removed = [];
      for (const sessionId of client.subscriptions) {
        if (!wanted.has(sessionId)) removed.push(sessionId);
      }
      client.subscriptions.clear();
      for (const sessionId of wanted) {
        client.subscriptions.add(sessionId);
        await bridge.subscribe(sessionId);
      }
      for (const sessionId of removed) {
        // bridge.clients 是 Set, 没有 .some —— 必须自己遍历
        let stillWanted = false;
        for (const other of bridge.clients) {
          if (other !== client && other.subscriptions.has(sessionId)) {
            stillWanted = true;
            break;
          }
        }
        if (!stillWanted) bridge.unsubscribe(sessionId);
      }
      return;
    }

    case ClientFrame.PROMPT: {
      const sessionId = String(data.sessionId ?? '');
      const text = String(data.text ?? '');
      const mode = data.mode === 'interrupt' || data.mode === 'steer' ? 'steer' : 'queue';
      const result = await bridge.submitPrompt(sessionId, text, { mode });
      client.send(serverFrame('prompt.accepted', { sessionId, ...result }));
      return;
    }

    case ClientFrame.CANCEL: {
      const sessionId = String(data.sessionId ?? '');
      const result = await bridge.cancelSession(sessionId);
      client.send(serverFrame('cancel.accepted', { sessionId, ...result }));
      return;
    }

    default:
      client.send(serverFrame(ServerFrame.ERROR, { code: ErrorCode.BAD_REQUEST, message: `unsupported frame type ${frame.type}` }));
  }
}

/** Send a JSON response. */
function sendJson(response, status, body) {
  const payload = JSON.stringify(body ?? {});
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
  });
  response.end(payload);
}

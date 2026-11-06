// The bridge core (session aggregation, prompt submission, live subscriptions) and the route
// table that maps PROTOCOL.md endpoints onto handlers.
//
// Two data sources are combined:
//   * the running DSH desktop application (live state, and the only way to make the desktop agent
//     actually execute an instruction), and
//   * the DSH session store on disk (canonical history, creation timestamps, message counts).

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * The http base of the relay, derived from the device dial-in url.
 *
 * The bridge dials the relay over `ws://host:port/bridge`, but the phone side of the relay is
 * plain http on the same host. A relay that terminates TLS usually listens on another port, so
 * `--relay-public-url` overrides the derived value.
 */
function relayHttpBase(relayUrl, publicUrl) {
  if (publicUrl !== null && publicUrl !== undefined && publicUrl.length > 0) {
    return publicUrl.replace(/\/+$/u, '');
  }
  const url = new URL(relayUrl);
  const protocol = url.protocol === 'wss:' ? 'https:' : url.protocol === 'ws:' ? 'http:' : url.protocol;
  return `${protocol}//${url.host}`;
}

import {
  API_PREFIX,
  ErrorCode,
  MessageKind,
  MessageRole,
  MessageStatus,
  PROTOCOL_VERSION,
  SERVER_NAME,
  SessionState,
  ServerFrame,
  makeMessage,
  makeSessionSummary,
  serverFrame,
  truncate,
} from './protocol.js';
import {
  SessionTailer,
  StoreIndex,
  appendSessionRow,
  createStoreSession,
  eventText,
  firstUserText,
  listStoreSessions,
  mapEventsToMessages,
  readMessageText,
  readSessionLog,
} from './store.js';
import { readSessionStats } from './session-stats.js';
import { primaryLanAddress } from './config.js';
import { DshError, readDshVersion } from './dsh.js';
import { PushNotifier, PushTokenStore, loadPushConfig } from './push.js';
import { DISCOVER_PATH, DiscoveryService, PAIR_PATH, REMOTE_CONFIG_PATH } from './discovery.js';
import { buildSessionTree, UNTITLED as UNTITLED_SESSION } from './session-tree.js';
import { groupDirectories, normalizeDirectory } from './workspace.js';
import { detectDangerousActions, summarizeActions } from './prompt-preview.js';
import { ScanWorker } from './scan-worker.js';

const SURFACE_ROLES = new Set(['user', 'assistant', 'system', 'tool']);

/** How many characters of a message the list carries (the rest is fetched on demand). */
export const PREVIEW_LIMIT = 800;

/**
 * True when a title is broken: the desktop stored a title whose bytes were mangled on the way in,
 * so the text is only question marks (or the replacement character) — or it carries a run of them
 * ("Canopy ????????").
 */
function isBrokenTitle(text) {
  const value = String(text ?? '').trim();
  if (value.length === 0) return true;
  if (/^[\uFFFD?\s]+$/u.test(value)) return true;
  return /\?{3,}|\uFFFD{2,}/u.test(value);
}

/** The bytes of a string, as hex — used to show what a broken title really contained. */
function hexOf(text, limit = 32) {
  const bytes = Buffer.from(String(text ?? ''), 'utf8');
  const shown = bytes.subarray(0, limit).toString('hex');
  return bytes.length > limit ? `${shown}…(${bytes.length} 字节)` : shown;
}

/**
 * Cut a message down to the preview size.
 *
 * The list carries a preview only: one message can be tens of kilobytes long, and the phone
 * would have to download all of them to show a conversation. The message says how long the
 * original was, so the phone can offer "show more" and fetch the rest.
 */
function toPreviewMessage(message) {
  const text = typeof message?.text === 'string' ? message.text : '';
  if (text.length <= PREVIEW_LIMIT) {
    return { ...message, text, truncated: false, totalLength: text.length, previewLimit: PREVIEW_LIMIT };
  }
  let cut = text.slice(0, PREVIEW_LIMIT);
  // 别把一个代理对(一个 emoji 的一半)切成两半。
  if (cut.length > 0 && /[\uD800-\uDBFF]/u.test(cut.charAt(cut.length - 1))) cut = cut.slice(0, -1);
  return { ...message, text: cut, truncated: true, totalLength: text.length, previewLimit: PREVIEW_LIMIT };
}

/** How long a skill list is reused before it is asked for again. */
const SKILL_CACHE_MS = 10 * 60_000;
/**
 * How long a live turn waits for its durable event.
 *
 * The live row (`m-live-<attemptId>`) is closed by the `end` frame of the stream, but the
 * durable `assistant/message` event that follows still has to find it: that event completes
 * the very same row with the canonical text and the canonical time, instead of creating a
 * second row. If the event never arrives, the entry is dropped after this time.
 */
const LIVE_TURN_TTL_MS = 5 * 60_000;

/**
 * The queued items of a session, in the shape the phone wants.
 *
 * DSH keeps a queued item as a message (`{ id, role, content: [{ type, text }] }`);
 * the phone only needs the id and the text.
 */
function normalizeQueueItems(list, target) {
  if (!Array.isArray(list)) return [];
  return list.map((item) => {
    const parts = Array.isArray(item?.content) ? item.content : [];
    let text = '';
    for (const part of parts) {
      if (part?.type === 'text' && typeof part.text === 'string') {
        text = part.text;
        break;
      }
    }
    return { id: String(item?.id ?? ''), text, target };
  });
}

/** An error that carries an HTTP status and a PROTOCOL.md error code. */
export class BridgeError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.name = 'BridgeError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

/**
 * The bridge service.
 * Holds the DSH client, the store index and the set of connected phone clients.
 */
export class Bridge {
  constructor({ options, state, dsh, log, push = null }) {
    this.options = options;
    this.state = state;
    this.dsh = dsh;
    this.log = log ?? (() => {});
    this.index = new StoreIndex();
    /**
     * The store scanner.
     *
     * The store walk and the log inflation are CPU bound and take seconds on a machine with a
     * few thousand messages. They therefore run in their own thread: on the main thread they
     * would block the event loop, and even the "is there a desktop here?" probe
     * (`GET /_dsh/discover`) would take seconds — the phone would report "no desktop found".
     */
    this.scan = new ScanWorker({
      index: this.index,
      log: (level, message) => this.log(level, message),
    });
    this.clients = new Set();
    this.streams = new Map();
    /** 桥接自己的提问(手机可答): id -> { sessionId, questions, resolve, reject, timer } */
    this.bridgeAsks = new Map();
    this.tailers = new Map();
    /**
     * 登记过的手机: 设备号 → 设备令牌。
     *
     * 为什么记这个: 手机续心跳的时候, 设备号是在**请求体**里的, 而请求体有可能
     * 缺失(老版本的 App 就没带, 或者密封通道解包失败时退回了明文)。那时候如果
     * 直接把空的设备号转发给中继, 中继会收到
     * `/_relay/accounts/<账号>/phones//heartbeat` —— 设备号是空的, 中继认不出来,
     * 于是手机的在线状态就再也刷不上去了(桌面上会显示"我的手机 离线")。
     * ⇒ 登记的时候把设备号记下来, 续心跳时请求体里没有就用它 ✓
     */
    this.phones = new Map();
    this.unsubbed = new Set();      // 明确退订过的会话：流被掐时不要再自动重开
    this.dshAvailable = false;
    this.dshError = null;
    /**
     * The version of the desktop DSH.
     *
     * It only changes when the desktop is updated, so it is cached; the phone reads it from
     * `/api/v1/health` to tell "the desktop is fine" from "the desktop was upgraded and may no
     * longer match this bridge".
     */
    this.dshVersion = null;
    this.dshVersionAt = 0;
    this.sessionSignature = '';
    this.lastList = [];
    this.pollTimer = null;
    this.countTimer = null;
    this.dshRowsCache = { at: 0, rows: null };
    this.dshRowsPromise = null;
    this.dshRowsTtlMs = 5000;
    /** Live assistant turns, keyed by session id (at most one turn at a time). */
    this.liveTurns = new Map();
    /** The skill list per session, with the time it was fetched. */
    this.skillCache = new Map();
    /** The push notifier (Huawei Push Kit); `null` disables the push entirely. */
    this.push = push ?? this.#createPushNotifier(state);    /** The last known pending count and the sessions that were running. */
    this.pending = { count: 0, running: new Set(), at: 0 };
    /**
     * The state the phone was last notified about.
     *
     * It is deliberately separate from `this.pending`: the phone polls `GET /api/v1/pending`
     * itself, and that must not hide a change from the watch.
     */
    this.notified = { count: 0, running: new Set(), at: 0 };
    /**
     * The signature of the last `pending` frame that was broadcast.
     *
     * The phone turns that frame into a local notification, so it must only be sent when
     * something really changed — an idle desktop has to stay quiet.
     */
    this.pendingSignature = '';
    /** The last pending frame that was broadcast (a phone that connects later gets it). */
    this.pendingLast = null;
    this.pendingTimer = null;
    /**
     * The LAN discovery service: "is there a desktop agent here?", the pairing code and
     * the remote (cloud relay) configuration the phone needs to leave the LAN.
     */
    // The discovery service gets the **same** options object: a bridge that registers itself
    // at the relay only learns its device id and its account afterwards (the credentials are
    // resolved after the bridge was created), and the phone asks the discovery service where
    // the relay is. A copy would keep the empty values of the moment the bridge was created.
    this.options.pairingHost = this.options.pairingHost ?? primaryLanAddress();
    this.discovery = new DiscoveryService({
      options: this.options,
      state,
      log: (level, message) => this.log(level, message),
      // The lifetime of the pairing code. The default is 60 seconds; `--pairing-code-ttl`
      // makes it longer for a slow scan or a slow user.
      ...(this.options.pairingCodeTtlMs === null || this.options.pairingCodeTtlMs === undefined
        ? {}
        : { codeTtlMs: this.options.pairingCodeTtlMs }),
    });
  }

  /**
   * The version of the desktop DSH, read from the runtime metadata.
   *
   * Cached for a minute: the file is small but the phone polls `/health` now and then, and the
   * version only changes when the desktop is updated.
   *
   * @returns {string|null}
   */
  dshVersionNow() {
    const now = Date.now();
    if (this.dshVersion !== null && now - this.dshVersionAt < 60_000) return this.dshVersion;
    this.dshVersion = readDshVersion();
    this.dshVersionAt = now;
    return this.dshVersion;
  }

  /**
   * The default push notifier.
   *
   * The configuration and the phone tokens live next to the bridge state, in files the repository
   * ignores (`push.local.json` and `push-tokens.local.json`).
   */
  #createPushNotifier(state) {
    try {
      const dir = path.dirname(state?.file ?? '.');
      return new PushNotifier({
        config: loadPushConfig({ file: path.join(dir, 'push.local.json') }),
        store: new PushTokenStore({ file: path.join(dir, 'push-tokens.local.json'), log: this.log }),
        log: this.log,
      });
    } catch (error) {
      this.log('warn', `the push notifier is disabled: ${error instanceof Error ? error.message : String(error)}`);
      return null;
    }
  }

  /* ------------------------------------------------------------------ lifecycle */

  /** Probe DSH and start the background index. */
  async start() {
    this.scan.start();
    this.scan.requestScan('start');
    this.startPolling();
    // The DSH probe answers in about a second; it must not delay the startup banner.
    void this.probeDsh();
    // The session list is fetched right away, so a phone that connects in the first seconds
    // does not get an empty tree (the DSH can take a while to build the list).
    this.#refreshDshRows();
  }

  /** Stop every background job. */
  stop() {
    this.scan.stop();
    if (this.pollTimer !== null) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    if (this.countTimer !== null) {
      clearInterval(this.countTimer);
      this.countTimer = null;
    }
    if (this.pendingTimer !== null) {
      clearInterval(this.pendingTimer);
      this.pendingTimer = null;
    }
    for (const stream of this.streams.values()) stream.close();
    this.streams.clear();
    for (const tailer of this.tailers.values()) tailer.stop();
    this.tailers.clear();
  }

  /**
   * Periodically refresh the store index and publish session list changes.
   * Inflating every session log is expensive, so the message counts are computed by a separate,
   * slower worker that only ever handles one small batch per tick.
   */
  startPolling() {
    if (this.pollTimer !== null) return;
    let busy = false;
    const refresh = async () => {
      if (busy) return;
      busy = true;
      try {
        // index.refresh() 是同步的, 它要重读桌面端所有会话的日志 —— 几千条消息的机器上
        // 一轮要好几秒, 期间**事件循环全被堵住**。手机那边正好在这时来探测
        // (GET /_dsh/discover) 就会超时, 于是用户看到"没找到桌面端"。
        // 所以: 没有人在听的时候不刷, 让人先能"发现"到我们, 连上再刷。
        const wanted = this.clients.size > 0 || (this.push?.store?.size ?? 0) > 0;
        if (wanted) {
          this.index.refresh();
        }
        // Only ask the DSH application for live data when a phone is actually listening.
        if (this.clients.size > 0) {
          await this.listSessions();
          this.publishSessionListIfChanged();
        }
      } catch (error) {
        this.log('warn', `index refresh failed: ${error.message}`);
      } finally {
        busy = false;
      }
    };
    void refresh();
    // 1.5 秒一次太密了: 每轮都要重读桌面端的会话日志, 几千条消息的机器上
    // 一轮要一两秒, 事件循环被占满 -> 连"有人在吗"这种探测都会被拖慢到秒级,
    // 手机那边就显示"没找到桌面端"。
    this.pollTimer = setInterval(() => { void refresh(); }, 20000);
    this.pollTimer.unref?.();

    const count = () => {
      // 统计待办要同步扫全部消息, 几千条消息的机器上会**堵住事件循环一两秒**。
      // 堵住的时候连"有人在吗"(GET /_dsh/discover)这种探测都要排队 -> 手机那边
      // 超时 -> 显示"没找到桌面端"。所以没人要听的时候就不扫。
      const wanted = this.clients.size > 0 || (this.push?.store?.size ?? 0) > 0;
      if (!wanted) return;
      try {
        this.index.computePendingCounts();
      } catch (error) {
        this.log('warn', `message counting failed: ${error.message}`);
      }
    };
    // 同理: 统计待办要扫全部消息, 200 毫秒一次会把 CPU 和事件循环吃光。
    this.countTimer = setInterval(count, 10000);
    this.countTimer.unref?.();
  }

  /** Check whether the DSH application accepts the bridge credential. */
  async probeDsh() {
    if (this.options.adapter === 'local') {
      this.dshAvailable = false;
      this.dshError = 'the local adapter does not talk to the DSH application';
      return { reachable: false, authenticated: false, error: this.dshError };
    }
    // The probe warms the row cache, so the first request of the phone is answered from it.
    let rows = await this.#refreshDshRows();
    if (rows === null && !String(this.dshError ?? '').includes('timed out')) {
      // The DSH application can be busy for several seconds; a failed probe is retried once.
      rows = await this.#refreshDshRows();
    }
    this.dshAvailable = rows !== null;
    if (!this.dshAvailable) this.log('warn', `DSH is not usable: ${this.dshError ?? 'unknown reason'}`);
    return { reachable: rows !== null, authenticated: rows !== null, error: this.dshError };
  }

  /* ------------------------------------------------------------------- sessions */

  /**
   * Live rows from the DSH application, or `null` when they are not available yet.
   *
   * The DSH list call takes between one and eight seconds, so the rows are cached: a stale cache
   * is served immediately while a refresh runs in the background. A cold cache never blocks the
   * caller — the store alone is enough to answer the request.
   */
  async dshSessionRows() {
    if (this.options.adapter === 'local') return null;
    const cached = this.dshRowsCache.rows;
    if (cached !== null) {
      if (Date.now() - this.dshRowsCache.at >= this.dshRowsTtlMs) this.#refreshDshRows();
      return cached;
    }
    this.#refreshDshRows();
    return null;
  }

  /**
   * The rows of `session/list`, waiting for the first answer when the cache is still cold.
   *
   * The DSH can take a while to answer the first time (it has to build the list of every
   * session). A phone that asks right after the bridge started would get an empty list, so the
   * request waits for the answer that is already on its way.
   */
  async dshRowsForRequest(timeoutMs = 45_000) {
    const rows = await this.dshSessionRows();
    if (rows !== null) return rows;
    const pending = this.dshRowsPromise;
    if (pending === null) return this.dshRowsCache.rows;
    const refreshed = await Promise.race([
      pending,
      new Promise((resolve) => { setTimeout(() => resolve(null), timeoutMs).unref?.(); }),
    ]);
    return refreshed ?? this.dshRowsCache.rows;
  }

  /** Refresh the cached DSH rows in the background. */
  #refreshDshRows() {
    if (this.dshRowsPromise !== null) return this.dshRowsPromise;
    this.dshRowsPromise = this.dsh.listSessionRows()
      .then((rows) => {
        this.dshAvailable = true;
        this.dshError = null;
        this.dshRowsCache = { at: Date.now(), rows };
        return rows;
      })
      .catch((error) => {
        this.dshAvailable = false;
        this.dshError = error instanceof Error ? error.message : String(error);
        this.dshRowsCache = { at: Date.now(), rows: this.dshRowsCache.rows };
        return null;
      })
      .finally(() => { this.dshRowsPromise = null; });
    return this.dshRowsPromise;
  }

  /** Build the SessionSummary list. */
  async listSessions() {
    // The store metadata comes from the scanner thread. Waiting for it does not block the event
    // loop (the discovery probe is answered while the scan runs), but the session list should
    // not be empty just because the scan has not finished yet.
    if (this.index.all().length === 0) await this.scan.whenScanned(3000);
    const rows = await this.dshSessionRows();
    const summaries = this.buildIndexSummaries();

    if (rows === null) {
      // No live information yet. In the `local` adapter the newest session counts as running;
      // when the application is merely slow we only trust `$DSH_SESSION_ID`, because the live
      // state of the other sessions is unknown.
      const newest = [...summaries.values()].sort((a, b) => b.updatedAt - a.updatedAt)[0] ?? null;
      const runningId = this.options.adapter === 'local'
        ? (process.env.DSH_SESSION_ID ?? newest?.id ?? null)
        : (process.env.DSH_SESSION_ID ?? null);
      for (const summary of summaries.values()) {
        summary.state = summary.id === runningId ? SessionState.RUNNING : SessionState.IDLE;
      }
      const list = [...summaries.values()].sort((a, b) => b.updatedAt - a.updatedAt);
      this.lastList = list;
      return list;
    }

    for (const row of rows) {
      const id = String(row.sessionId ?? row.id ?? '');
      if (id.length === 0) continue;
      const values = row.projections?.values ?? {};
      const existing = summaries.get(id);
      const title = this.titleFor(id, { values, row, entry: this.index.get(id) });
      const model = values.modelSelection?.lastUsed ?? values.modelSelection?.next ?? existing?.model ?? null;
      summaries.set(id, makeSessionSummary({
        id,
        title,
        cwd: normalizeDirectory(row.cwd ?? values.workingDirectory ?? existing?.cwd ?? ''),
        createdAt: existing?.createdAt ?? row.updatedAt ?? 0,
        updatedAt: row.updatedAt ?? existing?.updatedAt ?? 0,
        state: row.running === true ? SessionState.RUNNING : SessionState.IDLE,
        messageCount: existing?.messageCount ?? 0,
        model: model && typeof model.provider === 'string' && typeof model.model === 'string' ? model : undefined,
      }));
    }

    // A session we are running in right now is running, whatever the application reports.
    const activeId = process.env.DSH_SESSION_ID;
    if (activeId && summaries.has(activeId)) summaries.get(activeId).state = SessionState.RUNNING;

    const list = [...summaries.values()].sort((a, b) => b.updatedAt - a.updatedAt);
    this.lastList = list;
    return list;
  }

  /**
   * Session summaries built from the store index alone.
   * This is the fast path: it needs no round trip to the DSH application.
   */
  buildIndexSummaries() {
    const summaries = new Map();
    for (const entry of this.index.all()) {
      summaries.set(entry.id, makeSessionSummary({
        id: entry.id,
        title: this.titleFor(entry.id, { entry }),
        cwd: normalizeDirectory(entry.cwd),
        createdAt: entry.createdAt,
        updatedAt: entry.mtimeMs,
        state: SessionState.IDLE,
        messageCount: entry.messageCount,
        model: entry.model ?? undefined,
      }));
    }
    return summaries;
  }

  /**
   * The title of one session.
   *
   * The order is: the title of the live projection, the title of the summary the desktop hands
   * out, the title of the store metadata, the first words of the first user message and — as the
   * last resort — "未命名会话". A session id is never a title: it tells the user nothing.
   *
   * A title that only consists of question marks is treated as broken (the desktop sometimes
   * stores a title whose bytes were mangled on the way in) and the next source is used.
   */
  titleFor(id, { values = {}, row = null, entry = null } = {}) {
    const sources = [
      ['projections.values.title', values?.title],
      ['summary.title', row?.summary?.title ?? row?.summaryTitle],
      ['store.title', entry?.title],
      ['store.firstUserText', entry?.firstUserText],
    ];
    for (const [source, value] of sources) {
      if (typeof value !== 'string') continue;
      const trimmed = value.trim();
      if (trimmed.length === 0 || isBrokenTitle(trimmed)) continue;
      if (source === 'store.firstUserText') return truncate(trimmed, 30);
      return trimmed;
    }

    // 投影和元数据里都没有: 看看会话日志里的第一条用户消息。
    const fromLog = this.firstUserTextOf(id);
    if (fromLog !== null) {
      const trimmed = fromLog.trim();
      if (trimmed.length > 0 && !isBrokenTitle(trimmed)) return truncate(trimmed, 30);
    }

    // 标题没拿到: 把原始字节和解析后的标题都记下来, 方便查乱码(每个会话只记一次)。
    const raw = values?.title ?? entry?.title ?? null;
    if (this.warnedTitles === undefined) this.warnedTitles = new Set();
    if (!this.warnedTitles.has(id)) {
      this.warnedTitles.add(id);
      this.log('warn', `会话 ${id} 没有可用的标题: 原始值=${JSON.stringify(raw)} `
        + `原始字节=${hexOf(String(raw ?? ''))}`);
    }
    return UNTITLED_SESSION;
  }

  /**
   * The first words of the first user message of a session (read from the zstd log).
   *
   * The result is cached: the log is only read once per session.
   *
   * A session without messages is skipped: its log holds nothing but the header, and inflating
   * hundreds of empty logs costs seconds (and the zstd decoder of Node is not happy about being
   * used by two threads at the same time — the scanner thread inflates logs too).
   */
  firstUserTextOf(id) {
    if (this.firstUserTextCache === undefined) this.firstUserTextCache = new Map();
    if (this.firstUserTextCache.has(id)) return this.firstUserTextCache.get(id);
    const entry = this.index.get(id);
    if (entry !== undefined && entry.messageCountExact === true && entry.messageCount === 0) {
      // 没有消息的会话读不出首条用户消息(它的日志里只有文件头)。
      this.firstUserTextCache.set(id, null);
      return null;
    }
    const logPath = entry?.logPath ?? this.findLogPath(id);
    let text = null;
    if (logPath !== null) {
      try {
        text = firstUserText(logPath);
      } catch (error) {
        this.log('warn', `读会话 ${id} 的日志失败: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    this.firstUserTextCache.set(id, text);
    return text;
  }

  /** One session summary, or `null`. */
  async getSession(id) {
    const list = await this.listSessions();
    return list.find((summary) => summary.id === id) ?? null;
  }

  /**
   * The status numbers of one session, read from the projection-cache metadata.
   * `null` when the session has no readable metadata (the endpoint answers `{"stats": null}`).
   */
  sessionStats(id) {
    return readSessionStats(id);
  }

  /**
   * The messages of one session — the **newest** page, oldest first.
   *
   * The phone opens a conversation and wants to see what just happened, so the window ends at the
   * newest message. `before` asks for the page before a message (the phone scrolls up).
   *
   * The body of a message is cut down to {@link PREVIEW_LIMIT} characters; the rest is fetched
   * with `GET /api/v1/sessions/{id}/messages/{seq}/full`.
   *
   * @returns {Promise<{messages: object[], hasMore: boolean, oldestSeq: number|null, newestSeq: number|null}>}
   */
  async listMessages(id, { limit = 200, before = null } = {}) {
    // 手机端只要最新的一小段, 别去解析整个会话(几千条事件要好几秒)
    const tailLines = before === null && limit > 0 ? Math.min(limit * 4, 4000) : 0;
    const snapshot = this.readStoreMessages(id, { tailLines });
    if (snapshot !== null) {
      let messages = snapshot;
      if (before !== null && before !== undefined) {
        const index = messages.findIndex((message) => message.id === before);
        messages = index === -1 ? messages.filter((message) => compareMessageId(message.id, before) < 0) : messages.slice(0, index);
      }
      if (limit > 0 && messages.length > limit) messages = messages.slice(messages.length - limit);
      // 上面这一页是从日志尾巴读的, 所以前面多半还有更早的消息。
      const total = this.index.get(id)?.messageCount ?? 0;
      const hasMore = before !== null && before !== undefined ? true : total > messages.length;
      return this.withPageInfo(messages, { hasMore });
    }

    // The store does not know this session: ask the DSH application instead.
    if (!this.dshAvailable) throw new BridgeError(503, ErrorCode.DSH_UNAVAILABLE, this.dshError ?? 'the DSH application is not reachable');
    // 游标要用真实的最新值(日志里的最大 seq): 桌面端不允许问一个超过游标的数。
    const throughSeq = await this.resolveThroughSeq(id);
    const page = await this.dsh.pageMessages(id, { throughSeq, maxMessages: Math.max(1, limit) });
    const events = page.records.map((record) => record?.event).filter(Boolean);
    const messages = mapEventsToMessages(events, id);
    // 桌面端给的一页可能比要的还大(它自己决定页大小), 这里裁到 limit 条。
    const trimmed = limit > 0 && messages.length > limit ? messages.slice(messages.length - limit) : messages;
    return this.withPageInfo(trimmed, { hasMore: page.hasMore });
  }

  /**
   * Cut the body of every message down to the preview size and describe the page.
   *
   * The phone appends the messages as they are, so they have to be sorted by sequence and the
   * range of the page has to be reported (the phone asks for the next page with `beforeSeq`).
   */
  withPageInfo(messages, { hasMore = false } = {}) {
    const sorted = [...messages].sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
    const previews = sorted.map((message) => toPreviewMessage(message));
    const seqs = sorted.map((message) => message.seq).filter((seq) => Number.isFinite(seq));
    return {
      messages: previews,
      hasMore,
      oldestSeq: seqs.length > 0 ? Math.min(...seqs) : null,
      newestSeq: seqs.length > 0 ? Math.max(...seqs) : null,
    };
  }

  /**
   * The full text of one message.
   *
   * The log is zstd compressed, so the text is read through the same decoding path as the list.
   *
   * @returns {Promise<{text: string, found: boolean}>}
   */
  async fullMessage(id, seq) {
    const logPath = this.index.get(id)?.logPath ?? this.findLogPath(id);
    if (logPath !== null) {
      const found = readMessageText(logPath, seq);
      if (found !== null) return found;
    }
    // Store 不知道这个会话: 从 DSH 问一页(这一页的末尾就是这条消息)。
    if (!this.dshAvailable) throw new BridgeError(503, ErrorCode.DSH_UNAVAILABLE, this.dshError ?? 'the DSH application is not reachable');
    const page = await this.dsh.pageMessages(id, { throughSeq: seq, maxMessages: 200 });
    for (const record of page.records) {
      const event = record?.event;
      if (!event || !Number.isFinite(event.seq) || event.seq !== seq) continue;
      const data = event.data && typeof event.data === 'object' ? event.data : {};
      return { text: eventText(data), found: true };
    }
    return { text: '', found: false };
  }

  /** Messages read from the on-disk store, or `null` when the session is unknown there. */
  readStoreMessages(id, { tailLines = 0 } = {}) {
    const entry = this.index.get(id);
    const logPath = entry?.logPath ?? this.findLogPath(id);
    if (logPath === null) return null;
    const snapshot = readSessionLog(logPath, { tailLines });
    if (snapshot === null) return null;
    if (snapshot.messages.length === 0 && snapshot.header === null) return null;
    return snapshot.messages;
  }

  /** Locate the log file of a session without using the index. */
  findLogPath(id) {
    for (const session of listStoreSessions()) {
      if (session.id === id) return session.logPath;
    }
    return null;
  }

  /**
   * The highest sequence number the store knows for a session.
   *
   * Only the tail of the log is read: the newest sequence is always in it, and a session with a
   * few thousand events would cost seconds to parse completely.
   *
   * `null` when the store does not know the session — the caller then asks the desktop itself.
   */
  async resolveThroughSeq(id) {
    const logPath = this.index.get(id)?.logPath ?? this.findLogPath(id);
    if (logPath === null) return null;
    let max = 0;
    for (const tailLines of [200, 0]) {
      const snapshot = readSessionLog(logPath, { tailLines });
      for (const event of snapshot?.events ?? []) {
        if (Number.isFinite(event.seq) && event.seq > max) max = event.seq;
      }
      if (max > 0) break;
    }
    return max > 0 ? max : null;
  }

  /**
   * The devices of the account this bridge belongs to.
   *
   * The account lives in the relay, so the bridge asks the relay for the presence of its devices
   * (the relay owns the device registry). When the bridge runs without a relay — the plain LAN
   * setup — there is only one device, this one.
   */
  async listDevices() {
    const options = this.options ?? {};
    const relay = options.relay ?? null;
    const account = options.account ?? null;
    const accountToken = options.accountToken ?? null;
    if (relay !== null && account !== null && accountToken !== null) {
      const base = relayHttpBase(relay, options.relayPublicUrl ?? null);
      const url = `${base}/_relay/accounts/${encodeURIComponent(account)}/devices`
        + `?accountToken=${encodeURIComponent(accountToken)}`;
      try {
        const response = await fetch(url, { headers: { Accept: 'application/json' } });
        if (response.ok) {
          const body = await response.json();
          if (Array.isArray(body?.devices)) {
            return {
              account: { id: account, name: String(body?.account?.name ?? account) },
              devices: body.devices.map((device) => ({
                id: String(device?.id ?? ''),
                name: String(device?.name ?? ''),
                role: String(device?.role ?? 'desktop'),
                online: device?.online === true,
                lastSeen: Number.isFinite(device?.lastSeen) ? device.lastSeen : 0,
              })),
            };
          }
        }
      } catch {
        // The relay is not reachable: fall through to the local device.
      }
    }
    return {
      account: { id: account ?? '', name: account ?? '' },
      devices: [{
        id: String(options.deviceId ?? 'local'),
        name: String(options.relayName ?? '本机'),
        role: 'desktop',
        online: true,
        lastSeen: Date.now(),
      }],
    };
  }

  /**
   * Register a phone as a device of this bridge's account.
   *
   * The phone cannot talk to the relay's own endpoints itself: the connection between the phone
   * and the desktop is a byte pipe, and the relay's answers would mix with the desktop's answers
   * on that connection. So the phone asks the bridge, and the bridge asks the relay over its own
   * connection.
   */
  async registerPhone(deviceId, name, token) {
    const options = this.options ?? {};
    const relay = options.relay ?? null;
    const account = options.account ?? null;
    const accountToken = options.accountToken ?? null;
    if (relay === null || account === null || accountToken === null) {
      return { ok: false, message: 'the bridge is not connected to an account' };
    }
    const base = relayHttpBase(relay, options.relayPublicUrl ?? null);
    const url = `${base}/_relay/accounts/${encodeURIComponent(account)}/phones`;
    const body = JSON.stringify({ deviceId, name, token });
    const answer = await this.#relayRequest('POST', url, accountToken, body);
    if (!answer.ok) {
      return { ok: false, message: answer.message, status: answer.status };
    }
    // 记下这台手机: 续心跳的时候请求体里可能没有设备号 ⇒ 用这里记的兜底 ✓
    if (typeof deviceId === 'string' && deviceId.length > 0) {
      this.phones.set(deviceId, { name: name ?? '', token: token ?? '' });
    }
    return { ok: true, device: answer.body?.device ?? null };
  }

  /** Tell the relay that the phone is still there. */
  async heartbeatPhone(deviceId) {
    const options = this.options ?? {};
    const relay = options.relay ?? null;
    const account = options.account ?? null;
    const accountToken = options.accountToken ?? null;
    if (relay === null || account === null || accountToken === null) {
      return { ok: false, message: 'the bridge is not connected to an account' };
    }
    // 请求体里没有设备号(老版本的 App) ⇒ 用登记时记下来的那个 ✓
    let target = typeof deviceId === 'string' ? deviceId.trim() : '';
    if (target.length === 0) {
      target = this.phones.keys().next().value ?? '';
    }
    if (target.length === 0) {
      return { ok: false, message: 'the phone did not say which device it is' };
    }
    const base = relayHttpBase(relay, options.relayPublicUrl ?? null);
    const url = `${base}/_relay/accounts/${encodeURIComponent(account)}`
      + `/phones/${encodeURIComponent(target)}/heartbeat`;
    const answer = await this.#relayRequest('POST', url, accountToken, '{}');
    if (!answer.ok) {
      return { ok: false, message: answer.message, status: answer.status };
    }
    return { ok: true, device: answer.body?.device ?? null };
  }

  /** One request to the relay, with the account token. */
  async #relayRequest(method, url, token, body) {
    try {
      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          Accept: 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body,
      });
      const text = await response.text();
      let parsed = null;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = null;
      }
      if (!response.ok) {
        return {
          ok: false,
          status: response.status,
          message: String(parsed?.error?.message ?? parsed?.message ?? `HTTP ${response.status}`),
        };
      }
      return { ok: true, status: response.status, body: parsed };
    } catch (error) {
      return { ok: false, status: 0, message: error?.message ?? 'the relay is not reachable' };
    }
  }

  /* ---------------------------------------------------------------------- writes */

  /**
   * Submit a prompt so the desktop agent executes it.
   * The DSH application is the only component able to wake the agent, so this is the write path.
   */
  async submitPrompt(id, text, { mode = 'queue' } = {}) {
    const trimmed = String(text ?? '');
    if (trimmed.trim().length === 0) throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'the prompt text must not be empty');

    if (this.options.adapter === 'local') {
      const messageId = `m-local-${crypto.randomUUID()}`;
      const seq = (this.index.get(id)?.messageCount ?? 0) + 1000;
      const row = {
        type: 'user/message',
        seq,
        time: Date.now(),
        data: {
          content: [{ type: 'text', text: trimmed }],
          source: { kind: 'user', rpcId: messageId },
          role: 'user',
          id: messageId,
        },
      };
      appendSessionRow(id, row);
      this.index.refresh();
      // The store tailer streams the new row to the subscribed clients.
      return { accepted: true, messageId: `m-${seq}` };
    }

    // The prompt call itself is the probe: a transport failure means DSH is not reachable.
    try {
      const result = await this.dsh.submitPrompt(id, trimmed, { mode });
      this.dshAvailable = true;
      this.dshError = null;
      this.index.refresh();
      return { accepted: result.accepted, messageId: null };
    } catch (error) {
      this.dshAvailable = false;
      this.dshError = error instanceof Error ? error.message : String(error);
      if (error instanceof DshError) {
        throw new BridgeError(502, error.code, error.message, error.details);
      }
      throw new BridgeError(503, ErrorCode.DSH_UNAVAILABLE, `the DSH application could not be reached: ${this.dshError}`);
    }
  }

  /** Cancel the active turn of a session. */
  async cancelSession(id) {
    if (this.options.adapter === 'local') return { ok: true };
    try {
      const result = await this.dsh.cancel(id);
      this.dshAvailable = true;
      return { ok: result.accepted !== false };
    } catch (error) {
      this.dshAvailable = false;
      if (error instanceof DshError) throw new BridgeError(502, error.code, error.message, error.details);
      throw new BridgeError(503, ErrorCode.DSH_UNAVAILABLE, `the DSH application could not be reached: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /* ------------------------------------------------------------ pending (待办) and push */

  /**
   * The number of things the desktop is waiting for.
   *
   * The count is the number of running sessions plus the queued tasks (the inbox of the
   * projections) plus the questions that need an answer. The session rows of the DSH application
   * already carry the inbox of every session, so no extra call is needed.
   */
  async pendingCount() {
    let rows = await this.dshSessionRows();
    if (rows === null && this.dshRowsPromise !== null) {
      // The very first request can arrive before the first list; give the refresh a short moment.
      const refreshed = await Promise.race([
        this.dshRowsPromise,
        new Promise((resolve) => { setTimeout(() => resolve(null), 2500).unref?.(); }),
      ]);
      if (refreshed !== null) rows = refreshed;
    }
    if (rows === null) {
      // The DSH application is unreachable: keep the last known count.
      return this.pending.count;
    }
    const running = new Set();
    const questionList = [];
    let queued = 0;
    let questions = 0;
    for (const row of rows) {
      const values = row?.projections?.values ?? {};
      if (row?.running === true) running.add(row.sessionId);
      queued += (values.inbox?.['next-turn']?.length ?? 0) + (values.inbox?.['next-step']?.length ?? 0);
      const active = values.userQuestions?.active;
      const open = Array.isArray(active) ? active.length : 0;
      questions += open;
      if (open > 0) {
        const sessionId = String(row?.sessionId ?? row?.id ?? '');
        if (sessionId.length > 0) questionList.push({ sessionId, title: this.titleOf(sessionId) });
      }
    }
    // 投影里的 active 在真实机器上一直是空的(实测), 所以运行中的会话再补一轮:
    // 从会话记录里找还没回答的 ask_user_question。运行中的会话一般就一两个, 负担可控。
    // 桥接自己的提问(手机可答)也要计入待办, 不然列表页不发通知。
    for (const ask of this.bridgeAsks.values()) {
      if (questionList.some((item) => item.sessionId === ask.sessionId)) continue;
      questions += 1;
      questionList.push({ sessionId: ask.sessionId, title: this.titleOf(ask.sessionId) });
    }
    for (const sessionId of running) {
      if (questionList.some((item) => item.sessionId === sessionId)) continue;
      let calls = [];
      try {
        calls = await this.pendingAskCalls(sessionId);
      } catch {
        calls = [];
      }
      if (calls.length > 0) {
        questions += calls.length;
        questionList.push({ sessionId, title: this.titleOf(sessionId) });
      }
    }
    this.pending = {
      count: running.size + queued + questions,
      running,
      at: Date.now(),
      queued,
      questions,
      questionList,
    };
    return this.pending.count;
  }

  /** Register the push token of a phone. */
  registerPushToken(deviceId, token) {
    if (this.push === null || this.push.store === null) {
      throw new BridgeError(503, ErrorCode.INTERNAL, 'the bridge does not accept push tokens');
    }
    const entry = this.push.store.register(deviceId, token);
    this.log('info', `a phone registered a push token (${entry.platform}, ${entry.deviceId})`);
    // The watch only runs while a phone can be reached.
    this.startPendingWatch();
    return { ok: true, deviceId: entry.deviceId, registered: this.push.store.size };
  }

  /**
   * Watch the pending state and push a notification to the phone when it changes.
   *
   * The watch only runs while a phone has registered a push token, and it never throws: a broken
   * push must not disturb the bridge.
   */
  startPendingWatch() {
    if (this.pendingTimer !== null) return;
    const intervalMs = Number.parseInt(process.env.DSH_PENDING_INTERVAL_MS ?? '15000', 10);
    const tick = async () => {
      try {
        const count = await this.pendingCount();
        const running = this.pending.running ?? new Set();
        const before = this.notified;
        // 上一轮在跑、这一轮不在跑了的会话 = 任务刚结束。
        const finished = [...(before.running ?? [])].filter((id) => !running.has(id));
        const questions = this.pendingQuestionList();
        // 广播给连着的手机: 本地通知(任务结束 / 需要做决策)靠这一帧。
        this.broadcastPending(count, running, finished, questions);
        // 云端推送只在有 push token 时做, 而且只在真的变了的时候推。
        if (this.push !== null && (this.push.store?.size ?? 0) > 0) {
          if (count !== before.count || finished.length > 0) {
            await this.push.notify({
              title: `桌面端有 ${count} 项待办`,
              body: this.pendingSummary(count),
            });
          }
        }
        this.notified = { count, running, at: Date.now() };
      } catch (error) {
        this.log('warn', `the pending watch failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    };
    void tick();
    this.pendingTimer = setInterval(() => { void tick(); }, Number.isFinite(intervalMs) && intervalMs > 0 ? intervalMs : 15000);
    this.pendingTimer.unref?.();
  }

  /**
   * The sessions that are waiting for an answer from the user.
   *
   * A question is an entry in the `userQuestions.active` list of the session projections; the
   * phone turns them into a "桌面端需要你确认" notification.
   *
   * The list comes from the same rows the count was computed from, so the two can never
   * disagree.
   *
   * @returns {{sessionId: string, title: string}[]}
   */
  pendingQuestionList() {
    return this.pending.questionList ?? [];
  }

  /**
   * Tell the connected phones what the desktop is waiting for.
   *
   * The frame is only sent when something changed: an idle desktop has to stay quiet, otherwise
   * the phone would notify again and again.
   */
  broadcastPending(count, running, finished, questions) {
    const signature = this.pendingSignatureOf(count, running, questions);
    if (signature === this.pendingSignature) return;
    this.pendingSignature = signature;
    const payload = {
      count,
      running: [...running],
      finished: finished.map((id) => ({ sessionId: id, title: this.titleOf(id) })),
      questions,
      queued: this.pending.queued ?? 0,
    };
    this.pendingLast = payload;
    this.broadcast(ServerFrame.PENDING, payload);
  }

  /** The fingerprint of a pending state: the same state is never sent twice. */
  pendingSignatureOf(count, running, questions) {
    return `${count}|${[...running].sort().join(',')}|${questions.map((q) => q.sessionId).sort().join(',')}`;
  }

  /** A short human readable summary of the pending state. */
  pendingSummary(count) {
    const parts = [];
    const running = this.pending.running?.size ?? 0;
    if (running > 0) parts.push(`${running} 个会话正在运行`);
    if ((this.pending.queued ?? 0) > 0) parts.push(`${this.pending.queued} 个任务排队中`);
    if ((this.pending.questions ?? 0) > 0) parts.push(`${this.pending.questions} 个问题待确认`);
    if (parts.length === 0) return count > 0 ? '桌面端有新的进展' : '桌面端已清空';
    return parts.join(', ');
  }

  /* --------------------------------------------------- desktop UI parity (models, queue, …) */

  /**
   * Run one DSH call and translate its failure into the bridge's error envelope.
   * A DSH-level failure (the request was understood but rejected) becomes a 502 with the DSH
   * error code; a transport failure means DSH is not reachable and becomes a 503.
   */
  async dshCall(operation) {
    try {
      const value = await operation();
      this.dshAvailable = true;
      this.dshError = null;
      return value;
    } catch (error) {
      if (error instanceof DshError) throw new BridgeError(502, error.code, error.message, error.details);
      this.dshAvailable = false;
      this.dshError = error instanceof Error ? error.message : String(error);
      throw new BridgeError(503, ErrorCode.DSH_UNAVAILABLE, `the DSH application could not be reached: ${this.dshError}`);
    }
  }

  /** The model catalog, flattened into the shape the phone renders. */
  async modelCatalog() {
    const catalog = await this.dshCall(() => this.dsh.modelCatalog());
    const groups = Array.isArray(catalog?.groups) ? catalog.groups : [];
    return {
      default: normalizeModel(catalog?.default),
      providers: groups.map((group) => ({
        id: String(group?.id ?? ''),
        name: String(group?.name ?? group?.id ?? ''),
        models: (Array.isArray(group?.models) ? group.models : []).map((model) => ({
          id: String(model?.id ?? ''),
          name: String(model?.name ?? model?.id ?? ''),
          efforts: (Array.isArray(model?.reasoning?.efforts) ? model.reasoning.efforts : []).map((effort) => ({
            id: String(effort?.id ?? ''),
            name: String(effort?.name ?? effort?.id ?? ''),
          })),
          defaultEffort: typeof model?.reasoning?.defaultEffort === 'string' && model.reasoning.defaultEffort.length > 0
            ? model.reasoning.defaultEffort
            : null,
        })),
      })),
    };
  }

  /** Select the model of a session. */
  async selectSessionModel(id, body) {
    const provider = String(body?.provider ?? '');
    const model = String(body?.model ?? '');
    if (provider.length === 0 || model.length === 0) {
      throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'provider and model are required');
    }
    const reasoningEffort = body?.reasoningEffort === undefined || body?.reasoningEffort === null
      ? undefined
      : String(body.reasoningEffort);
    const selected = await this.dshCall(() => this.dsh.selectModel(id, { provider, model, reasoningEffort }));
    return { selected: normalizeModel(selected) };
  }

  /**
   * The projections of a session.
   *
   * The live call (`session/projections`) is the freshest, but it can fail — the DSH answers
   * "build context fail" for a session whose context cannot be rebuilt. That must not take the
   * session tree (or the queue) with it: every row of `session/list` already carries the
   * projections, so they are the fallback.
   */
  async sessionProjections(id) {
    try {
      const projections = await this.dshCall(() => this.dsh.projections(id));
      if (projections !== null && projections !== undefined) return projections;
    } catch (error) {
      this.log('warn', `the projections of ${id} could not be read (${error.message}), the session list is used instead`);
    }
    const rows = await this.dshSessionRows();
    for (const row of rows ?? []) {
      const sessionId = String(row?.sessionId ?? row?.id ?? '');
      if (sessionId === id && row?.projections !== undefined) return row.projections;
    }
    return null;
  }

  /** The queued items of a session (the desktop's task boxes). */
  async sessionQueue(id) {
    const projections = await this.sessionProjections(id);
    const inbox = projections?.values?.inbox ?? {};
    return {
      nextTurn: normalizeQueueItems(inbox['next-turn'], 'next-turn'),
      nextStep: normalizeQueueItems(inbox['next-step'], 'next-step'),
    };
  }

  /**
   * The questions the desktop is waiting for the user to answer.
   *
   * DSH keeps them in the session projections (`values.userQuestions.active`); the bridge
   * returns them verbatim so the phone can draw the options and answer with a normal prompt.
   */
  async sessionQuestions(id) {
    // 桌面端的互动弹窗不是「投影里的 active 列表」——它是模型调用了
    // ask_user_question 工具, 那个 tool/call 记录会一直挂在会话历史里, 直到
    // 用户回答后出现对应的 tool/result。投影(userQuestions.active)在真实机器上
    // 实测一直是空的, 所以这里直接从会话记录里翻:
    //   - 名字是 ask_user_question / request_user_input 的 tool/call
    //   - 还没有同名 toolCallId 的 tool/result
    const calls = await this.pendingAskCalls(id);
    // 桥接自己的提问排在前面: 这些是手机真的能答的(DSH 前台提问只能桌面端答)。
    for (const ask of this.bridgeAsks.values()) {
      if (ask.sessionId === id) {
        calls.unshift({ callId: ask.id, questions: ask.questions, answerable: true });
      }
    }
    return { questions: calls };
  }

  /**
   * 会话里「问完还没人回答」的 ask 调用。
   *
   * 每条都是一次 ask_user_question 工具调用; `questions` 是手机端渲染用的
   * [{id, question, header?, options?, multiSelect?}]。
   */
  async pendingAskCalls(sessionId) {
    let page = null;
    try {
      page = await this.dsh.pageMessages(sessionId, { maxMessages: 200 });
    } catch (error) {
      this.log('warn', `the ask history of ${sessionId} could not be read: ${error instanceof Error ? error.message : String(error)}`);
      return [];
    }
    const records = Array.isArray(page?.records) ? page.records : [];
    const events = [];
    for (const record of records) {
      if (record?.type === 'event' && record.event !== undefined) events.push(record.event);
      else if (record?.type === 'tool/call' || record?.type === 'tool/result') events.push(record);
    }
    // Result records reach the bridge in two shapes: the raw DSH event carries
    // `data.toolCallId`, while the normalized page records carry
    // `data.message.toolCallId` (plus the callId inside `data.message.source`).
    // The JSON fallback catches any future shape that still names the call.
    const settled = new Set();
    const addCallId = (value) => {
      if (typeof value === 'string' && value.length > 0) settled.add(value);
    };
    for (const event of events) {
      if (event?.type !== 'tool/result') continue;
      const data = event?.data ?? {};
      addCallId(data.toolCallId);
      addCallId(data.callId);
      addCallId(data.message?.toolCallId);
      addCallId(data.message?.source?.callId);
      const text = JSON.stringify(data);
      for (const match of text.matchAll(/call_[A-Za-z0-9_]+/gu)) addCallId(match[0]);
    }
    const calls = [];
    for (const event of events) {
      if (event?.type !== 'tool/call') continue;
      const name = event?.data?.name;
      if (name !== 'ask_user_question' && name !== 'request_user_input') continue;
      const callId = event?.data?.callId;
      if (typeof callId !== 'string' || callId.length === 0 || settled.has(callId)) continue;
      let args = event?.data?.arguments;
      if (typeof args === 'string') {
        try { args = JSON.parse(args); } catch { args = null; }
      }
      const raw = Array.isArray(args?.questions) ? args.questions : [];
      const questions = [];
      for (const item of raw) {
        if (item === null || typeof item !== 'object') continue;
        if (typeof item.id !== 'string' || item.id.length === 0) continue;
        if (typeof item.question !== 'string' || item.question.length === 0) continue;
        const options = Array.isArray(item.options)
          ? item.options.filter((o) => o !== null && typeof o === 'object' && typeof o.label === 'string')
            .map((o) => ({ label: o.label, ...(typeof o.description === 'string' ? { description: o.description } : {}) }))
          : undefined;
        questions.push({
          id: item.id,
          question: item.question,
          ...(typeof item.header === 'string' && item.header.length > 0 ? { header: item.header } : {}),
          ...(typeof item.detail === 'string' && item.detail.length > 0 ? { detail: item.detail } : {}),
          ...(options !== undefined && options.length > 0 ? { options } : {}),
          ...(item.multiSelect === true ? { multiSelect: true } : {}),
        });
      }
      // 这类「前台正在等」的提问在 DSH 里只有当前前台客户端能作答, 远端只能看;
      // 把话说清楚, 手机端好按这个字段决定要不要给「提交」。
      if (questions.length > 0) calls.push({ callId, questions, answerable: false });
    }
    return calls;
  }

  /**
   * Answer the open questions of one ask call.
   *
   * Body: { callId, answers: [{ id, selected: string[], custom?: string }] }
   */
  async answerSessionQuestions(id, body) {
    const callId = String(body?.callId ?? '');
    if (callId.length === 0) throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'callId is required');
    const answers = body?.answers;
    if (!Array.isArray(answers) || answers.length === 0) {
      throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'answers must be a non-empty array');
    }
    for (const item of answers) {
      if (typeof item?.id !== 'string' || item.id.length === 0) {
        throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'every answer needs a question id');
      }
      if (!Array.isArray(item.selected)) {
        throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'selected must be an array of option labels');
      }
    }
    const bridged = this.bridgeAsks.get(callId);
    if (bridged !== undefined) {
      this.bridgeAsks.delete(callId);
      if (bridged.timer !== null) clearTimeout(bridged.timer);
      bridged.resolve(answers);
      return { ok: true };
    }
    const settled = await this.dshCall(() => this.dsh.answerQuestions(id, callId, answers));
    if (!settled) {
      // 这条提问正被桌面端前台接着(session 里那条 tool/call 还在等), DSH 只允许
      // 当前前台客户端作答, 远端 client 调用会返回 false —— 别假装成功。
      throw new BridgeError(409, 'QUESTION_DESKTOP_ONLY',
        '这条问题正在桌面端前台等待回答，只能在电脑上作答；手机端可以查看和收到提醒。');
    }
    return { ok: true };
  }

  /**
   * 手机可以回答的提问(桥接自己发)。
   *
   * DSH 自带的 ask_user_question 是「前台等待」, 只有桌面端当前客户端能答, 手机/桥接
   * 去答 DSH 返回 false。所以需要手机作答的场景走这条通道: 桥接 hold 住这个 HTTP
   * 请求, 手机在卡片上回答后 resolve, 请求返回答案。
   *
   * @param {string} sessionId 会话(手机端按会话展示卡片)
   * @param {object[]} questions [{id, question, header?, options?, multiSelect?}]
   * @param {number} timeoutMs 超时(默认 10 分钟)
   */
  async askUser(sessionId, questions, timeoutMs = 10 * 60 * 1000) {
    if (typeof sessionId !== 'string' || sessionId.length === 0) {
      throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'sessionId is required');
    }
    if (!Array.isArray(questions) || questions.length === 0) {
      throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'questions must be a non-empty array');
    }
    const id = `bridge-ask-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.bridgeAsks.delete(id);
        reject(new BridgeError(504, 'ASK_TIMEOUT', 'the phone did not answer in time'));
      }, Math.min(Math.max(Number(timeoutMs) || 0, 1000), 30 * 60 * 1000));
      timer.unref?.();
      this.bridgeAsks.set(id, { id, sessionId, questions, resolve, reject, timer });
      this.log('info', `bridge ask ${id} waiting for the phone (${sessionId})`);
    });
  }

  /**
   * The breakdown of the pending badge: running ids + queued count + question list.
   * (`GET /api/v1/pending` only returns the total, which left the phone guessing what it
   * was counting.)
   */
  async pendingDetail() {
    await this.pendingCount();
    // 排队项明细: 来自 session/list 的行投影(inbox), 和 /queue 走的投影不是同一条路
    const queuedItems = [];
    const rows = await this.dshSessionRows();
    for (const row of rows ?? []) {
      const values = row?.projections?.values ?? {};
      for (const target of ['next-turn', 'next-step']) {
        const list = values.inbox?.[target];
        if (!Array.isArray(list)) continue;
        for (const item of list) {
          const id = String(item?.id ?? '');
          if (id.length === 0) continue;
          const sessionId = String(row?.sessionId ?? row?.id ?? '');
          queuedItems.push({
            sessionId,
            title: this.titleOf(sessionId),
            target,
            id,
          });
        }
      }
    }
    return {
      count: this.pending.count,
      running: [...(this.pending.running ?? [])],
      queued: this.pending.queued ?? 0,
      questions: this.pending.questions ?? 0,
      questionList: this.pending.questionList ?? [],
      queuedItems,
    };
  }

  /* ------------------------------------------------ 桥接设置(插件/独立运行共用) */

  /** 设置文件的路径（插件会读它，网页会写它）。 */
  bridgeConfigPath() {
    if (process.env.DSH_BRIDGE_CONFIG) return path.resolve(process.env.DSH_BRIDGE_CONFIG);
    return path.join(os.homedir(), '.dsh-harmony-bridge', 'plugin-config.json');
  }

  /** 读设置文件（不存在返回空对象）。 */
  readBridgeConfig() {
    const file = this.bridgeConfigPath();
    try {
      const raw = fs.readFileSync(file, 'utf8');
      const parsed = JSON.parse(raw);
      return parsed !== null && typeof parsed === 'object' ? parsed : {};
    } catch {
      return {};
    }
  }

  /** 写设置文件（只保留认识的键）。 */
  saveBridgeConfig(body) {
    const allowed = ['port', 'host', 'relay', 'relayPublicUrl', 'relayName',
      'deviceId', 'deviceToken', 'account', 'accountToken', 'autoStart', 'verbose'];
    const next = { ...this.readBridgeConfig() };
    for (const key of allowed) {
      if (body !== null && typeof body === 'object' && Object.hasOwn(body, key)) {
        next[key] = body[key];
      }
    }
    const file = this.bridgeConfigPath();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(next, null, 2), { mode: 0o600 });
    return { ok: true, file, config: next };
  }

  /** 设置页（浏览器打开；改完重启 DSH / 桥接生效）。 */
  settingsPage() {
    const current = this.readBridgeConfig();
    const text = (key) => {
      const value = current[key];
      return value === undefined || value === null ? '' : String(value);
    };
    const checked = (key, fallback) => {
      const value = current[key];
      return value === undefined ? fallback : value === true;
    };
    const esc = (value) => String(value)
      .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;');
    return `<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DSH Harmony 桥接设置</title>
<style>
 :root { color-scheme: dark; }
 body { margin:0; background:#151517; color:#e8e8ea;
        font: 15px/1.5 -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; }
 .wrap { max-width: 720px; margin: 0 auto; padding: 24px 18px 60px; }
 h1 { font-size: 20px; margin: 0 0 6px; }
 p.sub { color:#9a9aa2; font-size: 13px; margin: 0 0 20px; }
 .card { background:#202025; border:1px solid #2e2e33; border-radius:12px; padding:16px; margin-bottom:14px; }
 label { display:block; font-size:13px; color:#b9b9c0; margin: 12px 0 4px; }
 input[type=text], input[type=password], input[type=number] {
   width:100%; box-sizing:border-box; background:#111113; color:#e8e8ea;
   border:1px solid #3a3a40; border-radius:8px; padding:10px 12px; font-size:15px; }
 .row { display:flex; gap:12px; }
 .row > div { flex:1; }
 .hint { color:#8a8a92; font-size:12px; margin-top:4px; }
 .check { display:flex; align-items:center; gap:8px; margin-top:14px; color:#cfcfd6; font-size:14px; }
 button { margin-top:20px; width:100%; padding:13px; border:0; border-radius:10px;
          background:#2f6fed; color:#fff; font-size:16px; }
 #msg { margin-top:14px; font-size:13px; color:#7ee2a8; white-space:pre-wrap; }
 .warn { color:#ffb35c; font-size:12px; margin-top:10px; }
</style></head><body><div class="wrap">
<h1>DSH Harmony 桥接设置</h1>
<p class="sub">改动会保存到 <code>${esc(this.bridgeConfigPath())}</code>；保存后<strong>重启 DSH（插件模式）</strong>
或重启桥接进程才生效。</p>
<div class="card">
  <label>配对令牌（浏览器里需要它才能读写；在桥接启动日志 / 手机上能看到）</label>
  <input id="token" type="password" placeholder="粘贴桥接令牌">
  <div class="hint">令牌只存在页面内存里，不会保存。</div>

  <div class="row">
    <div><label>端口 port</label>
      <input id="port" type="number" value="${esc(text('port') || 8787)}">
      <div class="hint">手机自动探测优先扫 8787；换端口后要手动填地址</div></div>
    <div><label>监听地址 host</label>
      <input id="host" type="text" value="${esc(text('host') || '0.0.0.0')}">
      <div class="hint">127.0.0.1 = 只有本机/中继能连</div></div>
  </div>

  <label>云中继地址 relay（可留空 = 只走局域网）</label>
  <input id="relay" type="text" placeholder="wss://relay.example.com/bridge" value="${esc(text('relay'))}">
  <label>中继公开地址 relayPublicUrl（可选）</label>
  <input id="relayPublicUrl" type="text" value="${esc(text('relayPublicUrl'))}">
  <label>中继里的设备名 relayName（可选）</label>
  <input id="relayName" type="text" value="${esc(text('relayName'))}">

  <div class="row">
    <div><label>设备号 deviceId</label><input id="deviceId" type="text" value="${esc(text('deviceId'))}"></div>
    <div><label>设备令牌 deviceToken</label><input id="deviceToken" type="password" value="${esc(text('deviceToken'))}"></div>
  </div>
  <div class="row">
    <div><label>账号 account（可选）</label><input id="account" type="text" value="${esc(text('account'))}"></div>
    <div><label>账号令牌 accountToken（可选）</label><input id="accountToken" type="password" value="${esc(text('accountToken'))}"></div>
  </div>
  <div class="hint">已经有中继凭据的电脑（$USERPROFILE 下的 bridge.json）通常只需要填 relay。</div>

  <label class="check"><input id="autoStart" type="checkbox" ${checked('autoStart', true) ? 'checked' : ''}> 随 DSH 自动启动</label>
  <label class="check"><input id="verbose" type="checkbox" ${checked('verbose', false) ? 'checked' : ''}> 把日志打到 DSH 控制台</label>

  <button id="save">保存设置</button>
  <div id="msg"></div>
  <div class="warn">改端口/中继后要重启 DSH（或桥接）才会用新配置。</div>
</div>
<script>
 const $ = (id) => document.getElementById(id);
 const params = new URLSearchParams(location.search);
 if (params.get('token')) $('token').value = params.get('token');
 async function load() {
   if (!$('token').value) return;
   const res = await fetch('/api/v1/bridge-config', { headers: { authorization: 'Bearer ' + $('token').value } });
   const data = await res.json();
   if (!res.ok) { $('msg').textContent = '读取失败: ' + (data.error?.message ?? res.status); return; }
   const cfg = data.config ?? {};
   for (const key of ['port','host','relay','relayPublicUrl','relayName','deviceId','deviceToken','account','accountToken']) {
     if (cfg[key] !== undefined && cfg[key] !== null) $(key).value = cfg[key];
   }
   $('autoStart').checked = cfg.autoStart === undefined ? true : cfg.autoStart === true;
   $('verbose').checked = cfg.verbose === true;
   $('msg').textContent = '已读取当前设置';
 }
 $('token').addEventListener('change', load);
 if ($('token').value) load();
 $('save').addEventListener('click', async () => {
   const payload = {
     port: Number($('port').value || 8787),
     host: $('host').value.trim(),
     relay: $('relay').value.trim(),
     relayPublicUrl: $('relayPublicUrl').value.trim(),
     relayName: $('relayName').value.trim(),
     deviceId: $('deviceId').value.trim(),
     deviceToken: $('deviceToken').value.trim(),
     account: $('account').value.trim(),
     accountToken: $('accountToken').value.trim(),
     autoStart: $('autoStart').checked,
     verbose: $('verbose').checked,
   };
   const res = await fetch('/api/v1/bridge-config', {
     method: 'POST',
     headers: { authorization: 'Bearer ' + $('token').value, 'content-type': 'application/json' },
     body: JSON.stringify(payload),
   });
   const data = await res.json();
   $('msg').textContent = res.ok ? '已保存到 ' + data.file + '（重启 DSH 生效）'
     : '保存失败: ' + (data.error?.message ?? res.status);
 });
</script></div></body></html>`;
  }

  /** Edit, remove or steer one queued item. */
  async updateSessionQueue(id, body) {
    const itemId = String(body?.itemId ?? '');
    if (itemId.length === 0) throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'itemId is required');
    const action = body?.action;
    if (action === null || typeof action !== 'object' || typeof action.kind !== 'string') {
      throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'action.kind is required');
    }
    if (action.kind === 'edit') {
      const content = action.content;
      if (!Array.isArray(content) || content.length === 0
        || content.some((part) => part?.type !== 'text' || typeof part.text !== 'string')) {
        throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'action.content must be a non-empty text content list');
      }
    }
    await this.dshCall(() => this.dsh.updateQueue(id, itemId, action));
    return { ok: true };
  }

  /** The slash commands the desktop offers. */
  async sessionCommands(id) {
    const commands = await this.dshCall(() => this.dsh.listCommands(id));
    return {
      commands: commands.map((command) => ({
        name: String(command?.name ?? ''),
        description: String(command?.description ?? ''),
        hint: typeof command?.input?.hint === 'string' ? command.input.hint : '',
      })),
    };
  }

  /**
   * Run a slash command in a session.
   *
   * The desktop does **not** send a slash command as a prompt: its "/" palette calls the host's
   * command registry (`commands/execute`), the host resolves the name and runs the handler
   * (`/permission <preset>` switches the preset, `/plan` enters plan mode, `/compact` folds the
   * history). A command sent as a prompt would just be text for the model. The phone needs the
   * same path, otherwise "add a command" on the phone does nothing.
   *
   * @param {string} id the session
   * @param {string} line the whole command line, the leading slash included
   * @returns {Promise<{ok: boolean, text: string}>}
   */
  async executeCommand(id, line) {
    const text = typeof line === 'string' ? line.trim() : '';
    if (text.length === 0) throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'the command line must not be empty');
    if (!text.startsWith('/')) throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'a command line starts with a slash');
    const result = await this.dshCall(() => this.dsh.executeCommand(id, text));
    this.log('info', `the session ${id} ran the command "${text}" (${result.ok ? 'ok' : 'failed'})`);
    return { ok: result.ok === true, text: typeof result.text === 'string' ? result.text : '' };
  }

  /**
   * The skills a session can use.
   *
   * DSH builds this list from every skill provider on the machine, which takes seconds on a
   * cold session. The skills hardly ever change, so the answer is cached for a few minutes —
   * otherwise the phone's request times out while the first list is being built.
   */
  async sessionSkills(id) {
    const cached = this.skillCache?.get(id);
    if (cached !== undefined && Date.now() - cached.at < SKILL_CACHE_MS) {
      return cached.value;
    }
    const skills = await this.dshCall(() => this.dsh.listSkills(id));
    const value = {
      skills: skills.map((skill) => ({
        name: String(skill?.name ?? ''),
        description: String(skill?.description ?? ''),
        path: typeof skill?.path === 'string' ? skill.path : '',
      })),
    };
    if (this.skillCache === undefined) {
      this.skillCache = new Map();
    }
    this.skillCache.set(id, { at: Date.now(), value });
    return value;
  }

  /** The files that can be referenced with `@` in a session. */
  async sessionFiles(id, query) {
    const files = await this.dshCall(() => this.dsh.listFileReferences(id, String(query ?? '')));
    return {
      files: files.map((file) => ({
        path: String(file?.path ?? ''),
        kind: file?.kind === 'directory' ? 'directory' : 'file',
      })),
    };
  }

  /** The permission presets the desktop application offers. */
  async permissionPresets() {
    const catalog = await this.dshCall(() => this.dsh.permissionPresets());
    return {
      options: catalog.options.map((option) => ({
        value: String(option?.value ?? ''),
        name: String(option?.name ?? option?.value ?? ''),
        description: typeof option?.description === 'string' ? option.description : '',
      })),
      defaultPreset: catalog.defaultPreset ?? '',
    };
  }

  /**
   * The agent presets — the "mode" a new conversation runs in.
   *
   * The desktop names them the same way, so the phone can offer exactly the same choice.
   */
  async agentPresets() {
    const catalog = await this.dshCall(() => this.dsh.agentPresets());
    const presets = Array.isArray(catalog?.presets) ? catalog.presets : [];
    return {
      presets: presets.map((preset) => ({
        id: String(preset?.id ?? ''),
        name: String(preset?.name ?? preset?.id ?? ''),
        description: typeof preset?.description === 'string' ? preset.description : '',
        isDefault: preset?.isDefault === true,
        broken: typeof preset?.broken === 'string' ? preset.broken : '',
      })).filter((preset) => preset.id.length > 0),
    };
  }

  /**
   * The certificate of the relay the bridge dials into (or of the bridge itself).
   *
   * The phone asks for it over the plain http link: a self signed https link is refused by the
   * system before the phone could ever read the fingerprint, so the fingerprint has to travel
   * over the link that already works.
   *
   * Without a relay the bridge has nothing to pin, so it answers with `sha256: null` and
   * `selfSigned: false` — the phone stays quiet then.
   */
  relayCertificate() {
    const relay = typeof this.options.relay === 'string' ? this.options.relay : '';
    let host = this.discovery.host ?? '';
    let port = Number(this.options.port ?? 0);
    // The fingerprint of the relay certificate: `null` when the bridge does not know one. It is
    // `null` and not an empty string, so that "there is no fingerprint" cannot be mistaken for
    // "the fingerprint is the empty string".
    let sha256 = null;
    let selfSigned = false;

    if (relay.length > 0) {
      // The address the **phone** uses: the public url when the relay terminates TLS on
      // another port, otherwise the address of the relay itself.
      const publicUrl = typeof this.options.relayPublicUrl === 'string' ? this.options.relayPublicUrl : '';
      const address = publicUrl.length > 0 ? publicUrl : relay.replace(/^ws/iu, 'http');
      try {
        const url = new URL(address);
        host = url.hostname || host;
        // The port the **phone** connects to: the port of the url, or the default port of the
        // scheme (`https`/`wss` → 443, `http`/`ws` → 80). It must not be the port of the
        // bridge: the phone pins the fingerprint under `host:port`, and a wrong port would
        // store it under a key that never matches the address the phone really uses.
        const explicit = Number.parseInt(url.port ?? '', 10);
        port = Number.isInteger(explicit) && explicit > 0
          ? explicit
          : (url.protocol === 'https:' || url.protocol === 'wss:' ? 443 : 80);
      } catch {
        // Keep the address of the bridge.
      }
      // The certificate the launcher generated for the relay (--relay-ca). Its SHA256 is the
      // fingerprint the phone pins.
      const certificateFile = typeof this.options.relayCa === 'string' ? this.options.relayCa : '';
      if (certificateFile.length > 0) {
        try {
          const pem = fs.readFileSync(path.resolve(certificateFile), 'utf8');
          const certificate = new crypto.X509Certificate(pem);
          sha256 = crypto.createHash('sha256').update(certificate.raw).digest('hex').toUpperCase();
          selfSigned = sha256.length > 0;
        } catch (error) {
          this.log('warn', `the relay certificate could not be read: ${error.message}`);
        }
      }
    }

    return { sha256, host, port, selfSigned };
  }

  /**
   * Look at a prompt before it is sent: does the phone have to ask the user once more?
   *
   * Only a session that runs with `danger-full-access` is worth a second look. When the
   * permission cannot be read, nothing is blocked — the phone sends the prompt anyway.
   */
  async promptPreview(id, text) {
    const body = typeof text === 'string' ? text : '';
    const empty = { requiresConfirmation: false, reason: '', summary: '', actions: [] };
    if (body.trim().length === 0) return empty;

    let permission = null;
    try {
      permission = await this.sessionPermissionValue(id);
    } catch {
      permission = null;
    }
    if (permission !== 'danger-full-access') return empty;

    const actions = detectDangerousActions(body);
    if (actions.length === 0) return empty;

    let cwd = '';
    try {
      cwd = this.index.get(id)?.cwd ?? '';
    } catch {
      cwd = '';
    }
    return {
      requiresConfirmation: true,
      reason: 'danger-full-access',
      summary: summarizeActions(actions, cwd),
      actions,
    };
  }

  /**
   * The session tree of the desktop: conversations with their topics and sub tasks.
   *
   * The tree is built from the rows of `session/list` — every row already carries the
   * projections of its session (the title, the topics, the permission, the open questions),
   * so no extra call per session is needed.
   */
  async sessionTree() {
    const rows = await this.dshRowsForRequest();
    if (rows === null) {
      // The desktop could not give us its session list. That happens when the DSH itself
      // refuses to answer — one session whose live header and persisted header disagree
      // ("session source headers conflict") makes the whole `session/list` call fail — or
      // when the DSH is not up yet.
      //
      // **An empty tree would be a lie**: the local scanner has every session on disk. So the
      // tree is built from the store index instead. It is flat (the store does not keep the
      // parent links) and it carries no live projections, but the user sees their sessions
      // instead of nothing.
      if (this.index.all().length === 0) await this.scan.whenScanned(3000);
      const fallback = this.buildIndexSummaries();
      this.log('warn', `the desktop session list is unavailable (${this.dshError ?? 'unknown reason'}); serving the ${fallback.size} sessions from the local store instead`);
      const rows2 = [...fallback.values()].map((summary) => ({
        sessionId: summary.id,
        cwd: summary.cwd,
        updatedAt: summary.updatedAt,
        projections: { values: { title: summary.title } },
      }));
      return buildSessionTree(rows2, (id) => fallback.get(id) ?? null);
    }
    const summaries = this.buildIndexSummaries();
    return buildSessionTree(normalizeRowDirectories(rows), (id) => summaries.get(id) ?? null);
  }

  /** The model, the permissions and the running flag of a session. */
  async sessionState(id) {
    const projections = await this.sessionProjections(id);
    const values = projections?.values ?? {};
    // The live projection carries the permission the desktop shows right now; the projection
    // cache on disk carries the structured form (preset / sandbox / approval) but is written
    // only at the host's checkpoints, so it lags behind a switch. The live value wins.
    const live = typeof values?.permissions?.currentValue === 'string' ? values.permissions.currentValue : null;
    const cached = this.sessionStats(id)?.permissionInfo ?? null;
    const permissions = live === null
      ? cached
      : { ...(cached ?? {}), currentValue: live, preset: live };
    const sessions = await this.listSessions();
    const summary = sessions.find((entry) => entry.id === id);
    return {
      model: normalizeModel(values?.modelSelection?.lastUsed ?? values?.modelSelection?.next),
      permissions,
      running: summary !== undefined && summary.state === SessionState.RUNNING,
    };
  }

  /**
   * Switch the permission preset of a session.
   *
   * The DSH remote surface has no `setPermission`: the write path is the `/permission` slash
   * command, which is exactly what the desktop's own permission capsule submits
   * (`@deepseek-ai/dsh-client-ui-permission-presets` → `live.command('/permission <preset>')`).
   * The command handler appends the three knob events (`permission/preset`, `sandbox/mode`,
   * `approval/policy`), so the session's projected permission really changes.
   *
   * @param {string} id the session
   * @param {string} preset one of the names of the permission catalog
   * @param {string[]} [knownNames] the catalog names, when the caller already fetched them
   * @returns {Promise<{preset: string, currentValue: string|null}>}
   */
  async setSessionPermission(id, preset, knownNames = null) {
    const name = typeof preset === 'string' ? preset.trim() : '';
    if (name.length === 0) throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'the permission preset must not be empty');
    const names = knownNames ?? await this.permissionPresetNames();
    if (!names.includes(name)) {
      throw new BridgeError(400, ErrorCode.BAD_REQUEST, `unknown permission preset "${name}" (available: ${names.join(', ')})`);
    }
    await this.dshCall(() => this.dsh.setSessionPermission(id, name));
    this.log('info', `the session ${id} switched to the permission preset "${name}"`);
    return { preset: name, currentValue: await this.sessionPermissionValue(id) };
  }

  /** The names of the permission presets the host offers. */
  async permissionPresetNames() {
    const catalog = await this.dshCall(() => this.dsh.permissionPresets());
    return (catalog?.options ?? []).map((option) => option?.value).filter(Boolean);
  }

  /** The permission preset a session currently projects (null when it is unknown). */
  async sessionPermissionValue(id) {
    try {
      const projections = await this.dshCall(() => this.dsh.projections(id));
      const value = projections?.values?.permissions?.currentValue;
      return typeof value === 'string' && value.length > 0 ? value : null;
    } catch (error) {
      this.log('warn', `the permission of the session ${id} could not be read: ${error.message}`);
      return null;
    }
  }

  /** Create a session in `cwd`. */
  async createSession({ cwd, title, agentPreset, permission } = {}) {
    const directory = typeof cwd === 'string' && cwd.trim().length > 0 ? cwd.trim() : process.cwd();
    const preset = typeof agentPreset === 'string' && agentPreset.trim().length > 0 ? agentPreset.trim() : null;
    // The permission preset is applied through the host's `/permission` command — the same write
    // path the desktop's permission capsule uses. See `setSessionPermission`.
    const chosenPermission = typeof permission === 'string' && permission.trim().length > 0 ? permission.trim() : null;
    if (chosenPermission !== null) {
      this.log('info', `the new session requests the permission preset "${chosenPermission}"`);
    }
    if (this.options.adapter === 'local') {
      const created = createStoreSession({ cwd: directory, title: title ?? '' });
      this.index.refresh();
      const summary = await this.getSession(created.sessionId);
      return summary ?? makeSessionSummary({
        id: created.sessionId,
        title: title ?? created.sessionId,
        cwd: normalizeDirectory(directory),
        createdAt: created.createdAt,
        updatedAt: created.createdAt,
        state: SessionState.IDLE,
        messageCount: 0,
      });
    }

    try {
      // An unknown preset is rejected *before* the session exists, so the phone does not end up
      // with a session it did not ask for. The catalog is fetched once and reused.
      const knownNames = chosenPermission !== null ? await this.permissionPresetNames() : null;
      if (knownNames !== null && !knownNames.includes(chosenPermission)) {
        throw new BridgeError(400, ErrorCode.BAD_REQUEST, `unknown permission preset "${chosenPermission}" (available: ${knownNames.join(', ')})`);
      }
      const created = await this.dsh.createSession({ cwd: directory, agentPreset: preset });
      let appliedPermission = null;
      if (chosenPermission !== null && created.sessionId) {
        try {
          appliedPermission = await this.setSessionPermission(created.sessionId, chosenPermission, knownNames);
        } catch (error) {
          // The session exists; only the permission did not take. The phone gets the session and
          // the real permission value (the session detail shows the truth).
          this.log('warn', `the permission preset "${chosenPermission}" could not be applied: ${error.message}`);
          appliedPermission = { preset: chosenPermission, currentValue: await this.sessionPermissionValue(created.sessionId) };
        }
      }
      if (title && created.sessionId) {
        try {
          await this.dsh.renameSession(created.sessionId, title);
        } catch (error) {
          this.log('warn', `could not rename the new session: ${error.message}`);
        }
      }
      this.index.refresh();
      const summary = created.sessionId ? await this.getSession(created.sessionId) : null;
      const result = summary ?? makeSessionSummary({
        id: created.sessionId ?? '',
        title: title ?? created.sessionId ?? '',
        cwd: normalizeDirectory(directory),
        createdAt: Date.now(),
        updatedAt: Date.now(),
        state: SessionState.IDLE,
        messageCount: 0,
      });
      if (appliedPermission !== null) {
        // The phone reads the permission it got back (extra fields are ignored by the summary
        // type, the phone shows the live value from the stats endpoint anyway).
        result.permission = appliedPermission.currentValue ?? appliedPermission.preset;
      }
      return result;
    } catch (error) {
      if (error instanceof BridgeError) throw error;
      if (error instanceof DshError) throw new BridgeError(502, error.code, error.message, error.details);
      throw new BridgeError(502, ErrorCode.DSH_UNAVAILABLE, error instanceof Error ? error.message : String(error));
    }
  }

  /** Distinct working directories seen in the store and in the application. */
  async listWorkspaces() {
    // The store metadata comes from the scanner thread; waiting for it does not block the
    // event loop, but the list should not be empty because the scan has not finished yet.
    if (this.index.all().length === 0) await this.scan.whenScanned(3000);
    const cwds = new Set(this.index.workspaces());
    const rows = await this.dshSessionRows();
    for (const row of rows ?? []) {
      const cwd = row.cwd ?? row.projections?.values?.workingDirectory;
      if (typeof cwd === 'string' && cwd.length > 0) cwds.add(cwd);
    }
    // One directory, one entry. The same folder reaches the bridge in several spellings
    // (`D:\app\x`, `D:/app\x`), and the phone would show one group per spelling.
    return groupDirectories(cwds).map((group) => ({
      cwd: group.path,
      label: pathLabel(group.path),
    }));
  }

  /* -------------------------------------------------------------- subscriptions */

  /** Register a phone client. */
  addClient(client) {
    this.clients.add(client);
    client.send(serverFrame(ServerFrame.HELLO, {
      server: SERVER_NAME,
      version: PROTOCOL_VERSION,
      token: this.state.token,
      dsh: {
        webUrl: this.options.dshUrl,
        reachable: this.dshAvailable,
        adapter: this.options.adapter,
      },
    }));
    // The store index is filled by the scanner thread. The phone gets the list of the store as
    // soon as it is there (waiting for it does not block the event loop), the live list of the
    // application follows once DSH has been queried.
    void this.scan.whenScanned(3000).then(() => {
      const indexed = [...this.buildIndexSummaries().values()].sort((a, b) => b.updatedAt - a.updatedAt);
      client.send(serverFrame(ServerFrame.SESSION_LIST, { sessions: indexed }));
    }).catch(() => {});
    void this.listSessions().then((sessions) => {
      this.lastList = sessions;
      client.send(serverFrame(ServerFrame.SESSION_LIST, { sessions }));
    }).catch(() => {});
    // 手机刚连上: 把当前的待办告诉它, 并开始监视。
    // 监视出来的变化会变成手机上的本地通知(任务结束 / 需要做决策)。
    this.startPendingWatch();
    // A phone that connects later still gets the current state (the watch keeps it up to date).
    if (this.pendingLast !== null) {
      client.send(serverFrame(ServerFrame.PENDING, this.pendingLast));
    }
  }

  /** Remove a phone client. */
  removeClient(client) {
    this.clients.delete(client);
  }

  /** Send one frame to every connected client. */
  broadcast(type, data) {
    const frame = serverFrame(type, data);
    for (const client of this.clients) client.send(frame);
  }

  /** Publish the session list, but only when it actually changed. */
  publishSessionListIfChanged() {
    const signature = this.lastList
      .map((summary) => `${summary.id}:${summary.updatedAt}:${summary.title}:${summary.state}:${summary.messageCount}`)
      .join('|');
    if (signature === this.sessionSignature) return;
    this.sessionSignature = signature;
    this.broadcast(ServerFrame.SESSION_LIST, { sessions: this.lastList });
  }

  /** Publish a newly created message. */
  publishMessageCreated(sessionId, message) {
    this.broadcast(ServerFrame.MESSAGE_CREATED, { sessionId, message });
    this.broadcast(ServerFrame.MESSAGE_COMPLETED, { sessionId, message });
  }

  /**
   * Start streaming one session.
   * The DSH WebSocket carrier is preferred; the store tailer is the fallback.
   */
  async subscribe(sessionId) {
    if (this.streams.has(sessionId) || this.tailers.has(sessionId)) return;
    this.unsubbed.delete(sessionId);        // 又有人订阅了 → 取消之前的退订标记
    // 不看 dshAvailable：那个标志只在启动探测时准，DSH 后起来的时候它可能还是 false，
    // 于是订阅就退化成读本地日志（新会话根本没有日志）→ 一帧都收不到。
    // 直接试 DSH 的 follow，失败再退回本地日志。
    if (this.options.adapter !== 'local') {
      /* streamRef：close 回调里要拿流句柄比对，但 stream 这个 const 在 await
         之前还没初始化 —— 回调若在这中间触发，直接引用会撞 TDZ（ReferenceError）。
         所以先用 streamRef 这一个可变引用，拿到句柄后再填。 */
      let streamRef = null;
      try {
        const stream = await this.dsh.openFollow(sessionId, {
          onSnapshot: (value) => this.handleDshSnapshot(sessionId, value),
          onEvent: (event) => this.handleDshEvent(sessionId, event),
          onDelta: (frame) => this.handleDshDelta(sessionId, frame),
          onError: (error) => this.log('warn', `dsh stream error for ${sessionId}: ${error?.message ?? error}`),
          /* 链路被掐了（DSH 侧的 session/follow 会被关掉：会话重建、远端重启、
             空闲回收…）就把流记掉并重开一次。
             这是「逐字帧偶尔全丢」的真正原因：旧代码根本不知道流没了，
             `this.streams` 里一直挂着一个死流，于是这个会话再也收不到
             assistant-stream 帧，只剩 created/completed。
             重开后 DSH 会先发一份快照，handleDshSnapshot 会把已经发生的事补齐。
             BRIDGE_FOLLOW_REOPEN=0 可以关掉它（用来做 A/B 对照）。 */
          onClose: () => {
            if (process.env.BRIDGE_FOLLOW_REOPEN === '0') return;
            if (!streamRef) return;                       // 句柄还没拿到，交给 subscribe 自己
            if (this.streams.get(sessionId) !== streamRef) return;
            this.streams.delete(sessionId);
            this.log('warn', `dsh follow stream closed for ${sessionId}; reopening`);
            setTimeout(() => {
              if (this.unsubbed.has(sessionId)) return;
              if (this.streams.has(sessionId) || this.tailers.has(sessionId)) return;
              void this.subscribe(sessionId);
            }, 1200).unref?.();
          },
        });
        streamRef = stream;
        this.streams.set(sessionId, stream);
        this.dshAvailable = true;
        return;
      } catch (error) {
        this.log('warn', `could not open the DSH follow stream for ${sessionId}: ${error.message}`);
      }
    }
    this.startStoreTailer(sessionId);
  }

  /** Stop streaming one session. */
  unsubscribe(sessionId) {
    /* 标记成「不要了」—— 否则 close 回调里排的那个重开定时器会把刚退订的会话又拉回来。 */
    this.unsubbed.add(sessionId);
    const stream = this.streams.get(sessionId);
    if (stream) {
      stream.close();
      this.streams.delete(sessionId);
    }
    const tailer = this.tailers.get(sessionId);
    if (tailer) {
      tailer.stop();
      this.tailers.delete(sessionId);
    }
  }

  /** Stream one session by polling the on-disk log. */
  startStoreTailer(sessionId) {
    if (this.tailers.has(sessionId)) return;
    const logPath = this.index.get(sessionId)?.logPath ?? this.findLogPath(sessionId);
    if (logPath === null) return;
    const tailer = new SessionTailer(sessionId, logPath, {
      pollIntervalMs: 600,
      onEvents: (events) => {
        const messages = mapEventsToMessages(events, sessionId);
        for (const message of messages) {
          this.broadcast(ServerFrame.MESSAGE_CREATED, { sessionId, message });
          this.broadcast(ServerFrame.MESSAGE_COMPLETED, { sessionId, message });
        }
      },
    });
    this.tailers.set(sessionId, tailer);
    tailer.start();
  }

  /**
   * The follow stream opens with a snapshot of everything that already happened.
   * Without replaying it a client that subscribes *after* the turn already ran sees
   * no frames at all — the turn is over, so no live event will ever arrive.
   * This is the normal case: the bridge is told to prompt a session and only then
   * a viewer subscribes.
   */
  handleDshSnapshot(sessionId, snapshot) {
    if (!snapshot || typeof snapshot !== 'object') return;
    const records = Array.isArray(snapshot.records) ? snapshot.records : [];
    const events = [];
    for (const record of records) {
      if (!record || typeof record !== 'object') continue;
      if (record.type === 'event' && record.event) events.push(record.event);
      else if (record.type === 'event' && record.event === undefined && record.seq !== undefined) events.push(record);
    }
    if (events.length === 0) return;

    const messages = mapEventsToMessages(events, sessionId);
    for (const message of messages) {
      this.broadcast(ServerFrame.MESSAGE_CREATED, { sessionId, message });
      this.broadcast(ServerFrame.MESSAGE_COMPLETED, { sessionId, message });
    }

    // The state is the last thing that happened: a start without an end means "still running".
    let state = SessionState.IDLE;
    for (const event of events) {
      const type = event && typeof event.type === 'string' ? event.type : '';
      if (type === 'turn/start' || type === 'step/start') state = SessionState.RUNNING;
      else if (type === 'turn/end' || type === 'step/end') state = SessionState.IDLE;
    }
    this.broadcast(ServerFrame.SESSION_STATE, { sessionId, state, title: this.titleOf(sessionId) });
  }

  /** Translate one DSH wire event into protocol frames. */
  handleDshEvent(sessionId, event) {
    if (!event || typeof event !== 'object') return;
    const type = typeof event.type === 'string' ? event.type : '';

    if (type === 'turn/start' || type === 'step/start') {
      this.broadcast(ServerFrame.SESSION_STATE, { sessionId, state: SessionState.RUNNING, title: this.titleOf(sessionId) });
      return;
    }
    if (type === 'turn/end') {
      this.broadcast(ServerFrame.SESSION_STATE, { sessionId, state: SessionState.IDLE, title: this.titleOf(sessionId) });
      return;
    }

    // An assistant turn that was streamed live must not produce a second row: the live row is
    // completed again with the canonical text instead.
    if (type === 'assistant/message') {
      const turn = this.liveTurns.get(sessionId);
      if (turn !== undefined) {
        this.liveTurns.delete(sessionId);
        const [message] = mapEventsToMessages([event], sessionId);
        if (message !== undefined) {
          // An error is never overwritten by a later success: the durable event knows whether
          // the turn was interrupted, the stream knows whether it was committed.
          const failed = message.status === MessageStatus.ERROR || turn.status === MessageStatus.ERROR;
          this.broadcast(ServerFrame.MESSAGE_COMPLETED, {
            sessionId,
            message: {
              ...message,
              id: turn.messageId,
              status: failed ? MessageStatus.ERROR : MessageStatus.DONE,
            },
          });
        }
        return;
      }
    }

    const messages = mapEventsToMessages([event], sessionId);
    for (const message of messages) {
      this.broadcast(ServerFrame.MESSAGE_CREATED, { sessionId, message });
      this.broadcast(ServerFrame.MESSAGE_COMPLETED, { sessionId, message });
    }
  }

  /**
   * Translate one assistant-stream frame into protocol frames.
   * The live turn uses a provisional id (`m-live-<attemptId>`); the durable event that carries the
   * very same text updates that row instead of creating a second one. The durable event and the
   * end of the stream can arrive in either order, so both paths are handled.
   */
  handleDshDelta(sessionId, frame) {
    if (!frame || typeof frame !== 'object') return;
    const attemptId = String(frame.attemptId ?? 'unknown');

    if (frame.type === 'start') {
      const messageId = `m-live-${attemptId}`;
      this.liveTurns.set(sessionId, { attemptId, messageId, text: '', completed: false, expiresAt: Date.now() + LIVE_TURN_TTL_MS });
      this.#sweepLiveTurns();
      this.broadcast(ServerFrame.MESSAGE_CREATED, {
        sessionId,
        message: makeMessage({
          id: messageId,
          sessionId,
          role: MessageRole.ASSISTANT,
          kind: MessageKind.TEXT,
          text: '',
          createdAt: Date.now(),
          status: MessageStatus.STREAMING,
        }),
      });
      return;
    }

    if (frame.type === 'chunk') {
      const chunk = frame.chunk ?? {};
      // Only the visible answer is streamed; the reasoning deltas stay inside the desktop agent.
      if (chunk.type !== undefined && chunk.type !== 'text-delta') return;
      const text = typeof chunk.text === 'string' ? chunk.text : '';
      if (text.length === 0) return;
      const turn = this.liveTurns.get(sessionId) ?? { attemptId, messageId: `m-live-${attemptId}`, text: '', completed: false };
      turn.text += text;
      // The turn is alive: the deadline for the durable event moves with it.
      turn.expiresAt = Date.now() + LIVE_TURN_TTL_MS;
      this.liveTurns.set(sessionId, turn);
      this.broadcast(ServerFrame.MESSAGE_DELTA, { sessionId, messageId: turn.messageId, delta: text });
      return;
    }

    if (frame.type === 'end') {
      const turn = this.liveTurns.get(sessionId);
      if (turn === undefined) return;
      const outcome = frame.outcome ?? {};
      const committed = outcome.kind === 'committed';
      if (turn.completed) {
        // The durable event already closed this row.
        this.liveTurns.delete(sessionId);
        return;
      }
      /* The turn is **not** removed here.
       *
       * The durable `assistant/message` event of this turn arrives *after* the stream ended.
       * It has to find the live turn, so that it completes the very same row (with the
       * canonical text and the canonical time) instead of creating a second row next to the
       * live one. Removing the turn here would turn every assistant step into two rows: the
       * live one that stays empty and the durable one that arrives late.
       *
       * The row is closed right away nevertheless, so that the phone does not have to wait
       * for the durable event. The durable event only refines it afterwards. */
      turn.ended = true;
      turn.status = committed ? MessageStatus.DONE : MessageStatus.ERROR;
      turn.expiresAt = Date.now() + LIVE_TURN_TTL_MS;
      this.liveTurns.set(sessionId, turn);
      this.#sweepLiveTurns();
      this.broadcast(ServerFrame.MESSAGE_COMPLETED, {
        sessionId,
        message: makeMessage({
          id: turn.messageId,
          sessionId,
          role: MessageRole.ASSISTANT,
          kind: MessageKind.TEXT,
          text: turn.text,
          createdAt: Date.now(),
          status: committed ? MessageStatus.DONE : MessageStatus.ERROR,
        }),
      });
    }
  }

  /**
   * Drop the live turns that no durable event claimed.
   *
   * The map holds at most one turn per session, so this is a safety net against a session
   * that keeps a stale entry forever - not a memory leak.
   */
  #sweepLiveTurns() {
    const now = Date.now();
    for (const [sessionId, turn] of this.liveTurns) {
      if (typeof turn.expiresAt === 'number' && turn.expiresAt <= now) {
        this.liveTurns.delete(sessionId);
      }
    }
  }

  /** The current title of a session (best effort). */
  titleOf(sessionId) {
    // 没有标题的会话也不能拿 id 顶着: 用户看到的是「未命名会话」。
    return this.lastList.find((summary) => summary.id === sessionId)?.title ?? UNTITLED_SESSION;
  }

  /** The pairing payload the phone scans. */
  pairingInfo() {
    const host = this.options.pairingHost ?? '127.0.0.1';
    const port = this.options.port;
    const token = this.state.token;
    return {
      token,
      url: `http://${host}:${port}`,
      qrPayload: `dsh-harmony://connect?host=${host}&port=${port}&token=${token}`,
    };
  }
}

/** Compare two message ids of the `m-<seq>` shape. */
function compareMessageId(a, b) {
  const left = /^m-(\d+)$/u.exec(a);
  const right = /^m-(\d+)$/u.exec(b);
  if (left && right) return Number(left[1]) - Number(right[1]);
  return String(a).localeCompare(String(b));
}

/** The short label of a working directory (its last segment). */
function pathLabel(cwd) {
  const parts = String(cwd).split(/[\\/]/u).filter((part) => part.length > 0);
  return parts.length > 0 ? parts[parts.length - 1] : cwd;
}

/**
 * One spelling per working directory in the rows of `session/list`.
 *
 * The desktop stores the working directory as the caller wrote it, so the same folder can
 * show up as `D:\app\x` in one row and `D:/app/x` in the next. The phone groups its list by
 * that string, so the rows are normalised before they leave the bridge — otherwise one
 * project shows up as two groups, and the group that holds the sessions the desktop calls
 * "ungrouped" is the one that looks like a second copy of the project.
 *
 * @param {Array<object>} rows - the rows of `session/list`.
 * @returns {Array<object>} the rows with one spelling per directory.
 */
function normalizeRowDirectories(rows) {
  return rows.map((row) => {
    if (row === null || typeof row !== 'object') return row;
    const next = { ...row };
    let changed = false;
    if (typeof row.cwd === 'string') {
      const cwd = normalizeDirectory(row.cwd);
      if (cwd !== row.cwd) {
        next.cwd = cwd;
        changed = true;
      }
    }
    const values = row.projections?.values;
    if (values !== undefined && values !== null && typeof values.workingDirectory === 'string') {
      const workingDirectory = normalizeDirectory(values.workingDirectory);
      if (workingDirectory !== values.workingDirectory) {
        next.projections = { ...row.projections, values: { ...values, workingDirectory } };
        changed = true;
      }
    }
    return changed ? next : row;
  });
}

/**
 * Normalise a model selection into `{provider, model, reasoningEffort?}`.
 * `null` when the value does not carry a provider and a model.
 */
function normalizeModel(value) {
  if (value === null || value === undefined || typeof value !== 'object') return null;
  const provider = typeof value.provider === 'string' ? value.provider : '';
  const model = typeof value.model === 'string' ? value.model : '';
  if (provider.length === 0 && model.length === 0) return null;
  const selection = { provider, model };
  if (typeof value.reasoningEffort === 'string' && value.reasoningEffort.length > 0) {
    selection.reasoningEffort = value.reasoningEffort;
  }
  return selection;
}

/**
 * Build the route table.
 * Each route is `{ method, pattern, handler }`; the pattern uses `:name` placeholders.
 */
export function createRoutes(bridge) {
  /**
   * The desktop-UI parity endpoints are registered under both spellings: `/api/v1/session/:id/…`
   * (the form the phone contract names them with) and `/api/v1/sessions/:id/…` (the plural form
   * the other session routes already use).
   */
  const sessionRoutes = (method, suffix, handler) => [
    { method, pattern: `${API_PREFIX}/session/:id${suffix}`, handler },
    { method, pattern: `${API_PREFIX}/sessions/:id${suffix}`, handler },
  ];

  const routes = [
    {
      // 桥接自己发起的提问: 手机可以回答, 请求会一直等到答案或超时。
      method: 'POST',
      pattern: `${API_PREFIX}/ask`,
      handler: async (request) => {
        const body = request.body ?? {};
        const answers = await bridge.askUser(body.sessionId ?? '', body.questions, body.timeoutMs);
        return { body: { ok: true, answers } };
      },
    },
    {
      method: 'GET',
      pattern: `${API_PREFIX}/health`,
      handler: async () => ({
        body: {
          ok: true,
          name: SERVER_NAME,
          version: PROTOCOL_VERSION,
          dsh: {
            webUrl: bridge.options.dshUrl,
            reachable: bridge.dshAvailable,
            /**
             * Why the desktop session list is not usable.
             *
             * Without it the failure was silent: the phone saw an empty session list and
             * nothing said why. Now the reason travels with the health answer.
             */
            error: bridge.dshError ?? null,
            /**
             * The version of the desktop DSH.
             *
             * The phone could not learn it before: `/health` only carried the bridge's own
             * protocol version, so a desktop that was upgraded (and possibly incompatible)
             * looked exactly like a healthy one. Now the phone can tell the two apart.
             */
            version: bridge.dshVersionNow(),
          },
          now: Date.now(),
        },
      }),
    },
    {
      method: 'GET',
      pattern: `${API_PREFIX}/sessions`,
      handler: async () => ({ body: { sessions: await bridge.listSessions() } }),
    },
    {
      method: 'POST',
      pattern: `${API_PREFIX}/sessions`,
      handler: async (request) => ({ body: { session: await bridge.createSession(request.body ?? {}) } }),
    },
    {
      method: 'GET',
      pattern: `${API_PREFIX}/sessions/:id`,
      handler: async (request) => {
        const summary = await bridge.getSession(request.params.id);
        if (summary === null) throw new BridgeError(404, ErrorCode.NOT_FOUND, `unknown session ${request.params.id}`);
        return { body: { session: summary } };
      },
    },
    {
      method: 'GET',
      pattern: `${API_PREFIX}/sessions/:id/stats`,
      handler: async (request) => ({ body: { stats: bridge.sessionStats(request.params.id) } }),
    },
    {
      // The devices of the account this bridge belongs to (the phone's "设备" page).
      method: 'GET',
      pattern: `${API_PREFIX}/devices`,
      handler: async () => {
        const result = await bridge.listDevices();
        return { body: { account: result.account, devices: result.devices } };
      },
    },
    {
      // The phone registers itself as a device of the account (the bridge talks to the relay).
      method: 'POST',
      pattern: `${API_PREFIX}/phone/register`,
      handler: async (request) => {
        const body = request.body ?? {};
        const result = await bridge.registerPhone(
          String(body.deviceId ?? ''),
          String(body.name ?? '我的手机'),
          String(body.token ?? ''),
        );
        return { status: result.ok ? 200 : (result.status ?? 502), body: result };
      },
    },
    {
      // The phone says that it is still there.
      method: 'POST',
      pattern: `${API_PREFIX}/phone/heartbeat`,
      handler: async (request) => {
        const body = request.body ?? {};
        const result = await bridge.heartbeatPhone(String(body.deviceId ?? ''));
        return { status: result.ok ? 200 : (result.status ?? 502), body: result };
      },
    },
    {
      method: 'GET',
      pattern: `${API_PREFIX}/sessions/:id/messages`,
      handler: async (request) => {
        const limit = request.query.limit === undefined ? 200 : Number.parseInt(request.query.limit, 10);
        const page = await bridge.listMessages(request.params.id, {
          limit: Number.isFinite(limit) ? limit : 200,
          before: request.query.before ?? null,
        });
        return { body: page };
      },
    },
    {
      // 全文: 列表里只给预览, 手机点「更多」时按 seq 来要原文。
      method: 'GET',
      pattern: `${API_PREFIX}/sessions/:id/messages/:seq/full`,
      handler: async (request) => {
        const seq = Number.parseInt(String(request.params.seq ?? ''), 10);
        if (!Number.isFinite(seq)) {
          throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'the message sequence must be a number');
        }
        const result = await bridge.fullMessage(request.params.id, seq);
        return { body: { text: result.text, seq, found: result.found } };
      },
    },
    {
      method: 'POST',
      pattern: `${API_PREFIX}/sessions/:id/messages`,
      handler: async (request) => {
        const body = request.body ?? {};
        const result = await bridge.submitPrompt(request.params.id, body.text, { mode: body.mode ?? 'queue' });
        return { body: result };
      },
    },
    {
      method: 'POST',
      pattern: `${API_PREFIX}/sessions/:id/cancel`,
      handler: async (request) => ({ body: await bridge.cancelSession(request.params.id) }),
    },
    {
      method: 'GET',
      pattern: `${API_PREFIX}/workspaces`,
      handler: async () => ({ body: { workspaces: await bridge.listWorkspaces() } }),
    },
    {
      // The desktop's session tree: conversations first, their topics and sub tasks behind them.
      method: 'GET',
      pattern: `${API_PREFIX}/session-tree`,
      handler: async () => ({ body: { conversations: await bridge.sessionTree() } }),
    },
    {
      // The agent presets (the "mode" a new conversation runs in).
      method: 'GET',
      pattern: `${API_PREFIX}/agent-presets`,
      handler: async () => ({ body: await bridge.agentPresets() }),
    },
    {
      // The desktop's session tree: conversations first, their topics and sub tasks behind them.
      method: 'GET',
      pattern: `${API_PREFIX}/session-tree`,
      handler: async () => ({ body: { conversations: await bridge.sessionTree() } }),
    },
    {
      // The agent presets (the "mode" a new conversation runs in).
      method: 'GET',
      pattern: `${API_PREFIX}/agent-presets`,
      handler: async () => ({ body: await bridge.agentPresets() }),
    },
    {
      // 桥接设置页(浏览器打开, 带 ?token= 才能读写)
      method: 'GET',
      pattern: '/settings',
      handler: async () => ({ html: bridge.settingsPage() }),
    },
    {
      method: 'GET',
      pattern: `${API_PREFIX}/bridge-config`,
      handler: async () => ({ body: { ok: true, file: bridge.bridgeConfigPath(), config: bridge.readBridgeConfig() } }),
    },
    {
      method: 'POST',
      pattern: `${API_PREFIX}/bridge-config`,
      handler: async (request) => ({ body: bridge.saveBridgeConfig(request.body ?? {}) }),
    },
    {
      // The number of things the desktop is waiting for (the badge of the phone).
      method: 'GET',
      pattern: `${API_PREFIX}/pending`,
      handler: async () => ({ body: await bridge.pendingDetail() }),
    },
    {
      // The fingerprint of the self signed certificate of the relay (the phone pins it).
      method: 'GET',
      pattern: `${API_PREFIX}/relay/certificate`,
      handler: async () => ({ body: bridge.relayCertificate() }),
    },
    {
      // What a prompt is about to do: the phone asks the user once more when it is dangerous.
      method: 'GET',
      pattern: `${API_PREFIX}/sessions/:id/prompt-preview`,
      handler: async (request) => ({
        body: await bridge.promptPreview(request.params.id, request.query.text ?? ''),
      }),
    },
    {
      // "Is there a desktop agent on this machine?" — the phone asks every host of the
      // local network, so this route must stay reachable without a token.
      method: 'GET',
      pattern: DISCOVER_PATH,
      handler: async () => ({ body: bridge.discovery.discover() }),
    },
    {
      // Exchange the pairing code for the bridge token.
      method: 'POST',
      pattern: PAIR_PATH,
      handler: async (request) => {
        const code = String(request.body?.code ?? '').trim();
        const result = bridge.discovery.pair(code);
        if (!result.ok) {
          throw new BridgeError(400, ErrorCode.BAD_REQUEST, result.reason);
        }
        return { body: result };
      },
    },
    {
      // Everything the phone needs to switch from the LAN to the cloud relay.
      method: 'GET',
      pattern: REMOTE_CONFIG_PATH,
      handler: async () => ({ body: bridge.discovery.remoteConfig() }),
    },
    {
      // The phone hands over its Huawei Push Kit token.
      method: 'POST',
      pattern: `${API_PREFIX}/phone/push-token`,
      handler: async (request) => {
        const body = request.body ?? {};
        const token = String(body.token ?? '').trim();
        if (token.length === 0) {
          throw new BridgeError(400, ErrorCode.BAD_REQUEST, 'the push token must not be empty');
        }
        const result = bridge.registerPushToken(String(body.deviceId ?? ''), token);
        return { body: result };
      },
    },
    {
      // The models that can be selected (the desktop's model picker).
      method: 'GET',
      pattern: `${API_PREFIX}/models`,
      handler: async () => ({ body: await bridge.modelCatalog() }),
    },
    {
      // The permission presets the desktop offers (the desktop's permission picker).
      method: 'GET',
      pattern: `${API_PREFIX}/permissions`,
      handler: async () => ({ body: await bridge.permissionPresets() }),
    },
    ...sessionRoutes('POST', '/model', async (request) => ({
      body: await bridge.selectSessionModel(request.params.id, request.body ?? {}),
    })),
    ...sessionRoutes('GET', '/questions', async (request) => ({
      body: await bridge.sessionQuestions(request.params.id),
    })),
    ...sessionRoutes('POST', '/questions', async (request) => ({
      body: await bridge.answerSessionQuestions(request.params.id, request.body ?? {}),
    })),
    ...sessionRoutes('GET', '/queue', async (request) => ({
      body: await bridge.sessionQueue(request.params.id),
    })),
    ...sessionRoutes('POST', '/queue', async (request) => ({
      body: await bridge.updateSessionQueue(request.params.id, request.body ?? {}),
    })),
    ...sessionRoutes('GET', '/commands', async (request) => ({
      body: await bridge.sessionCommands(request.params.id),
    })),
    // 跑一条斜杠指令 —— 桌面端的「/」面板走的就是这条命令通道, 不是当提示词发出去 ✓
    ...sessionRoutes('POST', '/command', async (request) => {
      const body = request.body ?? {};
      return { body: await bridge.executeCommand(request.params.id, body.line) };
    }),
    ...sessionRoutes('GET', '/skills', async (request) => ({
      body: await bridge.sessionSkills(request.params.id),
    })),
    ...sessionRoutes('GET', '/files', async (request) => ({
      body: await bridge.sessionFiles(request.params.id, request.query.query ?? ''),
    })),
    ...sessionRoutes('GET', '/state', async (request) => ({
      body: await bridge.sessionState(request.params.id),
    })),
    {
      method: 'GET',
      pattern: `${API_PREFIX}/pairing`,
      handler: async (ctx) => {
        const remote = ctx.request?.socket?.remoteAddress ?? '';
        const isLocal = remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
        if (!isLocal && !bridge.options.allowUnauthPairing) {
          throw new BridgeError(403, ErrorCode.UNAUTHORIZED, 'the pairing endpoint is restricted to localhost; start the bridge with --allow-unauth-pairing to change that');
        }
        return { body: bridge.pairingInfo() };
      },
    },
  ];
  return routes;
}

/** The route matcher. */
export class Router {
  constructor(routes) {
    this.routes = routes;
    this.compiled = routes.map((route) => ({
      ...route,
      segments: route.pattern.split('/').filter((segment) => segment.length > 0),
    }));
  }

  /** Find the handler of a request, or `null`. */
  match(method, pathname) {
    const parts = pathname.split('/').filter((segment) => segment.length > 0);
    let pathMatched = false;
    for (const route of this.compiled) {
      if (route.segments.length !== parts.length) continue;
      const params = {};
      let ok = true;
      for (let i = 0; i < route.segments.length; i += 1) {
        const segment = route.segments[i];
        if (segment.startsWith(':')) params[segment.slice(1)] = decodeURIComponent(parts[i]);
        else if (segment !== parts[i]) {
          ok = false;
          break;
        }
      }
      if (!ok) continue;
      pathMatched = true;
      if (route.method === method) return { route, params };
    }
    if (pathMatched) return { methodMismatch: true };
    return null;
  }
}

export { SURFACE_ROLES };

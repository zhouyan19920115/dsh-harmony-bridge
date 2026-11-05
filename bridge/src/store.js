// Reader for the DSH on-disk session store: zstd-compressed JSON Lines logs plus the
// session projection-cache metadata.
//
// Two facts drive the implementation:
//   1. Node's `zlib.zstdDecompressSync` only decodes the FIRST zstd frame, while DSH writes one
//      frame per JSONL row. `decodeZstdFrames` therefore walks the zstd frame structure itself and
//      inflates every frame separately.
//   2. The log keeps growing while the agent works, so the reader is tail-friendly: it reports the
//      file size/mtime it last saw and can hand back only the rows that appeared since then.

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';

import { dshHome } from './config.js';
import { MessageKind, MessageRole, MessageStatus, makeMessage, truncate } from './protocol.js';

const ZSTD_MAGIC = 0xfd2fb528;

/** Directory that holds one sub-directory per `slug(cwd)`. */
export function sessionsRoot() {
  return path.join(dshHome(), 'sessions');
}

/** Directory that holds the per-session projection-cache metadata. */
export function metadataRoot() {
  return path.join(dshHome(), 'storages', 'session_projcache', 'sessions');
}

/**
 * Convert a working directory into the directory name DSH uses on disk.
 * Observed convention: `D:\APP\Deepseek\DSHHarmony` → `--D-APP-Deepseek-DSHHarmony--`,
 * spaces become `~0020`.
 */
export function cwdToSlug(cwd) {
  const normalized = String(cwd ?? '').replace(/\//gu, '\\').replace(/\\+$/u, '');
  const match = /^([A-Za-z]):(.*)$/u.exec(normalized);
  const drive = match ? match[1] : '';
  const rest = match ? match[2].replace(/^\\+/u, '') : normalized;
  const encoded = rest
    .split('\\')
    .map((segment) => segment.replace(/ /gu, '~0020'))
    .join('-');
  return `--${drive}-${encoded}--`;
}

/**
 * Best-effort inverse of {@link cwdToSlug}. Lossy (a literal `-` in a folder name is
 * indistinguishable from a separator) — always prefer `identity.cwd` from the metadata JSON.
 */
export function slugToCwd(slug) {
  const text = String(slug ?? '');
  const trimmed = text.startsWith('--') && text.endsWith('--') && text.length > 4
    ? text.slice(2, -2)
    : text;
  const dash = trimmed.indexOf('-');
  if (dash === -1) return trimmed.replace(/~0020/gu, ' ');
  const drive = trimmed.slice(0, dash);
  const rest = trimmed.slice(dash + 1).replace(/~0020/gu, ' ');
  return `${drive}:\\${rest.split('-').join('\\')}`;
}

/**
 * Yield the byte range of every complete zstd frame in `buffer`.
 * The zstd frame layout is walked from the specification (RFC 8878 §3.1.1) so the reader never
 * has to inflate a frame to find the next one.
 */
export function zstdFrameRanges(buffer) {
  const ranges = [];
  let offset = 0;
  while (offset + 4 <= buffer.length) {
    if (buffer.readUInt32LE(offset) !== ZSTD_MAGIC) break;
    const start = offset;
    let cursor = offset + 4;
    if (cursor >= buffer.length) break;

    const descriptor = buffer[cursor];
    cursor += 1;
    const contentSizeFlag = descriptor >> 6;
    const singleSegment = (descriptor >> 5) & 1;
    const hasChecksum = (descriptor >> 2) & 1;
    const dictionaryIdFlag = descriptor & 3;

    if (singleSegment === 0) cursor += 1; // Window_Descriptor
    cursor += dictionaryIdFlag === 0 ? 0 : dictionaryIdFlag === 1 ? 1 : dictionaryIdFlag === 2 ? 2 : 4;
    const contentSizeBytes = contentSizeFlag === 0 ? (singleSegment === 1 ? 1 : 0) : contentSizeFlag === 1 ? 2 : contentSizeFlag === 2 ? 4 : 8;
    cursor += contentSizeBytes;

    let lastBlock = false;
    let broken = false;
    while (!lastBlock) {
      if (cursor + 3 > buffer.length) {
        broken = true;
        break;
      }
      const header = buffer[cursor] | (buffer[cursor + 1] << 8) | (buffer[cursor + 2] << 16);
      cursor += 3;
      lastBlock = (header & 1) === 1;
      const blockType = (header >> 1) & 3;
      const blockSize = header >>> 3;
      if (blockType === 0) cursor += blockSize; // Raw_Block
      else if (blockType === 1) cursor += 1; // RLE_Block
      else if (blockType === 2) cursor += blockSize; // Compressed_Block
      else {
        broken = true;
        break;
      }
    }
    if (broken) break;
    if (hasChecksum) cursor += 4;
    if (cursor > buffer.length) break;
    ranges.push({ start, end: cursor });
    offset = cursor;
  }
  return ranges;
}

/**
 * Inflate every complete zstd frame of `buffer`.
 * Returns the concatenated payload plus the byte offset that was successfully consumed, so a
 * caller tailing a growing file knows where the last good frame ended.
 */
export function decodeZstdFrames(buffer) {
  const ranges = zstdFrameRanges(buffer);
  const parts = [];
  let consumed = 0;
  for (const range of ranges) {
    let decoded;
    try {
      decoded = zlib.zstdDecompressSync(buffer.subarray(range.start, range.end));
    } catch {
      break; // A partially written trailing frame: stop, keep what we have.
    }
    parts.push(decoded);
    consumed = range.end;
  }
  return { data: Buffer.concat(parts), consumed, frames: ranges.length };
}

/**
 * Read and decode one session log file.
 * Returns `{ header, rows, messages, size, mtimeMs, consumed }` or `null` when the file is absent.
 *
 * `tailLines` is a speed optimisation for the phone: a session with a few thousand events
 * takes seconds to parse line by line, and the phone only ever wants the newest window.
 * When it is set, only the last N lines are parsed (plus the first line, which carries the
 * session header). `rows` then only contains that tail.
 */
export function readSessionLog(logPath, { tailLines = 0 } = {}) {
  let stat;
  try {
    stat = fs.statSync(logPath);
  } catch {
    return null;
  }
  const buffer = fs.readFileSync(logPath);
  const { data, consumed, frames } = decodeZstdFrames(buffer);
  const text = data.toString('utf8');
  const allLines = text.split('\n');

  let header = null;
  let eventLines = allLines;
  if (tailLines > 0 && allLines.length > tailLines + 1) {
    eventLines = allLines.slice(allLines.length - tailLines);
    // 第一行通常是 session header, 单独解析出来
    try {
      const first = JSON.parse(allLines[0].trim());
      if (first && first.type === 'session') header = first;
    } catch {
      // 忽略: 后面还会再找一次
    }
  }

  const rows = [];
  for (const line of eventLines) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    try {
      rows.push(JSON.parse(trimmed));
    } catch {
      // A torn final line (the agent was mid-write): ignore it.
    }
  }
  if (header === null) {
    header = rows.find((row) => row && row.type === 'session') ?? null;
  }
  const events = rows.filter((row) => row && row.type !== 'session');
  return {
    header,
    rows,
    events,
    messages: mapEventsToMessages(events, header?.id ?? ''),
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    consumed,
    frames,
  };
}

/** Read the projection-cache metadata JSON of a session. */
export function readSessionMetadata(sessionId) {
  const file = path.join(metadataRoot(), `${sessionId}.json`);
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return parsed?.record ?? null;
  } catch {
    return null;
  }
}

/**
 * Every session present in the on-disk store.
 * The returned records carry the identity taken from the metadata JSON when available, because
 * the directory slug cannot be reversed losslessly.
 */
export function listStoreSessions() {
  const root = sessionsRoot();
  let slugDirs;
  try {
    slugDirs = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return [];
  }

  const sessions = [];
  for (const slugDir of slugDirs) {
    if (!slugDir.isDirectory()) continue;
    const slugPath = path.join(root, slugDir.name);
    let sessionDirs;
    try {
      sessionDirs = fs.readdirSync(slugPath, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const sessionDir of sessionDirs) {
      if (!sessionDir.isDirectory()) continue;
      const sessionPath = path.join(slugPath, sessionDir.name);
      const logPath = path.join(sessionPath, 'session.v4.jsonl.zstd');
      let stat;
      try {
        stat = fs.statSync(logPath);
      } catch {
        continue;
      }
      const id = sessionDir.name;
      const metadata = readSessionMetadata(id);
      const cwd = metadata?.identity?.cwd ?? slugToCwd(slugDir.name);
      sessions.push({
        id,
        cwd,
        slug: slugDir.name,
        dir: sessionPath,
        logPath,
        size: stat.size,
        mtimeMs: stat.mtimeMs,
        // The creation time of the log file. It is the fallback for the sessions whose
        // metadata does not carry a creation time (the projection is written later).
        birthtimeMs: stat.birthtimeMs,
        metadata,
      });
    }
  }
  return sessions;
}

/** Distinct working directories seen in the store. */
export function listStoreWorkspaces() {
  const seen = new Map();
  for (const session of listStoreSessions()) {
    if (session.cwd && !seen.has(session.cwd)) seen.set(session.cwd, session.id);
  }
  return [...seen.keys()].sort((a, b) => a.localeCompare(b));
}

/** Extract plain text out of a DSH content-part array. */
export function partsToText(parts) {
  if (typeof parts === 'string') return parts;
  if (!Array.isArray(parts)) return '';
  const chunks = [];
  for (const part of parts) {
    if (typeof part === 'string') {
      chunks.push(part);
      continue;
    }
    if (!part || typeof part !== 'object') continue;
    /* Only the visible text of the assistant.
     *
     * The content of an assistant message is a list of parts: `text` (the answer),
     * `reasoning` (the private thinking of the model) and `tool-call` (a tool it wants to
     * use). Only the `text` parts belong on the phone - the reasoning is not the answer, and
     * the tool call is shown as its own row. */
    if (part.type !== 'text') continue;
    if (typeof part.text === 'string') chunks.push(part.text);
  }
  return chunks.join('');
}

/** Pull the textual body out of an event payload, tolerating the various nesting shapes. */
export function eventText(data) {
  if (!data || typeof data !== 'object') return '';
  const direct = partsToText(data.content);
  if (direct.length > 0) return direct;
  const message = data.message;
  if (typeof message === 'string') return message;
  if (message && typeof message === 'object') {
    const fromMessage = partsToText(message.content);
    if (fromMessage.length > 0) return fromMessage;
    if (typeof message.text === 'string') return message.text;
  }
  return '';
}

/**
 * Map DSH session events onto the PROTOCOL.md Message shape.
 * Unknown event types are ignored on purpose: the log vocabulary grows with the harness.
 */
export function mapEventsToMessages(events, sessionId) {
  const messages = [];
  // 每条消息都带上自己的 seq: 手机端拿它去要全文(`/messages/{seq}/full`)。
  const push = (input) => {
    messages.push({ ...makeMessage(input), seq: input.seq });
  };
  for (const event of events) {
    if (!event || typeof event !== 'object') continue;
    const type = typeof event.type === 'string' ? event.type : '';
    const data = event.data && typeof event.data === 'object' ? event.data : {};
    const seq = Number.isFinite(event.seq) ? event.seq : messages.length;
    const createdAt = Number.isFinite(event.time) ? event.time : 0;
    const id = `m-${seq}`;

    if (type === 'user/message') {
      push({
        id,
        sessionId,
        seq,
        role: MessageRole.USER,
        kind: MessageKind.TEXT,
        text: eventText(data),
        createdAt,
        status: MessageStatus.DONE,
      });
      continue;
    }

    if (type === 'assistant/message') {
      const interrupted = data.interrupted === true;
      push({
        id,
        sessionId,
        seq,
        role: MessageRole.ASSISTANT,
        kind: MessageKind.TEXT,
        text: eventText(data),
        createdAt,
        status: interrupted ? MessageStatus.ERROR : MessageStatus.DONE,
      });
      continue;
    }

    if (type === 'system/message' || type === 'developer/message') {
      push({
        id,
        sessionId,
        seq,
        role: MessageRole.SYSTEM,
        kind: MessageKind.TEXT,
        text: eventText(data),
        createdAt,
        status: MessageStatus.DONE,
      });
      continue;
    }

    if (type === 'tool/call') {
      const name = typeof data.name === 'string' ? data.name : 'tool';
      const args = typeof data.arguments === 'string' ? data.arguments : JSON.stringify(data.arguments ?? {});
      push({
        id,
        sessionId,
        seq,
        role: MessageRole.ASSISTANT,
        kind: MessageKind.TOOL_CALL,
        name,
        text: `${name}(${truncate(args, 400)})`,
        createdAt,
        status: MessageStatus.DONE,
      });
      continue;
    }

    if (type === 'tool/result') {
      const isError = Boolean(data.error);
      const text = eventText(data) || (isError ? JSON.stringify(data.error) : '');
      push({
        id,
        sessionId,
        seq,
        role: MessageRole.TOOL,
        kind: MessageKind.TOOL_RESULT,
        text,
        createdAt,
        status: isError ? MessageStatus.ERROR : MessageStatus.DONE,
      });
    }
  }
  return messages;
}

/**
 * The full text of one message of a session log.
 *
 * The log is a zstd compressed JSON Lines file, so the text is read through the same decoding
 * path as the list (`readSessionLog`) — never from a plain text file.
 *
 * @param {string} logPath the path of `session.v4.jsonl.zstd`
 * @param {number} seq the sequence number of the wanted message
 * @returns {{text: string, found: boolean, role: string, kind: string, createdAt: number}|null}
 */
export function readMessageText(logPath, seq) {
  const snapshot = readSessionLog(logPath);
  if (snapshot === null) return null;
  for (const event of snapshot.events) {
    if (!event || !Number.isFinite(event.seq) || event.seq !== seq) continue;
    const data = event.data && typeof event.data === 'object' ? event.data : {};
    const type = typeof event.type === 'string' ? event.type : '';
    let role = MessageRole.SYSTEM;
    let kind = MessageKind.TEXT;
    if (type === 'user/message') role = MessageRole.USER;
    else if (type === 'assistant/message') role = MessageRole.ASSISTANT;
    else if (type === 'tool/result') {
      role = MessageRole.TOOL;
      kind = MessageKind.TOOL_RESULT;
    } else if (type === 'tool/call') {
      role = MessageRole.ASSISTANT;
      kind = MessageKind.TOOL_CALL;
    }
    const isError = Boolean(data.error);
    const text = eventText(data) || (isError ? JSON.stringify(data.error) : '');
    return {
      text,
      found: true,
      role,
      kind,
      createdAt: Number.isFinite(event.time) ? event.time : 0,
    };
  }
  return { text: '', found: false, role: MessageRole.SYSTEM, kind: MessageKind.TEXT, createdAt: 0 };
}

/**
 * The text of the first user message of a session log.
 *
 * It is the last fallback for a session whose title the desktop could not produce.
 *
 * @param {string} logPath the path of `session.v4.jsonl.zstd`
 * @returns {string|null} the text, or `null` when the log has no user message
 */
export function firstUserText(logPath) {
  const snapshot = readSessionLog(logPath);
  if (snapshot === null) return null;
  for (const event of snapshot.events) {
    if (event?.type !== 'user/message') continue;
    const data = event.data && typeof event.data === 'object' ? event.data : {};
    const text = eventText(data);
    if (text.length > 0) return text;
  }
  return null;
}

/**
 * Watch one session log for growth and report newly appended rows.
 * The poller re-reads and re-inflates the file whenever its size or mtime changed and diffs the
 * parsed rows against the ones already delivered.
 */
export class SessionTailer {
  constructor(sessionId, logPath, { pollIntervalMs = 600, onEvents } = {}) {
    this.sessionId = sessionId;
    this.logPath = logPath;
    this.pollIntervalMs = pollIntervalMs;
    this.onEvents = onEvents ?? (() => {});
    this.size = -1;
    this.mtimeMs = -1;
    this.rowCount = 0;
    this.timer = null;
  }

  /** Read the log once and deliver everything that is new since the previous call. */
  poll() {
    const snapshot = readSessionLog(this.logPath);
    if (snapshot === null) return [];
    const changed = snapshot.size !== this.size || snapshot.mtimeMs !== this.mtimeMs;
    this.size = snapshot.size;
    this.mtimeMs = snapshot.mtimeMs;
    if (!changed) return [];
    const fresh = snapshot.events.slice(this.rowCount);
    this.rowCount = snapshot.events.length;
    if (fresh.length > 0) this.onEvents(fresh, snapshot);
    return fresh;
  }

  /**
   * Take the current content as the baseline without emitting anything.
   * Only rows appended after this point are reported.
   */
  prime() {
    const snapshot = readSessionLog(this.logPath);
    if (snapshot === null) return;
    this.size = snapshot.size;
    this.mtimeMs = snapshot.mtimeMs;
    this.rowCount = snapshot.events.length;
  }

  start() {
    if (this.timer !== null) return;
    this.prime();
    this.timer = setInterval(() => {
      try {
        this.poll();
      } catch {
        // A transient read error must never kill the bridge.
      }
    }, this.pollIntervalMs);
    this.timer.unref?.();
  }

  stop() {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}

/**
 * An incremental index over the DSH session store.
 *
 * The directory listing and the metadata JSONs are cheap to re-read (a few dozen milliseconds for
 * the whole store), so they are refreshed on every poll. Inflating every session log is not cheap,
 * so message counts are computed lazily in the background and cached until the log changes.
 */
export class StoreIndex {
  constructor({ batchSize = 16 } = {}) {
    this.entries = new Map();
    this.batchSize = batchSize;
    this.pending = [];
    this.scanning = false;
    /** The entries whose message count was computed in the last batch. */
    this.lastCounted = [];
  }

  /** Re-scan the store directory and refresh the cheap metadata. */
  refresh() {
    const sessions = listStoreSessions();
    const seen = new Set();
    for (const session of sessions) {
      seen.add(session.id);
      const previous = this.entries.get(session.id);
      const metadata = session.metadata;
      const identity = metadata?.identity ?? {};
      const rows = metadata?.rows ?? {};
      const title = typeof rows.title?.val === 'string' && rows.title.val.length > 0 ? rows.title.val : null;
      const firstUserText = typeof rows.titleInput?.val?.first?.text === 'string' ? rows.titleInput.val.first.text : null;
      const modelSelection = rows.modelSelection?.val?.lastUsed ?? rows.modelSelection?.val?.next ?? null;

      const changed = previous === undefined
        || previous.size !== session.size
        || previous.mtimeMs !== session.mtimeMs;

      const entry = {
        id: session.id,
        cwd: identity.cwd ?? session.cwd ?? '',
        createdAt: typeof identity.createdAt === 'number' && identity.createdAt > 0
          ? identity.createdAt
          // The projection does not always carry the creation time; the log file does.
          : (typeof session.birthtimeMs === 'number' && session.birthtimeMs > 0 ? session.birthtimeMs : 0),
        title,
        firstUserText,
        model: modelSelection && typeof modelSelection.provider === 'string' && typeof modelSelection.model === 'string'
          ? { provider: modelSelection.provider, model: modelSelection.model }
          : null,
        agentPreset: typeof rows.agentPreset?.val === 'string' ? rows.agentPreset.val : null,
        messageCount: previous?.messageCount ?? 0,
        messageCountExact: previous?.messageCountExact ?? false,
        size: session.size,
        mtimeMs: session.mtimeMs,
        logPath: session.logPath,
        dir: session.dir,
      };
      this.entries.set(session.id, entry);
      if (changed || !previous?.messageCountExact) this.pending.push(session.id);
    }

    for (const id of [...this.entries.keys()]) if (!seen.has(id)) this.entries.delete(id);
    return this.entries;
  }

  /** One entry of the index, or `undefined`. */
  get(id) {
    return this.entries.get(id);
  }

  /** All entries. */
  all() {
    return [...this.entries.values()];
  }

  /**
   * Replace the entries with the snapshot a scanner thread produced.
   *
   * The main thread never walks the store itself (that blocks the event loop for seconds on a
   * big store), it only uses what the scanner found. The pending list belongs to the scanner,
   * so it is cleared here.
   */
  applyEntries(entries) {
    const next = new Map();
    for (const entry of entries ?? []) {
      if (entry && typeof entry.id === 'string') next.set(entry.id, entry);
    }
    this.entries = next;
    this.pending = [];
  }

  /**
   * Update the entries whose message count was computed in the last batch.
   *
   * The scanner counts the logs one batch at a time and sends the counted entries along, so
   * the session list can show the message count while the rest is still being counted.
   */
  applyCountedEntries(entries) {
    for (const entry of entries ?? []) {
      if (entry && typeof entry.id === 'string') this.entries.set(entry.id, entry);
    }
  }

  /** Are there logs left whose message count is not known yet? */
  hasPending() {
    return this.pending.length > 0;
  }

  /**
   * Inflate a few pending logs and cache their message counts.
   * Returns `true` while work remains.
   */
  computePendingCounts(batchSize = this.batchSize) {
    this.lastCounted = [];
    if (this.pending.length === 0) return false;
    const batch = this.pending.splice(0, batchSize);
    for (const id of batch) {
      const entry = this.entries.get(id);
      if (entry === undefined) continue;
      try {
        const snapshot = readSessionLog(entry.logPath);
        if (snapshot === null) continue;
        entry.messageCount = snapshot.messages.length;
        entry.messageCountExact = true;
        if (snapshot.header && typeof snapshot.header.createdAt === 'number' && entry.createdAt === 0) {
          entry.createdAt = snapshot.header.createdAt;
        }
        this.lastCounted.push(entry);
      } catch {
        // A log that cannot be read simply keeps its previous count.
      }
    }
    return this.pending.length > 0;
  }

  /** Distinct working directories known to the store. */
  workspaces() {
    const seen = new Map();
    for (const entry of this.entries.values()) {
      if (entry.cwd && !seen.has(entry.cwd)) seen.set(entry.cwd, entry.id);
    }
    return [...seen.keys()].sort((a, b) => a.localeCompare(b));
  }
}

/**
 * Append one JSONL row to a session log.
 * DSH stores the log as a sequence of independent zstd frames, so a new frame can simply be
 * appended; the reader picks it up on the next poll.
 */
export function appendSessionRow(sessionId, row) {
  const root = sessionsRoot();
  let slugDirs;
  try {
    slugDirs = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return false;
  }
  for (const slugDir of slugDirs) {
    if (!slugDir.isDirectory()) continue;
    const logPath = path.join(root, slugDir.name, sessionId, 'session.v4.jsonl.zstd');
    if (!fs.existsSync(logPath)) continue;
    const payload = Buffer.from(`${JSON.stringify(row)}\n`, 'utf8');
    fs.appendFileSync(logPath, zlib.zstdCompressSync(payload));
    return true;
  }
  return false;
}

/**
 * Create a new session directory in the store, copying the exact layout DSH uses.
 * Used by the `local` adapter; the `dsh` adapter creates sessions through the DSH API instead.
 */
export function createStoreSession({ cwd, title = '', agentPreset = 'standard', sessionId = `session-${crypto.randomUUID()}` } = {}) {
  const slug = cwdToSlug(cwd);
  const dir = path.join(sessionsRoot(), slug, sessionId);
  fs.mkdirSync(dir, { recursive: true });
  const createdAt = Date.now();
  const header = {
    type: 'session',
    version: 4,
    id: sessionId,
    createdAt,
    cwd,
    isSeeded: false,
    delegationDepth: 0,
    agentPreset,
  };
  const logPath = path.join(dir, 'session.v4.jsonl.zstd');
  fs.writeFileSync(logPath, zlib.zstdCompressSync(Buffer.from(`${JSON.stringify(header)}\n`, 'utf8')));

  const metadata = {
    version: 7,
    record: {
      identity: { formatVersion: 4, createdAt, cwd, isSeeded: false, inheritedEventCount: 0 },
      rows: {
        title: { ver: 1, seq: 0, val: title },
        agentPreset: { ver: 1, seq: 0, val: agentPreset },
        workingDirectory: { ver: 1, seq: 0, val: cwd },
        sessionStats: { ver: 1, seq: 0, val: { turns: 0, steps: 0, llmMs: 0, toolMs: 0, ttftMs: 0 } },
      },
    },
  };
  fs.mkdirSync(metadataRoot(), { recursive: true });
  fs.writeFileSync(path.join(metadataRoot(), `${sessionId}.json`), `${JSON.stringify(metadata, null, 2)}\n`, 'utf8');

  return { sessionId, logPath, dir, createdAt };
}

// Shared constants, error envelopes and shape validators for the PROTOCOL.md wire contract.
// Everything the phone sees is defined here so the HTTP layer, the WebSocket layer and the
// tests cannot drift apart.

export const PROTOCOL_VERSION = '1.0.0';
export const SERVER_NAME = 'dsh-harmony-bridge';
export const API_PREFIX = '/api/v1';
export const WS_PATH = '/ws';

/** Error codes used by the bridge itself. */
export const ErrorCode = {
  BAD_REQUEST: 'bad_request',
  UNAUTHORIZED: 'unauthorized',
  NOT_FOUND: 'not_found',
  INTERNAL: 'internal',
  DSH_UNAVAILABLE: 'dsh_unavailable',
  METHOD_NOT_ALLOWED: 'method_not_allowed',
};

/** Build the PROTOCOL.md error envelope. */
export function errorEnvelope(code, message, details) {
  const error = { code, message: String(message ?? code) };
  if (details !== undefined) error.details = details;
  return { error };
}

/** The three session states defined by PROTOCOL.md §4. */
export const SessionState = Object.freeze({ IDLE: 'idle', RUNNING: 'running', ERROR: 'error' });
/** The four message roles defined by PROTOCOL.md §4. */
export const MessageRole = Object.freeze({ USER: 'user', ASSISTANT: 'assistant', SYSTEM: 'system', TOOL: 'tool' });
/** The three message kinds defined by PROTOCOL.md §4. */
export const MessageKind = Object.freeze({ TEXT: 'text', TOOL_CALL: 'tool_call', TOOL_RESULT: 'tool_result' });
/** The three message statuses defined by PROTOCOL.md §4. */
export const MessageStatus = Object.freeze({ STREAMING: 'streaming', DONE: 'done', ERROR: 'error' });

/**
 * Build a SessionSummary. Missing fields degrade to safe defaults so the phone never
 * receives `undefined` where the protocol promises a concrete type.
 */
export function makeSessionSummary(input) {
  const summary = {
    id: String(input.id ?? ''),
    title: typeof input.title === 'string' && input.title.length > 0 ? input.title : String(input.id ?? ''),
    cwd: typeof input.cwd === 'string' ? input.cwd : '',
    createdAt: toEpochMs(input.createdAt),
    updatedAt: toEpochMs(input.updatedAt),
    state: input.state === SessionState.RUNNING || input.state === SessionState.ERROR ? input.state : SessionState.IDLE,
    messageCount: Number.isFinite(input.messageCount) ? Math.max(0, Math.trunc(input.messageCount)) : 0,
  };
  if (input.model && typeof input.model.provider === 'string' && typeof input.model.model === 'string') {
    summary.model = { provider: input.model.provider, model: input.model.model };
  }
  return summary;
}

/** Build a Message. */
export function makeMessage(input) {
  return {
    id: String(input.id ?? ''),
    sessionId: String(input.sessionId ?? ''),
    role: toRole(input.role),
    kind: toKind(input.kind),
    text: typeof input.text === 'string' ? input.text : '',
    // 工具名(只有 tool_call 有): 手机端要按桌面端的样式显示 "工具 pswh {...}"
    name: typeof input.name === 'string' ? input.name : '',
    createdAt: toEpochMs(input.createdAt),
    status: toStatus(input.status),
  };
}

function toRole(role) {
  return role === MessageRole.USER || role === MessageRole.ASSISTANT || role === MessageRole.SYSTEM || role === MessageRole.TOOL
    ? role
    : MessageRole.SYSTEM;
}

function toKind(kind) {
  return kind === MessageKind.TEXT || kind === MessageKind.TOOL_CALL || kind === MessageKind.TOOL_RESULT ? kind : MessageKind.TEXT;
}

function toStatus(status) {
  return status === MessageStatus.STREAMING || status === MessageStatus.ERROR ? status : MessageStatus.DONE;
}

/** Normalise anything into epoch milliseconds. */
export function toEpochMs(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.trunc(value);
  if (value instanceof Date) return value.getTime();
  if (typeof value === 'string') {
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return 0;
}

/** True when `value` looks like a SessionSummary. */
export function isSessionSummary(value) {
  if (!value || typeof value !== 'object') return false;
  if (typeof value.id !== 'string' || value.id.length === 0) return false;
  if (typeof value.title !== 'string') return false;
  if (typeof value.cwd !== 'string') return false;
  if (!Number.isFinite(value.createdAt) || !Number.isFinite(value.updatedAt)) return false;
  if (!Object.values(SessionState).includes(value.state)) return false;
  if (!Number.isFinite(value.messageCount)) return false;
  if (value.model !== undefined) {
    if (!value.model || typeof value.model.provider !== 'string' || typeof value.model.model !== 'string') return false;
  }
  return true;
}

/** True when `value` looks like a Message. */
export function isMessage(value) {
  if (!value || typeof value !== 'object') return false;
  if (typeof value.id !== 'string' || value.id.length === 0) return false;
  if (typeof value.sessionId !== 'string') return false;
  if (!Object.values(MessageRole).includes(value.role)) return false;
  if (!Object.values(MessageKind).includes(value.kind)) return false;
  if (typeof value.text !== 'string') return false;
  if (!Number.isFinite(value.createdAt)) return false;
  if (!Object.values(MessageStatus).includes(value.status)) return false;
  return true;
}

/** Truncate `text` to `max` characters, appending an ellipsis when it was cut. */
export function truncate(text, max = 80) {
  const flat = String(text ?? '').replace(/\s+/gu, ' ').trim();
  if (flat.length <= max) return flat;
  return `${flat.slice(0, Math.max(0, max - 1))}…`;
}

/** Client → server WebSocket frame types (PROTOCOL.md §3). */
export const ClientFrame = Object.freeze({
  SUBSCRIBE: 'subscribe',
  PROMPT: 'prompt',
  CANCEL: 'cancel',
  PING: 'ping',
});

/** Server → client WebSocket frame types (PROTOCOL.md §3). */
export const ServerFrame = Object.freeze({
  HELLO: 'hello',
  SESSION_LIST: 'session.list',
  SESSION_STATE: 'session.state',
  /** The summary of what the desktop is waiting for (running / finished / questions). */
  PENDING: 'pending',
  MESSAGE_CREATED: 'message.created',
  MESSAGE_DELTA: 'message.delta',
  MESSAGE_COMPLETED: 'message.completed',
  ERROR: 'error',
  PONG: 'pong',
});

/** Build a server → client envelope. */
export function serverFrame(type, data) {
  return { type, data: data ?? {} };
}

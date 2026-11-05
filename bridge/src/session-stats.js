// Reader for the DSH session projection-cache metadata: it projects the versioned rows of
// `<sessionId>.json` into the flat, phone-friendly status object that
// `GET /api/v1/sessions/{id}/stats` serves.
//
// The desktop DSH UI shows a status strip at the bottom of a session (turns, steps, tokens,
// context window, compaction counts, …). Every number of that strip comes from these rows, so
// the bridge only has to flatten them — nothing here is derived from the conversation itself.
//
// Two facts shape the implementation:
//   1. every row of the metadata is `{ ver, seq, val }` and the payload lives in `val`;
//   2. rows are optional (older sessions simply do not have them), so every field is read
//      defensively — a missing or malformed row leaves its field out of the result instead of
//      failing the request.

import fs from 'node:fs';
import path from 'node:path';

import { metadataRoot } from './store.js';

/**
 * A session id must be a plain file name: it is turned into a path below.
 * Anything else (`..`, a path separator) is refused instead of escaping the metadata directory.
 */
function isSafeSessionId(sessionId) {
  if (typeof sessionId !== 'string') return false;
  if (sessionId.length === 0 || sessionId.length > 200) return false;
  if (/[/\\]/u.test(sessionId)) return false;
  return !sessionId.includes('..');
}

/** Read the raw metadata file of a session. Returns `null` when it is missing or unparsable. */
function readMetadataFile(sessionId, root) {
  const file = path.join(root, `${sessionId}.json`);
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
  // The mtime is the moment DSH last rewrote the projection: it is the session's `updatedAt`.
  let mtimeMs = null;
  try {
    mtimeMs = Math.trunc(fs.statSync(file).mtimeMs);
  } catch {
    mtimeMs = null;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  const record = parsed?.record;
  if (!record || typeof record !== 'object') return null;
  return { record, mtimeMs };
}

/** A finite number, or `undefined`. */
function num(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

/** A non-empty string, or `undefined`. */
function str(value) {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/** Copy the defined entries of `source` into `target`; `undefined` values are dropped. */
function assignDefined(target, source) {
  for (const [key, value] of Object.entries(source)) {
    if (value !== undefined) target[key] = value;
  }
}

/**
 * The status numbers of one session, as read from the projection-cache metadata.
 *
 * Returns `null` when the session has no readable metadata (missing file, unparsable JSON, or
 * no `record` in it). Otherwise a plain object that carries only the fields that could actually
 * be read: a session whose metadata predates a row simply has no such field.
 *
 * @param {string} sessionId
 * @param {{ root?: string }} [options] `root` overrides the metadata directory (used by tests).
 * @returns {object|null}
 */
export function readSessionStats(sessionId, { root = metadataRoot() } = {}) {
  const id = typeof sessionId === 'string' ? sessionId.trim() : '';
  if (!isSafeSessionId(id)) return null;

  const metadata = readMetadataFile(id, root);
  if (metadata === null) return null;
  const { record, mtimeMs } = metadata;

  const rows = (record.rows && typeof record.rows === 'object') ? record.rows : {};
  // Every row is `{ ver, seq, val }`: the payload lives in `val`.
  const row = (name) => {
    const entry = rows[name];
    if (!entry || typeof entry !== 'object') return undefined;
    return entry.val;
  };

  const stats = { sessionId: id };

  // Turns, steps and the timing of the last turn.
  const sessionStats = row('sessionStats');
  if (sessionStats && typeof sessionStats === 'object') {
    assignDefined(stats, {
      turns: num(sessionStats.turns),
      steps: num(sessionStats.steps),
      lastTurn: num(sessionStats.lastTurn),
      llmMs: num(sessionStats.llmMs),
      toolMs: num(sessionStats.toolMs),
      ttftMs: num(sessionStats.ttftMs),
    });
  }

  // Token counters (totals over the whole session).
  const totals = row('tokenUsage')?.totals;
  if (totals && typeof totals === 'object') {
    assignDefined(stats, {
      uncachedInputTokens: num(totals.uncachedInputTokens),
      outputTokens: num(totals.outputTokens),
      cacheReadTokens: num(totals.cacheReadTokens),
      cacheWriteTokens: num(totals.cacheWriteTokens),
    });
  }

  // Context window occupancy and its breakdown.
  const pressure = row('contextPressure');
  const breakdown = row('contextBreakdown');
  const breakdownValues = breakdown?.breakdown;
  assignDefined(stats, {
    contextTokens: num(pressure?.surfaceTokens) ?? num(breakdown?.surfaceTokens),
    contextWindow: num(pressure?.contextWindow),
  });
  if (breakdownValues && typeof breakdownValues === 'object') {
    const contextBreakdown = {};
    assignDefined(contextBreakdown, {
      systemTokens: num(breakdownValues.systemTokens),
      toolsTokens: num(breakdownValues.toolsTokens),
      messageTokens: num(breakdownValues.messageTokens),
    });
    if (Object.keys(contextBreakdown).length > 0) stats.contextBreakdown = contextBreakdown;
  }

  // The permission preset of the session. The phone compares `permission` against the sandbox
  // mode names ("danger-full-access", "workspace-write"), so it is served as a plain string; the
  // structured form follows in `permissionInfo`.
  const permissions = row('permissions');
  const sandboxMode = str(row('sandboxMode'));
  const permissionMode = str(permissions?.sandbox) ?? sandboxMode ?? str(permissions?.preset);
  assignDefined(stats, { permission: permissionMode, sandboxMode });
  if (permissions && typeof permissions === 'object') {
    const permissionInfo = {};
    assignDefined(permissionInfo, {
      preset: str(permissions.preset),
      sandbox: str(permissions.sandbox),
      approval: str(permissions.approval),
    });
    if (Object.keys(permissionInfo).length > 0) stats.permissionInfo = permissionInfo;
  }

  // The model the session runs on. The phone shows `model` as one line of text, so it is served
  // as the model name; the structured form follows in `modelInfo`.
  const lastUsed = row('modelSelection')?.lastUsed;
  const modelName = str(lastUsed?.model);
  const modelProvider = str(lastUsed?.provider);
  assignDefined(stats, { model: modelName });
  if (lastUsed && typeof lastUsed === 'object') {
    const modelInfo = {};
    assignDefined(modelInfo, { provider: modelProvider, model: modelName });
    if (Object.keys(modelInfo).length > 0) stats.modelInfo = modelInfo;
  }

  // The subagent identity of the session (the agent mode and its label).
  const subagent = row('subagent');
  const identity = subagent?.identity;
  const agentMode = str(identity?.mode);
  const agentLabel = str(identity?.label);
  assignDefined(stats, { agentMode, agentLabel });

  // A background task is a subagent whose turn has not completed yet. The metadata of one
  // session says nothing about the subagents it spawned, so only the session itself counts.
  const timing = row('subagentTiming');
  stats.backgroundTasks = (agentMode !== undefined && timing?.lastTurnCompleted === false) ? 1 : 0;

  // The counters behind the desktop status strip (savings, compression, compaction, spill).
  const optimizer = row('tokenOptimizer');
  if (optimizer && typeof optimizer === 'object') {
    const tokenOptimizer = {};
    assignDefined(tokenOptimizer, {
      savedTokens: num(optimizer.savedTokens),
      savedChars: num(optimizer.savedChars),
      originalChars: num(optimizer.originalChars),
      retainedChars: num(optimizer.retainedChars),
      compressedResults: num(optimizer.compressedResults),
      compactionCount: num(optimizer.compactionCount),
      compactedTokens: num(optimizer.compactedTokens),
      spilledResults: num(optimizer.spilledResults),
    });
    if (Object.keys(tokenOptimizer).length > 0) stats.tokenOptimizer = tokenOptimizer;
  }

  // The projection is rewritten whenever the session changes, so its mtime is the update time.
  stats.updatedAt = mtimeMs ?? num(record.identity?.createdAt) ?? Date.now();

  return stats;
}

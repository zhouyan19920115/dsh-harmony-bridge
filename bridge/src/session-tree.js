// The session tree the desktop shows in its sidebar: conversations first, their topics and
// sub tasks right behind them.
//
// The desktop groups every session under its parent; a sub agent (`session/follow` addresses
// of the kind `subagent`) belongs to the conversation that spawned it. The bridge turns the
// flat `session/list` rows into that two level tree so the phone can render it as it is.

/** The title a session gets when the desktop did not give a usable one. */
export const UNTITLED = '未命名会话';

/**
 * True when a title is broken: the desktop stored a title whose bytes were mangled on the way in,
 * so the text is only question marks (or the replacement character) — or it carries a run of them
 * ("Canopy ????????").
 */
export function isBrokenTitle(text) {
  const value = String(text ?? '').trim();
  if (value.length === 0) return true;
  if (/^[\uFFFD?\s]+$/u.test(value)) return true;
  return /\?{3,}|\uFFFD{2,}/u.test(value);
}

/**
 * The title of a node, with the fallbacks the tree needs.
 *
 * A session id is never a title: it tells the user nothing, so the last fallback is "未命名会话".
 */
export function titleOf(...candidates) {
  for (const candidate of candidates) {
    if (typeof candidate !== 'string') continue;
    const trimmed = candidate.trim();
    if (trimmed.length === 0 || isBrokenTitle(trimmed)) continue;
    return trimmed;
  }
  return UNTITLED;
}

/** The parent id of a row, whatever the DSH calls it. */
export function parentIdOf(row) {
  const candidates = [
    row?.parentSessionId,
    row?.parent?.sessionId,
    row?.parentId,
    row?.session?.parentSessionId,
    row?.projections?.values?.parentSessionId,
    row?.address?.parentSessionId,
  ];
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.length > 0) return candidate;
  }
  return null;
}

/**
 * Build the tree from the raw DSH rows.
 *
 * @param {Array<object>} rows the rows of `session/list`
 * @param {(id: string) => object|null} summarize the summary of one session, if known
 * @returns {Array<{id: string, title: string, cwd: string, state: string, topics: Array<object>}>}
 */
export function buildSessionTree(rows, summarize) {
  const list = Array.isArray(rows) ? rows : [];
  const children = new Map();
  const parents = new Map();

  for (const row of list) {
    const id = String(row?.sessionId ?? row?.id ?? '');
    if (id.length === 0) continue;
    const parent = parentIdOf(row);
    if (parent === null || parent === id) continue;
    parents.set(id, parent);
    const bucket = children.get(parent) ?? [];
    bucket.push(row);
    children.set(parent, bucket);
  }

  const conversations = [];
  for (const row of list) {
    const id = String(row?.sessionId ?? row?.id ?? '');
    if (id.length === 0) continue;
    // A session that has a parent is not a conversation of its own.
    if (parents.has(id)) continue;
    const summary = summarize(id) ?? {};
    const values = row?.projections?.values ?? {};
    const topics = (children.get(id) ?? []).map((child) => {
      const childId = String(child?.sessionId ?? child?.id ?? '');
      const childSummary = summarize(childId) ?? {};
      const childValues = child?.projections?.values ?? {};
      return {
        id: childId,
        title: titleOf(childValues.title, childSummary.title, child?.summary?.title),
        state: childSummary.state ?? (child?.running === true ? 'running' : 'idle'),
        kind: 'subtask',
        cwd: child?.cwd ?? childSummary.cwd ?? '',
      };
    });
    conversations.push({
      id,
      title: titleOf(values.title, summary.title, row?.summary?.title),
      cwd: row?.cwd ?? values.workingDirectory ?? summary.cwd ?? '',
      state: summary.state ?? (row?.running === true ? 'running' : 'idle'),
      updatedAt: summary.updatedAt ?? row?.updatedAt ?? 0,
      topics,
    });
  }

  conversations.sort((a, b) => (b.updatedAt ?? 0) - (a.updatedAt ?? 0));
  return conversations;
}

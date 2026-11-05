// One directory, one spelling.
//
// DSH stores the working directory of a session as the caller wrote it, so the same folder
// reaches the bridge in several spellings: `D:\app\x`, `D:/app/x` and `D:\\app\\x` all name
// one directory on Windows. The phone groups its session list by the cwd string, so without a
// normalisation one project shows up as two "DSHHarmony" groups — and the forward-slash
// group is exactly the batch the desktop shows as "ungrouped", because a session created
// with a bare `cwd` never joins a Workspace (see `DshClient.createSession`).
//
// These helpers give every directory one spelling and one comparison key, so the bridge
// talks about a directory instead of about the way somebody wrote it down.

/** Windows compares paths case-insensitively; other systems do not. */
const CASE_INSENSITIVE = process.platform === 'win32';

/**
 * One separator, one backslash: every separator becomes a backslash and a run of
 * separators collapses into one.
 *
 * A UNC path keeps its two leading separators — `\\server\share` is a different thing
 * than `\server\share`.
 *
 * @param {unknown} value - the raw spelling.
 * @returns {string} the path with backslashes only.
 */
export function normalizeSeparators(value) {
  const text = String(value ?? '').trim();
  const unc = text.startsWith('\\\\') || text.startsWith('//');
  const body = text.replace(/[\\/]+/gu, '\\');
  return unc ? `\\\\${body.replace(/^\\+/u, '')}` : body;
}

/**
 * The canonical spelling of a directory: backslashes, no repeated separator and no
 * trailing one — except on the root of a drive, where the separator is the name.
 *
 * @param {unknown} value - the raw spelling.
 * @returns {string} the canonical spelling, or an empty string when there is no path.
 */
export function normalizeDirectory(value) {
  const text = normalizeSeparators(value);
  if (text.length === 0) return '';
  if (/^[A-Za-z]:\\$/u.test(text)) return text;
  return text.replace(/\\+$/u, '');
}

/**
 * The key two spellings of the same directory share.
 *
 * @param {unknown} value - the raw spelling.
 * @returns {string} the comparison key.
 */
export function directoryKey(value) {
  const text = normalizeDirectory(value);
  return CASE_INSENSITIVE ? text.toLowerCase() : text;
}

/**
 * Pick the spelling that best represents a directory: no forward slashes, no repeated
 * separator, then the shortest one. The desktop writes the canonical form, so a directory
 * the desktop knows is spelled the way the desktop spells it.
 *
 * @param {string[]} spellings - the spellings of one directory.
 * @returns {string} the representative spelling.
 */
export function pickDirectorySpelling(spellings) {
  const scored = spellings.map((spelling) => ({
    spelling,
    forward: (spelling.match(/\//gu) ?? []).length,
    repeated: (spelling.match(/[\\/]{2,}/gu) ?? []).length,
    length: spelling.length,
  }));
  scored.sort((left, right) => left.forward - right.forward
    || left.repeated - right.repeated
    || left.length - right.length
    || left.spelling.localeCompare(right.spelling));
  return scored[0]?.spelling ?? '';
}

/**
 * Group the spellings of directories: one entry per directory, with every spelling that
 * named it.
 *
 * @param {Iterable<string>} paths - the raw spellings.
 * @returns {{path: string, spellings: string[]}[]} one entry per directory.
 */
export function groupDirectories(paths) {
  const groups = new Map();
  for (const raw of paths) {
    if (typeof raw !== 'string') continue;
    const trimmed = raw.trim();
    if (trimmed.length === 0) continue;
    const key = directoryKey(trimmed);
    if (key.length === 0) continue;
    const group = groups.get(key);
    if (group === undefined) groups.set(key, { key, spellings: [trimmed] });
    else group.spellings.push(trimmed);
  }
  return [...groups.values()]
    .map((group) => ({ path: pickDirectorySpelling(group.spellings), spellings: group.spellings }))
    .sort((left, right) => left.path.localeCompare(right.path));
}

// The dangerous action detector behind `GET /api/v1/sessions/{id}/prompt-preview`.
//
// The phone asks the bridge what a prompt is going to do before it sends it. Only a session
// that runs with `danger-full-access` may be stopped for a second look — a read-only or a
// workspace-write session must not nag the user.
//
// The detector is a plain text scan: the bridge sees the prompt, not the tool calls the agent
// will make, so it looks for the shapes that are dangerous on their own: a command that
// changes the machine, a deletion, a write outside the workspace and a configuration change.
//
// The result is a list of actions plus one sentence in plain language, because the phone shows
// that sentence as it is.

/** A command that runs something and changes the machine. */
const COMMAND_PATTERNS = [
  { kind: 'command', pattern: /\b(?:npm|pnpm|yarn|bun)\s+(?:install|i|add|remove|uninstall|update|publish|run)\b/iu },
  { kind: 'command', pattern: /\b(?:pip|pip3|poetry|uv)\s+(?:install|uninstall|add)\b/iu },
  { kind: 'command', pattern: /\bgit\s+(?:push|commit|reset|clean|checkout|merge|rebase|revert|tag)\b/iu },
  { kind: 'command', pattern: /\b(?:docker|docker-compose|kubectl|helm|terraform|ansible|vagrant)\b/iu },
  { kind: 'command', pattern: /\b(?:choco|winget|scoop|brew|apt|apt-get|yum|dnf|pacman)\s+(?:install|uninstall|remove|add)\b/iu },
  { kind: 'command', pattern: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b/iu },
  { kind: 'command', pattern: /\b(?:python|python3|node|deno|bun)\s+[^\n]*\b(?:subprocess|os\.system|exec|spawn)\b/iu },
  { kind: 'command', pattern: /\b(?:powershell|pwsh|cmd(?:\.exe)?)\b[^\n]*-(?:enc|encodedcommand)\b/iu },
  { kind: 'command', pattern: /\breg(?:\.exe)?\s+(?:add|delete|import)\b/iu },
  { kind: 'command', pattern: /\bsetx\b|\bNew-ItemProperty\b|\bSet-ItemProperty\b/iu },
];

/** A deletion of a file or a directory. */
const DELETE_PATTERNS = [
  { pattern: /\brm\s+(?:-[a-zA-Z]*\s+)*-?[a-zA-Z]*[rf][a-zA-Z]*\s+([^\s;&|]+)/u },
  { pattern: /\brmdir\s+([^\s;&|]+)/iu },
  { pattern: /\bRemove-Item\b[^\n]*?(?:-Path\s+)?["']?([^\s"';|]+)/iu },
  { pattern: /\bdel(?:ete)?\s+(?:\/[sq]\s+)*["']?([^\s"';|]+)/iu },
  { pattern: /\bshutil\.rmtree\s*\(\s*["']([^"']+)["']/u },
  { pattern: /\bfs\.(?:rm|rmSync|unlink|unlinkSync)\s*\(\s*["']([^"']+)["']/u },
  { pattern: /\bgit\s+clean\s+(?:-[a-zA-Z]+\s+)*/iu },
  { pattern: /\bDrop-Item\b[^\n]*?(?:-Path\s+)?["']?([^\s"';|]+)/iu },
];

/** A write to a file. */
const WRITE_PATTERNS = [
  { pattern: /\bSet-Content\b|\bAdd-Content\b|\bOut-File\b/iu },
  { pattern: /\b(?:tee|install)\b[^\n]*\s>\s*["']?([^\s"';|]+)/u },
  { pattern: /\b(?:writeFile|writeFileSync|appendFile|appendFileSync)\s*\(\s*["']([^"']+)["']/u },
  { pattern: /\b(?:cat|echo)\b[^\n]*>\s*["']?([^\s"';|]+)/u },
];

/** A change of a configuration file. */
const CONFIG_PATTERNS = [
  { kind: 'config', pattern: /\bgit\s+config\b/iu },
  { kind: 'config', pattern: ["package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", ".env", "settings.json", "config.json", "tsconfig.json", "vite.config.ts", "webpack.config.js", "Dockerfile", "docker-compose.yml", ".gitignore", ".npmrc"].join('|') },
];

/** The text of a match, trimmed and shortened. */
function shorten(text, max = 120) {
  const clean = String(text ?? '').replace(/\s+/gu, ' ').trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

/** The paths of the configuration files a text mentions. */
function configPaths(text) {
  const names = ['package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', '.env',
    'settings.json', 'config.json', 'tsconfig.json', 'vite.config.ts', 'webpack.config.js',
    'Dockerfile', 'docker-compose.yml', '.gitignore', '.npmrc'];
  const found = [];
  for (const name of names) {
    if (found.length > 4) break;
    if (text.includes(name)) found.push(name);
  }
  return found;
}

/**
 * The dangerous actions a prompt text contains.
 *
 * @param {string} text the prompt the phone wants to send
 * @returns {Array<{kind: string, text?: string, path?: string}>}
 */
export function detectDangerousActions(text) {
  const body = typeof text === 'string' ? text : '';
  if (body.trim().length === 0) return [];
  const actions = [];
  const seen = new Set();

  const push = (action) => {
    const key = `${action.kind}|${action.text ?? ''}|${action.path ?? ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    actions.push(action);
  };

  for (const { kind, pattern } of COMMAND_PATTERNS) {
    const match = pattern.exec(body);
    if (match === null) continue;
    push({ kind, text: shorten(match[0]) });
  }

  for (const { pattern } of DELETE_PATTERNS) {
    const match = pattern.exec(body);
    if (match === null) continue;
    const path = match[1] === undefined ? '' : shorten(match[1], 80);
    push(path.length > 0 ? { kind: 'delete', path, text: shorten(match[0]) } : { kind: 'delete', text: shorten(match[0]) });
  }

  for (const { pattern } of WRITE_PATTERNS) {
    const match = pattern.exec(body);
    if (match === null) continue;
    const path = match[1] === undefined ? '' : shorten(match[1], 80);
    push(path.length > 0 ? { kind: 'write', path, text: shorten(match[0]) } : { kind: 'write', text: shorten(match[0]) });
  }

  for (const { kind, pattern } of CONFIG_PATTERNS) {
    if (kind === 'config' && typeof pattern !== 'string') continue;
    if (kind === 'config') {
      for (const path of configPaths(body)) push({ kind: 'config', path });
      continue;
    }
    const match = pattern.exec(body);
    if (match === null) continue;
    push({ kind, text: shorten(match[0]) });
  }

  return actions;
}

/**
 * One sentence in plain language about what the desktop is about to do.
 *
 * @param {Array<{kind: string, text?: string, path?: string}>} actions
 * @param {string} [cwd] the working directory of the session
 * @returns {string}
 */
export function summarizeActions(actions, cwd = '') {
  const list = Array.isArray(actions) ? actions : [];
  if (list.length === 0) return '';
  const place = typeof cwd === 'string' && cwd.length > 0 ? `在 ${cwd} 里` : '';
  const describe = (action) => {
    if (action.kind === 'delete') {
      const path = action.path ?? action.text ?? '文件';
      return `删除 ${path}`;
    }
    if (action.kind === 'write') {
      const path = action.path ?? action.text ?? '文件';
      return `写 ${path}`;
    }
    if (action.kind === 'config') {
      const path = action.path ?? action.text ?? '配置';
      return `改配置 ${path}`;
    }
    return `执行 ${action.text ?? '命令'}`;
  };
  const first = describe(list[0]);
  if (list.length === 1) return `桌面端要${place}${first}`;
  const rest = list.slice(1, 4).map(describe).join('、');
  return `桌面端要${place}${first} 等 ${list.length} 个危险动作: ${rest}`;
}

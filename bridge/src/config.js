// Configuration: on-disk state file (token), LAN address discovery and DSH home resolution.
// The token is the phone's only credential towards the bridge, so it is generated once and reused.
//
// The bridge can also be configured with a JSON file (`bridge.config.json`), so that a user who
// only wants "my phone talks to my computer over the public relay" does not have to learn any
// command line flag. The command line always wins over the file.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import https from 'node:https';
import http from 'node:http';

export const DEFAULT_PORT = 8787;
export const DEFAULT_HOST = '0.0.0.0';
export const DEFAULT_DSH_URL = 'http://127.0.0.1:10748';
export const DEFAULT_STATE_DIR = '.dsh-harmony-bridge';
export const DEFAULT_STATE_FILE = 'bridge.json';
export const DEFAULT_CONFIG_FILE = 'bridge.config.json';

/** The version of the bridge, sent to the relay when the bridge registers itself. */
export const BRIDGE_VERSION = '1.0.0';

/** Resolve `%USERPROFILE%\.dsh-harmony-bridge\bridge.json` unless overridden. */
export function defaultStateFile() {
  const home = os.homedir();
  return path.join(home, DEFAULT_STATE_DIR, DEFAULT_STATE_FILE);
}

/** Resolve `%USERPROFILE%\.dsh-harmony-bridge\bridge.config.json` unless overridden. */
export function defaultConfigFile() {
  const home = os.homedir();
  return path.join(home, DEFAULT_STATE_DIR, DEFAULT_CONFIG_FILE);
}

/** Resolve the DSH home directory (`$DSH_HOME` else `~/.dsh`). */
export function dshHome() {
  const fromEnv = process.env.DSH_HOME;
  if (typeof fromEnv === 'string' && fromEnv.length > 0) return fromEnv;
  return path.join(os.homedir(), '.dsh');
}

/**
 * Read the persisted bridge state, creating the directory and a fresh token when needed.
 * The token is 32 random bytes rendered as lowercase hex (64 characters).
 */
export function loadOrCreateState(stateFile) {
  const file = path.resolve(stateFile ?? defaultStateFile());
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true });

  let state = null;
  if (fs.existsSync(file)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (parsed && typeof parsed.token === 'string' && parsed.token.length >= 32) state = parsed;
    } catch {
      state = null;
    }
  }

  if (state === null) {
    state = { version: 1, token: crypto.randomBytes(32).toString('hex'), createdAt: Date.now() };
    fs.writeFileSync(file, `${JSON.stringify(state, null, 2)}\n`, { encoding: 'utf8' });
  }

  return {
    file,
    token: state.token,
    createdAt: state.createdAt ?? Date.now(),
    // The credentials the relay issued for this machine (null when the bridge never used a relay).
    relay: state.relay ?? null,
    raw: state,
  };
}

/**
 * Write the state file back (used after the relay issued new credentials).
 *
 * @param {object} state the state object, as returned by {@link loadOrCreateState}
 */
export function saveState(state) {
  const file = path.resolve(state.file);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(state.raw ?? state, null, 2)}\n`, { encoding: 'utf8' });
  return file;
}

// ---------------------------------------------------------------- the config file

/**
 * The keys the config file may carry, and the option each one fills.
 *
 * A config file describes **where** the bridge should talk to. It never carries credentials:
 * the account, the device and the tokens are generated on this machine, so a config file can
 * be copied around without handing out a secret.
 */
export const CONFIG_KEYS = Object.freeze({
  port: 'port',
  host: 'host',
  state: 'state',
  adapter: 'adapter',
  dshUrl: 'dshUrl',
  allowUnauthPairing: 'allowUnauthPairing',
  relay: 'relay',
  relayCa: 'relayCa',
  relayPublicUrl: 'relayPublicUrl',
  deviceName: 'relayName',
});

/**
 * The keys a config file must NOT carry.
 *
 * They are refused with a clear message: a credential in a config file would end up in a backup,
 * in a screenshot or in a git repository.
 */
export const FORBIDDEN_CONFIG_KEYS = Object.freeze([
  'token',
  'account',
  'accountToken',
  'deviceId',
  'deviceToken',
  'accounts',
  'devices',
  'accountsFile',
  'devicesFile',
]);

/**
 * Find the `--config <path>` argument without parsing everything else.
 *
 * @param {string[]} argv the command line
 * @param {string|null} fallback the path to use when the command line does not name one
 * @returns {string|null}
 */
export function findConfigPath(argv = [], fallback = null) {
  for (let i = 0; i < argv.length; i += 1) {
    const raw = argv[i];
    if (!raw.startsWith('--')) continue;
    const eq = raw.indexOf('=');
    const name = eq === -1 ? raw.slice(2) : raw.slice(2, eq);
    if (name !== 'config') continue;
    if (eq !== -1) return raw.slice(eq + 1);
    const next = argv[i + 1];
    return next === undefined || next.startsWith('--') ? fallback : next;
  }
  return fallback;
}

/**
 * Read a JSON config file.
 *
 * @param {string} file the path of the file
 * @returns {object} the parsed object (an empty object when the file does not exist)
 */
export function loadConfigFile(file) {
  if (!file) return {};
  const resolved = path.resolve(file);
  if (!fs.existsSync(resolved)) return {};
  let parsed;
  try {
    // A file written by an editor on Windows often starts with a byte order mark; JSON.parse
    // does not accept it.
    const text = fs.readFileSync(resolved, 'utf8').replace(/^\uFEFF/u, '');
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`the config file ${resolved} is not valid JSON: ${error.message}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`the config file ${resolved} must hold a JSON object`);
  }
  return parsed;
}

/**
 * Turn the keys of a config file into the options of the bridge.
 *
 * @param {object} raw the parsed config file
 * @param {string} [file] the file the options came from, for the error messages
 * @returns {object} the options the command line does not override
 */
export function configToOptions(raw, file = 'the config file') {
  const options = {};
  const refused = [];
  for (const [key, value] of Object.entries(raw ?? {})) {
    if (FORBIDDEN_CONFIG_KEYS.includes(key)) {
      refused.push(key);
      continue;
    }
    const option = CONFIG_KEYS[key];
    if (option === undefined) {
      throw new Error(`${file}: unknown key "${key}" (known: ${Object.keys(CONFIG_KEYS).join(', ')})`);
    }
    if (value === null || value === undefined) continue;
    if (typeof value === 'object') {
      throw new Error(`${file}: the key "${key}" must be a simple value`);
    }
    options[option] = value;
  }
  if (refused.length > 0) {
    throw new Error(
      `${file}: the key(s) ${refused.join(', ')} are refused — the account, the device and the tokens `
      + 'are generated on this machine, a config file only says where to connect.',
    );
  }
  return options;
}

// ---------------------------------------------------------------- the relay registration

/**
 * Generate the identity of this machine: the account, the device and the local secret.
 *
 * All three are generated **here**, never handed out by a config file. The relay decides which
 * ids it keeps and issues the tokens.
 *
 * @returns {{accountId: string, deviceId: string, secret: string}}
 */
export function generateLocalIdentity() {
  return {
    accountId: `acc-${crypto.randomBytes(4).toString('hex')}`,
    deviceId: `dev-${crypto.randomBytes(4).toString('hex')}`,
    secret: crypto.randomBytes(32).toString('hex'),
  };
}

/** The path of the registration endpoint of the relay. */
export const RELAY_REGISTER_PATH = '/_relay/accounts/register';

/**
 * The base url of the registration endpoint of a relay.
 *
 * The relay is addressed with a ws:// url (the device dials in to it), the registration happens
 * over http(s) on the same host.
 *
 * @param {string} relayUrl the ws:// or wss:// url of the relay
 * @param {string} [publicUrl] the public http(s) url of the relay, when it is known
 * @returns {string} the http(s) url of the registration endpoint
 */
export function relayRegisterUrl(relayUrl, publicUrl = null) {
  if (publicUrl) {
    const base = new URL(publicUrl);
    base.pathname = RELAY_REGISTER_PATH;
    base.search = '';
    base.hash = '';
    return base.toString();
  }
  const base = new URL(String(relayUrl));
  base.protocol = base.protocol === 'wss:' ? 'https:' : 'http:';
  base.pathname = RELAY_REGISTER_PATH;
  base.search = '';
  base.hash = '';
  return base.toString();
}

/**
 * Ask a relay to register this machine.
 *
 * The relay is the trust boundary: it issues the account token and the device token. The bridge
 * only sends its own locally generated ids and the local secret.
 *
 * @param {object} options the options
 * @param {string} options.url the http(s) url of the registration endpoint
 * @param {string} options.deviceName the friendly name of this computer
 * @param {{accountId: string, deviceId: string, secret: string}} options.identity the local identity
 * @param {Buffer|null} [options.ca] the PEM of the trust anchor of a self signed relay
 * @param {number} [options.timeoutMs] how long to wait for the relay
 * @param {string} [options.platform] the platform of this computer
 * @returns {Promise<object>} the credentials the relay issued
 */
export function registerWithRelay(options) {
  const { url, deviceName, identity, ca = null, timeoutMs = 15000, platform = process.platform } = options;
  const body = JSON.stringify({
    deviceName: String(deviceName ?? ''),
    deviceId: identity.deviceId,
    accountId: identity.accountId,
    secret: identity.secret,
    platform,
    version: BRIDGE_VERSION,
  });

  return new Promise((resolve, reject) => {
    let target;
    try {
      target = new URL(url);
    } catch (error) {
      reject(new Error(`invalid relay registration url ${url}: ${error.message}`));
      return;
    }
    const agent = target.protocol === 'https:' && ca ? new https.Agent({ ca }) : undefined;
    const request = (target.protocol === 'https:' ? https : http).request(
      target,
      {
        method: 'POST',
        agent,
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
          'user-agent': `dsh-harmony-bridge/${BRIDGE_VERSION}`,
        },
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let parsed = null;
          try {
            parsed = text.length > 0 ? JSON.parse(text) : null;
          } catch {
            parsed = null;
          }
          if (response.statusCode >= 200 && response.statusCode < 300) {
            if (!parsed || typeof parsed.deviceToken !== 'string' || typeof parsed.accountToken !== 'string') {
              reject(new Error('the relay answered the registration without an account token and a device token'));
              return;
            }
            resolve(parsed);
            return;
          }
          const code = parsed?.error?.code ?? `http_${response.statusCode}`;
          const message = parsed?.error?.message ?? text.slice(0, 200);
          reject(new RelayRegistrationError(code, message, response.statusCode, parsed));
        });
      },
    );
    request.setTimeout(timeoutMs, () => {
      request.destroy(new Error(`the relay did not answer within ${timeoutMs} ms`));
    });
    request.on('error', (error) => {
      reject(new Error(`the relay ${target.host} could not be reached: ${error.message}`));
    });
    request.end(body);
  });
}

/** The error of a registration the relay refused. */
export class RelayRegistrationError extends Error {
  constructor(code, message, status = 0, payload = null) {
    super(`${code}: ${message}`);
    this.name = 'RelayRegistrationError';
    this.code = code;
    this.status = status;
    this.payload = payload;
  }
}

/**
 * Every non-internal IPv4 address of this machine, most "LAN looking" first.
 * Used to print the URLs a phone on the same network can reach.
 */
export function lanAddresses() {
  const interfaces = os.networkInterfaces();
  const found = [];
  for (const [name, entries] of Object.entries(interfaces)) {
    for (const entry of entries ?? []) {
      if (entry.internal) continue;
      if (entry.family !== 'IPv4' && entry.family !== 4) continue;
      if (typeof entry.address !== 'string' || entry.address.length === 0) continue;
      found.push({ interface: name, address: entry.address, netmask: entry.netmask, mac: entry.mac });
    }
  }
  // Prefer RFC1918-ish private ranges first: they are the ones a phone can reach.
  const rank = (entry) => {
    if (entry.address.startsWith('192.168.')) return 0;
    if (entry.address.startsWith('10.')) return 1;
    if (/^172\.(1[6-9]|2\d|3[01])\./u.test(entry.address)) return 2;
    return 3;
  };
  found.sort((a, b) => rank(a) - rank(b) || a.address.localeCompare(b.address));
  return found;
}

/** The single best LAN address, or `127.0.0.1` when the machine has none. */
export function primaryLanAddress() {
  const all = lanAddresses();
  return all.length > 0 ? all[0].address : '127.0.0.1';
}

/**
 * Parse a `--flag value` / `--flag=value` style argument list.
 *
 * @param {string[]} argv the command line
 * @param {object} [base] the options a config file provided; the command line wins over them
 */
export function parseArgs(argv, base = {}) {
  const options = {
    port: DEFAULT_PORT,
    host: DEFAULT_HOST,
    state: null,
    adapter: 'dsh',
    allowUnauthPairing: false,
    dshUrl: null, // null means: look for the DSH host automatically
    relay: null,
    deviceToken: null,
    deviceId: null,
    relayName: os.hostname(),
    account: null,
    accountToken: null,
    relayPublicUrl: null,
    relayCa: null,
    // How long the pairing code stays valid. `null` = the discovery service's own default (60 s).
    pairingCodeTtlMs: null,
    config: null,
    // Print the full token and exit (the only way to get it out of the machine on purpose).
    printToken: false,
    // The bridge registers itself at the relay when it has no credentials yet.
    autoRegister: true,
    help: false,
    ...base,
  };
  const rest = [];

  for (let i = 0; i < argv.length; i += 1) {
    const raw = argv[i];
    if (!raw.startsWith('--')) {
      rest.push(raw);
      continue;
    }
    const eq = raw.indexOf('=');
    const name = eq === -1 ? raw.slice(2) : raw.slice(2, eq);
    let value = eq === -1 ? undefined : raw.slice(eq + 1);
    const take = () => {
      if (value !== undefined) return value;
      i += 1;
      return argv[i];
    };

    switch (name) {
      case 'port':
        options.port = Number.parseInt(take() ?? '', 10);
        break;
      case 'host':
        options.host = take() ?? DEFAULT_HOST;
        break;
      case 'state':
        options.state = take() ?? null;
        break;
      case 'adapter':
        options.adapter = (take() ?? 'dsh').toLowerCase();
        break;
      case 'dsh-url':
        options.dshUrl = take() ?? DEFAULT_DSH_URL;
        break;
      case 'allow-unauth-pairing':
        options.allowUnauthPairing = value === undefined ? true : value !== 'false';
        break;
      case 'print-token':
        options.printToken = value === undefined ? true : value !== 'false';
        break;
      case 'relay':
        options.relay = take() ?? null;
        break;
      case 'device-token':
        options.deviceToken = take() ?? null;
        break;
      case 'device-id':
        options.deviceId = take() ?? null;
        break;
      case 'relay-name':
        options.relayName = take() ?? os.hostname();
        break;
      case 'account':
        options.account = take() ?? null;
        break;
      case 'account-token':
        options.accountToken = take() ?? null;
        break;
      case 'relay-public-url':
        options.relayPublicUrl = take() ?? null;
        break;
      case 'relay-ca':
        options.relayCa = take() ?? null;
        break;
      case 'pairing-code-ttl': {
        // How long the pairing code stays valid. The default (60 s) is short on purpose, but a
        // slow scan or a slow user runs into it: the phone fetches the code, and the code is
        // already replaced by the time the user taps "connect".
        const seconds = Number.parseInt(take() ?? '', 10);
        if (!Number.isFinite(seconds) || seconds < 10) {
          throw new Error('--pairing-code-ttl needs a number of seconds (at least 10)');
        }
        options.pairingCodeTtlMs = Math.min(seconds, 3600) * 1000;
        break;
      }
      case 'config':
        options.config = take() ?? null;
        break;
      case 'no-register':
        options.autoRegister = false;
        break;
      case 'register':
        options.autoRegister = value === undefined ? true : value !== 'false';
        break;
      case 'help':
      case 'h':
        options.help = true;
        break;
      default:
        throw new Error(`unknown option --${name}`);
    }
  }

  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65535) {
    throw new Error(`invalid --port value: ${options.port}`);
  }
  if (options.adapter !== 'dsh' && options.adapter !== 'local') {
    throw new Error(`invalid --adapter value: ${options.adapter} (expected "dsh" or "local")`);
  }
  if (options.relay) {
    // The device id and the device token belong together. When they are missing the bridge
    // registers itself at the relay (see cli.js), so only a half filled pair is an error.
    if (Boolean(options.deviceToken) !== Boolean(options.deviceId)) {
      throw new Error('--device-token and --device-id go together');
    }
    if (!options.deviceToken && !options.autoRegister) {
      throw new Error('--relay requires --device-token and --device-id (drop --no-register to let the bridge register itself)');
    }
    if (options.deviceId && !/^[A-Za-z0-9._-]+$/u.test(options.deviceId)) {
      throw new Error(`invalid --device-id value: ${options.deviceId}`);
    }
    let relayUrl;
    try {
      relayUrl = new URL(options.relay);
    } catch {
      throw new Error(`invalid --relay value: ${options.relay}`);
    }
    if (relayUrl.protocol !== 'ws:' && relayUrl.protocol !== 'wss:') {
      throw new Error(`invalid --relay value: ${options.relay} (expected ws:// or wss://)`);
    }
    // The account is optional: a relay that only knows the flat device registry still works.
    if (options.account !== null && !/^[A-Za-z0-9._-]+$/u.test(options.account)) {
      throw new Error(`invalid --account value: ${options.account}`);
    }
    if (options.accountToken !== null && !/^[0-9a-f]+$/iu.test(options.accountToken)) {
      throw new Error(`invalid --account-token value: ${options.accountToken} (expected hex)`);
    }
    if (options.accountToken !== null && options.account === null) {
      // The account token identifies the account on its own (the relay resolves it), but the
      // bridge cannot print an account scoped pairing url without the account id.
      options.accountMissing = true;
    }
    if (options.relayPublicUrl !== null) {
      let publicUrl;
      try {
        publicUrl = new URL(options.relayPublicUrl);
      } catch {
        throw new Error(`invalid --relay-public-url value: ${options.relayPublicUrl}`);
      }
      if (publicUrl.protocol !== 'http:' && publicUrl.protocol !== 'https:') {
        throw new Error(`invalid --relay-public-url value: ${options.relayPublicUrl} (expected http:// or https://)`);
      }
    }
    // The trust anchor of a self signed relay certificate only makes sense over TLS.
    if (options.relayCa !== null && relayUrl.protocol !== 'wss:') {
      throw new Error('--relay-ca needs a wss:// relay URL');
    }
  } else if (options.account !== null || options.accountToken !== null) {
    throw new Error('--account and --account-token need --relay');
  } else if (options.relayCa !== null) {
    throw new Error('--relay-ca needs --relay');
  }
  options.rest = rest;
  return options;
}

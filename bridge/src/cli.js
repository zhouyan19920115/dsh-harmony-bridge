#!/usr/bin/env node
// Command line entry point of the DSH Harmony bridge.
//
// Parses the options, loads (or creates) the token, probes the DSH application, prints the LAN
// URLs, the token, a copy-paste curl example and the pairing QR code, and then serves the API.

import process from 'node:process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  DEFAULT_DSH_URL,
  configToOptions,
  defaultConfigFile,
  findConfigPath,
  generateLocalIdentity,
  loadConfigFile,
  loadOrCreateState,
  lanAddresses,
  parseArgs,
  primaryLanAddress,
  registerWithRelay,
  relayRegisterUrl,
  saveState,
} from './config.js';
import { DshClient, DSH_MINIMUM_VERSION, discoverDshUrl, isDshVersionSafe, readDshVersion } from './dsh.js';
import { Bridge, Router, createRoutes } from './router.js';
import { createBridgeServer } from './server.js';
import { PROTOCOL_VERSION, SERVER_NAME } from './protocol.js';
import { qrToText } from './qr.js';
import { RelayClient, relayPhoneUrl } from './relay-client.js';
import { maskSecret } from './mask.js';

/** Log with the `[bridge]` prefix and a timestamp. */
export function makeLogger(prefix = '[bridge]') {
  return (level, message) => {
    const stamp = new Date().toISOString().replace('T', ' ').slice(0, 23);
    process.stdout.write(`${stamp} ${prefix} ${level.toUpperCase().padEnd(5)} ${message}\n`);
  };
}

/**
 * Trim the whitespace a copy picked up (a token that was copied out of a wrapped line).
 *
 * A blank *inside* the token cannot be repaired here — the token is refused further down, because
 * the handshake header cannot carry it.
 *
 * @param {string} value
 * @returns {string}
 */
function trimSecret(value) {
  return typeof value === 'string' ? value.trim() : value;
}

/**
 * Check the secrets the bridge hands to the relay.
 *
 * A copy that picked up a line break leaves blanks inside the secret, and the handshake cannot
 * carry that: `Sec-WebSocket-Protocol` is a comma separated list of protocol names, so a space
 * splits the secret in two and the relay reads a truncated one. The relay then answers 401 every
 * 30 s, forever, while the banner still says the remote is ready — the bridge would look fine
 * and be unreachable. So a secret with a blank inside is refused outright.
 *
 * @param {{deviceToken?: string|null, accountToken?: string|null}} secrets
 * @returns {{ok: boolean, name: string, reason: string}} the verdict
 */
export function checkRelaySecrets(secrets = {}) {
  const candidates = [
    ['--device-token', secrets.deviceToken],
    ['--account-token', secrets.accountToken],
  ];
  for (const [name, value] of candidates) {
    if (typeof value !== 'string' || value.length === 0) continue;
    if (/\s/u.test(value)) {
      return {
        ok: false,
        name,
        reason: `${name} contains whitespace — the relay handshake would carry a broken secret (401 forever)`,
      };
    }
  }
  return { ok: true, name: '', reason: '' };
}

const USAGE = `dsh-harmony-bridge ${PROTOCOL_VERSION}

Usage: dsh-harmony-bridge [options]

Options:
  --config <file>             JSON file with the options below; the command line wins over it
                              (default %USERPROFILE%\\.dsh-harmony-bridge\\bridge.config.json)
  --port <number>            TCP port to listen on (default 8787)
  --host <address>           address to bind (default 0.0.0.0)
  --state <file>             state file holding the token
                             (default %USERPROFILE%\\.dsh-harmony-bridge\\bridge.json)
  --adapter <dsh|local>      where prompts are executed (default dsh)
  --dsh-url <url>            base URL of the DSH application (default: found automatically)
  --allow-unauth-pairing     allow /api/v1/pairing from other hosts
  --pairing-code-ttl <sec>   how long the pairing code stays valid (default 60);
                              raise it when a slow scan or a slow user runs into
                              "the pairing code has expired"
  --relay <ws-url>           cloud relay the bridge dials out to, e.g.
                             wss://relay.example.com:8443/bridge (default: off)
  --relay-ca <file>          PEM file with the certificate of a self signed relay;
                             the relay certificate is always verified
  --device-token <hex>       token the relay knows this device by (required with --relay)
  --device-id <id>           device id the relay knows this device by, e.g. dev-8f2a
                             (required with --relay)
  --relay-name <name>        friendly device name shown in the relay (default: the hostname)
  --account <id>             account of the relay, e.g. acc-1a2b (the account owns the
                             devices, the phone addresses them as /<accountId>/<deviceId>)
  --account-token <hex>      secret of that account; a device that presents it joins the
                             account
  --relay-public-url <url>   public base url of the relay for the phone, e.g.
                             https://relay.example.com:8443 (default: derived from --relay)
  --no-register              never register at the relay; --relay then needs
                             --device-id and --device-token
  --print-token              print the full access token and exit (the banner only shows it
                             masked; this is the deliberate way to get the real one)
  --help                     show this text
`;

/**
 * Print the startup banner.
 */
function printBanner({ log, options, state, bridge, urls, relay = null }) {
  const line = '─'.repeat(64);
  log('info', `${line}`);
  log('info', `${SERVER_NAME} ${PROTOCOL_VERSION} — desktop bridge for the HarmonyOS client`);
  log('info', `adapter        : ${options.adapter}   dsh: ${options.dshUrl}`);
  log('info', `listening on   : http://${options.host}:${options.port}`);
  log('info', `state file     : ${state.file}`);
  log('info', `pairing code   : valid for ${Math.round((options.pairingCodeTtlMs ?? 60_000) / 1000)} s`);
  log('info', `dsh reachable  : ${bridge.dshAvailable ? 'yes' : `no (${bridge.dshError ?? 'unknown'})`}`);
  // The version of the DSH matters: older hosts trust a forged Host header (CVE-2026-82533).
  const dshVersion = options.dshVersion ?? null;
  log('info', `dsh version    : ${dshVersion ?? 'unknown'}`);
  if (dshVersion !== null && !isDshVersionSafe(dshVersion)) {
    log('warn', `the DSH ${dshVersion} is older than ${DSH_MINIMUM_VERSION}: it is affected by the local Host header bypass (CVE-2026-82533) — please update the DSH application.`);
  }
  // The push configuration is never shown with its secret, only its shape.
  const push = bridge.push?.describe?.() ?? null;
  if (push !== null) {
    log('info', `push           : ${push.enabled ? `configured (${push.appId})` : 'not configured — notifications are only logged'}`
      + `   phones: ${push.registeredPhones}`);
  }
  log('info', line);
  log('info', 'LAN URLs (the phone must use one of these):');
  for (const url of urls) log('info', `  ${url}`);
  let pairingUrl = null;
  if (options.relay) {
    log('info', '');
    log('info', 'cloud relay (the phone may reach the bridge through the relay):');
    log('info', `  relay url      : ${options.relay}`);
    log('info', `  device id      : ${options.deviceId}`);
    log('info', `  device name    : ${options.relayName}`);
    log('info', `  account id     : ${options.account ?? '(none — the flat device registry is used)'}`);
    log('info', `  relay connected: ${relay?.connected ? 'yes' : `no${relay?.lastError ? ` (${relay.lastError})` : ''}`}`);
    // The address the phone types into its "桌面端地址" field. The relay's phone side port is not
    // part of the device handshake, so the relay port is used here; when the relay terminates TLS
    // on a separate phone side port, replace the port (and the scheme) by hand.
    pairingUrl = relayPhoneUrl(options.relay, options.deviceId, options.account, options.relayPublicUrl);
    log('info', `  phone address  : ${pairingUrl}`);
    log('info', `  pair this phone: ${pairingUrl}`);
    if (options.relay.startsWith('wss:') && !options.relayPublicUrl) {
      log('info', '  note           : the relay phone side port may differ from the device port,');
      log('info', '                    use --relay-public-url https://<relay-host>:<phone-port>');
    }
  }
  log('info', '');
  // The token is a secret: the banner only shows its shape. The full one goes to stderr, so
  // that a redirected stdout (a log file) never contains it. `--print-token` prints it on
  // purpose, for the scripts that need to hand it to the phone.
  log('info', `token          : ${maskSecret(state.token)}`);
  log('info', '                 (the full token is on stderr; to copy it: node bridge/src/cli.js --print-token)');
  process.stderr.write(`[bridge] full token (copy it into the phone): ${state.token}\n`);
  log('info', '');
  log('info', 'try it:');
  log('info', `  curl -s -H "Authorization: Bearer ${maskSecret(state.token)}" http://127.0.0.1:${options.port}/api/v1/health`);
  log('info', `  curl -s -H "Authorization: Bearer ${maskSecret(state.token)}" http://127.0.0.1:${options.port}/api/v1/sessions`);
  log('info', line);

  const pairing = bridge.pairingInfo();
  try {
    const { text } = qrToText(pairing.qrPayload, { level: 'M' });
    log('info', 'scan to pair the phone:');
    for (const row of text.split('\n')) log('info', `  ${row}`);
    log('info', line);
  } catch (error) {
    log('warn', `the pairing QR code could not be rendered: ${error.message}`);
  }

  if (options.relay && pairingUrl) {
    // The relay pairing qr: the phone opens this url, it carries the account and the device.
    try {
      const { text } = qrToText(pairingUrl, { level: 'M' });
      log('info', 'scan to pair the phone with the relay (account + device):');
      for (const row of text.split('\n')) log('info', `  ${row}`);
      log('info', line);
    } catch (error) {
      log('warn', `the relay pairing QR code could not be rendered: ${error.message}`);
    }
  }
}

/**
 * The credentials the bridge uses at the relay.
 *
 * Three sources, in this order:
 *
 *   1. the command line — a hand made setup (`--device-id` + `--device-token`);
 *   2. the state file — the credentials the relay issued during an earlier run;
 *   3. a fresh registration — the first run of a bridge that points at a relay.
 *
 * The registration never fails silently: the error is printed and the bridge stops, because a
 * bridge that did not register cannot be reached by a phone.
 *
 * @param {object} options the options
 * @param {object} options.options the parsed options
 * @param {object} options.state the state of this machine
 * @param {Function} options.log the logger
 * @param {Buffer|null} options.relayCa the trust anchor of a self signed relay
 * @returns {Promise<{deviceId: string, deviceToken: string, account: string|null, accountToken: string|null, publicUrl: string|null}>}
 */
async function resolveRelayCredentials({ options, state, log, relayCa }) {
  // 1) the command line
  if (options.deviceToken && options.deviceId) {
    log('info', `relay credentials : from the command line (the device ${options.deviceId})`);
    return {
      deviceId: options.deviceId,
      deviceToken: options.deviceToken,
      account: options.account,
      accountToken: options.accountToken,
      publicUrl: options.relayPublicUrl,
    };
  }

  // 2) the credentials of an earlier run
  const stored = state.relay;
  if (stored && stored.deviceId && stored.deviceToken) {
    // The credentials belong to the **account**, not to the address. When the relay is reached
    // through another address (the domain changed, the tunnel came in between), the device has
    // to keep its identity: a fresh registration would create a *second* device, and the phone
    // — which knows the old device id — would only see "device offline".
    if (stored.url !== options.relay) {
      log('info', `relay address      : ${stored.url} -> ${options.relay} (the device keeps its identity)`);
      stored.url = options.relay;
      // The public address the phone is told to use belongs to the relay, and the relay is
      // reached through another address now. A phone that pairs from now on must not be sent to
      // the old address — it would carry the raw server address around in its own storage.
      if (options.relayPublicUrl && stored.publicUrl !== options.relayPublicUrl) {
        log('info', `relay public url   : ${stored.publicUrl ?? '(none)'} -> ${options.relayPublicUrl}`);
        stored.publicUrl = options.relayPublicUrl;
      }
      state.raw.relay = stored;
      saveState(state);
    }
    log('info', `relay credentials : the account ${stored.accountId} / the device ${stored.deviceId}`);
    log('info', `relay registered  : ${new Date(stored.registeredAt ?? Date.now()).toISOString()}`);
    return {
      deviceId: stored.deviceId,
      deviceToken: stored.deviceToken,
      account: stored.accountId ?? null,
      accountToken: stored.accountToken ?? null,
      publicUrl: stored.publicUrl ?? options.relayPublicUrl,
    };
  }

  // 3) register
  if (!options.autoRegister) {
    throw new Error('--no-register was given, so the bridge did not register itself');
  }
  const url = relayRegisterUrl(options.relay, options.relayPublicUrl);
  log('info', `relay             : ${options.relay}`);
  log('info', `registering       : POST ${url}`);

  let identity = generateLocalIdentity();
  let issued = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      issued = await registerWithRelay({
        url,
        deviceName: options.relayName,
        identity,
        ca: relayCa,
      });
      break;
    } catch (error) {
      // The relay already knows this device id with another secret: start over with a new one.
      if (error?.code === 'device_conflict' && attempt === 0) {
        log('warn', 'the relay already knows this device id, a new one is generated');
        identity = generateLocalIdentity();
        continue;
      }
      throw error;
    }
  }
  if (issued === null) throw new Error('the relay did not issue any credentials');

  const credentials = {
    url: options.relay,
    accountId: issued.accountId,
    deviceId: issued.deviceId,
    deviceToken: issued.deviceToken,
    accountToken: issued.accountToken,
    publicUrl: issued.publicUrl ?? options.relayPublicUrl ?? null,
    registeredAt: issued.registeredAt ?? Date.now(),
  };
  // The credentials stay on this machine, they are never part of a config file.
  state.raw.relay = credentials;
  saveState(state);
  log('info', `registered        : the account ${credentials.accountId} / the device ${credentials.deviceId}`);
  log('info', `credentials saved : ${state.file}`);
  return {
    deviceId: credentials.deviceId,
    deviceToken: credentials.deviceToken,
    account: credentials.accountId,
    accountToken: credentials.accountToken,
    publicUrl: credentials.publicUrl,
  };
}

/** Run the bridge. */
export async function main(argv = process.argv.slice(2)) {
  // The config file comes first, the command line wins over it. The file only says *where* to
  // connect; the account, the device and the tokens are always generated on this machine.
  const configArg = findConfigPath(argv, null);
  const configPath = configArg ?? defaultConfigFile();
  let fileOptions = {};
  let configFile = null;
  try {
    const raw = loadConfigFile(configPath);
    if (Object.keys(raw).length > 0) {
      fileOptions = configToOptions(raw, configPath);
      configFile = configPath;
    } else if (configArg !== null) {
      process.stderr.write(`[bridge] ERROR the config file ${configPath} does not exist\n`);
      process.exitCode = 2;
      return null;
    }
  } catch (error) {
    process.stderr.write(`[bridge] ERROR ${error.message}\n`);
    process.exitCode = 2;
    return null;
  }

  let options;
  try {
    options = parseArgs(argv, fileOptions);
  } catch (error) {
    process.stderr.write(`[bridge] ERROR ${error.message}\n\n${USAGE}`);
    process.exitCode = 2;
    return null;
  }
  if (options.help) {
    process.stdout.write(USAGE);
    return null;
  }

  const log = makeLogger();
  if (configFile) log('info', `config file    : ${configFile}`);
  const state = loadOrCreateState(options.state);
  // The deliberate way to get the full token: it goes to stdout and the bridge does not start.
  if (options.printToken) {
    process.stdout.write(`${state.token}\n`);
    return null;
  }
  // The DSH desktop host picks a free port for itself, so the bridge looks for it when the
  // operator did not pin one down with `--dsh-url`.
  let dshUrl = options.dshUrl;
  // Only an automatically found host may be looked up again later: a desktop upgrade restarts
  // the DSH and it can come back on another port. A pinned url stays pinned.
  const dshAutoDiscovered = dshUrl === null;
  if (dshUrl === null) {
    const found = await discoverDshUrl();
    dshUrl = found ?? DEFAULT_DSH_URL;
    options.dshUrl = dshUrl;
    log('info', found
      ? `dsh host       : ${found} (found automatically)`
      : `dsh host       : ${dshUrl} (not found — is the DSH desktop application running?)`);
  }
  const dsh = new DshClient({ baseUrl: dshUrl, allowRediscovery: dshAutoDiscovered, log });
  // The version of the DSH matters for the security of the whole chain: hosts older than
  // DSH_MINIMUM_VERSION trust a forged Host header (CVE-2026-82533).
  options.dshVersion = readDshVersion();
  const pairingHost = primaryLanAddress();
  options.pairingHost = pairingHost;

  const bridge = new Bridge({ options, state, dsh, log });
  const router = new Router(createRoutes(bridge));
  const http = createBridgeServer({ bridge, router });

  await bridge.start();

  const addresses = lanAddresses();
  const urls = addresses.length > 0
    ? addresses.map((entry) => `http://${entry.address}:${options.port}`)
    : [`http://127.0.0.1:${options.port}`];

  let relay = null;
  if (options.relay) {
    // The relay opens streams towards 127.0.0.1:<port>, so the local server listens first.
    await http.listen(options.port, options.host);
    // The trust anchor of a self signed relay certificate. The certificate is still verified.
    let relayCa = null;
    if (options.relayCa) {
      try {
        relayCa = fs.readFileSync(path.resolve(options.relayCa));
      } catch (error) {
        log('error', `the relay CA file cannot be read: ${error.message}`);
        process.exitCode = 2;
        bridge.stop();
        await http.close();
        return null;
      }
    }

    // The credentials of the relay: the command line, the ones the relay issued earlier, or a
    // fresh registration. The first run of a bridge that points at a relay registers itself, so
    // the user does not have to create an account anywhere.
    let credentials;
    try {
      credentials = await resolveRelayCredentials({ options, state, log, relayCa });
    } catch (error) {
      process.stderr.write(`[bridge] ERROR the registration at the relay failed: ${error.message}\n`);
      process.stderr.write('[bridge] ERROR 没有注册上, 手机连不到你的电脑 —— 中继拒绝了这次注册。\n');
      process.stderr.write('[bridge] ERROR 请检查网络, 或者换一个中继地址, 再启动一次。\n');
      process.exitCode = 1;
      // The local server and the background jobs are already running, so they have to go down
      // again — otherwise the bridge would keep running without a relay and look like it
      // worked.
      bridge.stop();
      await http.close();
      return null;
    }
    options.deviceId = credentials.deviceId;
    options.deviceToken = credentials.deviceToken;
    if (credentials.account) options.account = credentials.account;
    if (credentials.accountToken) options.accountToken = credentials.accountToken;
    if (credentials.publicUrl && !options.relayPublicUrl) options.relayPublicUrl = credentials.publicUrl;

    // A copy that picked up a line break leaves blanks around the secret: they are trimmed here.
    options.deviceToken = trimSecret(options.deviceToken);
    if (options.accountToken) options.accountToken = trimSecret(options.accountToken);

    // A blank *inside* a token cannot be carried by the handshake: the `Sec-WebSocket-Protocol`
    // header is a comma separated list, so a space splits the secret in two and the relay reads
    // a truncated one — 401, every 30 s, forever, while the banner still says "remote ready".
    // The bridge refuses to start instead of pretending to be reachable.
    const secrets = checkRelaySecrets({
      deviceToken: options.deviceToken,
      accountToken: options.accountToken,
    });
    if (!secrets.ok) {
      process.stderr.write(`[bridge] ERROR ${secrets.reason}.\n`);
      process.stderr.write('[bridge] ERROR 令牌里混进了空格或换行 —— 复制的时候断行了。中继会一直拒绝(401)，远程就用不了。\n');
      process.stderr.write('[bridge] ERROR 去掉令牌里的空白再启动；或者干脆不传 --device-token，让桥接从本机的凭据文件里读。\n');
      process.exitCode = 2;
      bridge.stop();
      await http.close();
      return null;
    }
    if (!/^[0-9a-f]+$/iu.test(options.deviceToken)) {
      log('warn', 'the device token is not hexadecimal — the relay may reject the device');
    }

    relay = new RelayClient({
      url: options.relay,
      deviceToken: options.deviceToken,
      deviceId: options.deviceId,
      name: options.relayName,
      accountId: options.account,
      accountToken: options.accountToken,
      // The token the phone holds: the relay checks it, so that only the phone of this bridge
      // gets into the phone side of the relay.
      bridgeToken: state.token,
      targetPort: options.port,
      ca: relayCa,
      log,
    });
    relay.on('connected', () => {
      const certificate = relay.certificate();
      if (certificate === null) return;
      log('info', `relay certificate : ${certificate.subject || '(no subject)'}`);
      log('info', `relay sha256     : ${certificate.fingerprint}`);
    });
    relay.start();
    // Give the relay a moment so the banner can tell whether the device is online.
    await relay.waitForConnection(2000);
  }

  printBanner({ log, options, state, bridge, urls, relay: relay ? relay.status() : null });

  if (!options.relay) {
    await http.listen(options.port, options.host);
  }
  log('info', 'ready — the phone can connect now');

  const shutdown = async (signal) => {
    log('info', `received ${signal}, shutting down`);
    if (relay) await relay.stop();
    bridge.stop();
    await http.close();
    process.exit(0);
  };
  process.on('SIGINT', () => { void shutdown('SIGINT'); });
  process.on('SIGTERM', () => { void shutdown('SIGTERM'); });

  return { bridge, http, options, state, relay };
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main()
    .then(() => {
      // A failure sets the exit code. The connection to the DSH would keep the process alive,
      // so the exit is explicit — otherwise a bridge that could not register would look like it
      // had started.
      if (process.exitCode) process.exit(process.exitCode);
    })
    .catch((error) => {
      process.stderr.write(`[bridge] ERROR ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
      process.exit(1);
    });
}

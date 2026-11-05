// Push notifications for the HarmonyOS phone.
//
// The phone registers its Huawei Push Kit token with the bridge; from then on the bridge can
// wake the phone up when the desktop has something pending (a finished turn, a queued task that
// was picked up, a question that needs a human answer).
//
// Three rules shape this file:
//   1. **No secret is ever hard coded.** The app id, the client secret and the endpoints come
//      from the environment or from a local (git-ignored) configuration file. When they are
//      missing the notifier only logs what it would have sent.
//   2. **A push must never break the bridge.** Every failure is caught, logged and swallowed.
//   3. **The phone's token is private.** It is stored in a git-ignored file next to the bridge
//      state and never leaves the machine.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/** The Huawei Push Kit v3 endpoint; the project id is the app id. */
const DEFAULT_SEND_HOST = 'https://push-api.cloud.huawei.com';

/** The Huawei OAuth2 endpoint that exchanges the client credentials for an access token. */
const DEFAULT_TOKEN_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/token';

/** base64url without padding (the encoding every JWT uses). */
function base64Url(value) {
  return Buffer.from(value).toString('base64').replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/u, '');
}

/**
 * Mint the JWT the Push Kit v3 API expects as a bearer token.
 *
 * The token is an HS256 JWT over `{iat, exp, app_id}` signed with the client secret; the
 * Push Kit gateway validates it and looks up the app by its id.
 */
export function mintJwt(appId, secret, ttlSeconds = 3600) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64Url(JSON.stringify({ typ: 'JWT', alg: 'HS256' }));
  const payload = base64Url(JSON.stringify({ iat: now, exp: now + ttlSeconds, app_id: appId }));
  const signature = base64Url(crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest());
  return `${header}.${payload}.${signature}`;
}

/** Read a JSON file; `null` when it is missing or unparsable. */
function readJsonFile(file) {
  if (typeof file !== 'string' || file.length === 0) return null;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Resolve the push configuration.
 *
 * Every value may come from the environment (`DSH_PUSH_*`) or from a local configuration file
 * (`push.local.json` next to the bridge state, which the repository ignores). The environment
 * wins.
 */
export function loadPushConfig({ env = process.env, file = null } = {}) {
  const fromFile = readJsonFile(file) ?? {};
  const pick = (name, fileName) => {
    const value = env[name];
    if (typeof value === 'string' && value.trim().length > 0) return value.trim();
    const fallback = fromFile[fileName ?? name];
    return typeof fallback === 'string' && fallback.trim().length > 0 ? fallback.trim() : null;
  };

  const appId = pick('DSH_PUSH_APPID', 'appId');
  const secret = pick('DSH_PUSH_SECRET', 'secret');
  const tokenUrl = pick('DSH_PUSH_TOKEN_URL', 'tokenUrl');
  const sendUrl = pick('DSH_PUSH_SEND_URL', 'sendUrl')
    ?? (appId === null ? null : `${DEFAULT_SEND_HOST}/v3/${appId}/messages:send`);

  return {
    appId,
    secret,
    tokenUrl,
    sendUrl,
    // A token url alone is enough: it exchanges the credentials for a bearer token.
    enabled: appId !== null && (secret !== null || tokenUrl !== null),
  };
}

/**
 * The push tokens of the registered phones, persisted in a git-ignored file.
 *
 * The file lives next to the bridge state (`push-tokens.local.json`), so it is never part of the
 * repository even when the bridge state itself is kept inside the working tree.
 */
export class PushTokenStore {
  constructor({ file, log = () => {} } = {}) {
    this.file = file;
    this.log = log;
    this.tokens = new Map();
    this.load();
  }

  load() {
    const parsed = readJsonFile(this.file);
    const entries = Array.isArray(parsed?.tokens) ? parsed.tokens : [];
    this.tokens = new Map();
    for (const entry of entries) {
      if (typeof entry?.token === 'string' && entry.token.length > 0) {
        this.tokens.set(entry.deviceId ?? entry.token, entry);
      }
    }
  }

  save() {
    if (typeof this.file !== 'string' || this.file.length === 0) return;
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      const payload = { version: 1, updatedAt: Date.now(), tokens: [...this.tokens.values()] };
      fs.writeFileSync(this.file, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    } catch (error) {
      this.log('warn', `could not persist the push tokens: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /** Remember the token of one phone. */
  register(deviceId, token, { platform = 'harmonyos' } = {}) {
    const id = typeof deviceId === 'string' && deviceId.length > 0 ? deviceId : token;
    const entry = { deviceId: id, token, platform, updatedAt: Date.now() };
    this.tokens.set(id, entry);
    this.save();
    return entry;
  }

  /** Forget the token of one phone. */
  remove(deviceId) {
    const removed = this.tokens.delete(deviceId);
    if (removed) this.save();
    return removed;
  }

  /** Every known token string. */
  all() {
    return [...this.tokens.values()].map((entry) => entry.token);
  }

  get size() {
    return this.tokens.size;
  }
}

/**
 * Sends notifications through the Huawei Push Kit server API.
 *
 * Every method swallows its errors: a broken push configuration or an unreachable gateway must
 * never disturb the bridge.
 */
export class PushNotifier {
  constructor({ config = loadPushConfig(), store = null, log = () => {}, fetchImpl = globalThis.fetch } = {}) {
    this.config = config;
    this.store = store;
    this.log = log;
    this.fetch = fetchImpl;
    this.accessToken = null;
    this.accessTokenExpiresAt = 0;
  }

  /** The configuration as it is safe to show in a log. */
  describe() {
    return {
      enabled: this.config.enabled,
      appId: this.config.appId,
      sendUrl: this.config.sendUrl,
      tokenUrl: this.config.tokenUrl,
      registeredPhones: this.store?.size ?? 0,
    };
  }

  /** The bearer token for the Push Kit API. */
  async bearerToken() {
    if (this.config.tokenUrl !== null) {
      // A token url is asked for a fresh access token (client credentials).
      if (this.accessToken !== null && Date.now() < this.accessTokenExpiresAt) return this.accessToken;
      const body = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: this.config.appId ?? '',
        client_secret: this.config.secret ?? '',
      });
      const response = await this.fetch(this.config.tokenUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      });
      const text = await response.text();
      if (!response.ok) throw new Error(`the push token endpoint answered HTTP ${response.status}: ${text.slice(0, 200)}`);
      const parsed = JSON.parse(text);
      const token = parsed?.access_token ?? parsed?.accessToken ?? null;
      if (typeof token !== 'string' || token.length === 0) throw new Error('the push token endpoint returned no access token');
      this.accessToken = token;
      this.accessTokenExpiresAt = Date.now() + Math.max(60, (Number(parsed?.expires_in) || 3600) - 60) * 1000;
      return token;
    }
    if (this.config.secret === null) throw new Error('no push secret is configured');
    // Otherwise the gateway accepts a JWT that the app signs itself.
    return mintJwt(this.config.appId ?? '', this.config.secret);
  }

  /**
   * Send one notification to every registered phone.
   *
   * @returns {Promise<boolean>} whether the notification was handed over to the gateway.
   */
  async notify({ title, body, category = 'IM' }) {
    if (!this.config.enabled) {
      this.log('info', `push is not configured, would have sent "${title}": ${body}`);
      return false;
    }
    const tokens = this.store?.all() ?? [];
    if (tokens.length === 0) {
      this.log('debug', 'no phone has registered a push token yet');
      return false;
    }
    try {
      const bearer = await this.bearerToken();
      const payload = {
        payload: {
          notification: {
            category,
            title: String(title ?? ''),
            body: String(body ?? ''),
            clickAction: { actionType: 0 },
            foregroundShow: true,
            notifyId: Date.now(),
          },
        },
        target: { token: tokens },
        pushOptions: { ttl: 86400 },
      };
      const response = await this.fetch(this.config.sendUrl, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${bearer}`,
          'push-type': '0',
        },
        body: JSON.stringify(payload),
      });
      const text = await response.text();
      if (!response.ok) {
        this.log('warn', `the push gateway answered HTTP ${response.status}: ${text.slice(0, 200)}`);
        return false;
      }
      this.log('info', `push sent to ${tokens.length} phone(s): ${title}`);
      return true;
    } catch (error) {
      // A push is a nicety: it must never break the bridge.
      this.log('warn', `the push failed: ${error instanceof Error ? error.message : String(error)}`);
      return false;
    }
  }
}

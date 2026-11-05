// The end to end encryption between the phone and the bridge.
//
// The relay is a byte pipe: it forwards the headers and the body as they are. That is enough
// for a relay to read every message of the user — and to replay the bridge token, which would
// let it impersonate the phone. To take that away, the body of a request and the body of its
// answer travel encrypted:
//
//   X-Dsh-Seal    base64(iv(12B) || ciphertext || tag(16B))   AES-256-GCM
//   X-Dsh-Seal-Ts the timestamp (ms) the seal was made for
//
// The key is derived from the bridge token, which both sides know (the phone got it while
// pairing, the bridge has it in its state file) and which the relay never sees:
//
//   HKDF-SHA256(bridge token, salt = accountId + ':' + deviceId, info = 'dsh-harmony-seal-v1')
//
// The additional data (method + path + timestamp) is bound into the tag, so a captured seal
// cannot be moved to another endpoint or replayed outside the window of five minutes.
//
// The phone side is `harmony/entry/src/main/ets/common/Seal.ets`; it uses the same formula
// (@kit.CryptoArchitectureKit: HKDF and AES-GCM).

import crypto from 'node:crypto';

/** The header that carries the sealed body. */
export const SEAL_HEADER = 'x-dsh-seal';
/** The header that carries the timestamp of the seal. */
export const SEAL_TIMESTAMP_HEADER = 'x-dsh-seal-ts';
/** The header that carries the ids the key is derived from (`<accountId>:<deviceId>`). */
export const SEAL_ID_HEADER = 'x-dsh-seal-id';
/**
 * The header that carries the **wrapped** seal key.
 *
 * The phone keeps a random seal key (its bytes never leave the phone in the clear) and sends
 * it wrapped: the wrapping key is derived from the bridge token, so the relay cannot unwrap it.
 * The bridge opens the wrapper and uses the seal key for the bodies.
 */
export const SEAL_KEY_HEADER = 'x-dsh-seal-key';
/** The label of the derivation of the wrapping key. */
export const SEAL_WRAP_INFO = 'dsh-harmony-seal-wrap-v1';
/** The length of the derived key in bytes. */
export const SEAL_KEY_BYTES = 32;
/** The length of the nonce in bytes. */
export const SEAL_IV_BYTES = 12;
/** The length of the authentication tag in bytes. */
export const SEAL_TAG_BYTES = 16;
/** How old a seal may be (the replay window). */
export const SEAL_MAX_AGE_MS = 5 * 60 * 1000;
/** The label of the key derivation. */
export const SEAL_INFO = 'dsh-harmony-seal-v1';

/**
 * Split the ids the seal key is derived from.
 *
 * The value is `<accountId>:<deviceId>`. It is not a secret: the salt of a key derivation is
 * public, only the bridge token (the key material) is secret.
 *
 * @param {string} value the value of the header
 * @returns {{accountId: string, deviceId: string}}
 */
export function parseSealId(value) {
  const text = String(value ?? '');
  const index = text.indexOf(':');
  if (index === -1) return { accountId: '', deviceId: text };
  return { accountId: text.slice(0, index), deviceId: text.slice(index + 1) };
}

/**
 * Derive the seal key of one device.
 *
 * @param {{token: string, accountId?: string, deviceId?: string}} options the bridge token and
 *   the ids of the account and the device
 * @returns {Buffer} 32 bytes
 */
export function deriveSealKey({ token, accountId = '', deviceId = '' }) {
  if (typeof token !== 'string' || token.length === 0) {
    throw new Error('the bridge token is required for the seal');
  }
  const salt = Buffer.from(`${accountId}:${deviceId}`, 'utf8');
  return Buffer.from(crypto.hkdfSync(
    'sha256',
    Buffer.from(token, 'utf8'),
    salt,
    Buffer.from(SEAL_INFO, 'utf8'),
    SEAL_KEY_BYTES,
  ));
}

/** The additional data that is bound into the tag. */
function additionalData(method, path, timestamp) {
  return Buffer.from(`${String(method).toUpperCase()}\n${String(path)}\n${timestamp}`, 'utf8');
}

/**
 * Derive the key that wraps the seal key of the phone.
 *
 * It is derived from the bridge token, so the relay cannot unwrap the seal key of the phone.
 */
export function deriveWrapKey({ token, accountId = '', deviceId = '' }) {
  if (typeof token !== 'string' || token.length === 0) {
    throw new Error('the bridge token is required for the seal');
  }
  const salt = Buffer.from(`${accountId}:${deviceId}`, 'utf8');
  return Buffer.from(crypto.hkdfSync(
    'sha256',
    Buffer.from(token, 'utf8'),
    salt,
    Buffer.from(SEAL_WRAP_INFO, 'utf8'),
    SEAL_KEY_BYTES,
  ));
}

/**
 * Wrap the seal key of the phone for the bridge.
 *
 * @param {Buffer} wrapKey the wrapping key (derived from the bridge token)
 * @param {Buffer} sealKey the 32 bytes of the seal key of the phone
 * @param {{accountId?: string, deviceId?: string}} options the ids the key is bound to
 * @returns {string} the envelope, base64
 */
export function wrapSealKey(wrapKey, sealKey, { accountId = '', deviceId = '' } = {}) {
  const iv = crypto.randomBytes(SEAL_IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', wrapKey, iv);
  cipher.setAAD(Buffer.from(`${accountId}:${deviceId}`, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(sealKey), cipher.final()]);
  return Buffer.concat([iv, ciphertext, cipher.getAuthTag()]).toString('base64');
}

/**
 * Unwrap the seal key of the phone.
 *
 * @param {Buffer} wrapKey the wrapping key (derived from the bridge token)
 * @param {string} envelope the value of the `X-Dsh-Seal-Key` header
 * @param {{accountId?: string, deviceId?: string}} options the ids the key is bound to
 * @returns {Buffer} the 32 bytes of the seal key
 */
export function unwrapSealKey(wrapKey, envelope, { accountId = '', deviceId = '' } = {}) {
  const raw = Buffer.from(String(envelope ?? ''), 'base64');
  if (raw.length < SEAL_IV_BYTES + SEAL_TAG_BYTES) {
    throw new Error('the wrapped seal key is too short');
  }
  const iv = raw.subarray(0, SEAL_IV_BYTES);
  const tag = raw.subarray(raw.length - SEAL_TAG_BYTES);
  const ciphertext = raw.subarray(SEAL_IV_BYTES, raw.length - SEAL_TAG_BYTES);
  const decipher = crypto.createDecipheriv('aes-256-gcm', wrapKey, iv);
  decipher.setAAD(Buffer.from(`${accountId}:${deviceId}`, 'utf8'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Seal a body.
 *
 * @param {Buffer} key the derived key
 * @param {string|Buffer} body the body to protect
 * @param {{method?: string, path?: string, timestamp?: number}} options what the seal is bound to
 * @returns {{seal: string, timestamp: number}} the envelope and the timestamp
 */
export function sealBody(key, body, { method = 'GET', path = '/', timestamp = Date.now() } = {}) {
  if (!Buffer.isBuffer(key) || key.length !== SEAL_KEY_BYTES) {
    throw new Error('the seal key must be 32 bytes');
  }
  const iv = crypto.randomBytes(SEAL_IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(additionalData(method, path, timestamp));
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
  const envelope = Buffer.concat([iv, ciphertext, cipher.getAuthTag()]);
  return { seal: envelope.toString('base64'), timestamp };
}

/**
 * Open a seal.
 *
 * @param {Buffer} key the derived key
 * @param {string} envelope the value of the `X-Dsh-Seal` header
 * @param {{method?: string, path?: string, timestamp: number, now?: number, maxAgeMs?: number}} options
 *   what the seal is bound to and when it was made
 * @returns {string} the body
 */
export function unsealBody(key, envelope, {
  method = 'GET',
  path = '/',
  timestamp,
  now = Date.now(),
  maxAgeMs = SEAL_MAX_AGE_MS,
} = {}) {
  if (!Buffer.isBuffer(key) || key.length !== SEAL_KEY_BYTES) {
    throw new Error('the seal key must be 32 bytes');
  }
  if (!Number.isFinite(timestamp)) {
    throw new Error('the seal needs a timestamp');
  }
  // A replay of an old seal is refused.
  if (Math.abs(now - timestamp) > maxAgeMs) {
    throw new Error('the seal is outside the replay window');
  }
  const raw = Buffer.from(String(envelope ?? ''), 'base64');
  if (raw.length < SEAL_IV_BYTES + SEAL_TAG_BYTES) {
    throw new Error('the seal is too short');
  }
  const iv = raw.subarray(0, SEAL_IV_BYTES);
  const tag = raw.subarray(raw.length - SEAL_TAG_BYTES);
  const ciphertext = raw.subarray(SEAL_IV_BYTES, raw.length - SEAL_TAG_BYTES);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(additionalData(method, path, timestamp));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

/**
 * The headers of a sealed request or answer.
 *
 * @param {Buffer} key the derived key
 * @param {string|Buffer} body the body to protect
 * @param {{method?: string, path?: string, timestamp?: number}} options what the seal is bound to
 * @returns {Record<string, string>} the headers to add
 */
export function sealHeaders(key, body, options = {}) {
  const { seal, timestamp } = sealBody(key, body, options);
  return { [SEAL_HEADER]: seal, [SEAL_TIMESTAMP_HEADER]: String(timestamp) };
}

/**
 * Read the sealed body out of the headers of a request.
 *
 * @param {Buffer} key the derived key
 * @param {Record<string, string|string[]|undefined>} headers the headers of the request
 * @param {{method?: string, path?: string, now?: number, maxAgeMs?: number}} options
 * @returns {string|null} the body, or `null` when the request is not sealed
 */
export function readSealedBody(key, headers, { method = 'GET', path = '/', now = Date.now(), maxAgeMs = SEAL_MAX_AGE_MS } = {}) {
  const seal = header(headers, SEAL_HEADER);
  if (seal === null) return null;
  const timestamp = Number.parseInt(header(headers, SEAL_TIMESTAMP_HEADER) ?? '', 10);
  return unsealBody(key, seal, { method, path, timestamp, now, maxAgeMs });
}

/** The value of a header, whatever the node version does with the case. */
function header(headers, name) {
  if (!headers) return null;
  const value = headers[name] ?? headers[name.toLowerCase()];
  if (value === undefined || value === null) return null;
  return Array.isArray(value) ? value[0] : String(value);
}

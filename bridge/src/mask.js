// Helpers that keep secrets out of the terminal and the logs.
//
// The rule of the house: **a token or a server address never appears in full** in a log line, in
// the startup banner or in an error message. What may be shown is the shape — the first few
// characters and the last few, the rest is dots. The full token is only ever handed over on
// purpose (stderr, or `--print-token`).

/**
 * Mask a secret: keep the head and the tail, the rest becomes dots.
 *
 * @param {string} value the secret
 * @param {number} head how many characters to keep at the front
 * @param {number} tail how many characters to keep at the end
 * @returns {string} the masked form
 */
export function maskSecret(value, head = 4, tail = 4) {
  const text = String(value ?? '');
  if (text.length === 0) return '';
  if (text.length <= head + tail) return '*'.repeat(Math.max(text.length, 4));
  return `${text.slice(0, head)}******${text.slice(text.length - tail)}`;
}

/**
 * Mask one label of a host: keep the first character only.
 */
function maskHostLabel(label) {
  if (label.length === 0) return label;
  return `${label.slice(0, 1)}***`;
}

/** True when the host is an IPv4 address (every label is numeric). */
function isIpHost(host) {
  const parts = host.split('.');
  if (parts.length < 2) return false;
  return parts.every((part) => part.length > 0 && /^\d+$/.test(part));
}

/**
 * Mask a host.
 *
 * A domain keeps its top level domain (`r***.e***.com`), an IP masks every label
 * (`192.***.***.***`).
 *
 * @param {string} host the host
 * @returns {string} the masked host
 */
export function maskHost(host) {
  const text = String(host ?? '').trim();
  if (text.length === 0) return '';
  const parts = text.split('.');
  const ip = isIpHost(text);
  return parts
    .map((part, index) => (index === parts.length - 1 && !ip ? part : maskHostLabel(part)))
    .join('.');
}

/**
 * Mask one segment of a path: `acc-1a2b` becomes `acc-••••`.
 */
function maskPathSegment(segment) {
  const dash = segment.lastIndexOf('-');
  if (dash > 0 && dash < segment.length - 1) return `${segment.slice(0, dash)}-${'*'.repeat(4)}`;
  if (segment.length >= 16) return '*'.repeat(4);
  return segment;
}

/**
 * Mask a server address: the host and the account/device numbers in the path.
 *
 * `http://192.168.1.112:8788/acc-1a2b/dev-8f2a`
 *   → `http://192.***.***.***:8788/acc-••••/dev-••••`
 *
 * @param {string} endpoint the address
 * @returns {string} the masked address
 */
export function maskEndpoint(endpoint) {
  const text = String(endpoint ?? '').trim();
  if (text.length === 0) return '';
  let rest = text;
  let scheme = '';
  const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\//iu.exec(rest);
  if (schemeMatch !== null) {
    scheme = `${schemeMatch[1]}://`;
    rest = rest.slice(schemeMatch[0].length);
  }
  let query = '';
  const q = rest.indexOf('?');
  if (q >= 0) {
    query = rest.slice(q + 1);
    rest = rest.slice(0, q);
  }
  let path = '';
  const p = rest.indexOf('/');
  if (p >= 0) {
    path = rest.slice(p);
    rest = rest.slice(0, p);
  }
  let host = rest;
  let port = '';
  const colon = rest.lastIndexOf(':');
  if (colon > 0 && /^\d+$/.test(rest.slice(colon + 1))) {
    host = rest.slice(0, colon);
    port = rest.slice(colon + 1);
  }
  const maskedPath = path
    .split('/')
    .map((segment) => (segment.length === 0 ? segment : maskPathSegment(segment)))
    .join('/');
  let maskedQuery = '';
  if (query.length > 0) {
    maskedQuery = `?${query
      .split('&')
      .map((pair) => {
        const eq = pair.indexOf('=');
        if (eq < 0) return pair;
        return `${pair.slice(0, eq)}=${maskSecret(pair.slice(eq + 1))}`;
      })
      .join('&')}`;
  }
  return `${scheme}${maskHost(host)}${port.length > 0 ? `:${port}` : ''}${maskedPath}${maskedQuery}`;
}

/**
 * Wash a text that may carry secrets (an error message, a URL, a stack trace).
 *
 * This is the last line of defence: somebody who dumps a whole request object in a `catch` block
 * still does not leak the token.
 *
 * @param {unknown} text the text
 * @returns {string} the washed text
 */
export function scrubSecrets(text) {
  let out = String(text ?? '');
  out = out.replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/giu, '$1***');
  out = out.replace(/((?:account|device|bridge|access)?[Tt]oken"?\s*[:=]\s*"?)[A-Za-z0-9._~+/=-]{8,}/giu, '$1***');
  out = out.replace(/("?authorization"?\s*[:=]\s*"?)[^"',}\s]{8,}/giu, '$1***');
  out = out.replace(/\b[A-Fa-f0-9]{24,}\b/gu, '***');
  out = out.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/giu, '***');
  return out;
}

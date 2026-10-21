/**
 * AFFiNE's `appConfig` query returns the effective server configuration. The
 * tool description used to promise that secrets are masked by AFFiNE, but a
 * self-hosted 0.27.4 server returns them in clear (SMTP password, database URL,
 * signing private key). Anything that leaves this process towards a chat log
 * must therefore be redacted here, not trusted to the server.
 */
export const REDACTED = "[redacted]";

// Key names whose values are secrets. Matched case-insensitively against the
// property name only, never against the value.
const SECRET_KEY = /(^|[^a-z])(password|passwd|secret|token|apikey|api_key|privatekey|private_key|credential|authorization)([^a-z]|$)|(password|secret|token|apikey|privatekey|clientsecret|webhookkey|webhookauth)$|^key$/i;

// postgres://user:pass@host/db  ->  postgres://user:[redacted]@host/db
const URL_CREDENTIALS = /\b([a-z][a-z0-9+.-]*:\/\/[^\s:/@]+):([^\s@/]+)@/gi;

const PEM_BLOCK = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;

function redactString(value: string): string {
  return value.replace(PEM_BLOCK, REDACTED).replace(URL_CREDENTIALS, `$1:${REDACTED}@`);
}

/**
 * Returns a deep copy of `value` with secret-looking properties replaced.
 * Empty strings are kept as-is so "not configured" stays distinguishable from
 * "configured but hidden".
 */
export function redactConfig<T>(value: T, key = ""): T {
  if (typeof value === "string") {
    if (value !== "" && key && SECRET_KEY.test(key)) return REDACTED as unknown as T;
    return redactString(value) as unknown as T;
  }
  if (Array.isArray(value)) return value.map((v) => redactConfig(v, key)) as unknown as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = redactConfig(v, k);
    return out as T;
  }
  return value;
}

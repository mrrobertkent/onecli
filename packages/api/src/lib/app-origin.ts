/**
 * Structural shape of a header bag, rather than `Headers`, so that Next's
 * `ReadonlyHeaders` satisfies it without this package importing from `next/`.
 */
interface HeaderLookup {
  get(name: string): string | null | undefined;
}

/**
 * A syntactically valid `host` or `host:port` — a registered name or an IP
 * literal, optionally bracketed for IPv6.
 *
 * Header-derived origins reach `Location` headers and, on the OAuth
 * fragment-bridge path, a `<script>` block, so constraining the character set
 * here removes that injection sink for every consumer.
 */
const HOST_PATTERN = /^(?:[A-Za-z0-9._~-]+|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?$/;

/** First env var with a non-empty value, ignoring surrounding whitespace. */
const firstConfigured = (...values: (string | undefined)[]) => {
  for (const value of values) {
    const trimmed = value?.trim();
    if (trimmed) return trimmed;
  }
  return undefined;
};

/**
 * The public app URL the operator explicitly configured, or `undefined` when
 * they configured none — empty and whitespace-only values count as
 * unconfigured. Trailing slashes are stripped.
 *
 * Use this, not the `APP_URL` constant in `lib/env.ts`, to decide whether an
 * origin was configured: that constant is defaulted to localhost and so is
 * never falsy.
 */
export const configuredAppUrl = (): string | undefined =>
  firstConfigured(
    process.env.APP_URL,
    process.env.NEXT_PUBLIC_APP_URL,
  )?.replace(/\/+$/, "");

/**
 * Validate an origin that reached us as data rather than as request headers,
 * such as one signed into the OAuth state at `/authorize`.
 *
 * Returns the normalized `scheme://host[:port]`, or `undefined` for anything
 * that is not a well-formed http(s) origin. Fails soft so a bad value falls
 * through to the caller's next fallback rather than stranding the user
 * mid-connect; tampering is already ruled out by the state's HMAC.
 */
export const normalizeOrigin = (value: unknown): string | undefined => {
  if (typeof value !== "string") return undefined;
  const match = /^(https?):\/\/(.+)$/i.exec(value.trim().replace(/\/+$/, ""));
  const [, scheme, host] = match ?? [];
  // The greedy `.+` above pulls any path, query or `user:pass@` prefix into
  // `host`, where `HOST_PATTERN` rejects it.
  if (!scheme || !host || !HOST_PATTERN.test(host)) return undefined;
  return `${scheme.toLowerCase()}://${host}`;
};

/**
 * Origin (scheme + host) the client used to reach us, or `undefined` when the
 * headers carry no usable host. Trusts `X-Forwarded-Host`/`X-Forwarded-Proto`
 * and falls back to `Host`.
 *
 * `fallbackProto` applies only on the `Host` path: a forwarded host with no
 * forwarded proto stays `http`.
 */
export const originFromHeaders = (
  headers: HeaderLookup,
  fallbackProto = "http",
): string | undefined => {
  const rawProto = headers.get("x-forwarded-proto")?.split(",")[0]?.trim();
  // Only the two schemes we serve; anything else is discarded rather than
  // propagated into a redirect.
  const forwardedProto =
    rawProto === "https" || rawProto === "http" ? rawProto : undefined;

  const firstHost = (value: string | null | undefined) => {
    const host = value?.split(",")[0]?.trim();
    return host && HOST_PATTERN.test(host) ? host : undefined;
  };

  const forwardedHost = firstHost(headers.get("x-forwarded-host"));
  if (forwardedHost) return `${forwardedProto ?? "http"}://${forwardedHost}`;

  const host = firstHost(headers.get("host"));
  if (host) return `${forwardedProto ?? fallbackProto}://${host}`;

  return undefined;
};

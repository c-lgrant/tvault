// The webhook's own checks on a /v1/proxy upstream URL. The control plane names
// the URL and the header templates, and the webhook puts the credential into
// them, so the webhook must not rely on the control plane's checks alone:
//
//   - private addresses: an upstream on a loopback, private or link-local
//     address is refused unless the operator set TV_PROXY_ALLOW_PRIVATE=true;
//   - origin allowlist: when the operator set TV_PROXY_ALLOWED_ORIGINS, a
//     credential is only ever sent to an origin listed there for its service.
//
// Both are settings of the webhook. Nothing in a request can change them.

import { invalidRequest, upstreamError, upstreamNotAllowed } from "./errors.ts";
import type { RuntimeContext } from "../../runtime/context.ts";

/** Service name → allowed origins. The key "*" applies to every service. */
export type ProxyOriginAllowlist = Readonly<Record<string, readonly string[]>>;

/**
 * Parse TV_PROXY_ALLOWED_ORIGINS: a JSON object of service name → list of
 * origins (`{"github":["https://api.githubcopilot.com"],"*":["https://mcp.example.com"]}`).
 * Throws on anything else: a list that cannot be read must not mean "allow all".
 */
export function parseProxyAllowedOrigins(raw: string | undefined): ProxyOriginAllowlist | undefined {
  if (raw === undefined || raw.trim() === "") return undefined;
  const bad = (why: string) => new Error(`TV_PROXY_ALLOWED_ORIGINS is not valid: ${why}`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw bad("it is not JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw bad("it must be a JSON object");
  const out: Record<string, string[]> = Object.create(null) as Record<string, string[]>;
  for (const [service, list] of Object.entries(parsed as Record<string, unknown>)) {
    if (!Array.isArray(list)) throw bad(`the value for '${service}' must be a list of origins`);
    out[service] = list.map((entry) => {
      let url: URL | null = null;
      try {
        url = typeof entry === "string" ? new URL(entry) : null;
      } catch {
        url = null;
      }
      if (!url || (url.protocol !== "https:" && url.protocol !== "http:")) {
        throw bad(`'${service}' has an entry that is not an http(s) origin`);
      }
      return url.origin;
    });
  }
  return out;
}

/** Parse the upstream URL; only http and https are ever called. */
export function parseUpstreamUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw invalidRequest("'upstream.url' is not a valid URL");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw invalidRequest("'upstream.url' must be an http or https URL");
  }
  return url;
}

/** With an allowlist set, the origin must be listed for this service or under "*". */
export function assertOriginAllowed(allowlist: ProxyOriginAllowlist | undefined, service: string, url: URL): void {
  if (!allowlist) return;
  const own = Object.hasOwn(allowlist, service) ? allowlist[service]! : [];
  const any = Object.hasOwn(allowlist, "*") ? allowlist["*"]! : [];
  if (own.includes(url.origin) || any.includes(url.origin)) return;
  throw upstreamNotAllowed(
    "This webhook does not allow that upstream origin for this credential. Its operator can add it to TV_PROXY_ALLOWED_ORIGINS.",
  );
}

function ipv4Octets(host: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  return o.every((n) => n <= 255) ? o : null;
}

function isPrivateIpv4(o: number[]): boolean {
  const [a, b, c] = o as [number, number, number, number];
  return (
    a === 0 || // "this network"
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) || // carrier-grade NAT
    (a === 169 && b === 254) || // link-local, cloud metadata
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 198 && (b === 18 || b === 19)) || // benchmarking
    a >= 224 // multicast and reserved
  );
}

/** Eight 16-bit groups of an IPv6 address (no brackets, no zone), or null. */
function ipv6Groups(host: string): number[] | null {
  let text = host;
  // A trailing dotted IPv4 part ("::ffff:127.0.0.1") counts as two groups.
  const lastColon = text.lastIndexOf(":");
  const tail = text.slice(lastColon + 1);
  if (tail.includes(".")) {
    const v4 = ipv4Octets(tail);
    if (!v4) return null;
    text = `${text.slice(0, lastColon + 1)}${((v4[0]! << 8) | v4[1]!).toString(16)}:${((v4[2]! << 8) | v4[3]!).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const parse = (s: string): number[] | null => {
    if (s === "") return [];
    const parts = s.split(":");
    const nums = parts.map((p) => (/^[0-9a-f]{1,4}$/i.test(p) ? parseInt(p, 16) : NaN));
    return nums.some(Number.isNaN) ? null : nums;
  };
  const head = parse(halves[0]!);
  const rest = halves.length === 2 ? parse(halves[1]!) : [];
  if (!head || !rest) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;
  const fill = 8 - head.length - rest.length;
  return fill < 1 ? null : [...head, ...new Array<number>(fill).fill(0), ...rest];
}

/**
 * Everything that is not plain global unicast is private. An address that
 * carries an IPv4 address (mapped, NAT64, 6to4) is judged by that address;
 * tunnel and documentation prefixes are refused outright.
 */
function isPrivateIpv6(g: number[]): boolean {
  const embedded = (hi: number, lo: number) => isPrivateIpv4([hi >> 8, hi & 0xff, lo >> 8, lo & 0xff]);
  const zeroTo = (n: number) => g.slice(0, n).every((x) => x === 0);
  if (zeroTo(5) && g[5] === 0xffff) return embedded(g[6]!, g[7]!); // IPv4-mapped ::ffff:0:0/96
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return embedded(g[6]!, g[7]!); // NAT64 64:ff9b::/96
  if (g[0] === 0x2002) return embedded(g[1]!, g[2]!); // 6to4
  const first = g[0]!;
  // Only 2000::/3 is global unicast. That leaves out ::, ::1, IPv4-compatible,
  // 64:ff9b:1::/48, 100::/64, unique local, link-local and multicast.
  if ((first & 0xe000) !== 0x2000) return true;
  if (first === 0x2001 && g[1] === 0) return true; // Teredo 2001::/32
  if (first === 0x2001 && g[1] === 0xdb8) return true; // documentation
  return false;
}

/** Request headers that name a host other than the one in the URL. */
export function isRoutingHeader(name: string): boolean {
  const n = name.trim().toLowerCase();
  return n === "host" || n === ":authority" || n === "forwarded" || n === "x-forwarded-host";
}

/** True for an IP address (v4 or v6 text) that is not a public unicast address. */
export function isPrivateAddress(address: string): boolean {
  const v4 = ipv4Octets(address);
  if (v4) return isPrivateIpv4(v4);
  const v6 = ipv6Groups(address.replace(/^\[|\]$/g, "").replace(/%.*$/, ""));
  // Not an address at all: nothing to say here (names are judged by isPrivateHost).
  return v6 ? isPrivateIpv6(v6) : false;
}

const PRIVATE_SUFFIXES = [".localhost", ".local", ".internal", ".lan", ".home.arpa"];

/**
 * True when a URL hostname can only be a private target: an address literal in
 * a private range, `localhost`, a single-label name, or a name under a
 * private-use suffix. `URL` has already normalised the IPv4 forms (hex, octal,
 * one number), so a dotted-decimal test is enough.
 */
export function isPrivateHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (host.startsWith("[")) return isPrivateAddress(host);
  if (ipv4Octets(host)) return isPrivateAddress(host);
  if (host === "localhost" || !host.includes(".")) return true;
  return PRIVATE_SUFFIXES.some((s) => host.endsWith(s));
}

/**
 * Refuse a private upstream unless the operator allowed it. Where the runtime
 * can resolve names (Node), every address the name resolves to is checked too,
 * and a name that does not resolve is not called. The upstream call resolves
 * the name again, so a name that changes its answer between the two is not
 * caught here (the connection is not pinned to the checked address).
 */
export async function assertPublicUpstream(
  ctx: Pick<RuntimeContext, "config" | "resolveHost">,
  url: URL,
): Promise<void> {
  if (ctx.config.proxyAllowPrivate) return;
  const refuse = () =>
    upstreamNotAllowed(
      "This webhook does not call private addresses. Its operator can set TV_PROXY_ALLOW_PRIVATE=true to allow them.",
    );
  if (isPrivateHost(url.hostname)) throw refuse();
  if (!ctx.resolveHost || ipv4Octets(url.hostname) || url.hostname.startsWith("[")) return;
  let addresses: string[];
  try {
    addresses = await ctx.resolveHost(url.hostname);
  } catch {
    // A name that cannot be checked is not called.
    throw upstreamError("Upstream request failed");
  }
  if (addresses.length === 0 || addresses.some(isPrivateAddress)) throw refuse();
}

const dns = require('dns');
const net = require('net');
const http = require('http');
const https = require('https');

/**
 * @function stripHostnameBrackets
 * @description Removes surrounding brackets from IPv6 hostnames (e.g. "[::1]" → "::1").
 * @param {string} hostname
 * @returns {string}
 */
function stripHostnameBrackets(hostname) {
    if (typeof hostname !== 'string') return '';
    const trimmed = hostname.trim().toLowerCase();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
        return trimmed.slice(1, -1);
    }
    return trimmed;
}

/**
 * Non-public IPv4 ranges as [base, prefixLength].
 * Covers RFC 1918, loopback, link-local/cloud metadata, CGNAT, "this" network,
 * IETF protocol assignments, documentation (TEST-NET-1/2/3), 6to4 relay,
 * benchmarking, multicast, and the reserved/broadcast 240.0.0.0/4 block.
 */
const PRIVATE_IPV4_RANGES = [
    ['0.0.0.0', 8],
    ['10.0.0.0', 8],
    ['100.64.0.0', 10],
    ['127.0.0.0', 8],
    ['169.254.0.0', 16],
    ['172.16.0.0', 12],
    ['192.0.0.0', 24],
    ['192.0.2.0', 24],
    ['192.88.99.0', 24],
    ['192.168.0.0', 16],
    ['198.18.0.0', 15],
    ['198.51.100.0', 24],
    ['203.0.113.0', 24],
    ['224.0.0.0', 4],
    ['240.0.0.0', 4],
];

/**
 * @function parseIPv4
 * @param {string} ip
 * @returns {number|null} the address as an unsigned 32-bit integer
 */
function parseIPv4(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
        return null;
    }
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function ipv4InCidr(value, base, prefix) {
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return (value & mask) === (parseIPv4(base) & mask);
}

/**
 * @function isPrivateIPv4
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateIPv4(ip) {
    const value = parseIPv4(ip);
    if (value === null) return false;
    return PRIVATE_IPV4_RANGES.some(([base, prefix]) => ipv4InCidr(value, base, prefix));
}

/**
 * @function parseIPv6
 * @description Parses an IPv6 address (optionally with a zone id and/or an
 * embedded dotted IPv4 tail such as 64:ff9b::127.0.0.1) into eight 16-bit groups.
 * @param {string} input
 * @returns {number[]|null}
 */
function parseIPv6(input) {
    let ip = stripHostnameBrackets(input);
    const zoneIndex = ip.indexOf('%');
    if (zoneIndex !== -1) ip = ip.slice(0, zoneIndex);
    if (!net.isIPv6(ip)) return null;

    const lastColon = ip.lastIndexOf(':');
    const tail = ip.slice(lastColon + 1);
    if (tail.includes('.')) {
        const octets = tail.split('.').map(Number);
        if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
            return null;
        }
        const hi = ((octets[0] << 8) | octets[1]).toString(16);
        const lo = ((octets[2] << 8) | octets[3]).toString(16);
        ip = `${ip.slice(0, lastColon + 1)}${hi}:${lo}`;
    }

    const halves = ip.split('::');
    if (halves.length > 2) return null;

    const head = halves[0] ? halves[0].split(':') : [];
    const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    const missing = 8 - head.length - rest.length;
    if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;

    const groups = [
        ...head,
        ...Array.from({ length: halves.length === 2 ? missing : 0 }, () => '0'),
        ...rest,
    ].map((part) => parseInt(part, 16));

    if (groups.length !== 8 || groups.some((g) => !Number.isInteger(g) || g < 0 || g > 0xffff)) {
        return null;
    }
    return groups;
}

function embeddedIPv4(hi, lo) {
    return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

/**
 * @function isPrivateIPv6
 * @description Blocks loopback/unspecified, link-local, site-local, ULA,
 * multicast, documentation, discard, Teredo, and every IPv6 transition
 * mechanism (IPv4-mapped, IPv4-compatible, IPv4-translated, NAT64, 6to4) whose
 * embedded IPv4 address is non-public.
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateIPv6(ip) {
    const g = parseIPv6(ip);
    if (!g) return false;

    const upperFiveZero = g.slice(0, 5).every((x) => x === 0);

    // :: (unspecified), ::1 (loopback) and the deprecated IPv4-compatible ::/96
    if (upperFiveZero && g[5] === 0) return true;

    // ::ffff:0:0/96 IPv4-mapped
    if (upperFiveZero && g[5] === 0xffff) return isPrivateIPv4(embeddedIPv4(g[6], g[7]));

    // ::ffff:0:0:0/96 IPv4-translated (SIIT)
    if (g.slice(0, 4).every((x) => x === 0) && g[4] === 0xffff && g[5] === 0) {
        return isPrivateIPv4(embeddedIPv4(g[6], g[7]));
    }

    // 64:ff9b::/96 NAT64 well-known prefix -> check the embedded IPv4
    if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) {
        return isPrivateIPv4(embeddedIPv4(g[6], g[7]));
    }
    // 64:ff9b:1::/48 local-use NAT64
    if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 1) return true;

    // 2002::/16 6to4 -> IPv4 is encoded in groups 1 and 2
    if (g[0] === 0x2002) return isPrivateIPv4(embeddedIPv4(g[1], g[2]));

    // 2001::/32 Teredo (embeds an obfuscated IPv4 + server) and 2001:db8::/32 documentation
    if (g[0] === 0x2001 && g[1] === 0) return true;
    if (g[0] === 0x2001 && g[1] === 0x0db8) return true;

    // 100::/64 discard-only
    if (g[0] === 0x100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return true;

    // fe80::/10 link-local, fec0::/10 deprecated site-local
    if ((g[0] & 0xffc0) === 0xfe80) return true;
    if ((g[0] & 0xffc0) === 0xfec0) return true;
    // fc00::/7 unique local (ULA)
    if ((g[0] & 0xfe00) === 0xfc00) return true;
    // ff00::/8 multicast
    if ((g[0] & 0xff00) === 0xff00) return true;

    return false;
}

/**
 * @function isPrivateIP
 * @description Returns true for private, loopback, link-local, ULA, CGNAT, multicast,
 * reserved, documentation and metadata ranges (including IPv6 forms that embed them).
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateIP(ip) {
    if (typeof ip !== 'string' || !ip) return false;
    const normalized = stripHostnameBrackets(ip);

    if (net.isIPv4(normalized)) return isPrivateIPv4(normalized);
    if (net.isIPv6(normalized)) return isPrivateIPv6(normalized);
    return false;
}

/**
 * @function lookupAllAddresses
 * @param {string} hostname
 * @returns {Promise<string[]>}
 */
function lookupAllAddresses(hostname) {
    return new Promise((resolve) => {
        dns.lookup(hostname, { all: true }, (err, addrs) => {
            if (err || !Array.isArray(addrs)) {
                resolve([]);
                return;
            }
            resolve(addrs.map((entry) => entry.address));
        });
    });
}

/**
 * @function assertSafePublicHttpUrl
 * @description Ensures a URL is http(s) and does not target private/internal addresses.
 * Performs DNS resolution and re-checks every returned address.
 *
 * NOTE: this is a point-in-time check. Anything that actually connects to the
 * URL must use `safeFetchText` (which re-validates every redirect hop and pins
 * the connection to validated addresses) instead of calling `fetch` directly.
 * @param {string} urlString
 * @returns {Promise<URL>}
 */
async function assertSafePublicHttpUrl(urlString) {
    if (typeof urlString !== 'string' || !urlString.trim()) {
        throw new Error('Invalid URL');
    }

    let parsed;
    try {
        parsed = new URL(urlString.trim());
    } catch {
        throw new Error('Invalid URL');
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error('Only HTTP and HTTPS URLs are allowed');
    }

    const hostname = stripHostnameBrackets(parsed.hostname);
    if (!hostname) {
        throw new Error('Invalid URL hostname');
    }

    if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
        throw new Error('URL points to a private or internal network address');
    }

    if (net.isIP(hostname) && isPrivateIP(hostname)) {
        throw new Error('URL points to a private or internal network address');
    }

    const addresses = await lookupAllAddresses(hostname);
    if (!addresses.length && !net.isIP(hostname)) {
        throw new Error('Unable to resolve URL hostname');
    }

    for (const addr of addresses) {
        if (isPrivateIP(addr)) {
            throw new Error('URL resolves to a private or internal network address');
        }
    }

    return parsed;
}

/**
 * DNS lookup used by outbound sockets. It validates the addresses at connect
 * time and hands exactly those addresses to the socket, so a hostname cannot
 * resolve to a public IP during `assertSafePublicHttpUrl` and to an internal
 * one when the connection is made (DNS rebinding).
 */
function safeLookup(hostname, options, callback) {
    if (typeof options === 'function') {
        callback = options;
        options = {};
    }

    dns.lookup(hostname, { all: true }, (err, addrs) => {
        if (err) return callback(err);
        if (!Array.isArray(addrs) || addrs.length === 0) {
            return callback(new Error('Unable to resolve URL hostname'));
        }
        if (addrs.some((entry) => isPrivateIP(entry.address))) {
            return callback(new Error('URL resolves to a private or internal network address'));
        }
        if (options && options.all) return callback(null, addrs);
        return callback(null, addrs[0].address, addrs[0].family);
    });
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function requestOnce(parsed, { headers, timeoutMs, maxBytes }) {
    return new Promise((resolve, reject) => {
        const transport = parsed.protocol === 'https:' ? https : http;
        let settled = false;
        let timer;

        const finish = (fn, value) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            fn(value);
        };

        const req = transport.request(
            parsed,
            {
                method: 'GET',
                agent: false,
                lookup: safeLookup,
                headers: { 'Accept-Encoding': 'identity', ...headers },
            },
            (res) => {
                const status = res.statusCode || 0;
                const base = {
                    status,
                    ok: status >= 200 && status < 300,
                    headers: res.headers || {},
                    location: (res.headers && res.headers.location) || null,
                };

                if (REDIRECT_STATUSES.has(status)) {
                    res.destroy();
                    return finish(resolve, { ...base, text: '', truncated: false });
                }

                const chunks = [];
                let size = 0;

                res.on('data', (chunk) => {
                    if (settled) return;
                    size += chunk.length;
                    if (size > maxBytes) {
                        chunks.push(chunk.subarray(0, chunk.length - (size - maxBytes)));
                        res.destroy();
                        return finish(resolve, {
                            ...base,
                            text: Buffer.concat(chunks).toString('utf8'),
                            truncated: true,
                        });
                    }
                    chunks.push(chunk);
                });
                res.on('end', () =>
                    finish(resolve, {
                        ...base,
                        text: Buffer.concat(chunks).toString('utf8'),
                        truncated: false,
                    })
                );
                res.on('error', (err) => finish(reject, err));
            }
        );

        timer = setTimeout(() => {
            const err = new Error('Request timed out');
            req.destroy(err);
            finish(reject, err);
        }, Math.max(1, timeoutMs));

        req.on('error', (err) => finish(reject, err));
        req.end();
    });
}

/**
 * @function safeFetchText
 * @description SSRF-safe GET that returns at most `maxBytes` of the body as text.
 *  - every hop (initial URL and each redirect) goes through `assertSafePublicHttpUrl`;
 *  - redirects are followed manually, up to `maxRedirects`;
 *  - the socket's DNS lookup re-validates addresses at connect time (anti DNS-rebinding);
 *  - the whole exchange (all hops + body) shares a single `timeoutMs` budget;
 *  - the body is capped, so a hostile server cannot exhaust memory.
 * @param {string} urlString
 * @param {Object} [options]
 * @param {number} [options.timeoutMs=5000]
 * @param {number} [options.maxBytes=262144]
 * @param {number} [options.maxRedirects=3]
 * @param {Object} [options.headers]
 * @returns {Promise<{status:number, ok:boolean, headers:Object, text:string, truncated:boolean, url:string}>}
 */
async function safeFetchText(urlString, options = {}) {
    const { timeoutMs = 5000, maxBytes = 256 * 1024, maxRedirects = 3, headers = {} } = options;
    const deadline = Date.now() + timeoutMs;
    let current = urlString;

    for (let hop = 0; hop <= maxRedirects; hop++) {
        const parsed = await assertSafePublicHttpUrl(current);

        const remaining = deadline - Date.now();
        if (remaining <= 0) throw new Error('Request timed out');

        const response = await requestOnce(parsed, { headers, timeoutMs: remaining, maxBytes });

        if (REDIRECT_STATUSES.has(response.status) && response.location) {
            current = new URL(response.location, parsed).toString();
            continue;
        }

        return { ...response, url: parsed.toString() };
    }

    throw new Error('Too many redirects');
}

module.exports = {
    stripHostnameBrackets,
    isPrivateIP,
    assertSafePublicHttpUrl,
    safeFetchText,
    safeLookup,
};

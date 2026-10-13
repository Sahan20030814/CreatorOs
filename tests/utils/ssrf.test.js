const dns = require('dns');
const {
    isPrivateIP,
    stripHostnameBrackets,
    assertSafePublicHttpUrl,
    safeFetchText,
    safeLookup,
} = require('../../utils/ssrf');
const http = require('http');
const { PassThrough } = require('stream');
const { EventEmitter } = require('events');

describe('ssrf helpers', () => {
    describe('stripHostnameBrackets', () => {
        it('strips brackets from IPv6 hostnames', () => {
            expect(stripHostnameBrackets('[::1]')).toBe('::1');
            expect(stripHostnameBrackets('[fe80::1]')).toBe('fe80::1');
        });

        it('lowercases hostnames without brackets', () => {
            expect(stripHostnameBrackets('Example.COM')).toBe('example.com');
        });
    });

    describe('isPrivateIP', () => {
        it('blocks private and loopback IPv4 addresses', () => {
            expect(isPrivateIP('127.0.0.1')).toBe(true);
            expect(isPrivateIP('10.0.0.5')).toBe(true);
            expect(isPrivateIP('192.168.1.10')).toBe(true);
            expect(isPrivateIP('172.16.0.1')).toBe(true);
            expect(isPrivateIP('169.254.169.254')).toBe(true);
            expect(isPrivateIP('100.64.0.1')).toBe(true);
            expect(isPrivateIP('0.0.0.0')).toBe(true);
        });

        it('blocks IPv6 loopback, link-local, and ULA addresses', () => {
            expect(isPrivateIP('::1')).toBe(true);
            expect(isPrivateIP('[::1]')).toBe(true);
            expect(isPrivateIP('fe80::1')).toBe(true);
            expect(isPrivateIP('fc00::1')).toBe(true);
            expect(isPrivateIP('fd12:3456:789a::1')).toBe(true);
            expect(isPrivateIP('::ffff:127.0.0.1')).toBe(true);
            expect(isPrivateIP('::ffff:169.254.169.254')).toBe(true);
        });

        it('allows public addresses', () => {
            expect(isPrivateIP('8.8.8.8')).toBe(false);
            expect(isPrivateIP('1.1.1.1')).toBe(false);
            expect(isPrivateIP('2001:4860:4860::8888')).toBe(false);
        });
    });

    describe('assertSafePublicHttpUrl', () => {
        afterEach(() => {
            jest.restoreAllMocks();
        });

        it('rejects non-http protocols', async () => {
            await expect(assertSafePublicHttpUrl('javascript:alert(1)')).rejects.toThrow(
                /Only HTTP and HTTPS/
            );
            await expect(assertSafePublicHttpUrl('ftp://example.com/logo.png')).rejects.toThrow(
                /Only HTTP and HTTPS/
            );
        });

        it('rejects localhost and private IP literals', async () => {
            await expect(assertSafePublicHttpUrl('http://localhost/logo.png')).rejects.toThrow(
                /private or internal/
            );
            await expect(assertSafePublicHttpUrl('http://127.0.0.1/logo.png')).rejects.toThrow(
                /private or internal/
            );
            await expect(assertSafePublicHttpUrl('http://169.254.169.254/latest/meta-data/')).rejects.toThrow(
                /private or internal/
            );
            await expect(assertSafePublicHttpUrl('http://[::1]/logo.png')).rejects.toThrow(
                /private or internal/
            );
            await expect(assertSafePublicHttpUrl('http://[fe80::1]/logo.png')).rejects.toThrow(
                /private or internal/
            );
        });

        it('rejects hostnames that resolve to private addresses', async () => {
            jest.spyOn(dns, 'lookup').mockImplementation((hostname, options, callback) => {
                callback(null, [{ address: '127.0.0.1', family: 4 }]);
            });

            await expect(assertSafePublicHttpUrl('https://evil.example/logo.png')).rejects.toThrow(
                /resolves to a private/
            );
        });

        it('allows public http(s) URLs whose DNS is public', async () => {
            jest.spyOn(dns, 'lookup').mockImplementation((hostname, options, callback) => {
                callback(null, [{ address: '93.184.216.34', family: 4 }]);
            });

            await expect(assertSafePublicHttpUrl('https://example.com/logo.png')).resolves.toBeInstanceOf(URL);
        });
    });
});

describe('ssrf bypass forms', () => {
    it('blocks IPv6 transition / embedded-IPv4 forms that point at internal hosts', () => {
        [
            '::ffff:0:7f00:1', // IPv4-translated 127.0.0.1
            '64:ff9b::7f00:1', // NAT64 -> 127.0.0.1
            '64:ff9b::127.0.0.1', // NAT64, dotted tail
            '64:ff9b::a9fe:a9fe', // NAT64 -> 169.254.169.254
            '64:ff9b:1::1', // local-use NAT64
            '2002:7f00:1::', // 6to4 -> 127.0.0.1
            '2002:a9fe:a9fe::1', // 6to4 -> 169.254.169.254
            '2001:0:4136:e378:8000:63bf:3fff:fdd2', // Teredo
            '2001:db8::1', // documentation
            'fec0::1', // site-local
            'ff02::1', // multicast
            '::7f00:1', // IPv4-compatible
            'fe80::1%eth0', // zone id
        ].forEach((ip) => expect([ip, isPrivateIP(ip)]).toEqual([ip, true]));
    });

    it('blocks reserved IPv4 ranges that are not routable on the public internet', () => {
        [
            '192.0.0.1',
            '192.0.2.1',
            '198.51.100.1',
            '203.0.113.1',
            '224.0.0.1',
            '240.0.0.1',
            '255.255.255.255',
        ].forEach((ip) => expect([ip, isPrivateIP(ip)]).toEqual([ip, true]));
    });

    it('still allows genuinely public addresses, including ones embedded in transition prefixes', () => {
        [
            '8.8.8.8',
            '1.1.1.1',
            '2606:4700::1111',
            '64:ff9b::808:808', // NAT64 -> 8.8.8.8
            '2002:808:808::1', // 6to4 -> 8.8.8.8
            '::ffff:8.8.8.8',
        ].forEach((ip) => expect([ip, isPrivateIP(ip)]).toEqual([ip, false]));
    });
});

describe('safeFetchText', () => {
    const publicDns = () =>
        jest.spyOn(require('dns'), 'lookup').mockImplementation((host, options, cb) =>
            cb(null, [{ address: '93.184.216.34', family: 4 }])
        );

    function mockHttp(responses) {
        const calls = [];
        jest.spyOn(http, 'request').mockImplementation((url, options, cb) => {
            calls.push(String(url));
            const spec = responses.shift();
            const req = new EventEmitter();
            req.destroy = jest.fn();
            req.end = () => {
                const res = new PassThrough();
                res.statusCode = spec.status;
                res.headers = spec.headers || {};
                cb(res);
                setImmediate(() => {
                    (spec.chunks || []).forEach((chunk) => res.write(chunk));
                    res.end();
                });
            };
            return req;
        });
        return calls;
    }

    afterEach(() => jest.restoreAllMocks());

    it('refuses a public URL that redirects to the cloud metadata service', async () => {
        publicDns();
        const calls = mockHttp([
            { status: 302, headers: { location: 'http://169.254.169.254/latest/meta-data/' } },
        ]);

        await expect(safeFetchText('http://example.com/')).rejects.toThrow(/private or internal/);
        expect(calls).toHaveLength(1); // the internal hop was never requested
    });

    it('refuses a redirect to a hostname that resolves to an internal address', async () => {
        jest.spyOn(require('dns'), 'lookup').mockImplementation((host, options, cb) =>
            cb(null, [{ address: host === 'internal.example' ? '10.0.0.5' : '93.184.216.34', family: 4 }])
        );
        const calls = mockHttp([{ status: 301, headers: { location: 'http://internal.example/admin' } }]);

        await expect(safeFetchText('http://example.com/')).rejects.toThrow(/private or internal/);
        expect(calls).toHaveLength(1);
    });

    it('follows safe redirects (relative locations included) and returns the body', async () => {
        publicDns();
        const calls = mockHttp([
            { status: 302, headers: { location: '/final' } },
            { status: 200, headers: { 'content-type': 'text/html' }, chunks: ['<title>Hi</title>'] },
        ]);

        const res = await safeFetchText('http://example.com/start');
        expect(res.ok).toBe(true);
        expect(res.text).toBe('<title>Hi</title>');
        expect(calls).toEqual(['http://example.com/start', 'http://example.com/final']);
    });

    it('gives up after maxRedirects', async () => {
        publicDns();
        mockHttp(Array.from({ length: 5 }, () => ({ status: 302, headers: { location: '/loop' } })));

        await expect(safeFetchText('http://example.com/', { maxRedirects: 2 })).rejects.toThrow(
            /Too many redirects/
        );
    });

    it('caps the response body at maxBytes', async () => {
        publicDns();
        mockHttp([{ status: 200, chunks: ['a'.repeat(100), 'b'.repeat(100)] }]);

        const res = await safeFetchText('http://example.com/', { maxBytes: 10 });
        expect(res.truncated).toBe(true);
        expect(res.text).toBe('a'.repeat(10));
    });

    it('safeLookup rejects a name that now resolves to an internal address (DNS rebinding)', (done) => {
        jest.spyOn(require('dns'), 'lookup').mockImplementation((host, options, cb) =>
            cb(null, [{ address: '127.0.0.1', family: 4 }])
        );
        safeLookup('rebind.example', { all: true }, (err) => {
            expect(err).toBeTruthy();
            expect(err.message).toMatch(/private or internal/);
            done();
        });
    });

    it('safeLookup returns only validated addresses for public names', (done) => {
        publicDns();
        safeLookup('example.com', { all: true }, (err, addrs) => {
            expect(err).toBeNull();
            expect(addrs).toEqual([{ address: '93.184.216.34', family: 4 }]);
            done();
        });
    });
});

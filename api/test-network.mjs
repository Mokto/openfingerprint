import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { copyFile, mkdir, mkdtemp, readFile, readdir, rm, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tor, hosting, vpn, vpnServers, privatevpnServers, gluetunServers, datacenter, proxy, update, validate, loop, prune } from './update-network-data.mjs';
import { identifyEnvironment } from './test-certs.mjs';

const directory = await mkdtemp(resolve(tmpdir(), 'openfingerprint-network-check-'));
const identify = identifyEnvironment(directory);
const path = resolve(directory, 'network.json');
const binary = fileURLToPath(new URL('./target/debug/openfingerprint-api', import.meta.url));
const now = Math.floor(Date.now() / 1000);
const meta = (id, license, lifetime) => ({ id, license, license_url: 'https://example.test/license', license_text: 'test license', attribution: 'test source', url: 'https://example.test/source', revision: 'a'.repeat(64), updated_at_unix: now - 60, fetched_at_unix: now, expires_at_unix: now + lifetime });
const snapshot = {
    version: 1,
    tor: { metadata: meta('tor_exit', 'CC0-1.0', 3600), entries: ['8.8.8.8', '2606:4700:4700::1111'].map(ip => ({ ip, observed_at_unix: now - 60 })) },
    hosting: { metadata: meta('cloud_ranges', 'MIT', 86400), entries: [{ network: '8.8.8.0/24', provider: 'Test Cloud' }, { network: '2606:4700::/32', provider: 'IPv6 Cloud' }] },
    vpn: { metadata: meta('vpn_ranges', 'MIT', 86400), entries: [{ network: '8.8.8.0/25' }, { network: '2606:4700:4700::/48' }] },
    datacenter: { metadata: meta('datacenter_ranges', 'MIT', 86400), entries: [{ network: '8.8.0.0/16' }] },
    proxy: { metadata: meta('open_proxies', 'MIT', 3600), entries: [{ ip: '8.8.8.8', protocols: ['http', 'socks5'] }] },
    vpn_servers: { metadata: meta('vpn_servers', 'CC0-1.0', 86400), entries: [{ network: '1.1.1.1/32' }, { network: '2001:4860:4860::8888/128' }] },
    privatevpn_servers: { metadata: meta('privatevpn_servers', 'MIT', 86400), entries: [{ network: '193.104.211.5/32' }, { network: '2001:4860:4860::8844/128' }] }
};
const x4bLicense = "MIT License\n\nCopyright (c) 2026 X4B (Mathew Heard)\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the \"Software\"), to deal\nin the Software without restriction, including without limitation the rights\nto use, copy, modify, merge, publish, distribute, sublicense, and/or sell\ncopies of the Software, and to permit persons to whom the Software is\nfurnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all\ncopies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\nIMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\nFITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\nAUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\nLIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\nOUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\nSOFTWARE.\n";
const proxyLicense = "MIT License\n\nCopyright (c) 2022 monosans\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the \"Software\"), to deal\nin the Software without restriction, including without limitation the rights\nto use, copy, modify, merge, publish, distribute, sublicense, and/or sell\ncopies of the Software, and to permit persons to whom the Software is\nfurnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all\ncopies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\nIMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\nFITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\nAUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\nLIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\nOUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\nSOFTWARE.\n";
const servers = [];
async function start(extra = {}) {
    const env = { ...process.env };
    for (const key of ['OPENFINGERPRINT_REDIS_URL', 'OPENFINGERPRINT_REDIS_PASSWORD', 'OPENFINGERPRINT_RDAP_BOOTSTRAP', 'OPENFINGERPRINT_COUNTRY_DATA', 'OPENFINGERPRINT_NETWORK_DATA']) delete env[key];
    const child = spawn(binary, [], { env: { ...env, ...identify, OPENFINGERPRINT_REDIS_URL: 'redis://127.0.0.1:1/', OPENFINGERPRINT_LISTEN_ADDR: '127.0.0.1:0', OPENFINGERPRINT_METRICS_ADDR: '127.0.0.1:0', OPENFINGERPRINT_NETWORK_DATA: path, ...extra }, stdio: ['ignore', 'pipe', 'pipe'] });
    const server = { child, output: '' };
    servers.push(server);
    child.stderr.on('data', data => { server.output += data; });
    server.base = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Startup timeout')), 10000);
        child.once('error', () => { clearTimeout(timer); reject(new Error('Startup failed')); });
        child.once('exit', () => { clearTimeout(timer); reject(new Error('Server exited')); });
        child.stdout.on('data', data => {
            server.output += data;
            const address = /listening on (127\.0\.0\.1:\d+)/.exec(server.output);
            if (address) { clearTimeout(timer); resolve(`http://${address[1]}`); }
        });
    });
    return server;
}
async function post(server, route, body, headers = {}) {
    return fetch(server.base + route, { method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json', ...headers }, signal: AbortSignal.timeout(5000) });
}
async function check(server, ip) {
    const response = await post(server, '/v1/check', { ip, detail: true });
    assert.equal(response.status, 200);
    return (await response.json()).ip.network;
}
let phase = 'snapshot and updater';
try {
    await writeFile(path, JSON.stringify(snapshot));
    await validate(path);
    const date = new Date((now - 1800) * 1000).toISOString();
    const name = date.slice(0, 19).replace(/[T:]/g, '-');
    const observation = date.slice(0, 19).replace('T', ' ');
    const exitBody = `@type tordnsel 1.0\nExitAddress 8.8.8.8 ${observation}\nExitAddress 2606:4700:4700::1111 ${observation}\nExitAddress 9.9.9.9 2020-01-01 00:00:00\n`;
    const fetchBytes = async url => {
        if (url.endsWith('/exit-lists/')) return Buffer.from(`<a href="${name}">latest</a>`);
        if (url.endsWith(name)) return Buffer.from(exitBody);
        if (url.includes('/commits?')) return Buffer.from(JSON.stringify([{ sha: 'a'.repeat(40), commit: { committer: { date: date.replace('.000Z', 'Z') } } }]));
        if (url.endsWith('LICENSE')) return Buffer.from('unreviewed license');
        throw new Error('source unavailable');
    };
    assert.deepEqual((await tor(fetchBytes, now)).entries, [
        { ip: '2606:4700:4700::1111', observed_at_unix: now - 1800 },
        { ip: '8.8.8.8', observed_at_unix: now - 1800 }
    ]);
    const stamp = time => new Date(time * 1000).toISOString().slice(0, 19).replace('T', ' ');
    const boundary = [
        'ExitAddress 8.8.8.8 ' + stamp(now - 86399),
        'ExitAddress 8.8.8.8 ' + stamp(now - 60),
        'ExitAddress 8.8.8.8 ' + stamp(now - 120),
        'ExitAddress 1.1.1.1 ' + stamp(now - 86399),
        'ExitAddress 9.9.9.9 ' + stamp(now - 86400)
    ].join('\n');
    assert.deepEqual((await tor(async url => url.endsWith('/exit-lists/') ? fetchBytes(url) : Buffer.from(boundary), now)).entries, [
        { ip: '1.1.1.1', observed_at_unix: now - 86399 },
        { ip: '8.8.8.8', observed_at_unix: now - 60 }
    ]);
    await assert.rejects(tor(async url => url.endsWith('/exit-lists/') ? fetchBytes(url) : Buffer.from('ExitAddress invalid 2026-11-07 00:00:00'), now));
    await assert.rejects(hosting(fetchBytes, now), /license changed/);
    const listSource = (readme, files) => async url => {
        if (url.includes('/commits?')) return fetchBytes(url);
        if (url.endsWith('README.md')) return Buffer.from(readme);
        const file = Object.keys(files).find(name => url.endsWith(name));
        if (file) return Buffer.from(files[file]);
        throw new Error('source unavailable');
    };
    const readme = year => `# License\n\n\`\`\`\n${x4bLicense.replace('2026', year)}\`\`\`\n`;
    const lists = { 'vpn/ipv4.txt': '1.2.3.0/24\n1.2.4.0/24\n1.2.3.0/24\n', 'vpn/ipv6.txt': '2001:4860::/32\n', 'datacenter/ipv4.txt': '5.6.0.0/16\n', 'datacenter/ipv6.txt': '\n2a00::/12\n' };
    const vpnResult = await vpn(listSource(readme('2030'), lists), now);
    assert.deepEqual(vpnResult.entries, [{ network: '1.2.3.0/24' }, { network: '1.2.4.0/24' }, { network: '2001:4860::/32' }]);
    assert.equal(vpnResult.metadata.id, 'vpn_ranges');
    assert.equal(vpnResult.metadata.expires_at_unix - vpnResult.metadata.updated_at_unix, 7 * 86400);
    assert.deepEqual((await datacenter(listSource(readme('2026'), lists), now)).entries, [{ network: '2a00::/12' }, { network: '5.6.0.0/16' }]);
    await assert.rejects(vpn(listSource(readme('2026').replace('Permission', 'Changed'), lists), now), /license changed/);
    await assert.rejects(vpn(listSource(readme('2026'), { ...lists, 'vpn/ipv4.txt': '1.2.3.0\n' }), now), /Invalid list CIDR/);
    await assert.rejects(vpn(listSource(readme('2026'), { ...lists, 'vpn/ipv6.txt': '1.2.3.0/24\n' }), now), /Invalid list CIDR/);
    const proxyFetch = body => async url => url.includes('/commits?') ? fetchBytes(url) : url.endsWith('LICENSE') ? Buffer.from(proxyLicense) : url.endsWith('all.txt') ? Buffer.from(body) : Promise.reject(new Error('source unavailable'));
    assert.deepEqual((await proxy(proxyFetch('http://9.9.9.9:80\nsocks5://9.9.9.9:1080\nsocks4://u:p@1.1.1.1:3629\n\n'), now)).entries, [
        { ip: '1.1.1.1', protocols: ['socks4'] },
        { ip: '9.9.9.9', protocols: ['http', 'socks5'] }
    ]);
    await assert.rejects(proxy(proxyFetch('ftp://9.9.9.9:21\n'), now), /Invalid proxy entry/);
    await assert.rejects(proxy(proxyFetch('http://not-an-ip:80\n'), now), /Invalid proxy entry/);
    await assert.rejects(proxy(proxyFetch('\n'), now), /Invalid proxy count/);
    await assert.rejects(proxy(async url => url.endsWith('LICENSE') ? Buffer.from('other') : fetchBytes(url), now), /license changed/);
    const serverLicense = await readFile(new URL('./data/vpn-servers-license.txt', import.meta.url), 'utf8');
    const publication = date.slice(0, 10);
    const serverFetch = (body = '1.1.1.1\n2001:4860:4860::8888\n1.1.1.1\n', published = publication) => async url => {
        if (url.includes('/commits?')) return fetchBytes(url);
        if (url.endsWith('/LICENSE')) return Buffer.from(serverLicense);
        if (url.endsWith('/README.md')) return Buffer.from(`**Last updated:** ${published}`);
        if (url.endsWith('.txt')) return Buffer.from(body);
        throw new Error('source unavailable');
    };
    const requested = [];
    const serversResult = await vpnServers(async url => { requested.push(url); return serverFetch()(url); }, now);
    assert.equal(requested.filter(url => url.endsWith('.txt')).length, 10);
    assert.deepEqual(serversResult.entries, [{ network: '1.1.1.1/32' }, { network: '2001:4860:4860::8888/128' }]);
    assert.equal(serversResult.metadata.id, 'vpn_servers');
    assert.equal(serversResult.metadata.license, 'CC0-1.0');
    assert.equal(serversResult.metadata.updated_at_unix, Date.parse(publication + 'T00:00:00Z') / 1000);
    assert.equal(serversResult.metadata.expires_at_unix, serversResult.metadata.updated_at_unix + 7 * 86400);
    for (const body of ['1.1.1.0/24\n', 'vpn.example.test\n', 'http://1.1.1.1\n', '\n']) await assert.rejects(vpnServers(serverFetch(body), now));
    await assert.rejects(vpnServers(serverFetch(undefined, '2020-01-01'), now), /Stale\/future/);
    await assert.rejects(vpnServers(serverFetch(undefined, new Date((now + 86400) * 1000).toISOString().slice(0, 10)), now), /Future/);
    await assert.rejects(vpnServers(async url => url.endsWith('/LICENSE') ? Buffer.from('changed license') : serverFetch()(url), now), /license changed/);
    const privatevpnLicense = x4bLicense.replace('X4B (Mathew Heard)', 'Quentin McGaw');
    const privatevpnData = { version: 4, timestamp: now - 30 * 86400, servers: [{ vpn: 'openvpn', ips: ['193.104.211.5', '2001:4860:4860::8844', '193.104.211.5'] }] };
    const privatevpnFetch = (data = privatevpnData, committed = date.replace('.000Z', 'Z')) => async url => {
        if (url.includes('/commits?')) return Buffer.from(JSON.stringify([{ sha: 'a'.repeat(40), commit: { committer: { date: committed } } }]));
        assert(url.startsWith('https://raw.githubusercontent.com/qdm12/gluetun-servers/' + 'a'.repeat(40) + '/'));
        if (url.endsWith('/LICENSE')) return Buffer.from(privatevpnLicense);
        if (url.endsWith('/pkg/servers/privatevpn.json')) return Buffer.from(JSON.stringify(data));
        throw new Error('source unavailable');
    };
    const privatevpnResult = await privatevpnServers(privatevpnFetch(), now);
    assert.deepEqual(privatevpnResult.entries, [{ network: '193.104.211.5/32' }, { network: '2001:4860:4860::8844/128' }]);
    assert.equal(privatevpnResult.metadata.id, 'privatevpn_servers');
    assert.equal(privatevpnResult.metadata.license_text, privatevpnLicense);
    assert.equal(privatevpnResult.metadata.updated_at_unix, privatevpnData.timestamp);
    assert.equal(privatevpnResult.metadata.expires_at_unix, privatevpnData.timestamp + 45 * 86400);
    const oldCommit = new Date((now - 35 * 86400) * 1000).toISOString().replace('.000Z', 'Z');
    assert.equal((await privatevpnServers(privatevpnFetch(privatevpnData, oldCommit), now)).metadata.updated_at_unix, now - 35 * 86400);
    for (const bad of [
        { ...privatevpnData, version: 5 }, { ...privatevpnData, servers: [] },
        { ...privatevpnData, servers: [{ vpn: 'openvpn', ips: [] }] },
        ...['193.104.211.0/24', 'vpn.example.test', 'https://193.104.211.5', 42].map(ip => ({ ...privatevpnData, servers: [{ vpn: 'openvpn', ips: [ip] }] })),
        ...[now + 1, now - 45 * 86400, 0, '123', now - 0.5].map(timestamp => ({ ...privatevpnData, timestamp }))
    ]) await assert.rejects(privatevpnServers(privatevpnFetch(bad), now));
    await assert.rejects(privatevpnServers(privatevpnFetch(privatevpnData, new Date((now + 60) * 1000).toISOString().replace('.000Z', 'Z')), now), /timestamp/);
    await assert.rejects(privatevpnServers(async url => url.endsWith('/LICENSE') ? Buffer.from('changed license') : privatevpnFetch()(url), now), /license changed/);
    const extraProviders = [['cyberghost', 5], ['expressvpn', 2], ['purevpn', 3], ['vpnunlimited', 1, 'vpn unlimited'], ['privado', 6]];
    const gluetunData = Object.fromEntries(extraProviders.map(([provider, version, file = provider], index) => [file, { ...privatevpnData, version, servers: [{ vpn: 'openvpn', ips: [`1.1.1.${10 + index}`, `2001:4860:4860::${10 + index}`, `1.1.1.${10 + index}`] }] }]));
    const gluetunFetch = async url => {
        if (url.includes('/commits?')) return fetchBytes(url);
        if (url.endsWith('/LICENSE')) return Buffer.from(privatevpnLicense);
        const file = decodeURIComponent(url.split('/').at(-1)).replace(/\.json$/, '');
        if (gluetunData[file]) return Buffer.from(JSON.stringify(gluetunData[file]));
        return privatevpnFetch()(url);
    };
    for (const [provider, version, file = provider] of extraProviders) {
        const requested = [];
        const source = await gluetunServers(async url => { requested.push(url); return gluetunFetch(url); }, now, provider);
        assert.equal(new URL(requested[0]).searchParams.get('path'), `pkg/servers/${file}.json`);
        assert.equal(requested[2], `https://raw.githubusercontent.com/qdm12/gluetun-servers/${'a'.repeat(40)}/pkg/servers/${encodeURIComponent(file)}.json`);
        assert.equal(source.metadata.id, provider + '_servers');
        assert.equal(source.metadata.updated_at_unix, privatevpnData.timestamp);
        assert.equal(source.metadata.expires_at_unix, privatevpnData.timestamp + 45 * 86400);
        assert.equal(source.entries.length, 2);
        for (const bad of [{ ...gluetunData[file], version: version + 10 }, { ...gluetunData[file], timestamp: now + 1 }, { ...gluetunData[file], timestamp: now - 45 * 86400 }]) {
            await assert.rejects(gluetunServers(async url => url.endsWith('.json') ? Buffer.from(JSON.stringify(bad)) : gluetunFetch(url), now, provider));
        }
        snapshot[provider + '_servers'] = source;
    }
    for (const provider of ['ipvanish', 'vyprvpn', '__proto__', '../privatevpn']) await assert.rejects(gluetunServers(async () => assert.fail('Unsupported provider must not fetch'), now, provider), /Unsupported/);
    const allFetch = async url => url.includes('Joe12387/') ? serverFetch()(url) : url.includes('qdm12/gluetun-servers/') ? gluetunFetch(url) : fetchBytes(url);
    const loaded = await update(path, { fetchBytes: allFetch, now });
    for (const [provider] of extraProviders) assert(loaded.sources.includes(provider + '_servers') && !loaded.failures.includes(provider + '_servers'));
    const cyberghostRetained = JSON.parse(await readFile(path)).cyberghost_servers;
    const isolated = await update(path, { now: now + 60, fetchBytes: async url => {
        if (url.includes('cyberghost')) throw new Error('provider unavailable');
        return allFetch(url);
    } });
    assert(isolated.failures.includes('cyberghost_servers'));
    assert(!isolated.failures.includes('expressvpn_servers'));
    const independent = JSON.parse(await readFile(path));
    assert.deepEqual(independent.cyberghost_servers, cyberghostRetained);
    assert.equal(independent.expressvpn_servers.metadata.fetched_at_unix, now + 60);
    assert.equal(independent.expressvpn_servers.metadata.updated_at_unix, privatevpnData.timestamp);
    assert(loaded.sources.includes('privatevpn_servers') && !loaded.failures.includes('privatevpn_servers'));
    const privatevpnRetained = JSON.parse(await readFile(path)).privatevpn_servers;
    assert(loaded.sources.includes('vpn_servers') && !loaded.failures.includes('vpn_servers'));
    const retained = JSON.parse(await readFile(path)).vpn_servers;
    const incomplete = await update(path, { now: now + 60, fetchBytes: async url => {
        if (url.endsWith('/windscribe.txt')) throw new Error('provider unavailable');
        return url.includes('Joe12387/') ? serverFetch()(url) : fetchBytes(url);
    } });
    assert(incomplete.failures.includes('vpn_servers'));
    assert(incomplete.failures.includes('privatevpn_servers'));
    assert.deepEqual(JSON.parse(await readFile(path)).vpn_servers, retained);
    assert.deepEqual(JSON.parse(await readFile(path)).privatevpn_servers, privatevpnRetained);
    const result = await update(path, { fetchBytes, now });
    assert.deepEqual(result.failures, ['hosting', 'vpn', 'datacenter', 'proxy', 'asn', 'vpn_servers', 'privatevpn_servers', ...extraProviders.map(([provider]) => provider + '_servers')]);
    assert.deepEqual(JSON.parse(await readFile(path)).vpn_servers, retained);
    const refreshed = JSON.parse(await readFile(path));
    assert.equal(refreshed.hosting.metadata.expires_at_unix, snapshot.hosting.metadata.expires_at_unix);
    assert.equal(refreshed.tor.metadata.updated_at_unix, now - 1800);
    const previous = await readFile(path, 'utf8');
    await assert.rejects(update(path, { fetchBytes: async () => { throw new Error('offline'); }, now }));
    assert.equal(await readFile(path, 'utf8'), previous);
    await writeFile(path + '.lock', '');
    await update(path, { fetchBytes, now });
    assert.equal(await readFile(path, 'utf8'), previous);
    let calls = 0;
    await update(path, { fetchBytes, now, check: async file => { if (calls++ === 0) throw new Error('Transient validator failure'); await validate(file); } });
    assert(JSON.parse(await readFile(path)).hosting);
    const controller = new AbortController();
    let entered;
    const blocked = new Promise(resolve => { entered = resolve; });
    const running = update(path, { now, signal: controller.signal, fetchBytes: async (_url, signal) => { entered(); await new Promise((_, reject) => signal.addEventListener('abort', () => reject(new Error('Aborted')), { once: true })); } });
    const stopped = assert.rejects(running);
    await blocked;
    await assert.rejects(update(path, { fetchBytes, now }));
    controller.abort();
    await stopped;
    await update(path, { fetchBytes, now });
    assert.equal(await readFile(path, 'utf8'), previous);
    {
        const sidecar = resolve(directory, 'sidecar');
        const manifest = resolve(sidecar, 'network.json');
        await mkdir(sidecar);
        const keep = 'b'.repeat(64);
        const [old, recent, current] = ['a'.repeat(64), 'c'.repeat(64), keep].map(revision => resolve(sidecar, `asn-${revision}.mmdb`));
        const other = resolve(sidecar, 'notes.txt');
        for (const file of [old, recent, current, other]) await writeFile(file, 'x');
        await writeFile(manifest, JSON.stringify({ version: 1, asn: { revision: keep } }));
        const stale = new Date(Date.now() - 7200000);
        for (const file of [old, current, other]) await utimes(file, stale, stale);
        await prune(manifest);
        assert.deepEqual((await readdir(sidecar)).sort(), ['network.json', `asn-${'b'.repeat(64)}.mmdb`, `asn-${'c'.repeat(64)}.mmdb`, 'notes.txt'].sort());
        const stop = new AbortController();
        const runs = [];
        const looping = loop(manifest, stop.signal, { interval: 20, retry: 5, run: async () => { runs.push(Date.now()); if (runs.length === 2) stop.abort(); return { failures: [], sources: ['tor'] }; } });
        await looping;
        assert.equal(runs.length, 2);
        const missing = resolve(sidecar, 'missing/network.json');
        const gaps = [];
        const retrying = new AbortController();
        await loop(missing, retrying.signal, { interval: 100000, retry: 5, run: async () => { gaps.push(Date.now()); if (gaps.length === 3) retrying.abort(); throw new Error('offline'); } });
        assert.equal(gaps.length, 3, 'A failed first refresh must retry quickly, not after the interval');
        const afterFailure = new AbortController();
        const failures = [];
        await loop(manifest, afterFailure.signal, { interval: 5, retry: 100000, run: async () => { failures.push(Date.now()); if (failures.length === 3) afterFailure.abort(); throw new Error('offline'); } });
        assert.equal(failures.length, 3, 'A failure with an existing manifest retries on the normal interval');
    }
    const owner = spawn(process.execPath, ['--input-type=module', '-e', `import { update } from ${JSON.stringify(new URL('./update-network-data.mjs', import.meta.url).href)}; await update(${JSON.stringify(path)}, { fetchBytes: async () => { console.log('locked'); return new Promise(() => {}); } });`], { stdio: ['ignore','pipe','pipe'] });
    servers.push({ child: owner, output: '' });
    owner.stderr.resume();
    await once(owner.stdout, 'data');
    const died = once(owner, 'exit');
    owner.kill('SIGKILL');
    await died;
    let recovered = false;
    for (let attempt = 0; attempt < 20; attempt++) {
        try { await update(path, { fetchBytes, now }); recovered = true; break; }
        catch { await new Promise(resolve => setTimeout(resolve, 25)); }
    }
    assert(recovered, 'OS updater lock must recover after parent SIGKILL');
    await writeFile(path, JSON.stringify(snapshot));
    console.log('Network updater validates observed exits, license changes, retained expiry, atomic preservation and exclusive updates.');

    phase = 'stateless facts and isolation';
    const direct = await start();
    const matched = await check(direct, '8.8.8.8');
    assert.equal(matched.tor.value, true);
    assert.deepEqual(matched.hosting.value.providers, ['Test Cloud']);
    assert.equal(matched.asn.value, null);
    assert.deepEqual(matched.vpn.value, { scope: 'listed_vpn_range' });
    assert.deepEqual(matched.datacenter.value, { scope: 'listed_datacenter_range' });
    assert.deepEqual(matched.proxy.value, { protocols: ['http', 'socks5'], scope: 'listed_open_proxy' });
    assert.equal(matched.source, 'backend_supplied');
    const seeded = await check(direct, '1.1.1.1');
    assert.deepEqual(seeded.vpn.value, { scope: 'listed_vpn_server' });
    assert.equal(seeded.vpn.source.id, 'vpn_servers');
    assert.equal((await (await post(direct, '/v1/check', { ip: '1.1.1.1' })).json()).vpn, true);
    assert.equal((await (await post(direct, '/openfingerprint.v1.OpenFingerprint/Check', { ip: '1.1.1.1' }, { 'Connect-Protocol-Version': '1' })).json()).vpn, true);
    assert.equal((await check(direct, '::ffff:1.1.1.1')).vpn.value.scope, 'listed_vpn_server');
    assert.equal((await check(direct, '2001:4860:4860::8888')).vpn.value.scope, 'listed_vpn_server');
    assert.equal((await check(direct, '1.1.1.2')).vpn.value, null);
    const privatevpn = await check(direct, '193.104.211.5');
    assert.deepEqual(privatevpn.vpn.value, { scope: 'listed_vpn_server' });
    assert.equal(privatevpn.vpn.source.id, 'privatevpn_servers');
    assert.equal((await check(direct, '::ffff:193.104.211.5')).vpn.value.scope, 'listed_vpn_server');
    assert.equal((await check(direct, '2001:4860:4860::8844')).vpn.source.id, 'privatevpn_servers');
    assert.equal((await check(direct, '193.104.211.6')).vpn.value, null);
    assert.equal((await (await post(direct, '/v1/check', { ip: '193.104.211.5' })).json()).vpn, true);
    assert.equal((await (await post(direct, '/openfingerprint.v1.OpenFingerprint/Check', { ip: '193.104.211.5' }, { 'Connect-Protocol-Version': '1' })).json()).vpn, true);
    assert.equal((await check(direct, '::ffff:8.8.8.8')).tor.value, true);
    assert.equal((await check(direct, '2606:4700:4700::1111')).tor.value, true);
    const absent = await check(direct, '9.9.9.9');
    assert.equal(absent.status, 'unknown');
    assert.equal(absent.hosting.value, null);
    assert.equal(absent.tor.status, 'not_listed');
    assert.equal(absent.vpn.status, 'not_listed');
    assert.equal(absent.proxy.status, 'not_listed');
    const outside = await check(direct, '8.8.9.9');
    assert.equal(outside.vpn.value, null);
    assert.deepEqual(outside.datacenter.value, { scope: 'listed_datacenter_range' });
    assert.deepEqual((await check(direct, '2606:4700:4700::1')).vpn.value, { scope: 'listed_vpn_range' });
    assert.equal((await check(direct, '8.8.8.8:80')).status, 'invalid_input');
    assert.equal((await check(direct, '192.168.1.1')).reason, 'non_global_ip');
    for (const [index, [provider]] of extraProviders.entries()) {
        const ip = `1.1.1.${10 + index}`;
        const fact = (await check(direct, ip)).vpn;
        assert.deepEqual(fact.value, { scope: 'listed_vpn_server' });
        assert.equal(fact.source.id, provider + '_servers');
        assert.equal((await check(direct, `::ffff:${ip}`)).vpn.source.id, provider + '_servers');
        assert.equal((await check(direct, `2001:4860:4860::${10 + index}`)).vpn.source.id, provider + '_servers');
        assert.equal((await (await post(direct, '/v1/check', { ip })).json()).vpn, true);
        assert.equal((await (await post(direct, '/openfingerprint.v1.OpenFingerprint/Check', { ip }, { 'Connect-Protocol-Version': '1' })).json()).vpn, true);
    }
    assert.equal((await check(direct, '1.1.1.15')).vpn.value, null);
    const stale = structuredClone(snapshot);
    stale.tor.metadata.updated_at_unix = now - 20000;
    stale.tor.metadata.fetched_at_unix = now - 19000;
    stale.tor.metadata.expires_at_unix = now - 10000;
    stale.tor.entries = stale.tor.entries.map(({ ip }) => ({ ip, observed_at_unix: now - 20000 }));
    const stalePath = resolve(directory, 'stale.json');
    await writeFile(stalePath, JSON.stringify(stale));
    const staleServer = await start({ OPENFINGERPRINT_NETWORK_DATA: stalePath });
    const partial = await check(staleServer, '8.8.8.8');
    assert.equal(partial.tor.value, null);
    assert.equal(partial.tor.status, 'stale_data');
    assert.deepEqual(partial.hosting.value.providers, ['Test Cloud']);
    const metrics = /metrics on (127\.0\.0\.1:\d+)/.exec(direct.output)[1];
    const text = await (await fetch('http://' + metrics + '/metrics')).text();
    assert(text.includes('openfingerprint_network_data_source_fresh{source="tor_exit"} 1'));
    assert(text.includes('openfingerprint_network_data_source_fresh{source="vpn_servers"} 1'));
    assert(text.includes('openfingerprint_network_data_source_fresh{source="privatevpn_servers"} 1'));
    for (const [provider] of extraProviders) assert(text.includes(`openfingerprint_network_data_source_fresh{source="${provider}_servers"} 1`));
    assert(!text.includes('8.8.8.8'));
    const series = name => Number(new RegExp(`^${name.replace(/[{}"]/g, '\\$&')} (\\d+)$`, 'm').exec(text)?.[1]);
    assert(series('openfingerprint_http_request_duration_seconds_count{route="check",status="2xx"}') >= 1);
    assert(series('openfingerprint_check_step_duration_seconds_count{step="ip_network"}') >= 1);
    assert(series('openfingerprint_check_step_duration_seconds_count{step="ip_country"}') >= 1);
    console.log('IPv4/IPv6 facts, mapped addresses, invalid/non-global inputs, independent expiry and aggregate-only metrics passed.');

    if (process.env.OPENFINGERPRINT_TEST_NETWORK_DATA) {
        phase = 'real ASN database';
        const live = await start({ OPENFINGERPRINT_NETWORK_DATA: process.env.OPENFINGERPRINT_TEST_NETWORK_DATA });
        assert.equal((await check(live, '8.8.8.8')).asn.value.number, 15169);
        assert.equal((await check(live, '2606:4700:4700::1111')).asn.value.number, 13335);
        console.log('Real DB-IP MMDB lookups passed for IPv4 and IPv6.');
        const realPath = process.env.OPENFINGERPRINT_TEST_NETWORK_DATA;
        const real = JSON.parse(await readFile(realPath));
        const repairPath = resolve(directory, 'repair/network.json');
        await mkdir(dirname(repairPath));
        await writeFile(repairPath, JSON.stringify(real));
        const repairing = await start({ OPENFINGERPRINT_NETWORK_DATA: repairPath });
        assert.equal((await check(repairing, '8.8.8.8')).asn.status, 'invalid_data');
        const asset = `asn-${real.asn.revision}.mmdb`;
        await copyFile(resolve(dirname(realPath), asset), resolve(dirname(repairPath), asset));
        await validate(repairPath);
        console.log('Waiting for the 60-second reload to verify repaired ASN sidecars recover without a manifest edit.');
        await new Promise(resolve => setTimeout(resolve, 60000));
        const deadline = Date.now() + 15000;
        while ((await check(repairing, '8.8.8.8')).asn.value?.number !== 15169) {
            assert(Date.now() < deadline, 'Repaired ASN sidecar did not reload');
            await new Promise(resolve => setTimeout(resolve, 250));
        }
        console.log('Unchanged-manifest ASN sidecar repair and automatic reload passed.');
    }
    for (const { output } of servers) for (const value of ['8.8.8.8', '2606:4700:4700::1111']) assert(!output.includes(value));
} catch (error) {
    console.error(`Network self-check failed during ${phase}: ${error.name}. Sensitive values suppressed.`);
    console.error(error.stack?.split('\n').find(line => line.trim().startsWith('at ')) ?? '');
    process.exitCode = 1;
} finally {
    await Promise.all(servers.map(async ({ child }) => {
        if (child.exitCode !== null || child.signalCode !== null) return;
        const exited = once(child, 'exit');
        child.kill('SIGTERM');
        await exited;
    }));
    await rm(directory, { recursive: true, force: true });
}

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createHash, randomBytes } from 'node:crypto';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tor, hosting, update, validate } from './update-network-data.mjs';

const directory = await mkdtemp(resolve(tmpdir(), 'openfingerprint-network-check-'));
const path = resolve(directory, 'network.json');
const binary = fileURLToPath(new URL('./target/debug/openfingerprint-api', import.meta.url));
const now = Math.floor(Date.now() / 1000);
const secret = randomBytes(32).toString('hex');
const sites = JSON.stringify([{ id: 'network_test', secret_key: secret }]);
const meta = (id, license, lifetime) => ({ id, license, license_url: 'https://example.test/license', license_text: 'test license', attribution: 'test source', url: 'https://example.test/source', revision: 'a'.repeat(64), updated_at_unix: now - 60, fetched_at_unix: now, expires_at_unix: now + lifetime });
const snapshot = {
    version: 1,
    tor: { metadata: meta('tor_exit', 'CC0-1.0', 3600), entries: ['8.8.8.8', '2606:4700:4700::1111'] },
    hosting: { metadata: meta('cloud_ranges', 'MIT', 86400), entries: [{ network: '8.8.8.0/24', provider: 'Test Cloud' }, { network: '2606:4700::/32', provider: 'IPv6 Cloud' }] }
};
const servers = [];
async function start(extra = {}) {
    const env = { ...process.env };
    for (const key of ['OPENFINGERPRINT_REDIS_URL', 'OPENFINGERPRINT_REDIS_PASSWORD', 'OPENFINGERPRINT_RDAP_BOOTSTRAP', 'OPENFINGERPRINT_COUNTRY_DATA', 'OPENFINGERPRINT_NETWORK_DATA', 'OPENFINGERPRINT_TRUSTED_PROXIES']) delete env[key];
    const child = spawn(binary, [], { env: { ...env, OPENFINGERPRINT_REDIS_URL: 'redis://127.0.0.1:1/', OPENFINGERPRINT_SITES: sites, OPENFINGERPRINT_LISTEN_ADDR: '127.0.0.1:0', OPENFINGERPRINT_METRICS_ADDR: '127.0.0.1:0', OPENFINGERPRINT_NETWORK_DATA: path, ...extra }, stdio: ['ignore', 'pipe', 'pipe'] });
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
const auth = { Authorization: `Bearer ${secret}` };
async function post(server, route, body, headers = auth) {
    return fetch(server.base + route, { method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json', ...headers }, signal: AbortSignal.timeout(5000) });
}
async function check(server, ip) {
    const response = await post(server, '/v1/check', { ip });
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
        if (url.includes('/commits?')) return Buffer.from(JSON.stringify([{ sha: 'a'.repeat(40), commit: { committer: { date } } }]));
        if (url.endsWith('LICENSE')) return Buffer.from('unreviewed license');
        throw new Error('source unavailable');
    };
    assert.equal((await tor(fetchBytes, now)).entries.length, 2);
    await assert.rejects(tor(async url => url.endsWith('/exit-lists/') ? fetchBytes(url) : Buffer.from('ExitAddress invalid 2026-11-07 00:00:00'), now));
    await assert.rejects(hosting(fetchBytes, now), /license changed/);
    const result = await update(path, { fetchBytes, now });
    assert.deepEqual(result.failures, ['hosting', 'asn']);
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
    for (const proxies of ['["0.0.0.0/0"]', '["10.0.0.1/8"]', 'not-json']) await assert.rejects(start({ OPENFINGERPRINT_TRUSTED_PROXIES: proxies }));
    const direct = await start();
    const matched = await check(direct, '8.8.8.8');
    assert.equal(matched.tor.value, true);
    assert.deepEqual(matched.hosting.value.providers, ['Test Cloud']);
    assert.equal(matched.asn.value, null);
    assert.equal(matched.source, 'backend_supplied');
    assert.equal((await check(direct, '::ffff:8.8.8.8')).tor.value, true);
    assert.equal((await check(direct, '2606:4700:4700::1111')).tor.value, true);
    const absent = await check(direct, '9.9.9.9');
    assert.equal(absent.status, 'unknown');
    assert.equal(absent.hosting.value, null);
    assert.equal(absent.tor.status, 'not_listed');
    assert.equal((await check(direct, '8.8.8.8:80')).status, 'invalid_input');
    assert.equal((await check(direct, '192.168.1.1')).reason, 'non_global_ip');
    const stale = structuredClone(snapshot);
    stale.tor.metadata.updated_at_unix = now - 20000;
    stale.tor.metadata.fetched_at_unix = now - 19000;
    stale.tor.metadata.expires_at_unix = now - 10000;
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
    assert(!text.includes('8.8.8.8'));
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
    if (process.env.OPENFINGERPRINT_TEST_REDIS_URL) {
        phase = 'request provenance and protected action';
        const redis = { OPENFINGERPRINT_REDIS_URL: process.env.OPENFINGERPRINT_TEST_REDIS_URL };
        const untrusted = await start(redis);
        const trusted = await start({ ...redis, OPENFINGERPRINT_TRUSTED_PROXIES: '["127.0.0.1/32"]' });
        const sha = v => createHash('sha256').update(v).digest('hex');
        const components = { example: sha('network-check') };
        const signals = { version: 5, fingerprint: sha('stealth-agent:5\0' + JSON.stringify({ components: Object.entries(components), hints: [] })), coreFingerprint: null, components, hints: {}, unavailable: {}, excluded: [], durationMs: 1, automation: { version: 1 } };
        const origin = 'https://network-test.example';
        async function collect(server, forwarded, delayMs = 0) {
            const binding = randomBytes(32).toString('hex');
            const issued = await post(server, '/v1/challenges', { binding, origin });
            const { challenge } = await issued.json();
            const input = { challenge, signals, context: {} };
            const headers = { Origin: origin, ...(forwarded === null ? {} : { 'X-Forwarded-For': forwarded }) };
            assert.equal((await post(server, '/v1/collect', { ...input, ip: '8.8.8.8' }, headers)).status, 400);
            const response = await post(server, '/v1/collect', input, headers);
            assert.equal(response.status, 200);
            const publicResult = await response.json();
            assert.deepEqual(Object.keys(publicResult), ['event_id']);
            if (delayMs) await new Promise(resolve => setTimeout(resolve, delayMs));
            const event = await post(server, '/v1/events/consume', { ...publicResult, binding });
            assert.equal(event.status, 200);
            assert.equal((await post(server, '/v1/events/consume', { ...publicResult, binding })).status, 409);
            return event.json();
        }
        assert.equal((await collect(untrusted, '8.8.8.8')).ip.reason, 'non_global_ip');
        const event = await collect(trusted, 'garbage, 9.9.9.9, 8.8.8.8');
        assert.equal(event.ip.source, 'trusted_proxy');
        assert.equal(event.ip.tor.value, true);
        assert(!JSON.stringify(event).includes('8.8.8.8'));
        assert.equal((await collect(trusted, '8.8.8.8:80')).ip.reason, 'invalid_forwarded_ip');
        assert.equal((await collect(trusted, null)).ip.reason, 'forwarded_ip_unavailable');
        const expiring = structuredClone(snapshot);
        const time = Math.floor(Date.now() / 1000);
        expiring.tor.metadata.updated_at_unix = time - 1;
        expiring.tor.metadata.fetched_at_unix = time;
        expiring.tor.metadata.expires_at_unix = time + 2;
        const expiringPath = resolve(directory, 'expiring.json');
        await writeFile(expiringPath, JSON.stringify(expiring));
        const expiringServer = await start({ ...redis, OPENFINGERPRINT_TRUSTED_PROXIES: '["127.0.0.1/32"]', OPENFINGERPRINT_NETWORK_DATA: expiringPath });
        const expired = await collect(expiringServer, '8.8.8.8', 3100);
        assert.equal(expired.ip.tor.value, null);
        assert.equal(expired.ip.tor.status, 'stale_data');
        assert.deepEqual(expired.ip.hosting.value.providers, ['Test Cloud']);
        console.log('Collection ignores untrusted forwarding, walks trusted chains, rejects browser IP claims and returns single-use events without raw IP retention.');
    } else console.log('Network collection integration skipped: set OPENFINGERPRINT_TEST_REDIS_URL.');
    for (const { output } of servers) for (const value of [secret, '8.8.8.8', '2606:4700:4700::1111']) assert(!output.includes(value));
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

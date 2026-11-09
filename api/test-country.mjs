import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { refresh } from './update-country-data.mjs';

function encode(value) {
    if (Buffer.isBuffer(value)) return value;
    if (typeof value === 'string') return Buffer.concat([Buffer.from([0x40 | Buffer.byteLength(value)]), Buffer.from(value)]);
    if (typeof value === 'number') {
        const bytes = Buffer.alloc(5);
        bytes[0] = 0xc4;
        bytes.writeUInt32BE(value, 1);
        return bytes;
    }
    if (Array.isArray(value)) return Buffer.concat([Buffer.from([value.length, 4]), ...value.map(encode)]);
    return Buffer.concat([Buffer.from([0xe0 | Object.keys(value).length]), ...Object.entries(value).flatMap(([k, v]) => [encode(k), encode(v)])]);
}

function database(epoch, code = 'DK', type = 'DBIP-Country-Lite') {
    const nodes = [[null, null]];
    for (const [prefix, country] of [['00000000', code], ['0010000000000001', 'SE']]) {
        let node = 0;
        [...prefix].forEach((bit, i) => {
            if (i === prefix.length - 1) nodes[node][Number(bit)] = country;
            else {
                if (nodes[node][Number(bit)] === null) {
                    nodes[node][Number(bit)] = nodes.length;
                    nodes.push([null, null]);
                }
                node = nodes[node][Number(bit)];
            }
        });
    }
    const records = [encode({ country: { iso_code: code } }), encode({ country: { iso_code: 'SE' } })];
    const tree = Buffer.alloc(nodes.length * 6);
    nodes.forEach((children, i) => children.forEach((child, j) => {
        const pointer = child === null ? nodes.length : typeof child === 'number' ? child : nodes.length + 16 + (child === code ? 0 : records[0].length);
        tree.writeUIntBE(pointer, i * 6 + j * 3, 3);
    }));
    return Buffer.concat([tree, Buffer.alloc(16), ...records, Buffer.from('\xab\xcd\xefMaxMind.com', 'latin1'), encode({
        binary_format_major_version: Buffer.from([0xa1, 2]), binary_format_minor_version: Buffer.from([0xa0]),
        build_epoch: Buffer.concat([Buffer.from([4, 2]), encode(epoch).subarray(1)]),
        database_type: type, description: { en: 'Synthetic test data' }, ip_version: Buffer.from([0xa1, 6]),
        languages: ['en'], node_count: nodes.length, record_size: Buffer.from([0xa1, 24])
    })]);
}

process.env.OPENFINGERPRINT_COUNTRY_VALIDATOR = fileURLToPath(new URL('./target/debug/openfingerprint-api', import.meta.url));
const directory = await mkdtemp(join(tmpdir(), 'openfingerprint-country-'));
const path = join(directory, 'country.mmdb');
const now = Math.floor(Date.now() / 1000);
const bytes = database(now - 100);
const digest = createHash('sha1').update(bytes).digest('hex');
const url = 'https://download.db-ip.com/free/dbip-country-lite-2026-01.mmdb.gz';
const page = `<dt>SHA1SUM</dt><dd class="small">${digest}</dd><a href='${url}'>MMDB</a>`;
const networkPath = join(directory, 'network.json');
await writeFile(networkPath, JSON.stringify({ version: 1, tor: {
    metadata: { id: 'tor_exit', license: 'CC0-1.0', license_url: 'https://example.test/license', attribution: 'test source', url: 'https://example.test/source', revision: 'a'.repeat(64), updated_at_unix: now - 100, fetched_at_unix: now, expires_at_unix: now + 3600 },
    entries: [{ ip: '8.8.8.8', observed_at_unix: now - 100 }]
} }));
const calls = [];
const fetcher = (payload = gzipSync(bytes), html = page, headers = {}) => async (input, options) => {
    assert.equal(options.redirect, 'error');
    assert(options.signal);
    calls.push(input);
    return input === url ? new Response(payload, { headers }) : new Response(html);
};
let child;
async function start() {
    child = spawn(fileURLToPath(new URL('./target/debug/openfingerprint-api', import.meta.url)), [], {
        env: { ...process.env, OPENFINGERPRINT_LISTEN_ADDR: '127.0.0.1:0', OPENFINGERPRINT_METRICS_ADDR: '127.0.0.1:0',
            OPENFINGERPRINT_COUNTRY_DATA: path, OPENFINGERPRINT_COUNTRY_DATA_RELOAD_SECONDS: '1',
            OPENFINGERPRINT_NETWORK_DATA: networkPath, OPENFINGERPRINT_DOMAIN_DATA: join(directory, 'missing.json'),
            OPENFINGERPRINT_REDIS_URL: 'redis://127.0.0.1:1/0', OPENFINGERPRINT_REDIS_PASSWORD: undefined,
            OPENFINGERPRINT_DNS: '127.0.0.1:9' },
        stdio: ['ignore', 'pipe', 'pipe']
    });
    let output = '';
    child.stdout.on('data', b => { output += b; });
    child.stderr.on('data', b => { output += b; });
    for (let i = 0; i < 500; i++) {
        assert(child.exitCode === null, `Server exited: ${output}`);
        const api = /listening on (127\.0\.0\.1:\d+)/.exec(output);
        const metrics = /metrics on (127\.0\.0\.1:\d+)/.exec(output);
        if (api && metrics) return { api: `http://${api[1]}`, metrics: `http://${metrics[1]}` };
        await setTimeout(10);
    }
    throw new Error(`Startup timeout: ${output}`);
}
async function stop() {
    if (!child || child.exitCode !== null) return;
    const exited = new Promise(resolve => child.once('exit', resolve));
    child.kill('SIGTERM');
    await exited;
    child = null;
}
async function replace(bytes) {
    await writeFile(`${path}.tmp`, bytes);
    await rename(`${path}.tmp`, path);
}
async function check(server, ip, extra = {}) {
    const response = await fetch(`${server.api}/v1/check`, { method: 'POST',
        headers: { 'content-type': 'application/json', 'x-forwarded-for': '8.8.8.8' },
        body: JSON.stringify({ ip, detail: true, ...extra }) });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    const body = await response.json();
    if (typeof ip === 'string') assert(!JSON.stringify(body).includes(ip));
    return body;
}
async function eventually(fn) {
    for (let i = 0; i < 60; i++) { if (await fn()) return; await setTimeout(100); }
    assert.fail('Reload did not reach expected state');
}

try {
    await refresh(path, fetcher());
    assert.deepEqual(calls, ['https://db-ip.com/db/download/ip-to-country-lite', url]);
    assert.deepEqual(await readFile(path), bytes);
    for (const bad of [fetcher(Buffer.from('not gzip')), fetcher(gzipSync(Buffer.from('not MMDB'))),
        fetcher(gzipSync(bytes), page.replace(digest, '0'.repeat(40))), fetcher(gzipSync(bytes), '<html/>'),
        fetcher(gzipSync(bytes), page, { 'content-length': String(33 * 1024 * 1024) }),
        async () => new Response('', { status: 503 }),
        fetcher(gzipSync(bytes), page.replace('download.db-ip.com', 'attacker.test'))]) {
        await assert.rejects(refresh(path, bad));
        assert.deepEqual(await readFile(path), bytes);
    }
    const corrupt = Buffer.from(bytes);
    corrupt.writeUIntBE(0xffffff, 0, 3);
    for (const candidate of [corrupt, database(now + 3600), database(now - 200),
        database(now - 63 * 86400), database(now, 'DK', 'Wrong-Database')]) {
        const checksum = createHash('sha1').update(candidate).digest('hex');
        await assert.rejects(refresh(path, fetcher(gzipSync(candidate), page.replace(digest, checksum))));
        assert.deepEqual(await readFile(path), bytes);
    }
    await assert.rejects(refresh(path, async input => input === url
        ? new Response(new ReadableStream({ start(controller) {
            controller.enqueue(Buffer.alloc(17 * 1024 * 1024));
            controller.enqueue(Buffer.alloc(17 * 1024 * 1024));
            controller.close();
        } })) : new Response(page)));
    await assert.rejects(refresh(path, fetcher(gzipSync(Buffer.alloc(33 * 1024 * 1024)))));
    const timeout = AbortSignal.timeout;
    AbortSignal.timeout = () => {
        const controller = new AbortController();
        setTimeout(10).then(() => controller.abort(new Error('Fixture timeout')));
        return controller.signal;
    };
    try {
        await assert.rejects(refresh(path, async (input, { signal }) => input === url
            ? new Response(new ReadableStream({ start(controller) {
                signal.addEventListener('abort', () => controller.error(signal.reason));
            } })) : new Response(page)));
    } finally {
        AbortSignal.timeout = timeout;
    }
    assert.deepEqual(await readFile(path), bytes);
    let server = await start();
    const expected = (await check(server, '8.8.8.8')).ip;
    assert.equal(expected.status, 'ok', JSON.stringify(expected));
    assert.equal(expected.countryCode, 'DK');
    assert.equal(expected.network.tor.value, true);
    assert.equal(expected.network.source, 'backend_supplied');
    assert.equal(expected.source.license, 'CC-BY-4.0');
    assert.equal(expected.source.updatedAtUnix, now - 100);
    assert.equal(expected.source.expiresAtUnix, now - 100 + 62 * 86400);
    assert.equal(expected.source.sha256, createHash('sha256').update(bytes).digest('hex'));
    assert.deepEqual((await check(server, '::ffff:8.8.8.8')).ip, expected);
    assert.equal((await check(server, '2001:4860::8888')).ip.countryCode, 'SE');
    const compact = await check(server, '2001:4860::8888', { detail: false });
    assert.equal(compact.country, 'se');
    assert(!('ip' in compact) && !('countryCode' in compact) && !('source' in compact));
    assert.equal((await check(server, '2606:4700::1111')).ip.reason, 'not_found');
    for (const ip of ['127.0.0.1', '192.0.2.1', '10.0.0.1', '100.64.0.1', '::1', 'fe80::1', '2001:db8::1', '::ffff:10.0.0.1']) {
        const result = (await check(server, ip)).ip;
        assert.equal(result.status, 'unknown');
        assert.equal(result.reason, 'non_public_ip');
        assert(!('countryCode' in result));
    }
    for (const ip of ['8.8.8.8:80', '[::1]', 'fe80::1%eth0', '8.8.8.0/24', true, []]) {
        assert.equal((await check(server, ip)).ip.reason, 'invalid_ip');
    }
    const mixed = await check(server, '8.8.8.8', { domain: 'not a domain', signals: {} });
    assert.deepEqual(mixed.ip, expected);
    assert.equal(mixed.domain.status, 'invalid_input');
    assert.equal(mixed.signals.status, 'invalid_input');
    await replace(Buffer.from('broken'));
    await eventually(async () => (await (await fetch(`${server.metrics}/metrics`)).text()).includes('openfingerprint_country_data_reload_failures_total 1\n'));
    assert.deepEqual((await check(server, '8.8.8.8')).ip, expected);
    await replace(database(now - 200, 'US'));
    await eventually(async () => (await (await fetch(`${server.metrics}/metrics`)).text()).includes('openfingerprint_country_data_reload_failures_total 2\n'));
    assert.deepEqual((await check(server, '8.8.8.8')).ip, expected);
    await replace(database(now - 50, 'US'));
    await eventually(async () => (await check(server, '8.8.8.8')).ip.countryCode === 'US');
    await rm(path);
    await eventually(async () => (await (await fetch(`${server.metrics}/metrics`)).text()).includes('openfingerprint_country_data_reload_failures_total 3\n'));
    assert.equal((await check(server, '8.8.8.8')).ip.countryCode, 'US');
    await stop();
    for (const [fixture, reason] of [
        [database(now - 63 * 86400), 'stale_data'], [database(now + 3600), 'unavailable'],
        [database(now, 'DK', 'Wrong-Database'), 'unavailable'], [Buffer.from('broken'), 'unavailable'],
        [database(now, 'ZZ'), 'not_found'], [database(now, 'AA'), 'not_found'], [database(now, 'EU'), 'not_found']
    ]) {
        await replace(fixture);
        server = await start();
        const result = (await check(server, '8.8.8.8')).ip;
        assert.equal(result.status, 'unknown');
        assert.equal(result.reason, reason);
        assert(!('countryCode' in result));
        assert.equal(result.network.tor.value, true);
        await stop();
    }
    await rm(path);
    server = await start();
    assert.equal((await check(server, '8.8.8.8')).ip.reason, 'unavailable');
    await replace(bytes);
    await eventually(async () => (await check(server, '8.8.8.8')).ip.countryCode === 'DK');
    console.log('Country updater integrity, IPv4/IPv6, special-use ranges, provenance, expiry, isolation and live reload checks passed.');
} finally {
    await stop();
    await rm(directory, { recursive: true, force: true });
}

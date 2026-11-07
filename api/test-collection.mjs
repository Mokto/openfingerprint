import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const redis = process.env.OPENFINGERPRINT_TEST_REDIS_URL;
if (!redis) {
    console.log('Collection integration skipped: set OPENFINGERPRINT_TEST_REDIS_URL to a disposable Redis database.');
    process.exit(0);
}
const token = () => randomBytes(32).toString('hex');
const sites = [{ id: 'collection_test_a', secret_key: token() }, { id: 'collection_test_b', secret_key: token() }];
const servers = [];
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const ttl = 3000;
let phase = 'startup';
async function start(redisUrl = redis) {
    const child = spawn(fileURLToPath(new URL('./target/debug/openfingerprint-api', import.meta.url)), [], {
        env: {
            ...process.env,
            OPENFINGERPRINT_LISTEN_ADDR: '127.0.0.1:0',
            OPENFINGERPRINT_SITES: JSON.stringify(sites),
            OPENFINGERPRINT_REDIS_URL: redisUrl,
            OPENFINGERPRINT_COLLECTION_TTL_SECONDS: String(ttl / 1000),
            OPENFINGERPRINT_COLLECTION_CAPACITY: '8',
            OPENFINGERPRINT_DOMAIN_DATA: '/nonexistent/collection-test-snapshot',
            OPENFINGERPRINT_METRICS_ADDR: '127.0.0.1:0'
        },
        stdio: ['ignore', 'pipe', 'pipe']
    });
    const server = { child, output: '' };
    servers.push(server);
    child.stderr.on('data', data => { server.output += data; });
    server.base = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Startup timeout')), 10000);
        child.once('error', () => { clearTimeout(timer); reject(new Error('Startup failed')); });
        child.once('exit', () => { clearTimeout(timer); reject(new Error('Server exited')); });
        child.stdout.on('data', data => {
            server.output += data;
            const match = /listening on (127\.0\.0\.1:\d+)/.exec(server.output);
            if (match) { clearTimeout(timer); resolve(`http://${match[1]}`); }
        });
    });
    return server;
}
const auth = site => ({ Authorization: `Bearer ${site.secret_key}` });
async function post(server, path, body, headers = {}) {
    const response = await fetch(server.base + path, {
        method: 'POST', headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body), signal: AbortSignal.timeout(5000)
    });
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('set-cookie'), null);
    assert.equal(response.headers.get('access-control-allow-origin'), null);
    return response;
}
const sha = value => createHash('sha256').update(value).digest('hex');
const components = { fontPreferences: sha('collection-fixture') };
const signals = {
    version: 5,
    fingerprint: sha('stealth-agent:5\0' + JSON.stringify({ components: Object.entries(components), hints: [] })),
    coreFingerprint: null, components, hints: {}, unavailable: {}, excluded: [], durationMs: 1,
    automation: { version: 1, webdriver: false, headlessUserAgent: false, seleniumArtifacts: false, phantomArtifacts: false }
};
const origin = 'https://collection.example.test';
const privateUa = `Mozilla/5.0 HeadlessChrome/156.0.0.0 collection-private-${token()}`;
const browserHeaders = { Origin: origin, 'User-Agent': privateUa, 'Sec-CH-UA-Platform': '"Windows"' };
const body = challenge => ({ challenge, signals, context: { userAgent: 'Chrome/156', platform: 'MacIntel' } });
async function issue(server, binding = token(), site = sites[0]) {
    const response = await post(server, '/v1/challenges', { binding, origin }, auth(site));
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.match(result.challenge, /^[0-9a-f]{64}$/);
    assert.equal(result.expires_in_ms, ttl);
    return { challenge: result.challenge, binding };
}
async function publish(server, challenge) {
    const response = await post(server, '/v1/collect', body(challenge), browserHeaders);
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.deepEqual(Object.keys(result), ['event_id']);
    assert.match(result.event_id, /^[0-9a-f]{64}$/);
    return result.event_id;
}
try {
    await assert.rejects(start('rediss://secret:private@localhost:6379/#insecure'));
    await assert.rejects(start('redis+unix:///tmp/collection-not-supported.sock'));
    const a = await start();
    const b = await start();
    phase = 'authentication and input boundaries';
    for (const path of ['/v1/challenges', '/v1/events/consume']) {
        assert.equal((await post(a, path, {})).status, 401);
        assert.equal((await post(a, path, {}, { ...auth(sites[0]), Origin: origin })).status, 403);
    }
    for (const input of [
        { binding: token(), origin: 'http://example.test' },
        { binding: 'session-id', origin },
        { binding: token(), origin: origin + '/' },
        { binding: token(), origin, extra: true }
    ]) assert.equal((await post(a, '/v1/challenges', input, auth(sites[0]))).status, 400);
    const issued = await issue(a);
    for (const headers of [{}, { ...browserHeaders, Origin: 'https://wrong.test' },
        { ...browserHeaders, Cookie: 'session=private' }, { ...browserHeaders, ...auth(sites[0]) }]) {
        assert.equal((await post(a, '/v1/collect', body(issued.challenge), headers)).status, 403);
    }
    for (const input of [
        { ...body(issued.challenge), extra: true },
        { ...body(issued.challenge), signals: { ...signals, fingerprint: token() } },
        { ...body(issued.challenge), signals: { ...signals, automation: null } },
        { ...body(issued.challenge), signals: { ...signals, automation: { version: 2 } } },
        { ...body(issued.challenge), context: { userAgent: 'x'.repeat(513) } },
        { ...body(issued.challenge), context: { platform: false } },
        { ...body(issued.challenge), challenge: 'bad' }
    ]) assert.equal((await post(a, '/v1/collect', input, browserHeaders)).status, 400);
    assert.equal((await post(a, '/v1/collect', { ...body(issued.challenge), padding: 'x'.repeat(65536) }, browserHeaders)).status, 413);
    assert.equal((await post(a, '/v1/collect', body(token()), browserHeaders)).status, 409);
    console.log('Collection authentication, origin, credential, schema and body boundaries passed.');

    phase = 'atomic publication across replicas';
    const published = await Promise.all(Array.from({ length: 12 }, (_, i) => post(i % 2 ? a : b, '/v1/collect', body(issued.challenge), browserHeaders)));
    assert.equal(published.filter(r => r.status === 200).length, 1);
    assert.equal(published.filter(r => r.status === 409).length, 11);
    const eventId = (await published.find(r => r.status === 200).json()).event_id;
    assert.equal((await post(b, '/v1/events/consume', { event_id: eventId, binding: token() }, auth(sites[0]))).status, 409);
    assert.equal((await post(b, '/v1/events/consume', { event_id: eventId, binding: issued.binding }, auth(sites[1]))).status, 409);
    const consumed = await Promise.all(Array.from({ length: 12 }, (_, i) => post(i % 2 ? a : b, '/v1/events/consume', { event_id: eventId, binding: issued.binding }, auth(sites[0]))));
    assert.equal(consumed.filter(r => r.status === 200).length, 1);
    assert.equal(consumed.filter(r => r.status === 409).length, 11);
    const event = await consumed.find(r => r.status === 200).json();
    assert.equal(event.event_id, eventId);
    assert.equal(event.signals.fingerprint, signals.fingerprint);
    assert.equal(event.signals.automation.status, 'detected');
    assert.deepEqual(event.signals.automation.indicators, ['headless_user_agent']);
    assert.deepEqual(event.signals.automation.unavailable_probes, []);
    assert.deepEqual(event.consistency.indicators, ['user_agent_mismatch', 'platform_mismatch']);
    assert.deepEqual(event.consistency.unavailable_checks, []);
    assert.equal(event.request.headless_user_agent, true);
    assert.equal(event.expires_at_unix_ms - event.created_at_unix_ms, ttl);
    assert(!JSON.stringify(event).includes(privateUa));
    assert(!('binding' in event));
    assert.equal((await post(a, '/v1/collect', body(issued.challenge), browserHeaders)).status, 409);
    console.log('Cross-replica single-use challenges/events, tenant/action binding and server-derived checks passed.');

    phase = 'unknown evidence and absent client hints';
    const unknown = await issue(a);
    const unknownBody = { challenge: unknown.challenge, signals: { ...signals, automation: { version: 1 } }, context: {} };
    const unknownResponse = await post(a, '/v1/collect', unknownBody, { Origin: origin, 'User-Agent': '' });
    assert.equal(unknownResponse.status, 200);
    const unknownId = (await unknownResponse.json()).event_id;
    const unknownEvent = await post(b, '/v1/events/consume', { event_id: unknownId, binding: unknown.binding }, auth(sites[0]));
    const unknownResult = await unknownEvent.json();
    assert.equal(unknownResult.signals.automation.status, 'unknown');
    assert.equal(unknownResult.consistency.status, 'unknown');

    phase = 'expiration and bounded capacity';
    const expires = await issue(a);
    const expiresEvent = await issue(a);
    const expiresId = await publish(b, expiresEvent.challenge);
    await sleep(ttl + 150);
    assert.equal((await post(a, '/v1/collect', body(expires.challenge), browserHeaders)).status, 409);
    assert.equal((await post(b, '/v1/events/consume', { event_id: expiresId, binding: expiresEvent.binding }, auth(sites[0]))).status, 409);
    const capacity = await Promise.all(Array.from({ length: 9 }, () => post(a, '/v1/challenges', { binding: token(), origin }, auth(sites[0]))));
    assert.equal(capacity.filter(r => r.status === 200).length, 8);
    assert.equal(capacity.filter(r => r.status === 429).length, 1);
    console.log('Missing observations remain unknown; expiration and per-site capacity checks passed.');

    phase = 'Redis failure and stateless isolation';
    const unavailable = await start('redis://127.0.0.1:1/');
    assert.equal((await post(unavailable, '/v1/challenges', { binding: token(), origin }, auth(sites[0]))).status, 503);
    const check = await post(unavailable, '/v1/check', { signals }, auth(sites[0]));
    assert.equal(check.status, 200);
    assert.equal((await check.json()).signals.fingerprint, signals.fingerprint);
    for (const server of servers) {
        for (const secret of ['secret:private', privateUa, signals.fingerprint, ...sites.map(s => s.secret_key), issued.challenge, issued.binding, eventId]) {
            assert(!server.output.includes(secret));
        }
    }
    console.log('Redis failure is closed without breaking stateless checks; request evidence and credentials are not logged.');
} catch {
    console.error(`Collection self-check failed during: ${phase}. Sensitive values suppressed.`);
    process.exitCode = 1;
} finally {
    await Promise.all(servers.map(async ({ child }) => {
        if (child.exitCode !== null) return;
        const exited = once(child, 'exit');
        child.kill('SIGTERM');
        await exited;
    }));
}

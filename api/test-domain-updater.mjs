import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { domains, monitoredDomains, download, snapshot, update, unprotected, publish, kubernetes } from './update-domain-data.mjs';

assert.deepEqual(domains('# note\nMAIL.example\nmail.example\nbücher.example\n'), ['mail.example', 'xn--bcher-kva.example']);
for (const value of ['', 'https://example.test', 'bad..example', 'example.test/path', `example.test${String.fromCharCode(92)}evil`, String.fromCharCode(1) + 'example.test', 'example.test' + String.fromCharCode(0), '*.example.test', '192.0.2.1', 'x'.repeat(64) + '.example']) {
    assert.throws(() => domains(value));
}
const bundled = JSON.parse(await readFile(new URL('./data/domains.json', import.meta.url), 'utf8'));
const now = Math.floor(Date.now() / 1000);
const feed = () => ({ version: 1, t: now, domains: {
    'recent.example': { provider: 'provider.example', firstseen: now - 30 * 86400, lastseen: now - 86400 },
    'boundary.example': { provider: 'provider.example', firstseen: now - 30 * 86400, lastseen: now - 14 * 86400 },
    'old.example': { provider: 'provider.example', firstseen: now - 30 * 86400, lastseen: now - 14 * 86400 - 1 }
} });
assert.deepEqual(monitoredDomains(JSON.stringify(feed()), now), ['boundary.example', 'recent.example']);
for (const change of [
    d => { d.version = 2; },
    d => { d.t = now - 3 * 86400 - 1; },
    d => { d.t = now + 301; },
    d => { d.domains = []; },
    d => { d.domains = {}; },
    d => { d.domains['recent.example'].provider = null; },
    d => { d.domains['recent.example'].firstseen = now; },
    d => { d.domains['recent.example'].lastseen = 'yesterday'; },
    d => { d.domains['recent.example'].lastseen = now + 301; },
    d => { d.domains['RECENT.example'] = d.domains['recent.example']; },
    d => { d.domains['https://bad.example'] = d.domains['recent.example']; },
    d => { d.domains['old.example'].firstseen = -1; }
]) {
    const d = feed(); change(d);
    assert.throws(() => monitoredDomains(JSON.stringify(d), now));
}
for (const invalid of ['{', 'null', '[]', '"not a feed"']) assert.throws(() => monitoredDomains(invalid, now));
assert.throws(() => monitoredDomains(JSON.stringify(feed()), now + 15 * 86400));
const allOld = feed();
for (const observation of Object.values(allOld.domains)) observation.lastseen = now - 20 * 86400;
assert.throws(() => monitoredDomains(JSON.stringify(allOld), now));
async function publicSource(url) {
    if (url.includes('api.github.com/')) return JSON.stringify({ sha: 'a'.repeat(40), commit: { committer: { date: new Date((now - 60) * 1000).toISOString() } } });
    if (url.includes('7c/fakefilter/')) return url.endsWith('LICENSE.md') ? bundled.sources.find(s => s.id === 'fakefilter_recent').license_text : JSON.stringify(feed());
    if (url.includes('disposable-email-domains/')) return url.endsWith('LICENSE.txt') ? bundled.sources.find(s => s.id === 'disposable_email_domains').license_text : 'mail.example\n';
    if (url.includes('matomo-org/')) return url.endsWith('README.md') ? '## License\nPublic Domain (no copyright).' : 'spam.example\n';
    const id = url.includes('is-a-dev/') ? 'is_a_dev' : 'is_a_bot';
    return url.endsWith('LICENSE') ? bundled.sources.find(s => s.id === id).license_text : (id === 'is_a_dev' ? 'is-a.dev' : 'is-a.bot');
}
const result = JSON.parse(await snapshot(publicSource, now));
assert.equal(result.sources.length, 9);
for (const s of result.sources) {
    assert.equal(createHash('sha256').update(s.license_text).digest('hex'), s.license_sha256);
    assert(s.expires_at_unix > s.fetched_at_unix);
}
assert.equal(result.sources.find(s => s.id === 'fakefilter_recent').license, 'BSD-3-Clause');
assert.deepEqual(result.sources.find(s => s.id === 'fakefilter_recent').domains, ['boundary.example', 'recent.example']);
for (const id of ['reviewed_free_subdomains', 'reviewed_disposable_disputes', 'reviewed_public_mailboxes', 'reviewed_relays']) {
    assert.equal(result.sources.find(s => s.id === id).fetched_at_unix, bundled.sources.find(s => s.id === id).fetched_at_unix);
}
await assert.rejects(snapshot(async url => url.endsWith('LICENSE.txt') ? 'Terms changed' : publicSource(url), now), /license changed/);
await assert.rejects(snapshot(async url => url.includes('7c/fakefilter/') && url.endsWith('LICENSE.md') ? 'Terms changed' : publicSource(url), now), /license changed/);
await assert.rejects(snapshot(async url => url.endsWith('disposable_email_blocklist.conf') ? 'https://example.test' : publicSource(url), now));
const dir = await mkdtemp(join(tmpdir(), 'openfingerprint-updater-'));
try {
    const path = join(dir, 'snapshot.json');
    await writeFile(path, 'previous');
    await assert.rejects(update(path, async () => { throw new Error('offline'); }));
    assert.equal(await readFile(path, 'utf8'), 'previous');
    await assert.rejects(update(path, async url => url.endsWith('disposable_email_blocklist.conf') ? `example.test${String.fromCharCode(92)}evil` : publicSource(url)));
    assert.equal(await readFile(path, 'utf8'), 'previous');
    await assert.rejects(update(path, async url => url.includes('7c/fakefilter/') && url.endsWith('data.json') ? JSON.stringify({ ...feed(), t: now - 4 * 86400 }) : publicSource(url)));
    assert.equal(await readFile(path, 'utf8'), 'previous');
    const fetch = globalThis.fetch;
    try {
        let cancelled = false;
        globalThis.fetch = async (_, options) => {
            assert.equal(options.redirect, 'error');
            assert(options.signal instanceof AbortSignal);
            return new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(8 * 1024 * 1024 + 1)); }, cancel() { cancelled = true; } }));
        };
        await assert.rejects(download('https://example.test/source'), /too large/);
        assert(cancelled);
        globalThis.fetch = async () => { throw new DOMException('Timed out', 'TimeoutError'); };
        await assert.rejects(update(path), { name: 'TimeoutError' });
        assert.equal(await readFile(path, 'utf8'), 'previous');
        globalThis.fetch = async () => new Response('', { status: 302 });
        await assert.rejects(update(path), /HTTP 302/);
        assert.equal(await readFile(path, 'utf8'), 'previous');
        globalThis.fetch = async () => new Response('', { status: 503 });
        await assert.rejects(update(path), /HTTP 503/);
        assert.equal(await readFile(path, 'utf8'), 'previous');
    } finally { globalThis.fetch = fetch; }
    await update(path, publicSource);
    assert.equal(JSON.parse(await readFile(path, 'utf8')).version, 1);
} finally { await rm(dir, { recursive: true, force: true }); }
assert.deepEqual(unprotected(['gmail.com', 'mx.google.com', 'yandex.net', 'com.br', 'mail.example', 'notgmail.com']), {
    kept: ['com.br', 'mail.example', 'notgmail.com'], dropped: ['gmail.com', 'mx.google.com', 'yandex.net']
});
const guarded = JSON.parse(await snapshot(async url => url.endsWith('disposable_email_blocklist.conf') ? 'mail.example\ngmail.com\naspmx.l.google.com\nhotmail.fr\n' : url.endsWith('spammers.txt') ? 'spam.example\nyahoo.com\n' : publicSource(url), now));
assert.deepEqual(guarded.sources.find(s => s.id === 'disposable_email_domains').domains, ['mail.example'], 'Reviewed public mailbox domains are protected too');
assert(guarded.sources.find(s => s.id === 'reviewed_public_mailboxes').domains.includes('hotmail.fr'));
assert.deepEqual(guarded.sources.find(s => s.id === 'reviewed_relays').domains.slice(0, 2), ['aleeas.com', 'anonaddy.com']);
assert.deepEqual(guarded.sources.find(s => s.id === 'matomo_referrer_spam').domains, ['spam.example']);
const published = [];
await publish('openfingerprint-domain-data', publicSource, async (name, data) => published.push([name, JSON.parse(data).version]));
assert.deepEqual(published, [['openfingerprint-domain-data', 1]]);
await assert.rejects(publish('Bad_Name', publicSource, async () => assert.fail('must not write')), /ConfigMap name/);
await assert.rejects(publish('openfingerprint-domain-data', async url => url.endsWith('disposable_email_blocklist.conf') ? Array.from({ length: 80000 }, (_, i) => `entry-${i}.example`).join('\n') : publicSource(url), async () => assert.fail('must not write')), /ConfigMap size/);
const account = await mkdtemp(join(tmpdir(), 'openfingerprint-sa-'));
const realFetch = globalThis.fetch;
try {
    await writeFile(join(account, 'token'), 'token-value\n');
    await writeFile(join(account, 'namespace'), 'openfingerprint\n');
    const env = { KUBERNETES_SERVICE_HOST: '10.43.0.1', KUBERNETES_SERVICE_PORT: '443' };
    for (const [first, created] of [[200, false], [404, true]]) {
        const calls = [];
        globalThis.fetch = async (url, options) => {
            calls.push([url, options.method, options.headers['Content-Type'], options.headers.Authorization, options.redirect, JSON.parse(options.body)]);
            return new Response('{}', { status: calls.length === 1 ? first : 201 });
        };
        await kubernetes('openfingerprint-domain-data', 'snapshot', { dir: account, env });
        const base = 'https://10.43.0.1:443/api/v1/namespaces/openfingerprint/configmaps';
        assert.deepEqual(calls[0].slice(0, 5), [`${base}/openfingerprint-domain-data`, 'PATCH', 'application/merge-patch+json', 'Bearer token-value', 'error']);
        assert.deepEqual(calls[0][5], { data: { 'domains.json': 'snapshot' } });
        assert.equal(calls.length, created ? 2 : 1);
        if (created) assert.deepEqual([calls[1][0], calls[1][1], calls[1][5].metadata.name, calls[1][5].data['domains.json']], [base, 'POST', 'openfingerprint-domain-data', 'snapshot']);
    }
    globalThis.fetch = async () => new Response('{}', { status: 403 });
    await assert.rejects(kubernetes('openfingerprint-domain-data', 'snapshot', { dir: account, env }), /HTTP 403/);
    await assert.rejects(kubernetes('openfingerprint-domain-data', 'snapshot', { dir: account, env: {} }), /Kubernetes pod/);
} finally {
    globalThis.fetch = realFetch;
    await rm(account, { recursive: true, force: true });
}
console.log('Open-data updater normalization, monitored freshness, license guards, protected mail domains, ConfigMap publishing and atomic preservation checks passed.');

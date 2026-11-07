import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { parseArgs } from 'node:util';
import { once } from 'node:events';
import { createSocket } from 'node:dgram';
import { createServer } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, chmodSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const { values } = parseArgs({
	options: {
		image: { type: 'string' },
		platform: { type: 'string' },
        'domain-data-mode': { type: 'string' },
		binary: {
			type: 'string',
			default: fileURLToPath(new URL('./target/debug/openfingerprint-api', import.meta.url))
		}
	}
});
const key = () => randomBytes(32).toString('hex');
const sites = ['alpha', 'beta', 'quota', 'malformed', 'check', 'check_invalid', 'shared', 'invalid_signals', 'reload', 'dns'].map((id) => ({
    id,
    secret_key: key(),
    ...(id === 'alpha' ? { site_key: key(), origins: ['https://alpha.test'] } : {})
}));
assert(!values.platform || values.image, '--platform requires --image');
const container = values.image ? `openfingerprint-test-${randomBytes(8).toString('hex')}` : null;
const mode = values['domain-data-mode'] ?? 'fresh';
assert(['fresh', 'stale', 'invalid', 'missing'].includes(mode));
const directory = mkdtempSync(join(tmpdir(), 'openfingerprint-domain-test-'));
chmodSync(directory, 0o755);
const dataPath = join(directory, 'domains.json');
const now = Math.floor(Date.now() / 1000);
const license = readFileSync(new URL('./data/domains.json', import.meta.url), 'utf8');
const cc0 = JSON.parse(license).sources.find(s => s.license === 'CC0-1.0').license_text;
const fixtureDomains = { disposable: ['mail.example', 'sharklasers.com'], free_subdomain: ['free.example', 'duckdns.org'], referrer_spam: ['spam.example', 'bad.customer.example', 'github.io'], public_mailbox: ['publicmail.example'], relay: ['relay.example'] };
const sources = Object.keys(fixtureDomains).map(category => ({
    id: category, category, license: 'CC0-1.0', license_text: cc0,
    license_sha256: createHash('sha256').update(cc0).digest('hex'),
    url: 'https://example.test/source', revision: 'fixture1', updated_at_unix: now - 3600,
    fetched_at_unix: now - 3600, expires_at_unix: mode === 'stale' ? now - 1 : now + 3600,
    domains: fixtureDomains[category],
    allowlist: category === 'disposable' ? ['good.mail.example'] : []
}));
const bsd = JSON.parse(license).sources.find(s => s.id === 'fakefilter_recent').license_text;
sources.push(
    { ...sources[0], id: 'monitored', license: 'BSD-3-Clause', license_text: bsd, license_sha256: createHash('sha256').update(bsd).digest('hex') },
    { ...sources[0], id: 'reviewed', category: 'disposable_review', domains: ['disputed.mail.example'], allowlist: [] }
);
if (mode !== 'missing') writeFileSync(dataPath, mode === 'invalid' ? '{}' : JSON.stringify({ version: 1, sources }), { mode: 0o644 });
const dnsQueries = [];
const mxAnswers = {
    'dnsmx.example': [[20, 'mx.other.example'], [10, 'MX1.Mail.Example.']],
    'mxmixed.example': [[10, 'aspmx.l.google.example'], [20, 'mx1.mail.example']],
    'mxunlisted.example': [[10, 'mx.notmail.example']],
    'mxself.example': [[10, 'mx.mxself.example']],
    'mxdisputed.example': [[10, 'mx.disputed.mail.example']],
    'mxallowed.example': [[10, 'mx1.mail.example'], [20, 'mx.good.mail.example']],
    'dnsdrop.example': [[10, 'mx.drop.example']],
    'workspace.example': [[5, 'eu-smtp-inbound-1.mimecast.com'], [1, 'smtp.google.com'], [9, 'eu-smtp-inbound-2.mimecast.com']]
};
const dns = createSocket('udp4');
const dnsName = name => Buffer.concat([...name.split('.').filter(Boolean).map(l => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0])]);
dns.on('message', (msg, peer) => {
    let pos = 12;
    const labels = [];
    while (msg[pos]) { labels.push(msg.subarray(pos + 1, pos + 1 + msg[pos]).toString()); pos += msg[pos] + 1; }
    const name = labels.join('.');
    dnsQueries.push(name);
    const reply = (rcode, records = [], { id = msg.readUInt16BE(0), flags = 0x8180 } = {}) => {
        const header = Buffer.alloc(12);
        header.writeUInt16BE(id, 0);
        header.writeUInt16BE(flags | rcode, 2);
        header.writeUInt16BE(1, 4);
        header.writeUInt16BE(records.length, 6);
        const answers = records.map(([preference, host]) => {
            const data = Buffer.concat([Buffer.from([0, preference]), dnsName(host)]);
            return Buffer.concat([Buffer.from([0xc0, 12, 0, 15, 0, 1, 0, 0, 0, 60, 0, data.length]), data]);
        });
        dns.send(Buffer.concat([header, msg.subarray(12, pos + 5), ...answers]), peer.port, peer.address);
    };
    if (name === 'dnsdrop.example' && !dnsQueries.slice(0, -1).includes(name)) return; // lose the first query
    if (mxAnswers[name]) reply(0, mxAnswers[name]);
    else if (name === 'dnsnx.example') reply(3);
    else if (name === 'dnsnull.example') reply(0, [[0, '.']]);
    else if (name === 'dnsfail.example') reply(2);
    else if (name === 'dnstrunc.example') reply(0, [], { flags: 0x8380 });
    else if (name === 'dnsspoof.example') { reply(0, [[10, 'mx1.mail.example']], { id: msg.readUInt16BE(0) ^ 0xffff }); reply(0); }
    else if (name !== 'dnsslow.example') reply(0);
});
await new Promise(resolve => dns.bind(0, container ? '0.0.0.0' : '127.0.0.1', resolve));
const registered = '2026-11-01T00:00:00Z';
const rdapRequests = [];
const rdap = createServer((req, res) => {
    const name = req.url.replace('/rdap/domain/', '');
    rdapRequests.push(name);
    if (req.headers.accept !== 'application/rdap+json') { res.writeHead(400).end(); return; }
    const domain = (ldhName, events) => res.writeHead(200, { 'content-type': 'application/rdap+json' }).end(JSON.stringify({ objectClassName: 'domain', ldhName, events }));
    if (name === 'rdapfound.example') domain('RDAPFOUND.EXAMPLE', [{ eventAction: 'expiration', eventDate: '2030-01-01T00:00:00Z' }, { eventAction: 'registration', eventDate: registered }]);
    else if (name === 'rdapnodate.example') domain(name, [{ eventAction: 'last changed', eventDate: registered }]);
    else if (name === 'rdapwrong.example') domain('other.example', [{ eventAction: 'registration', eventDate: registered }]);
    else if (name === 'rdapbroken.example') res.writeHead(503).end();
    else if (name === 'rdapmoved.example') res.writeHead(302, { location: '/rdap/domain/rdapfound.example' }).end();
    else if (name !== 'rdapslow.example') res.writeHead(404).end();
});
await new Promise(resolve => rdap.listen(0, container ? '0.0.0.0' : '127.0.0.1', resolve));
const redisStore = new Map();
const redis = createTcpServer(socket => {
    let buffer = '';
    socket.on('data', chunk => {
        buffer += chunk;
        for (;;) {
            const lines = buffer.split('\r\n');
            const count = Number(lines[0]?.slice(1));
            if (!count || lines.length < 1 + count * 2) return;
            const args = Array.from({ length: count }, (_, i) => lines[2 + i * 2]);
            buffer = lines.slice(1 + count * 2).join('\r\n');
            if (args[0] === 'GET') { const v = redisStore.get(args[1]); socket.write(v === undefined ? '$-1\r\n' : `$${v.length}\r\n${v}\r\n`); }
            else if (args[0] === 'SET' && args[3] === 'EX') { redisStore.set(args[1], args[2]); socket.write('+OK\r\n'); }
            else socket.write('-ERR unsupported\r\n');
        }
    });
    socket.on('error', () => {});
});
await new Promise(resolve => redis.listen(0, container ? '0.0.0.0' : '127.0.0.1', resolve));
const whoisQueries = [];
const whois = createTcpServer(socket => socket.once('data', chunk => {
    const name = chunk.toString().trim();
    whoisQueries.push(name);
    socket.end(name === 'old.wtest' ? 'Domain Name: old.wtest\r\nCreation Date: 2001-02-03T04:05:06Z\r\n' : name === 'busy.wtest' ? 'Query rate limit exceeded\r\n' : 'Domain not found.\r\n');
}).on('error', () => {}));
await new Promise(resolve => whois.listen(0, container ? '0.0.0.0' : '127.0.0.1', resolve));
writeFileSync(join(directory, 'whois.json'), JSON.stringify({ servers: { wtest: `${container ? 'dns.test' : '127.0.0.1'}:${whois.address().port}` } }), { mode: 0o644 });
writeFileSync(join(directory, 'rdap.json'), JSON.stringify({ services: [[['example', 'test', 'org', 'io', 'uk'], [`http://${container ? 'dns.test' : '127.0.0.1'}:${rdap.address().port}/rdap/`]]] }), { mode: 0o644 });
const args = container
	? [
			'run', '--rm', '--name', container, '--read-only', '--cap-drop=ALL',
			'--security-opt=no-new-privileges', '-p', '127.0.0.1::8180', '-p', '127.0.0.1::9180',
			'--env', 'OPENFINGERPRINT_LISTEN_ADDR',
			'--env', 'OPENFINGERPRINT_SITES',
            '--env', 'OPENFINGERPRINT_METRICS_ADDR',
            '--env', 'OPENFINGERPRINT_DOMAIN_DATA_RELOAD_SECONDS',
            '--env', 'OPENFINGERPRINT_DOMAIN_DATA',
            '--env', 'OPENFINGERPRINT_DNS', '--add-host', 'dns.test:host-gateway',
            '--env', 'OPENFINGERPRINT_RDAP_BOOTSTRAP', '--env', 'OPENFINGERPRINT_WHOIS_SERVERS', '--env', 'OPENFINGERPRINT_REDIS_URL',
            '--mount', `type=bind,src=${directory},dst=/domain-data,readonly`,
			...(values.platform ? ['--platform', values.platform] : []),
			values.image
		]
	: [];
delete process.env.OPENFINGERPRINT_SIGNING_KEY;
delete process.env.OPENFINGERPRINT_REDIS_PASSWORD;
delete process.env.OPENFINGERPRINT_REDIS_URL;
delete process.env.OPENFINGERPRINT_NETWORK_DATA;
delete process.env.OPENFINGERPRINT_TRUSTED_PROXIES;
const child = spawn(container ? 'docker' : values.binary, args, {
	env: {
		...process.env,
		OPENFINGERPRINT_LISTEN_ADDR: container ? '0.0.0.0:8180' : '127.0.0.1:0',
		OPENFINGERPRINT_SITES: JSON.stringify(sites),
        OPENFINGERPRINT_DOMAIN_DATA: container ? '/domain-data/domains.json' : dataPath,
        OPENFINGERPRINT_METRICS_ADDR: container ? '0.0.0.0:9180' : '127.0.0.1:0',
        OPENFINGERPRINT_DOMAIN_DATA_RELOAD_SECONDS: '1',
        OPENFINGERPRINT_DNS: `${container ? 'dns.test' : '127.0.0.1'}:${dns.address().port}`,
        OPENFINGERPRINT_RDAP_BOOTSTRAP: container ? '/domain-data/rdap.json' : join(directory, 'rdap.json'),
        OPENFINGERPRINT_WHOIS_SERVERS: container ? '/domain-data/whois.json' : join(directory, 'whois.json'),
        OPENFINGERPRINT_REDIS_URL: `redis://${container ? 'dns.test' : '127.0.0.1'}:${redis.address().port}/`
	},
	stdio: ['ignore', 'pipe', 'pipe']
});
let phase = 'startup';
let timer;
let serverOutput = '';
let metricsOrigin;
const base = new Promise((resolve, reject) => {
	let output = '';
	child.stdout.on('data', (data) => {
		serverOutput += data.toString();
		output += data.toString();
		const metrics = /metrics on (127\.0\.0\.1:\d+|0\.0\.0\.0:9180)/.exec(output);
		if (metrics && !metricsOrigin) {
			metricsOrigin = `http://${container ? execFileSync('docker', ['port', container, '9180/tcp'], { encoding: 'utf8', timeout: 10000 }).trim() : metrics[1]}`;
		}
		const match = /listening on (127\.0\.0\.1:\d+|0\.0\.0\.0:8180)/.exec(output);
		if (match) {
			clearTimeout(timer);
			try {
				const address = container
					? execFileSync('docker', ['port', container, '8180/tcp'], {
							encoding: 'utf8', timeout: 10000
						}).trim()
					: match[1];
				assert(/^127\.0\.0\.1:\d+$/.test(address));
				resolve(`http://${address}`);
			} catch {
				reject(new Error('Container port unavailable'));
			}
		}
	});
	child.on('error', () => reject(new Error('Startup failed')));
	child.on('exit', () => reject(new Error('Server exited')));
	timer = setTimeout(() => reject(new Error('Startup timed out')), container ? 30000 : 10000);
});
child.stderr.on('data', data => { serverOutput += data.toString(); });
const digest = (s) => createHash('sha256').update(s).digest('hex');
function signals(locale = 'same', font = 'same', version = 4) {
	const components = { fontFallbacks: digest('fallback'), fontPreferences: digest(font) };
	const hints = { locale: digest(locale) };
	const entries = (object) =>
		Object.entries(object).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
	return {
		version,
		fingerprint: digest(
			`stealth-agent:${version}\0` +
				JSON.stringify({ components: entries(components), hints: entries(hints) })
		),
		coreFingerprint: digest(`stealth-core:${version}\0` + JSON.stringify(entries(components))),
		components,
		hints,
		excluded: ['audio', 'canvas', 'screen'],
		unavailable: { audio: 'unstable', canvas: 'unsupported', screen: 'timeout' },
		storageId: null,
		durationMs: 5,
		timings: { fontPreferences: { durationMs: 1, blockingMs: 0.1 } }
	};
}
let origin;
async function request(path, headers, body, method = 'POST') {
	return fetch(origin + path, {
		method,
		headers: { 'content-type': 'application/json', ...headers },
		...(body === undefined ? {} : { body: typeof body === 'string' ? body : JSON.stringify(body) }),
		signal: AbortSignal.timeout(10000)
	});
}

const authHeaders = (site) => ({ Authorization: `Bearer ${site.secret_key}` });
function domainExpected(overrides = {}) {
    const hasReview = overrides.disputed && ['fresh', 'stale'].includes(mode);
    const result = { status: hasReview ? 'partial' : mode === 'fresh' ? 'ok' : 'unknown' };
    if (['invalid', 'missing'].includes(mode)) result.reason = mode === 'invalid' ? 'invalid_data' : 'data_unavailable';
    for (const [field, category, scope] of [['disposable', 'disposable', 'disposable_domain'], ['free_subdomain', 'free_subdomain', 'free_subdomain_namespace'], ['spam', 'referrer_spam', 'referrer_spam'], ['public_mailbox', 'public_mailbox', 'public_mailbox'], ['relay', 'relay', 'email_relay']]) {
        const matched = overrides[field];
        const status = mode === 'fresh' ? (matched === true ? 'listed' : matched === false ? (field === 'free_subdomain' ? 'provider_domain' : 'allowlisted') : 'not_listed') : 'unknown';
        const disputed = hasReview && field === 'disposable';
        const fact = { value: disputed ? null : mode === 'fresh' ? matched ?? null : null, status: disputed ? 'conflict' : status, scope };
        if (disputed) fact.reason = 'review_required';
        else if (mode !== 'fresh') fact.reason = mode === 'stale' ? 'no_fresh_data' : result.reason;
        fact.sources = ['invalid', 'missing'].includes(mode) ? [] : sources.filter(s => s.category === category || (category === 'disposable' && s.category === 'disposable_review')).map(s => {
            const { category: _, license_text, domains, allowlist, ...meta } = s;
            const sourceStatus = mode === 'stale' ? 'stale' : s.category === 'disposable_review' ? (hasReview ? 'disputed' : 'not_listed') : field === 'spam' && overrides.public_suffix_excluded ? 'public_suffix_excluded' : status;
            return { ...meta, status: sourceStatus };
        });
        result[field] = fact;
    }
    result.did_you_mean = overrides.did_you_mean ?? null;
    result.mx_lookup = overrides.mx_lookup ?? 'no_records';
    if (overrides.mx_providers) result.mx_providers = overrides.mx_providers;
    result.registration = overrides.registration ?? { status: 'not_found' };
    return result;
}
try {
    origin = await base;
    phase = 'health and routes';
    const health = await request('/health', {}, undefined, 'GET');
    assert.equal(health.status, 200);
    assert.equal(await health.text(), 'ok');
    assert.equal(health.headers.get('cache-control'), 'no-store');
    assert.equal(health.headers.get('set-cookie'), null);
    for (const method of ['GET', 'POST', 'OPTIONS']) {
        const response = await request('/v1/collect', { Origin: 'https://alpha.test' }, undefined, method);
        assert.equal(response.status, method === 'POST' ? 400 : 405);
        assert.equal(response.headers.get('access-control-allow-origin'), null);
    }
    for (const path of ['/v1/check', '/v1/verify']) {
        assert.equal((await request(path, {}, undefined, 'GET')).status, 405);
        assert.equal((await request(path, {}, undefined, 'OPTIONS')).status, 405);
    }
    console.log('Health, check, verification and collection routes are available (Redis failures: test-collection.mjs).');

    phase = 'authentication before parsing and no browser CORS';
    for (const path of ['/v1/check', '/v1/verify']) {
        for (const [index, headers] of [
            {},
            authHeaders({ secret_key: key() }),
            authHeaders({ secret_key: sites[0].site_key }),
            { 'X-Site-Key': sites[0].site_key },
            { Authorization: 'Bearer short' }
        ].entries()) {
            phase = `authentication before parsing: ${path} case ${index}`;
            const response = await request(path, headers, 'not-json');
            assert.equal(response.status, 401);
            assert.deepEqual(await response.json(), { error: 'unauthorized' });
        }
        phase = `unauthorized oversized body: ${path}`;
        assert.equal((await request(path, {}, 'x'.repeat(65537))).status, 401);
        phase = `browser Origin rejection: ${path}`;
        const forbidden = await request(path, {
            ...authHeaders(sites[0]), Origin: 'https://alpha.test'
        }, 'not-json');
        assert.equal(forbidden.status, 403);
        assert.equal(forbidden.headers.get('access-control-allow-origin'), null);
        assert.equal(forbidden.headers.get('cache-control'), 'no-store');
    }
    console.log('Server-key compatibility, public-key rejection and browser-origin boundaries passed.');

    phase = 'canonical profiles for both supported schemas';
    for (const version of [4, 5]) {
        const input = signals('same', 'same', version);
        delete input.timings;
        delete input.storageId;
        for (const site of sites.slice(0, 2)) {
            const response = await request('/v1/verify', authHeaders(site), input);
            assert.equal(response.status, 200);
            assert.equal(response.headers.get('cache-control'), 'no-store');
            assert.equal(response.headers.get('set-cookie'), null);
            assert.equal(response.headers.get('access-control-allow-origin'), null);
            assert.deepEqual(await response.json(), {
                status: 'ok', schema_version: version, fingerprint: input.fingerprint
            });
        }
        assert.equal((await request('/v1/verify', authHeaders(sites[0]), {
            ...input, coreFingerprint: null
        })).status, 200);
        const different = signals('different', 'different', version);
        await request('/v1/verify', authHeaders(sites[0]), different);
        const repeated = await request('/v1/verify', authHeaders(sites[0]), input);
        assert.deepEqual(await repeated.json(), {
            status: 'ok', schema_version: version, fingerprint: input.fingerprint
        });
    }
    assert.notEqual(signals('same', 'same', 4).fingerprint, signals('same', 'same', 5).fingerprint);
    for (const insufficient of [
        { ...signals(), fingerprint: null },
        { ...signals(), fingerprint: null, coreFingerprint: null, components: {}, hints: {} }
    ]) {
        const response = await request('/v1/verify', authHeaders(sites[0]), insufficient);
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), {
            status: 'insufficient_signals', schema_version: null, fingerprint: null
        });
    }
    console.log('Canonical schema-4/5 profiles, repeat verification and unknown/core-only identities passed.');

    phase = 'independent requested checks and explicit unconfigured intelligence';
    const unknown = { status: 'unknown', reason: 'not_configured', network: { status: 'unknown', reason: 'non_global_ip', source: 'backend_supplied' } };
    const checkedProfile = input => ({
        status: 'ok', schema_version: input.version, fingerprint: input.fingerprint,
        evidence: { included_components: 2, included_hints: 1, unavailable_probes: 3, excluded_probes: 3 }
    });
    for (const version of [4, 5]) {
        const input = signals('same', 'same', version);
        const response = await request('/v1/check', authHeaders(sites[4]), { signals: input });
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), { signals: checkedProfile(input) });
    }
    const automation = { version: 1, webdriver: true, headlessUserAgent: false, seleniumArtifacts: false, phantomArtifacts: false };
    const automationExpected = {
        status: 'detected', rule_version: 1, source: 'client_reported',
        indicators: ['webdriver'], unavailable_probes: []
    };
    const fields = { signals: signals(), domain: 'ExAmPlE.test.', ip: '2001:db8::1', automation };
    for (let mask = 1; mask < 16; mask++) {
        const selected = Object.fromEntries(Object.entries(fields).filter((_, i) => mask & (1 << i)));
        const response = await request('/v1/check', authHeaders(sites[4]), selected);
        assert.equal(response.status, 200);
        assert.equal(response.headers.get('cache-control'), 'no-store');
        assert.equal(response.headers.get('set-cookie'), null);
        assert.equal(response.headers.get('access-control-allow-origin'), null);
        const expected = {};
        if ('signals' in selected) expected.signals = checkedProfile(selected.signals);
        if ('domain' in selected) expected.domain = domainExpected();
        if ('ip' in selected) expected.ip = unknown;
        if ('automation' in selected) expected.automation = automationExpected;
        assert.deepEqual(await response.json(), expected);
    }
    phase = 'automation evidence, unknowns and independent failures';
    for (const [observations, status, indicators, unavailable] of [
        [{ ...automation, webdriver: false }, 'not_detected', [], []],
        [{ version: 1 }, 'unknown', [], ['webdriver', 'headless_user_agent', 'selenium_artifacts', 'phantom_artifacts']],
        [{ ...automation, webdriver: null }, 'unknown', [], ['webdriver']],
        [{ ...automation, headlessUserAgent: null }, 'detected', ['webdriver'], ['headless_user_agent']],
        [{ ...automation, webdriver: false, headlessUserAgent: true }, 'detected', ['headless_user_agent'], []]
    ]) {
        const response = await request('/v1/check', authHeaders(sites[4]), { automation: observations, signals: signals() });
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), {
            automation: { status, rule_version: 1, source: 'client_reported', indicators, unavailable_probes: unavailable },
            signals: checkedProfile(signals())
        });
    }
    for (const invalid of [false, [], 'browser', {}, { version: 2 }, { ...automation, webdriver: 'false' }, { ...automation, extra: true }]) {
        const response = await request('/v1/check', authHeaders(sites[4]), { ...fields, automation: invalid });
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), {
            automation: { ...automationExpected, status: 'invalid_input', indicators: [], reason: 'invalid_automation' },
            signals: checkedProfile(signals()), domain: domainExpected(), ip: unknown
        });
    }
    const invalidSignals = await request('/v1/check', authHeaders(sites[4]), { automation, signals: false });
    assert.equal(invalidSignals.status, 200);
    assert.deepEqual(await invalidSignals.json(), {
        automation: automationExpected,
        signals: { status: 'invalid_input', reason: 'invalid_signals', schema_version: null, fingerprint: null, evidence: null }
    });
    const omittedAutomation = await request('/v1/check', authHeaders(sites[4]), { automation: null, signals: signals() });
    assert.deepEqual(await omittedAutomation.json(), { signals: checkedProfile(signals()) });
    const legacyAutomation = await request('/v1/verify', authHeaders(sites[4]), { ...signals(), automation });
    assert.equal(legacyAutomation.status, 200);
    assert.deepEqual(await legacyAutomation.json(), { status: 'ok', schema_version: 4, fingerprint: signals().fingerprint });
    const nestedAutomation = await request('/v1/check', authHeaders(sites[4]), { signals: { ...signals(), automation } });
    assert.deepEqual(await nestedAutomation.json(), { signals: { ...checkedProfile(signals()), automation: automationExpected } });
    const invalidNested = await request('/v1/check', authHeaders(sites[4]), { signals: { ...signals(), automation: false } });
    assert.deepEqual(await invalidNested.json(), { signals: { ...checkedProfile(signals()), automation: { ...automationExpected, status: 'invalid_input', indicators: [], reason: 'invalid_automation' } } });
    console.log('Automation rules, all 15 input combinations, unknowns, stable identities and independent failures passed.');
    const coreOnly = await request('/v1/check', authHeaders(sites[4]), {
        signals: { ...signals(), fingerprint: null }, domain: 'example.test'
    });
    assert.deepEqual(await coreOnly.json(), {
        signals: { ...checkedProfile(signals()), status: 'insufficient_signals', schema_version: null, fingerprint: null },
        domain: domainExpected()
    });
    const nulls = await request('/v1/check', authHeaders(sites[4]), {
        signals: null, domain: null, ip: '192.0.2.1'
    });
    assert.deepEqual(await nulls.json(), { ip: unknown });
    console.log('All 15 input combinations, requested-only results, evidence counts and domain data state passed.');
    phase = `domain classification and source scope (${mode})`;
    for (const [domain, expected] of [
        ['mail.example', { disposable: true }], ['Child.MAIL.example.', { disposable: true }],
        ['notmail.example', {}], ['good.mail.example', { disposable: false }],
        ['child.good.mail.example', { disposable: false }],
        ['disputed.mail.example', { disposable: true, disputed: true }],
        ['child.disputed.mail.example', { disposable: true }],
        ['tenant.free.example', { free_subdomain: true, ...(mode === 'fresh' ? { registration: { status: 'not_applicable' } } : {}) }], ['free.example', { free_subdomain: false }],
        ['tenant.duckdns.org', { free_subdomain: true, registration: { status: 'not_applicable' } }], ['duckdns.org', { free_subdomain: false }],
        ['spam.example', { spam: true }], ['child.spam.example', { spam: true }],
        ['bad.customer.example', { spam: true }], ['customer.example', {}],
        ['notbad.customer.example', {}], ['innocent.github.io', { public_suffix_excluded: true, registration: { status: 'not_applicable' } }],
        ['co.uk', { registration: { status: 'not_applicable' }, mx_lookup: 'not_needed' }]
    ]) {
        const response = await request('/v1/check', authHeaders(sites[4]), { signals: signals(), domain });
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), { signals: checkedProfile(signals()), domain: domainExpected(expected) });
    }
    console.log(`Domain facts, label boundaries, provenance, unknowns and browser isolation passed (${mode}).`);

    phase = `MX lookups and MX-provider inference (${mode})`;
    for (const [domain, lookup, disposable] of [
        ['dnsmx.example', 'resolved', true], ['mxmixed.example', 'resolved', true], ['mxunlisted.example', 'resolved'],
        ['mxself.example', 'resolved'], ['mxdisputed.example', 'resolved'], ['mxallowed.example', 'resolved'],
        ['dnsnx.example', 'no_domain'], ['dnsnull.example', 'no_records'],
        ['dnsfail.example', 'unavailable'], ['dnstrunc.example', 'unavailable'], ['dnsslow.example', 'unavailable'],
        ['dnsdrop.example', 'resolved'],
        ['dnsspoof.example', 'no_records']
    ]) {
        const started = Date.now();
        const response = await request('/v1/check', authHeaders(sites[9]), { domain });
        assert(Date.now() - started < 3000);
        const want = domainExpected({ mx_lookup: lookup, ...(lookup === 'resolved' ? { mx_providers: [] } : {}), ...(mode === 'fresh' && disposable ? { disposable } : {}) });
        if (mode === 'fresh' && disposable) want.disposable.status = 'mx_listed';
        assert.deepEqual(await response.json(), { domain: want });
    }
    assert(['example.test', 'dnsmx.example', 'mail.example', 'good.mail.example', 'innocent.github.io'].every(name => dnsQueries.includes(name)), 'Every registrable domain is looked up');
    assert(!dnsQueries.includes('co.uk'), 'Public suffixes are not sent to DNS');
    console.log(`MX lookups, provider inference and its blockers, timeouts, spoofed replies and public-suffix skipping passed (${mode}).`);

    phase = `public mailboxes, relays, typo suggestions and MX providers (${mode})`;
    for (const [domain, expected] of [
        ['publicmail.example', { public_mailbox: true }], ['sub.publicmail.example', {}],
        ['relay.example', { relay: true }], ['user.relay.example', { relay: true }],
        ['publicmial.example', mode === 'fresh' ? { did_you_mean: 'publicmail.example' } : {}],
        ['workspace.example', { mx_lookup: 'resolved', mx_providers: [{ slug: 'google', type: 'mailbox' }, { slug: 'mimecast', type: 'gateway' }] }]
    ]) {
        const response = await request('/v1/check', authHeaders(sites[9]), { domain });
        assert.deepEqual(await response.json(), { domain: domainExpected(expected) }, domain);
    }
    console.log(`Public mailboxes (exact), relays (with subdomains), typo suggestions and MX providers passed (${mode}).`);

    phase = `RDAP registration dates (${mode})`;
    for (const [domain, registration] of [
        ['rdapfound.example', { status: 'found', registered_at_unix: Date.parse(registered) / 1000 }],
        ['mail.rdapfound.example', { status: 'found', registered_at_unix: Date.parse(registered) / 1000 }],
        ['rdapnodate.example', { status: 'no_date' }], ['rdapwrong.example', { status: 'unavailable' }],
        ['rdapbroken.example', { status: 'unavailable' }], ['rdapmoved.example', { status: 'unavailable' }],
        ['rdapslow.example', { status: 'unavailable' }], ['example.zz', { status: 'unsupported_tld' }],
        ['mail.old.wtest', { status: 'found', registered_at_unix: Date.parse('2001-02-03T00:00:00Z') / 1000 }],
        ['new.wtest', { status: 'not_found' }], ['busy.wtest', { status: 'unavailable' }]
    ]) {
        const started = Date.now();
        const response = await request('/v1/check', authHeaders(sites[9]), { domain });
        assert(Date.now() - started < 3500);
        assert.deepEqual((await response.json()).domain.registration, registration);
    }
    assert(rdapRequests.includes('mail.example') && !rdapRequests.some(name => name.split('.').length > 2), 'RDAP must query registrable domains only');
    assert.equal(rdapRequests.filter(name => name === 'rdapfound.example').length, 1, 'Cached registrations must not reach the registry again');
    assert.equal(rdapRequests.filter(name => name === 'rdapbroken.example').length, 1);
    assert(redisStore.size > 0 && [...redisStore.keys()].every(k => /^openfingerprint:rdap:v1:[0-9a-f]{64}$/.test(k)), 'Cache keys are hashed registered domains');
    assert(![...redisStore.values()].some(v => v === 'unavailable'), 'Unavailable answers are not cached');
    assert(!rdapRequests.some(name => /github|co\.uk|duckdns\.org$/.test(name) && name !== 'duckdns.org'), 'Private-namespace tenants and public suffixes are not registrable');
    assert.deepEqual(whoisQueries, ['old.wtest', 'new.wtest', 'busy.wtest'], 'WHOIS gets the registrable domain once, then the cache answers');
    console.log(`RDAP and WHOIS registration dates, cache, registrable-domain scope, redirects, timeouts and unsupported TLDs passed (${mode}).`);

    phase = 'independent field validation and bounded envelopes';
    for (const domain of ['', 'localhost', 'https://example.test', 'person@example.test', 'example.test:80', 'a..test', 'bücher.test', 'a'.repeat(64) + '.test', {}, 42]) {
        const response = await request('/v1/check', authHeaders(sites[5]), {
            signals: signals(), domain, ip: '192.0.2.1'
        });
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), {
            signals: checkedProfile(signals()), domain: { status: 'invalid_input', reason: 'invalid_domain' }, ip: unknown
        });
    }
    for (const ip of ['', 'example.test', '192.0.2.1:80', '[2001:db8::1]', '192.0.2.0/24', 'fe80::1%eth0', [], true]) {
        const response = await request('/v1/check', authHeaders(sites[5]), { domain: 'example.test', ip });
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), { domain: domainExpected(), ip: { status: 'invalid_input', reason: 'invalid_ip', network: { status: 'invalid_input', reason: 'invalid_ip', source: 'backend_supplied' } } });
    }
    for (const body of [{}, { signals: null, domain: null, ip: null }, { automation: null }, [], null, 'not-json',
        { mx: ['mx.mail.example'] }, { domain: 'example.test', mx: ['mx.mail.example'] },
        ...['email', 'visitor_token', 'account_id', 'userAgent', 'storageId'].map(k => ({ domain: 'example.test', [k]: 'unsolicited' }))]) {
        const response = await request('/v1/check', authHeaders(sites[5]), body);
        assert.equal(response.status, 400);
        assert.deepEqual(await response.json(), { error: 'invalid_request' });
    }
    assert.equal((await request('/v1/check', authHeaders(sites[5]), { domain: 'x'.repeat(65536) })).status, 413);
    console.log('Invalid fields preserve other results; malformed, empty, unsolicited and oversized envelopes are rejected.');

    phase = 'strict evidence and metadata validation';
    const input = signals();
    const invalid = [
        { ...input, fingerprint: digest('tampered') },
        { ...input, coreFingerprint: digest('tampered') },
        { ...input, version: 2 },
        { ...input, version: 5 },
        { ...input, version: 6 },
        { ...input, storageId: 'unsolicited' },
        { ...input, excluded: ['canvas', 'canvas'] },
        { ...input, excluded: ['other'] },
        { ...input, components: { fonts: 'raw' } },
        { ...input, components: {} },
        { ...input, hints: input.components },
        { ...input, unavailable: { fontPreferences: 'error' } },
        { ...input, unavailable: { audio: 'arbitrary' } },
        { ...input, timings: { fonts: { durationMs: 60001, blockingMs: 1 } } },
        { ...input, durationMs: -1 },
        { ...input, durationMs: 60001 },
        { ...input, components: Object.fromEntries(Array.from({ length: 33 }, (_, i) => ['probe' + i, digest('fixture')])) },
        ...['email', 'visitor_token', 'account_id', 'ip', 'userAgent', 'sdkVersion'].map(
            name => ({ ...input, [name]: 'unsolicited' })
        )
    ];
    for (const body of invalid) {
        const response = await request('/v1/verify', authHeaders(sites[0]), body);
        assert.equal(response.status, 400);
        assert.deepEqual(await response.json(), { error: 'invalid_request' });
        const check = await request('/v1/check', authHeaders(sites[7]), { signals: body, domain: 'example.test' });
        assert.equal(check.status, 200);
        assert.deepEqual(await check.json(), {
            signals: { status: 'invalid_input', reason: 'invalid_signals', schema_version: null, fingerprint: null, evidence: null },
            domain: domainExpected()
        });
    }
    for (const signals of [false, [], 'not evidence']) {
        const response = await request('/v1/check', authHeaders(sites[7]), { signals, ip: '192.0.2.1' });
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), {
            signals: { status: 'invalid_input', reason: 'invalid_signals', schema_version: null, fingerprint: null, evidence: null },
            ip: unknown
        });
    }
    assert.equal((await request('/v1/verify', authHeaders(sites[0]), 'not-json')).status, 400);
    assert.equal((await request('/v1/verify', authHeaders(sites[0]), JSON.stringify({
        padding: 'x'.repeat(65536)
    }))).status, 413);
    console.log('Strict hashes, schema separation, unsolicited visitor-data rejection and body limits passed.');

    phase = 'snapshot reload and metrics';
    assert(metricsOrigin, 'Metrics listener missing');
    const metric = async (name) => {
        const text = await (await fetch(metricsOrigin + '/metrics', { signal: AbortSignal.timeout(5000) })).text();
        return Number(text.split('\n').find(line => line.startsWith(name + ' '))?.split(' ')[1]);
    };
    assert.equal(await metric('openfingerprint_domain_data_loaded'), ['fresh', 'stale'].includes(mode) ? 1 : 0);
    const replace = (body) => { writeFileSync(dataPath + '.tmp', body, { mode: 0o644 }); renameSync(dataPath + '.tmp', dataPath); };
    const reloadedValue = async () => (await (await request('/v1/check', authHeaders(sites[8]), { domain: 'reloaded.example' })).json()).domain.disposable?.value ?? null;
    const waitFor = async (expected) => {
        for (let i = 0; i < 40 && await reloadedValue() !== expected; i++) await new Promise(r => setTimeout(r, 250));
        assert.equal(await reloadedValue(), expected);
    };
    assert.equal(await reloadedValue(), null);
    replace(JSON.stringify({ version: 1, sources: sources.map(s => ({ ...s, expires_at_unix: now + 3600, domains: s.id === 'disposable' ? [...s.domains, 'reloaded.example'] : s.domains })) }));
    await waitFor(true);
    assert.equal(await metric('openfingerprint_domain_data_loaded'), 1);
    replace('{}');
    for (let i = 0; i < 40 && await metric('openfingerprint_domain_data_reload_failures_total') !== 1; i++) await new Promise(r => setTimeout(r, 250));
    assert.equal(await metric('openfingerprint_domain_data_reload_failures_total'), 1);
    assert.equal(await reloadedValue(), true);
    assert.equal(await metric('openfingerprint_domain_data_loaded'), 1);
    assert.equal(await metric('openfingerprint_mx_lookups_total{result="resolved"}'), 8);
    assert.equal(await metric('openfingerprint_whois_lookups_total{result="found"}'), 1);
    assert.equal(await metric('openfingerprint_rdap_lookups_total{result="found"}'), 1);
    assert(await metric('openfingerprint_rdap_cache_total{result="hit"}') >= 1);
    assert.equal(await metric('openfingerprint_rdap_cache_total{result="error"}'), 0);
    console.log(`Snapshot reload, last-good retention and metrics passed (${mode}).`);
    phase = 'no request or credential logging';
    for (const sensitive of [
        ...sites.flatMap(site => [site.secret_key, site.site_key].filter(Boolean)),
        signals().fingerprint, signals('same', 'same', 5).fingerprint,
        signals().components.fontPreferences, 'unsolicited', 'ExAmPlE.test.', '2001:db8::1', '192.0.2.1',
        'mail.example', 'disputed.mail.example', 'child.disputed.mail.example', 'dnsmx.example', 'mx.other.example', 'rdapfound.example'
    ]) assert(!serverOutput.includes(sensitive));
    console.log('No request evidence, raw metadata or credentials appeared in server output.');
	if (container) {
		phase = 'non-root image, license retention and graceful SIGTERM';
		const imageEnv = JSON.parse(execFileSync('docker', [
			'image', 'inspect', '--format', '{{json .Config.Env}}', values.image
		], { encoding: 'utf8' }));
		assert(!imageEnv.some((value) => /^(OPENFINGERPRINT_SIGNING_KEY|OPENFINGERPRINT_SITES)=/.test(value)));
		assert.equal(
			execFileSync('docker', ['exec', container, 'id', '-u'], { encoding: 'utf8' }).trim(),
			'65532'
		);
		assert.equal(
			execFileSync('docker', ['inspect', '--format', '{{.HostConfig.ReadonlyRootfs}}', container], {
				encoding: 'utf8'
			}).trim(),
			'true'
		);
		execFileSync('docker', ['exec', container, 'sh', '-c', [
			'test -s /usr/share/licenses/openfingerprint-api/Cargo.lock',
			'test -s /usr/share/licenses/openfingerprint-api/openfingerprint-api/LICENSE',
			'test -d /usr/share/licenses/openfingerprint-api/rust',
            'test -s /usr/share/licenses/openfingerprint-api/domain-data.json',
            'grep -q BSD-3-Clause /usr/share/licenses/openfingerprint-api/domain-data.json',
            'grep -q "Neither the name of the copyright holder" /usr/share/licenses/openfingerprint-api/domain-data.json'
		].join(' && ')], { stdio: 'ignore' });
		const exited = once(child, 'exit', { signal: AbortSignal.timeout(10000) });
		execFileSync('docker', ['stop', '--time', '3', container], { stdio: 'ignore', timeout: 10000 });
		const [code, signal] = await exited;
		assert.equal(code, 0);
		assert.equal(signal, null);
		console.log('Non-root, read-only image, retained licenses and graceful SIGTERM checks passed.');
	}
} catch {
	console.error(
		`API self-check failed during: ${phase}. Sensitive response/credential values suppressed.`
	);
	process.exitCode = 1;
} finally {
	clearTimeout(timer);
	if (container) {
		try {
			execFileSync('docker', ['rm', '--force', container], { stdio: 'ignore', timeout: 10000 });
		} catch {}
	}
	if (child.exitCode === null) {
		child.kill('SIGTERM');
		await Promise.race([
			once(child, 'exit'),
			new Promise((resolve) => {
				const timeout = setTimeout(() => {
					child.kill('SIGKILL');
					resolve();
				}, 3000);
				timeout.unref();
			})
		]);
	}
    dns.close();
    rdap.closeAllConnections();
    rdap.close();
    redis.close();
    whois.close();
    rmSync(directory, { recursive: true, force: true });
}

if (!values['domain-data-mode'] && !process.exitCode) {
    const env = { ...process.env, OPENFINGERPRINT_SITES: JSON.stringify(sites), OPENFINGERPRINT_LISTEN_ADDR: '127.0.0.1:0', OPENFINGERPRINT_DNS: '127.0.0.1:9' };
    delete env.OPENFINGERPRINT_REDIS_URL;
    const noRedis = container
        ? spawnSync('docker', ['run', '--rm', '--env', 'OPENFINGERPRINT_SITES', '--env', 'OPENFINGERPRINT_LISTEN_ADDR', '--env', 'OPENFINGERPRINT_DNS', values.image], { env, encoding: 'utf8', timeout: 30000 })
        : spawnSync(values.binary, [], { env, encoding: 'utf8', timeout: 30000 });
    assert(noRedis.status !== 0 && noRedis.stderr.includes('OPENFINGERPRINT_REDIS_URL is required'), 'The API must refuse to start without Redis');
    console.log('Startup without Redis refused.');
    await import('./test-domain-updater.mjs');
    for (const mode of ['stale', 'invalid', 'missing']) {
        const result = spawnSync(process.execPath, [fileURLToPath(import.meta.url), ...process.argv.slice(2), '--domain-data-mode', mode], { stdio: 'inherit', timeout: 120000 });
        if (result.status !== 0) { process.exitCode = 1; break; }
    }
}

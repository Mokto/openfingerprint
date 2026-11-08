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
import { connect } from 'node:http2';
import { seal } from '../sdk/src/token.ts';

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
// The API has no authentication and ignores this old setting; it is passed to prove that.
const legacySites = JSON.stringify([{ id: 'legacy', secret_key: randomBytes(32).toString('hex') }]);
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
    'ispmail.example': [[10, 'mx-rogers.mail.am0.yahoodns.net']],
    'aliasmx.example': [[10, 'mx1.simplelogin.co'], [20, 'mx2.simplelogin.co']],
    'halfalias.example': [[10, 'mx1.simplelogin.co'], [20, 'mx.other.example']],
    'throwaway.example': [[10, 'mail.wabblywabble.com'], [20, 'mail.wallywatts.com']],
    'halfthrow.example': [[10, 'mail.wabblywabble.com'], [20, 'mx.other.example']],
    'priyo.example': [[10, 'fr.priyohost.net']],
    'priyohost-other.example': [[10, 'mail.priyohost.net']],
    'yahoobiz.example': [[10, 'mx-biz.mail.am0.yahoodns.net']],
    'workspace.example': [[5, 'eu-smtp-inbound-1.mimecast.com'], [1, 'smtp.google.com'], [9, 'eu-smtp-inbound-2.mimecast.com']]
};
const bigSpf = `v=spf1 ${Array.from({ length: 40 }, (_, i) => `ip4:192.0.2.${i}`).join(' ')} -all`;
const txtAnswers = {
    'authmail.example': [['v=spf1 include:_spf.mail.example -all'], ['site-verification=abc']],
    '_dmarc.authmail.example': [['v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@authmail.example']],
    'twospf.example': [['v=spf1 -all'], ['v=spf1 ~all']],
    'badpolicy.example': [['v=spf1 -all']],
    '_dmarc.badpolicy.example': [['v=DMARC1; p=sometimes']],
    'bigtxt.example': [bigSpf.match(/.{1,255}/g), ...Array.from({ length: 4 }, (_, i) => [`verification-${i}=${'x'.repeat(240)}`])]
};
const txtQueries = [];
const dns = createSocket('udp4');
const dnsName = name => Buffer.concat([...name.split('.').filter(Boolean).map(l => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0])]);
// Answers one query; `send` gets the reply bytes. Over UDP, TXT sets above 512 bytes are truncated.
function answerDns(msg, send, tcp = false) {
    let pos = 12;
    const labels = [];
    while (msg[pos]) { labels.push(msg.subarray(pos + 1, pos + 1 + msg[pos]).toString()); pos += msg[pos] + 1; }
    const name = labels.join('.');
    const qtype = msg.readUInt16BE(pos + 1);
    const reply = (rcode, records = [], { id = msg.readUInt16BE(0), flags = 0x8180, type = 15 } = {}) => {
        const header = Buffer.alloc(12);
        header.writeUInt16BE(id, 0);
        header.writeUInt16BE(flags | rcode, 2);
        header.writeUInt16BE(1, 4);
        header.writeUInt16BE(records.length, 6);
        const answers = records.map(record => {
            const data = type === 16 ? Buffer.concat(record.map(t => Buffer.concat([Buffer.from([t.length]), Buffer.from(t)]))) : Buffer.concat([Buffer.from([0, record[0]]), dnsName(record[1])]);
            return Buffer.concat([Buffer.from([0xc0, 12, 0, type, 0, 1, 0, 0, 0, 60, data.length >> 8, data.length & 0xff]), data]);
        });
        send(Buffer.concat([header, msg.subarray(12, pos + 5), ...answers]));
    };
    if (qtype === 16) {
        txtQueries.push(`${tcp ? 'tcp:' : ''}${name}`);
        const records = txtAnswers[name] ?? [];
        if (!tcp && records.flat().join('').length > 512) reply(0, [], { flags: 0x8380, type: 16 });
        else reply(0, records, { type: 16 });
        return;
    }
    dnsQueries.push(name);
    if (name === 'dnsdrop.example' && !dnsQueries.slice(0, -1).includes(name)) return; // lose the first query
    if (mxAnswers[name]) reply(0, mxAnswers[name]);
    else if (name === 'dnsnx.example') reply(3);
    else if (name === 'dnsnull.example') reply(0, [[0, '.']]);
    else if (name === 'dnsfail.example') reply(2);
    else if (name === 'dnstrunc.example') reply(0, [], { flags: 0x8380 });
    else if (name === 'dnsspoof.example') { reply(0, [[10, 'mx1.mail.example']], { id: msg.readUInt16BE(0) ^ 0xffff }); reply(0); }
    else if (name !== 'dnsslow.example') reply(0);
}
dns.on('message', (msg, peer) => answerDns(msg, out => dns.send(out, peer.port, peer.address)));
await new Promise(resolve => dns.bind(0, container ? '0.0.0.0' : '127.0.0.1', resolve));
const dnsTcp = createTcpServer(socket => socket.once('data', chunk => answerDns(chunk.subarray(2), out => socket.end(Buffer.concat([Buffer.from([out.length >> 8, out.length & 0xff]), out])), true)).on('error', () => {}));
await new Promise(resolve => dnsTcp.listen(dns.address().port, container ? '0.0.0.0' : '127.0.0.1', resolve));
const registered = '2026-11-01T00:00:00Z';
const rdapRequests = [];
const rdap = createServer((req, res) => {
    const name = req.url.replace('/rdap/domain/', '');
    rdapRequests.push(name);
    if (req.headers.accept !== 'application/rdap+json') { res.writeHead(400).end(); return; }
    const domain = (ldhName, events) => res.writeHead(200, { 'content-type': 'application/rdap+json' }).end(JSON.stringify({ objectClassName: 'domain', ldhName, events }));
    if (name === 'rdapfound.example') domain('RDAPFOUND.EXAMPLE', [{ eventAction: 'expiration', eventDate: '2030-01-01T00:00:00Z' }, { eventAction: 'registration', eventDate: registered }]);
    else if (name === 'rdapnodate.example') domain(name, [{ eventAction: 'last changed', eventDate: registered }]);
    else if (name === 'rdapbadcalendar.example') domain(name, [{ eventAction: 'registration', eventDate: '2026-02-31T00:00:00Z' }]);
    else if (name === 'rdapbadoffset.example') domain(name, [{ eventAction: 'registration', eventDate: '2026-01-10T00:00:00+00:99' }]);
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
            else if (args[0] === 'SET' && args[3] === 'NX' && args[4] === 'EX') {
                if (redisStore.has(args[1])) socket.write('$-1\r\n');
                else { redisStore.set(args[1], args[2]); socket.write('+OK\r\n'); }
            }
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
const child = spawn(container ? 'docker' : values.binary, args, {
	env: {
		...process.env,
		OPENFINGERPRINT_LISTEN_ADDR: container ? '0.0.0.0:8180' : '127.0.0.1:0',
		OPENFINGERPRINT_SITES: legacySites,
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
const shortId = (hex) => Buffer.from(hex, 'hex').subarray(0, 16).toString('base64url').slice(0, 21);
const digest = (s) => createHash('sha256').update(s).digest('hex');
let tokenCounter = 0;
function signals(locale = 'same', font = 'same', version = 1) {
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
		// Each call is a new collection: identical content would count as a replayed token.
		durationMs: 5 + (tokenCounter++ % 1000) / 1000,
		timings: { fontPreferences: { durationMs: 1, blockingMs: 0.1 } }
	};
}
let origin;
const plain = (value) => value && typeof value === 'object' && !Array.isArray(value);
const prepared = (path, body) =>
	path === '/v1/check' && plain(body)
		? { detail: true, ...body, ...(plain(body.signals) ? { signals: seal(body.signals) } : {}) }
		: body;
async function request(path, headers, body, method = 'POST') {
	return fetch(origin + path, {
		method,
		headers: { 'content-type': 'application/json', ...headers },
		...(body === undefined ? {} : { body: typeof body === 'string' ? body : JSON.stringify(prepared(path, body)) }),
		signal: AbortSignal.timeout(10000)
	});
}

const camelKey = k => k.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());
const camel = o => Object.fromEntries(Object.entries(o).map(([k, v]) => [camelKey(k), v]));
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
            return { ...camel(meta), status: sourceStatus };
        });
        result[camelKey(field)] = fact;
    }
    result.cheapTld = { value: null, status: 'unknown_tld', ...overrides.cheapTld, scope: 'tld_registration_price' };
    result.suggestedDomain = overrides.did_you_mean ?? null;
    result.mxLookup = overrides.mx_lookup ?? 'no_records';
    if (overrides.mx_providers) result.mxProviders = overrides.mx_providers;
    result.registration = overrides.registration ?? { status: 'not_found' };
    result.spf = overrides.spf ?? { status: overrides.mx_lookup === 'not_needed' ? 'not_needed' : 'none' };
    result.dmarc = overrides.dmarc ?? { status: overrides.mx_lookup === 'not_needed' ? 'not_needed' : 'none' };
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
    for (const path of ['/v1/challenges', '/v1/collect', '/v1/events/consume'])
        for (const method of ['GET', 'POST']) assert.equal((await request(path, {}, undefined, method)).status, 404, `${method} ${path} was removed`);
    for (const path of ['/v1/check', '/v1/verify']) {
        assert.equal((await request(path, {}, undefined, 'GET')).status, 405);
        assert.equal((await request(path, {}, undefined, 'OPTIONS')).status, 405);
    }
    console.log('Health, check and verification routes are available; the challenge-bound collection routes are gone.');

    phase = 'no authentication and no browser access';
    for (const path of ['/v1/check', '/v1/verify']) {
        for (const [index, headers] of [{}, { Authorization: 'Bearer ignored' }, { Authorization: 'Basic abc' }, { 'X-Site-Key': 'ignored' }].entries()) {
            phase = `credentials are neither required nor read: ${path} case ${index}`;
            const response = await request(path, headers, 'not-json');
            assert.equal(response.status, 400, 'parsed, not authenticated');
            assert.deepEqual(await response.json(), { error: 'invalid_request' });
        }
        phase = `oversized body: ${path}`;
        assert.equal((await request(path, {}, 'x'.repeat(65537))).status, 413);
        phase = `browser Origin rejection: ${path}`;
        for (const headers of [{ Origin: 'https://alpha.test' }, { Origin: 'https://alpha.test', Authorization: 'Bearer ignored' }]) {
            const forbidden = await request(path, headers, 'not-json');
            assert.equal(forbidden.status, 403);
            assert.deepEqual(await forbidden.json(), { error: 'origin_not_allowed' });
            assert.equal(forbidden.headers.get('access-control-allow-origin'), null);
            assert.equal(forbidden.headers.get('cache-control'), 'no-store');
        }
    }
    assert(serverOutput.includes('OPENFINGERPRINT_SITES is ignored'), 'the old setting is reported, not silently dropped');
    console.log('Requests need no credentials, ignore any that are sent, and refuse browser origins.');

    phase = 'canonical profiles for both supported schemas';
    for (const version of [1]) {
        const input = signals('same', 'same', version);
        delete input.timings;
        delete input.storageId;
        for (const headers of [{}, { Authorization: 'Bearer ignored' }]) {
            const response = await request('/v1/verify', headers, input);
            assert.equal(response.status, 200);
            assert.equal(response.headers.get('cache-control'), 'no-store');
            assert.equal(response.headers.get('set-cookie'), null);
            assert.equal(response.headers.get('access-control-allow-origin'), null);
            assert.deepEqual(await response.json(), {
                status: 'ok', schema_version: version, fingerprint: shortId(input.fingerprint)
            });
        }
        assert.equal((await request('/v1/verify', {}, {
            ...input, coreFingerprint: null
        })).status, 200);
        const different = signals('different', 'different', version);
        await request('/v1/verify', {}, different);
        const repeated = await request('/v1/verify', {}, input);
        assert.deepEqual(await repeated.json(), {
            status: 'ok', schema_version: version, fingerprint: shortId(input.fingerprint)
        });
    }
    assert.notEqual(signals('same', 'same', 1).fingerprint, signals('same', 'same', 2).fingerprint);
    for (const insufficient of [
        { ...signals(), fingerprint: null },
        { ...signals(), fingerprint: null, coreFingerprint: null, components: {}, hints: {} }
    ]) {
        const response = await request('/v1/verify', {}, insufficient);
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), {
            status: 'insufficient_signals', schema_version: null, fingerprint: null
        });
    }
    console.log('Canonical schema-1 profiles, repeat verification and unknown/core-only identities passed.');

    phase = 'token replay and age';
    const send = async (token) => (await fetch(origin + '/v1/check', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ signals: token })
    })).json();
    const collection = { ...signals('replay', 'replay'), collectedAt: Date.now() - 90000 };
    const token = seal(collection);
    const first = await send(token);
    assert.equal(first.fingerprint, shortId(collection.fingerprint));
    assert.equal(first.replayed, false);
    assert(first.tokenAgeMs >= 90000 && first.tokenAgeMs < 100000, 'age by the browser clock');
    assert.equal((await send(token)).replayed, true, 'the same token again');
    assert.equal((await send(seal(collection))).replayed, true, 'the same evidence under a new random prefix');
    assert.equal((await send(seal({ ...collection, durationMs: collection.durationMs + 1 }))).replayed, false, 'new evidence is new');
    const ahead = await send(seal({ ...signals('ahead', 'ahead'), collectedAt: Date.now() + 5000 }));
    assert(ahead.tokenAgeMs < 0 && ahead.tokenAgeMs > -6000, 'a browser clock that is ahead gives a negative age');
    const old = await send(seal(signals('old', 'old')));
    assert.equal(old.replayed, false);
    assert.equal(old.tokenAgeMs, undefined, 'tokens from SDKs without a collection time have no age');
    for (const collectedAt of [-1, 2e15, 'now']) {
        assert.deepEqual(await send(seal({ ...signals(), collectedAt })), { fingerprint: null, invalid: ['signals'] });
    }
    assert.deepEqual(await send(seal({ nope: 1 })), { fingerprint: null, invalid: ['signals'] });
    const verified = { ...signals('verify', 'verify'), collectedAt: Date.now() };
    for (let i = 0; i < 2; i++) assert.equal((await request('/v1/verify', {}, verified)).status, 200);
    assert.equal((await send(seal(verified))).replayed, false, '/v1/verify never marks a token');
    const detailed = await (await request('/v1/check', {}, { signals: { ...signals('detail', 'detail'), collectedAt: Date.now() } })).json();
    assert.equal(detailed.signals.replayed, false);
    assert(Number.isInteger(detailed.signals.tokenAgeMs));
    console.log('Replayed tokens (even resealed), token age, old tokens, invalid collection times and verify isolation passed.');

    phase = 'independent requested checks and explicit unconfigured intelligence';
    const unknown = { status: 'unknown', reason: 'not_configured', network: { status: 'unknown', reason: 'non_global_ip', source: 'backend_supplied' } };
    const checkedProfile = input => ({
        status: 'ok', schema_version: input.version, fingerprint: shortId(input.fingerprint),
        evidence: { includedComponents: 2, includedHints: 1, unavailableProbes: 3, excludedProbes: 3 },
        replayed: false
    });
    for (const version of [1]) {
        const input = signals('same', 'same', version);
        const response = await request('/v1/check', {}, { signals: input });
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), { signals: checkedProfile(input) });
    }
    const automation = { version: 1, webdriver: true, headlessUserAgent: false, seleniumArtifacts: false, phantomArtifacts: false };
    const automationExpected = {
        status: 'detected', ruleVersion: 1, source: 'client_reported',
        indicators: ['webdriver'], unavailableProbes: []
    };
    const fields = { signals: signals(), domain: 'ExAmPlE.test.', ip: '2001:db8::1', automation };
    for (let mask = 1; mask < 16; mask++) {
        const selected = Object.fromEntries(Object.entries(fields).filter((_, i) => mask & (1 << i)));
        if ('signals' in selected) selected.signals = signals();
        const response = await request('/v1/check', {}, selected);
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
        [{ ...automation, webdriver: false, headlessUserAgent: true }, 'detected', ['headless_user_agent'], []],
        [{ version: 2, softwareRenderer: true, cdpDetected: false }, 'detected', ['software_renderer'], ['webdriver', 'headless_user_agent', 'selenium_artifacts', 'phantom_artifacts', 'platform_mismatch', 'missing_chrome_object', 'notification_permission_quirk', 'empty_plugins', 'empty_languages', 'zero_dimensions', 'native_function_tampering', 'worker_user_agent_mismatch']]
    ]) {
        const response = await request('/v1/check', {}, { automation: observations, signals: signals() });
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), {
            automation: { status, ruleVersion: observations.version, source: 'client_reported', indicators, unavailableProbes: unavailable },
            signals: checkedProfile(signals())
        });
    }
    for (const invalid of [false, [], 'browser', {}, { version: 3 }, { ...automation, webdriver: 'false' }, { ...automation, extra: true }]) {
        const response = await request('/v1/check', {}, { ...fields, signals: signals(), automation: invalid });
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), {
            automation: { ...automationExpected, status: 'invalid_input', indicators: [], reason: 'invalid_automation' },
            signals: checkedProfile(signals()), domain: domainExpected(), ip: unknown
        });
    }
    const invalidSignals = await request('/v1/check', {}, { automation, signals: false });
    assert.equal(invalidSignals.status, 200);
    assert.deepEqual(await invalidSignals.json(), {
        automation: automationExpected,
        signals: { status: 'invalid_input', reason: 'invalid_signals', schema_version: null, fingerprint: null, evidence: null }
    });
    const omittedAutomation = await request('/v1/check', {}, { automation: null, signals: signals() });
    assert.deepEqual(await omittedAutomation.json(), { signals: checkedProfile(signals()) });
    const legacyAutomation = await request('/v1/verify', {}, { ...signals(), automation });
    assert.equal(legacyAutomation.status, 200);
    assert.deepEqual(await legacyAutomation.json(), { status: 'ok', schema_version: 1, fingerprint: shortId(signals().fingerprint) });
    const nestedAutomation = await request('/v1/check', {}, { signals: { ...signals(), automation } });
    assert.deepEqual(await nestedAutomation.json(), { signals: { ...checkedProfile(signals()), automation: automationExpected } });
    const invalidNested = await request('/v1/check', {}, { signals: { ...signals(), automation: false } });
    assert.deepEqual(await invalidNested.json(), { signals: { ...checkedProfile(signals()), automation: { ...automationExpected, status: 'invalid_input', indicators: [], reason: 'invalid_automation' } } });
    phase = 'tampering evidence stays separate from automation and identity';
    const profile = checkedProfile(signals());
    for (const [tampering, expected] of [
        [{ version: 1, canvasReadbackAltered: false, audioRenderAltered: false }, { status: 'not_detected', indicators: [], unavailable_probes: [] }],
        [{ version: 1, canvasReadbackAltered: true, audioRenderAltered: null }, { status: 'detected', indicators: ['canvas_readback_altered'], unavailable_probes: ['audio_render_altered'] }],
        [{ version: 1 }, { status: 'unknown', indicators: [], unavailable_probes: ['canvas_readback_altered', 'audio_render_altered'] }]
    ]) {
        const response = await request('/v1/check', {}, { signals: { ...signals(), automation, tampering } });
        assert.deepEqual(await response.json(), { signals: { ...profile, automation: automationExpected, tampering: { rule_version: 1, source: 'client_reported', ...expected } } });
    }
    for (const invalid of [false, [], { version: 2 }, { version: 1, extra: true }, { version: 1, audioRenderAltered: 'true' }]) {
        const response = await request('/v1/check', {}, { signals: { ...signals(), tampering: invalid } });
        assert.deepEqual(await response.json(), { signals: { ...profile, tampering: { status: 'invalid_input', rule_version: 1, source: 'client_reported', indicators: [], unavailable_probes: [], reason: 'invalid_tampering' } } });
    }
    const withTampering = await request('/v1/check', {}, { signals: { ...signals(), tampering: { version: 1, canvasReadbackAltered: true, audioRenderAltered: true } } });
    assert.equal((await withTampering.json()).signals.fingerprint, profile.fingerprint);
    console.log('Automation rules, all 15 input combinations, unknowns, stable identities and independent failures passed.');
    const coreOnly = await request('/v1/check', {}, {
        signals: { ...signals(), fingerprint: null }, domain: 'example.test'
    });
    assert.deepEqual(await coreOnly.json(), {
        signals: { ...checkedProfile(signals()), status: 'insufficient_signals', schema_version: null, fingerprint: null },
        domain: domainExpected()
    });
    const nulls = await request('/v1/check', {}, {
        signals: null, domain: null, ip: '192.0.2.1'
    });
    assert.deepEqual(await nulls.json(), { ip: unknown });
    const compactCall = async (body) => (await fetch(origin + '/v1/check', {
        method: 'POST', headers: { 'content-type': 'application/json', ...{} }, body: JSON.stringify(body)
    })).json();
    const compactResult = await compactCall({
        signals: seal({ ...signals(), automation: { version: 1, webdriver: true } }),
        domain: 'mail.example', ip: '192.0.2.1'
    });
    assert.deepEqual(Object.keys(compactResult).filter(k => ['signals', 'domain', 'ip', 'email'].includes(k)), []);
    assert.equal(compactResult.fingerprint, shortId(signals().fingerprint));
    assert.match(compactResult.fingerprint, /^[A-Za-z0-9_-]{21}$/);
    assert.equal(compactResult.automation, true);
    assert.equal(compactResult.disposable, mode === 'fresh' ? true : undefined);
    assert.equal(compactResult.mx, false);
    const compactEmail = await compactCall({ email: 'Admin@mail.example' });
    assert.deepEqual(compactEmail, mode === 'fresh' ? { disposable: true, mx: false } : { mx: false });
    assert.deepEqual(await compactCall({ email: 'nope' }), { invalid: ['email'] });
    assert.deepEqual(await compactCall({ signals: 'not-a-token', ip: 'nope' }), {
        fingerprint: null, invalid: ['signals', 'ip']
    });
    assert.deepEqual(await compactCall({ signals: signals(), domain: 'mail.example' }), { fingerprint: null, invalid: ['signals'], ...await compactCall({ domain: 'mail.example' }) });
    const rpcCheck = '/openfingerprint.v1.OpenFingerprint/Check';
    const grpcCall = (fields, path = rpcCheck, headers = {}) => new Promise((resolve, reject) => {
        const session = connect(origin);
        session.on('error', reject);
        const stream = session.request({
            ':method': 'POST', ':path': path,
            'content-type': 'application/grpc', te: 'trailers', ...headers
        });
        const message = Buffer.concat(Object.entries(fields).map(([tag, text]) => {
            const value = Buffer.from(text);
            const size = value.length < 128 ? [value.length] : [(value.length & 127) | 128, value.length >> 7];
            return Buffer.concat([Buffer.from([(Number(tag) << 3) | 2, ...size]), value]);
        }));
        const frame = Buffer.alloc(5 + message.length);
        frame.writeUInt32BE(message.length, 1);
        message.copy(frame, 5);
        const chunks = [];
        let trailers;
        stream.on('response', (headers) => { trailers = headers; });
        stream.on('data', (chunk) => chunks.push(chunk));
        stream.on('trailers', (t) => { trailers = { ...trailers, ...t }; });
        stream.on('end', () => {
            session.close();
            const raw = Buffer.concat(chunks);
            const body = raw.subarray(5);
            const decoded = {};
            let i = 0;
            const varint = () => {
                let value = 0n;
                for (let shift = 0n; ; shift += 7n) {
                    const byte = body[i++];
                    value |= BigInt(byte & 127) << shift;
                    if (!(byte & 128)) return value;
                }
            };
            while (path === rpcCheck && i < body.length) {
                const field = Number(varint());
                const tag = field >> 3;
                if ((field & 7) === 0) {
                    const value = varint();
                    decoded[tag] = tag === 17 ? Number(BigInt.asIntN(64, value)) : value === 1n;
                    continue;
                }
                const length = Number(varint());
                assert(length < 128);
                const text = body.subarray(i, i + length).toString();
                i += length;
                decoded[tag] = tag === 14 ? [...(decoded[tag] ?? []), text] : text;
            }
            resolve({ status: Number(trailers?.['grpc-status'] ?? NaN), decoded, raw });
        });
        stream.on('error', reject);
        stream.end(frame);
    });
    const grpcResult = await grpcCall({ 1: seal({ ...signals(), automation: { version: 1, webdriver: true } }), 2: 'mail.example', 4: 'nope' });
    assert.equal(grpcResult.status, 0);
    assert.equal(grpcResult.decoded[1], shortId(signals().fingerprint));
    assert.equal(grpcResult.decoded[2], true);
    assert.equal(grpcResult.decoded[4], mode === 'fresh' ? true : undefined);
    assert.equal(grpcResult.decoded[8], false);
    assert.equal(grpcResult.decoded[16], false, 'replayed');
    assert.equal(grpcResult.decoded[17], undefined, 'no collection time, no age');
    assert.deepEqual(grpcResult.decoded[14], ['ip']);
    assert.equal((await grpcCall({ 2: 'mail.example' })).status, 0, 'no credentials needed');
    assert.equal((await grpcCall({ 2: 'mail.example' }, rpcCheck, { authorization: 'Bearer ignored' })).status, 0, 'and none read');
    assert.equal((await grpcCall({})).status, 3);
    const reflection = '/grpc.reflection.v1.ServerReflection/ServerReflectionInfo';
    const listed = await grpcCall({ 7: '*' }, reflection);
    assert.equal(listed.status, 0);
    assert(listed.raw.includes('openfingerprint.v1.OpenFingerprint'));
    const connectCheck = (body) => fetch(origin + rpcCheck, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body)
    });
    const viaConnect = await connectCheck({ signals: seal({ ...signals(), automation: { version: 1, webdriver: true } }), domain: 'mail.example', ip: 'nope' });
    assert.equal(viaConnect.status, 200);
    assert.deepEqual(await viaConnect.json(), { fingerprint: shortId(signals().fingerprint), replayed: false, automation: true, mx: false, ...(mode === 'fresh' ? { disposable: true } : {}), invalid: ['ip'] });
    assert.equal((await connectCheck({ ip: '8.8.8.8' })).status, 200);
    assert.equal((await connectCheck({})).status, 400);
    assert.equal((await fetch(origin + rpcCheck, { method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://evil.test' }, body: '{"ip":"8.8.8.8"}' })).status, 403);
    console.log('All 15 input combinations, requested-only results, evidence counts and domain data state passed.');
    phase = `domain classification and source scope (${mode})`;
    for (const [domain, expected] of [
        ['mail.example', { disposable: true }], ['Child.MAIL.example.', { disposable: true }],
        ['notmail.example', {}], ['good.mail.example', { disposable: false }],
        ['child.good.mail.example', { disposable: false }],
        ['disputed.mail.example', { disposable: true, disputed: true }],
        ['child.disputed.mail.example', { disposable: true }],
        ['tenant.free.example', { free_subdomain: true, ...(mode === 'fresh' ? { registration: { status: 'not_applicable' } } : {}) }], ['free.example', { free_subdomain: false }],
        ['tenant.duckdns.org', { free_subdomain: true, cheapTld: { value: false, status: 'not_cheap' }, registration: { status: 'not_applicable' } }], ['duckdns.org', { free_subdomain: false, cheapTld: { value: false, status: 'not_cheap' } }],
        ['spam.example', { spam: true }], ['child.spam.example', { spam: true }],
        ['bad.customer.example', { spam: true }], ['customer.example', {}],
        ['notbad.customer.example', {}], ['innocent.github.io', { public_suffix_excluded: true, cheapTld: { value: false, status: 'not_cheap' }, registration: { status: 'not_applicable' } }],
        ['co.uk', { cheapTld: { value: false, status: 'not_cheap' }, registration: { status: 'not_applicable' }, mx_lookup: 'not_needed' }]
    ]) {
        const response = await request('/v1/check', {}, { signals: signals(), domain });
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
        const response = await request('/v1/check', {}, { domain });
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
        ['workspace.example', { mx_lookup: 'resolved', mx_providers: [{ slug: 'google', type: 'mailbox' }, { slug: 'mimecast', type: 'gateway' }] }],
        ['ispmail.example', { mx_lookup: 'resolved', mx_providers: [{ slug: 'yahoo', type: 'mailbox' }], ...(mode === 'fresh' ? { public_mailbox: true, consumer_mx: true } : {}) }],
        ['aliasmx.example', { mx_lookup: 'resolved', mx_providers: [{ slug: 'simplelogin', type: 'forwarding' }], ...(mode === 'fresh' ? { relay: true, relay_mx: true } : {}) }],
        ['halfalias.example', { mx_lookup: 'resolved', mx_providers: [{ slug: 'simplelogin', type: 'forwarding' }] }],
        ['throwaway.example', { mx_lookup: 'resolved', mx_providers: [], ...(mode === 'fresh' ? { disposable: true, infra_mx: true } : {}) }],
        ['priyo.example', { mx_lookup: 'resolved', mx_providers: [], ...(mode === 'fresh' ? { disposable: true, infra_mx: true } : {}) }],
        ['halfthrow.example', { mx_lookup: 'resolved', mx_providers: [] }],
        ['priyohost-other.example', { mx_lookup: 'resolved', mx_providers: [] }],
        ['yahoobiz.example', { mx_lookup: 'resolved', mx_providers: [{ slug: 'yahoo', type: 'mailbox' }] }]
    ]) {
        const response = await request('/v1/check', {}, { domain });
        const want = domainExpected(expected);
        for (const [flag, field] of [['consumer_mx', 'publicMailbox'], ['relay_mx', 'relay'], ['infra_mx', 'disposable']]) {
            if (!expected[flag]) continue;
            want[field].status = 'mx_listed';
            for (const source of want[field].sources) source.status = 'not_listed';
        }
        assert.deepEqual(await response.json(), { domain: want }, domain);
    }
    console.log(`Public mailboxes (exact and consumer MX), relays (with subdomains), typo suggestions and MX providers passed (${mode}).`);

    phase = `cheap TLDs (${mode})`;
    for (const [domain, cheapTld] of [
        ['shop.xyz', { value: true, status: 'cheap' }], ['a.b.top', { value: true, status: 'cheap' }],
        ['shop.com', { value: false, status: 'not_cheap' }], ['shop.de', { value: false, status: 'not_cheap' }]
    ]) {
        const response = await request('/v1/check', {}, { domain });
        const { registration: _, ...got } = (await response.json()).domain;
        const { registration: __, ...want } = domainExpected({ cheapTld });
        assert.deepEqual(got, want, domain);
    }
    console.log(`Cheap TLD verdicts passed (${mode}).`);

    phase = `full email addresses and role accounts (${mode})`;
    for (const [email, role, expected] of [
        ['Support+EU@PublicMail.example', true, { public_mailbox: true }],
        ['no-reply@relay.example', true, { relay: true }],
        ['zq.person-7@relay.example', false, { relay: true }]
    ]) {
        const body = await (await request('/v1/check', {}, { email })).json();
        assert.deepEqual(body, { domain: domainExpected(expected), email: { status: 'checked', roleAccount: role } }, 'email case');
    }
    for (const email of ['publicmail.example', 'a@b@publicmail.example', 'a..b@publicmail.example', '"a b"@publicmail.example', 'a@localhost', 42, {}]) {
        const body = await (await request('/v1/check', {}, { email, ip: '192.0.2.1' })).json();
        assert.deepEqual(Object.keys(body).sort(), ['email', 'ip'], 'Invalid addresses run no domain check');
        assert.deepEqual(body.email, { status: 'invalid_input', reason: 'invalid_email' });
    }
    console.log(`Full email addresses: role accounts, domain checks of the address's domain and invalid addresses passed (${mode}).`);

    phase = `SPF and DMARC (${mode})`;
    for (const [domain, spf, dmarc] of [
        ['authmail.example', { status: 'found', policy: 'fail' }, { status: 'found', policy: 'reject' }],
        ['news.authmail.example', { status: 'none' }, { status: 'found', policy: 'quarantine', inherited: true }],
        ['twospf.example', { status: 'multiple' }, { status: 'none' }],
        ['badpolicy.example', { status: 'found', policy: 'fail' }, { status: 'invalid' }],
        ['bigtxt.example', { status: 'found', policy: 'fail' }, { status: 'none' }]
    ]) {
        const body = await (await request('/v1/check', {}, { domain })).json();
        assert.deepEqual([body.domain.spf, body.domain.dmarc], [spf, dmarc], domain);
    }
    assert(txtQueries.includes('bigtxt.example') && txtQueries.includes('tcp:bigtxt.example'), 'Truncated TXT answers are repeated over TCP');
    assert(txtQueries.includes('_dmarc.news.authmail.example') && txtQueries.includes('_dmarc.authmail.example'));
    assert(!txtQueries.some(name => name.endsWith('co.uk')), 'Public suffixes are not sent to DNS');
    console.log(`SPF and DMARC records, organisational-domain fallback and TCP for truncated answers passed (${mode}).`);

    phase = `RDAP registration dates (${mode})`;
    for (const [domain, registration] of [
        ['rdapfound.example', { status: 'found', registeredAtUnix: Date.parse(registered) / 1000 }],
        ['mail.rdapfound.example', { status: 'found', registeredAtUnix: Date.parse(registered) / 1000 }],
        ['rdapnodate.example', { status: 'no_date' }], ['rdapwrong.example', { status: 'unavailable' }],
        ['rdapbadcalendar.example', { status: 'no_date' }], ['rdapbadoffset.example', { status: 'no_date' }],
        ['rdapbroken.example', { status: 'unavailable' }], ['rdapmoved.example', { status: 'unavailable' }],
        ['rdapslow.example', { status: 'unavailable' }], ['example.zz', { status: 'unsupported_tld' }],
        ['mail.old.wtest', { status: 'found', registeredAtUnix: Date.parse('2001-02-03T00:00:00Z') / 1000 }],
        ['new.wtest', { status: 'not_found' }], ['busy.wtest', { status: 'unavailable' }]
    ]) {
        const started = Date.now();
        const response = await request('/v1/check', {}, { domain });
        assert(Date.now() - started < 3500);
        assert.deepEqual((await response.json()).domain.registration, registration);
    }
    assert(rdapRequests.includes('mail.example') && !rdapRequests.some(name => name.split('.').length > 2), 'RDAP must query registrable domains only');
    assert.equal(rdapRequests.filter(name => name === 'rdapfound.example').length, 1, 'Cached registrations must not reach the registry again');
    assert.equal(rdapRequests.filter(name => name === 'rdapbroken.example').length, 1);
    const rdapKeys = [...redisStore.keys()].filter(k => !k.startsWith('openfingerprint:replay:'));
    assert(rdapKeys.length > 0 && rdapKeys.every(k => /^openfingerprint:rdap:v2:[0-9a-f]{64}$/.test(k)), 'Cache keys are hashed registered domains');
    assert(![...redisStore.values()].some(v => v === 'unavailable'), 'Unavailable answers are not cached');
    assert(!rdapRequests.some(name => /github|co\.uk|duckdns\.org$/.test(name) && name !== 'duckdns.org'), 'Private-namespace tenants and public suffixes are not registrable');
    assert.deepEqual(whoisQueries, ['old.wtest', 'new.wtest', 'busy.wtest'], 'WHOIS gets the registrable domain once, then the cache answers');
    console.log(`RDAP and WHOIS registration dates, cache, registrable-domain scope, redirects, timeouts and unsupported TLDs passed (${mode}).`);

    phase = 'independent field validation and bounded envelopes';
    for (const domain of ['', 'localhost', 'https://example.test', 'person@example.test', 'example.test:80', 'a..test', 'bücher.test', 'a'.repeat(64) + '.test', {}, 42]) {
        const response = await request('/v1/check', {}, {
            signals: signals(), domain, ip: '192.0.2.1'
        });
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), {
            signals: checkedProfile(signals()), domain: { status: 'invalid_input', reason: 'invalid_domain' }, ip: unknown
        });
    }
    for (const ip of ['', 'example.test', '192.0.2.1:80', '[2001:db8::1]', '192.0.2.0/24', 'fe80::1%eth0', [], true]) {
        const response = await request('/v1/check', {}, { domain: 'example.test', ip });
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), { domain: domainExpected(), ip: { status: 'invalid_input', reason: 'invalid_ip', network: { status: 'invalid_input', reason: 'invalid_ip', source: 'backend_supplied' } } });
    }
    for (const body of [{}, { signals: null, domain: null, ip: null }, { automation: null }, [], null, 'not-json',
        { mx: ['mx.mail.example'] }, { domain: 'example.test', mx: ['mx.mail.example'] },
        { domain: 'example.test', email: 'a@example.test' },
        ...['visitor_token', 'account_id', 'userAgent', 'storageId'].map(k => ({ domain: 'example.test', [k]: 'unsolicited' }))]) {
        const response = await request('/v1/check', {}, body);
        assert.equal(response.status, 400);
        assert.deepEqual(await response.json(), { error: 'invalid_request' });
    }
    assert.equal((await request('/v1/check', {}, { domain: 'x'.repeat(65536) })).status, 413);
    console.log('Invalid fields preserve other results; malformed, empty, unsolicited and oversized envelopes are rejected.');

    phase = 'strict evidence and metadata validation';
    const input = signals();
    const invalid = [
        { ...input, fingerprint: digest('tampered') },
        { ...input, coreFingerprint: digest('tampered') },
        { ...input, version: 2 },
        { ...input, version: 0 },
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
        const response = await request('/v1/verify', {}, body);
        assert.equal(response.status, 400);
        assert.deepEqual(await response.json(), { error: 'invalid_request' });
        const check = await request('/v1/check', {}, { signals: body, domain: 'example.test' });
        assert.equal(check.status, 200);
        assert.deepEqual(await check.json(), {
            signals: { status: 'invalid_input', reason: 'invalid_signals', schema_version: null, fingerprint: null, evidence: null },
            domain: domainExpected()
        });
    }
    for (const signals of [false, [], 'not evidence']) {
        const response = await request('/v1/check', {}, { signals, ip: '192.0.2.1' });
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), {
            signals: { status: 'invalid_input', reason: 'invalid_signals', schema_version: null, fingerprint: null, evidence: null },
            ip: unknown
        });
    }
    assert.equal((await request('/v1/verify', {}, 'not-json')).status, 400);
    assert.equal((await request('/v1/verify', {}, JSON.stringify({
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
    const reloadedValue = async () => (await (await request('/v1/check', {}, { domain: 'reloaded.example' })).json()).domain.disposable?.value ?? null;
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
    assert.equal(await metric('openfingerprint_mx_lookups_total{result="resolved"}'), 16);
    assert.equal(await metric('openfingerprint_whois_lookups_total{result="found"}'), 1);
    assert.equal(await metric('openfingerprint_dns_tcp_queries_total'), 2, 'bigtxt (TXT) and dnstrunc (MX, truncated over TCP too)');
    assert(await metric('openfingerprint_txt_lookups_total{result="resolved"}') >= 6);
    assert.equal(await metric('openfingerprint_rdap_lookups_total{result="found"}'), 1);
    assert(await metric('openfingerprint_rdap_cache_total{result="hit"}') >= 1);
    assert.equal(await metric('openfingerprint_rdap_cache_total{result="error"}'), 0);
    assert(await metric('openfingerprint_replay_checks_total{result="replayed"}') >= 2);
    assert(await metric('openfingerprint_replay_checks_total{result="new"}') >= 5);
    assert.equal(await metric('openfingerprint_replay_checks_total{result="error"}'), 0);
    console.log(`Snapshot reload, last-good retention and metrics passed (${mode}).`);
    phase = 'no request or credential logging';
    for (const sensitive of [
        JSON.parse(legacySites)[0].secret_key,
        signals().fingerprint, shortId(signals().fingerprint), signals('same', 'same', 5).fingerprint,
        signals().components.fontPreferences, 'unsolicited', 'ExAmPlE.test.', 'Support+EU', 'zq.person-7', '2001:db8::1', '192.0.2.1',
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
    dnsTcp.close();
    whois.close();
    rmSync(directory, { recursive: true, force: true });
}

if (!values['domain-data-mode'] && !process.exitCode) {
    const env = { ...process.env, OPENFINGERPRINT_SITES: legacySites, OPENFINGERPRINT_LISTEN_ADDR: '127.0.0.1:0', OPENFINGERPRINT_DNS: '127.0.0.1:9' };
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

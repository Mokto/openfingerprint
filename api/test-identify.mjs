import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { request as https } from 'node:https';
import { connect as h2 } from 'node:http2';
import { connect as tcpConnect, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect as tlsConnect } from 'node:tls';
import { fileURLToPath } from 'node:url';
import { certificate } from './test-certs.mjs';

const binary = fileURLToPath(new URL('./target/debug/openfingerprint-api', import.meta.url));
const directory = mkdtempSync(join(tmpdir(), 'openfingerprint-identify-'));
const certs = join(directory, 'certs');
certificate(certs, 'default.test', true);
certificate(join(certs, 'collect.example.test'), 'collect.example.test', false);
mkdirSync(join(certs, '..data'));

const store = new Map();
let refuseNextStore = false;
const redis = createServer((socket) => {
	let buffer = '';
	socket.on('data', (chunk) => {
		buffer += chunk;
		for (;;) {
			const lines = buffer.split('\r\n');
			const count = Number(lines[0]?.slice(1));
			if (!count || lines.length < 1 + count * 2) return;
			const args = Array.from({ length: count }, (_, i) => lines[2 + i * 2]);
			buffer = lines.slice(1 + count * 2).join('\r\n');
			if (args[0] === 'GET') {
				const v = store.get(args[1]);
				socket.write(v === undefined ? '$-1\r\n' : `$${Buffer.byteLength(v)}\r\n${v}\r\n`);
			} else if (args[0] === 'SET' && args[3] === 'NX') {
				if (refuseNextStore) {
					refuseNextStore = false;
					socket.write('$-1\r\n');
				} else if (store.has(args[1])) socket.write('$-1\r\n');
				else {
					store.set(args[1], args[2]);
					socket.write('+OK\r\n');
				}
			} else socket.write('-ERR unsupported\r\n');
		}
	});
	socket.on('error', () => {});
});
await new Promise((resolve) => redis.listen(0, '127.0.0.1', resolve));

const environment = (extra) => ({
	...process.env,
	OPENFINGERPRINT_LISTEN_ADDR: '127.0.0.1:0',
	OPENFINGERPRINT_METRICS_ADDR: '127.0.0.1:0',
	OPENFINGERPRINT_DNS: '127.0.0.1:9',
	OPENFINGERPRINT_REDIS_URL: `redis://127.0.0.1:${redis.address().port}/`,
	OPENFINGERPRINT_IDENTIFY_ADDR: '127.0.0.1:0',
	OPENFINGERPRINT_IDENTIFY_CERTS: certs,
	OPENFINGERPRINT_IDENTIFY_ORIGINS: 'https://app.example.test, http://localhost:5173',
	...extra
});
const start = (extra) => {
	const child = spawn(binary, [], { env: environment(extra), stdio: ['ignore', 'pipe', 'pipe'] });
	const addresses = new Promise((resolve, reject) => {
	let output = '';
	child.stdout.on('data', (data) => {
		output += data;
		const found = (label) => new RegExp(`${label} on (127\\.0\\.0\\.1:\\d+)`).exec(output)?.[1];
		if (found('listening') && found('identify') && found('metrics'))
			resolve({ api: found('listening'), identify: found('identify'), metrics: found('metrics') });
	});
	child.on('exit', () => reject(new Error('API exited')));
	setTimeout(() => reject(new Error('API did not start')), 10000);
	});
	return { child, addresses };
};
const { child, addresses: started } = start({});
const addresses = await started;
const proxied = start({ OPENFINGERPRINT_IDENTIFY_PROXY_PROTOCOL: 'true' });
let phase = 'startup';
const [host, port] = addresses.identify.split(':');

const post = (body, headers = {}, method = 'POST', servername = 'collect.example.test') =>
	new Promise((resolve, reject) => {
		const req = https(
			{ host, port, path: '/v1/identify', method, servername, rejectUnauthorized: false, headers },
			(res) => {
				let text = '';
				res.on('data', (d) => (text += d));
				res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
			}
		);
		req.on('error', reject);
		req.end(body);
	});
const check = async (body) =>
	(await fetch(`http://${addresses.api}/v1/check`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify(body)
	}).then(async (r) => ({ status: r.status, body: await r.json() })));
const metric = async (name) => {
	const text = await (await fetch(`http://${addresses.metrics}/metrics`)).text();
	return Number(text.split('\n').find((line) => line.startsWith(name + ' '))?.split(' ')[1] ?? NaN);
};

const digest = (s) => createHash('sha256').update(s).digest('hex');
const chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36';
let counter = 0;
const evidence = () => {
	const components = { fontFallbacks: digest('fallback'), fontPreferences: digest('same') };
	const hints = { locale: digest('same') };
	const entries = (o) => Object.entries(o).sort(([a], [b]) => (a < b ? -1 : 1));
	return JSON.stringify({
		version: 1,
		fingerprint: digest('stealth-agent:1\0' + JSON.stringify({ components: entries(components), hints: entries(hints) })),
		coreFingerprint: digest('stealth-core:1\0' + JSON.stringify(entries(components))),
		components,
		hints,
		excluded: [],
		unavailable: {},
		durationMs: 5 + counter++ / 1000,
		timings: {},
		spoofing: { version: 1, userAgent: chrome, language: 'en-US', clientHints: null }
	});
};
const allowed = { origin: 'https://app.example.test', 'user-agent': chrome, 'accept-language': 'en-US,en;q=0.9' };

try {
	phase = 'origins, CORS and input checks';
	assert.equal((await post(evidence(), {})).status, 403, 'no Origin');
	assert.equal((await post(evidence(), { origin: 'https://evil.test' })).status, 403);
	const bad = await post('not evidence', allowed);
	assert.equal(bad.status, 400);
	assert.equal(bad.headers['access-control-allow-origin'], 'https://app.example.test');
	const preflight = await post('', { ...allowed, 'access-control-request-method': 'POST' }, 'OPTIONS');
	assert.equal(preflight.status, 204);
	assert.equal(preflight.headers['access-control-allow-origin'], 'https://app.example.test');
	assert.equal(preflight.headers['access-control-allow-methods'], 'POST');
	assert.equal(preflight.headers.vary, 'Origin');
	assert.equal((await post('', { origin: 'https://evil.test' }, 'OPTIONS')).status, 403);

	phase = 'an identification stores what the listener observed and /v1/check evaluates it';
	const created = await post(evidence(), allowed);
	assert.equal(created.status, 200, created.text);
	assert.equal(created.headers['cache-control'], 'no-store');
	const { identificationId } = JSON.parse(created.text);
	assert.match(identificationId, /^[A-Za-z0-9_-]{22}$/);
	assert.deepEqual([...store.keys()].filter((k) => k.startsWith('openfingerprint:identification:')).map((k) => /^openfingerprint:identification:v1:[0-9a-f]{64}$/.test(k)), [true]);
	const stored = JSON.parse([...store.values()][0]);
	assert.deepEqual(Object.keys(stored).sort(), ['createdAtMs', 'evidence', 'headers', 'ja4', 'origin']);
	assert.deepEqual(stored.headers, { userAgent: chrome, acceptLanguage: 'en-US,en;q=0.9' });
	const detail = (await check({ identificationId, detail: true })).body.identification;
	assert.equal(detail.status, 'ok');
	assert.match(detail.ja4, /^t13d\d{4}00_[0-9a-f]{12}_[0-9a-f]{12}$/, 'Node https: TLS 1.3 with SNI and no ALPN');
	assert.equal(detail.origin, 'https://app.example.test');
	assert(detail.ageMs >= 0 && detail.ageMs < 5000, 'age by the server clock');
	assert.equal(detail.replayed, false);
	// Node's handshake is a library's, but its fingerprint is only listed for the Node.js
	// versions that were measured; an unlisted one must stay unknown, never a mismatch.
	if (detail.tlsClient === null) assert.deepEqual(detail.spoofing.unavailableProbes, ['tls_mismatch']);
	else {
		assert.equal(detail.tlsClient, 'node');
		assert.deepEqual(detail.spoofing.indicators, ['tls_mismatch'], 'a Chrome token sent from a script');
	}
	const compact = (await check({ identificationId })).body;
	assert.equal(compact.replayed, true, 'the second lookup');
	assert(!('fingerprint' in compact));
	assert(!('visitorId' in compact));
	assert.match(detail.fingerprint, /^[A-Za-z0-9_-]{21}$/);

	phase = 'invalid and unknown identifications';
	for (const id of ['AAAAAAAAAAAAAAAAAAAAAA', 'short', 42])
		assert.deepEqual((await check({ identificationId: id })).body, { invalid: ['identificationId'] }, String(id));

	phase = 'HTTP/2 and certificates chosen by SNI';
	const session = h2(`https://${addresses.identify}`, { rejectUnauthorized: false, servername: 'collect.example.test' });
	const viaH2 = await new Promise((resolve, reject) => {
		const stream = session.request({ ':method': 'POST', ':path': '/v1/identify', ...allowed });
		let text = '';
		stream.on('response', (h) => stream.on('data', (d) => (text += d)).on('end', () => resolve({ status: h[':status'], text })));
		stream.on('error', reject);
		stream.end(evidence());
	});
	session.close();
	assert.equal(viaH2.status, 200);
	const viaH2Identification = (await check({ identificationId: JSON.parse(viaH2.text).identificationId, detail: true })).body.identification;
	assert.match(viaH2Identification.ja4, /^t13d\d{4}h2_/);
	const peer = (servername) =>
		new Promise((resolve, reject) => {
			const socket = tlsConnect({ host, port: Number(port), servername, rejectUnauthorized: false }, () => {
				resolve(socket.getPeerCertificate().subject.CN);
				socket.end();
			});
			socket.on('error', reject);
		});
	assert.equal(await peer('collect.example.test'), 'collect.example.test');
	assert.equal(await peer('COLLECT.example.test'), 'collect.example.test');
	assert.equal(await peer('other.test'), 'default.test');

	phase = 'behavior metrics count stored snapshots, not repeated evaluations';
	const observation = (version, sample) => `openfingerprint_behavior_observations_total{evidence="${version}",mouse_clicks="${sample}"}`;
	const patternMetric = (version, sample, pattern) => `openfingerprint_behavior_patterns_total{evidence="${version}",mouse_clicks="${sample}",pattern="${pattern}"}`;
	assert.equal(await metric(observation('missing', 'unknown')), 2);
	const flagMetric = result => `openfingerprint_suspicious_click_patterns_total{result="${result}"}`;
	assert.equal(await metric(flagMetric('unknown')), 2);
	for (const version of [1, 2]) {
		for (const [clicks, sample] of [[0, '0'], [1, '1'], [2, '2'], [3, '3_4'], [4, '3_4'], [5, '5_9'], [9, '5_9'], [10, '10_plus']]) {
			const watched = { version, watchedMs: 1200, pointerMoves: clicks, mouseClicks: clicks, clicksWithoutMovement: clicks, centeredClicks: clicks, keys: 0, instantKeys: 0, insertedTexts: 0, touches: 0, wheels: 0, untrustedEvents: 0 };
			const body = { ...JSON.parse(evidence()), behavior: watched };
			const series = observation(`v${version}`, sample);
			const before = await metric(series);
			const flagSeries = flagMetric(version === 2 && clicks >= 3 ? 'true' : 'unknown');
			const flagsBefore = await metric(flagSeries);
			const created = await post(JSON.stringify(body), allowed);
			assert.equal(created.status, 200, created.text);
			assert.equal(await metric(series), before + 1);
			const id = JSON.parse(created.text).identificationId;
			for (let i = 0; i < 3; i++) {
				const detail = (await check({ identificationId: id, detail: true })).body.identification;
				assert.equal(detail.fingerprint, viaH2Identification.fingerprint, 'behavior never changes identity');
				assert.deepEqual(detail.behavior, { status: 'observed', ruleVersion: 2, source: 'client_reported', patterns: clicks ? ['clicks_without_movement', 'centered_clicks'] : ['no_input'], suspiciousClickPattern: version === 2 && clicks >= 3 ? true : null });
			}
			assert.equal(await metric(series), before + 1, 'checks do not recount observations');
			assert.equal(await metric(flagSeries), flagsBefore + 1, 'checks do not recount flags');
			for (const pattern of clicks ? ['clicks_without_movement', 'centered_clicks'] : ['no_input'])
				assert.equal(await metric(patternMetric(`v${version}`, sample, pattern)), before + 1);
		}
	}
	const nonmatching = { version: 2, watchedMs: 1200, pointerMoves: 8, mouseClicks: 3, clicksWithoutMovement: 2, centeredClicks: 3, keys: 0, instantKeys: 0, insertedTexts: 0, touches: 0, wheels: 0, untrustedEvents: 0 };
	const falseBefore = await metric(flagMetric('false'));
	const nonmatchingPost = await post(JSON.stringify({ ...JSON.parse(evidence()), behavior: nonmatching }), allowed);
	assert.equal(nonmatchingPost.status, 200, nonmatchingPost.text);
	const nonmatchingId = JSON.parse(nonmatchingPost.text).identificationId;
	for (let i = 0; i < 3; i++) assert.equal((await check({ identificationId: nonmatchingId })).body.suspiciousClickPattern, false);
	assert.equal(await metric(flagMetric('false')), falseBefore + 1);
	const flagTotals = await Promise.all(['true', 'false', 'unknown'].map(result => metric(flagMetric(result))));
	const beforeInvalid = await metric(observation('v2', '1'));
	assert.equal((await post(JSON.stringify({ ...JSON.parse(evidence()), behavior: { version: 3 } }), allowed)).status, 400);
	assert.equal(await metric(observation('v2', '1')), beforeInvalid, 'rejected reports are not observations');
	assert.equal(await metric(observation('missing', 'unknown')), 2, 'missing is not observed zero input');

	refuseNextStore = true;
	assert.equal((await post(evidence(), allowed)).status, 503, 'failed storage is not an observation');
	assert.equal(await metric(observation('missing', 'unknown')), 2);

	assert.deepEqual(await Promise.all(['true', 'false', 'unknown'].map(result => metric(flagMetric(result)))), flagTotals, 'invalid reports and failed stores do not count flags');

	phase = 'rate limit and metrics';
	const consumed = (await Promise.all(['stored', 'invalid', 'error'].map(result => metric(`openfingerprint_identifications_total{result="${result}"}`)))).reduce((a, b) => a + b, 0);
	let limited = 0;
	for (let i = 0; i < 61 && !limited; i++) if ((await post(evidence(), allowed)).status === 429) limited = i;
	assert.equal(limited, 60 - consumed, 'the per-network limit applies after exactly 60 allowed-origin posts a minute');
	for (const [name, minimum] of [
		['openfingerprint_identifications_total{result="stored"}', 2],
		['openfingerprint_identifications_total{result="origin_refused"}', 2],
		['openfingerprint_identifications_total{result="invalid"}', 1],
		['openfingerprint_identifications_total{result="rate_limited"}', 1],
		['openfingerprint_identification_lookups_total{result="found"}', 3],
		['openfingerprint_identification_lookups_total{result="unknown"}', 1],
		['openfingerprint_identify_certificates', 2],
		['openfingerprint_http_request_duration_seconds_count{route="identify",status="2xx"}', 2]
	])
		assert((await metric(name)) >= minimum, `${name} >= ${minimum}`);

	phase = 'PROXY protocol gives the client address the rate limit uses';
	const behindProxy = (await proxied.addresses).identify.split(':');
	const viaProxy = (source) =>
		new Promise((resolve, reject) => {
			const socket = tcpConnect(Number(behindProxy[1]), behindProxy[0], () => {
				socket.write(`PROXY TCP4 ${source} 10.0.0.1 40000 443\r\n`);
				const req = https(
					{ path: '/v1/identify', method: 'POST', servername: 'collect.example.test', rejectUnauthorized: false, headers: allowed, createConnection: () => tlsConnect({ socket, servername: 'collect.example.test', rejectUnauthorized: false }) },
					(res) => res.resume().on('end', () => resolve(res.statusCode))
				);
				req.on('error', reject);
				req.end(evidence());
			});
			socket.on('error', reject);
		});
	const statuses = [];
	for (let i = 0; i < 61; i++) statuses.push(await viaProxy('198.51.100.7'));
	assert.deepEqual([statuses.slice(0, 60).every((s) => s === 200), statuses[60]], [true, 429]);
	assert.equal(await viaProxy('198.51.100.8'), 200, 'another client address has its own limit');
	const plain = await new Promise((resolve) => {
		const req = https({ host: behindProxy[0], port: behindProxy[1], path: '/v1/identify', method: 'POST', rejectUnauthorized: false, headers: allowed }, (res) => resolve(res.statusCode));
		req.on('error', () => resolve('refused'));
		req.end(evidence());
	});
	assert.equal(plain, 'refused', 'without a PROXY header the connection is dropped');

	phase = 'configuration errors stop startup';
	const empty = join(directory, 'empty');
	mkdirSync(empty);
	for (const [extra, message] of [
		[{ OPENFINGERPRINT_IDENTIFY_ADDR: undefined }, 'OPENFINGERPRINT_IDENTIFY_ADDR is required'],
		[{ OPENFINGERPRINT_IDENTIFY_CERTS: undefined }, 'OPENFINGERPRINT_IDENTIFY_CERTS is required'],
		[{ OPENFINGERPRINT_IDENTIFY_LIMIT_PER_MINUTE: '0' }, 'OPENFINGERPRINT_IDENTIFY_LIMIT_PER_MINUTE must be'],
		[{ OPENFINGERPRINT_IDENTIFY_ORIGINS: 'app.example.test' }, 'OPENFINGERPRINT_IDENTIFY_ORIGINS must be'],
		[{ OPENFINGERPRINT_IDENTIFY_PROXY_PROTOCOL: 'yes' }, 'OPENFINGERPRINT_IDENTIFY_PROXY_PROTOCOL must be'],
		[{ OPENFINGERPRINT_IDENTIFY_CERTS: empty }, 'No usable tls.crt and tls.key']
	]) {
		const env = environment(extra);
		for (const [k, v] of Object.entries(extra)) if (v === undefined) delete env[k];
		const run = spawnSync(binary, [], { env, encoding: 'utf8', timeout: 10000 });
		assert(run.status !== 0 && run.stderr.includes(message), `${message}: ${run.stderr}`);
	}
	console.log('Identify listener: origins, CORS, identifications, TLS fingerprints, SNI certificates, HTTP/2, PROXY protocol, rate limits and startup checks passed.');
} catch (error) {
	console.error(`Identify self-check failed during: ${phase}.`);
	console.error(error.message);
	process.exitCode = 1;
} finally {
	child.kill();
	proxied.child.kill();
	redis.close();
	rmSync(directory, { recursive: true, force: true });
}

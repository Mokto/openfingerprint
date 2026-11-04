import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { parseArgs } from 'node:util';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';

const { values } = parseArgs({
	options: {
		image: { type: 'string' },
		platform: { type: 'string' },
		binary: {
			type: 'string',
			default: fileURLToPath(new URL('../api/target/debug/openfingerprint-api', import.meta.url))
		}
	}
});
const key = () => randomBytes(32).toString('hex');
const sites = ['alpha', 'beta', 'quota'].map((id) => ({
	id,
	site_key: key(),
	secret_key: key(),
	origins: [`https://${id}.test`, ...(id === 'alpha' ? ['https://*.example.test', 'https://*.dc2.other.test'] : [])]
}));
assert(!values.platform || values.image, '--platform requires --image');
const container = values.image ? `openfingerprint-test-${randomBytes(8).toString('hex')}` : null;
const args = container
	? [
			'run', '--rm', '--name', container, '--read-only', '--cap-drop=ALL',
			'--security-opt=no-new-privileges', '-p', '127.0.0.1::8180',
			'--env', 'OPENFINGERPRINT_LISTEN_ADDR', '--env', 'OPENFINGERPRINT_SIGNING_KEY',
			'--env', 'OPENFINGERPRINT_SITES',
			...(values.platform ? ['--platform', values.platform] : []),
			values.image
		]
	: [];
const child = spawn(container ? 'docker' : values.binary, args, {
	env: {
		...process.env,
		OPENFINGERPRINT_LISTEN_ADDR: container ? '0.0.0.0:8180' : '127.0.0.1:0',
		OPENFINGERPRINT_SIGNING_KEY: key(),
		OPENFINGERPRINT_SITES: JSON.stringify(sites)
	},
	stdio: ['ignore', 'pipe', 'pipe']
});
let phase = 'startup';
let timer;
const base = new Promise((resolve, reject) => {
	let output = '';
	child.stdout.on('data', (data) => {
		output += data.toString();
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
child.stderr.on('data', () => {});
const digest = (s) => createHash('sha256').update(s).digest('hex');
function signals(locale = 'same', font = 'same') {
	const components = { fontFallbacks: digest('fallback'), fontPreferences: digest(font) };
	const hints = { locale: digest(locale) };
	const entries = (object) =>
		Object.entries(object).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
	return {
		version: 4,
		fingerprint: digest(
			'stealth-agent:4\0' +
				JSON.stringify({ components: entries(components), hints: entries(hints) })
		),
		coreFingerprint: digest('stealth-core:4\0' + JSON.stringify(entries(components))),
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
const collectHeaders = (site) => ({ 'x-site-key': site.site_key, Origin: site.origins[0] });
const authHeaders = (site) => ({ Authorization: `Bearer ${site.secret_key}` });
async function collect(site = sites[0], body = signals()) {
	const response = await request('/v1/collect', collectHeaders(site), body);
	assert.equal(response.status, 200);
	return (await response.json()).visitor_token;
}
async function check(site, token, email) {
	const response = await request('/v1/check', authHeaders(site), { visitor_token: token, email });
	assert.equal(response.status, 200);
	return response.json();
}
try {
	origin = await base;
	phase = 'auth before JSON parsing';
	assert.equal((await request('/v1/check', {}, 'not-json')).status, 401);
	assert.equal((await request('/v1/collect', {}, 'not-json')).status, 401);
	assert.equal(
		(await request('/v1/check', { ...authHeaders(sites[0]), Origin: sites[0].origins[0] }, {}))
			.status,
		403
	);
	phase = 'server-only stateless profile verification';
	assert.equal((await request('/v1/verify', {}, 'not-json')).status, 401);
	assert.equal((await request('/v1/verify', authHeaders({ secret_key: key() }), 'not-json')).status, 401);
	assert.equal((await request('/v1/verify', { ...authHeaders(sites[0]), Origin: sites[0].origins[0] }, 'not-json')).status, 403);
	const verifiedInput = signals();
	delete verifiedInput.timings;
	delete verifiedInput.storageId;
	for (const site of sites.slice(0, 2)) {
		const response = await request('/v1/verify', authHeaders(site), verifiedInput);
		assert.equal(response.status, 200);
		assert.equal(response.headers.get('cache-control'), 'no-store');
		assert.equal(response.headers.get('access-control-allow-origin'), null);
		assert.deepEqual(await response.json(), { status: 'ok', schema_version: 4, fingerprint: verifiedInput.fingerprint });
	}
	const fullOnly = { ...verifiedInput, coreFingerprint: null };
	assert.equal((await request('/v1/verify', authHeaders(sites[0]), fullOnly)).status, 200);
	for (const insufficient of [
		{ ...verifiedInput, fingerprint: null },
		{ ...verifiedInput, fingerprint: null, coreFingerprint: null, components: {}, hints: {} }
	]) {
		const response = await request('/v1/verify', authHeaders(sites[0]), insufficient);
		assert.equal(response.status, 200);
		assert.deepEqual(await response.json(), { status: 'insufficient_signals', schema_version: null, fingerprint: null });
	}
	for (const invalid of [
		{ ...verifiedInput, fingerprint: digest('tampered') },
		{ ...verifiedInput, coreFingerprint: digest('tampered') },
		{ ...verifiedInput, version: 2 },
		{ ...verifiedInput, storageId: 'unsolicited' },
		{ ...verifiedInput, excluded: ['canvas', 'canvas'] },
		{ ...verifiedInput, components: { fonts: 'raw' } },
		{ ...verifiedInput, account_id: 'unsolicited' }
	]) assert.equal((await request('/v1/verify', authHeaders(sites[0]), invalid)).status, 400);
	assert.equal((await request('/v1/verify', authHeaders(sites[0]), 'not-json')).status, 400);
	assert.equal((await request('/v1/verify', authHeaders(sites[0]), JSON.stringify({ padding: 'x'.repeat(65536) }))).status, 413);
	assert.equal((await request('/v1/verify', { Origin: sites[0].origins[0] }, undefined, 'OPTIONS')).status, 405);
	console.log('Server-only profile verification, nullable identities, exact canonical hashes and strict input boundaries passed.');
	phase = 'CORS origin and preflight';
	assert.equal(
		(
			await request(
				'/v1/collect',
				{ ...collectHeaders(sites[0]), Origin: 'https://beta.test' },
				signals()
			)
		).status,
		403
	);
	const preflight = await request(
		'/v1/collect',
		{
			Origin: sites[0].origins[0],
			'access-control-request-method': 'POST',
			'access-control-request-headers': 'content-type, x-site-key'
		},
		undefined,
		'OPTIONS'
	);
	assert.equal(preflight.status, 204);
	assert.equal(preflight.headers.get('access-control-allow-origin'), sites[0].origins[0]);
	assert.equal(
		(
			await request(
				'/v1/collect',
				{ Origin: 'null', 'access-control-request-method': 'POST' },
				undefined,
				'OPTIONS'
			)
		).status,
		403
	);
	assert.equal(
		(
			await request(
				'/v1/collect',
				{
					Origin: sites[0].origins[0],
					'access-control-request-method': 'POST',
					'access-control-request-headers': 'authorization'
				},
				undefined,
				'OPTIONS'
			)
		).status,
		403
	);
	phase = 'wildcard origins require HTTPS subdomain boundaries';
	for (const allowed of ['https://app.example.test', 'https://one.two.example.test', 'https://signup.dc2.other.test']) {
		const response = await request('/v1/collect', { ...collectHeaders(sites[0]), Origin: allowed }, signals());
		assert.equal(response.status, 200);
		assert.equal(response.headers.get('access-control-allow-origin'), allowed);
		await response.arrayBuffer();
		const preflight = await request('/v1/collect', {
			Origin: allowed, 'access-control-request-method': 'POST'
		}, undefined, 'OPTIONS');
		assert.equal(preflight.status, 204);
		assert.equal(preflight.headers.get('access-control-allow-origin'), allowed);
	}
	for (const denied of ['https://example.test', 'http://app.example.test', 'https://appexample.test',
		'https://app.example.test.evil.test', 'https://app.example.test:8443', 'https://*.example.test',
		'https://user@app.example.test', 'https://app.example.test/path', 'https://app.other.test']) {
		assert.equal((await request('/v1/collect', { ...collectHeaders(sites[0]), Origin: denied }, 'not-json')).status, 403);
		assert.equal((await request('/v1/collect', {
			Origin: denied, 'access-control-request-method': 'POST'
		}, undefined, 'OPTIONS')).status, 403);
	}
	assert.equal((await request('/v1/collect', { ...collectHeaders(sites[1]), Origin: 'https://app.example.test' }, signals())).status, 403);
	console.log('Authentication, exact/wildcard-origin boundaries and preflight checks passed.');
	phase = 'exact-profile repeats and normalized-email retries';
	const first = await collect();
	const a = await check(sites[0], first, 'poc.first@gmail.com');
	assert.equal(a.linking.other_emails_seen, 0);
	assert(a.linking.recorded);
	assert.equal(a.verdict, 'allow');
	const retry = await check(sites[0], first, 'pocfirst+trial@googlemail.com');
	assert.equal(retry.linking.other_emails_seen, 0);
	assert(retry.linking.recorded);
	const reused = await check(sites[0], first, 'poc.second@gmail.com');
	assert.equal(reused.linking.status, 'token_already_bound');
	assert.equal(reused.linking.other_emails_seen, null);
	const second = await collect();
	const b = await check(sites[0], second, 'poc.second@gmail.com');
	assert.equal(b.linking.other_emails_seen, 1);
	assert.equal(b.verdict, 'allow');
	phase = 'tenant-bound tokens and isolated histories';
	const wrongTenant = await check(sites[1], second, 'poc.third@gmail.com');
	assert.equal(wrongTenant.linking.status, 'invalid_token');
	assert.equal(wrongTenant.linking.other_emails_seen, null);
	const other = await collect(sites[1]);
	assert.equal((await check(sites[1], other, 'poc.third@gmail.com')).linking.other_emails_seen, 0);
	phase = 'full-profile rather than core-only matching';
	assert(signals().coreFingerprint === signals('different').coreFingerprint);
	const changed = await collect(sites[0], signals('different'));
	assert.equal(
		(await check(sites[0], changed, 'poc.fourth@gmail.com')).linking.other_emails_seen,
		0
	);
	console.log(
		'Two different email checks on the same exact profile return 0 then 1; aliases/retries do not double-count. Tenant isolation and no core-only merging passed.'
	);
	phase = 'tampered/missing/insufficient tokens fail open';
	const tampered = first.slice(0, -1) + (first.endsWith('0') ? '1' : '0');
	const bad = await check(sites[0], tampered, 'poc.fifth@gmail.com');
	assert.equal(bad.linking.status, 'invalid_token');
	assert.equal(bad.linking.other_emails_seen, null);
	assert.equal(bad.verdict, 'allow');
	const missing = await check(sites[0], undefined, 'poc.fifth@gmail.com');
	assert.equal(missing.linking.status, 'not_collected');
	const degraded = signals();
	degraded.fingerprint = null;
	degraded.coreFingerprint = null;
	degraded.components = {};
	degraded.hints = {};
	const unavailable = await collect(sites[0], degraded);
	const insufficient = await check(sites[0], unavailable, 'poc.fifth@gmail.com');
	assert.equal(insufficient.linking.status, 'insufficient_signals');
	assert.equal(insufficient.linking.other_emails_seen, null);
	phase = 'invalid email syntax does not bind observations';
	const syntaxToken = await collect(sites[0], signals('syntax'));
	const malformedEmail = await check(sites[0], syntaxToken, 'a,b@gmail.com');
	assert.equal(malformedEmail.verdict, 'block');
	assert.equal(malformedEmail.linking.status, 'invalid_email');
	assert.equal(malformedEmail.linking.other_emails_seen, null);
	assert.equal(malformedEmail.linking.recorded, false);
	const syntaxRetry = await check(sites[0], syntaxToken, 'poc.valid@gmail.com');
	assert.equal(syntaxRetry.linking.other_emails_seen, 0);
	assert.equal(syntaxRetry.linking.recorded, true);
	phase = 'atomic concurrent linking';
	const profile = signals('concurrent');
	const tokens = await Promise.all([collect(sites[0], profile), collect(sites[0], profile)]);
	const concurrent = await Promise.all(
		tokens.map((token, i) => check(sites[0], token, `poc.concurrent${i}@gmail.com`))
	);
	assert.deepEqual(concurrent.map((r) => r.linking.other_emails_seen).sort(), [0, 1]);
	phase = 'bounded strict input';
	const inconsistent = signals();
	inconsistent.fingerprint = digest('wrong');
	assert.equal((await request('/v1/collect', collectHeaders(sites[0]), inconsistent)).status, 400);
	for (const body of [
		{ ...signals(), version: 2 },
		{ ...signals(), raw: 'forbidden' },
		{ ...signals(), excluded: ['canvas', 'canvas'] },
		{ ...signals(), storageId: 'unsolicited' },
		{ ...signals(), components: { fontPreferences: 'raw-data' } },
		{ ...signals(), timings: { probe: { durationMs: -1, blockingMs: 0 } } }
	])
		assert.equal((await request('/v1/collect', collectHeaders(sites[0]), body)).status, 400);
	const oversized = await request(
		'/v1/collect',
		collectHeaders(sites[0]),
		JSON.stringify({ padding: 'x'.repeat(65536) })
	);
	assert.equal(oversized.status, 413);
	assert.equal(oversized.headers.get('cache-control'), 'no-store');
	assert.equal(oversized.headers.get('access-control-allow-origin'), sites[0].origins[0]);
	const invalid = await request('/v1/check', authHeaders(sites[0]), { email: 'a'.repeat(255) });
	assert.equal(invalid.status, 400);
	console.log(
		'Tampering, degraded collection, concurrency, strict schema/hash/metadata validation and body limits passed.'
	);
	phase = 'independent per-site verification quota';
	for (let i = 0; i < 60; i++) {
		const response = await request('/v1/verify', authHeaders(sites[2]), signals());
		assert.equal(response.status, 200);
		await response.arrayBuffer();
	}
	assert.equal((await request('/v1/verify', authHeaders(sites[2]), signals())).status, 429);
	assert.equal((await request('/v1/verify', authHeaders(sites[1]), signals())).status, 200);
	phase = 'per-site bounded rate quota';
	for (let i = 0; i < 60; i++) {
		const response = await request('/v1/collect', collectHeaders(sites[2]), signals());
		assert.equal(response.status, 200);
		await response.arrayBuffer();
	}
	assert.equal((await request('/v1/collect', collectHeaders(sites[2]), signals())).status, 429);
	assert.equal((await request('/v1/collect', collectHeaders(sites[1]), signals())).status, 200);
	console.log(
		'Per-site quotas passed. POC smoke finished; no credentials, tokens, emails or fingerprint values printed.'
	);
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
			'test -d /usr/share/licenses/openfingerprint-api/rust'
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
		`POC smoke failed during: ${phase}. Sensitive response/credential values suppressed.`
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
}

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
const sites = ['alpha', 'beta', 'quota', 'malformed', 'check', 'check_invalid', 'shared', 'invalid_signals'].map((id) => ({
    id,
    secret_key: key(),
    ...(id === 'alpha' ? { site_key: key(), origins: ['https://alpha.test'] } : {})
}));
assert(!values.platform || values.image, '--platform requires --image');
const container = values.image ? `openfingerprint-test-${randomBytes(8).toString('hex')}` : null;
const args = container
	? [
			'run', '--rm', '--name', container, '--read-only', '--cap-drop=ALL',
			'--security-opt=no-new-privileges', '-p', '127.0.0.1::8180',
			'--env', 'OPENFINGERPRINT_LISTEN_ADDR',
			'--env', 'OPENFINGERPRINT_SITES',
			...(values.platform ? ['--platform', values.platform] : []),
			values.image
		]
	: [];
delete process.env.OPENFINGERPRINT_SIGNING_KEY;
const child = spawn(container ? 'docker' : values.binary, args, {
	env: {
		...process.env,
		OPENFINGERPRINT_LISTEN_ADDR: container ? '0.0.0.0:8180' : '127.0.0.1:0',
		OPENFINGERPRINT_SITES: JSON.stringify(sites)
	},
	stdio: ['ignore', 'pipe', 'pipe']
});
let phase = 'startup';
let timer;
let serverOutput = '';
const base = new Promise((resolve, reject) => {
	let output = '';
	child.stdout.on('data', (data) => {
		serverOutput += data.toString();
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
try {
    origin = await base;
    phase = 'health and retired routes';
    const health = await request('/health', {}, undefined, 'GET');
    assert.equal(health.status, 200);
    assert.equal(await health.text(), 'ok');
    assert.equal(health.headers.get('cache-control'), 'no-store');
    assert.equal(health.headers.get('set-cookie'), null);
    for (const method of ['GET', 'POST', 'OPTIONS']) {
        const response = await request('/v1/collect', { Origin: 'https://alpha.test' }, undefined, method);
        assert.equal(response.status, 404);
        assert.equal(response.headers.get('access-control-allow-origin'), null);
    }
    for (const path of ['/v1/check', '/v1/verify']) {
        assert.equal((await request(path, {}, undefined, 'GET')).status, 405);
        assert.equal((await request(path, {}, undefined, 'OPTIONS')).status, 405);
    }
    console.log('Health, unified check and legacy verification routes are available; collection is retired.');

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
    const unknown = { status: 'unknown', reason: 'not_configured' };
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
    const fields = { signals: signals(), domain: 'ExAmPlE.test.', ip: '2001:db8::1' };
    for (let mask = 1; mask < 8; mask++) {
        const selected = Object.fromEntries(Object.entries(fields).filter((_, i) => mask & (1 << i)));
        const response = await request('/v1/check', authHeaders(sites[4]), selected);
        assert.equal(response.status, 200);
        assert.equal(response.headers.get('cache-control'), 'no-store');
        assert.equal(response.headers.get('set-cookie'), null);
        assert.equal(response.headers.get('access-control-allow-origin'), null);
        const expected = {};
        if ('signals' in selected) expected.signals = checkedProfile(selected.signals);
        if ('domain' in selected) expected.domain = unknown;
        if ('ip' in selected) expected.ip = unknown;
        assert.deepEqual(await response.json(), expected);
    }
    const coreOnly = await request('/v1/check', authHeaders(sites[4]), {
        signals: { ...signals(), fingerprint: null }, domain: 'example.test'
    });
    assert.deepEqual(await coreOnly.json(), {
        signals: { ...checkedProfile(signals()), status: 'insufficient_signals', schema_version: null, fingerprint: null },
        domain: unknown
    });
    const nulls = await request('/v1/check', authHeaders(sites[4]), {
        signals: null, domain: null, ip: '192.0.2.1'
    });
    assert.deepEqual(await nulls.json(), { ip: unknown });
    console.log('All seven input combinations, requested-only results, evidence counts and unknown intelligence passed.');

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
        assert.deepEqual(await response.json(), { domain: unknown, ip: { status: 'invalid_input', reason: 'invalid_ip' } });
    }
    for (const body of [{}, { signals: null, domain: null, ip: null }, [], null, 'not-json',
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
            domain: unknown
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

    phase = 'independent per-site quotas, including malformed authenticated requests';
    for (const [site, body, status] of [
        [sites[2], signals(), 200],
        [sites[3], 'not-json', 400]
    ]) {
        await Promise.all(Array.from({ length: 60 }, async (_, i) => {
            const path = site === sites[3] && i % 2 ? '/v1/check' : '/v1/verify';
            const response = await request(path, authHeaders(site), body);
            assert.equal(response.status, status);
            await response.arrayBuffer();
        }));
        const denied = await request('/v1/verify', authHeaders(site), signals());
        assert.equal(denied.status, 429);
        assert.deepEqual(await denied.json(), { error: 'rate_limit' });
    }
    assert.equal((await request('/v1/verify', authHeaders(sites[1]), signals())).status, 200);
    for (let i = 0; i < 60; i++) {
        const path = i % 2 ? '/v1/verify' : '/v1/check';
        const response = await request(path, authHeaders(sites[6]), i % 2 ? signals() : { domain: 'example.test' });
        assert.equal(response.status, 200);
        await response.arrayBuffer();
    }
    for (const path of ['/v1/check', '/v1/verify']) {
        const response = await request(path, authHeaders(sites[6]), 'not-json');
        assert.equal(response.status, 429);
        assert.deepEqual(await response.json(), { error: 'rate_limit' });
    }
    console.log('Independent site quotas and one shared check/verify quota passed; no sensitive values printed.');
    phase = 'no request or credential logging';
    for (const sensitive of [
        ...sites.flatMap(site => [site.secret_key, site.site_key].filter(Boolean)),
        signals().fingerprint, signals('same', 'same', 5).fingerprint,
        signals().components.fontPreferences, 'unsolicited', 'ExAmPlE.test.', '2001:db8::1', '192.0.2.1'
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
}

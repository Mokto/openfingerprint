import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { gzipSync } from 'node:zlib';
import { collect, collectAutomation } from './dist/index.js';
import { identityExclusions } from './src/policy.ts';

const { values } = parseArgs({
	allowNegative: true,
	options: {
		references: { type: 'boolean', default: true },
		chrome: { type: 'boolean', default: false },
		headed: { type: 'boolean', default: false },
		out: { type: 'string', default: '.test-results/headless.json' }
	}
});
for (const [ua, vendor, expected] of [
	['Version/17.0 Safari/605.1.15', 'Apple Computer, Inc.', true],
	['Version/26.6.1 Safari/605.1.15', 'Apple Computer, Inc.', true],
	['Version/16.6 Safari/605.1.15', 'Apple Computer, Inc.', false],
	['Chrome/156.0.0.0 Safari/537.36', 'Google Inc.', false],
	['CriOS/156.0.0.0 Safari/604.1', 'Apple Computer, Inc.', false],
	['FxiOS/143.1 Safari/604.1', 'Apple Computer, Inc.', false],
	['Version/26.0 Safari/605.1.15', 'Google Inc.', false],
	['AppleWebKit/605.1.15 Mobile/15E148', 'Apple Computer, Inc.', false]
])
	assert.equal(identityExclusions(ua, vendor).length > 0, expected);
await assert.rejects(collect(), /secure browser context/);
assert.throws(collectAutomation, /browser context/);
const require = createRequire(new URL('./package.json', import.meta.url));
const { chromium, firefox, webkit } = require('playwright-core');
const sources = { custom: await readFile(new URL('dist/index.iife.js', import.meta.url), 'utf8') };
for (const file of ['dist/index.js', 'dist/index.iife.js']) {
	const code = await readFile(new URL(file, import.meta.url), 'utf8');
	assert(code.includes('Copyright (c) 2026 Théo Mathieu'));
	assert(code.includes('Copyright (c) 2025 FingerprintJS, Inc'));
	assert(code.includes('MIT License'));
}
const runners = {
	custom:
		'async () => { const r = await OpenFingerprint.collect(); return { id: r.fingerprint, components: Object.keys(r.components).length, hints:Object.keys(r.hints).length, unavailable: r.unavailable, timings:r.timings }; }'
};
if (values.references) {
	const { build } = require('esbuild');
	const web = fileURLToPath(new URL('.', import.meta.url));
	for (const [name, contents, run] of [
		[
			'thumbmark',
			`import { Thumbmark } from '@thumbmarkjs/thumbmarkjs'; window.Reference = Thumbmark;`,
			'async () => { const r = await new Reference({logging:false}).get(); return {id:r.thumbmark,components:Object.keys(r.components).length}; }'
		],
		[
			'fpjs',
			`import FingerprintJS, {sources} from '@fingerprintjs/fingerprintjs'; window.Reference = FingerprintJS; window.fontPreferenceReference=sources.fontPreferences;`,
			'async () => { const a = await Reference.load({monitoring:false}); const r = await a.get(); return {id:r.visitorId,components:Object.keys(r.components).length}; }'
		]
	]) {
		const built = await build({
			stdin: { contents, resolveDir: web },
			bundle: true,
			write: false,
			minify: true,
			target: 'es2022',
			format: 'iife',
			logLevel: 'silent'
		});
		sources[name] = built.outputFiles[0].text;
		runners[name] = run;
	}
}
const report = {
	at: new Date().toISOString(),
	headed: values.headed,
	scope:
		'One automated host, isolated localhost profiles; library collection only, not physical-device accuracy or network latency.',
	bundles: {},
	browsers: [],
	checks: [],
	measurements: []
};
for (const [name, code] of Object.entries(sources))
	report.bundles[name] = {
		bytes: Buffer.byteLength(code),
		gzip_bytes: gzipSync(code).byteLength,
		sha256: createHash('sha256').update(code).digest('hex')
	};
let pageHeaders = {};
const collected = [];
const server = createServer((req, res) => {
	const url = new URL(req.url || '/', 'http://localhost');
	res.setHeader('Cache-Control', 'no-store');
	res.setHeader(
		'Content-Security-Policy',
		`default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src ${url.searchParams.has('collect') ? "'self'" : "'none'"}; img-src 'self' data:; frame-src 'self'; worker-src blob:`
	);
	if (req.method === 'POST' && url.pathname === '/v1/identify') {
		let body = '';
		req.on('data', (chunk) => (body += chunk));
		req.on('end', () => {
			collected.push({ body, type: req.headers['content-type'], cookie: req.headers.cookie });
			if (url.searchParams.has('hang')) return;
			res.writeHead(url.searchParams.has('fail') ? 503 : 200, { 'Content-Type': 'application/json' });
			res.end(JSON.stringify({ identificationId: url.searchParams.has('bad') ? 'x' : 'AbCdEfGhIjKlMnOpQrStU_' }));
		});
		return;
	}
	const name = url.pathname.slice(1).replace('.js', '');
	if (url.pathname === '/watch') {
		// Script the page itself compiles without a URL must not count as driver code.
		res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'unsafe-inline'; frame-src 'self'; worker-src blob:");
		res.setHeader('Content-Type', 'text/html');
		res.end(`<!doctype html><html><meta charset="utf-8"><title>watch</title><body>
<button id="target" style="width:120px;height:40px" onclick="document.querySelector('#target')">target</button><a id="link" href="javascript:void document.querySelector('#link')">link</a>
<script src="/custom.js"></script><script>OpenFingerprint.watch();</script>
<script>
document.querySelector('body'); eval("document.querySelector('body')"); new Function("document.title")();
setTimeout("document.getElementById('target')", 0);
const inline = document.createElement('script');
inline.textContent = "document.querySelector('body'); setTimeout(function () { document.body.outerHTML; }, 5)";
document.head.appendChild(inline);
document.getElementById('target').click(); document.getElementById('link').click();
setTimeout(() => OpenFingerprint.collect({ timeoutMs: 3000 }).then((r) => { window.pageOnly = r.automation.protocolScript; window.pageBehavior = r.behavior; }), 300);
</script></body></html>`);
	} else if ((req.url || '').endsWith('.js') && Object.hasOwn(sources, name)) {
		res.setHeader('Content-Type', 'text/javascript');
		res.end(sources[name]);
	} else if (Object.hasOwn(runners, name)) {
		pageHeaders = req.headers;
		res.setHeader('Content-Type', 'text/html');
		res.end(
			`<!doctype html><html><meta charset="utf-8"><body><script>window.violations=[];document.addEventListener('securitypolicyviolation', e => violations.push(e.violatedDirective))</script><script src="/${name}.js"></script><script>window.run = ${runners[name]};</script></body></html>`
		);
	} else {
		res.writeHead(404);
		res.end();
	}
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://localhost:${server.address().port}`;
const output = resolve(values.out);
await mkdir(dirname(output), { recursive: true });
const checkpoint = () => writeFile(output, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });

function valid(r) {
	assert.equal(r.version, 1);
	for (const removed of ['token', 'storageId', 'collectedAt', 'eventId']) assert(!(removed in r), removed);
	assert(Array.isArray(r.excluded));
	assert(r.fingerprint === null || /^[0-9a-f]{64}$/.test(r.fingerprint));
	assert(r.coreFingerprint === null || /^[0-9a-f]{64}$/.test(r.coreFingerprint));
	for (const map of [r.components, r.hints])
		for (const v of Object.values(map)) assert.match(v, /^[0-9a-f]{64}$/);
	assert(
		Object.values(r.unavailable).every((v) =>
			['unsupported', 'unstable', 'error', 'timeout'].includes(v)
		)
	);
	for (const k of Object.keys(r.unavailable)) assert(!(k in r.components) && !(k in r.hints));
}

try {
	for (const [name, engine, extra] of [
		...(values.chrome
			? [['chrome', chromium, { channel: 'chrome', args: ['--enable-automation'] }]]
			: []),
		['chromium', chromium, {}],
		['firefox', firefox, {}],
		['webkit', webkit, {}]
	]) {
		const browser = await engine.launch({ ...extra, headless: !values.headed, timeout: 30000 });
		const external = [];
		report.browsers.push({ name, version: browser.version() });
		const context = await browser.newContext();
		await context.route('**/*', (route) => {
			if (new URL(route.request().url()).origin !== origin) {
				external.push('blocked');
				return route.abort();
			}
			return route.continue();
		});
		const page = await context.newPage();
		const mockGpu = () => {
				const original = HTMLCanvasElement.prototype.getContext;
				const gpu = new Proxy({
					getParameter: parameter => parameter === 'MAX_VERTEX_ATTRIBS' ? (window.gpuLimit ?? 16) : 32,
					getExtension: name => name === 'WEBGL_lose_context' ? { loseContext() {} } : null,
					getShaderPrecisionFormat: () => ({ rangeMin: 127, rangeMax: 127, precision: 23 }),
					getSupportedExtensions: () => [],
				}, { get: (target, key) => key in target ? target[key] : key });
				HTMLCanvasElement.prototype.getContext = function (type, ...args) {
					return type === 'webgl' ? gpu : original.call(this, type, ...args);
				};
			};
		const fresh = async (init, arg, gpu = false) => {
			const p = await context.newPage();
			if (gpu) await p.addInitScript(mockGpu);
			if (init) await p.addInitScript(init, arg);
			await p.goto(`${origin}/custom`);
			return p;
		};
		try {
			await page.goto(`${origin}/custom`);
			const automation = await page.evaluate(() => OpenFingerprint.collectAutomation());
			assert.equal(automation.version, 7);
			assert.equal(automation.protocolScript, null, 'without watch() the trap is unobserved');
			assert.equal(automation.cdpDetected, name === 'chromium' || name === 'chrome', 'Playwright enables CDP Runtime in Chromium only');
			const headlessBrand = await page.evaluate(() =>
				!!navigator.userAgentData?.brands.some((entry) => entry.brand === 'HeadlessChrome'));
			for (const key of ['nativeFunctionTampering', 'driverArtifacts', 'engineMismatch', 'userAgentDataMismatch', 'proportionalMonospace', 'engineApiMismatch'])
				assert.equal(automation[key], false, `a clean page has no ${key}`);
			for (const [key, value] of Object.entries(automation)) assert(key === 'version' || value === null || typeof value === 'boolean', key);
			assert.equal(automation.softwareRenderer, null);
			assert.equal(automation.notificationPermissionQuirk, null);
			assert.equal(automation.workerUserAgentMismatch, null);
			assert.equal(automation.webdriver, await page.evaluate(() =>
				typeof navigator.webdriver === 'boolean' ? navigator.webdriver : null));
			if (name === 'chromium' || name === 'chrome') assert.equal(automation.webdriver, true);
			assert.equal(automation.headlessUserAgent, headlessBrand || await page.evaluate(() =>
				/\bHeadlessChrome\//.test(navigator.userAgent)));
			assert.equal(automation.seleniumArtifacts, false);
			assert.equal(automation.phantomArtifacts, false);
			for (const scenario of ['absent', 'markers', 'errors', 'unsupported', 'wrong_type']) {
				const p = await fresh((scenario) => {
					Object.defineProperty(navigator, 'webdriver', { configurable: true, get: () => {
						if (scenario === 'errors') throw new Error('unavailable');
						return scenario === 'unsupported' ? undefined : scenario === 'wrong_type' ? 'false' : false;
					} });
					Object.defineProperty(navigator, 'userAgent', { configurable: true, get: () => {
						if (scenario === 'errors') throw new Error('unavailable');
						return scenario === 'unsupported' ? '' : scenario === 'wrong_type' ? 123 :
							scenario === 'markers' ? 'Mozilla/5.0 HeadlessChrome/156.0.0.0' : 'Mozilla/5.0 Chrome/156.0.0.0';
					} });
					if (scenario === 'markers') {
						Object.defineProperty(document, '__webdriver_script_fn', { get() { throw new Error('must not execute'); } });
						Object.defineProperty(window, 'callPhantom', { get() { throw new Error('must not execute'); } });
						Object.defineProperty(window, 'cdc_adoQpoasnfa76pfcZLmcfl_Array', { get() { throw new Error('must not execute'); } });
					}
				}, scenario);
				try {
					const unreadable = ['errors', 'unsupported', 'wrong_type'].includes(scenario);
					const observed = await p.evaluate(() => OpenFingerprint.collectAutomation());
					assert.deepEqual(
						Object.fromEntries(Object.entries(observed).slice(0, 5)),
						{
							version: 7,
							webdriver: unreadable ? null : false,
							headlessUserAgent: unreadable ? null : scenario === 'markers' || headlessBrand,
							seleniumArtifacts: scenario === 'markers',
							phantomArtifacts: scenario === 'markers'
						}
					);
					assert.equal(observed.driverArtifacts, scenario === 'markers');
					if (unreadable) {
						assert.equal(observed.engineMismatch, null);
						assert.equal(observed.userAgentDataMismatch, null);
						assert.equal(observed.platformMismatch, null);
						assert.equal(observed.missingChromeObject, null);
						assert.equal(observed.emptyPlugins, null);
					}
				} finally {
					await p.close();
				}
			}
			const spoof = await fresh(() => {
				const define = (target, key, value) => Object.defineProperty(target, key, { configurable: true, get: () => value });
				define(navigator, 'userAgent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/156.0.0.0 Safari/537.36');
				define(navigator, 'platform', 'MacIntel');
				define(navigator, 'languages', []);
				define(navigator, 'plugins', []);
				define(window, 'chrome', undefined);
				define(screen, 'width', 0);
				Function.prototype.toString = function toString() { return 'function toString() {}'; };
				const measure = CanvasRenderingContext2D.prototype.measureText;
				CanvasRenderingContext2D.prototype.measureText = function measureText(text) {
					this.font = this.font.replace('monospace', 'sans-serif');
					return measure.call(this, text);
				};
			});
			try {
				const spoofed = await spoof.evaluate(() => OpenFingerprint.collectAutomation());
				for (const key of ['platformMismatch', 'missingChromeObject', 'emptyPlugins', 'emptyLanguages', 'zeroDimensions', 'nativeFunctionTampering', 'proportionalMonospace'])
					assert.equal(spoofed[key], true, key);
				const blink = name === 'chromium' || name === 'chrome';
				assert.equal(spoofed.engineMismatch, !blink, 'a Chrome user agent contradicts a non-V8 engine');
				assert.equal(spoofed.userAgentDataMismatch, blink && await spoof.evaluate(() =>
					navigator.userAgentData.brands.find((entry) => entry.brand === 'Chromium').version !== '156'));
				const collected = await spoof.evaluate(() => OpenFingerprint.collect({ timeoutMs: 5000 }));
				assert(['notificationPermissionQuirk', 'workerUserAgentMismatch'].every((key) => typeof collected.automation[key] === 'boolean'));
				assert.equal(collected.automation.workerUserAgentMismatch, true);
			} finally {
				await spoof.close();
			}
			const own = await fresh();
			try {
				const sent = pageHeaders;
				const claimed = await own.evaluate(() => OpenFingerprint.collectSpoofing());
				const collected = await own.evaluate(() => OpenFingerprint.collect({ timeoutMs: 5000 }).then((r) => r.spoofing));
				assert.deepEqual(collected, claimed);
				assert.equal(claimed.version, 1);
				assert.equal(claimed.userAgent, sent['user-agent'], 'the reported user agent is the one the browser sends');
				const primary = (tag) => tag.split(/[-_]/)[0].toLowerCase();
				if (sent['accept-language'])
					assert.equal(primary(claimed.language), primary(sent['accept-language'].split(',')[0].split(';')[0]));
				if (name === 'firefox' || name === 'webkit') {
					assert.equal(claimed.clientHints, null);
					assert.equal(sent['sec-ch-ua'], undefined);
				} else {
					const brands = [...sent['sec-ch-ua'].matchAll(/"([^"]*)";v="([^"]*)"/g)].map((m) => `${m[1]} ${m[2]}`).sort();
					assert.deepEqual(claimed.clientHints.brands.map((b) => `${b.brand} ${b.version}`).sort(), brands);
					assert.equal(`"${claimed.clientHints.platform}"`, sent['sec-ch-ua-platform']);
					assert.equal(claimed.clientHints.mobile ? '?1' : '?0', sent['sec-ch-ua-mobile']);
				}
			} finally {
				await own.close();
			}
			const unreadable = await fresh(() => {
				Object.defineProperty(navigator, 'userAgent', { configurable: true, get() { throw new Error('blocked'); } });
				Object.defineProperty(navigator, 'language', { configurable: true, get: () => 42 });
				Object.defineProperty(Navigator.prototype, 'userAgentData', { configurable: true, get: () => ({ brands: 'x', mobile: false, platform: 'X' }) });
			});
			try {
				assert.deepEqual(await unreadable.evaluate(() => OpenFingerprint.collectSpoofing()), {
					version: 1, userAgent: null, language: null, clientHints: null
				});
			} finally {
				await unreadable.close();
			}
			report.checks.push({
				browser: name,
				check: 'Spoofing evidence matches the headers the browser sends and is null when unreadable',
				passed: true
			});
			const posting = await context.newPage();
			try {
				await posting.goto(`${origin}/custom?collect`);
				collected.length = 0;
				const outcomes = await posting.evaluate(async () => {
					const run = (endpoint) => OpenFingerprint.identify({ timeoutMs: 5000, endpoint });
					const ok = await run(`${location.origin}/v1/identify`);
					const started = performance.now();
					const hung = await run(`${location.origin}/v1/identify?hang`);
					return {
						ok,
						hung: { ...hung, waitedMs: performance.now() - started },
						failed: await run(`${location.origin}/v1/identify?fail`),
						malformed: await run(`${location.origin}/v1/identify?bad`),
						refused: await Promise.all([undefined, 'ftp://x.test/v1/identify', '/v1/identify', 42].map((endpoint) =>
							OpenFingerprint.identify({ endpoint }).then(() => 'accepted', (e) => e.constructor.name)))
					};
				});
				assert.deepEqual(outcomes.ok, { identificationId: 'AbCdEfGhIjKlMnOpQrStU_' });
				const posted = JSON.parse(collected[0].body);
				valid(posted);
				assert.equal(posted.fingerprint === null || /^[0-9a-f]{64}$/.test(posted.fingerprint), true, 'the evidence is posted as JSON');
				assert.match(collected[0].type, /^text\/plain/, 'a simple request, without a CORS preflight');
				assert.equal(collected[0].cookie, undefined);
				assert.equal(outcomes.hung.identificationId, null);
				assert(outcomes.hung.waitedMs > 2500 && outcomes.hung.waitedMs < 10000, `posting gives up after 3 s: ${outcomes.hung.waitedMs}`);
				assert.deepEqual([outcomes.failed, outcomes.malformed], [{ identificationId: null }, { identificationId: null }]);
				assert.deepEqual(outcomes.refused, ['TypeError', 'TypeError', 'TypeError', 'TypeError']);
				assert.equal(collected.length, 4, 'only the valid endpoints were contacted');
			} finally {
				await posting.close();
			}
			report.checks.push({
				browser: name,
				check: 'identify() posts the evidence as text/plain JSON and returns the identification ID; failures give null',
				passed: true
			});
			const watching = await context.newPage();
			try {
				await watching.goto(`${origin}/watch`);
				await watching.waitForFunction(() => window.pageOnly !== undefined, null, { timeout: 15000 });
				const traps = name !== 'webkit';
				assert.equal(await watching.evaluate(() => window.pageOnly), traps ? false : null, 'page scripts without a URL are not driver code');
				const idle = await watching.evaluate(() => window.pageBehavior);
				assert.equal(idle.version, 1);
				assert.equal(idle.untrustedEvents, 2, 'the page clicked twice from script');
				assert.equal(idle.mouseClicks + idle.keys + idle.pointerMoves, 0);
				await watching.click('#target');
				const after = await watching.evaluate(() => {
					document.querySelector('body');
					return OpenFingerprint.collect({ timeoutMs: 3000 }).then((r) => ({ protocolScript: r.automation.protocolScript, behavior: r.behavior }));
				});
				assert.equal(after.protocolScript, traps || null, 'driver code calling a trapped method');
				assert.deepEqual([after.behavior.mouseClicks, after.behavior.clicksWithoutMovement, after.behavior.centeredClicks], [1, 1, 1], 'a driver click lands centred without movement');
				assert.equal(await watching.evaluate(() => document.querySelector('#target').id), 'target', 'trapped methods still work');
			} finally {
				await watching.close();
			}
			report.checks.push({
				browser: name,
				check: 'watch(): page scripts stay unflagged, driver evaluation is trapped (Chromium and Firefox), clicks are counted',
				passed: true
			});
			const probe = async (init, late, key = 'nativeFunctionTampering') => {
				const p = await fresh(init);
				try {
					return await p.evaluate(([late, key]) => {
						if (late) document.createElement = () => { throw new Error('blocked'); };
						return OpenFingerprint.collectAutomation()[key];
					}, [late, key]);
				} finally {
					await p.close();
				}
			};
			assert.equal(await probe(() => {
				const original = Function.prototype.toString;
				Function.prototype.toString = function toString(...args) { return original.apply(this, args); };
			}), false, 'a delegating toString wrapper, as Sentry installs, is not tampering');
			assert.equal(await probe(() => {
				const original = Function.prototype.toString;
				const masked = new WeakSet();
				Function.prototype.toString = function toString(...args) {
					return masked.has(this) ? 'function get webdriver() { [native code] }' : original.apply(this, args);
				};
				masked.add(Function.prototype.toString);
				const patched = function () { return false; };
				masked.add(patched);
				Object.defineProperty(Navigator.prototype, 'webdriver', { configurable: true, get: patched });
			}), true, 'a patched native hidden behind a masking toString is still found');
			assert.equal(await probe(() => {
				Permissions.prototype.query = function query() { return Promise.resolve({ state: 'prompt' }); };
			}), true, 'a replaced Permissions.query is found');
			assert.equal(await probe(() => {
				Permissions.prototype.query = new Proxy(Permissions.prototype.query, {});
			}), true, 'a Proxy around Permissions.query is found although toString calls it native');
			assert.equal(await probe(() => {
				Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
			}), true, 'a webdriver override on the navigator instance is found');
			assert.equal(await probe(() => {
				delete Navigator.prototype.webdriver;
			}), true, 'a deleted webdriver getter is found');
			assert.equal(await probe(() => {
				const create = document.createElement.bind(document);
				document.createElement = (tag) => {
					const element = create(tag);
					if (tag === 'iframe') Object.defineProperty(element, 'contentWindow', { get: () => window });
					return element;
				};
			}), true, 'a detached frame with a window, as puppeteer-extra-plugin-stealth fakes, is found');
			assert.equal(await probe(undefined, true), null, 'no frame means unknown, not a verdict');
			assert.equal(await probe(undefined, true, 'cdpDetected'), null, 'no frame leaves CDP unknown');
			assert.equal(await probe(() => { HTMLCanvasElement.prototype.getContext = () => null; }, false, 'proportionalMonospace'), null, 'no 2D canvas leaves monospace unknown');
			assert.equal(await probe(() => {
				Object.defineProperty(navigator, 'userAgent', { configurable: true, get: () => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/150.0.0.0 Safari/537.36' });
				delete window.CompressionStream;
			}, false, 'engineApiMismatch'), true, 'a Chrome 150 user agent without CompressionStream imitates Chrome');
			assert.equal(await probe(() => {
				Object.defineProperty(navigator, 'userAgentData', { configurable: true, get: () => ({ brands: [], mobile: false, platform: 'Windows' }) });
			}, false, 'engineApiMismatch'), true, 'a userAgentData built in script is not NavigatorUAData');
			const wrapped = await fresh(() => {
				const debug = console.debug;
				window.stackReads = 0;
				console.debug = function (...args) {
					for (const arg of args) if (arg instanceof Error) (window.stackReads++, arg.stack);
					return debug.apply(this, args);
				};
				Error.prepareStackTrace = (error) => String(error);
			});
			try {
				const observed = await wrapped.evaluate(() => {
					const prepare = Error.prepareStackTrace;
					const cdp = OpenFingerprint.collectAutomation().cdpDetected;
					return { cdp, stackReads: window.stackReads, untouched: Error.prepareStackTrace === prepare };
				});
				assert.deepEqual(observed, { cdp: name === 'chromium' || name === 'chrome', stackReads: 0, untouched: true });
			} finally {
				await wrapped.close();
			}
			report.checks.push({
				browser: name,
				check: 'Native function and CDP probes ignore page wrappers, leave page globals alone, find masked, proxied, deleted and instance patches and are unknown without a frame',
				passed: true
			});
			// Playwright installs an exposed function's binding in every page of its context.
			const isolated = await browser.newContext();
			try {
				const bound = await isolated.newPage();
				await bound.exposeFunction('reportBack', () => true);
				await bound.goto(`${origin}/custom`);
				assert.equal(await bound.evaluate(() => OpenFingerprint.collectAutomation().driverArtifacts), true, 'a Playwright binding is a driver artifact');
			} finally {
				await isolated.close();
			}
			const background = await fresh(() => {
				Object.defineProperty(window, 'outerWidth', { configurable: true, get: () => 0 });
				Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'hidden' });
			});
			try {
				assert.equal(await background.evaluate(() => OpenFingerprint.collectAutomation().zeroDimensions), null, 'a hidden tab with a 0x0 window is unknown');
			} finally {
				await background.close();
			}
			report.checks.push({
				browser: name,
				check: 'Automation observations isolate throwing/missing properties and never execute artifact getters',
				passed: true
			});
			const clean = await page.evaluate(() => OpenFingerprint.collect({ timeoutMs: 5000 }).then(r => r.tampering));
			assert.deepEqual(clean, { version: 1, canvasReadbackAltered: false, audioRenderAltered: false });
			const noisy = await fresh(() => {
				const read = CanvasRenderingContext2D.prototype.getImageData;
				CanvasRenderingContext2D.prototype.getImageData = function (...args) {
					const image = read.apply(this, args);
					image.data[0] ^= 1;
					return image;
				};
				const channel = AudioBuffer.prototype.getChannelData;
				AudioBuffer.prototype.getChannelData = function (...args) {
					const data = channel.apply(this, args);
					for (let i = 0; i < data.length; i += 97) data[i] += 1e-7;
					return data;
				};
			});
			try {
				const injected = await noisy.evaluate(() => OpenFingerprint.collect({ timeoutMs: 5000 }).then(r => r.tampering));
				assert.deepEqual(injected, { version: 1, canvasReadbackAltered: true, audioRenderAltered: true });
				const blocked = await fresh(() => {
					CanvasRenderingContext2D.prototype.getImageData = () => { throw new Error('blocked'); };
					window.OfflineAudioContext = undefined;
					window.webkitOfflineAudioContext = undefined;
				});
				try {
					const unreadable = await blocked.evaluate(() => OpenFingerprint.collect({ timeoutMs: 5000 }).then(r => r.tampering));
					assert.deepEqual(unreadable, { version: 1, canvasReadbackAltered: null, audioRenderAltered: null });
				} finally {
					await blocked.close();
				}
			} finally {
				await noisy.close();
			}
			report.checks.push({
				browser: name,
				check: 'Tampering probes read exact on clean canvas/audio, flag injected noise and report null when blocked',
				passed: true
			});
			const a = await page.evaluate(() => OpenFingerprint.collect({ timeoutMs: 5000 }));
			valid(a);
			const { notificationPermissionQuirk, workerUserAgentMismatch, softwareRenderer, ...rest } = a.automation;
			for (const [key, value] of Object.entries(rest)) assert.equal(value, automation[key], key);
			for (const value of [notificationPermissionQuirk, workerUserAgentMismatch, softwareRenderer])
				assert(value === null || typeof value === 'boolean');
			assert(!('webdriver' in a.hints));
			assert(
				a.fingerprint,
				`${name}: no initial ID ${JSON.stringify({ durationMs: a.durationMs, unavailable: a.unavailable, components: Object.keys(a.components), timings: a.timings })}`
			);
			const b = await page.evaluate(() => OpenFingerprint.collect({ timeoutMs: 1000 }));
			valid(b);
			await page.evaluate(() => {
				Object.defineProperty(navigator, 'languages', {
					value: [navigator.language],
					configurable: true
				});
				const offset = new Date().getTimezoneOffset();
				Date.prototype.getTimezoneOffset = () => offset - 60;
			});
			const reducedLanguages = await page.evaluate(() =>
				OpenFingerprint.collect({ timeoutMs: 1000 })
			);
			valid(reducedLanguages);
			assert.equal(reducedLanguages.fingerprint, a.fingerprint);
			report.checks.push({
				browser: name,
				check: 'incognito-style language-list reduction and DST offset shift keep the full ID',
				passed: true
			});
			await page.evaluate(() => {
				Object.defineProperty(navigator, 'language', { value: 'zz-ZZ', configurable: true });
			});
			const localeOnly = await page.evaluate(() => OpenFingerprint.collect({ timeoutMs: 5000 }));
			valid(localeOnly);
			assert.notEqual(localeOnly.fingerprint, a.fingerprint);
			assert.equal(localeOnly.coreFingerprint, a.coreFingerprint);
			assert.deepEqual(localeOnly.components, a.components);
			assert.notEqual(localeOnly.hints.locale, a.hints.locale);
			for (const key of Object.keys(a.hints).filter((key) => key !== 'locale'))
				assert.equal(localeOnly.hints[key], a.hints[key], key);
			report.checks.push({
				browser: name,
				check: 'A language-only change alters only the locale hint and full fingerprint',
				passed: true
			});
			await page.evaluate(() => {
				Object.defineProperty(screen, 'width', { value: 999, configurable: true });
				Object.defineProperty(navigator, 'hardwareConcurrency', { value: 1, configurable: true });
			});
			const changedHints = await page.evaluate(() => OpenFingerprint.collect({ timeoutMs: 1000 }));
			assert.notDeepEqual(a.hints, changedHints.hints);
			assert.equal(a.coreFingerprint, changedHints.coreFingerprint);
			assert.notEqual(a.fingerprint, changedHints.fingerprint);
			assert.equal(await page.locator('iframe').count(), 0);
			await page.reload();
			await page.evaluate(() => {
				localStorage.clear();
				sessionStorage.clear();
			});
			await page.evaluate(() => OpenFingerprint.collect({ timeoutMs: 1000 }));
			assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0, 'nothing is stored');
			const order = ([x], [y]) => (x < y ? -1 : x > y ? 1 : 0);
			const components = Object.entries(a.components)
				.filter(([name]) => !a.excluded.includes(name))
				.sort(order);
			const hints = Object.entries(a.hints)
				.filter(([name]) => !a.excluded.includes(name))
				.sort(order);
			const canonical = 'stealth-agent:1\0' + JSON.stringify({ components, hints });
			assert.equal(a.fingerprint, createHash('sha256').update(canonical).digest('hex'));
			assert.equal(
				a.coreFingerprint,
				createHash('sha256')
					.update('stealth-core:1\0' + JSON.stringify(components))
					.digest('hex')
			);
			report.checks.push({
				browser: name,
				check: 'hashed output, aggregate, optional namespaced storage, reload, DOM cleanup',
				passed: true
			});

			const batching = await fresh(() => {
				const now = performance.now.bind(performance);
				let offset = 0;
				window.fontCalls = 0;
				window.callsInSlice = 0;
				window.maxCallsInSlice = 0;
				window.fontYields = 0;
				window.fontCandidates = new Set();
				Object.defineProperty(performance, 'now', { value: () => now() + offset });
				const getDocument = Object.getOwnPropertyDescriptor(
					HTMLIFrameElement.prototype,
					'contentDocument'
				);
				const seen = new WeakSet();
				Object.defineProperty(HTMLIFrameElement.prototype, 'contentDocument', {
					get() {
						const doc = getDocument.get.call(this);
						if (
							doc?.defaultView &&
							this.title === 'Fraud-prevention font probe' &&
							!seen.has(doc)
						) {
							seen.add(doc);
							const proto = doc.defaultView.CanvasRenderingContext2D.prototype;
							const measure = proto.measureText;
							proto.measureText = function (...args) {
								const candidate = /^64px\s+(.+?),\s*(monospace|sans-serif|serif)$/.exec(this.font);
								if (candidate) window.fontCandidates.add(candidate[1].replace(/^["']|["']$/g, ''));
								offset += 5;
								window.fontCalls++;
								window.callsInSlice++;
								window.maxCallsInSlice = Math.max(window.maxCallsInSlice, window.callsInSlice);
								return measure.apply(this, args);
							};
						}
						return doc;
					}
				});
				const Channel = MessageChannel;
				globalThis.MessageChannel = class extends Channel {
					constructor() {
						super();
						const post = this.port2.postMessage.bind(this.port2);
						this.port2.postMessage = (...args) => {
							window.callsInSlice = 0;
							window.fontYields++;
							return post(...args);
						};
					}
				};
			});
			const batched = await batching.evaluate(async () => {
				const r = await OpenFingerprint.collect({ timeoutMs: 5000 });
				return {
					identified: !!r.fingerprint,
					fontCalls,
					maxCallsInSlice,
					fontYields,
					candidates: fontCandidates.size
				};
			});
			assert(batched.identified);
			assert(batched.fontCalls > 96);
			assert.equal(
				batched.candidates,
				96,
				'The font catalogue must still test all 96 font families'
			);
			assert.equal(
				batched.maxCallsInSlice,
				1,
				'Yield between native reads when a read consumes the slice'
			);
			assert(batched.fontYields > 12);
			assert.equal(await batching.locator('iframe').count(), 0);
			await batching.close();
			report.checks.push({
				browser: name,
				check:
					'Time-budgeted slices cover baseline, catalogue and fallback font reads without omitting measurements',
				passed: true
			});

			const paused = await fresh(() => {
				Object.defineProperty(performance, 'now', { value: () => 0 });
				const timeout = setTimeout;
				globalThis.setTimeout = (callback, ms, ...args) =>
					ms === 5000 ? 0 : timeout(callback, ms, ...args);
				const Controller = AbortController;
				globalThis.AbortController = class extends Controller {
					constructor() {
						super();
						window.collectionController = this;
					}
				};
				window.channelsCreated = 0;
				window.portsClosed = 0;
				const Channel = MessageChannel;
				globalThis.MessageChannel = class extends Channel {
					constructor() {
						super();
						window.channelsCreated++;
						for (const port of [this.port1, this.port2]) {
							const close = port.close.bind(port);
							port.close = () => {
								window.portsClosed++;
								close();
							};
						}
						this.port2.postMessage = () => {
							window.pauseQueued = true;
						};
					}
				};
			});
			await paused.evaluate(() => {
				window.pausedCollection = OpenFingerprint.collect({ timeoutMs: 5000 });
			});
			await paused.waitForFunction(() => window.pauseQueued);
			const stopped = await paused.evaluate(async () => {
				window.collectionController.abort();
				const result = await window.pausedCollection;
				return { status: result.unavailable.fonts, channelsCreated, portsClosed };
			});
			assert.equal(stopped.status, 'timeout');
			assert(stopped.channelsCreated > 0);
			assert.equal(stopped.portsClosed, stopped.channelsCreated * 2);
			assert.equal(await paused.locator('iframe').count(), 0);
			await paused.close();

			for (const expire of ['between-reads', 'during-yield']) {
				const delayed = await fresh((mode) => {
					let clock = 0;
					Object.defineProperty(performance, 'now', { value: () => clock });
					Object.defineProperty(navigator, 'userAgent', { value: 'Chrome/156', configurable: true });
					window.deadlineReads = 0;
					window.lateReads = 0;
					window.audioDisconnects = 0;
					window.abortTimerFired = false;
					window.realTimeout = setTimeout;
					globalThis.setTimeout = (callback, ms, ...args) => window.realTimeout(() => {
						if (ms === 2000) window.abortTimerFired = true;
						callback(...args);
					}, ms === 2000 ? 30000 : ms);
					globalThis.OfflineAudioContext = class {
						createOscillator() {
							return { frequency: { value: 0 }, connect() {}, start() {}, disconnect() { window.audioDisconnects++; } };
						}
						createDynamicsCompressor() {
							return { threshold: { value: 0 }, knee: { value: 0 }, ratio: { value: 0 }, connect() {}, disconnect() { window.audioDisconnects++; } };
						}
						startRendering() { return new Promise(() => {}); }
					};
					const getDocument = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentDocument');
					Object.defineProperty(HTMLIFrameElement.prototype, 'contentDocument', {
						get() {
							const doc = getDocument.get.call(this);
							if (doc?.defaultView && this.title === 'Fraud-prevention font probe') {
								doc.defaultView.HTMLCanvasElement.prototype.getContext = () => ({
									font: '',
									measureText() {
										window.deadlineReads++;
										if (clock >= 2000) window.lateReads++;
										clock += 25;
										return { width: this.font.includes(',') ? 11 : 10, actualBoundingBoxAscent: 8, actualBoundingBoxDescent: 2 };
									}
								});
							}
							return doc;
						}
					});
					if (mode === 'during-yield') {
						const Channel = MessageChannel;
						globalThis.MessageChannel = class extends Channel {
							constructor() {
								super();
								this.port1.addEventListener('message', () => { clock = 2000; }, { once: true });
							}
						};
					}
				}, expire);
				const deadline = await delayed.evaluate(async () => {
					let watchdog;
					try {
						return await Promise.race([
							OpenFingerprint.collect().then(result => ({ result, lateReads, deadlineReads, audioDisconnects, abortTimerFired })),
							new Promise(resolve => { watchdog = window.realTimeout(() => resolve({ watchdog: true }), 5000); })
						]);
					} finally { clearTimeout(watchdog); }
				});
				assert(!deadline.watchdog, 'Logical expiry must cancel pending work without waiting for a delayed timer');
				assert.equal(deadline.lateReads, 0);
				assert.equal(deadline.deadlineReads, expire === 'during-yield' ? 0 : 80);
				assert.equal(deadline.abortTimerFired, false);
				assert.equal(deadline.audioDisconnects, 4);
				assert.equal(deadline.result.fingerprint, null);
				assert.equal(deadline.result.coreFingerprint, null);
				assert.equal(deadline.result.unavailable.fonts, 'timeout');
				assert.equal(deadline.result.unavailable.audio, 'timeout');
				assert.equal(await delayed.locator('iframe').count(), 0);
				await delayed.close();
			}
			report.checks.push({ browser: name, check: 'Logical expiry before reads or after yields cancels concurrent audio even with a delayed abort timer', passed: true });

			const cancelled = await page.evaluate(() => OpenFingerprint.collect({ timeoutMs: 1 }));
			valid(cancelled);
			assert.equal(await page.locator('iframe').count(), 0);
			const rejected = await page.evaluate(async () => {
				for (const options of [
					{ timeoutMs: NaN },
					{ timeoutMs: 0 },
					{ timeoutMs: 5001 }
				]) {
					try {
						await OpenFingerprint.collect(options);
						return false;
					} catch {}
				}
				return true;
			});
			assert(rejected);
			let p = await fresh(() => {
				Object.defineProperty(globalThis, 'OfflineAudioContext', { value: undefined });
				Object.defineProperty(globalThis, 'webkitOfflineAudioContext', { value: undefined });
				HTMLCanvasElement.prototype.getContext = () => null;
				Object.defineProperty(HTMLIFrameElement.prototype, 'contentDocument', { get: () => null });
			});
			let r = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 1000 }));
			valid(r);
			for (const k of ['audio', 'canvas', 'fonts', 'fontFallbacks', 'fontPreferences', 'gpu'])
				assert.equal(r.unavailable[k], 'unsupported');
			assert.equal(r.fingerprint, null);
			await p.close();

			p = await fresh(() => {
				const Original = globalThis.OfflineAudioContext;
				if (Original) Original.prototype.startRendering = () => new Promise(() => {});
			});
			r = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 100 }));
			valid(r);
			assert.equal(r.unavailable.audio, 'timeout');
			assert(r.durationMs < 1500);
			await p.close();

			p = await fresh(() => {
				let tick = 0;
				const original = CanvasRenderingContext2D.prototype.getImageData;
				CanvasRenderingContext2D.prototype.getImageData = function (...args) {
					const data = original.apply(this, args);
					data.data[0] = ++tick % 256;
					return data;
				};
			});
			r = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 1000 }));
			valid(r);
			assert.equal(r.unavailable.canvas, 'unstable');
			assert(!r.components.canvas);
			await p.close();

			p = await fresh(() => {
				Object.defineProperty(HTMLIFrameElement.prototype, 'contentDocument', {
					get() {
						throw new Error('Denied');
					}
				});
			});
			r = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 1000 }));
			valid(r);
			assert.equal(r.unavailable.fonts, 'error');
			assert.equal(await p.locator('iframe').count(), 0);
			await p.close();
			for (const gpu of ['native', 'unsupported', 'error']) {
				p = await fresh((mode) => {
					const original = HTMLCanvasElement.prototype.getContext;
					HTMLCanvasElement.prototype.getContext = function (type, ...args) {
						if (type === 'webgl') {
							const end = performance.now() + 1100;
							while (performance.now() < end) {}
							if (mode === 'unsupported') return null;
							if (mode === 'error') throw new Error('GPU unavailable');
						}
						return original.call(this, type, ...args);
					};
				}, gpu);
				r = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 1000 }));
				valid(r);
				assert(
					r.components.fonts &&
						r.components.fontPreferences &&
						(r.excluded.includes('canvas') || r.components.canvas),
					'A slow GPU must not discard earlier trusted hashes'
				);
				if (r.excluded.includes('canvas')) assert.equal(r.unavailable.canvas, 'timeout');
				assert.equal(r.unavailable.gpu, 'timeout');
				await p.close();
			}
			for (const failure of ['render', 'start', 'fidelity']) {
				p = await fresh((mode) => {
					let count = 0;
					window.audioDisconnects = 0;
					globalThis.OfflineAudioContext = class {
						constructor(channels, length) {
							this.id = length === 4410 ? 0 : ++count;
						}
						createOscillator() {
							return {
								frequency: { value: 0 },
								connect() {},
								disconnect() {
									window.audioDisconnects++;
								},
								start() {
									if (mode === 'start') throw new Error('Denied');
								}
							};
						}
						createDynamicsCompressor() {
							return {
								threshold: { value: 0 },
								knee: { value: 0 },
								ratio: { value: 0 },
								connect() {},
								disconnect() {
									window.audioDisconnects++;
								}
							};
						}
						startRendering() {
							if (mode === 'fidelity')
								return Promise.resolve({
									getChannelData: () => new Float32Array(4096).fill(window.audioLevel ?? 0.25)
								});
							return this.id === 1 ? Promise.reject(new Error('Denied')) : new Promise(() => {});
						}
					};
				}, failure);
				r = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 1000 }));
				if (failure === 'fidelity') {
					assert(r.components.audio);
					await p.evaluate(() => {
						window.audioLevel = 0.25000003;
					});
					const precise = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 1000 }));
					assert(precise.components.audio);
					assert.notEqual(
						r.components.audio,
						precise.components.audio,
						'Small audio differences must not be rounded away'
					);
				} else {
					assert.equal(r.unavailable.audio, 'error');
					assert.equal(await p.evaluate(() => window.audioDisconnects), 4);
				}
				await p.close();
			}

			p = await fresh(undefined, undefined, true);
			const detailBefore = await p.evaluate(() => OpenFingerprint.collect());
			await p.evaluate(() => {
				const descriptor = Object.getOwnPropertyDescriptor(
					HTMLIFrameElement.prototype,
					'contentDocument'
				);
				Object.defineProperty(HTMLIFrameElement.prototype, 'contentDocument', {
					configurable: true,
					get() {
						const doc = descriptor.get.call(this);
						const proto = doc.defaultView.CanvasRenderingContext2D.prototype;
						const original = proto.measureText;
						proto.measureText = function (...args) {
							const metrics = original.apply(this, args);
							return new Proxy(metrics, {
								get(target, key) {
									return key === 'width' ? target.width + 0.125 : Reflect.get(target, key, target);
								}
							});
						};
						return doc;
					}
				});
				window.gpuLimit = 17;
			});
			const detailAfter = await p.evaluate(() => OpenFingerprint.collect());
			for (const component of ['fonts', 'fontFallbacks', 'gpu']) {
				assert(detailBefore.components[component] && detailAfter.components[component]);
				assert.notEqual(
					detailBefore.components[component],
					detailAfter.components[component],
					`${component} must preserve measured detail`
				);
			}
			await p.close();
			report.checks.push({
				browser: name,
				check:
					'font metrics, canvas fallback metrics, extra GPU limits and sub-quantization audio differences are preserved',
				passed: true
			});
			p = await fresh();
			if (sources.fpjs) await p.addScriptTag({ url: `${origin}/fpjs.js` });
			const preferenceBefore = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 5000 }));
			assert(preferenceBefore.components.fontPreferences);
			if (sources.fpjs) {
				const parity = await p.evaluate(async () => {
					const expected = await window.fontPreferenceReference();
					const bytes = await crypto.subtle.digest(
						'SHA-256',
						new TextEncoder().encode(JSON.stringify(expected))
					);
					const reference = Array.from(new Uint8Array(bytes), (b) =>
						b.toString(16).padStart(2, '0')
					).join('');
					const actual = await OpenFingerprint.collect({ timeoutMs: 5000 });
					return actual.components.fontPreferences === reference;
				});
				assert(parity, `${name}: layout-font preferences must match the pinned reference`);
			}
			await p.addStyleTag({
				content:
					'html { font-size: 48px; } body, span {font: bold 40px fantasy !important;letter-spacing:12px !important;} iframe {display:none !important;width:0 !important;height:0 !important;}'
			});
			const hostStyled = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 5000 }));
			assert.equal(
				hostStyled.components.fontPreferences,
				preferenceBefore.components.fontPreferences,
				'Host CSS must not contaminate preferences'
			);
			await p.evaluate(() => {
				const descriptor = Object.getOwnPropertyDescriptor(
					HTMLIFrameElement.prototype,
					'contentDocument'
				);
				Object.defineProperty(HTMLIFrameElement.prototype, 'contentDocument', {
					configurable: true,
					get() {
						const doc = descriptor.get.call(this);
						if (!doc) return doc;
						const proto = doc.defaultView.Element.prototype;
						if (!doc.preferencePatched) {
							doc.preferencePatched = true;
							const original = proto.getBoundingClientRect;
							proto.getBoundingClientRect = function () {
								const rect = original.call(this);
								return this.tagName === 'SPAN'
									? new Proxy(rect, {
											get: (target, key) =>
												key === 'width' ? target.width + 0.125 : Reflect.get(target, key, target)
										})
									: rect;
							};
						}
						return doc;
					}
				});
			});
			const preferenceAfter = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 5000 }));
			assert.notEqual(
				preferenceAfter.components.fontPreferences,
				preferenceBefore.components.fontPreferences,
				'DOM font differences missed by canvas must survive hashing'
			);
			assert.equal(
				preferenceAfter.components.fontFallbacks,
				preferenceBefore.components.fontFallbacks
			);
			assert.notEqual(preferenceAfter.coreFingerprint, hostStyled.coreFingerprint);
			assert.notEqual(preferenceAfter.fingerprint, hostStyled.fingerprint);
			assert.equal(await p.locator('iframe').count(), 0);
			await p.close();
			p = await fresh(() => {
				const append = Element.prototype.append;
				Element.prototype.append = function (...nodes) {
					for (const node of nodes) {
						if (
							node instanceof HTMLIFrameElement &&
							node.title === 'Fraud-prevention font preferences'
						)
							window.pendingFontFrame = node;
						else append.call(this, node);
					}
				};
			});
			const loadTimeout = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 1000 }));
			assert.equal(loadTimeout.unavailable.fontPreferences, 'timeout');
			assert(
				await p.evaluate(
					() =>
						!!window.pendingFontFrame &&
						!pendingFontFrame.isConnected &&
						pendingFontFrame.onload === null &&
						pendingFontFrame.onerror === null
				)
			);
			assert.equal(await p.locator('iframe').count(), 0);
			await p.close();
			if (sources.fpjs)
				for (const deviceScaleFactor of [1.25, 2, 3]) {
					const scaled = await browser.newContext({ deviceScaleFactor });
					try {
						const q = await scaled.newPage();
						await q.goto(`${origin}/custom`);
						await q.addScriptTag({ url: `${origin}/fpjs.js` });
						assert(
							await q.evaluate(async () => {
								const native = await window.fontPreferenceReference();
								const bytes = await crypto.subtle.digest(
									'SHA-256',
									new TextEncoder().encode(JSON.stringify(native))
								);
								const expected = Array.from(new Uint8Array(bytes), (b) =>
									b.toString(16).padStart(2, '0')
								).join('');
								const actual = await OpenFingerprint.collect({ timeoutMs: 5000 });
								return actual.components.fontPreferences === expected;
							}),
							`${name}: fractional/high-DPI calibration must match the reference`
						);
					} finally {
						await scaled.close();
					}
				}
			report.checks.push({
				browser: name,
				check:
					'Calibrated layout-font preferences, host-CSS isolation, canvas-independent distinctions, load-timeout cleanup, and optional pinned-reference parity at DPR 1/1.25/2/3. Not a physical-device test.',
				passed: true
			});
			p = await fresh(() => {
				Object.defineProperty(navigator, 'userAgent', {
					value: 'Mozilla/5.0 Version/26.6.1 Safari/605.1.15',
					configurable: true
				});
				Object.defineProperty(navigator, 'vendor', {
					value: 'Apple Computer, Inc.',
					configurable: true
				});
				for (const [key, regular, privateValue] of [
					['width', 800, 1600],
					['height', 600, 900]
				])
					Object.defineProperty(screen, key, {
						configurable: true,
						get: () => (window.privacyMode ? privateValue : regular)
					});
				Object.defineProperty(window, 'devicePixelRatio', {
					configurable: true,
					get: () => (window.privacyMode ? 3 : 1)
				});
				const image = CanvasRenderingContext2D.prototype.getImageData;
				CanvasRenderingContext2D.prototype.getImageData = function (...args) {
					const data = image.apply(this, args);
					data.data[0] = window.privacyMode ? 47 : 33;
					return data;
				};
				let count = 0;
				globalThis.OfflineAudioContext = class {
					id = ++count;
					createOscillator() {
						return { frequency: { value: 0 }, connect() {}, disconnect() {}, start() {} };
					}
					createDynamicsCompressor() {
						return {
							threshold: { value: 0 },
							knee: { value: 0 },
							ratio: { value: 0 },
							connect() {},
							disconnect() {}
						};
					}
					startRendering() {
						if (window.audioHang) return new Promise(() => {});
						const level = window.privacyMode ? 0.25 + this.id * 1e-6 : 0.25;
						return Promise.resolve({ getChannelData: () => new Float32Array(4096).fill(level) });
					}
				};
			}, undefined, true);
			const regular = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 5000 }));
			assert(
				regular.fingerprint &&
					regular.coreFingerprint &&
					regular.components.audio &&
					regular.components.canvas
			);
			assert.deepEqual(regular.excluded, ['audio', 'canvas', 'screen']);
			await p.evaluate(() => {
				window.privacyMode = true;
			});
			const privateMode = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 5000 }));
			valid(privateMode);
			assert.equal(
				privateMode.fingerprint,
				regular.fingerprint,
				'Safari policy must ignore protected diagnostic changes'
			);
			assert.equal(privateMode.coreFingerprint, regular.coreFingerprint);
			assert.notEqual(privateMode.components.canvas, regular.components.canvas);
			assert.notEqual(privateMode.hints.screen, regular.hints.screen);
			assert.equal(privateMode.hints.display, regular.hints.display);
			assert.equal(privateMode.unavailable.audio, 'unstable');
			await p.evaluate(() => { window.gpuLimit = 17; });
			const hardwareChange = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 5000 }));
			assert.notEqual(
				hardwareChange.fingerprint,
				privateMode.fingerprint,
				'Trusted GPU differences must still separate profiles'
			);
			assert.notEqual(hardwareChange.coreFingerprint, privateMode.coreFingerprint);
			await p.evaluate(() =>
				Object.defineProperty(screen, 'colorDepth', { value: 16, configurable: true })
			);
			const colorChange = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 5000 }));
			assert.notEqual(
				colorChange.fingerprint,
				hardwareChange.fingerprint,
				'Stable display information must not be discarded with geometry'
			);
			await p.evaluate(() => {
				window.audioHang = true;
			});
			const diagnosticTimeout = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 1000 }));
			assert.equal(diagnosticTimeout.automation.version, 7);
			assert(diagnosticTimeout.components.canvas);
			assert.equal(diagnosticTimeout.unavailable.audio, 'timeout');
			assert.equal(
				diagnosticTimeout.fingerprint,
				colorChange.fingerprint,
				'A diagnostic timeout must not erase a completed identity'
			);
			assert.equal(await p.locator('iframe').count(), 0);
			await p.evaluate(() => {
				window.audioHang = false;
				window.privacyMode = false;
				HTMLCanvasElement.prototype.getContext = () => null;
				Object.defineProperty(HTMLIFrameElement.prototype, 'contentDocument', {
					configurable: true,
					get: () => null
				});
			});
			const diagnosticsOnly = await p.evaluate(() => OpenFingerprint.collect({ timeoutMs: 2000 }));
			assert(diagnosticsOnly.components.audio);
			assert.equal(
				diagnosticsOnly.fingerprint,
				null,
				'Excluded diagnostic evidence alone must never mint an identity'
			);
			assert.equal(diagnosticsOnly.coreFingerprint, null);
			await p.close();
			report.checks.push({
				browser: name,
				check:
					'Simulated Safari privacy: protected diagnostics differ without splitting IDs; GPU/color-depth evidence retained; diagnostic timeouts preserve IDs. Not a physical-iPhone accuracy test.',
				passed: true
			});
			p = await fresh(() => {
				const original = crypto.subtle.digest.bind(crypto.subtle);
				window.aggregateSeen = false;
				crypto.subtle.digest = (algorithm, data) => {
					if (new TextDecoder().decode(data).startsWith('stealth-agent:1')) {
						window.aggregateSeen = true;
						return new Promise(() => {});
					}
					return original(algorithm, data);
				};
			});
			r = await p.evaluate(() =>
				Promise.race([
					OpenFingerprint.collect({ timeoutMs: 1000 }),
					new Promise((_, reject) =>
						setTimeout(() => reject(new Error('Aggregate hash exceeded deadline')), 2500)
					)
				])
			);
			assert.equal(await p.evaluate(() => window.aggregateSeen), true);
			assert.equal(r.fingerprint, null);
			assert(r.durationMs < 2000);
			await p.close();
			report.checks.push({
				browser: name,
				check:
					'invalid inputs, unavailable APIs, blocked storage, hung audio and aggregate deadlines, unstable canvas, failed iframe cleanup, slow GPU retains earlier hashes, audio setup and sibling failure cleanup',
				passed: true
			});

			for (let i = 0; i < 9; i++) {
				const libraries = Object.keys(runners);
				for (let j = 0; j < libraries.length; j++) {
					const library = libraries[(i + j) % libraries.length];
					await page.goto(`${origin}/${library}`);
					const measured = await page.evaluate(async () => {
						const start = performance.now();
						const result = await window.run();
						return {
							...result,
							elapsed_ms: Math.round((performance.now() - start) * 10) / 10,
							csp: window.violations
						};
					});
					assert(measured.id, `${name}/${library} did not return an ID`);
					assert.equal(measured.csp.length, 0);
					report.measurements.push({
						browser: name,
						library,
						round: i,
						elapsed_ms: measured.elapsed_ms,
						components: measured.components,
						...(measured.hints !== undefined ? { hint_components: measured.hints } : {}),
						unavailable: measured.unavailable || {},
						...(measured.timings ? { timings: measured.timings } : {})
					});
				}
				await checkpoint();
			}
			assert.equal(external.length, 0);
			console.log(
				`${name}: checks passed; ${9 * Object.keys(runners).length} benchmark observations; no external requests`
			);
			await checkpoint();
		} finally {
			await browser.close();
		}
	}
	await checkpoint();
	console.log(`Report: ${output}`);
} catch (error) {
	console.error(String(error.stack ?? error).replace(/[0-9a-f]{64}/gi, '[redacted]'));
	process.exitCode = 1;
} finally {
	await new Promise((r) => server.close(r));
}

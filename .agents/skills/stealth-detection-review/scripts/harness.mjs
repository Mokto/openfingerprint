#!/usr/bin/env node
// Opens a local page that runs the built SDK in each stealth/automation tool and reports which
// automation and tampering probes fire. Tools install into ~/.cache/openfingerprint-stealth at
// their latest versions, so each run tests what attackers would download that day.
//
// node harness.mjs [--sdk sdk/dist/index.iife.js] [--only name,name] [--headed] [--timeout 120]
import { spawn, execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

const { values } = parseArgs({
	options: {
		sdk: { type: 'string', default: 'sdk/dist/index.iife.js' },
		only: { type: 'string' },
		headed: { type: 'boolean', default: false },
		timeout: { type: 'string', default: '120' }
	}
});
const sdk = readFileSync(resolve(values.sdk), 'utf8');
const cache = join(homedir(), '.cache', 'openfingerprint-stealth');
mkdirSync(join(cache, 'results'), { recursive: true });
const headless = !values.headed;

// The page watches from the start; each driver reads document.title through its default
// evaluate API right after navigating, as a scraper would, before the page collects.
const PAGE = `<!doctype html><html lang="en"><head><title>probe</title></head><body><p>probe</p><script>${sdk.replace(/<\/script/gi, '<\\/script')}</script><script>
OpenFingerprint.watch();
setTimeout(async () => {
	let body;
	try {
		const r = await OpenFingerprint.collect({ timeoutMs: 5000 });
		body = { automation: r.automation, tampering: r.tampering, behavior: r.behavior, userAgent: navigator.userAgent,
			brands: navigator.userAgentData?.brands ?? null, unavailable: r.unavailable };
	} catch (error) {
		body = { error: String(error && error.stack || error) };
	}
	await fetch('/result' + location.search, { method: 'POST', body: JSON.stringify(body) });
}, 3000);
</script></body></html>`;

const visit = async (page, url) => {
	await page.goto(url);
	await page.evaluate(() => document.title);
};

// Each Node driver opens the URL and stays open; the harness closes it once the page reports.
const node = {
	'playwright-chromium': async (url, m) => {
		const browser = await m('playwright').chromium.launch({ headless });
		await visit(await browser.newPage(), url);
		return () => browser.close();
	},
	'playwright-firefox': async (url, m) => {
		const browser = await m('playwright').firefox.launch({ headless });
		await visit(await browser.newPage(), url);
		return () => browser.close();
	},
	'playwright-extra-stealth': async (url, m) => {
		const chromium = m('playwright-extra').addExtra(m('playwright').chromium);
		chromium.use(m('puppeteer-extra-plugin-stealth')());
		const browser = await chromium.launch({ headless });
		await visit(await browser.newPage(), url);
		return () => browser.close();
	},
	patchright: async (url, m) => {
		const { chromium } = m('patchright');
		const context = await chromium.launchPersistentContext(join(cache, 'patchright-profile'), { headless, viewport: null });
		await visit(await context.newPage(), url);
		return () => context.close();
	},
	'rebrowser-playwright': async (url, m) => {
		const browser = await m('rebrowser-playwright').chromium.launch({ headless });
		await visit(await browser.newPage(), url);
		return () => browser.close();
	},
	// Needs a free licence key: run `npx cloakbrowser login` in ~/.cache/openfingerprint-stealth once.
	cloakbrowser: async (url) => {
		const browser = await (await esm('cloakbrowser')).launch({ headless });
		await visit(await browser.newPage(), url);
		return () => browser.close();
	},
	clearcote: async (url) => {
		const browser = await (await esm('clearcote')).launch({ headless, fingerprint: 'openfingerprint-harness' });
		await visit(await browser.newPage(), url);
		return () => browser.close();
	},
	// Obscura is its own engine behind a CDP server, not a Chromium build; there is no headed mode.
	obscura: async (url, m) => {
		const port = 9300 + Math.floor(Math.random() * 500);
		const child = spawn(join(cache, 'obscura', 'obscura'), ['serve', '--port', String(port), '--stealth', '--allow-private-network'], { stdio: 'ignore' });
		const stop = () => child.kill('SIGKILL');
		try {
			let browser;
			for (let attempt = 0; !browser; attempt++)
				browser = await m('playwright').chromium.connectOverCDP(`ws://127.0.0.1:${port}`).catch((error) => {
					if (attempt > 20) throw error;
					return new Promise((ok) => setTimeout(ok, 500));
				});
			await visit(await (await browser.newContext()).newPage(), url);
			return async () => {
				await browser.close().catch(() => {});
				stop();
			};
		} catch (error) {
			stop();
			throw error;
		}
	}
};

// Python drivers get the URL as argv[1] and Playwright's Chrome for Testing as argv[2], and sleep
// until the harness kills their process group. The installed Google Chrome does not start under
// chromedriver or nodriver on this Mac ("unable to discover open pages"). Headed Chrome started
// without --use-mock-keychain waits on a macOS Keychain prompt and never navigates; Playwright and
// ChromeDriver pass that flag themselves.
const python = {
	// Camoufox picks a random OS to claim by default; the pinned runs make results comparable.
	'camoufox': {
		packages: ['camoufox[geoip]'],
		setup: 'import subprocess, sys; subprocess.run([sys.executable, "-m", "camoufox", "fetch"], check=True)',
		code: `import sys, time
from camoufox.sync_api import Camoufox
with Camoufox(headless=${headless ? 'True' : 'False'}) as browser:
    page = browser.new_page()
    page.goto(sys.argv[1])
    page.evaluate('document.title')
    time.sleep(600)`
	},
	'camoufox-windows': {
		packages: ['camoufox[geoip]'],
		setup: 'import subprocess, sys; subprocess.run([sys.executable, "-m", "camoufox", "fetch"], check=True)',
		code: `import sys, time
from camoufox.sync_api import Camoufox
with Camoufox(headless=${headless ? 'True' : 'False'}, os='windows') as browser:
    page = browser.new_page()
    page.goto(sys.argv[1])
    page.evaluate('document.title')
    time.sleep(600)`
	},
	'camoufox-macos': {
		packages: ['camoufox[geoip]'],
		setup: 'import subprocess, sys; subprocess.run([sys.executable, "-m", "camoufox", "fetch"], check=True)',
		code: `import sys, time
from camoufox.sync_api import Camoufox
with Camoufox(headless=${headless ? 'True' : 'False'}, os='macos') as browser:
    page = browser.new_page()
    page.goto(sys.argv[1])
    page.evaluate('document.title')
    time.sleep(600)`
	},
	'invisible-playwright': {
		packages: ['invisible-playwright'],
		setup: 'from invisible_playwright import ensure_binary; ensure_binary()',
		code: `import sys, time
from invisible_playwright import InvisiblePlaywright
with InvisiblePlaywright(headless=${headless ? 'True' : 'False'}) as browser:
    page = browser.new_page()
    page.goto(sys.argv[1])
    page.evaluate('document.title')
    time.sleep(600)`
	},
	pydoll: {
		packages: ['pydoll-python'],
		code: `import sys, asyncio
from pydoll.browser import Chrome
from pydoll.browser.options import ChromiumOptions
async def main():
    options = ChromiumOptions()
    options.binary_location = sys.argv[2]
    options.headless = ${headless ? 'True' : 'False'}
    options.add_argument('--use-mock-keychain')
    async with Chrome(options=options) as browser:
        tab = await browser.start()
        await tab.go_to(sys.argv[1])
        await tab.execute_script('document.title')
        await asyncio.sleep(600)
asyncio.run(main())`
	},
	zendriver: {
		packages: ['zendriver'],
		code: `import sys, asyncio, zendriver as zd
async def main():
    browser = await zd.start(headless=${headless ? 'True' : 'False'}, browser_executable_path=sys.argv[2], browser_args=['--use-mock-keychain'])
    tab = await browser.get(sys.argv[1], new_tab=True)
    await tab.activate()
    await tab.evaluate('document.title')
    await asyncio.sleep(600)
asyncio.run(main())`
	},
	nodriver: {
		packages: ['nodriver'],
		code: `import sys, asyncio, nodriver as uc
async def main():
    browser = await uc.start(headless=${headless ? 'True' : 'False'}, browser_executable_path=sys.argv[2], browser_args=['--use-mock-keychain'])
    # The first tab never navigates in current Chrome: nodriver picks a browser_ui target.
    tab = await browser.get(sys.argv[1], new_tab=True)
    await tab.activate()
    await tab.evaluate('document.title')
    await asyncio.sleep(600)
asyncio.run(main())`
	},
	'seleniumbase-uc': {
		packages: ['seleniumbase'],
		code: `import sys, time
from seleniumbase import Driver
driver = Driver(uc=True, headless=${headless ? 'True' : 'False'}, binary_location=sys.argv[2])
driver.uc_open_with_reconnect(sys.argv[1], 1)
driver.execute_script('return document.title')
time.sleep(600)`
	},
	'selenium-chromedriver': {
		packages: ['selenium'],
		code: `import sys, time
from selenium import webdriver
options = webdriver.ChromeOptions()
${headless ? "options.add_argument('--headless=new')" : ''}
options.binary_location = sys.argv[2]
driver = webdriver.Chrome(options=options)
driver.get(sys.argv[1])
driver.execute_script('return document.title')
time.sleep(600)`
	}
};

const selected = values.only?.split(',') ?? [...Object.keys(node), ...Object.keys(python)];
const unknown = selected.filter((name) => !(name in node) && !(name in python));
if (unknown.length) throw new Error(`Unknown drivers: ${unknown.join(', ')}`);

// cloakbrowser supports only some playwright-core versions; it and clearcote use the top-level one.
const npmPackages = ['playwright', 'playwright-extra', 'puppeteer-extra-plugin-stealth', 'patchright', 'rebrowser-playwright', 'cloakbrowser', 'clearcote'];
const sh = (cmd, args, cwd = cache) => execFileSync(cmd, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] }).toString();
const setupErrors = {};
if (selected.some((name) => name in node)) {
	if (!existsSync(join(cache, 'package.json'))) writeFileSync(join(cache, 'package.json'), '{"private":true}');
	try {
		sh('npm', ['install', '--no-audit', '--no-fund', ...npmPackages.map((p) => `${p}@latest`)]);
		const range = JSON.parse(readFileSync(join(cache, 'node_modules', 'cloakbrowser', 'package.json'), 'utf8')).peerDependencies['playwright-core'];
		sh('npm', ['install', '--no-audit', '--no-fund', `playwright-core@${range}`]);
		sh('npx', ['playwright', 'install', 'chromium', 'firefox']);
		sh('npx', ['patchright', 'install', 'chromium']);
		sh('npx', ['rebrowser-playwright', 'install', 'chromium']);
		sh('npx', ['clearcote', 'install']);
		if (selected.includes('obscura')) {
			const target = `${process.arch === 'arm64' ? 'aarch64' : 'x86_64'}-${process.platform === 'darwin' ? 'macos' : 'linux'}`;
			mkdirSync(join(cache, 'obscura'), { recursive: true });
			sh('curl', ['-fsSL', '-o', 'obscura.tar.gz', `https://github.com/h4ckf0r0day/obscura/releases/latest/download/obscura-${target}-stealth.tar.gz`], join(cache, 'obscura'));
			sh('tar', ['-xzf', 'obscura.tar.gz'], join(cache, 'obscura'));
		}
	} catch (error) {
		setupErrors.npm = String(error.stderr || error.message).slice(-2000);
	}
}
const load = createRequire(join(cache, 'package.json'));
const esm = (name) => {
	const { exports } = JSON.parse(readFileSync(join(cache, 'node_modules', name, 'package.json'), 'utf8'));
	return import(pathToFileURL(join(cache, 'node_modules', name, exports['.'].import ?? exports['.'].default)).href);
};
const versions = {};
for (const name of npmPackages)
	try {
		versions[name] = JSON.parse(readFileSync(join(cache, 'node_modules', name, 'package.json'), 'utf8')).version;
	} catch {}
const testingChrome = () => load('playwright').chromium.executablePath();
const uv = (packages, args) => ['run', '--quiet', '--no-project', '--python', '3.12', '--refresh', ...packages.flatMap((p) => ['--with', p]), 'python', ...args];

const waiting = new Map();
const server = createServer((req, res) => {
	const url = new URL(req.url, 'http://localhost');
	if (req.method === 'POST' && url.pathname === '/result') {
		let body = '';
		req.on('data', (chunk) => (body += chunk));
		req.on('end', () => {
			waiting.get(url.searchParams.get('driver'))?.(JSON.parse(body));
			res.end('ok');
		});
		return;
	}
	res.setHeader('content-type', 'text/html; charset=utf-8');
	res.end(PAGE);
}).listen(0, '127.0.0.1');
await new Promise((ok) => server.once('listening', ok));
const base = `http://localhost:${server.address().port}/`;

const results = {};
for (const name of selected) {
	const url = `${base}?driver=${encodeURIComponent(name)}`;
	const reported = new Promise((ok) => waiting.set(name, ok));
	const timeout = () => new Promise((ok) => setTimeout(() => ok({ error: `no report within ${values.timeout}s` }), Number(values.timeout) * 1000));
	let close = async () => {};
	try {
		if (name in node) {
			if (setupErrors.npm) throw new Error(`npm setup failed: ${setupErrors.npm}`);
			close = await node[name](url, load);
		} else {
			const { packages, setup, code } = python[name];
			if (setup) sh('uv', uv(packages, ['-c', setup]));
			const child = spawn('uv', uv(packages, ['-c', code, url, testingChrome()]), { cwd: cache, detached: true, stdio: ['ignore', 'ignore', 'pipe'] });
			let stderr = '';
			child.stderr.on('data', (chunk) => (stderr = (stderr + chunk).slice(-2000)));
			const exited = new Promise((ok) => child.on('exit', (code) => ok({ error: `exited ${code}: ${stderr}` })));
			close = async () => {
				try {
					process.kill(-child.pid, 'SIGKILL');
				} catch {}
			};
			results[name] = await Promise.race([reported, timeout(), exited]);
		}
		results[name] ??= await Promise.race([reported, timeout()]);
	} catch (error) {
		results[name] = { error: String(error.message || error).slice(0, 2000) };
	} finally {
		await Promise.resolve(close()).catch(() => {});
	}
	const r = results[name];
	const fired = (section) => Object.entries(r[section] ?? {}).filter(([k, v]) => k !== 'version' && v === true).map(([k]) => k);
	const unknown = Object.entries(r.automation ?? {}).filter(([, v]) => v === null).map(([k]) => k);
	console.log(
		r.error
			? `- ${name}: error: ${r.error.split('\n')[0]}`
			: `- ${name}: automation [${fired('automation').join(', ') || 'none'}] tampering [${fired('tampering').join(', ') || 'none'}] unknown [${unknown.join(', ') || 'none'}]`
	);
}
server.close();
const file = join(cache, 'results', `${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
writeFileSync(file, JSON.stringify({ versions, headless, results }, null, 2));
console.log(`\nFull results: ${file}`);

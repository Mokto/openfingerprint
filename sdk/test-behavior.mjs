import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdir, writeFile } from 'node:fs/promises';
import { build } from 'esbuild';
import { chromium, firefox, webkit } from 'playwright-core';

const bundle = await build({
	stdin: {
		contents: "import * as sdk from './src/index.ts'; import { collectBehavior } from './src/watch.ts'; window.SDK = { ...sdk, collectBehavior };",
		resolveDir: import.meta.dirname
	},
	bundle: true, write: false, format: 'iife', target: 'es2022'
});
const server = createServer((request, response) => {
	response.setHeader('Cache-Control', 'no-store');
	if (request.url === '/sdk.js') {
		response.setHeader('Content-Type', 'text/javascript');
		response.end(bundle.outputFiles[0].text);
	} else {
		response.setHeader('Content-Type', 'text/html');
		response.end('<!doctype html><meta charset="utf-8"><button id="target" style="position:absolute;left:100px;top:100px;width:120px;height:40px">Activate</button><script src="/sdk.js"></script>');
	}
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://localhost:${server.address().port}`;
const rows = [];
try {
	for (const [family, engine] of Object.entries({ chromium, firefox, webkit })) {
		const browser = await engine.launch({ headless: true });
		try {
			const context = await browser.newContext({ hasTouch: true });
			const page = await context.newPage();
			const fresh = async (watch = true) => {
				await page.goto(origin);
				if (watch) await page.evaluate(() => SDK.watch());
			};
			const snapshot = () => page.evaluate(() => SDK.collectBehavior());
			const record = async (scenario, expected) => {
				const evidence = await snapshot();
				assert.equal(evidence.version, 2);
				for (const [key, value] of Object.entries(expected)) assert.equal(evidence[key], value, `${family}: ${scenario}: ${key}`);
				rows.push({ family, browserVersion: browser.version(), scenario, evidence });
				console.log(`${family}: ${scenario}: ${evidence.mouseClicks} clicks, ${evidence.clicksWithoutMovement} low-movement, ${evidence.centeredClicks} centered`);
				return evidence;
			};
			await fresh(false);
			assert.equal(await snapshot(), null);
			await page.evaluate(() => SDK.watch());
			await record('before interaction', { mouseClicks: 0, pointerMoves: 0 });

			if (family === 'chromium') {
				await fresh();
				const session = await context.newCDPSession(page);
				for (let i = 0; i < 10; i++) {
					await session.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: 160, y: 120, button: 'left', clickCount: 1 });
					await session.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: 160, y: 120, button: 'left', clickCount: 1 });
				}
				await record('protocol clicks with no movement (not a Selenium session)', { mouseClicks: 10, pointerMoves: 0, clicksWithoutMovement: 10, centeredClicks: 10 });
				await session.detach();
			}
			await fresh();
			for (let i = 0; i < 10; i++) await page.locator('#target').click();
			await record('Playwright locator clicks', { mouseClicks: 10, clicksWithoutMovement: 10, centeredClicks: 10 });

			await fresh();
			for (let i = 0; i < 10; i++) {
				await page.mouse.move(20, 20);
				await page.mouse.move(160, 120, { steps: 8 });
				await page.mouse.down();
				await page.mouse.up();
			}
			await record('automation moves but still clicks centre', { mouseClicks: 10, clicksWithoutMovement: 0, centeredClicks: 10 });

			await fresh();
			for (let i = 0; i < 10; i++) {
				await page.mouse.move(20, 20);
				await page.mouse.move(110, 110, { steps: 8 });
				await page.mouse.down();
				await page.mouse.up();
			}
			await record('automation with deliberate movement', { mouseClicks: 10, clicksWithoutMovement: 0, centeredClicks: 0 });

			await fresh();
			await page.mouse.move(20, 20);
			await page.mouse.move(110, 110, { steps: 8 });
			await page.mouse.down();
			await page.mouse.up();
			await record('ordinary movement then click (scripted control)', { mouseClicks: 1, clicksWithoutMovement: 0, centeredClicks: 0 });
			for (let i = 0; i < 9; i++) {
				await page.mouse.down();
				await page.mouse.up();
			}
			await record('stationary repeats after ordinary movement', { mouseClicks: 10, clicksWithoutMovement: 9, centeredClicks: 0 });

			await fresh(false);
			await page.mouse.move(160, 120);
			await page.evaluate(() => SDK.watch());
			await page.mouse.down();
			await page.mouse.up();
			await record('watch starts over button', { mouseClicks: 1, clicksWithoutMovement: 1, centeredClicks: 1 });
			await page.mouse.dblclick(160, 120);
			await record('unchanged cursor double-click', { mouseClicks: 3, clicksWithoutMovement: 3, centeredClicks: 3 });
			for (let i = 0; i < 7; i++) {
				await page.mouse.down();
				await page.mouse.up();
			}
			await record('ordinary stationary repeats (scripted control)', { mouseClicks: 10, clicksWithoutMovement: 10, centeredClicks: 10 });
			await page.evaluate(() => SDK.watch());
			await record('watch is idempotent', { mouseClicks: 10, clicksWithoutMovement: 10, centeredClicks: 10 });

			await fresh();
			await page.mouse.click(110, 110);
			await record('one large pointer jump', { mouseClicks: 1, clicksWithoutMovement: 1, centeredClicks: 0 });
			await fresh();
			await page.mouse.click(161, 121);
			await record('centre tolerance includes one pixel on each axis', { mouseClicks: 1, centeredClicks: 1 });
			await page.mouse.click(162, 122);
			await record('centre tolerance excludes two pixels', { mouseClicks: 2, centeredClicks: 1 });
			await page.evaluate(() => { document.getElementById('target').style.cssText = 'position:absolute;left:100px;top:100px;width:4px;height:4px;padding:0;border:0'; });
			await page.mouse.click(102, 102);
			await record('small target is not a centred click', { mouseClicks: 3, centeredClicks: 1 });

			await fresh(false);
			await page.mouse.move(110, 110);
			await page.evaluate(() => SDK.watch());
			await page.mouse.move(110.5, 110.5, { steps: 8 });
			await page.mouse.down();
			await page.mouse.up();
			const tiny = await record('subpixel movement is event-count dependent', { mouseClicks: 1, centeredClicks: 0 });
			assert.equal(tiny.clicksWithoutMovement, tiny.pointerMoves <= 1 ? 1 : 0);

			await fresh(false);
			await page.mouse.move(110, 110);
			await page.evaluate(() => SDK.watch());
			await page.mouse.down();
			await page.mouse.move(114, 114, { steps: 4 });
			await page.mouse.up();
			await record('movement after press does not change that click', { mouseClicks: 1, clicksWithoutMovement: 1 });
			await page.mouse.down();
			await page.mouse.up();
			await record('movement after press belongs to next interval', { mouseClicks: 2, clicksWithoutMovement: 1 });
			await page.mouse.down();
			await page.mouse.up();
			await record('press resets only the movement interval', { mouseClicks: 3, clicksWithoutMovement: 2 });

			await fresh();
			await page.locator('#target').focus();
			await page.keyboard.press('Enter');
			await page.keyboard.press('Space');
			await record('keyboard activation', { mouseClicks: 0, clicksWithoutMovement: 0, keys: 2 });
			await page.touchscreen.tap(160, 120);
			await record('touch activation', { mouseClicks: 0, clicksWithoutMovement: 0, touches: 1 });
			await page.evaluate(() => {
				document.getElementById('target').click();
				document.getElementById('target').dispatchEvent(new MouseEvent('click', { bubbles: true, detail: 1, clientX: 160, clientY: 120 }));
			});
			await record('script activation, not physical assistive technology', { mouseClicks: 0, clicksWithoutMovement: 0, untrustedEvents: 2 });
			await page.mouse.click(160, 120);
			await page.keyboard.press('Enter');
			await page.keyboard.press('Space');
			await page.touchscreen.tap(160, 120);
			await record('keyboard and touch after mouse input', { mouseClicks: 1, clicksWithoutMovement: 1, centeredClicks: 1, touches: 2, keys: 4 });

			await fresh();
			await page.route('**/v1/identify', async route => {
				await page.evaluate(body => { window.posted = JSON.parse(body); }, route.request().postData());
				await page.mouse.click(160, 120);
				await route.fulfill({ json: { identificationId: 'AbCdEfGhIjKlMnOpQrStU_' } });
			});
			await page.evaluate(() => {
				const digest = crypto.subtle.digest.bind(crypto.subtle);
				const gate = new Promise(resolve => { window.releaseDigest = resolve; });
				crypto.subtle.digest = async (...args) => {
					window.digestWaiting = true;
					await gate;
					return digest(...args);
				};
				window.identifying = SDK.identify({ endpoint: `${location.origin}/v1/identify`, timeoutMs: 5000 });
			});
			await page.waitForFunction(() => window.digestWaiting);
			await page.mouse.click(160, 120);
			await page.evaluate(() => window.releaseDigest());
			assert.equal((await page.evaluate(() => window.identifying)).identificationId, 'AbCdEfGhIjKlMnOpQrStU_');
			assert.equal(await page.evaluate(() => window.posted.behavior.mouseClicks), 1, 'snapshot includes input during collection, excludes input during posting');
			await record('identify snapshots at collection end, never resets', { mouseClicks: 2, clicksWithoutMovement: 2, centeredClicks: 2 });
			await fresh();
			await page.evaluate(() => SDK.identify({ endpoint: `${location.origin}/v1/identify`, timeoutMs: 5000 }));
			assert.equal(await page.evaluate(() => window.posted.behavior.mouseClicks), 0, 'early identification observes zero input');
			await fresh(false);
			await page.evaluate(() => SDK.identify({ endpoint: `${location.origin}/v1/identify`, timeoutMs: 5000 }));
			assert.equal(await page.evaluate(() => window.posted.behavior), null, 'unwatched identification stays unknown');
		} finally { await browser.close(); }
	}
	for (const family of ['chromium', 'firefox', 'webkit']) {
		const aggregate = scenario => {
			const { mouseClicks, clicksWithoutMovement, centeredClicks } = rows.find(row => row.family === family && row.scenario === scenario).evidence;
			return { mouseClicks, clicksWithoutMovement, centeredClicks };
		};
		assert.deepEqual(aggregate('Playwright locator clicks'), aggregate('ordinary stationary repeats (scripted control)'), 'the same aggregates cannot distinguish these interactions');
	}
	await mkdir(new URL('../.test-results/', import.meta.url), { recursive: true });
	await writeFile(new URL('../.test-results/behavior.json', import.meta.url), JSON.stringify({
		scope: 'Controlled headless input, not a human cohort or an accuracy estimate. No Selenium session or physical accessibility hardware tested.',
		rows
	}, null, 2) + '\n');
} finally { await new Promise(resolve => server.close(resolve)); }

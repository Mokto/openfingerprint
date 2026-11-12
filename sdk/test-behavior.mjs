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
			const record = async (scenario, expected, targets) => {
				const evidence = await snapshot();
				assert.equal(evidence.version, 2);
				for (const [key, value] of Object.entries(expected)) assert.equal(evidence[key], value, `${family}: ${scenario}: ${key}`);
				rows.push({ family, browserVersion: browser.version(), scenario, evidence, ...(targets ? { targets } : {}) });
				console.log(`${family}: ${scenario}: ${evidence.mouseClicks} clicks, ${evidence.clicksWithoutMovement} low-movement, ${evidence.centeredClicks} centered${targets ? `, ${targets.distinctTargets} targets, ${targets.targetChanges} target changes` : ''}`);
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

			const freshTargets = async mode => {
				await fresh(false);
				await page.evaluate(mode => {
					document.body.replaceChildren();
					for (let i = 0; i < (mode === 'single' || mode === 'replace' ? 1 : 10); i++) {
						const button = document.createElement('button');
						button.id = `target-${i}`;
						button.textContent = 'Activate';
						const x = mode === 'static' ? 100 + i % 5 * 140 : 100;
						const y = mode === 'static' ? 100 + Math.floor(i / 5) * 60 : 100;
						button.style.cssText = `position:absolute;left:${x}px;top:${y}px;width:120px;height:40px`;
						button.hidden = mode === 'wizard' && i > 0;
						document.body.append(button);
					}
					document.body.addEventListener('click', event => {
						if (!(event.target instanceof HTMLButtonElement)) return;
						if (mode === 'wizard') {
							event.target.hidden = true;
							if (event.target.nextElementSibling) event.target.nextElementSibling.hidden = false;
						} else if (mode === 'replace') event.target.replaceWith(event.target.cloneNode(true));
					});
				}, mode);
				await page.mouse.move(160, 120);
				await page.evaluate(() => {
					SDK.watch();
					let clicks = SDK.collectBehavior().mouseClicks;
					let last = null;
					const seen = new WeakSet();
					window.targetSample = { targetChanges: 0, distinctTargets: 0 };
					addEventListener('click', event => {
						const current = SDK.collectBehavior().mouseClicks;
						if (current === clicks) return;
						clicks = current;
						if (last && last !== event.target) window.targetSample.targetChanges++;
						if (!seen.has(event.target)) {
							seen.add(event.target);
							window.targetSample.distinctTargets++;
						}
						last = event.target;
					}, { capture: true, passive: true });
				});
			};
			const recordTargets = async (scenario, expected, targets) => {
				const sample = await page.evaluate(() => window.targetSample);
				assert.deepEqual(sample, targets, `${family}: ${scenario}: target sample`);
				await record(scenario, expected, sample);
			};
			await freshTargets('static');
			for (let i = 0; i < 10; i++) await page.locator(`#target-${i}`).click();
			await recordTargets('cross-target locator clicks', { mouseClicks: 10, clicksWithoutMovement: 10, centeredClicks: 10 }, { targetChanges: 9, distinctTargets: 10 });

			if (family === 'chromium') {
				await freshTargets('static');
				const session = await context.newCDPSession(page);
				for (let i = 0; i < 10; i++) {
					const position = { x: 160 + i % 5 * 140, y: 120 + Math.floor(i / 5) * 60, button: 'left', clickCount: 1 };
					await session.send('Input.dispatchMouseEvent', { ...position, type: 'mousePressed' });
					await session.send('Input.dispatchMouseEvent', { ...position, type: 'mouseReleased' });
				}
				await recordTargets('cross-target protocol clicks without move events', { mouseClicks: 10, pointerMoves: 0, clicksWithoutMovement: 10, centeredClicks: 10 }, { targetChanges: 9, distinctTargets: 10 });
				await session.detach();
			}

			for (const mode of ['single', 'wizard', 'replace']) {
				await freshTargets(mode);
				for (let i = 0; i < 10; i++) {
					await page.mouse.down();
					await page.mouse.up();
				}
				await recordTargets(`cross-target stationary ${mode} control`, { mouseClicks: 10, pointerMoves: 0, clicksWithoutMovement: 10, centeredClicks: 10 }, { targetChanges: mode === 'single' ? 0 : 9, distinctTargets: mode === 'single' ? 1 : 10 });
			}

			await freshTargets('static');
			for (let i = 0; i < 10; i++) {
				await page.mouse.move(160 + i % 5 * 140, 120 + Math.floor(i / 5) * 60);
				await page.mouse.down();
				await page.mouse.up();
			}
			await recordTargets('cross-target simulated pointer snapping, not assistive hardware', { mouseClicks: 10, clicksWithoutMovement: 10, centeredClicks: 10 }, { targetChanges: 9, distinctTargets: 10 });

			for (const offset of [0, 10]) {
				await freshTargets('static');
				for (let i = 0; i < 10; i++) {
					await page.mouse.move(20, 20);
					await page.mouse.move(160 + i % 5 * 140 + offset, 120 + Math.floor(i / 5) * 60 + offset, { steps: 8 });
					await page.mouse.down();
					await page.mouse.up();
				}
				await recordTargets(`cross-target multi-event movement with offset ${offset}`, { mouseClicks: 10, clicksWithoutMovement: 0, centeredClicks: offset ? 0 : 10 }, { targetChanges: 9, distinctTargets: 10 });
			}

			for (const activation of ['keyboard', 'touch', 'script']) {
				await freshTargets('static');
				for (let i = 0; i < 10; i++) {
					if (activation === 'keyboard') {
						await page.locator(`#target-${i}`).focus();
						await page.keyboard.press(i % 2 ? 'Enter' : 'Space');
					} else if (activation === 'touch') {
						await page.touchscreen.tap(160 + i % 5 * 140, 120 + Math.floor(i / 5) * 60);
					} else await page.locator(`#target-${i}`).evaluate(button => button.click());
				}
				await recordTargets(`cross-target ${activation} activation`, { mouseClicks: 0, clicksWithoutMovement: 0, centeredClicks: 0, ...(activation === 'keyboard' ? { keys: 10 } : activation === 'touch' ? { touches: 10 } : { untrustedEvents: 10 }) }, { targetChanges: 0, distinctTargets: 0 });
			}

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
	for (const family of ['chromium', 'firefox', 'webkit']) {
		const sample = scenario => rows.find(row => row.family === family && row.scenario === scenario);
		const candidate = ({ evidence: e, targets: t }) => e.mouseClicks >= 10 && e.clicksWithoutMovement === e.mouseClicks && e.centeredClicks === e.mouseClicks && t.targetChanges >= 9 && t.distinctTargets >= 10;
		for (const scenario of ['cross-target locator clicks', 'cross-target stationary wizard control', 'cross-target stationary replace control', 'cross-target simulated pointer snapping, not assistive hardware'])
			assert.equal(candidate(sample(scenario)), true, `${family}: the hypothesis also matches ${scenario}`);
		for (const scenario of ['cross-target stationary single control', 'cross-target multi-event movement with offset 0', 'cross-target multi-event movement with offset 10', 'cross-target keyboard activation', 'cross-target touch activation', 'cross-target script activation'])
			assert.equal(candidate(sample(scenario)), false, `${family}: ${scenario}`);
		const aggregate = scenario => {
			const { watchedMs, ...evidence } = sample(scenario).evidence;
			return { ...evidence, ...sample(scenario).targets };
		};
		assert.deepEqual(aggregate('cross-target locator clicks'), aggregate('cross-target simulated pointer snapping, not assistive hardware'), 'a snapped-pointer control has the same aggregate evidence as locator clicks');
		if (family === 'chromium') {
			assert.deepEqual(aggregate('cross-target protocol clicks without move events'), aggregate('cross-target stationary wizard control'), 'moving-layout controls collide with no-move protocol clicks, including pointerMoves');
			assert.deepEqual(aggregate('cross-target protocol clicks without move events'), aggregate('cross-target stationary replace control'), 'DOM replacement controls collide with no-move protocol clicks');
		}
	}
	await mkdir(new URL('../.test-results/', import.meta.url), { recursive: true });
	await writeFile(new URL('../.test-results/behavior.json', import.meta.url), JSON.stringify({
		scope: 'Controlled headless input, not a human cohort or an accuracy estimate. No Selenium session or physical accessibility hardware tested. Target samples are fixture-local aggregates, not SDK evidence or API inputs.',
		rows
	}, null, 2) + '\n');
} finally { await new Promise(resolve => server.close(resolve)); }

import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { analyze } from './analyze.mjs';

const require = createRequire(new URL('../sdk/package.json', import.meta.url));
const { chromium, firefox, webkit } = require('playwright-core');
const sdk = await readFile(new URL('../sdk/dist/index.js', import.meta.url));
const recorder = await readFile(new URL('./record.mjs', import.meta.url));
const study = randomUUID(), device = randomUUID();
const build = createHash('sha256').update(sdk).digest('hex');
const plan = { format: 1, study, build, schema: 5, targets: [], rounds: [
    { id: 1, day: 0, condition: 'baseline' }, { id: 2, day: 0, condition: 'reload' }
] };
const rows = [];
const requests = [];
const server = createServer((request, response) => {
    requests.push({ path: request.url, method: request.method });
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'none'; frame-src 'self'");
    if (request.url === '/sdk.js' || request.url === '/record.mjs') {
        response.setHeader('Content-Type', 'text/javascript');
        response.end(request.url === '/sdk.js' ? sdk : recorder);
    } else if (request.url === '/') {
        response.setHeader('Content-Type', 'text/html');
        response.end('<!doctype html><html><head><meta charset="utf-8"><title>Synthetic evaluation test</title></head><body></body></html>');
    } else response.writeHead(404).end();
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://localhost:${server.address().port}`;
try {
    for (const [family, engine] of Object.entries({ chromium, firefox, webkit })) {
        const browser = await engine.launch({ headless: true });
        try {
            const context = await browser.newContext();
            let external = 0;
            await context.route('**/*', route => {
                if (new URL(route.request().url()).origin !== origin) { external++; return route.abort(); }
                return route.continue();
            });
            const page = await context.newPage();
            const label = randomUUID();
            plan.targets.push({ browser: label, device, cohort: 'synthetic', platform: 'other', family, deviceClass: 'desktop' });
            for (const round of [1, 2]) {
                await page.goto(origin);
                const sample = await page.evaluate(async metadata => {
                    const { collect } = await import('/sdk.js');
                    const { capture } = await import('/record.mjs');
                    return capture(metadata, collect);
                }, { study, build, browser: label, round, consent: true });
                assert.equal(sample.status, 'collected');
                rows.push(sample);
            }
            assert.equal(external, 0);
        } finally { await browser.close(); }
    }
    const report = analyze(plan, rows, 2);
    assert.equal(report.real_device_observations, 0);
    assert.equal(report.cohorts[0].devices, 1);
    assert.equal(report.cohorts[0].recorded_samples, 6);
    assert.equal(report.cohorts[0].full.false_merges.rate, null);
    assert(requests.every(request => request.method === 'GET'));
    const output = new URL('../.test-results/identification/', import.meta.url);
    await mkdir(output, { recursive: true });
    await writeFile(new URL('smoke-report.json', output), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
    console.log('Identification capture passed in Chromium, Firefox and WebKit; synthetic pipeline check only, zero real-device observations.');
} finally { await new Promise(resolve => server.close(resolve)); }
